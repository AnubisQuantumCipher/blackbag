//! `black-bag` — hardened credential storage for Omarchy.

mod clipboard;
mod import;
mod tty;

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use blackbag_core::record::{Kind, Record, Secret, TotpConfig, TotpAlgorithm};
use blackbag_core::session::{self, Request, Response};
use blackbag_core::status::{HostPosture, SessionView, Status};
use blackbag_core::vault::{RecoveryKey, Vault};
use blackbag_core::{harden, memlock, vault_path};
use clap::{Args, Parser, Subcommand};
use uuid::Uuid;
use zeroize::Zeroizing;

use tty::Sink;

#[derive(Parser)]
#[command(
    name = "black-bag",
    version,
    about = "Hardened credential storage for Omarchy",
    long_about = "Black-Bag keeps credentials in an authenticated, padded, \
                  passphrase-derived vault with optional post-quantum recovery \
                  recipients. Secrets are page-locked, wiped on drop, and \
                  delivered to your terminal or clipboard — never to a log."
)]
struct Cli {
    /// Vault file to operate on.
    #[arg(long, global = true, env = "BLACK_BAG_VAULT_PATH")]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault.
    Init(InitArgs),
    /// Add a record.
    Add(AddArgs),
    /// List records (no secrets).
    List(ListArgs),
    /// Show one record (no secrets unless --reveal).
    Get(GetArgs),
    /// Remove a record.
    Remove(RemoveArgs),
    /// Print a TOTP code.
    Totp(TotpArgs),
    /// Mint a new data key, re-encrypt, and optionally change the passphrase.
    Rekey(RekeyArgs),
    /// Manage recovery recipients.
    #[command(subcommand)]
    Recovery(RecoveryCommand),
    /// Run the unlock agent, or talk to it.
    #[command(subcommand)]
    Agent(AgentCommand),
    /// Report vault and host posture.
    Doctor(DoctorArgs),
    /// Write status.json for the cockpit.
    Status(StatusArgs),
    /// Generate a password, passphrase or PIN.
    #[command(subcommand)]
    Gen(GenCommand),
    /// Convert a black-bagg 0.4.x (v1) vault to this format.
    Migrate(MigrateArgs),
    /// Bring records in from another password manager's export.
    Import(ImportArgs),
    /// Write every record out in plaintext, for moving to another manager.
    Export(ExportArgs),
    /// Clipboard helper: serve stdin as a sensitive clipboard offer.
    ///
    /// Spawned by `--to clipboard`; not meant to be run by hand. Hidden from
    /// help so nobody reaches for it with a secret on argv.
    #[command(hide = true, name = "clip-serve")]
    ClipServe {
        #[arg(long, default_value_t = 30)]
        clear_after: u64,
    },
}

/// Generated values go to STDOUT and the strength line to STDERR, so a pipe
/// captures the secret alone. That also means a shell redirect writes a
/// password to a file — which is the point of a generator, but worth knowing.
#[derive(Subcommand)]
enum GenCommand {
    /// A random password.
    Password {
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_lowercase: bool,
        #[arg(long)]
        no_uppercase: bool,
        #[arg(long)]
        no_digits: bool,
        #[arg(long)]
        no_symbols: bool,
        /// Drop 0/O/1/l/I/|/o, at a real cost in entropy that is reported.
        #[arg(long)]
        exclude_ambiguous: bool,
    },
    /// A random passphrase from the built-in 512-word list (9 bits per word).
    Passphrase {
        #[arg(long, default_value_t = 8)]
        words: usize,
        #[arg(long, default_value_t = '-')]
        separator: char,
        #[arg(long)]
        capitalise: bool,
    },
    /// A random numeric PIN.
    Pin {
        #[arg(long, default_value_t = 6)]
        digits: usize,
    },
}

#[derive(Args)]
struct InitArgs {
    /// Argon2id memory cost in KiB.
    #[arg(long, default_value_t = blackbag_core::crypto::DEFAULT_MEM_KIB)]
    mem_kib: u32,
}

#[derive(Args)]
struct AddArgs {
    /// Record kind.
    #[arg(value_parser = parse_kind)]
    kind: Kind,
    /// Title shown in listings.
    #[arg(long)]
    title: Option<String>,
    /// Comma-separated tags.
    #[arg(long, value_delimiter = ',')]
    tags: Vec<String>,
    /// Non-secret attribute, repeatable: --attr username=octocat
    #[arg(long = "attr", value_name = "KEY=VALUE")]
    attributes: Vec<String>,
    /// Secret field to prompt for, repeatable. Defaults to the kind's usual field.
    #[arg(long = "secret", value_name = "NAME")]
    secrets: Vec<String>,
    #[arg(long, default_value_t = 6)]
    totp_digits: u8,
    #[arg(long, default_value_t = 30)]
    totp_step: u64,
}

#[derive(Args)]
struct ListArgs {
    #[arg(long, value_parser = parse_kind)]
    kind: Option<Kind>,
    /// Substring match over titles, tags, and attributes — never secrets.
    #[arg(long)]
    query: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct GetArgs {
    id: Uuid,
    /// Reveal a secret field by name.
    #[arg(long)]
    reveal: Option<String>,
    /// Where a revealed secret goes.
    #[arg(long = "to", value_enum, default_value_t = Sink::Tty)]
    sink: Sink,
    /// Seconds before the clipboard is cleared.
    #[arg(long, default_value_t = 30)]
    clear_after: u64,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct RemoveArgs {
    id: Uuid,
    /// Required: removing a record is not undoable.
    #[arg(long)]
    yes: bool,
}

#[derive(Args)]
struct TotpArgs {
    id: Uuid,
    #[arg(long = "to", value_enum, default_value_t = Sink::Tty)]
    sink: Sink,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct RekeyArgs {
    /// Also change the master passphrase.
    #[arg(long)]
    change_passphrase: bool,
    /// New Argon2id memory cost in KiB.
    #[arg(long)]
    mem_kib: Option<u32>,
}

#[derive(Subcommand)]
enum RecoveryCommand {
    /// Add a hybrid X25519+ML-KEM-1024 recovery recipient.
    Add {
        label: String,
        /// Where to write the recovery key. Store it offline.
        #[arg(long)]
        out: PathBuf,
    },
    /// Unlock with a recovery key and immediately set a new passphrase.
    Use {
        #[arg(long)]
        key: PathBuf,
    },
    /// Revoke a recovery recipient.
    Remove { label: String },
    /// List recipients.
    List,
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Run the agent in the foreground.
    Serve {
        /// Lock after this many seconds without a request.
        #[arg(long, default_value_t = session::DEFAULT_IDLE_SECS)]
        idle_secs: u64,
        /// Lock this many seconds after an unlock no matter how busy the
        /// session is. 0 disables the ceiling.
        #[arg(long, default_value_t = session::DEFAULT_MAX_SESSION_SECS)]
        max_secs: u64,
    },
    /// Unlock the running agent (passphrase on stdin or the terminal).
    Unlock,
    /// Lock the running agent.
    Lock,
    /// Agent state as JSON.
    Status,
    /// Stop the agent.
    Stop,
    /// Non-secret record metadata from the unlocked agent, as JSON.
    ///
    /// This is what the cockpit reads. It carries titles, tags, attributes and
    /// per-field *handles* — never secret bytes.
    List {
        #[arg(long)]
        json: bool,
        #[arg(long, value_parser = parse_kind)]
        kind: Option<Kind>,
        #[arg(long)]
        query: Option<String>,
    },
    /// Copy one secret field to the clipboard without printing it.
    Reveal {
        id: Uuid,
        field: String,
        #[arg(long = "to", value_enum, default_value_t = Sink::Clipboard)]
        sink: Sink,
        #[arg(long, default_value_t = 30)]
        clear_after: u64,
    },
    /// Print one secret field to stdout.
    ///
    /// Deliberately separate from `reveal`: this is the one command that writes
    /// a secret to a redirectable stream, and the cockpit uses it only when the
    /// user explicitly chooses SHOW.
    Show { id: Uuid, field: String },
    /// Current TOTP code for a record.
    ///
    /// Copying a 2FA record must go through here, not through `reveal totp`:
    /// that returns the raw shared secret, which is binary and fails to decode
    /// as UTF-8.
    Totp {
        id: Uuid,
        #[arg(long = "to", value_enum)]
        sink: Option<Sink>,
        #[arg(long, default_value_t = 30)]
        clear_after: u64,
    },
    /// Create a record from a JSON draft read on stdin.
    ///
    /// Deliberately stdin and not flags: a draft carries secrets, and argv is
    /// world-readable through /proc.
    Add,
    /// Replace a record's contents from a JSON draft read on stdin.
    Edit { id: Uuid },
    /// Delete a record.
    Delete {
        id: Uuid,
        /// Required. Deleting a record is not undoable.
        #[arg(long)]
        yes: bool,
    },
    /// Credential hygiene across the whole vault, computed locally.
    ///
    /// The JSON form carries handles and titles and is as sensitive as the
    /// open vault. The default human form is counts only.
    Hygiene {
        #[arg(long)]
        json: bool,
    },
    /// Check passwords against Have I Been Pwned's Pwned Passwords corpus.
    ///
    /// The one command in this program that talks to the network, and it
    /// needs `--online` to say so. What leaves the machine: the first five
    /// hex characters of each distinct password's SHA-1 (k-anonymity), sent
    /// by curl. The agent does the matching against the full hash it never
    /// disclosed, and remembers exposures for the hygiene report until lock.
    Breach {
        /// Consent to the network requests described above.
        #[arg(long)]
        online: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
struct DoctorArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct StatusArgs {
    /// Write to $XDG_RUNTIME_DIR/black-bag/status.json instead of stdout.
    #[arg(long)]
    publish: bool,
}

#[derive(Args)]
struct ImportArgs {
    /// The export file to read.
    #[arg(long)]
    from: PathBuf,
    /// Which tool wrote it.
    #[arg(long, value_enum)]
    format: import::ImportFormat,
    /// Parse and report, but write nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args)]
struct ExportArgs {
    /// Where to write. Created 0600; refuses to overwrite.
    #[arg(long)]
    to: PathBuf,
    #[arg(long, value_enum, default_value_t = import::ExportFormat::Json)]
    format: import::ExportFormat,
    /// Required: the file will contain every secret in plaintext.
    #[arg(long)]
    plaintext_ok: bool,
}

#[derive(Args)]
struct MigrateArgs {
    /// The old v1 vault.
    #[arg(long)]
    from: PathBuf,
    /// Where to write the v2 vault.
    #[arg(long)]
    to: PathBuf,
}

fn parse_kind(s: &str) -> Result<Kind, String> {
    s.parse::<Kind>().map_err(|e| e.to_string())
}

fn main() {
    // Before anything else touches memory.
    let hardening = harden::harden_process();

    if let Err(err) = run(hardening) {
        eprintln!("black-bag: {err:#}");
        std::process::exit(1);
    }
}

fn run(hardening: harden::HardenReport) -> Result<()> {
    let cli = Cli::parse();
    let path = match cli.vault {
        Some(p) => p,
        None => vault_path()?,
    };

    match cli.command {
        Command::Init(args) => cmd_init(&path, args),
        Command::Add(args) => cmd_add(&path, args),
        Command::List(args) => cmd_list(&path, args),
        Command::Get(args) => cmd_get(&path, args),
        Command::Remove(args) => cmd_remove(&path, args),
        Command::Totp(args) => cmd_totp(&path, args),
        Command::Rekey(args) => cmd_rekey(&path, args),
        Command::Recovery(cmd) => cmd_recovery(&path, cmd),
        Command::Agent(cmd) => cmd_agent(&path, cmd, hardening),
        Command::Doctor(args) => cmd_doctor(&path, args, hardening),
        Command::Status(args) => cmd_status(&path, args, hardening),
        Command::Gen(cmd) => cmd_gen(cmd),
        Command::Migrate(args) => cmd_migrate(args),
        Command::Import(args) => cmd_import(&path, args),
        Command::Export(args) => cmd_export(&path, args),
        Command::ClipServe { clear_after } => clipboard::serve(clear_after),
    }
}

/// Open the vault, preferring the agent so the user is not asked again.
fn open_vault(path: &std::path::Path) -> Result<Vault> {
    let passphrase = tty::read_passphrase("Master passphrase: ")?;
    Vault::unlock(path, passphrase.as_bytes())
}

fn cmd_init(path: &std::path::Path, args: InitArgs) -> Result<()> {
    if path.exists() {
        bail!("a vault already exists at {}", path.display());
    }
    let passphrase = tty::read_new_passphrase()?;
    Vault::init(path, passphrase.as_bytes(), args.mem_kib)?;
    println!("Initialised vault at {}", path.display());
    println!(
        "Argon2id: mem={} KiB time={} lanes={}",
        args.mem_kib,
        blackbag_core::crypto::DEFAULT_TIME_COST,
        blackbag_core::crypto::recommended_lanes()
    );
    println!(
        "\nNext: add a recovery recipient so a forgotten passphrase is not a total loss:\n  \
         black-bag recovery add offsite --out ~/black-bag-recovery.key"
    );
    Ok(())
}

/// The secret field each kind prompts for when none is named.
fn default_secret_fields(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Login => &["password"],
        Kind::Totp => &[],
        Kind::Api => &["secret_key"],
        Kind::Ssh => &["private_key"],
        Kind::Pgp => &["private_key"],
        Kind::Wallet => &["seed"],
        Kind::Bank => &["account_number"],
        Kind::Wifi => &["passphrase"],
        Kind::Id => &["number"],
        Kind::Contact => &[],
        Kind::Note => &["body"],
        Kind::Recovery => &["payload"],
    }
}

fn cmd_add(path: &std::path::Path, args: AddArgs) -> Result<()> {
    // The master passphrase is read first, before any per-record prompt.
    // Asking for a record's password and only then for the passphrase that
    // unlocks the vault reads backwards to a human, and it makes the piped
    // form ambiguous about which line is which.
    let master = tty::read_passphrase("Master passphrase: ")?;

    let mut record = Record::new(args.kind, args.title.clone());
    record.tags = args.tags.clone();

    for attr in &args.attributes {
        let (key, value) = attr
            .split_once('=')
            .ok_or_else(|| anyhow!("--attr expects KEY=VALUE, got {attr}"))?;
        record.set_attribute(key, value);
    }

    if args.kind == Kind::Totp {
        // Deliberately prompt-only. A --totp-secret flag would have put shared
        // secret material in argv, which /proc publishes to every process on
        // the machine — the one rule this project does not bend.
        let encoded = tty::read_passphrase("Base32 TOTP secret: ")?;
        let cleaned: String = encoded
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect::<String>()
            .to_uppercase();
        let bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
            .ok_or_else(|| anyhow!("invalid base32 TOTP secret"))?;
        record.set_field("totp", Secret::new(&bytes));
        record.totp = Some(TotpConfig {
            issuer: record.attribute("issuer").map(str::to_string),
            account: record.attribute("account").map(str::to_string),
            digits: args.totp_digits,
            step: args.totp_step,
            skew: 1,
            algorithm: TotpAlgorithm::Sha1,
        });
    }

    let wanted: Vec<String> = if args.secrets.is_empty() {
        default_secret_fields(args.kind)
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        args.secrets.clone()
    };
    for name in wanted {
        let value = tty::read_passphrase(&format!("{name}: "))?;
        record.set_field(&name, Secret::from_str(&value));
    }

    record.validate()?;
    let id = record.id;

    let _lock = blackbag_core::vault::open_lock(path)?;
    let mut vault = Vault::unlock(path, master.as_bytes())?;
    vault.add_record(record)?;
    vault.save()?;
    println!("{id}");
    Ok(())
}

fn cmd_list(path: &std::path::Path, args: ListArgs) -> Result<()> {
    let vault = open_vault(path)?;
    let matched: Vec<_> = vault
        .records()
        .iter()
        .filter(|r| args.kind.is_none_or(|k| r.kind == k))
        .filter(|r| args.query.as_deref().is_none_or(|q| r.matches(q)))
        .collect();

    if args.json {
        let views: Vec<_> = matched
            .iter()
            .map(|r| session::RecordView::of(r))
            .collect();
        println!("{}", serde_json::to_string_pretty(&views)?);
        return Ok(());
    }

    if matched.is_empty() {
        println!("No matching records.");
        return Ok(());
    }
    for record in matched {
        println!(
            "{}  {:<8}  {:<28}  {}",
            record.id,
            record.kind,
            record.title.as_deref().unwrap_or("(untitled)"),
            record.summary()
        );
    }
    Ok(())
}

fn cmd_get(path: &std::path::Path, args: GetArgs) -> Result<()> {
    let vault = open_vault(path)?;
    let record = vault
        .get(args.id)
        .ok_or_else(|| anyhow!("record {} not found", args.id))?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&session::RecordView::of(record))?
        );
        return Ok(());
    }

    println!("id:      {}", record.id);
    println!("kind:    {}", record.kind);
    if let Some(title) = &record.title {
        println!("title:   {title}");
    }
    if !record.tags.is_empty() {
        println!("tags:    {}", record.tags.join(", "));
    }
    for (key, value) in &record.attributes {
        println!("{key:<8} {value}");
    }
    for field in &record.fields {
        println!(
            "secret:  {} ({} bytes, handle {})",
            field.name,
            field.secret.len(),
            field.secret.handle(&field.name)
        );
    }

    if let Some(name) = &args.reveal {
        let secret = record
            .field(name)
            .ok_or_else(|| anyhow!("no secret field named {name}"))?;
        let value = secret.expose_str()?;
        tty::emit_secret(&value, name, args.sink, args.clear_after)?;
    }
    Ok(())
}

fn cmd_remove(path: &std::path::Path, args: RemoveArgs) -> Result<()> {
    if !args.yes {
        bail!("refusing to remove without --yes");
    }
    let _lock = blackbag_core::vault::open_lock(path)?;
    let mut vault = open_vault(path)?;
    let record = vault.remove_record(args.id)?;
    vault.save()?;
    println!(
        "Removed {} ({})",
        record.id,
        record.title.as_deref().unwrap_or("untitled")
    );
    Ok(())
}

fn cmd_totp(path: &std::path::Path, args: TotpArgs) -> Result<()> {
    let vault = open_vault(path)?;
    let record = vault
        .get(args.id)
        .ok_or_else(|| anyhow!("record {} not found", args.id))?;
    let (code, ttl, step) = session::totp_now(record)?;

    if args.json {
        println!(
            "{}",
            serde_json::json!({ "code": code, "ttl_secs": ttl, "step": step })
        );
        return Ok(());
    }
    tty::emit_secret(&code, "code", args.sink, 30)?;
    eprintln!("valid for {ttl}s");
    Ok(())
}

fn cmd_rekey(path: &std::path::Path, args: RekeyArgs) -> Result<()> {
    let _lock = blackbag_core::vault::open_lock(path)?;
    let current = tty::read_passphrase("Current master passphrase: ")?;
    let mut vault = Vault::unlock(path, current.as_bytes())?;

    let next = if args.change_passphrase {
        tty::read_new_passphrase()?
    } else {
        current.clone()
    };

    vault.rekey(Some(next.as_bytes()), args.mem_kib)?;
    println!(
        "Re-keyed. New data key minted, payload re-encrypted, {} recipient(s) re-wrapped.",
        vault.file.header.recipients.len()
    );
    if args.change_passphrase {
        println!("Master passphrase changed.");
    }
    Ok(())
}

fn cmd_recovery(path: &std::path::Path, cmd: RecoveryCommand) -> Result<()> {
    match cmd {
        RecoveryCommand::List => {
            let status = Status::probe(path, SessionView::default(), HostPosture::measure());
            if status.recipients.is_empty() {
                println!("No recipients.");
            }
            for recipient in &status.recipients {
                println!(
                    "{:<20} {:<28} private key {}",
                    recipient.label,
                    recipient.kind,
                    if recipient.key_held_externally {
                        "held outside the vault"
                    } else {
                        "derived from your passphrase"
                    }
                );
            }
            Ok(())
        }
        RecoveryCommand::Add { label, out } => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            if out.exists() {
                bail!("{} already exists; refusing to overwrite key material", out.display());
            }
            let _lock = blackbag_core::vault::open_lock(path)?;
            let mut vault = open_vault(path)?;
            let key = vault.add_recovery_recipient(&label)?;

            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&out)
                .with_context(|| format!("failed to create {}", out.display()))?;
            file.write_all(serde_json::to_string_pretty(&key)?.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;

            println!("Added recovery recipient '{label}'.");
            println!("Key written to {} (mode 0600).", out.display());
            println!(
                "\nThis file can open your vault WITHOUT the passphrase. Move it to \
                 offline media now — it is not backed up anywhere else."
            );
            Ok(())
        }
        RecoveryCommand::Use { key } => {
            let raw = std::fs::read_to_string(&key)
                .with_context(|| format!("failed to read {}", key.display()))?;
            let recovery: RecoveryKey =
                serde_json::from_str(&raw).context("not a valid recovery key file")?;

            let _lock = blackbag_core::vault::open_lock(path)?;
            let mut vault = Vault::unlock_with_recovery(path, &recovery)?;
            println!("Unlocked with recovery key '{}'.", recovery.label);
            println!("Set a new master passphrase now.");
            let passphrase = tty::read_new_passphrase()?;
            vault.rekey(Some(passphrase.as_bytes()), None)?;
            println!("New passphrase set and vault re-keyed.");
            Ok(())
        }
        RecoveryCommand::Remove { label } => {
            let _lock = blackbag_core::vault::open_lock(path)?;
            let mut vault = open_vault(path)?;
            vault.remove_recipient(&label)?;
            println!("Removed recipient '{label}'. Its key file can no longer open this vault.");
            Ok(())
        }
    }
}

fn cmd_agent(
    path: &std::path::Path,
    cmd: AgentCommand,
    hardening: harden::HardenReport,
) -> Result<()> {
    match cmd {
        AgentCommand::Serve { idle_secs, max_secs } => {
            eprintln!(
                "black-bag agent listening at {}",
                session::socket_path()?.display()
            );
            // Host events that must lock the vault: suspend, session lock.
            let (tx, rx) = std::sync::mpsc::channel();
            let watch_state =
                blackbag_core::sleepwatch::spawn(blackbag_core::sleepwatch::WatchConfig::system(), tx);
            session::Agent::new(path.to_path_buf(), idle_secs)
                .with_max_session_secs(max_secs)
                .with_hardening(hardening)
                .with_lock_signals(rx, watch_state)
                .serve()
        }
        AgentCommand::Unlock => {
            let passphrase = tty::read_passphrase("Master passphrase: ")?;
            match session::ask(&Request::Unlock { passphrase })? {
                Response::Status(status) => {
                    println!("{}", serde_json::to_string_pretty(&status)?);
                    Ok(())
                }
                Response::Error { message } => bail!("{message}"),
                _ => bail!("unexpected reply"),
            }
        }
        AgentCommand::Lock => match session::ask(&Request::Lock)? {
            Response::Ok => {
                println!("Locked.");
                Ok(())
            }
            Response::Error { message } => bail!("{message}"),
            _ => bail!("unexpected reply"),
        },
        AgentCommand::Status => match session::ask(&Request::Status)? {
            Response::Status(status) => {
                println!("{}", serde_json::to_string_pretty(&status)?);
                Ok(())
            }
            Response::Error { message } => bail!("{message}"),
            _ => bail!("unexpected reply"),
        },
        AgentCommand::Stop => match session::ask(&Request::Shutdown)? {
            Response::Ok => {
                println!("Agent stopped.");
                Ok(())
            }
            Response::Error { message } => bail!("{message}"),
            _ => bail!("unexpected reply"),
        },

        AgentCommand::List { json, kind, query } => {
            let request = Request::List {
                kind: kind.map(|k| k.to_string()),
                query,
            };
            match session::ask(&request)? {
                Response::Records { records } => {
                    if json {
                        println!("{}", serde_json::to_string(&records)?);
                    } else {
                        for record in &records {
                            println!(
                                "{}  {:<8}  {}",
                                record.id,
                                record.kind,
                                record.title.as_deref().unwrap_or("(untitled)")
                            );
                        }
                    }
                    Ok(())
                }
                Response::Error { message } => bail!("{message}"),
                _ => bail!("unexpected reply"),
            }
        }

        AgentCommand::Reveal {
            id,
            field,
            sink,
            clear_after,
        } => {
            let request = Request::Reveal {
                id: id.to_string(),
                field: field.clone(),
            };
            match session::ask(&request)? {
                Response::Secret { value } => {
                    // `value` arrives wrapped, so it is wiped when this scope
                    // ends however the emit path returns.
                    tty::emit_secret(&value, &field, sink, clear_after)?;
                    Ok(())
                }
                Response::Error { message } => bail!("{message}"),
                _ => bail!("unexpected reply"),
            }
        }

        AgentCommand::Show { id, field } => {
            let request = Request::Reveal {
                id: id.to_string(),
                field,
            };
            match session::ask(&request)? {
                Response::Secret { value } => {
                    use std::io::Write;
                    let mut out = std::io::stdout();
                    out.write_all(value.as_bytes())?;
                    out.write_all(b"\n")?;
                    out.flush()?;
                    Ok(())
                }
                Response::Error { message } => bail!("{message}"),
                _ => bail!("unexpected reply"),
            }
        }

        AgentCommand::Add => {
            let draft = read_draft()?;
            match session::ask(&Request::Add { draft })? {
                Response::Saved { id } => {
                    println!("{id}");
                    Ok(())
                }
                Response::Error { message } => bail!("{message}"),
                _ => bail!("unexpected reply"),
            }
        }

        AgentCommand::Edit { id } => {
            let draft = read_draft()?;
            let request = Request::Update {
                id: id.to_string(),
                draft,
            };
            match session::ask(&request)? {
                Response::Saved { id } => {
                    println!("{id}");
                    Ok(())
                }
                Response::Error { message } => bail!("{message}"),
                _ => bail!("unexpected reply"),
            }
        }

        AgentCommand::Delete { id, yes } => {
            if !yes {
                bail!("refusing to delete without --yes");
            }
            match session::ask(&Request::Delete { id: id.to_string() })? {
                Response::Ok => {
                    eprintln!("deleted {id}");
                    Ok(())
                }
                Response::Error { message } => bail!("{message}"),
                _ => bail!("unexpected reply"),
            }
        }

        AgentCommand::Hygiene { json } => {
            match session::ask(&Request::Hygiene)? {
                Response::Hygiene(report) => {
                    if json {
                        // Handles plus titles: as sensitive as the open vault.
                        println!("{}", serde_json::to_string(&report)?);
                    } else {
                        println!("{}", blackbag_core::hygiene::summary_line(&report));
                        for record in &report.records {
                            println!(
                                "  {}  {:<8}  {}",
                                record.id,
                                record.kind,
                                record.title.as_deref().unwrap_or("(untitled)")
                            );
                            for issue in &record.issues {
                                println!("      [{}] {}", issue.severity(), issue.describe());
                            }
                        }
                    }
                    Ok(())
                }
                Response::Error { message } => bail!("{message}"),
                _ => bail!("unexpected reply"),
            }
        }

        AgentCommand::Breach { online, json } => cmd_breach(online, json),

        AgentCommand::Totp {
            id,
            sink,
            clear_after,
        } => {
            match session::ask(&Request::TotpCode { id: id.to_string() })? {
                Response::Totp {
                    code,
                    ttl_secs,
                    step,
                } => {
                    match sink {
                        Some(sink) => {
                            tty::emit_secret(&code, "code", sink, clear_after)?;
                        }
                        None => println!(
                            "{}",
                            serde_json::json!({ "code": code, "ttl_secs": ttl_secs, "step": step })
                        ),
                    }
                    Ok(())
                }
                Response::Error { message } => bail!("{message}"),
                _ => bail!("unexpected reply"),
            }
        }
    }
}

/// The breach check. Three round trips: prefixes out of the agent, buckets in
/// from the service through curl, buckets into the agent for matching.
fn cmd_breach(online: bool, json: bool) -> Result<()> {
    use blackbag_core::breach;

    if !online {
        eprintln!(
            "black-bag agent breach asks {} (Have I Been Pwned) about your passwords by \
             k-anonymity.\n\n\
             What leaves this machine: the first {} hex characters of the SHA-1 of each \
             distinct password — each naming a bucket of about a thousand leaked hashes — \
             padded with random decoys to a multiple of {} and shuffled, one HTTPS request \
             each, plus your IP address, the time, and the user agent black-bag/{}.\n\n\
             What does not: the full hash, which never leaves the agent; which password you \
             hold; whether anything matched; which of the prefixes were real; and, to within \
             {}, how many passwords you have.\n\n\
             Re-run with --online to consent.",
            breach::RANGE_URL,
            breach::PREFIX_LEN,
            breach::PAD_TO,
            env!("CARGO_PKG_VERSION"),
            breach::PAD_TO
        );
        std::process::exit(2);
    }
    if which("curl").is_none() {
        bail!("curl is required for the breach check and was not found on PATH");
    }

    let candidates = match session::ask(&Request::BreachPrefixes)? {
        Response::BreachPrefixes { candidates } => candidates,
        Response::Error { message } => bail!("{message}"),
        _ => bail!("unexpected reply"),
    };
    let real = breach::distinct_prefixes(&candidates);
    // Padded with decoys and shuffled, so the request count does not report
    // how many distinct passwords the vault holds and the order does not
    // sort them. A bucket that belongs to no real prefix is never consulted.
    let prefixes = breach::padded_prefixes(&real);
    if prefixes.is_empty() {
        if json {
            println!("{}", serde_json::to_string(&breach::Report::default())?);
        } else {
            println!("no password fields to check");
        }
        return Ok(());
    }

    let mut ranges = Vec::with_capacity(prefixes.len());
    let mut failures = Vec::new();
    for prefix in &prefixes {
        let url = format!("{}{}", breach::RANGE_URL, prefix);
        let output = std::process::Command::new("curl")
            .args([
                // First, or it does not suppress ~/.curlrc at all.
                "-q",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "20",
                // The user's own curlrc is not part of this program's
                // behaviour. An `-o` line in it would send the body to a file
                // and leave stdout empty, which parsed as an empty bucket and
                // therefore as "checked, and your password is not in it".
                // `-q` has to come first to take effect.
                "--proto",
                "=https",
                "--noproxy",
                "*",
                "--header",
                "Add-Padding: true",
                "--user-agent",
                concat!("black-bag/", env!("CARGO_PKG_VERSION")),
                &url,
            ])
            .output()
            .context("failed to run curl")?;
        if !output.status.success() {
            failures.push(format!(
                "{prefix}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
            continue;
        }
        let body = String::from_utf8_lossy(&output.stdout);
        let range = breach::parse_range(prefix, &body);
        // With Add-Padding a real bucket is never empty, so an empty one
        // means the body did not arrive — not that nothing matched.
        if range.suffixes.is_empty() {
            failures.push(format!("{prefix}: empty response"));
            continue;
        }
        ranges.push(range);
    }

    let report = match session::ask(&Request::BreachMatch { ranges })? {
        Response::Breach(report) => report,
        Response::Error { message } => bail!("{message}"),
        _ => bail!("unexpected reply"),
    };

    if json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!(
            "checked {} password field(s) against {} bucket(s); {} exposed{}",
            report.checked,
            real.len(),
            report.exposed.len(),
            if report.unchecked > 0 {
                format!("; {} not checked (fetch failed)", report.unchecked)
            } else {
                String::new()
            }
        );
        for exposure in &report.exposed {
            println!(
                "  {}  {:<28}  {} seen in {} breach(es)",
                exposure.id,
                exposure.title.as_deref().unwrap_or("(untitled)"),
                exposure.field,
                exposure.breaches
            );
        }
    }
    for failure in &failures {
        eprintln!("fetch failed for prefix {failure}");
    }
    if !failures.is_empty() && report.exposed.is_empty() {
        bail!("some buckets could not be fetched; the result is incomplete");
    }
    Ok(())
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
    })
}

fn cmd_doctor(
    path: &std::path::Path,
    args: DoctorArgs,
    hardening: harden::HardenReport,
) -> Result<()> {
    let host = HostPosture::measure().with_harden(hardening);
    let session_view = agent_session_view();
    let status = Status::probe(path, session_view, host);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("vault      {}", status.vault_path);
    println!(
        "present    {}{}",
        status.vault_present,
        status
            .vault_format
            .map(|v| format!(" (format v{v})"))
            .unwrap_or_default()
    );
    if let Some(epoch) = status.epoch {
        println!(
            "epoch      {epoch}{}",
            status
                .witness_epoch
                .map(|w| format!(" (witness {w})"))
                .unwrap_or_default()
        );
    }
    if let Some(kdf) = &status.kdf {
        println!(
            "kdf        {} mem={} KiB time={} lanes={}",
            kdf.algorithm, kdf.mem_cost_kib, kdf.time_cost, kdf.lanes
        );
    }
    for recipient in &status.recipients {
        println!("recipient  {} [{}]", recipient.label, recipient.kind);
    }
    println!(
        "session    {}{}",
        if status.session.unlocked {
            "unlocked"
        } else {
            "locked"
        },
        status
            .session
            .last_lock_reason
            .as_deref()
            .map(|r| format!(" (last lock: {r})"))
            .unwrap_or_default()
    );
    println!(
        "ceiling    {}",
        if status.session.max_session_secs == 0 {
            "off".to_string()
        } else {
            format!("{} s after unlock", status.session.max_session_secs)
        }
    );
    println!(
        "sleep      {}",
        status
            .session
            .sleep_watch
            .as_deref()
            .unwrap_or("no agent reachable; suspend and session lock are not watched")
    );
    println!(
        "mlock      {} (limit {} KiB, {} bytes locked now)",
        if status.host.mlock_working { "working" } else { "FAILED" },
        status.host.memlock_limit_bytes / 1024,
        memlock::locked_bytes()
    );
    println!(
        "arena      {} KiB locked, {} KiB unlocked, {} lock(s) refused",
        status.host.arena_locked_bytes / 1024,
        status.host.arena_unlocked_bytes / 1024,
        status.host.arena_failed_locks
    );
    println!(
        "session key {}  (every resting secret is ciphertext under it)",
        status.host.session_key_backing.as_deref().unwrap_or("unknown")
    );
    println!("coredump   pattern={}", status.host.core_pattern);
    println!(
        "           disabled for this process: {}",
        status.host.core_dumps_disabled
    );
    println!(
        "swap       {}",
        if status.host.swap_devices.is_empty() {
            "none".to_string()
        } else {
            status.host.swap_devices.join(", ")
        }
    );

    println!("\nfindings");
    for finding in &status.findings {
        let marker = match finding.severity {
            blackbag_core::status::Severity::Alert => "!!",
            blackbag_core::status::Severity::Warn => " !",
            blackbag_core::status::Severity::Note => " ·",
            blackbag_core::status::Severity::Ok => " ok",
        };
        println!("  {marker} {:<22} {}", finding.id, finding.title);
        if !finding.detail.is_empty() {
            println!("       {}", finding.detail);
        }
    }
    Ok(())
}

fn cmd_status(
    path: &std::path::Path,
    args: StatusArgs,
    hardening: harden::HardenReport,
) -> Result<()> {
    let host = HostPosture::measure().with_harden(hardening);
    let status = Status::probe(path, agent_session_view(), host);
    if args.publish {
        let written = status.publish()?;
        eprintln!("{}", written.display());
    } else {
        println!("{}", serde_json::to_string_pretty(&status)?);
    }
    Ok(())
}

fn cmd_gen(cmd: GenCommand) -> Result<()> {
    use blackbag_core::generate;
    use std::io::Write;

    let (secret, strength) = match cmd {
        GenCommand::Password {
            length,
            no_lowercase,
            no_uppercase,
            no_digits,
            no_symbols,
            exclude_ambiguous,
        } => {
            let spec = generate::PasswordSpec {
                length,
                lowercase: !no_lowercase,
                uppercase: !no_uppercase,
                digits: !no_digits,
                symbols: !no_symbols,
                exclude_ambiguous,
            };
            (generate::password(&spec)?, generate::strength_of_spec(&spec))
        }
        GenCommand::Passphrase {
            words,
            separator,
            capitalise,
        } => {
            let spec = generate::PassphraseSpec {
                words,
                separator,
                capitalise,
            };
            (
                generate::passphrase(&spec)?,
                generate::strength_of_passphrase(&spec),
            )
        }
        GenCommand::Pin { digits } => (generate::pin(digits)?, generate::strength_of_pin(digits)),
    };

    let value = secret.expose_str()?;
    let mut out = std::io::stdout();
    out.write_all(value.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;

    // stderr, so a pipe gets the secret and nothing else.
    eprintln!(
        "{:.1} bits · {} · {}",
        strength.entropy_bits, strength.label, strength.basis
    );
    Ok(())
}

/// Read a JSON `RecordDraft` from stdin.
///
/// The buffer is zeroized on the way out: a draft holds plaintext secrets, and
/// this process may live long enough for that to matter.
fn read_draft() -> Result<blackbag_core::session::RecordDraft> {
    use std::io::Read;

    let mut raw = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("failed to read the draft from stdin")?;
    if raw.trim().is_empty() {
        bail!("no draft on stdin — pipe a JSON RecordDraft in");
    }
    serde_json::from_str(&raw).context("stdin is not a valid record draft")
}

/// Ask the agent for lock state, tolerating its absence.
fn agent_session_view() -> SessionView {
    match session::ask(&Request::Status) {
        Ok(Response::Status(status)) => SessionView {
            unlocked: status.unlocked,
            method: status.method,
            expires_at: status.expires_at,
            idle_timeout_secs: status.idle_timeout_secs,
            session_ends_at: status.session_ends_at,
            max_session_secs: status.max_session_secs,
            last_lock_reason: status.last_lock_reason.map(|r| r.as_str().to_string()),
            sleep_watch: status.sleep_watch,
        },
        _ => SessionView::default(),
    }
}

fn cmd_import(path: &std::path::Path, args: ImportArgs) -> Result<()> {
    // The export is plaintext; read it into a buffer that is wiped when this
    // function returns, and never keep it longer than the parse.
    let raw = Zeroizing::new(
        std::fs::read_to_string(&args.from)
            .with_context(|| format!("failed to read {}", args.from.display()))?,
    );
    let imported = import::parse(args.format, &raw)?;
    drop(raw);

    let counts = imported.counts_by_kind();
    println!(
        "parsed {} record(s){}",
        imported.records.len(),
        if counts.is_empty() {
            String::new()
        } else {
            format!(
                ": {}",
                counts
                    .iter()
                    .map(|(k, n)| format!("{n} {k}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    );
    for line in &imported.skipped {
        eprintln!("skipped {line}");
    }
    if args.dry_run {
        println!("dry run: nothing written");
        return Ok(());
    }
    if imported.records.is_empty() {
        bail!("nothing to import");
    }

    let _lock = blackbag_core::vault::open_lock(path)?;
    let mut vault = open_vault(path)?;
    let mut added = 0usize;
    for record in imported.records {
        vault.add_record(record)?;
        added += 1;
    }
    vault.save()?;
    println!("imported {added} record(s) into {}", path.display());
    println!("The export file still holds every secret in plaintext. Delete it: shred -u {}", args.from.display());
    Ok(())
}

fn cmd_export(path: &std::path::Path, args: ExportArgs) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if !args.plaintext_ok {
        bail!(
            "an export contains every secret in plaintext; pass --plaintext-ok to say you know, \
             write it to removable media, and shred it when the other tool has read it"
        );
    }
    if args.to.exists() {
        bail!("{} already exists; refusing to overwrite", args.to.display());
    }
    let vault = open_vault(path)?;
    let rendered = import::render(vault.records(), args.format)?;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.to)
        .with_context(|| format!("failed to create {}", args.to.display()))?;
    file.write_all(rendered.as_bytes())?;
    file.sync_all()?;
    println!(
        "wrote {} record(s) to {} (mode 0600, plaintext)",
        vault.records().len(),
        args.to.display()
    );
    println!("When the other tool has imported it: shred -u {}", args.to.display());
    Ok(())
}

fn cmd_migrate(args: MigrateArgs) -> Result<()> {
    if args.to.exists() {
        bail!("{} already exists", args.to.display());
    }
    println!(
        "Reading black-bagg v1 vault at {}",
        args.from.display()
    );
    let passphrase = tty::read_passphrase("Master passphrase for the old vault: ")?;
    let records = migrate::read_v1(&args.from, passphrase.as_bytes())?;
    println!("Recovered {} record(s).", records.len());

    println!("Set the passphrase for the new vault (reusing the old one is fine).");
    let new_passphrase = tty::read_new_passphrase()?;
    Vault::init(
        &args.to,
        new_passphrase.as_bytes(),
        blackbag_core::crypto::DEFAULT_MEM_KIB,
    )?;
    let mut vault = Vault::unlock(&args.to, new_passphrase.as_bytes())?;
    for record in records {
        vault.add_record(record)?;
    }
    vault.save()?;
    println!("Wrote {} ({} records).", args.to.display(), vault.records().len());
    println!("Verify it opens, then destroy the old file.");
    Ok(())
}

mod migrate;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_a_defined_default_secret_set() {
        for kind in Kind::ALL {
            // Must not panic, and kinds that hold no secret must say so with
            // an empty slice rather than a bogus field name.
            let fields = default_secret_fields(kind);
            match kind {
                Kind::Contact | Kind::Totp => assert!(fields.is_empty()),
                _ => assert!(!fields.is_empty(), "{kind} has no default secret field"),
            }
        }
    }

    #[test]
    fn kind_parser_rejects_nonsense() {
        assert!(parse_kind("login").is_ok());
        assert!(parse_kind("not-a-kind").is_err());
    }
}
