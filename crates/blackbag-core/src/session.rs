//! The unlock agent.
//!
//! A cockpit that made you retype a 6-word passphrase for every reveal would
//! not get used, so an agent holds the unlocked vault in page-locked memory
//! behind a unix socket and expires it on a deadline.
//!
//! Three rules hold this together:
//!
//! 1. **The socket is the only door**, it is `0600` inside a `0700` directory,
//!    and every connection is checked with `SO_PEERCRED` — same uid, or the
//!    request is dropped. Directory permissions alone would be enough on a
//!    single-user box; the peer check is what makes it safe when it is not.
//! 2. **Passphrases arrive on the socket or on stdin, never in argv.**
//!    `/proc/<pid>/cmdline` is world-readable, so an argv passphrase is a
//!    passphrase published to every process on the machine.
//! 3. **Secrets leave one at a time, by explicit request.** There is no "dump
//!    the vault" call, because a cockpit never needs one.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::record::{Kind, Record, Secret, TotpAlgorithm, TotpConfig};
use crate::status::{self, HostPosture, SessionView, Status};
use crate::vault::{UnlockMethod, Vault};

/// Default idle timeout. Long enough to work, short enough that a walked-away
/// desk does not stay unlocked.
pub const DEFAULT_IDLE_SECS: u64 = 900;

pub fn socket_path() -> Result<PathBuf> {
    Ok(status::runtime_dir()?.join("agent.sock"))
}

/// What the cockpit can ask for.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness plus lock state.
    Status,
    /// Unlock with the master passphrase.
    Unlock { passphrase: String },
    /// Forget the DEK immediately.
    Lock,
    /// Non-secret metadata for every record.
    List {
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        query: Option<String>,
    },
    /// One record's non-secret metadata.
    Detail { id: String },
    /// One secret field, by name. The only path that returns secret bytes.
    Reveal { id: String, field: String },
    /// Create a record. Secrets travel inside this request, over the socket —
    /// which is exactly why authoring lives here and not behind CLI flags.
    Add { draft: RecordDraft },
    /// Replace a record's contents, keeping its id and created_at.
    Update { id: String, draft: RecordDraft },
    /// Remove a record. Not undoable.
    Delete { id: String },
    /// Local credential hygiene over the whole vault.
    ///
    /// The reply carries per-field handles and record titles, so it is as
    /// sensitive as the open vault itself and travels only over this socket.
    /// It must never be written to status.json — see hygiene.rs.
    Hygiene,
    /// Current TOTP code and its remaining validity.
    TotpCode { id: String },
    /// Push the deadline out; called when the user interacts.
    Touch,
    /// Stop the agent.
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Status(AgentStatus),
    // A struct variant, not a newtype around the Vec: serde's internally
    // tagged representation cannot serialise a newtype variant containing a
    // sequence, and fails at runtime rather than at compile time.
    Records { records: Vec<RecordView> },
    Detail(RecordView),
    Secret { value: String },
    Totp { code: String, ttl_secs: u64, step: u64 },
    Saved { id: String },
    Hygiene(crate::hygiene::VaultReport),
    Ok,
    Error { message: String },
}

/// A record as submitted by a UI.
///
/// Secret values are carried as strings here because this struct only ever
/// exists on the socket, in the agent's own memory, for the duration of one
/// request. It is deliberately NOT reachable from the command line: there is no
/// `--password` flag anywhere in this project, because `/proc/<pid>/cmdline` is
/// world-readable and an argv secret is a published secret.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RecordDraft {
    pub kind: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Open attributes: username, url, issuer, ssid, …
    #[serde(default)]
    pub attributes: Vec<(String, String)>,
    /// Named secret fields. An empty value on Update means "leave this one
    /// alone", so a UI can edit a title without re-typing the password.
    #[serde(default)]
    pub secrets: Vec<(String, String)>,
    #[serde(default)]
    pub totp: Option<TotpDraft>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TotpDraft {
    /// A bare base32 shared secret.
    #[serde(default)]
    pub secret_base32: Option<String>,
    /// A full `otpauth://totp/...` URI, which also supplies issuer, account,
    /// digits, period and algorithm. Takes precedence over the fields below.
    #[serde(default)]
    pub otpauth_uri: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
    #[serde(default)]
    pub digits: Option<u8>,
    #[serde(default)]
    pub step: Option<u64>,
    #[serde(default)]
    pub algorithm: Option<String>,
}

/// Parse an `otpauth://totp/…` URI into a secret plus its parameters.
///
/// Written by hand rather than pulling a URL crate in: the grammar we accept is
/// small, and a 2FA enrolment string is exactly the kind of input that should
/// not be widening the dependency graph of a vault.
pub fn parse_otpauth(uri: &str) -> Result<(Vec<u8>, TotpConfig)> {
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .or_else(|| uri.strip_prefix("otpauth://TOTP/"))
        .ok_or_else(|| anyhow!("not an otpauth://totp/ URI"))?;

    let (label, query) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };

    let label = percent_decode(label);
    // The label is "Issuer:Account" or just "Account".
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_string()), a.trim().to_string()),
        None => (None, label.trim().to_string()),
    };

    let mut secret_b32 = None;
    let mut issuer = label_issuer;
    let mut config = TotpConfig::default();

    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value);
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret_b32 = Some(value),
            "issuer" => issuer = Some(value),
            "digits" => {
                if let Ok(d) = value.parse::<u8>() {
                    config.digits = d;
                }
            }
            "period" => {
                if let Ok(p) = value.parse::<u64>() {
                    config.step = p;
                }
            }
            "algorithm" => {
                config.algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    _ => TotpAlgorithm::Sha1,
                }
            }
            _ => {}
        }
    }

    let secret_b32 = secret_b32.ok_or_else(|| anyhow!("otpauth URI has no secret parameter"))?;
    let bytes = decode_base32(&secret_b32)?;

    config.issuer = issuer;
    config.account = if account.is_empty() { None } else { Some(account) };
    if !(6..=8).contains(&config.digits) {
        bail!("otpauth URI requests {} digits; 6-8 supported", config.digits);
    }
    if config.step == 0 {
        bail!("otpauth URI requests a zero period");
    }
    Ok((bytes, config))
}

/// Tolerant base32: strips spaces and hyphens, ignores case and padding, which
/// is how these secrets are actually printed on enrolment pages.
pub fn decode_base32(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .collect::<String>()
        .to_ascii_uppercase();
    if cleaned.is_empty() {
        bail!("secret is empty");
    }
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
        .ok_or_else(|| anyhow!("secret is not valid base32"))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl RecordDraft {
    /// Build a brand-new record.
    pub fn into_record(self) -> Result<Record> {
        let kind: Kind = self.kind.parse()?;
        let mut record = Record::new(kind, self.title.clone());
        self.apply_to(&mut record)?;
        Ok(record)
    }

    /// Apply this draft over an existing record, preserving id and created_at.
    ///
    /// A secret submitted as an empty string is left untouched, so a UI can
    /// present an edit form without ever holding the current password.
    pub fn apply_to(&self, record: &mut Record) -> Result<()> {
        let kind: Kind = self.kind.parse()?;
        record.kind = kind;
        record.title = self.title.clone();
        record.tags = self.tags.clone();
        record.attributes = self.attributes.clone();

        for (name, value) in &self.secrets {
            if name.trim().is_empty() {
                bail!("a secret field must have a name");
            }
            if value.is_empty() {
                continue;
            }
            record.set_field(name, Secret::from_str(value));
        }

        // A field the draft no longer lists is a field the user removed.
        let kept: HashSet<&str> = self
            .secrets
            .iter()
            .map(|(n, _)| n.as_str())
            .chain(self.totp.is_some().then_some("totp"))
            .collect();
        record.fields.retain(|f| kept.contains(f.name.as_str()));

        match &self.totp {
            Some(totp) => {
                let (bytes, mut config) = if let Some(uri) = totp
                    .otpauth_uri
                    .as_deref()
                    .filter(|u| !u.trim().is_empty())
                {
                    parse_otpauth(uri.trim())?
                } else if let Some(b32) = totp
                    .secret_base32
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                {
                    (decode_base32(b32)?, TotpConfig::default())
                } else if record.field("totp").is_some() {
                    // Editing a TOTP record without re-entering the secret.
                    let existing = record
                        .totp
                        .clone()
                        .unwrap_or_default();
                    (record.field("totp").unwrap().as_bytes().to_vec(), existing)
                } else {
                    bail!("a TOTP record needs a secret or an otpauth:// URI");
                };

                if let Some(v) = &totp.issuer {
                    if !v.is_empty() {
                        config.issuer = Some(v.clone());
                    }
                }
                if let Some(v) = &totp.account {
                    if !v.is_empty() {
                        config.account = Some(v.clone());
                    }
                }
                if let Some(d) = totp.digits {
                    config.digits = d;
                }
                if let Some(s) = totp.step {
                    config.step = s;
                }
                if let Some(a) = &totp.algorithm {
                    config.algorithm = match a.to_ascii_uppercase().as_str() {
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        _ => TotpAlgorithm::Sha1,
                    };
                }

                record.set_field("totp", Secret::new(&bytes));
                record.totp = Some(config);
            }
            None => {
                record.totp = None;
            }
        }

        record.updated_at = Utc::now();
        record.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub unlocked: bool,
    pub method: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub idle_timeout_secs: u64,
    pub record_count: usize,
    pub counts_by_kind: Vec<(String, usize)>,
    pub rollback_suspected: bool,
}

/// A record as the cockpit sees it: everything except the secret bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordView {
    pub id: String,
    pub kind: String,
    pub title: Option<String>,
    pub tags: Vec<String>,
    pub attributes: Vec<(String, String)>,
    /// Field names plus a non-reversible handle, so the UI can show that a
    /// secret exists — and whether two entries share one — without holding it.
    pub secret_fields: Vec<SecretFieldView>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub has_totp: bool,
    pub totp_digits: Option<u8>,
    pub totp_step: Option<u64>,
    pub totp_issuer: Option<String>,
    pub totp_account: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFieldView {
    pub name: String,
    pub handle: String,
    pub bytes: usize,
}

impl RecordView {
    pub fn of(record: &Record) -> Self {
        Self {
            id: record.id.to_string(),
            kind: record.kind.to_string(),
            title: record.title.clone(),
            tags: record.tags.clone(),
            attributes: record.attributes.clone(),
            secret_fields: record
                .fields
                .iter()
                .map(|f| SecretFieldView {
                    name: f.name.clone(),
                    handle: f.secret.handle(&f.name),
                    bytes: f.secret.len(),
                })
                .collect(),
            created_at: record.created_at,
            updated_at: record.updated_at,
            has_totp: record.totp.is_some(),
            totp_digits: record.totp.as_ref().map(|t| t.digits),
            totp_step: record.totp.as_ref().map(|t| t.step),
            totp_issuer: record.totp.as_ref().and_then(|t| t.issuer.clone()),
            totp_account: record.totp.as_ref().and_then(|t| t.account.clone()),
        }
    }
}

/// The agent process.
pub struct Agent {
    vault_path: PathBuf,
    idle: Duration,
    open: Option<OpenVault>,
    shutdown_requested: bool,
    /// What hardening this process actually achieved. Without it the agent
    /// published a default report and the cockpit raised a CORE_DUMPS finding
    /// against a process that had in fact disabled them.
    hardening: crate::harden::HardenReport,
}

struct OpenVault {
    vault: Vault,
    deadline: Instant,
    method: UnlockMethod,
}

impl Agent {
    pub fn new(vault_path: PathBuf, idle_secs: u64) -> Self {
        Self {
            vault_path,
            idle: Duration::from_secs(idle_secs.max(30)),
            open: None,
            shutdown_requested: false,
            hardening: crate::harden::HardenReport::default(),
        }
    }

    /// Record what `harden_process` achieved, so `status.json` reports this
    /// process rather than an unmeasured default.
    pub fn with_hardening(mut self, report: crate::harden::HardenReport) -> Self {
        self.hardening = report;
        self
    }

    /// Serve until shutdown. Publishes status on every state change so the bar
    /// widget tracks the lock state without polling the agent.
    pub fn serve(mut self) -> Result<()> {
        let path = socket_path()?;
        let dir = path
            .parent()
            .ok_or_else(|| anyhow!("bad socket path"))?
            .to_path_buf();
        std::fs::create_dir_all(&dir)?;
        status::set_owner_only(&dir)?;

        if path.exists() {
            // A live agent owns it; a dead one left it behind.
            if UnixStream::connect(&path).is_ok() {
                bail!("an agent is already running at {}", path.display());
            }
            std::fs::remove_file(&path)?;
        }

        let listener = UnixListener::bind(&path)
            .with_context(|| format!("failed to bind {}", path.display()))?;
        set_socket_mode(&path)?;
        listener.set_nonblocking(true)?;

        self.publish()?;

        loop {
            self.expire_if_idle()?;
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false)?;
                    if let Err(e) = self.handle(stream) {
                        eprintln!("black-bag agent: {e}");
                    }
                    if self.shutdown_requested {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(120));
                }
                Err(e) => return Err(e.into()),
            }
        }

        let _ = std::fs::remove_file(&path);
        self.open = None;
        self.publish()?;
        Ok(())
    }

    fn handle(&mut self, stream: UnixStream) -> Result<()> {
        // Rule 1: prove the peer is us before reading a single byte of request.
        let peer = peer_uid(&stream)?;
        if peer != unsafe { libc::getuid() } {
            bail!("rejected connection from uid {peer}");
        }

        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => self.dispatch(request),
            Err(e) => Response::Error {
                message: format!("malformed request: {e}"),
            },
        };
        line.zeroize();

        let mut out = stream;
        serde_json::to_writer(&mut out, &response)?;
        out.write_all(b"\n")?;
        out.flush()?;
        Ok(())
    }

    fn dispatch(&mut self, request: Request) -> Response {
        match self.dispatch_inner(request) {
            Ok(response) => response,
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        }
    }

    fn dispatch_inner(&mut self, request: Request) -> Result<Response> {
        match request {
            Request::Status => Ok(Response::Status(self.status_snapshot())),

            Request::Unlock { passphrase } => {
                let passphrase = Zeroizing::new(passphrase);
                let vault = Vault::unlock(&self.vault_path, passphrase.as_bytes())?;
                let method = vault.unlocked_by;
                self.open = Some(OpenVault {
                    vault,
                    deadline: Instant::now() + self.idle,
                    method,
                });
                self.publish()?;
                Ok(Response::Status(self.status_snapshot()))
            }

            Request::Lock => {
                self.open = None;
                self.publish()?;
                Ok(Response::Ok)
            }

            Request::Touch => {
                self.touch();
                Ok(Response::Status(self.status_snapshot()))
            }

            Request::List { kind, query } => {
                let kind = kind.map(|k| k.parse::<Kind>()).transpose()?;
                let open = self.opened()?;
                let views = open
                    .vault
                    .records()
                    .iter()
                    .filter(|r| kind.is_none_or(|k| r.kind == k))
                    .filter(|r| query.as_deref().is_none_or(|q| r.matches(q)))
                    .map(RecordView::of)
                    .collect();
                Ok(Response::Records { records: views })
            }

            Request::Detail { id } => {
                let id: Uuid = id.parse().context("invalid record id")?;
                let open = self.opened()?;
                let record = open
                    .vault
                    .get(id)
                    .ok_or_else(|| anyhow!("record not found"))?;
                Ok(Response::Detail(RecordView::of(record)))
            }

            Request::Reveal { id, field } => {
                let id: Uuid = id.parse().context("invalid record id")?;
                let open = self.opened()?;
                let record = open
                    .vault
                    .get(id)
                    .ok_or_else(|| anyhow!("record not found"))?;
                let secret = record
                    .field(&field)
                    .ok_or_else(|| anyhow!("no field named {field}"))?;
                Ok(Response::Secret {
                    value: secret.expose_str()?,
                })
            }

            Request::TotpCode { id } => {
                let id: Uuid = id.parse().context("invalid record id")?;
                let open = self.opened()?;
                let record = open
                    .vault
                    .get(id)
                    .ok_or_else(|| anyhow!("record not found"))?;
                let (code, ttl, step) = totp_now(record)?;
                Ok(Response::Totp {
                    code,
                    ttl_secs: ttl,
                    step,
                })
            }

            Request::Add { draft } => {
                let record = draft.into_record()?;
                let id = record.id;
                let open = self.opened()?;
                open.vault.add_record(record)?;
                open.vault.save()?;
                self.publish()?;
                Ok(Response::Saved { id: id.to_string() })
            }

            Request::Update { id, draft } => {
                let id: Uuid = id.parse().context("invalid record id")?;
                let open = self.opened()?;
                let record = open
                    .vault
                    .get_mut(id)
                    .ok_or_else(|| anyhow!("record not found"))?;
                draft.apply_to(record)?;
                open.vault.save()?;
                self.publish()?;
                Ok(Response::Saved { id: id.to_string() })
            }

            Request::Delete { id } => {
                let id: Uuid = id.parse().context("invalid record id")?;
                let open = self.opened()?;
                open.vault.remove_record(id)?;
                open.vault.save()?;
                self.publish()?;
                Ok(Response::Ok)
            }

            Request::Hygiene => {
                let open = self.opened()?;
                let report = crate::hygiene::analyse(open.vault.records(), Utc::now());
                Ok(Response::Hygiene(report))
            }

            Request::Shutdown => {
                self.shutdown_requested = true;
                self.open = None;
                Ok(Response::Ok)
            }
        }
    }

    fn opened(&mut self) -> Result<&mut OpenVault> {
        self.expire_if_idle()?;

        // Pick up anything the CLI wrote while we were holding the vault. Every
        // mutation here saves immediately, so there is never unsaved work to
        // lose by re-reading — and without this the next save would silently
        // overwrite the other writer's records.
        let rekeyed = match self.open.as_mut() {
            Some(open) => match open.vault.refresh() {
                Ok(_) => false,
                // The data key no longer opens the file: somebody re-keyed it.
                // Holding a stale key would be worse than making them unlock.
                Err(_) => true,
            },
            None => false,
        };
        if rekeyed {
            self.open = None;
            self.publish()?;
            bail!("the vault was re-keyed by another process; unlock again");
        }

        self.touch();
        self.open.as_mut().ok_or_else(|| anyhow!("vault is locked"))
    }

    fn touch(&mut self) {
        let idle = self.idle;
        if let Some(open) = self.open.as_mut() {
            open.deadline = Instant::now() + idle;
        }
    }

    fn expire_if_idle(&mut self) -> Result<()> {
        let expired = self
            .open
            .as_ref()
            .is_some_and(|open| Instant::now() >= open.deadline);
        if expired {
            self.open = None;
            self.publish()?;
        }
        Ok(())
    }

    fn status_snapshot(&self) -> AgentStatus {
        match &self.open {
            Some(open) => {
                let remaining = open.deadline.saturating_duration_since(Instant::now());
                AgentStatus {
                    unlocked: true,
                    method: Some(method_str(open.method).into()),
                    expires_at: Some(
                        Utc::now()
                            + ChronoDuration::seconds(remaining.as_secs().min(i64::MAX as u64) as i64),
                    ),
                    idle_timeout_secs: self.idle.as_secs(),
                    record_count: open.vault.records().len(),
                    counts_by_kind: open
                        .vault
                        .counts_by_kind()
                        .into_iter()
                        .map(|(k, n)| (k.to_string(), n))
                        .collect(),
                    rollback_suspected: open.vault.rollback_suspected,
                }
            }
            None => AgentStatus {
                unlocked: false,
                method: None,
                expires_at: None,
                idle_timeout_secs: self.idle.as_secs(),
                record_count: 0,
                counts_by_kind: Vec::new(),
                rollback_suspected: false,
            },
        }
    }

    /// Refresh `status.json`. Note what is NOT copied across: record counts stay
    /// in the socket response and never reach the file.
    fn publish(&self) -> Result<()> {
        let snapshot = self.status_snapshot();
        let view = SessionView {
            unlocked: snapshot.unlocked,
            method: snapshot.method.clone(),
            expires_at: snapshot.expires_at,
            idle_timeout_secs: snapshot.idle_timeout_secs,
        };
        Status::probe(
            &self.vault_path,
            view,
            HostPosture::measure().with_harden(self.hardening),
        )
        .publish()?;
        Ok(())
    }
}

fn method_str(method: UnlockMethod) -> &'static str {
    match method {
        UnlockMethod::Passphrase => "passphrase",
        UnlockMethod::RecoveryKey => "recovery-key",
    }
}

/// Current TOTP code plus seconds until it rolls.
pub fn totp_now(record: &Record) -> Result<(String, u64, u64)> {
    use totp_rs::{Algorithm, TOTP};

    let config = record
        .totp
        .as_ref()
        .ok_or_else(|| anyhow!("record has no TOTP configuration"))?;
    let secret = record
        .field("totp")
        .ok_or_else(|| anyhow!("record has no TOTP secret"))?;
    let algorithm = match config.algorithm {
        crate::record::TotpAlgorithm::Sha1 => Algorithm::SHA1,
        crate::record::TotpAlgorithm::Sha256 => Algorithm::SHA256,
        crate::record::TotpAlgorithm::Sha512 => Algorithm::SHA512,
    };
    let totp = TOTP::new(
        algorithm,
        usize::from(config.digits),
        config.skew,
        config.step,
        secret.as_bytes().to_vec(),
    )
    .map_err(|e| anyhow!("invalid TOTP configuration: {e}"))?;
    let code = totp.generate_current()?;
    let ttl = totp.ttl()?;
    Ok((code, ttl, config.step))
}

fn set_socket_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict {}", path.display()))
}

/// uid of the connected peer, via `SO_PEERCRED`.
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use std::os::unix::io::AsRawFd;

    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("SO_PEERCRED failed");
    }
    Ok(cred.uid)
}

/// Client side: one request, one response.
pub fn ask(request: &Request) -> Result<Response> {
    let path = socket_path()?;
    let mut stream = UnixStream::connect(&path)
        .with_context(|| format!("no agent listening at {}", path.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    serde_json::to_writer(&mut stream, request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        bail!("agent closed the connection without replying");
    }
    Ok(serde_json::from_str(&line)?)
}

/// Whether an agent is currently listening.
pub fn agent_running() -> bool {
    socket_path()
        .ok()
        .is_some_and(|p| UnixStream::connect(p).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Kind, Record, Secret, TotpConfig};

    #[test]
    fn record_view_carries_handles_not_secrets() {
        let mut record = Record::new(Kind::Login, Some("GitHub".into()));
        record.set_attribute("username", "octocat");
        record.set_field("password", Secret::from_str("UNIQUE-SECRET-VALUE"));

        let view = RecordView::of(&record);
        let json = serde_json::to_string(&view).unwrap();

        assert!(
            !json.contains("UNIQUE-SECRET-VALUE"),
            "RecordView leaked the secret: {json}"
        );
        assert_eq!(view.secret_fields.len(), 1);
        assert_eq!(view.secret_fields[0].name, "password");
        assert_eq!(view.secret_fields[0].handle.len(), 8);
        assert_eq!(view.secret_fields[0].bytes, "UNIQUE-SECRET-VALUE".len());
    }

    #[test]
    fn totp_produces_a_code_of_the_configured_width() {
        let mut record = Record::new(Kind::Totp, Some("Example".into()));
        // RFC 6238 style base32 secret, decoded.
        let secret = base32::decode(
            base32::Alphabet::Rfc4648 { padding: false },
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        )
        .unwrap();
        record.set_field("totp", Secret::new(&secret));
        record.totp = Some(TotpConfig {
            digits: 8,
            ..TotpConfig::default()
        });

        let (code, ttl, step) = totp_now(&record).unwrap();
        assert_eq!(code.len(), 8);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(step, 30);
        assert!(ttl <= 30);
    }

    #[test]
    fn totp_on_a_record_without_one_is_an_error() {
        let record = Record::new(Kind::Note, None);
        assert!(totp_now(&record).is_err());
    }

    /// Every `Response` variant must survive the wire.
    ///
    /// `#[serde(tag = "result")]` cannot serialise a newtype variant wrapping a
    /// sequence — it compiles and then fails at runtime with "cannot serialize
    /// tagged newtype variant". That is how `Records(Vec<_>)` shipped broken,
    /// so every variant is exercised here rather than trusted.
    #[test]
    fn every_response_variant_survives_json() {
        let record = Record::new(Kind::Login, Some("GitHub".into()));
        let view = RecordView::of(&record);
        let status = AgentStatus {
            unlocked: true,
            method: Some("passphrase".into()),
            expires_at: None,
            idle_timeout_secs: 900,
            record_count: 1,
            counts_by_kind: vec![("login".into(), 1)],
            rollback_suspected: false,
        };

        let variants = vec![
            Response::Status(status),
            Response::Records {
                records: vec![view.clone()],
            },
            Response::Detail(view),
            Response::Secret {
                value: "s".into(),
            },
            Response::Totp {
                code: "123456".into(),
                ttl_secs: 12,
                step: 30,
            },
            Response::Ok,
            Response::Error {
                message: "nope".into(),
            },
        ];

        for variant in &variants {
            let line = serde_json::to_string(variant)
                .unwrap_or_else(|e| panic!("{variant:?} failed to serialise: {e}"));
            assert!(line.contains("\"result\""), "missing tag in {line}");
            let _: Response = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("{line} failed to deserialise: {e}"));
        }
    }

    // ── otpauth:// ──────────────────────────────────────────────────────────

    const B32: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    #[test]
    fn otpauth_parses_a_standard_enrolment_uri() {
        let uri = format!(
            "otpauth://totp/GitHub:octocat?secret={B32}&issuer=GitHub&digits=8&period=60&algorithm=SHA256"
        );
        let (bytes, config) = parse_otpauth(&uri).unwrap();
        assert_eq!(bytes, decode_base32(B32).unwrap());
        assert_eq!(config.issuer.as_deref(), Some("GitHub"));
        assert_eq!(config.account.as_deref(), Some("octocat"));
        assert_eq!(config.digits, 8);
        assert_eq!(config.step, 60);
        assert_eq!(config.algorithm, TotpAlgorithm::Sha256);
    }

    #[test]
    fn otpauth_defaults_match_the_common_case() {
        let uri = format!("otpauth://totp/octocat?secret={B32}");
        let (_, config) = parse_otpauth(&uri).unwrap();
        assert_eq!(config.digits, 6);
        assert_eq!(config.step, 30);
        assert_eq!(config.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(config.account.as_deref(), Some("octocat"));
        assert!(config.issuer.is_none());
    }

    #[test]
    fn otpauth_decodes_percent_escapes_in_the_label() {
        let uri = format!("otpauth://totp/Big%20Corp:a%40b.com?secret={B32}");
        let (_, config) = parse_otpauth(&uri).unwrap();
        assert_eq!(config.issuer.as_deref(), Some("Big Corp"));
        assert_eq!(config.account.as_deref(), Some("a@b.com"));
    }

    #[test]
    fn otpauth_query_issuer_overrides_the_label() {
        let uri = format!("otpauth://totp/Stale:octocat?secret={B32}&issuer=Fresh");
        let (_, config) = parse_otpauth(&uri).unwrap();
        assert_eq!(config.issuer.as_deref(), Some("Fresh"));
    }

    #[test]
    fn otpauth_rejects_what_it_cannot_honour() {
        assert!(parse_otpauth("https://example.com").is_err());
        assert!(parse_otpauth("otpauth://totp/x").is_err(), "no secret");
        assert!(parse_otpauth("otpauth://totp/x?secret=!!!!").is_err(), "bad base32");
        assert!(
            parse_otpauth(&format!("otpauth://totp/x?secret={B32}&digits=9")).is_err(),
            "9 digits is out of range"
        );
        assert!(
            parse_otpauth(&format!("otpauth://totp/x?secret={B32}&period=0")).is_err(),
            "a zero period would divide by zero"
        );
    }

    #[test]
    fn base32_tolerates_how_secrets_are_actually_printed() {
        let spaced = decode_base32("jbsw y3dp-ehpk 3pxp").unwrap();
        let plain = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(spaced, plain, "case, spaces and hyphens must not matter");
        assert!(decode_base32("").is_err());
    }

    // ── drafts ──────────────────────────────────────────────────────────────

    fn login_draft() -> RecordDraft {
        RecordDraft {
            kind: "login".into(),
            title: Some("GitHub".into()),
            tags: vec!["dev".into()],
            attributes: vec![("username".into(), "octocat".into())],
            secrets: vec![("password".into(), "hunter2".into())],
            totp: None,
        }
    }

    #[test]
    fn a_draft_becomes_a_record() {
        let record = login_draft().into_record().unwrap();
        assert_eq!(record.kind, Kind::Login);
        assert_eq!(record.title.as_deref(), Some("GitHub"));
        assert_eq!(record.attribute("username"), Some("octocat"));
        assert_eq!(record.field("password").unwrap().expose_str().unwrap(), "hunter2");
    }

    #[test]
    fn editing_keeps_the_identity_of_the_record() {
        let mut record = login_draft().into_record().unwrap();
        let id = record.id;
        let created = record.created_at;

        let mut draft = login_draft();
        draft.title = Some("GitHub (work)".into());
        draft.apply_to(&mut record).unwrap();

        assert_eq!(record.id, id, "an edit must not re-identify the record");
        assert_eq!(record.created_at, created, "created_at is not editable");
        assert_eq!(record.title.as_deref(), Some("GitHub (work)"));
    }

    #[test]
    fn an_empty_secret_leaves_the_stored_one_alone() {
        // This is what lets an edit form exist without ever holding the
        // current password.
        let mut record = login_draft().into_record().unwrap();
        let mut draft = login_draft();
        draft.secrets = vec![("password".into(), String::new())];
        draft.title = Some("renamed".into());
        draft.apply_to(&mut record).unwrap();

        assert_eq!(record.title.as_deref(), Some("renamed"));
        assert_eq!(
            record.field("password").unwrap().expose_str().unwrap(),
            "hunter2",
            "a blank field in the form must not wipe the secret"
        );
    }

    #[test]
    fn dropping_a_field_from_the_draft_removes_it() {
        let mut record = login_draft().into_record().unwrap();
        record.set_field("recovery", Secret::from_str("codes"));
        assert!(record.field("recovery").is_some());

        login_draft().apply_to(&mut record).unwrap();
        assert!(
            record.field("recovery").is_none(),
            "a field the form no longer lists is a field the user deleted"
        );
        assert!(record.field("password").is_some());
    }

    #[test]
    fn a_totp_draft_accepts_a_bare_base32_secret() {
        let draft = RecordDraft {
            kind: "totp".into(),
            title: Some("GitHub 2FA".into()),
            totp: Some(TotpDraft {
                secret_base32: Some(B32.into()),
                issuer: Some("GitHub".into()),
                ..TotpDraft::default()
            }),
            ..RecordDraft::default()
        };
        let record = draft.into_record().unwrap();
        assert!(record.totp.is_some());
        assert_eq!(record.totp.as_ref().unwrap().issuer.as_deref(), Some("GitHub"));
        assert!(totp_now(&record).is_ok(), "the record must produce a code");
    }

    #[test]
    fn a_totp_draft_accepts_an_otpauth_uri() {
        let draft = RecordDraft {
            kind: "totp".into(),
            totp: Some(TotpDraft {
                otpauth_uri: Some(format!("otpauth://totp/GitHub:octocat?secret={B32}&digits=8")),
                ..TotpDraft::default()
            }),
            ..RecordDraft::default()
        };
        let record = draft.into_record().unwrap();
        assert_eq!(record.totp.as_ref().unwrap().digits, 8);
        let (code, _, _) = totp_now(&record).unwrap();
        assert_eq!(code.len(), 8);
    }

    #[test]
    fn a_totp_record_can_be_edited_without_re_entering_the_secret() {
        let draft = RecordDraft {
            kind: "totp".into(),
            totp: Some(TotpDraft {
                secret_base32: Some(B32.into()),
                ..TotpDraft::default()
            }),
            ..RecordDraft::default()
        };
        let mut record = draft.into_record().unwrap();
        let before = totp_now(&record).unwrap().0;

        let edit = RecordDraft {
            kind: "totp".into(),
            title: Some("renamed".into()),
            totp: Some(TotpDraft {
                issuer: Some("GitHub".into()),
                ..TotpDraft::default()
            }),
            ..RecordDraft::default()
        };
        edit.apply_to(&mut record).unwrap();

        assert_eq!(record.title.as_deref(), Some("renamed"));
        assert_eq!(record.totp.as_ref().unwrap().issuer.as_deref(), Some("GitHub"));
        assert_eq!(totp_now(&record).unwrap().0, before, "the secret survived the edit");
    }

    #[test]
    fn a_totp_draft_with_no_secret_at_all_is_refused() {
        let draft = RecordDraft {
            kind: "totp".into(),
            totp: Some(TotpDraft::default()),
            ..RecordDraft::default()
        };
        assert!(draft.into_record().is_err());
    }

    #[test]
    fn an_unknown_kind_is_refused() {
        let mut draft = login_draft();
        draft.kind = "nonsense".into();
        assert!(draft.into_record().is_err());
    }

    #[test]
    fn a_nameless_secret_field_is_refused() {
        let mut draft = login_draft();
        draft.secrets = vec![("  ".into(), "x".into())];
        assert!(draft.into_record().is_err());
    }

    #[test]
    fn a_draft_never_prints_its_secrets_via_debug() {
        // RecordDraft holds raw strings by necessity; make sure nobody has
        // added a Debug that would spill them into a log or panic message.
        let shown = format!("{:?}", login_draft().into_record().unwrap());
        assert!(!shown.contains("hunter2"), "Record Debug leaked: {shown}");
    }

    #[test]
    fn requests_roundtrip_as_json_lines() {
        let request = Request::Reveal {
            id: "1234".into(),
            field: "password".into(),
        };
        let line = serde_json::to_string(&request).unwrap();
        assert!(line.contains("\"op\":\"reveal\""));
        let back: Request = serde_json::from_str(&line).unwrap();
        matches!(back, Request::Reveal { .. });
    }
}
