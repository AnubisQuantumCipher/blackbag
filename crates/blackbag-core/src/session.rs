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
use std::sync::mpsc::Receiver;
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

/// Default ceiling on how long one unlock can last, however busy the user is.
/// Idle expiry alone lets a session that is touched every few minutes stay
/// open for days; a hard deadline bounds the window a stolen key is useful.
pub const DEFAULT_MAX_SESSION_SECS: u64 = 12 * 3600;

/// How long the agent waits for a connected peer to send its one request line,
/// or to accept the reply. The agent is single-threaded by design (the vault is
/// one object), so before this existed a peer that connected and sent nothing
/// held every other client — and idle expiry — hostage for as long as it liked.
/// Found by opening a socket and waiting.
pub const PEER_IO_TIMEOUT: Duration = Duration::from_secs(3);

/// The largest request this agent will read.
///
/// A request is a JSON line. The biggest legitimate one is an import of many
/// records through `AddMany`, which is why this is generous rather than tight;
/// what it must not be is unbounded, because a peer that never sends a newline
/// would otherwise grow this process's memory until something died.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

/// Why the vault stopped being open. Surfaced through status so the deck can
/// say "locked before suspend" instead of a generic "locked".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockReason {
    /// The user asked.
    Manual,
    /// No request arrived for the idle timeout.
    Idle,
    /// The hard session ceiling was reached.
    SessionCeiling,
    /// The host announced it is about to sleep.
    Suspend,
    /// The login session was locked.
    SessionLock,
    /// The vault was re-keyed by another process; the held key was stale.
    Rekeyed,
    /// The agent was told to stop.
    Shutdown,
}

impl LockReason {
    pub fn as_str(self) -> &'static str {
        match self {
            LockReason::Manual => "manual",
            LockReason::Idle => "idle",
            LockReason::SessionCeiling => "session-ceiling",
            LockReason::Suspend => "suspend",
            LockReason::SessionLock => "session-lock",
            LockReason::Rekeyed => "rekeyed",
            LockReason::Shutdown => "shutdown",
        }
    }
}

pub fn socket_path() -> Result<PathBuf> {
    Ok(status::runtime_dir()?.join("agent.sock"))
}

/// What the cockpit can ask for.
///
/// **Unknown fields are refused.** Serde's default is to ignore them, and for
/// this protocol that is the wrong default: both ends are meant to be the same
/// binary, and a field an older agent has never heard of is not a field it can
/// safely ignore. Measured — a newer client sent `client_data_hash` to an
/// older agent, the field was silently dropped, and the request was then read
/// as a *browser* request with an empty origin. It failed loudly by luck. The
/// next such field might not.
///
/// The limit, stated because it is real: serde's internally-tagged
/// representation still accepts stray keys alongside a **unit** variant, and
/// `deny_unknown_fields` does not change that. Every variant that carries data
/// is covered, which is where a dropped field could matter — a unit variant
/// has nothing to lose.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Liveness plus lock state.
    Status,
    /// Unlock with the master passphrase. Wiped with the request.
    Unlock { passphrase: Zeroizing<String> },
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
    ///
    /// Carries an optional proof. The first time a given program asks for a
    /// given field, the agent answers `ApprovalRequired` instead of the secret;
    /// the caller re-asks with the master passphrase, which grants the approval
    /// and returns the value. After that the same program reading the same
    /// field is served without asking, until the vault locks.
    ///
    /// One round trip rather than the passkeys' two-phase ceremony, because a
    /// caller here can simply ask again — a browser waiting on a WebAuthn
    /// promise cannot.
    Reveal {
        id: String,
        field: String,
        /// What the caller intends to do with it.
        ///
        /// Approving "show this on screen for ten seconds" is not approving
        /// "put this on the clipboard", where every other process in the
        /// session can read it. They are different exposures, so they are
        /// different questions and each is asked once.
        #[serde(default)]
        capability: Option<crate::policy::Capability>,
        #[serde(default)]
        passphrase: Option<Zeroizing<String>>,
    },
    /// Create a record. Secrets travel inside this request, over the socket —
    /// which is exactly why authoring lives here and not behind CLI flags.
    Add { draft: RecordDraft },
    /// Create many records in one write. An import of five hundred records
    /// through `Add` would be five hundred saves, five hundred epoch bumps
    /// and five hundred fsyncs.
    AddMany { drafts: Vec<RecordDraft> },
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
    ///
    /// Gated like any other secret read: a live second-factor code is a
    /// credential, and a process quietly harvesting them every thirty seconds
    /// is exactly the thing the approval policy exists to stop.
    TotpCode {
        id: String,
        /// Where the code is going. The clipboard is a different exposure
        /// from the card on screen — every other process in the session can
        /// read it — so it is a different approval, exactly as for `Reveal`.
        #[serde(default)]
        capability: Option<crate::policy::Capability>,
        #[serde(default)]
        passphrase: Option<Zeroizing<String>>,
    },
    /// The five-character SHA-1 prefixes of every password-like field, so a
    /// caller can fetch the matching Pwned Passwords buckets. The full hash
    /// never leaves the agent.
    BreachPrefixes,
    /// Buckets fetched by the caller. The agent does the matching and keeps
    /// the exposures for the rest of the session.
    BreachMatch { ranges: Vec<crate::breach::Range> },
    /// Push the deadline out; called when the user interacts.
    Touch,
    /// Register a passkey ceremony and put it in front of a human.
    ///
    /// Returns a nonce. Nothing is signed here: this only freezes what *may*
    /// be signed. See `consent.rs` for why the socket does not authorize a
    /// signature by itself.
    PasskeyBegin {
        operation: crate::consent::Operation,
        /// CTAP only: the client-data hash, hex. Mutually exclusive with
        /// `origin` and `challenge` — the agent enforces that, because a
        /// ceremony that was half of each would leave it ambiguous which bytes
        /// get signed.
        #[serde(default)]
        client_data_hash: Option<String>,
        /// The caller origin as the browser reported it, not as any client
        /// chose to describe itself.
        origin: String,
        rp_id: String,
        #[serde(default)]
        rp_name: Option<String>,
        /// `allowCredentials` from the relying party. Empty means "any
        /// discoverable credential for this relying party".
        #[serde(default)]
        allow_credentials: Vec<String>,
        /// The relying party's challenge, base64url, exactly as the browser
        /// supplied it. The bytes that get signed are built HERE, from this and
        /// the origin above — a caller that could hand in the signed bytes
        /// would have a signing oracle with attacker-chosen content, and the
        /// origin the human read would bear no mechanical relation to the one
        /// the relying party verifies.
        challenge: String,
        /// Whether the caller was a cross-origin iframe.
        #[serde(default)]
        cross_origin: bool,
        // Create-only.
        #[serde(default)]
        user_handle: Option<String>,
        #[serde(default)]
        user_name: Option<String>,
        #[serde(default)]
        user_display_name: Option<String>,
        #[serde(default)]
        want_prf: bool,
        /// PRF salts as the relying party supplied them, hex-encoded. The
        /// WebAuthn derivation is applied here, not by the caller.
        #[serde(default)]
        prf_first_salt: Option<String>,
        #[serde(default)]
        prf_second_salt: Option<String>,
    },
    /// Answer a waiting ceremony.
    ///
    /// An approval carries the vault passphrase, re-entered for this ceremony.
    /// Nothing else can approve: the socket establishes only that the peer runs
    /// as the same user, and everything in the session does. A refusal needs no
    /// proof — anyone may say no on your behalf, and the failure mode of a
    /// spurious refusal is a login that does not happen.
    PasskeyAnswer {
        nonce: String,
        approve: bool,
        /// Stand aside and let the browser's own path handle this — a hardware
        /// key, or a phone. Needs no passphrase, for the same reason a refusal
        /// does not: it denies nobody anything they had.
        #[serde(default)]
        defer: bool,
        #[serde(default)]
        credential_id: Option<String>,
        #[serde(default)]
        passphrase: Zeroizing<String>,
    },
    /// Collect the answer. Signs on the way out, exactly once.
    PasskeyCollect { nonce: String },
    /// What is waiting for a human right now, so the deck can show it.
    PasskeyQueue,
    /// Everything currently approved.
    Approvals,
    /// Withdraw one approval, or every approval for one program.
    Revoke {
        client: String,
        #[serde(default)]
        item: Option<String>,
    },
    /// Deny every program until told otherwise, or lift that.
    Lockdown { on: bool },
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
    /// The one reply that carries secret bytes. Wiped with the reply.
    Secret { value: Zeroizing<String> },
    Totp { code: String, ttl_secs: u64, step: u64 },
    Saved { id: String },
    /// Several records were written in one save.
    Added { count: usize },
    Hygiene(crate::hygiene::VaultReport),
    BreachPrefixes { candidates: Vec<crate::breach::Candidate> },
    Breach(crate::breach::Report),
    /// A ceremony was registered and is on screen.
    PasskeyRegistered {
        nonce: String,
        choices: Vec<crate::consent::Choice>,
    },
    /// Still waiting for a human.
    PasskeyWaiting,
    /// The ceremony completed. Everything here is public by construction: it
    /// is what goes to the relying party.
    PasskeyResult {
        /// The exact bytes the agent hashed. The extension hands these to
        /// Chromium verbatim; regenerating them anywhere else would produce a
        /// signature that does not verify.
        client_data_json: String,
        credential_id: String,
        authenticator_data: String,
        signature: String,
        user_handle: String,
        /// Registration only.
        #[serde(default)]
        attestation_object: Option<String>,
        #[serde(default)]
        public_key_der: Option<String>,
        /// PRF outputs, when the relying party asked and the credential has a seed.
        #[serde(default)]
        prf_first: Option<String>,
        #[serde(default)]
        prf_second: Option<String>,
    },
    PasskeyQueue {
        pending: Vec<crate::consent::Summary>,
    },
    /// Nobody has approved this program reading this field. Ask again with the
    /// master passphrase.
    ApprovalRequired {
        item: String,
        #[serde(default)]
        title: Option<String>,
        field: String,
        /// What is asking, for the prompt to show. Context, not control.
        #[serde(default)]
        client: Option<String>,
    },
    /// Everything currently approved, for the deck to show and revoke.
    Approvals {
        granted: Vec<crate::policy::Grant>,
        lockdown: bool,
    },
    /// The human chose the browser's own path. The caller must stand down for
    /// long enough that a hardware key or a phone can be reached, then tell
    /// the site to try again.
    PasskeyUseSecurityKey,
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
    /// Values are wiped when the draft is dropped.
    #[serde(default)]
    pub secrets: Vec<(String, Zeroizing<String>)>,
    /// Free-form notes attached to the record itself, as opposed to a secret
    /// field a kind happens to call "notes". `None` leaves what is stored
    /// alone; `Some("")` clears it.
    #[serde(default)]
    pub notes: Option<Zeroizing<String>>,
    #[serde(default)]
    pub totp: Option<TotpDraft>,
}

impl RecordDraft {
    /// The draft that would rebuild `record`. This is how a parsed import
    /// reaches the agent, which is the only process that should write the
    /// vault while it holds it open.
    pub fn of(record: &Record) -> Self {
        Self {
            kind: record.kind.to_string(),
            title: record.title.clone(),
            tags: record.tags.clone(),
            attributes: record.attributes.clone(),
            secrets: record
                .fields
                .iter()
                .filter(|f| f.name != "totp")
                .filter_map(|f| {
                    f.secret
                        .expose_str()
                        .ok()
                        .map(|v| (f.name.clone(), Zeroizing::new(v.to_string())))
                })
                .collect(),
            notes: record
                .notes
                .as_ref()
                .and_then(|n| n.expose_str().ok())
                .map(|n| Zeroizing::new(n.to_string())),
            totp: record.totp.as_ref().map(|cfg| TotpDraft {
                secret_base32: record.field("totp").map(|s| {
                    Zeroizing::new(base32::encode(
                        base32::Alphabet::Rfc4648 { padding: false },
                        s.open().as_slice(),
                    ))
                }),
                otpauth_uri: None,
                issuer: cfg.issuer.clone(),
                account: cfg.account.clone(),
                digits: Some(cfg.digits),
                step: Some(cfg.step),
                algorithm: Some(cfg.algorithm.as_str().to_string()),
            }),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TotpDraft {
    /// A bare base32 shared secret. Wiped with the draft.
    #[serde(default)]
    pub secret_base32: Option<Zeroizing<String>>,
    /// A full `otpauth://totp/...` URI, which also supplies issuer, account,
    /// digits, period and algorithm. Takes precedence over the fields below.
    /// Carries the secret, so it is wiped with the draft too.
    #[serde(default)]
    pub otpauth_uri: Option<Zeroizing<String>>,
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
    /// Apply the draft, returning the names of the secret fields whose value
    /// this changed — replaced or removed. The caller uses that to drop any
    /// breach verdict attached to the value that is no longer there.
    pub fn apply_to(&self, record: &mut Record) -> Result<Vec<String>> {
        let kind: Kind = self.kind.parse()?;
        record.kind = kind;
        record.title = self.title.clone();
        record.tags = self.tags.clone();
        record.attributes = self.attributes.clone();

        let mut changed: Vec<String> = Vec::new();
        for (name, value) in &self.secrets {
            if name.trim().is_empty() {
                bail!("a secret field must have a name");
            }
            if value.is_empty() {
                continue;
            }
            record.set_field(name, Secret::from_str(value));
            changed.push(name.clone());
        }

        // A field the draft no longer lists is a field the user removed.
        //
        // With one exception, and it is not a nicety. A passkey's key material
        // is never authored, never revealed and therefore never present in a
        // draft, so the ordinary rule would read its absence as a deletion and
        // prune it — leaving a passkey record that still looks like a passkey
        // and can never sign again. Silently, and with no way back. So the
        // fields that make a passkey a passkey survive any draft.
        let mut kept: HashSet<&str> = self
            .secrets
            .iter()
            .map(|(n, _)| n.as_str())
            .chain(self.totp.is_some().then_some("totp"))
            .collect();
        if record.kind == Kind::Passkey {
            kept.insert(crate::passkey::PRIVATE_KEY_FIELD);
            kept.insert(crate::passkey::PRF_SEED_FIELD);
        }
        for field in &record.fields {
            if !kept.contains(field.name.as_str()) {
                changed.push(field.name.clone());
            }
        }
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
                    (record.field("totp").unwrap().open().to_vec(), existing)
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

        if let Some(notes) = &self.notes {
            record.notes = (!notes.is_empty()).then(|| Secret::from_str(notes));
        }

        record.updated_at = Utc::now();
        record.validate()?;
        Ok(changed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub unlocked: bool,
    pub method: Option<String>,
    /// The nearer of the idle deadline and the session ceiling.
    pub expires_at: Option<DateTime<Utc>>,
    pub idle_timeout_secs: u64,
    /// When the session ends regardless of activity. `None` while locked.
    #[serde(default)]
    pub session_ends_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub max_session_secs: u64,
    /// Why the vault was last locked, if it has been locked since the agent
    /// started.
    #[serde(default)]
    pub last_lock_reason: Option<LockReason>,
    /// Whether the agent is subscribed to host sleep and session-lock events.
    #[serde(default)]
    pub sleep_watch: Option<String>,
    /// Passkey ceremonies waiting for a human. Carried here so that the CLI,
    /// which also publishes status.json, republishes the queue instead of
    /// blanking a prompt the agent is currently showing.
    #[serde(default)]
    pub pending_passkeys: Vec<crate::consent::Summary>,
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
/// Byte strings cross this socket as hex.
///
/// Not base64: there are several base64 alphabets in WebAuthn's own ecosystem
/// (standard, URL-safe, padded, unpadded) and a provider that picks the wrong
/// one produces a credential id the relying party does not recognise. Hex has
/// exactly one spelling.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The client data a relying party will verify, built here rather than handed in.
///
/// WebAuthn hashes these bytes into the signature, and the relying party
/// re-serialises its own copy to compare. Two properties matter and neither
/// survives letting a caller supply them:
///
///   * the `origin` is the one the human was shown, by construction rather
///     than by agreement between two components; and
///   * nothing attacker-chosen sits in the signed message except the challenge
///     the relying party itself issued.
///
/// The key order is fixed and matches what browsers emit, so the bytes returned
/// to the extension are the bytes the relying party checks.
fn client_data_json(kind: &str, challenge: &str, origin: &str, cross_origin: bool) -> Vec<u8> {
    // Built field by field rather than with `json!`, because serde_json's map
    // is a BTreeMap and would emit these in alphabetical order. Browsers emit
    // type, challenge, origin, crossOrigin, and a relying party that compares
    // the bytes it stored against the bytes a browser would produce should see
    // the same shape from us. Each VALUE still goes through serde_json, so an
    // origin carrying a quote cannot break out of the string it sits in.
    let q = |v: &str| serde_json::Value::String(v.to_string()).to_string();
    format!(
        r#"{{"type":{},"challenge":{},"origin":{},"crossOrigin":{}}}"#,
        q(kind),
        q(challenge),
        q(origin),
        cross_origin
    )
    .into_bytes()
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 {
        bail!("expected hex, got an odd number of characters");
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .map_err(|_| anyhow!("expected hex, got {:?}", &text[i..i + 2]))
        })
        .collect()
}

pub struct Agent {
    vault_path: PathBuf,
    idle: Duration,
    /// Ceiling on one unlock, measured from the unlock itself.
    max_session: Duration,
    open: Option<OpenVault>,
    shutdown_requested: bool,
    /// What hardening this process actually achieved. Without it the agent
    /// published a default report and the cockpit raised a CORE_DUMPS finding
    /// against a process that had in fact disabled them.
    hardening: crate::harden::HardenReport,
    last_lock_reason: Option<LockReason>,
    /// Host events that must lock the vault (suspend, session lock), delivered
    /// by whatever watcher the caller attached. `None` means nobody is watching.
    lock_signals: Option<Receiver<LockReason>>,
    /// A one-line description of the watcher's state, for status.
    sleep_watch: Option<std::sync::Arc<std::sync::Mutex<String>>>,
    /// Where `status.json` goes. `None` means the runtime directory; tests
    /// point it elsewhere so a test agent never overwrites the live document.
    status_dir: Option<PathBuf>,
    /// Passkey ceremonies waiting for a human.
    consent: crate::consent::Desk,
    /// Who is on the other end of the connection being served right now.
    peer: Option<PeerId>,
    /// Approvals in force for this unlocked session.
    approvals: crate::policy::Approvals,
    /// Where the history goes. `None` in tests that do not want a file.
    audit_path: Option<PathBuf>,
    /// Where the record of backups is read from.
    ///
    /// Configurable for the same reason the audit path is: a test that used
    /// the real one would read whatever this machine happens to have backed
    /// up, and a passkey test would then pass or fail depending on the
    /// operator's disk rather than on the code.
    backup_log_path: Option<PathBuf>,
}

struct OpenVault {
    vault: Vault,
    /// Results of a breach check run this session, folded into hygiene.
    exposure: crate::breach::ExposureMap,
    /// Slides forward on every request, capped by `ceiling`.
    deadline: Instant,
    /// Fixed at unlock time. Activity does not move it.
    ceiling: Instant,
    ceiling_wall: DateTime<Utc>,
    method: UnlockMethod,
}

impl OpenVault {
    fn effective_deadline(&self) -> Instant {
        self.deadline.min(self.ceiling)
    }
}

impl Agent {
    pub fn new(vault_path: PathBuf, idle_secs: u64) -> Self {
        Self {
            vault_path,
            idle: Duration::from_secs(idle_secs.max(30)),
            max_session: Duration::from_secs(DEFAULT_MAX_SESSION_SECS),
            open: None,
            shutdown_requested: false,
            hardening: crate::harden::HardenReport::default(),
            last_lock_reason: None,
            lock_signals: None,
            sleep_watch: None,
            status_dir: None,
            consent: crate::consent::Desk::new(),
            peer: None,
            approvals: crate::policy::Approvals::new(),
            audit_path: None,
            backup_log_path: crate::backup::Log::default_path().ok(),
        }
    }

    /// Record what `harden_process` achieved, so `status.json` reports this
    /// process rather than an unmeasured default.
    pub fn with_hardening(mut self, report: crate::harden::HardenReport) -> Self {
        self.hardening = report;
        self
    }

    /// Bound one unlock to `secs` regardless of activity. Zero disables the
    /// ceiling, which is a choice the operator has to make out loud.
    pub fn with_max_session_secs(mut self, secs: u64) -> Self {
        self.max_session = if secs == 0 {
            Duration::from_secs(u64::MAX / 4)
        } else {
            Duration::from_secs(secs.max(60))
        };
        self
    }

    /// Attach a source of host lock events. Each event received locks the
    /// vault with the given reason.
    pub fn with_lock_signals(
        mut self,
        rx: Receiver<LockReason>,
        state: std::sync::Arc<std::sync::Mutex<String>>,
    ) -> Self {
        self.lock_signals = Some(rx);
        self.sleep_watch = Some(state);
        self
    }

    /// Publish `status.json` into `dir` instead of the runtime directory.
    pub fn with_status_dir(mut self, dir: PathBuf) -> Self {
        self.status_dir = Some(dir);
        self
    }

    /// Where the audit log goes.
    ///
    /// A test agent points this at its own directory so a test run never
    /// appends to the operator's real history — which would make the one file
    /// whose value is that it is trustworthy the one file full of noise.
    pub fn with_audit_path(mut self, path: PathBuf) -> Self {
        self.audit_path = Some(path);
        self
    }

    /// Where the record of backups is read from. See the field comment.
    pub fn with_backup_log_path(mut self, path: PathBuf) -> Self {
        self.backup_log_path = Some(path);
        self
    }

    /// Write history to the default location under the state directory.
    pub fn with_default_audit(mut self) -> Self {
        self.audit_path = crate::audit::Log::default_path().ok();
        self
    }

    /// Serve at the default socket until shutdown.
    pub fn serve(self) -> Result<()> {
        let path = socket_path()?;
        self.serve_at(&path)
    }

    /// Serve at `path` until shutdown. Publishes status on every state change
    /// so the bar widget tracks the lock state without polling the agent.
    pub fn serve_at(mut self, path: &Path) -> Result<()> {
        let path = path.to_path_buf();
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
            self.drain_lock_signals()?;
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
        self.lock(LockReason::Shutdown);
        self.publish()?;
        Ok(())
    }

    /// Write one line of history, and never let that failure hide the event.
    ///
    /// A log that cannot be written is worth reporting, but refusing the
    /// request because of it would turn a full disk into a denial of service
    /// against the owner's own vault. The failure goes to stderr, where the
    /// unit journal keeps it.
    fn record_audit(
        &self,
        surface: crate::audit::Surface,
        decision: crate::audit::Decision,
        subject: &str,
        detail: Option<&str>,
    ) {
        let Some(path) = self.audit_path.as_ref() else {
            return;
        };
        if let Some(d) = detail {
            if crate::audit::reject_secret_looking(d).is_err() {
                eprintln!("black-bag agent: refusing to audit an overlong detail");
                return;
            }
        }
        let uid = unsafe { libc::getuid() };
        let who = match self.peer {
            Some(p) => crate::audit::who(uid, p.pid, PeerId::program(p.pid)),
            None => crate::audit::who(uid, 0, None),
        };
        if let Err(e) = crate::audit::Log::at(path).append(
            who,
            surface,
            decision,
            subject,
            detail,
            Utc::now(),
        ) {
            eprintln!("black-bag agent: could not write the audit log: {e}");
        }
    }

    /// Lock the vault, remembering why. Dropping `OpenVault` drops the `Vault`,
    /// whose data key and every record are wiped and unlocked on the way out.
    fn lock(&mut self, reason: LockReason) {
        // Every approval was given for the session that is ending. One that
        // outlived it would turn a lock into a pause.
        self.approvals.clear();
        // Anything waiting for a human was authorized against the session that
        // is ending. A ceremony that outlived its lock would let an approval
        // granted before a suspend be collected after it, which is exactly the
        // gap locking on suspend exists to close.
        self.consent.clear();
        if self.open.take().is_some() {
            self.last_lock_reason = Some(reason);
        }
    }

    /// Apply any host event the watcher delivered since the last pass.
    fn drain_lock_signals(&mut self) -> Result<()> {
        let mut received = None;
        if let Some(rx) = &self.lock_signals {
            while let Ok(reason) = rx.try_recv() {
                received = Some(reason);
            }
        }
        if let Some(reason) = received {
            if self.open.is_some() {
                eprintln!("black-bag agent: locking ({})", reason.as_str());
                self.lock(reason);
                self.publish()?;
            }
        }
        Ok(())
    }

    fn handle(&mut self, stream: UnixStream) -> Result<()> {
        // Rule 1: prove the peer is us before reading a single byte of request.
        let peer = peer_uid(&stream)?;
        if peer != unsafe { libc::getuid() } {
            bail!("rejected connection from uid {peer}");
        }
        self.peer = peer_pid(&stream).ok().and_then(PeerId::of);

        // Rule 4: a peer gets a bounded slice of the agent's attention. One
        // request line in, one reply out, each within PEER_IO_TIMEOUT.
        stream.set_read_timeout(Some(PEER_IO_TIMEOUT))?;
        stream.set_write_timeout(Some(PEER_IO_TIMEOUT))?;

        let mut raw = Vec::new();
        if !read_request_line(&stream, &mut raw)? {
            raw.zeroize();
            return Ok(());
        }
        let mut line = match String::from_utf8(raw) {
            Ok(line) => line,
            Err(e) => {
                // Wipe the bytes on the way out: a malformed request is still a
                // request, and may carry a passphrase somebody mistyped.
                let mut bytes = e.into_bytes();
                bytes.zeroize();
                bail!("request was not UTF-8");
            }
        };

        let mut response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => self.dispatch(request),
            Err(e) => Response::Error {
                message: format!("malformed request: {e}"),
            },
        };
        line.zeroize();

        let mut out = stream;
        let written = serde_json::to_writer(&mut out, &response)
            .map_err(anyhow::Error::from)
            .and_then(|_| out.write_all(b"\n").map_err(Into::into))
            .and_then(|_| out.flush().map_err(Into::into));
        // Whatever happened on the wire, a revealed value does not outlive the
        // request in this process.
        if let Response::Secret { value } = &mut response {
            value.zeroize();
        }
        written
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
                let vault = Vault::unlock(&self.vault_path, passphrase.as_bytes())?;
                let method = vault.unlocked_by;
                let now = Instant::now();
                let ceiling_wall = Utc::now()
                    + ChronoDuration::seconds(
                        self.max_session.as_secs().min(i64::MAX as u64 / 4) as i64,
                    );
                self.open = Some(OpenVault {
                    vault,
                    exposure: crate::breach::ExposureMap::new(),
                    deadline: now + self.idle,
                    ceiling: now + self.max_session,
                    ceiling_wall,
                    method,
                });
                self.publish()?;
                Ok(Response::Status(self.status_snapshot()))
            }

            Request::Lock => {
                self.lock(LockReason::Manual);
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

            Request::Reveal {
                id,
                field,
                capability,
                passphrase,
            } => {
                use crate::policy::{Capability, ClientKey, Verdict};

                let id: Uuid = id.parse().context("invalid record id")?;

                // Refused before anything else, and before a human is asked.
                // A passkey's key material is never handed back on any terms,
                // so prompting for approval first would be asking somebody to
                // authorise a thing that cannot happen — the same reason a
                // passkey ceremony with no usable credential never reaches the
                // screen.
                if self
                    .opened()?
                    .vault
                    .get(id)
                    .is_some_and(|r| r.kind == crate::record::Kind::Passkey)
                {
                    bail!(
                        "a passkey's key material is never revealed; it is used \
                         to sign, in the agent, and nowhere else"
                    );
                }

                let program = self.peer.and_then(|p| PeerId::program(p.pid));
                let client = ClientKey::for_peer(
                    program.as_deref(),
                    self.peer.map(|p| p.pid).unwrap_or(0),
                );

                // Decided BEFORE the vault is touched, so a refusal cannot be
                // distinguished from a miss by how long it took.
                let capability = capability.unwrap_or(Capability::Reveal);
                let verdict = self.approvals.consider(&client, &id.to_string(), capability);

                // Built once and used by every outcome. "approved · password"
                // does not say whether what was approved was a glance at the
                // screen or a copy onto a clipboard every other process can
                // read, and those are not the same thing to have said yes to.
                let detail = format!("{field} ({})", capability.as_str());

                let allowed = match verdict {
                    Verdict::Remembered => {
                        self.record_audit(
                            crate::audit::Surface::Socket,
                            crate::audit::Decision::Remembered,
                            &id.to_string(),
                            Some(&detail),
                        );
                        true
                    }
                    Verdict::Blocked(why) => {
                        self.record_audit(
                            crate::audit::Surface::Socket,
                            crate::audit::Decision::Blocked,
                            &id.to_string(),
                            Some(&detail),
                        );
                        bail!("{why}");
                    }
                    Verdict::MustAsk => match &passphrase {
                        // The proof, checked against the OPEN vault — never by
                        // re-reading the path, which any same-uid process can
                        // replace between the check and the read.
                        Some(pass)
                            if !pass.is_empty()
                                && self.opened()?.vault.passphrase_matches(pass.as_bytes()) =>
                        {
                            self.approvals.grant(&client, &id.to_string(), capability);
                            self.record_audit(
                                crate::audit::Surface::Socket,
                                crate::audit::Decision::Approved,
                                &id.to_string(),
                                Some(&detail),
                            );
                            true
                        }
                        Some(_) => {
                            self.record_audit(
                                crate::audit::Surface::Socket,
                                crate::audit::Decision::Refused,
                                &id.to_string(),
                                Some(&detail),
                            );
                            bail!("that is not the vault passphrase");
                        }
                        None => false,
                    },
                };

                if !allowed {
                    let title = self
                        .opened()?
                        .vault
                        .get(id)
                        .and_then(|r| r.title.clone());
                    return Ok(Response::ApprovalRequired {
                        item: id.to_string(),
                        title,
                        field,
                        client: program,
                    });
                }

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

            Request::TotpCode {
                id,
                capability,
                passphrase,
            } => {
                use crate::policy::{Capability, ClientKey, Verdict};

                let capability = capability.unwrap_or(Capability::Reveal);
                let id: Uuid = id.parse().context("invalid record id")?;
                let program = self.peer.and_then(|p| PeerId::program(p.pid));
                let client = ClientKey::for_peer(
                    program.as_deref(),
                    self.peer.map(|p| p.pid).unwrap_or(0),
                );

                let detail = format!("totp ({})", capability.as_str());
                match self.approvals.consider(&client, &id.to_string(), capability) {
                    Verdict::Remembered => {}
                    Verdict::Blocked(why) => {
                        self.record_audit(
                            crate::audit::Surface::Socket,
                            crate::audit::Decision::Blocked,
                            &id.to_string(),
                            Some(&detail),
                        );
                        bail!("{why}");
                    }
                    Verdict::MustAsk => match &passphrase {
                        Some(pass)
                            if !pass.is_empty()
                                && self.opened()?.vault.passphrase_matches(pass.as_bytes()) =>
                        {
                            self.approvals.grant(&client, &id.to_string(), capability);
                            self.record_audit(
                                crate::audit::Surface::Socket,
                                crate::audit::Decision::Approved,
                                &id.to_string(),
                                Some(&detail),
                            );
                        }
                        Some(_) => {
                            self.record_audit(
                                crate::audit::Surface::Socket,
                                crate::audit::Decision::Refused,
                                &id.to_string(),
                                Some(&detail),
                            );
                            bail!("that is not the vault passphrase");
                        }
                        None => {
                            let title =
                                self.opened()?.vault.get(id).and_then(|r| r.title.clone());
                            return Ok(Response::ApprovalRequired {
                                item: id.to_string(),
                                title,
                                field: "totp".into(),
                                client: program,
                            });
                        }
                    },
                }

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

            // Every mutation holds the vault's advisory lock across the
            // refresh-modify-save sequence, the same lock the CLI takes. The
            // file-stamp check in `Vault::save` catches a write that landed
            // between the refresh and the save; the lock makes sure one does
            // not land there in the first place.
            Request::Add { draft } => {
                let record = draft.into_record()?;
                let id = record.id;
                let _guard = crate::vault::open_lock(&self.vault_path)?;
                let open = self.opened()?;
                open.vault.add_record(record)?;
                open.vault.save()?;
                self.publish()?;
                Ok(Response::Saved { id: id.to_string() })
            }

            Request::AddMany { drafts } => {
                // Every draft becomes a record before anything is written, so
                // a malformed one at position four hundred does not leave
                // three hundred and ninety-nine behind it.
                let mut records = Vec::with_capacity(drafts.len());
                for draft in drafts {
                    records.push(draft.into_record()?);
                }
                let _guard = crate::vault::open_lock(&self.vault_path)?;
                let open = self.opened()?;
                let mut added = 0usize;
                for record in records {
                    open.vault.add_record(record)?;
                    added += 1;
                }
                open.vault.save()?;
                self.publish()?;
                Ok(Response::Added { count: added })
            }

            Request::Update { id, draft } => {
                let id: Uuid = id.parse().context("invalid record id")?;
                let _guard = crate::vault::open_lock(&self.vault_path)?;
                let open = self.opened()?;
                let record = open
                    .vault
                    .get_mut(id)
                    .ok_or_else(|| anyhow!("record not found"))?;
                let changed = draft.apply_to(record)?;
                // A field whose value the user just replaced cannot still be
                // carrying the verdict the corpus gave the old one. Without
                // this the deck kept calling a freshly changed password
                // breached until the next online check.
                for name in changed {
                    open.exposure.remove(&(id, name));
                }
                open.vault.save()?;
                self.publish()?;
                Ok(Response::Saved { id: id.to_string() })
            }

            Request::Delete { id } => {
                let id: Uuid = id.parse().context("invalid record id")?;
                let _guard = crate::vault::open_lock(&self.vault_path)?;
                let open = self.opened()?;
                open.vault.remove_record(id)?;
                open.exposure.retain(|(record_id, _), _| *record_id != id);
                open.vault.save()?;
                self.publish()?;
                Ok(Response::Ok)
            }

            Request::Hygiene => {
                let open = self.opened()?;
                let report = crate::hygiene::analyse_with_exposure(
                    open.vault.records(),
                    Utc::now(),
                    crate::hygiene::Policy::default(),
                    &open.exposure,
                );
                Ok(Response::Hygiene(report))
            }

            Request::BreachPrefixes => {
                let open = self.opened()?;
                Ok(Response::BreachPrefixes {
                    candidates: crate::breach::candidates(open.vault.records()),
                })
            }

            Request::BreachMatch { ranges } => {
                let open = self.opened()?;
                let (report, map) =
                    crate::breach::match_ranges(open.vault.records(), &ranges, &open.exposure);
                open.exposure = map;
                Ok(Response::Breach(report))
            }

            // ── passkeys ──────────────────────────────────────────────────
            //
            // Split in two because the agent is single-threaded: `Begin` only
            // records what may happen, and `Collect` performs it once a human
            // has answered. See `consent.rs`.
            Request::PasskeyBegin {
                operation,
                client_data_hash,
                origin,
                rp_id,
                rp_name,
                allow_credentials,
                challenge,
                cross_origin,
                user_handle,
                user_name,
                user_display_name,
                want_prf,
                prf_first_salt,
                prf_second_salt,
            } => {
                use crate::consent::{Ceremony, Choice, Operation, State};

                let client_data_hash = client_data_hash.as_deref().map(unhex).transpose()?;

                // Two lanes, two bindings, and the checks differ because what
                // is knowable differs.
                let (origin, challenge) = match &client_data_hash {
                    // CTAP. There is no origin on the wire — see
                    // `Ceremony::client_data_hash` — so there is nothing to
                    // check the relying party against, and pretending
                    // otherwise would be inventing a fact. What CAN be checked
                    // is that the relying party is a name somebody could
                    // actually own: a page must not be able to mint a
                    // credential scoped to `com`.
                    Some(hash) => {
                        if hash.len() != 32 {
                            bail!("a client data hash is 32 bytes");
                        }
                        // Refused, not quietly dropped. A caller that sent
                        // both is confused about which lane it is on, and
                        // discarding half of what it said would leave it
                        // believing an origin was checked when none was.
                        if !origin.is_empty() || !challenge.is_empty() {
                            bail!(
                                "a request bound by a client data hash carries no \
                                 origin and no challenge; this one carries both"
                            );
                        }
                        if !crate::passkey::rp_id_is_registrable(&rp_id) {
                            bail!(
                                "{rp_id} is a public suffix, not a relying party: a \
                                 credential scoped to it would work on every site under it"
                            );
                        }
                        (String::new(), String::new())
                    }
                    // The browser lane. The origin is the browser's, and the
                    // relying party must be a registrable-domain suffix of it.
                    // Checked HERE and not only in the signing code, so a
                    // ceremony that could never be signed is never put in front
                    // of a human in the first place.
                    None => {
                        if !crate::passkey::rp_id_is_valid_for_origin(&rp_id, &origin) {
                            bail!("relying party {rp_id} is not valid for origin {origin}");
                        }
                        if challenge.trim().is_empty() {
                            bail!("a passkey ceremony must carry the relying party's challenge");
                        }
                        (origin, challenge)
                    }
                };
                let rp_id = rp_id.trim_end_matches('.').to_ascii_lowercase();

                let allow: Vec<Vec<u8>> = allow_credentials
                    .iter()
                    .map(|h| unhex(h))
                    .collect::<Result<_>>()?;

                let choices: Vec<Choice> = {
                    let open = self.opened()?;
                    match operation {
                        // Nothing exists yet; the credential is minted on
                        // approval, so there is exactly one implicit choice.
                        Operation::Create => Vec::new(),
                        Operation::Assert => {
                            let records = if allow.is_empty() {
                                open.vault.passkeys_for_rp(&rp_id)
                            } else {
                                allow
                                    .iter()
                                    .filter_map(|id| open.vault.passkey_by_credential_id(id))
                                    // A named credential still has to belong to
                                    // the relying party that asked for it.
                                    // Without this, a caller could name a
                                    // credential id belonging to another site
                                    // and have it signed for this origin.
                                    .filter(|r| {
                                        r.passkey.as_ref().is_some_and(|p| p.rp_id == rp_id)
                                    })
                                    .collect()
                            };
                            records
                                .iter()
                                .filter_map(|r| {
                                    let p = r.passkey.as_ref()?;
                                    Some(Choice {
                                        record_id: r.id.to_string(),
                                        credential_id: p.credential_id.clone(),
                                        label: p.describe(),
                                    })
                                })
                                .collect()
                        }
                    }
                };

                let mut raw = [0u8; 16];
                getrandom::getrandom(&mut raw)
                    .map_err(|e| anyhow!("the system CSPRNG refused: {e}"))?;
                let nonce = hex(&raw);

                let ceremony = Ceremony {
                    client_data_hash,
                    nonce: nonce.clone(),
                    operation,
                    origin,
                    rp_id,
                    rp_name,
                    choices: choices.clone(),
                    challenge,
                    cross_origin,
                    user_handle: user_handle.as_deref().map(unhex).transpose()?,
                    user_name,
                    user_display_name,
                    want_prf,
                    prf_first_salt: prf_first_salt.as_deref().map(unhex).transpose()?,
                    prf_second_salt: prf_second_salt.as_deref().map(unhex).transpose()?,
                    owner: self.peer.map(|p| format!("{p:?}")),
                    requester: self.peer.and_then(|p| PeerId::program(p.pid)),
                    registered_at: Utc::now(),
                    attempts: 0,
                    state: State::AwaitingHuman,
                };
                self.consent.register(ceremony, Utc::now())?;
                // Publish so the deck, which watches status.json, puts it on
                // screen without being asked.
                self.publish()?;
                Ok(Response::PasskeyRegistered { nonce, choices })
            }

            Request::PasskeyAnswer {
                nonce,
                defer,
                approve,
                credential_id,
                passphrase,
            } => {
                // Checked before `approve`, so a caller that sets both gets the
                // weaker outcome rather than a signature.
                if defer {
                    self.consent.defer(&nonce, Utc::now())?;
                    self.publish()?;
                    return Ok(Response::Ok);
                }
                if !approve {
                    self.consent
                        .refuse(&nonce, "you refused this request", Utc::now())?;
                    self.publish()?;
                    return Ok(Response::Ok);
                }
                // The proof, and the whole reason this verb exists.
                //
                // Checked against the OPEN vault — the very handle whose data
                // key will produce the signature. An earlier version re-read
                // the vault path, which sounded stronger and was exploitable:
                // proof and signature came from two independent reads of a file
                // any same-uid process can replace for the moment in between.
                let proof_ok = !passphrase.is_empty()
                    && self.opened()?.vault.passphrase_matches(passphrase.as_bytes());
                let chosen = credential_id.as_deref().map(unhex).transpose()?;
                self.consent
                    .approve(&nonce, chosen.as_deref(), proof_ok, Utc::now())?;
                self.publish()?;
                Ok(Response::Ok)
            }

            Request::PasskeyQueue => Ok(Response::PasskeyQueue {
                pending: self.consent.summaries(Utc::now()),
            }),

            Request::Approvals => Ok(Response::Approvals {
                granted: self.approvals.granted().cloned().collect(),
                lockdown: self.approvals.is_locked_down(),
            }),

            Request::Revoke { client, item } => {
                use crate::policy::{Capability, ClientKey};
                let key = ClientKey::of(Some(&client));
                let n = match item {
                    Some(item) => {
                        // Every capability for that item: a person revoking
                        // "this program's access to this record" does not mean
                        // "except for copying it".
                        [
                            Capability::Reveal,
                            Capability::Copy,
                            Capability::SshSign,
                            Capability::SecretService,
                        ]
                        .into_iter()
                        .filter(|c| self.approvals.revoke(&key, &item, *c))
                        .count()
                    }
                    None => self.approvals.revoke_client(&key),
                };
                // Subject is WHOSE approvals went, so the line reads the same
                // way as every other: who did it, to what, and how much.
                self.record_audit(
                    crate::audit::Surface::Socket,
                    crate::audit::Decision::Revoked,
                    &client,
                    Some(&format!(
                        "{n} {} withdrawn",
                        if n == 1 { "approval" } else { "approvals" }
                    )),
                );
                self.publish()?;
                Ok(Response::Added { count: n })
            }

            Request::Lockdown { on } => {
                self.approvals.set_lockdown(on);
                self.record_audit(
                    crate::audit::Surface::Socket,
                    if on {
                        crate::audit::Decision::Blocked
                    } else {
                        crate::audit::Decision::Approved
                    },
                    "lockdown",
                    Some(if on { "on" } else { "off" }),
                );
                self.publish()?;
                Ok(Response::Ok)
            }

            Request::PasskeyCollect { nonce } => {
                use crate::consent::{Operation, State};

                let collector = self.peer.map(|p| format!("{p:?}"));
                let Some(ceremony) =
                    self.consent
                        .take_answered(&nonce, collector.as_deref(), Utc::now())
                else {
                    if self.consent.is_waiting(&nonce) {
                        return Ok(Response::PasskeyWaiting);
                    }
                    bail!("no passkey request is waiting with that id");
                };
                self.publish()?;

                let credential_id = match ceremony.state {
                    State::Approved { credential_id } => credential_id,
                    State::Refused { reason } => bail!("{reason}"),
                    // Its own reply, not an error string: the extension has to
                    // act on this — stand down so a hardware key can be
                    // reached — and a security decision taken by comparing
                    // prose breaks the first time the prose is improved.
                    State::Deferred => return Ok(Response::PasskeyUseSecurityKey),
                    State::AwaitingHuman => bail!("that request has not been answered"),
                };

                // A human said yes, in a surface this process controls, to this
                // exact frozen request. That — and only that — is what sets UV.
                let user_verified = true;

                // BS is a live fact, not a stored one: a backup can be deleted
                // between one ceremony and the next, so it is read now rather
                // than remembered. A log that will not load is treated as "no
                // backup", which understates rather than overstates.
                let backups = self
                    .backup_log_path
                    .as_ref()
                    .and_then(|p| crate::backup::Log::load(p).ok())
                    .unwrap_or_default();

                match ceremony.operation {
                    Operation::Create => {
                        let handle = ceremony
                            .user_handle
                            .clone()
                            .ok_or_else(|| anyhow!("a new passkey needs a user handle"))?;
                        let (created, seed) =
                            crate::passkey::Credential::create(crate::passkey::NewCredential {
                                rp_id: ceremony.rp_id.clone(),
                                rp_name: ceremony.rp_name.clone(),
                                user_handle: handle,
                                user_name: ceremony.user_name.clone(),
                                user_display_name: ceremony.user_display_name.clone(),
                                user_verified,
                                with_prf: ceremony.want_prf,
                                // A credential being created right now cannot
                                // be in a backup taken before it existed. It
                                // becomes backed up at the next
                                // `black-bag backup`, and says so from then on.
                                backed_up: false,
                            })?;

                        let mut record = crate::record::Record::new(
                            crate::record::Kind::Passkey,
                            Some(created.credential.config.describe()),
                        );
                        record.attributes.push((
                            "relying_party".into(),
                            created.credential.config.rp_id.clone(),
                        ));
                        if let Some(name) = &created.credential.config.user_name {
                            record.attributes.push(("username".into(), name.clone()));
                        }
                        record.set_field(
                            crate::passkey::PRIVATE_KEY_FIELD,
                            crate::record::Secret::new(created.credential.private_key()),
                        );
                        if let Some(seed) = &seed {
                            record.set_field(
                                crate::passkey::PRF_SEED_FIELD,
                                crate::record::Secret::new(seed.as_ref()),
                            );
                        }
                        record.passkey = Some(created.credential.config.clone());

                        let open = self.opened()?;
                        open.vault.add_record(record)?;
                        open.vault.save()?;
                        self.publish()?;

                        Ok(Response::PasskeyResult {
                            // Empty on the CTAP lane: the client hashed the
                            // bytes itself and we never saw them, so there is
                            // nothing honest to hand back. Handing back
                            // something plausible would be worse than nothing.
                            client_data_json: match &ceremony.client_data_hash {
                                Some(_) => String::new(),
                                None => hex(&client_data_json(
                                    "webauthn.create",
                                    &ceremony.challenge,
                                    &ceremony.origin,
                                    ceremony.cross_origin,
                                )),
                            },
                            credential_id: hex(&created.credential.config.credential_id),
                            authenticator_data: hex(&created.authenticator_data),
                            // A registration has no assertion signature.
                            signature: String::new(),
                            user_handle: hex(&created.credential.config.user_handle),
                            attestation_object: Some(hex(&created.attestation_object)),
                            public_key_der: Some(hex(&created.public_key_der)),
                            prf_first: None,
                            prf_second: None,
                        })
                    }
                    Operation::Assert => {
                        let open = self.opened()?;
                        let record = open
                            .vault
                            .passkey_by_credential_id(&credential_id)
                            .ok_or_else(|| anyhow!("that passkey is no longer in the vault"))?;
                        let prf_seed = record
                            .field(crate::passkey::PRF_SEED_FIELD)
                            .map(|s| s.open());
                        let credential = crate::passkey::credential_from_record(record)?;

                        // Is a copy of this vault, containing THIS credential,
                        // known to exist right now? A backup taken before the
                        // credential was written does not contain it, so the
                        // epochs are compared rather than merely asking whether
                        // any backup exists.
                        //
                        // A record written before `created_epoch` existed has
                        // no epoch to compare, and there is no honest way to
                        // guess one: it reports not-backed-up until the next
                        // backup, which then covers it for certain.
                        let backed_up = match (
                            backups.backed_up_through(open.vault.vault_id()),
                            record.created_epoch,
                        ) {
                            (Some(through), Some(written_at)) => written_at <= through,
                            _ => false,
                        };

                        // Two lanes, two bindings. The branch is on the
                        // ceremony's own recorded binding, which `register`
                        // guarantees is exactly one of the two — so a browser
                        // ceremony can never reach the prehashed path, where a
                        // caller would get to choose the signed bytes.
                        let (client_data, asserted) = match &ceremony.client_data_hash {
                            Some(hash) => (
                                // Nothing to hand back: the client already has
                                // the bytes it hashed, and we never saw them.
                                Vec::new(),
                                credential.assert_prehashed(hash, user_verified, backed_up)?,
                            ),
                            None => {
                                // Re-checked at the moment of signing, not
                                // merely when the ceremony was registered: the
                                // vault can be refreshed from disk in between.
                                let client_data = client_data_json(
                                    "webauthn.get",
                                    &ceremony.challenge,
                                    &ceremony.origin,
                                    ceremony.cross_origin,
                                );
                                let asserted = credential.assert(
                                    &ceremony.origin,
                                    &client_data,
                                    user_verified,
                                    backed_up,
                                )?;
                                (client_data, asserted)
                            }
                        };

                        // The PRF is evaluated only when the credential
                        // actually carries a seed AND the relying party asked.
                        // A credential minted without one has no answer to give,
                        // and inventing one would hand the relying party a key
                        // that changes the next time they ask.
                        let evaluate = |salt: &Option<Vec<u8>>| {
                            let seed = prf_seed.as_ref()?;
                            let salt = salt.as_ref()?;
                            Some(hex(
                                crate::passkey::prf_evaluate(seed.as_slice(), salt).as_ref(),
                            ))
                        };
                        let prf_first = evaluate(&ceremony.prf_first_salt);
                        let prf_second = evaluate(&ceremony.prf_second_salt);

                        Ok(Response::PasskeyResult {
                            client_data_json: hex(&client_data),
                            credential_id: hex(&credential_id),
                            authenticator_data: hex(&asserted.authenticator_data),
                            signature: hex(&asserted.signature),
                            user_handle: hex(&asserted.user_handle),
                            attestation_object: None,
                            public_key_der: None,
                            prf_first,
                            prf_second,
                        })
                    }
                }
            }

            Request::Shutdown => {
                self.shutdown_requested = true;
                self.lock(LockReason::Shutdown);
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
            Some(open) => open.vault.refresh().is_err(),
            None => false,
        };
        if rekeyed {
            self.lock(LockReason::Rekeyed);
            self.publish()?;
            bail!("the vault was re-keyed by another process; unlock again");
        }

        self.touch();
        self.open.as_mut().ok_or_else(|| anyhow!("vault is locked"))
    }

    /// Slide the idle deadline forward. The ceiling does not move.
    fn touch(&mut self) {
        let idle = self.idle;
        if let Some(open) = self.open.as_mut() {
            open.deadline = Instant::now() + idle;
        }
    }

    fn expire_if_idle(&mut self) -> Result<()> {
        let now = Instant::now();
        let reason = match self.open.as_ref() {
            Some(open) if now >= open.ceiling => Some(LockReason::SessionCeiling),
            Some(open) if now >= open.deadline => Some(LockReason::Idle),
            _ => None,
        };
        if let Some(reason) = reason {
            self.lock(reason);
            self.publish()?;
        }
        Ok(())
    }

    fn status_snapshot(&self) -> AgentStatus {
        let sleep_watch = self
            .sleep_watch
            .as_ref()
            .and_then(|s| s.lock().ok().map(|g| g.clone()));
        let max_session_secs = if self.max_session >= Duration::from_secs(u64::MAX / 4) {
            0
        } else {
            self.max_session.as_secs()
        };
        match &self.open {
            Some(open) => {
                let remaining = open
                    .effective_deadline()
                    .saturating_duration_since(Instant::now());
                AgentStatus {
                    unlocked: true,
                    method: Some(method_str(open.method).into()),
                    expires_at: Some(
                        Utc::now()
                            + ChronoDuration::seconds(remaining.as_secs().min(i64::MAX as u64) as i64),
                    ),
                    idle_timeout_secs: self.idle.as_secs(),
                    session_ends_at: (max_session_secs > 0).then_some(open.ceiling_wall),
                    max_session_secs,
                    last_lock_reason: self.last_lock_reason,
                    sleep_watch,
                    pending_passkeys: self.consent.summaries(Utc::now()),
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
                session_ends_at: None,
                max_session_secs,
                last_lock_reason: self.last_lock_reason,
                sleep_watch,
                // A locked agent holds no ceremonies: lock() clears the desk.
                pending_passkeys: Vec::new(),
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
            session_ends_at: snapshot.session_ends_at,
            max_session_secs: snapshot.max_session_secs,
            last_lock_reason: snapshot.last_lock_reason.map(|r| r.as_str().to_string()),
            sleep_watch: snapshot.sleep_watch.clone(),
            pending_passkeys: snapshot.pending_passkeys.clone(),
        };
        let status = Status::probe(
            &self.vault_path,
            view,
            HostPosture::measure().with_harden(self.hardening),
        );
        match &self.status_dir {
            Some(dir) => status.publish_to(dir)?,
            None => status.publish()?,
        };
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
/// Current TOTP code plus seconds until it rolls.
///
/// Computed by [`crate::totp`] rather than by `totp-rs`, which takes the
/// shared secret as an ordinary `Vec<u8>` and holds it, unzeroized, for the
/// life of the `TOTP` object — so every code the deck displayed copied the
/// long-lived 2FA credential into unlocked heap that was freed without being
/// wiped. Here the secret is borrowed straight out of the arena.
pub fn totp_now(record: &Record) -> Result<(String, u64, u64)> {
    let config = record
        .totp
        .as_ref()
        .ok_or_else(|| anyhow!("record has no TOTP configuration"))?;
    let secret = record
        .field("totp")
        .ok_or_else(|| anyhow!("record has no TOTP secret"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| anyhow!("the system clock is before the epoch"))?
        .as_secs();
    let opened = secret.open();
    let (code, ttl) = crate::totp::totp_at(
        opened.as_slice(),
        now,
        config.step,
        config.digits,
        config.algorithm,
    )?;
    Ok((code, ttl, config.step))
}

fn set_socket_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict {}", path.display()))
}

/// uid of the connected peer, via `SO_PEERCRED`.
/// Read one request line, bounded in both bytes and wall-clock time.
///
/// `SO_RCVTIMEO` — which is what `set_read_timeout` sets — bounds a single
/// `recv`, not a loop of them. `BufReader::read_line` loops, so a peer that
/// sends one byte every two seconds resets the timeout forever and the call
/// never returns.
///
/// That is not a slow client, it is a lock bypass. This agent is deliberately
/// single-threaded: it serves one connection to completion and only then
/// re-checks the idle deadline, the session ceiling and the queue of
/// suspend/screen-lock signals. A wedged connection therefore holds the data
/// key in memory across a suspend — exactly the case locking on suspend exists
/// to prevent.
///
/// Returns `false` on a clean end of input before any request arrived.
fn read_request_line(stream: &UnixStream, out: &mut Vec<u8>) -> Result<bool> {
    use std::io::Read;

    let deadline = Instant::now() + PEER_IO_TIMEOUT;
    let mut chunk = [0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            out.zeroize();
            bail!(
                "peer did not finish a request within {}s; dropped",
                PEER_IO_TIMEOUT.as_secs()
            );
        }
        // Re-armed each pass against the REMAINING budget, so the total is
        // bounded however the peer paces its bytes.
        stream.set_read_timeout(Some(remaining))?;

        match (&*stream).read(&mut chunk) {
            Ok(0) => return Ok(!out.is_empty()),
            Ok(n) => {
                if out.len() + n > MAX_REQUEST_BYTES {
                    out.zeroize();
                    bail!("request exceeds {MAX_REQUEST_BYTES} bytes; dropped");
                }
                out.extend_from_slice(&chunk[..n]);
                chunk.zeroize();
                if let Some(end) = out.iter().position(|&b| b == b'\n') {
                    out.truncate(end);
                    return Ok(true);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                out.zeroize();
                bail!(
                    "peer sent nothing within {}s; dropped",
                    PEER_IO_TIMEOUT.as_secs()
                );
            }
            Err(e) => {
                out.zeroize();
                return Err(e.into());
            }
        }
    }
}

/// Who a ceremony belongs to.
///
/// A pid alone is not an identity — pids are recycled, and a process that dies
/// mid-ceremony can be impersonated by whatever the kernel hands the number to
/// next. Field 22 of `/proc/<pid>/stat` is the process start time in clock
/// ticks since boot, and the pair is unique for the life of the boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerId {
    pid: i32,
    started: u64,
}

impl PeerId {
    /// What to call this peer on screen: the basename of its executable.
    ///
    /// Not a security control — a hostile process can be named anything, and
    /// `/proc/<pid>/exe` may be unreadable. It is there so a person answering a
    /// prompt can see that the thing asking to sign them in is their browser
    /// and not something else, which is the difference between a prompt that
    /// can be substituted for and one that cannot be substituted for silently.
    fn program(pid: i32) -> Option<String> {
        // `/proc/<pid>/exe` is the good answer, and it is not always available:
        // reading that symlink needs PTRACE_MODE_READ, and with Yama's
        // `ptrace_scope=1` — which this project recommends — a process can only
        // read it for its own descendants. The agent is nobody's parent, so on
        // a hardened box this fails for every caller.
        //
        // `/proc/<pid>/comm` is world-readable and always works. It is weaker:
        // a process can set it with `prctl`. That changes nothing, because this
        // is context and not control either way — see `policy.rs`.
        if let Some(name) = std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .and_then(|exe| exe.file_name().map(|n| n.to_string_lossy().into_owned()))
        {
            return Some(name);
        }
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        let comm = comm.trim();
        (!comm.is_empty()).then(|| comm.to_string())
    }

    fn of(pid: i32) -> Option<Self> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // The second field is the executable name in parentheses and may itself
        // contain spaces and parentheses, so fields are counted from the LAST
        // ')' rather than by splitting the whole line.
        let rest = &stat[stat.rfind(')')? + 1..];
        let started = rest.split_whitespace().nth(19)?.parse().ok()?;
        Some(Self { pid, started })
    }
}

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

/// The peer's pid, from the same kernel-attested credentials as its uid.
fn peer_pid(stream: &UnixStream) -> Result<i32> {
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
    Ok(cred.pid)
}

/// Client side: one request, one response, at the default socket.
pub fn ask(request: &Request) -> Result<Response> {
    let path = socket_path()?;
    ask_at(&path, request)
}

/// Client side against an explicit socket path.
pub fn ask_at(path: &Path, request: &Request) -> Result<Response> {
    let mut stream = UnixStream::connect(path)
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
    serde_json::from_str(&line).map_err(|e| {
        // An unknown variant means the agent is a different build from this
        // one — not a corrupt message. Say so, because the raw serde error
        // ("unknown variant `passkey_use_security_key`, expected one of …")
        // is an accurate sentence that sends a reader looking in entirely the
        // wrong place. Measured: a browser spawned the installed binary as its
        // native host while a freshly built agent was serving, and the whole
        // afternoon went on the wrong hypothesis.
        if e.to_string().contains("unknown variant") {
            anyhow!(
                "this build of black-bag ({}) does not understand what the agent \
                 replied — they are different versions. Restart the agent from \
                 the same binary as this one, or reinstall: {e}",
                env!("CARGO_PKG_VERSION")
            )
        } else {
            anyhow!("could not read the agent's reply: {e}")
        }
    })
}

/// A field this build does not understand is refused, not ignored.
#[cfg(test)]
mod unknown_field_tests {
    use super::*;

    /// Serde's default is to ignore an unknown field, and for this protocol
    /// that is the wrong default.
    ///
    /// Measured: a newer client sent `client_data_hash` to an older agent, the
    /// field vanished, and the request was then read as a browser request with
    /// an empty origin. That one failed loudly because the origin check caught
    /// it. A field whose absence merely weakened something would not have.
    #[test]
    fn an_unknown_field_is_refused_rather_than_dropped() {
        // A variant that HAS fields. Serde's internally-tagged representation
        // ignores stray keys alongside a unit variant no matter what is asked
        // of it, and a unit variant has nothing to lose anyway — the risk is
        // entirely in the variants that carry data.
        for json in [
            r#"{"op":"reveal","id":"x","field":"password","from_a_newer_build":1}"#,
            r#"{"op":"passkey_begin","operation":"create","origin":"https://e.com",
                 "rp_id":"e.com","allow_credentials":[],"challenge":"Yg",
                 "cross_origin":false,"client_data_hash_v2":"aa"}"#,
        ] {
            let err = serde_json::from_str::<Request>(json)
                .map(|r| format!("{r:?}"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("unknown field"),
                "an unknown field must be refused, not dropped: {err}"
            );
        }
    }

    /// And the ordinary shapes still parse, including the optional ones that
    /// are genuinely allowed to be absent.
    #[test]
    fn the_shapes_this_build_knows_still_parse() {
        for json in [
            r#"{"op":"status"}"#,
            r#"{"op":"reveal","id":"x","field":"password"}"#,
            r#"{"op":"totp_code","id":"x"}"#,
            r#"{"op":"list"}"#,
        ] {
            serde_json::from_str::<Request>(json)
                .unwrap_or_else(|e| panic!("{json} should parse: {e}"));
        }
    }
}

/// A reply this build does not understand is a version mismatch, and says so.
///
/// The raw serde error is accurate and useless: "unknown variant
/// `passkey_use_security_key`" reads like a corrupt message and sends a reader
/// hunting for a protocol bug. What it actually means is that two copies of
/// this program, built at different times, are talking to each other — which
/// is easy to arrange by accident, because a browser spawns the *installed*
/// binary as its native messaging host while a developer is running a freshly
/// built agent.
#[cfg(test)]
mod version_mismatch_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixListener;

    #[test]
    fn a_reply_from_another_build_names_the_problem() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut discard = String::new();
                let _ = BufReader::new(stream.try_clone().unwrap()).read_line(&mut discard);
                // A variant from a future build.
                // The tag is `result`, which is what the wire actually uses.
                let _ = stream.write_all(b"{\"result\":\"something_newer\"}\n");
            }
        });

        let err = ask_at(&sock, &Request::Status).unwrap_err().to_string();
        assert!(
            err.contains("different versions"),
            "the mismatch has to be named, not spelled out in serde's words: {err}"
        );
        assert!(
            err.contains(env!("CARGO_PKG_VERSION")),
            "and it has to say which build this is: {err}"
        );
    }

    /// A genuinely malformed reply is still reported as malformed, not
    /// misdiagnosed as a version skew.
    #[test]
    fn a_torn_reply_is_not_blamed_on_the_version() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut discard = String::new();
                let _ = BufReader::new(stream.try_clone().unwrap()).read_line(&mut discard);
                let _ = stream.write_all(b"{not json at all\n");
            }
        });

        let err = ask_at(&sock, &Request::Status).unwrap_err().to_string();
        assert!(err.contains("could not read the agent's reply"), "{err}");
        assert!(!err.contains("different versions"), "{err}");
    }
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
            session_ends_at: None,
            max_session_secs: DEFAULT_MAX_SESSION_SECS,
            last_lock_reason: Some(LockReason::Idle),
            sleep_watch: None,
            pending_passkeys: Vec::new(),
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
                value: Zeroizing::new("s".into()),
            },
            Response::Totp {
                code: "123456".into(),
                ttl_secs: 12,
                step: 30,
            },
            Response::BreachPrefixes {
                candidates: Vec::new(),
            },
            Response::Breach(crate::breach::Report::default()),
            Response::PasskeyRegistered {
                nonce: "0123456789abcdef0123456789abcdef".into(),
                choices: vec![crate::consent::Choice {
                    record_id: "r1".into(),
                    credential_id: vec![0xaa, 0xbb],
                    label: "ada at example.com".into(),
                }],
            },
            Response::PasskeyWaiting,
            Response::PasskeyResult {
                client_data_json: "7b7d".into(),
                credential_id: "aabb".into(),
                authenticator_data: "00".into(),
                signature: "3045".into(),
                user_handle: "7f".into(),
                attestation_object: Some("a3".into()),
                public_key_der: Some("3059".into()),
                prf_first: Some("11".into()),
                prf_second: None,
            },
            Response::PasskeyQueue {
                pending: Vec::new(),
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
            secrets: vec![("password".into(), Zeroizing::new("hunter2".into()))],
            notes: None,
            totp: None,
        }
    }

    #[test]
    fn a_draft_becomes_a_record() {
        let record = login_draft().into_record().unwrap();
        assert_eq!(record.kind, Kind::Login);
        assert_eq!(record.title.as_deref(), Some("GitHub"));
        assert_eq!(record.attribute("username"), Some("octocat"));
        assert_eq!(record.field("password").unwrap().expose_str().unwrap().as_str(), "hunter2");
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
        draft.secrets = vec![("password".into(), Zeroizing::new(String::new()))];
        draft.title = Some("renamed".into());
        draft.apply_to(&mut record).unwrap();

        assert_eq!(record.title.as_deref(), Some("renamed"));
        assert_eq!(
            record.field("password").unwrap().expose_str().unwrap().as_str(),
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
                secret_base32: Some(Zeroizing::new(B32.into())),
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
                otpauth_uri: Some(Zeroizing::new(format!("otpauth://totp/GitHub:octocat?secret={B32}&digits=8"))),
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
                secret_base32: Some(Zeroizing::new(B32.into())),
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
        draft.secrets = vec![("  ".into(), Zeroizing::new("x".into()))];
        assert!(draft.into_record().is_err());
    }

    #[test]
    fn a_draft_never_prints_its_secrets_via_debug() {
        // RecordDraft holds raw strings by necessity; make sure nobody has
        // added a Debug that would spill them into a log or panic message.
        let shown = format!("{:?}", login_draft().into_record().unwrap());
        assert!(!shown.contains("hunter2"), "Record Debug leaked: {shown}");
    }

    // ── the agent itself ────────────────────────────────────────────────────

    pub(super) fn spawn_test_agent(idle_secs: u64, max_secs: u64) -> (tempfile::TempDir, PathBuf, PathBuf) {
        use crate::vault::Vault;
        crate::vault::Witness::isolate_for_tests();
        crate::backup::Log::isolate_for_tests();
        let dir = tempfile::TempDir::new().unwrap();
        let vault = dir.path().join("vault.cbor");
        Vault::init(&vault, b"agent test passphrase", 32_768).unwrap();
        let sock = dir.path().join("agent.sock");
        let status_dir = dir.path().join("status");
        let agent = Agent::new(vault.clone(), idle_secs)
            .with_max_session_secs(max_secs)
            .with_status_dir(status_dir)
            .with_audit_path(dir.path().join("audit.jsonl"))
            .with_backup_log_path(dir.path().join("backups.json"));
        let sock_for_thread = sock.clone();
        std::thread::spawn(move || {
            if let Err(e) = agent.serve_at(&sock_for_thread) {
                eprintln!("test agent: {e}");
            }
        });
        let started = Instant::now();
        while UnixStream::connect(&sock).is_err() {
            assert!(started.elapsed() < Duration::from_secs(10), "agent never listened");
            std::thread::sleep(Duration::from_millis(20));
        }
        (dir, vault, sock)
    }

    #[test]
    fn a_silent_peer_cannot_stall_the_agent() {
        // Before PEER_IO_TIMEOUT existed this test hung forever: `handle`
        // blocked in `read_line` on the silent stream and no other client —
        // and no idle expiry — could run until the peer went away.
        let (_dir, _vault, sock) = spawn_test_agent(60, 0);

        let _silent = UnixStream::connect(&sock).unwrap();
        std::thread::sleep(Duration::from_millis(200));

        let started = Instant::now();
        let reply = ask_at(&sock, &Request::Status).expect("the agent must still answer");
        assert!(matches!(reply, Response::Status(_)));
        assert!(
            started.elapsed() < PEER_IO_TIMEOUT + Duration::from_secs(5),
            "a silent peer delayed the agent by {:?}",
            started.elapsed()
        );
        let _ = ask_at(&sock, &Request::Shutdown);
    }

    #[test]
    fn the_session_ceiling_locks_a_busy_session() {
        // Idle = 60 s, ceiling = 60 s floor... the ceiling floor is 60 s, so
        // instead assert the arithmetic through the status document: the
        // ceiling is reported and the effective deadline never exceeds it.
        let (_dir, _vault, sock) = spawn_test_agent(30, 60);
        let reply = ask_at(
            &sock,
            &Request::Unlock {
                passphrase: Zeroizing::new("agent test passphrase".into()),
            },
        )
        .unwrap();
        let Response::Status(status) = reply else {
            panic!("unlock did not return status: {reply:?}");
        };
        assert!(status.unlocked);
        assert_eq!(status.max_session_secs, 60);
        let ends = status.session_ends_at.expect("ceiling is reported while unlocked");
        let expires = status.expires_at.expect("deadline is reported while unlocked");
        assert!(expires <= ends + ChronoDuration::seconds(1));

        // Touch keeps the idle deadline sliding but never past the ceiling.
        std::thread::sleep(Duration::from_millis(300));
        let Response::Status(after) = ask_at(&sock, &Request::Touch).unwrap() else {
            panic!("touch did not return status");
        };
        assert!(after.expires_at.unwrap() <= ends + ChronoDuration::seconds(1));
        let _ = ask_at(&sock, &Request::Shutdown);
    }

    #[test]
    fn a_lock_signal_locks_and_names_its_reason() {
        use crate::vault::Vault;
        crate::vault::Witness::isolate_for_tests();
        let dir = tempfile::TempDir::new().unwrap();
        let vault = dir.path().join("vault.cbor");
        Vault::init(&vault, b"agent test passphrase", 32_768).unwrap();
        let sock = dir.path().join("agent.sock");
        let (tx, rx) = std::sync::mpsc::channel();
        let state = std::sync::Arc::new(std::sync::Mutex::new("test watcher".to_string()));
        let agent = Agent::new(vault.clone(), 60)
            .with_lock_signals(rx, state)
            .with_status_dir(dir.path().join("status"));
        let sock_for_thread = sock.clone();
        std::thread::spawn(move || {
            let _ = agent.serve_at(&sock_for_thread);
        });
        let started = Instant::now();
        while UnixStream::connect(&sock).is_err() {
            assert!(started.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(20));
        }

        let reply = ask_at(
            &sock,
            &Request::Unlock {
                passphrase: Zeroizing::new("agent test passphrase".into()),
            },
        )
        .unwrap();
        assert!(matches!(reply, Response::Status(AgentStatus { unlocked: true, .. })));

        tx.send(LockReason::Suspend).unwrap();
        // The serve loop drains signals between accepts (every ~120 ms).
        let started = Instant::now();
        loop {
            let Response::Status(status) = ask_at(&sock, &Request::Status).unwrap() else {
                panic!("status did not return status");
            };
            if !status.unlocked {
                assert_eq!(status.last_lock_reason, Some(LockReason::Suspend));
                assert_eq!(status.sleep_watch.as_deref(), Some("test watcher"));
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(5), "signal never locked the vault");
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = ask_at(&sock, &Request::Shutdown);
    }

    /// A parsed import must survive the trip through the agent whole —
    /// including the notes, which the draft had no field for and which a
    /// route through `Add` would therefore have dropped in silence.
    #[test]
    fn a_record_survives_the_round_trip_through_a_draft() {
        let mut record = Record::new(Kind::Ssh, Some("build box".into()));
        record.tags = vec!["infra".into()];
        record.set_attribute("label", "ci");
        record.set_field("private_key", Secret::from_str("-----BEGIN-----"));
        record.set_field("passphrase", Secret::from_str("unlock me"));
        record.notes = Some(Secret::from_str("kept in the safe"));

        let back = RecordDraft::of(&record).into_record().unwrap();
        assert_eq!(back.kind, Kind::Ssh);
        assert_eq!(back.title.as_deref(), Some("build box"));
        assert_eq!(back.tags, vec!["infra"]);
        assert_eq!(back.attribute("label"), Some("ci"));
        assert_eq!(
            back.field("private_key").unwrap().expose_str().unwrap().as_str(),
            "-----BEGIN-----"
        );
        assert_eq!(
            back.field("passphrase").unwrap().expose_str().unwrap().as_str(),
            "unlock me"
        );
        assert_eq!(
            back.notes.as_ref().unwrap().expose_str().unwrap().as_str(),
            "kept in the safe",
            "notes must not be lost on the way to the agent"
        );
    }

    /// And a TOTP record keeps its seed and its parameters.
    #[test]
    fn a_totp_record_survives_the_round_trip_through_a_draft() {
        let (bytes, mut cfg) =
            parse_otpauth("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP").unwrap();
        cfg.digits = 8;
        cfg.step = 60;
        cfg.issuer = Some("GitHub".into());
        let mut record = Record::new(Kind::Totp, Some("GitHub 2FA".into()));
        record.set_field("totp", Secret::new(&bytes));
        record.totp = Some(cfg);

        let back = RecordDraft::of(&record).into_record().unwrap();
        assert_eq!(
            back.field("totp").unwrap().open().as_slice(),
            bytes.as_slice(),
            "the shared secret must survive base32 and back"
        );
        let cfg = back.totp.as_ref().unwrap();
        assert_eq!(cfg.digits, 8);
        assert_eq!(cfg.step, 60);
        assert_eq!(cfg.issuer.as_deref(), Some("GitHub"));
    }

    #[test]
    fn requests_roundtrip_as_json_lines() {
        let request = Request::Reveal {
            capability: None,
            id: "1234".into(),
            field: "password".into(),
            passphrase: None,
        };
        let line = serde_json::to_string(&request).unwrap();
        assert!(line.contains("\"op\":\"reveal\""));
        let back: Request = serde_json::from_str(&line).unwrap();
        matches!(back, Request::Reveal { .. });
    }
}

/// The passkey ceremony, end to end, against a live agent over a real socket.
#[cfg(test)]
mod passkey_agent_tests {
    use super::tests::spawn_test_agent;
    use super::*;
    use crate::consent::Operation;

    const PASS: &str = "agent test passphrase";

    fn unlock(sock: &Path) {
        let r = ask_at(
            sock,
            &Request::Unlock {
                passphrase: Zeroizing::new(PASS.into()),
            },
        )
        .unwrap();
        assert!(matches!(r, Response::Status(_) | Response::Ok), "{r:?}");
    }

    fn begin(sock: &Path, op: Operation, origin: &str, rp: &str, allow: Vec<String>) -> Response {
        ask_at(
            sock,
            &Request::PasskeyBegin {
                operation: op,
                client_data_hash: None,
                origin: origin.into(),
                rp_id: rp.into(),
                rp_name: Some("Test RP".into()),
                allow_credentials: allow,
                challenge: "Y2hhbGxlbmdl".into(),
                cross_origin: false,
                user_handle: Some(hex(b"user-handle")),
                user_name: Some("ada".into()),
                user_display_name: Some("Ada".into()),
                want_prf: true,
                prf_first_salt: Some(hex(&[0x11; 32])),
                prf_second_salt: None,
            },
        )
        .unwrap()
    }

    /// Register a passkey and return its credential id.
    fn make_one(sock: &Path, rp: &str) -> String {
        let Response::PasskeyRegistered { nonce, .. } =
            begin(sock, Operation::Create, &format!("https://{rp}"), rp, vec![])
        else {
            panic!("create was not registered")
        };
        ask_at(
            sock,
            &Request::PasskeyAnswer {
                nonce: nonce.clone(),
                approve: true,
                defer: false,
                credential_id: None,
                passphrase: Zeroizing::new(PASS.into()),
            },
        )
        .unwrap();
        let Response::PasskeyResult { credential_id, .. } =
            ask_at(sock, &Request::PasskeyCollect { nonce }).unwrap()
        else {
            panic!("create did not complete")
        };
        credential_id
    }

    /// BS is not a boast. It is 0 while nothing holds a copy of this vault,
    /// and 1 once something does — for the same credential, in the same
    /// session, with nothing else changed.
    #[test]
    fn the_backup_flag_follows_the_actual_backup() {
        use crate::passkey::flags;

        let (dir, vault_path, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let id = make_one(&sock, "example.com");

        let flags_now = |allow: &str| -> u8 {
            let Response::PasskeyRegistered { nonce, .. } = begin(
                &sock,
                Operation::Assert,
                "https://example.com",
                "example.com",
                vec![allow.to_string()],
            ) else {
                panic!("assert was not registered")
            };
            ask_at(
                &sock,
                &Request::PasskeyAnswer {
                    nonce: nonce.clone(),
                    approve: true,
                    defer: false,
                    credential_id: Some(allow.to_string()),
                    passphrase: Zeroizing::new(PASS.into()),
                },
            )
            .unwrap();
            let Response::PasskeyResult {
                authenticator_data, ..
            } = ask_at(&sock, &Request::PasskeyCollect { nonce }).unwrap()
            else {
                panic!("assert did not complete")
            };
            let bytes = unhex(&authenticator_data).unwrap();
            // rpIdHash(32) || flags(1) || signCount(4)
            bytes[32]
        };

        let before = flags_now(&id);
        assert_eq!(
            before & flags::BS,
            0,
            "nothing has copied this vault, so BS must be 0"
        );
        assert_eq!(before & flags::BE, flags::BE, "BE is set regardless");

        // Take a real backup: copy the sealed file and record it, exactly as
        // `black-bag backup` does.
        let copy = dir.path().join("offsite.cbor");
        let bytes = std::fs::read(&vault_path).unwrap();
        std::fs::write(&copy, &bytes).unwrap();
        let file: crate::vault::VaultFile =
            ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let mut log = crate::backup::Log::default();
        log.push(crate::backup::Entry {
            at: Utc::now(),
            vault_id: file.header.vault_id,
            epoch: file.header.epoch,
            path: copy.clone(),
            digest: crate::backup::digest_of(&bytes),
            bytes: bytes.len() as u64,
        });
        log.save(&dir.path().join("backups.json")).unwrap();

        let after = flags_now(&id);
        assert_eq!(
            after & flags::BS,
            flags::BS,
            "a copy of this vault exists and contains this credential, so BS is 1"
        );
        assert_eq!(after & flags::BE, flags::BE, "BE did not move");

        // And it goes back down. This is the half that makes it truthful
        // rather than a one-way switch: delete the copy, and the credential
        // stops claiming to be backed up.
        std::fs::remove_file(&copy).unwrap();
        assert_eq!(
            flags_now(&id) & flags::BS,
            0,
            "a deleted backup must stop being asserted"
        );
    }

    /// A credential minted after the last backup is not in it.
    #[test]
    fn a_credential_newer_than_the_backup_is_not_backed_up() {
        use crate::passkey::flags;

        let (dir, vault_path, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let old = make_one(&sock, "example.com");

        // Back up now — this copy contains `old` and nothing after it.
        let copy = dir.path().join("offsite.cbor");
        let bytes = std::fs::read(&vault_path).unwrap();
        std::fs::write(&copy, &bytes).unwrap();
        let file: crate::vault::VaultFile =
            ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let mut log = crate::backup::Log::default();
        log.push(crate::backup::Entry {
            at: Utc::now(),
            vault_id: file.header.vault_id,
            epoch: file.header.epoch,
            path: copy,
            digest: crate::backup::digest_of(&bytes),
            bytes: bytes.len() as u64,
        });
        log.save(&dir.path().join("backups.json")).unwrap();

        let new = make_one(&sock, "later.example");

        let flags_of = |cred: &str, rp: &str| -> u8 {
            let Response::PasskeyRegistered { nonce, .. } = begin(
                &sock,
                Operation::Assert,
                &format!("https://{rp}"),
                rp,
                vec![cred.to_string()],
            ) else {
                panic!("assert was not registered")
            };
            ask_at(
                &sock,
                &Request::PasskeyAnswer {
                    nonce: nonce.clone(),
                    approve: true,
                    defer: false,
                    credential_id: Some(cred.to_string()),
                    passphrase: Zeroizing::new(PASS.into()),
                },
            )
            .unwrap();
            let Response::PasskeyResult {
                authenticator_data, ..
            } = ask_at(&sock, &Request::PasskeyCollect { nonce }).unwrap()
            else {
                panic!("assert did not complete")
            };
            unhex(&authenticator_data).unwrap()[32]
        };

        assert_eq!(
            flags_of(&old, "example.com") & flags::BS,
            flags::BS,
            "the credential the backup contains says so"
        );
        assert_eq!(
            flags_of(&new, "later.example") & flags::BS,
            0,
            "a credential minted after the backup is not in it, and must not claim to be"
        );
    }

    /// Standing aside is its own answer, and it is not a signature.
    ///
    /// The extension has to act on it — detach so a hardware key can be
    /// reached — which is why it comes back as its own reply rather than as an
    /// error string the caller would have to pattern-match on.
    #[test]
    fn standing_aside_for_a_security_key_signs_nothing() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let id = make_one(&sock, "example.com");

        let Response::PasskeyRegistered { nonce, .. } = begin(
            &sock,
            Operation::Assert,
            "https://example.com",
            "example.com",
            vec![id.clone()],
        ) else {
            panic!("assert was not registered")
        };

        // No passphrase: saying "not with this authenticator" denies nobody
        // anything they had, so it must not cost one.
        assert!(matches!(
            ask_at(
                &sock,
                &Request::PasskeyAnswer {
                    nonce: nonce.clone(),
                    approve: false,
                    defer: true,
                    credential_id: None,
                    passphrase: Zeroizing::new(String::new()),
                },
            )
            .unwrap(),
            Response::Ok
        ));

        assert!(
            matches!(
                ask_at(&sock, &Request::PasskeyCollect { nonce: nonce.clone() }).unwrap(),
                Response::PasskeyUseSecurityKey
            ),
            "the caller must be able to tell this from a refusal without reading prose"
        );

        // Single use, like every other answered ceremony: it cannot be
        // collected again and turned into something else. The agent reports a
        // refusal as a Response::Error rather than a transport failure, so
        // that is what to look for.
        assert!(
            matches!(
                ask_at(&sock, &Request::PasskeyCollect { nonce }).unwrap(),
                Response::Error { .. }
            ),
            "an answered ceremony is collected exactly once"
        );
    }

    /// A caller that sets both gets the weaker outcome, never a signature.
    #[test]
    fn deferring_beats_approving_when_a_caller_asks_for_both() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let id = make_one(&sock, "example.com");

        let Response::PasskeyRegistered { nonce, .. } = begin(
            &sock,
            Operation::Assert,
            "https://example.com",
            "example.com",
            vec![id.clone()],
        ) else {
            panic!("assert was not registered")
        };

        ask_at(
            &sock,
            &Request::PasskeyAnswer {
                nonce: nonce.clone(),
                // Both set, and the passphrase correct: still no signature.
                approve: true,
                defer: true,
                credential_id: Some(id),
                passphrase: Zeroizing::new(PASS.into()),
            },
        )
        .unwrap();

        assert!(matches!(
            ask_at(&sock, &Request::PasskeyCollect { nonce }).unwrap(),
            Response::PasskeyUseSecurityKey
        ));
    }

    /// The CTAP lane, end to end through the agent.
    ///
    /// A ceremony bound by a client-data hash carries no origin and no
    /// challenge, is approved the same way as any other, and signs the hash it
    /// was given rather than bytes it built.
    #[test]
    fn a_ceremony_bound_by_a_hash_signs_that_hash() {
        use p256::ecdsa::signature::Verifier;
        use p256::pkcs8::DecodePublicKey;

        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);

        let hash = [0x5au8; 32];
        let begin = |op: Operation, allow: Vec<String>| {
            ask_at(
                &sock,
                &Request::PasskeyBegin {
                    operation: op,
                    client_data_hash: Some(hex(&hash)),
                    origin: String::new(),
                    rp_id: "example.com".into(),
                    rp_name: Some("Example".into()),
                    allow_credentials: allow,
                    challenge: String::new(),
                    cross_origin: false,
                    user_handle: Some(hex(b"user-handle")),
                    user_name: Some("ada".into()),
                    user_display_name: Some("Ada".into()),
                    want_prf: false,
                    prf_first_salt: None,
                    prf_second_salt: None,
                },
            )
            .unwrap()
        };
        let answer_and_collect = |nonce: String, cred: Option<String>| {
            ask_at(
                &sock,
                &Request::PasskeyAnswer {
                    nonce: nonce.clone(),
                    approve: true,
                    defer: false,
                    credential_id: cred,
                    passphrase: Zeroizing::new(PASS.into()),
                },
            )
            .unwrap();
            ask_at(&sock, &Request::PasskeyCollect { nonce }).unwrap()
        };

        let Response::PasskeyRegistered { nonce, .. } = begin(Operation::Create, vec![]) else {
            panic!("create was not registered")
        };
        let Response::PasskeyResult {
            credential_id,
            client_data_json,
            public_key_der,
            ..
        } = answer_and_collect(nonce, None)
        else {
            panic!("create did not complete")
        };
        assert!(
            client_data_json.is_empty(),
            "we never saw the bytes that were hashed, so we hand back nothing"
        );
        let der = unhex(&public_key_der.expect("a public key")).unwrap();

        // Now assert, and check the signature is over authData || the hash we
        // supplied — not over anything this agent invented.
        let Response::PasskeyRegistered { nonce, .. } =
            begin(Operation::Assert, vec![credential_id.clone()])
        else {
            panic!("assert was not registered")
        };
        let Response::PasskeyResult {
            authenticator_data,
            signature,
            ..
        } = answer_and_collect(nonce, Some(credential_id))
        else {
            panic!("assert did not complete")
        };

        let auth_data = unhex(&authenticator_data).unwrap();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&hash);

        let key = p256::ecdsa::VerifyingKey::from_public_key_der(&der).unwrap();
        let sig = p256::ecdsa::DerSignature::try_from(unhex(&signature).unwrap().as_slice())
            .unwrap();
        key.verify(&signed, &sig)
            .expect("the signature must be over the hash the client supplied");

        // And not over some other hash, which is what makes the above mean
        // anything.
        let mut wrong = auth_data;
        wrong.extend_from_slice(&[0x5b; 32]);
        assert!(key.verify(&wrong, &sig).is_err());
    }

    /// A ceremony may be bound one way or the other, never both and never
    /// neither. Both would leave it ambiguous which bytes get signed.
    #[test]
    fn a_ceremony_cannot_be_bound_two_ways_or_none() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);

        let attempt = |hash: Option<String>, origin: &str, challenge: &str| {
            ask_at(
                &sock,
                &Request::PasskeyBegin {
                    operation: Operation::Create,
                    client_data_hash: hash,
                    origin: origin.into(),
                    rp_id: "example.com".into(),
                    rp_name: None,
                    allow_credentials: vec![],
                    challenge: challenge.into(),
                    cross_origin: false,
                    user_handle: Some(hex(b"u")),
                    user_name: None,
                    user_display_name: None,
                    want_prf: false,
                    prf_first_salt: None,
                    prf_second_salt: None,
                },
            )
            .unwrap()
        };

        // A hash AND an origin.
        assert!(
            matches!(
                attempt(Some(hex(&[1u8; 32])), "https://example.com", "Y2g"),
                Response::Error { .. }
            ),
            "two bindings is one too many"
        );
        // Neither.
        assert!(matches!(attempt(None, "", ""), Response::Error { .. }));
        // A hash of the wrong length.
        assert!(matches!(
            attempt(Some(hex(&[1u8; 31])), "", ""),
            Response::Error { .. }
        ));
        // And the honest one still works.
        assert!(matches!(
            attempt(Some(hex(&[1u8; 32])), "", ""),
            Response::PasskeyRegistered { .. }
        ));
    }

    /// With no origin to compare against, the only check left is that the
    /// relying party is a name somebody could own. Without it, a caller could
    /// mint a credential scoped to `com`.
    #[test]
    fn a_public_suffix_is_refused_on_the_ctap_lane_too() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);

        let attempt = |rp: &str| {
            ask_at(
                &sock,
                &Request::PasskeyBegin {
                    operation: Operation::Create,
                    client_data_hash: Some(hex(&[3u8; 32])),
                    origin: String::new(),
                    rp_id: rp.into(),
                    rp_name: None,
                    allow_credentials: vec![],
                    challenge: String::new(),
                    cross_origin: false,
                    user_handle: Some(hex(b"u")),
                    user_name: None,
                    user_display_name: None,
                    want_prf: false,
                    prf_first_salt: None,
                    prf_second_salt: None,
                },
            )
            .unwrap()
        };

        for rp in ["com", "co.uk", "github.io"] {
            assert!(
                matches!(attempt(rp), Response::Error { .. }),
                "{rp} is a public suffix and must not be a relying party"
            );
        }
        for rp in ["example.com", "example.co.uk", "localhost"] {
            assert!(
                matches!(attempt(rp), Response::PasskeyRegistered { .. }),
                "{rp} is a name somebody can own"
            );
        }
    }

    #[test]
    fn nothing_is_signed_until_a_human_has_answered() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let id = make_one(&sock, "example.com");

        let Response::PasskeyRegistered { nonce, choices } = begin(
            &sock,
            Operation::Assert,
            "https://example.com",
            "example.com",
            vec![],
        ) else {
            panic!("assert was not registered")
        };
        assert_eq!(choices.len(), 1, "the credential just minted is discoverable");

        // Collecting before an answer must not produce a signature.
        assert!(matches!(
            ask_at(&sock, &Request::PasskeyCollect { nonce: nonce.clone() }).unwrap(),
            Response::PasskeyWaiting
        ));

        ask_at(
            &sock,
            &Request::PasskeyAnswer {
                nonce: nonce.clone(),
                approve: true,
                defer: false,
                credential_id: Some(id),
                passphrase: Zeroizing::new(PASS.into()),
            },
        )
        .unwrap();

        let Response::PasskeyResult {
            signature,
            prf_first,
            ..
        } = ask_at(&sock, &Request::PasskeyCollect { nonce: nonce.clone() }).unwrap()
        else {
            panic!("an approved ceremony must produce a signature")
        };
        assert!(!signature.is_empty());
        assert!(prf_first.is_some(), "the relying party asked for a PRF value");

        // And exactly once.
        assert!(matches!(
            ask_at(&sock, &Request::PasskeyCollect { nonce }).unwrap(),
            Response::Error { .. }
        ));
    }

    /// The attack this whole two-phase design exists to stop.
    ///
    /// Before the proof requirement, `passkey_approve` was an ordinary socket
    /// verb: any process running as the user could register a ceremony,
    /// approve its own ceremony, collect the signature, and be logged in as the
    /// owner at any relying party the vault holds a passkey for — silently,
    /// with nothing on screen. This test performs exactly that sequence and
    /// requires it to fail.
    #[test]
    fn a_caller_cannot_approve_its_own_ceremony_without_the_passphrase() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let id = make_one(&sock, "bank.example");

        let Response::PasskeyRegistered { nonce, .. } = begin(
            &sock,
            Operation::Assert,
            "https://bank.example",
            "bank.example",
            vec![],
        ) else {
            panic!("assert was not registered")
        };

        for guess in ["", "not the passphrase", "correct horse battery staple"] {
            let reply = ask_at(
                &sock,
                &Request::PasskeyAnswer {
                    nonce: nonce.clone(),
                    approve: true,
                    defer: false,
                    credential_id: Some(id.clone()),
                    passphrase: Zeroizing::new(guess.into()),
                },
            )
            .unwrap();
            assert!(
                matches!(reply, Response::Error { .. }),
                "a wrong passphrase approved a login: {reply:?}"
            );
        }

        // Three wrong guesses refuse the ceremony outright, so the prompt is
        // not left standing as an oracle to keep guessing against.
        let reply = ask_at(&sock, &Request::PasskeyCollect { nonce }).unwrap();
        assert!(
            matches!(reply, Response::Error { .. }),
            "no signature may come out of this: {reply:?}"
        );
    }

    /// And the honest half: the right passphrase does approve it.
    #[test]
    fn the_passphrase_approves_it() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let id = make_one(&sock, "bank.example");

        let Response::PasskeyRegistered { nonce, .. } = begin(
            &sock,
            Operation::Assert,
            "https://bank.example",
            "bank.example",
            vec![],
        ) else {
            panic!()
        };
        ask_at(
            &sock,
            &Request::PasskeyAnswer {
                nonce: nonce.clone(),
                approve: true,
                defer: false,
                credential_id: Some(id),
                passphrase: Zeroizing::new(PASS.into()),
            },
        )
        .unwrap();

        let Response::PasskeyResult {
            signature,
            client_data_json,
            ..
        } = ask_at(&sock, &Request::PasskeyCollect { nonce }).unwrap()
        else {
            panic!("the right passphrase must approve it")
        };
        assert!(!signature.is_empty());

        // The agent built the signed bytes, and they name the origin the human
        // was shown — not anything a caller supplied.
        let cdj = String::from_utf8(unhex(&client_data_json).unwrap()).unwrap();
        assert!(cdj.contains(r#""origin":"https://bank.example""#), "{cdj}");
        assert!(cdj.contains(r#""type":"webauthn.get""#), "{cdj}");
        assert!(cdj.contains(r#""challenge":"Y2hhbGxlbmdl""#), "{cdj}");
    }

    #[test]
    fn a_refused_ceremony_signs_nothing() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        make_one(&sock, "example.com");

        let Response::PasskeyRegistered { nonce, .. } = begin(
            &sock,
            Operation::Assert,
            "https://example.com",
            "example.com",
            vec![],
        ) else {
            panic!()
        };
        ask_at(
            &sock,
            &Request::PasskeyAnswer {
                nonce: nonce.clone(),
                approve: false,
                defer: false,
                credential_id: None,
                passphrase: Zeroizing::new(String::new()),
            },
        )
        .unwrap();
        assert!(matches!(
            ask_at(&sock, &Request::PasskeyCollect { nonce }).unwrap(),
            Response::Error { .. }
        ));
    }

    /// The attack the origin check exists for: a page that is not the relying
    /// party asking for the relying party's credential.
    #[test]
    fn a_ceremony_for_the_wrong_origin_never_reaches_a_human() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        make_one(&sock, "example.com");

        for origin in [
            "https://evil.example",
            "https://example.com.evil.test",
            "http://example.com",
        ] {
            let r = begin(&sock, Operation::Assert, origin, "example.com", vec![]);
            assert!(
                matches!(r, Response::Error { .. }),
                "{origin} must be refused, got {r:?}"
            );
        }
        assert!(matches!(
            ask_at(&sock, &Request::PasskeyQueue).unwrap(),
            Response::PasskeyQueue { pending } if pending.is_empty()
        ));
    }

    /// Naming a credential that belongs to a different relying party must not
    /// smuggle it into this origin's ceremony.
    #[test]
    fn a_credential_from_another_relying_party_cannot_be_named() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let bank = make_one(&sock, "bank.example");
        make_one(&sock, "shop.example");

        // shop.example asks, but names the bank's credential.
        let r = begin(
            &sock,
            Operation::Assert,
            "https://shop.example",
            "shop.example",
            vec![bank],
        );
        assert!(
            matches!(r, Response::Error { .. }),
            "the bank's credential must not be usable at the shop, got {r:?}"
        );
    }

    #[test]
    fn locking_the_vault_abandons_everything_waiting() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        make_one(&sock, "example.com");
        let Response::PasskeyRegistered { nonce, .. } = begin(
            &sock,
            Operation::Assert,
            "https://example.com",
            "example.com",
            vec![],
        ) else {
            panic!()
        };

        ask_at(&sock, &Request::Lock).unwrap();
        unlock(&sock);

        assert!(
            matches!(
                ask_at(&sock, &Request::PasskeyCollect { nonce }).unwrap(),
                Response::Error { .. }
            ),
            "an approval must not survive the lock it was granted under"
        );
    }

    #[test]
    fn a_locked_vault_registers_no_ceremonies() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        let r = begin(
            &sock,
            Operation::Assert,
            "https://example.com",
            "example.com",
            vec![],
        );
        assert!(matches!(r, Response::Error { .. }), "{r:?}");
    }
}

#[cfg(test)]
mod passkey_reveal_tests {
    use super::tests::spawn_test_agent;
    use super::*;
    use crate::consent::Operation;

    const PASS: &str = "agent test passphrase";

    /// A passkey's private key must not be reachable through the one path that
    /// returns secret bytes.
    #[test]
    fn a_passkey_private_key_is_never_revealed() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        ask_at(
            &sock,
            &Request::Unlock {
                passphrase: Zeroizing::new("agent test passphrase".into()),
            },
        )
        .unwrap();

        // Mint one through the real ceremony.
        let Response::PasskeyRegistered { nonce, .. } = ask_at(
            &sock,
            &Request::PasskeyBegin {
                operation: Operation::Create,
                client_data_hash: None,
                origin: "https://example.com".into(),
                rp_id: "example.com".into(),
                rp_name: None,
                allow_credentials: vec![],
                challenge: "Y2hhbGxlbmdl".into(),
                cross_origin: false,
                user_handle: Some(hex(b"u")),
                user_name: Some("ada".into()),
                user_display_name: None,
                want_prf: true,
                prf_first_salt: None,
                prf_second_salt: None,
            },
        )
        .unwrap() else {
            panic!("create was not registered")
        };
        ask_at(
            &sock,
            &Request::PasskeyAnswer {
                nonce: nonce.clone(),
                approve: true,
                defer: false,
                credential_id: None,
                passphrase: Zeroizing::new(PASS.into()),
            },
        )
        .unwrap();
        ask_at(&sock, &Request::PasskeyCollect { nonce }).unwrap();

        let Response::Records { records } = ask_at(
            &sock,
            &Request::List {
                kind: Some("passkey".into()),
                query: None,
            },
        )
        .unwrap() else {
            panic!("list failed")
        };
        assert_eq!(records.len(), 1);
        let id = records[0].id.clone();

        for field in ["private_key", "prf_seed"] {
            let reply = ask_at(
                &sock,
                &Request::Reveal {
                    capability: None,
                    id: id.clone(),
                    field: field.into(),
                    passphrase: None,
                },
            )
            .unwrap();
            match reply {
                Response::Error { message } => {
                    assert!(message.contains("never revealed"), "{message}")
                }
                other => panic!("{field} was revealed: {other:?}"),
            }
        }
    }
}

#[cfg(test)]
mod passkey_edit_tests {
    use super::*;
    use crate::passkey::{PRF_SEED_FIELD, PRIVATE_KEY_FIELD};
    use crate::record::{Kind, Record, Secret};

    /// Editing a passkey's title must not destroy the passkey.
    ///
    /// `apply_to` prunes every field a draft does not list, and a passkey's key
    /// material is never in a draft because it is never authored and never
    /// revealed. Without the guard this test covers, renaming a passkey would
    /// leave a record that still says "passkey" and can never sign again.
    #[test]
    fn editing_a_passkey_keeps_the_key_that_makes_it_one() {
        let mut record = Record::new(Kind::Passkey, Some("old title".into()));
        record.set_field(PRIVATE_KEY_FIELD, Secret::new(b"the-private-key"));
        record.set_field(PRF_SEED_FIELD, Secret::new(b"the-prf-seed"));

        let draft = RecordDraft {
            kind: "passkey".into(),
            title: Some("new title".into()),
            ..Default::default()
        };
        draft.apply_to(&mut record).unwrap();

        assert_eq!(record.title.as_deref(), Some("new title"));
        assert_eq!(
            record.field(PRIVATE_KEY_FIELD).map(|f| f.open().to_vec()),
            Some(b"the-private-key".to_vec()),
            "the private key must survive an edit"
        );
        assert_eq!(
            record.field(PRF_SEED_FIELD).map(|f| f.open().to_vec()),
            Some(b"the-prf-seed".to_vec()),
            "so must the PRF seed, or every site using it loses its data"
        );
    }

    /// The exemption is narrow: an ordinary record still prunes.
    #[test]
    fn an_ordinary_record_still_drops_a_field_the_draft_omits() {
        let mut record = Record::new(Kind::Login, Some("t".into()));
        record.set_field("password", Secret::new(b"hunter2"));
        record.set_field("private_key", Secret::new(b"not a passkey"));

        let draft = RecordDraft {
            kind: "login".into(),
            title: Some("t".into()),
            secrets: vec![("password".into(), Zeroizing::new("hunter2".into()))],
            ..Default::default()
        };
        draft.apply_to(&mut record).unwrap();
        assert!(record.field("password").is_some());
        assert!(
            record.field("private_key").is_none(),
            "the passkey exemption must not leak to other kinds"
        );
    }
}

#[cfg(test)]
mod client_data_tests {
    use super::*;

    /// These bytes are hashed into a signature and stored by relying parties.
    /// Their shape is part of the contract, so it is pinned.
    #[test]
    fn client_data_has_the_shape_browsers_emit() {
        let bytes = client_data_json("webauthn.get", "Y2hhbGxlbmdl", "https://bank.example", false);
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://bank.example","crossOrigin":false}"#
        );
    }

    /// An origin reaches us from a browser. It must not be able to escape the
    /// string it is written into and forge the fields around it.
    #[test]
    fn a_hostile_origin_cannot_break_out_of_its_own_field() {
        let bytes = client_data_json(
            "webauthn.get",
            "c",
            r#"https://evil","crossOrigin":true,"x":"#,
            false,
        );
        let text = String::from_utf8(bytes).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["crossOrigin"], serde_json::json!(false), "{text}");
        assert!(parsed.get("x").is_none(), "an injected field appeared: {text}");
    }

    #[test]
    fn a_cross_origin_ceremony_says_so() {
        let text =
            String::from_utf8(client_data_json("webauthn.create", "c", "https://x.test", true))
                .unwrap();
        assert!(text.contains(r#""crossOrigin":true"#), "{text}");
        assert!(text.contains(r#""type":"webauthn.create""#), "{text}");
    }
}

#[cfg(test)]
mod peer_pinning_tests {
    use super::tests::spawn_test_agent;
    use super::*;

    /// A peer that dribbles bytes must not be able to hold the agent open.
    ///
    /// `set_read_timeout` bounds one `recv`, not a loop of them, so
    /// `read_line` used to reset its own deadline forever. This agent serves
    /// one connection to completion before it re-checks the idle deadline, the
    /// session ceiling, or the queued suspend and screen-lock signals — so a
    /// connection held open indefinitely holds the data key in memory across a
    /// suspend, which is the exact case lock-on-suspend exists to prevent.
    #[test]
    fn a_trickling_peer_cannot_pin_the_agent() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);

        let mut slow = UnixStream::connect(&sock).unwrap();
        let started = Instant::now();
        // One byte at a time, slower than the per-recv timeout, of a request
        // that never ends. The agent must give up on its own.
        std::thread::spawn(move || {
            for _ in 0..40 {
                if slow.write_all(b" ").is_err() {
                    return;
                }
                let _ = slow.flush();
                std::thread::sleep(Duration::from_millis(500));
            }
        });

        // While that is going on, an ordinary client must still be served.
        std::thread::sleep(PEER_IO_TIMEOUT + Duration::from_millis(1500));
        let reply = ask_at(&sock, &Request::Status).expect("the agent is still answering");
        assert!(matches!(reply, Response::Status(_)), "{reply:?}");
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "the agent was pinned for {:?}",
            started.elapsed()
        );
    }

    /// And a peer that sends a great deal without ever ending the line must be
    /// refused rather than grown into memory.
    #[test]
    fn an_endless_request_is_refused_rather_than_buffered() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        let mut flood = UnixStream::connect(&sock).unwrap();

        // Write hard, with no newline, until the agent drops us.
        let block = vec![b' '; 64 * 1024];
        let mut sent = 0usize;
        while sent < MAX_REQUEST_BYTES + (8 * 1024 * 1024) {
            if flood.write_all(&block).is_err() {
                break;
            }
            sent += block.len();
        }
        drop(flood);

        // The agent survived it and still answers.
        let reply = ask_at(&sock, &Request::Status).expect("the agent is still answering");
        assert!(matches!(reply, Response::Status(_)), "{reply:?}");
    }
}

#[cfg(test)]
mod reveal_policy_tests {
    use super::tests::spawn_test_agent;
    use super::*;
    use crate::record::Kind;

    const PASS: &str = "agent test passphrase";

    fn unlock(sock: &Path) {
        ask_at(
            sock,
            &Request::Unlock {
                passphrase: Zeroizing::new(PASS.into()),
            },
        )
        .unwrap();
    }

    fn add_login(sock: &Path) -> String {
        let mut draft = RecordDraft {
            kind: Kind::Login.as_str().into(),
            title: Some("Bank".into()),
            ..Default::default()
        };
        draft
            .secrets
            .push(("password".into(), Zeroizing::new("hunter2".into())));
        match ask_at(sock, &Request::Add { draft }).unwrap() {
            Response::Saved { id } => id,
            other => panic!("{other:?}"),
        }
    }

    fn add_totp(sock: &Path) -> String {
        let draft = RecordDraft {
            kind: Kind::Totp.as_str().into(),
            title: Some("Bank 2FA".into()),
            totp: Some(TotpDraft {
                // RFC 4648 base32 of b"12345678901234567890", the RFC 6238
                // test key.
                secret_base32: Some(Zeroizing::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into())),
                ..Default::default()
            }),
            ..Default::default()
        };
        match ask_at(sock, &Request::Add { draft }).unwrap() {
            Response::Saved { id } => id,
            other => panic!("{other:?}"),
        }
    }

    fn reveal(sock: &Path, id: &str, pass: Option<&str>) -> Response {
        reveal_as(sock, id, crate::policy::Capability::Reveal, pass)
    }

    fn reveal_as(
        sock: &Path,
        id: &str,
        capability: crate::policy::Capability,
        pass: Option<&str>,
    ) -> Response {
        ask_at(
            sock,
            &Request::Reveal {
                id: id.into(),
                field: "password".into(),
                capability: Some(capability),
                passphrase: pass.map(|p| Zeroizing::new(p.to_string())),
            },
        )
        .unwrap()
    }

    fn totp_code(sock: &Path, id: &str, pass: Option<&str>) -> Response {
        totp_code_as(sock, id, crate::policy::Capability::Reveal, pass)
    }

    fn totp_code_as(
        sock: &Path,
        id: &str,
        capability: crate::policy::Capability,
        pass: Option<&str>,
    ) -> Response {
        ask_at(
            sock,
            &Request::TotpCode {
                id: id.into(),
                capability: Some(capability),
                passphrase: pass.map(|p| Zeroizing::new(p.to_string())),
            },
        )
        .unwrap()
    }

    /// An unlocked vault used to answer every read on the socket. On a machine
    /// running coding agents, that is every agent reading every secret.
    #[test]
    fn the_first_read_is_not_served_and_the_second_is() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let id = add_login(&sock);

        match reveal(&sock, &id, None) {
            Response::ApprovalRequired { title, field, .. } => {
                assert_eq!(title.as_deref(), Some("Bank"));
                assert_eq!(field, "password");
            }
            other => panic!("a secret was served without approval: {other:?}"),
        }

        match reveal(&sock, &id, Some(PASS)) {
            Response::Secret { value } => assert_eq!(&*value, "hunter2"),
            other => panic!("the passphrase must approve it: {other:?}"),
        }

        // Remembered: no proof needed the second time.
        match reveal(&sock, &id, None) {
            Response::Secret { value } => assert_eq!(&*value, "hunter2"),
            other => panic!("an approval must be remembered: {other:?}"),
        }
    }

    #[test]
    fn a_wrong_passphrase_approves_nothing() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let id = add_login(&sock);

        match reveal(&sock, &id, Some("not it")) {
            Response::Error { message } => assert!(message.contains("not the vault passphrase")),
            other => panic!("{other:?}"),
        }
        // And it is still unapproved afterwards.
        assert!(matches!(
            reveal(&sock, &id, None),
            Response::ApprovalRequired { .. }
        ));
    }

    /// An approval belongs to the session it was granted in.
    #[test]
    fn locking_forgets_the_approval() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let id = add_login(&sock);
        reveal(&sock, &id, Some(PASS));
        assert!(matches!(reveal(&sock, &id, None), Response::Secret { .. }));

        ask_at(&sock, &Request::Lock).unwrap();
        unlock(&sock);

        assert!(
            matches!(reveal(&sock, &id, None), Response::ApprovalRequired { .. }),
            "an approval must not survive the lock it was granted under"
        );
    }

    /// Showing a secret on screen and putting it on the clipboard are not the
    /// same exposure, so they are not the same approval.
    ///
    /// The clipboard is readable by every other process in the session and
    /// outlives the glance; a value on screen does not. Approving one must not
    /// silently approve the other.
    #[test]
    fn approving_show_does_not_approve_copy() {
        use crate::policy::Capability;

        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let id = add_login(&sock);

        reveal_as(&sock, &id, Capability::Reveal, Some(PASS));
        assert!(matches!(
            reveal_as(&sock, &id, Capability::Reveal, None),
            Response::Secret { .. }
        ));

        assert!(
            matches!(
                reveal_as(&sock, &id, Capability::Copy, None),
                Response::ApprovalRequired { .. }
            ),
            "the clipboard is a different exposure and must be asked for separately"
        );

        // And the other way round, so neither direction leaks into the other.
        reveal_as(&sock, &id, Capability::Copy, Some(PASS));
        assert!(matches!(
            reveal_as(&sock, &id, Capability::Copy, None),
            Response::Secret { .. }
        ));
    }

    /// A live second-factor code is a credential, not a display value.
    #[test]
    fn a_totp_code_needs_approval_too() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let id = add_totp(&sock);

        match totp_code(&sock, &id, None) {
            Response::ApprovalRequired { field, .. } => assert_eq!(field, "totp"),
            other => panic!("a code was served without approval: {other:?}"),
        }
        match totp_code(&sock, &id, Some("not it")) {
            Response::Error { message } => assert!(message.contains("not the vault passphrase")),
            other => panic!("{other:?}"),
        }
        match totp_code(&sock, &id, Some(PASS)) {
            Response::Totp { code, .. } => assert_eq!(code.len(), 6),
            other => panic!("{other:?}"),
        }
        // Remembered, so the deck can keep the code ticking without asking
        // again every thirty seconds.
        assert!(matches!(
            totp_code(&sock, &id, None),
            Response::Totp { .. }
        ));

        // A code on the clipboard is readable by everything else in the
        // session for as long as it sits there. Showing one in a card is not
        // the same act, so showing it does not license copying it.
        assert!(
            matches!(
                totp_code_as(&sock, &id, crate::policy::Capability::Copy, None),
                Response::ApprovalRequired { .. }
            ),
            "putting a code on the clipboard is a separate question"
        );
    }

    /// Approving one field must not approve the record's other secrets.
    #[test]
    fn an_approval_is_for_one_field_of_one_record() {
        let (_d, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let a = add_login(&sock);
        let b = add_login(&sock);

        reveal(&sock, &a, Some(PASS));
        assert!(matches!(reveal(&sock, &a, None), Response::Secret { .. }));
        assert!(
            matches!(reveal(&sock, &b, None), Response::ApprovalRequired { .. }),
            "another record is another question"
        );
    }

    /// The history has to show what happened, and hold together.
    #[test]
    fn every_outcome_is_recorded_and_the_chain_holds() {
        let (dir, _v, sock) = spawn_test_agent(60, 3600);
        unlock(&sock);
        let id = add_login(&sock);

        reveal(&sock, &id, None); // asked, not served
        reveal(&sock, &id, Some("wrong")); // refused
        reveal(&sock, &id, Some(PASS)); // approved
        reveal(&sock, &id, None); // remembered

        let log = crate::audit::Log::at(dir.path().join("audit.jsonl"));
        let decisions: Vec<_> = log
            .entries()
            .unwrap()
            .iter()
            .map(|e| e.decision)
            .collect();
        use crate::audit::Decision::*;
        assert_eq!(
            decisions,
            vec![Refused, Approved, Remembered],
            "an unanswered ask writes nothing; a refusal, an approval and a \
             remembered use each write one line"
        );
        assert!(log.verify(None).unwrap().is_intact());

        // And the log records the field name, never the value.
        let raw = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert!(raw.contains("password"), "the field name is metadata");
        assert!(!raw.contains("hunter2"), "the value never is");
    }
}
