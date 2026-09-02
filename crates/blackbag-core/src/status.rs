//! The secret-free status document the cockpit reads.
//!
//! # The rule this file exists to enforce
//!
//! `status.json` is written to `$XDG_RUNTIME_DIR/black-bag/` in **plaintext**.
//! The vault is encrypted at rest; this file is not. So it carries only facts
//! that are already implied by the vault's existence — posture, parameters,
//! recipient labels, lock state. It NEVER carries record titles, tags,
//! attributes, counts, or secrets.
//!
//! When the cockpit needs record metadata it asks the agent over a socket and
//! the answer lives in the shell's memory, never on disk. If you are tempted to
//! add a field here, ask whether you would be happy for it to survive in a
//! world-readable backup of `/run`. That is the actual test.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::harden;
use crate::memlock;
use crate::vault::{Recipient, VaultFile, Witness};

pub const STATUS_SCHEMA_VERSION: u32 = 1;

/// Host security posture, reported as measured rather than as intended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPosture {
    /// Kernel core-dump handler. On Omarchy this pipes to systemd-coredump.
    pub core_pattern: String,
    /// True when this process disabled its own core dumps.
    pub core_dumps_disabled: bool,
    pub non_dumpable: bool,
    /// Active swap devices. Non-empty means "secrets never touch disk" holds
    /// only because of mlock.
    pub swap_devices: Vec<String>,
    pub memlock_limit_bytes: u64,
    pub memlock_unlimited: bool,
    /// Whether a 32-byte probe lock succeeded right now.
    pub mlock_working: bool,
    pub mlock_error: Option<String>,
    pub traced: bool,
    /// Bytes of secret arena currently mapped in locked slabs.
    #[serde(default)]
    pub arena_locked_bytes: u64,
    /// Bytes of secret arena the kernel refused to lock. Non-zero means some
    /// secrets in this process are swappable, and the deck says so.
    #[serde(default)]
    pub arena_unlocked_bytes: u64,
    #[serde(default)]
    pub arena_failed_locks: u64,
}

impl HostPosture {
    pub fn measure() -> Self {
        let (limit, unlimited) = memlock::memlock_limit();
        let (working, error) = match memlock::probe() {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e)),
        };
        Self {
            core_pattern: harden::host_core_pattern(),
            core_dumps_disabled: false,
            non_dumpable: false,
            swap_devices: harden::swap_devices(),
            memlock_limit_bytes: limit,
            memlock_unlimited: unlimited,
            mlock_working: working,
            mlock_error: error,
            traced: harden::tracer_pid().is_some(),
            arena_locked_bytes: crate::secmem::locked_bytes() as u64,
            arena_unlocked_bytes: crate::secmem::unlocked_bytes() as u64,
            arena_failed_locks: crate::secmem::failed_locks() as u64,
        }
    }

    pub fn with_harden(mut self, report: harden::HardenReport) -> Self {
        self.core_dumps_disabled = report.core_dumps_disabled;
        self.non_dumpable = report.non_dumpable;
        self.traced = report.traced;
        self
    }

    /// Findings worth surfacing in the cockpit, worst first. Each is a plain
    /// statement of an observed condition, not a score.
    pub fn findings(&self) -> Vec<Finding> {
        let mut out = Vec::new();
        if !self.core_dumps_disabled {
            out.push(Finding::warn(
                "CORE_DUMPS",
                "Core dumps are not disabled for this process",
                &format!("core_pattern = {}", self.core_pattern),
            ));
        }
        if !self.swap_devices.is_empty() {
            out.push(Finding::note(
                "SWAP_ACTIVE",
                "Swap is active; secrets stay off disk only because of mlock",
                &self.swap_devices.join(", "),
            ));
        }
        if !self.mlock_working {
            out.push(Finding::warn(
                "MLOCK_FAILED",
                "Memory locking is not working",
                self.mlock_error.as_deref().unwrap_or("unknown error"),
            ));
        }
        if self.traced {
            out.push(Finding::alert(
                "TRACED",
                "A debugger is attached to this process",
                "detach it before unlocking",
            ));
        }
        if self.arena_unlocked_bytes > 0 {
            out.push(Finding::warn(
                "ARENA_UNLOCKED",
                "Some secrets are in memory the kernel refused to lock",
                &format!(
                    "{} KiB unlocked; raise RLIMIT_MEMLOCK or store fewer large secrets",
                    self.arena_unlocked_bytes / 1024
                ),
            ));
        }
        if !self.memlock_unlimited && self.memlock_limit_bytes < 64 * 1024 * 1024 {
            out.push(Finding::note(
                "MEMLOCK_TIGHT",
                "The memlock budget is small",
                &format!(
                    "{} KiB; large secrets may fail to lock",
                    self.memlock_limit_bytes / 1024
                ),
            ));
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Alert,
    Warn,
    Note,
    Ok,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

impl Finding {
    fn make(severity: Severity, id: &str, title: &str, detail: &str) -> Self {
        Self {
            id: id.into(),
            severity,
            title: title.into(),
            detail: detail.into(),
        }
    }
    pub fn alert(id: &str, title: &str, detail: &str) -> Self {
        Self::make(Severity::Alert, id, title, detail)
    }
    pub fn warn(id: &str, title: &str, detail: &str) -> Self {
        Self::make(Severity::Warn, id, title, detail)
    }
    pub fn note(id: &str, title: &str, detail: &str) -> Self {
        Self::make(Severity::Note, id, title, detail)
    }
    pub fn ok(id: &str, title: &str, detail: &str) -> Self {
        Self::make(Severity::Ok, id, title, detail)
    }
}

/// A recipient as shown in the cockpit. Labels and public parameters only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientView {
    pub label: String,
    pub kind: String,
    /// True for the lane whose private key lives outside the vault.
    pub key_held_externally: bool,
}

/// Argon2 cost, plus how it compares to what we would choose today.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfView {
    pub algorithm: String,
    pub mem_cost_kib: u32,
    pub time_cost: u32,
    pub lanes: u32,
    pub meets_current_defaults: bool,
}

/// Agent/session state. Carries deadlines and reasons, never key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionView {
    pub unlocked: bool,
    pub method: Option<String>,
    /// The nearer of the idle deadline and the session ceiling.
    pub expires_at: Option<DateTime<Utc>>,
    pub idle_timeout_secs: u64,
    /// When the session ends regardless of activity.
    #[serde(default)]
    pub session_ends_at: Option<DateTime<Utc>>,
    /// The ceiling in seconds; 0 means the operator disabled it.
    #[serde(default)]
    pub max_session_secs: u64,
    /// Why the vault was last locked: manual, idle, session-ceiling, suspend,
    /// session-lock, rekeyed, shutdown.
    #[serde(default)]
    pub last_lock_reason: Option<String>,
    /// What the agent's host-event watcher reports about itself.
    #[serde(default)]
    pub sleep_watch: Option<String>,
}

impl Default for SessionView {
    fn default() -> Self {
        Self {
            unlocked: false,
            method: None,
            expires_at: None,
            idle_timeout_secs: 0,
            session_ends_at: None,
            max_session_secs: 0,
            last_lock_reason: None,
            sleep_watch: None,
        }
    }
}

/// The whole document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub schema_version: u32,
    pub published_at: DateTime<Utc>,
    pub engine_version: String,
    /// Present, readable, parseable.
    pub vault_present: bool,
    pub vault_path: String,
    pub vault_format: Option<u32>,
    pub vault_id: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub epoch: Option<u64>,
    pub witness_epoch: Option<u64>,
    pub rollback_suspected: bool,
    pub recipients: Vec<RecipientView>,
    pub kdf: Option<KdfView>,
    pub session: SessionView,
    pub host: HostPosture,
    pub findings: Vec<Finding>,
    /// Set when the vault could not be read at all.
    pub error: Option<String>,
}

impl Status {
    /// Build the document from the vault file alone — this never unlocks and
    /// never needs the passphrase, which is why the bar widget can show real
    /// state before the user authenticates.
    pub fn probe(vault_path: &Path, session: SessionView, host: HostPosture) -> Self {
        let mut status = Self {
            schema_version: STATUS_SCHEMA_VERSION,
            published_at: Utc::now(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            vault_present: false,
            vault_path: vault_path.display().to_string(),
            vault_format: None,
            vault_id: None,
            created_at: None,
            updated_at: None,
            epoch: None,
            witness_epoch: None,
            rollback_suspected: false,
            recipients: Vec::new(),
            kdf: None,
            session,
            findings: Vec::new(),
            host,
            error: None,
        };

        match read_header(vault_path) {
            Ok(Some(file)) => {
                status.vault_present = true;
                status.vault_format = Some(file.version);
                status.vault_id = Some(file.header.vault_id.to_string());
                status.created_at = Some(file.header.created_at);
                status.updated_at = Some(file.header.updated_at);
                status.epoch = Some(file.header.epoch);

                let witness = Witness::seen_epoch(file.header.vault_id);
                status.witness_epoch = witness;
                status.rollback_suspected =
                    witness.is_some_and(|seen| file.header.epoch < seen);

                for recipient in &file.header.recipients {
                    status.recipients.push(RecipientView {
                        label: recipient.label().to_string(),
                        kind: recipient.kind_str().to_string(),
                        key_held_externally: matches!(recipient, Recipient::Hybrid { .. }),
                    });
                    if let Recipient::Passphrase { argon, .. } = recipient {
                        status.kdf = Some(KdfView {
                            algorithm: "argon2id".into(),
                            mem_cost_kib: argon.mem_cost_kib,
                            time_cost: argon.time_cost,
                            lanes: argon.lanes,
                            meets_current_defaults: argon.mem_cost_kib
                                >= crypto::DEFAULT_MEM_KIB
                                && argon.time_cost >= crypto::DEFAULT_TIME_COST
                                && argon.lanes >= crypto::MIN_LANES,
                        });
                    }
                }
            }
            Ok(None) => {}
            Err(e) => status.error = Some(e.to_string()),
        }

        status.findings = status.derive_findings();
        status
    }

    fn derive_findings(&self) -> Vec<Finding> {
        let mut out = Vec::new();

        if self.rollback_suspected {
            out.push(Finding::alert(
                "ROLLBACK",
                "Vault epoch is behind the last epoch seen on this machine",
                &format!(
                    "file epoch {} < witnessed {}",
                    self.epoch.unwrap_or(0),
                    self.witness_epoch.unwrap_or(0)
                ),
            ));
        }
        if let Some(err) = &self.error {
            out.push(Finding::alert("VAULT_UNREADABLE", "Vault cannot be read", err));
        }
        if self.vault_present {
            if let Some(kdf) = &self.kdf {
                if !kdf.meets_current_defaults {
                    out.push(Finding::warn(
                        "KDF_BELOW_DEFAULT",
                        "Argon2 cost is below the current default",
                        &format!(
                            "mem={} KiB time={} lanes={}; re-key to raise it",
                            kdf.mem_cost_kib, kdf.time_cost, kdf.lanes
                        ),
                    ));
                }
            }
            if !self.recipients.iter().any(|r| r.key_held_externally) {
                out.push(Finding::note(
                    "NO_RECOVERY",
                    "No recovery recipient configured",
                    "losing the passphrase means losing the vault",
                ));
            }
        }

        out.extend(self.host.findings());

        if out.is_empty() {
            out.push(Finding::ok("CLEAR", "No findings", "posture matches policy"));
        }
        out.sort_by_key(|f| match f.severity {
            Severity::Alert => 0,
            Severity::Warn => 1,
            Severity::Note => 2,
            Severity::Ok => 3,
        });
        out
    }

    /// Publish atomically so a reader never sees a half-written document.
    pub fn publish(&self) -> Result<PathBuf> {
        let dir = runtime_dir()?;
        self.publish_to(&dir)
    }

    /// Publish into an explicit directory.
    pub fn publish_to(&self, dir: &Path) -> Result<PathBuf> {
        fs::create_dir_all(dir)?;
        set_owner_only(dir)?;
        let path = dir.join("status.json");
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        serde_json::to_writer_pretty(&mut tmp, self)?;
        use std::io::Write;
        tmp.write_all(b"\n")?;
        tmp.as_file_mut().sync_all()?;
        tmp.persist(&path)
            .map_err(|e| anyhow!("failed to publish status: {e}"))?;
        Ok(path)
    }
}

/// Read just enough of the file to describe it, without unlocking.
fn read_header(path: &Path) -> Result<Option<VaultFile>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let file: VaultFile =
        ciborium::de::from_reader(bytes.as_slice()).context("failed to parse vault")?;
    Ok(Some(file))
}

/// `$XDG_RUNTIME_DIR/black-bag`, falling back to the state directory.
pub fn runtime_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir).join("black-bag"));
        }
    }
    Ok(crate::state_dir()?.join("runtime"))
}

pub fn set_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to restrict {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;
    use tempfile::TempDir;

    #[test]
    fn status_of_a_missing_vault_is_honest() {
        let dir = TempDir::new().unwrap();
        let status = Status::probe(
            &dir.path().join("absent.cbor"),
            SessionView::default(),
            HostPosture::measure(),
        );
        assert!(!status.vault_present);
        assert!(status.error.is_none(), "absent is not an error");
        assert!(!status.session.unlocked);
    }

    #[test]
    fn status_never_serialises_record_material() {
        Witness::isolate_for_tests();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.cbor");
        Vault::init(&path, b"pass pass pass", 32_768).unwrap();

        let mut vault = Vault::unlock(&path, b"pass pass pass").unwrap();
        let mut record = crate::record::Record::new(
            crate::record::Kind::Login,
            Some("VERY-DISTINCTIVE-TITLE".into()),
        );
        record.set_attribute("username", "DISTINCTIVE-USER");
        record.set_field("password", crate::record::Secret::from_str("DISTINCTIVE-SECRET"));
        vault.add_record(record).unwrap();
        vault.save().unwrap();
        drop(vault);

        let status = Status::probe(&path, SessionView::default(), HostPosture::measure());
        let json = serde_json::to_string(&status).unwrap();

        for forbidden in [
            "VERY-DISTINCTIVE-TITLE",
            "DISTINCTIVE-USER",
            "DISTINCTIVE-SECRET",
        ] {
            assert!(
                !json.contains(forbidden),
                "status.json leaked {forbidden}:\n{json}"
            );
        }
        assert!(status.vault_present);
        assert_eq!(status.recipients.len(), 1);
    }

    #[test]
    fn a_weak_kdf_is_flagged() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.cbor");
        // 32 MiB is the floor, well under the 256 MiB default.
        Vault::init(&path, b"pass pass pass", 32_768).unwrap();
        let status = Status::probe(&path, SessionView::default(), HostPosture::measure());
        assert!(status.findings.iter().any(|f| f.id == "KDF_BELOW_DEFAULT"));
    }

    #[test]
    fn missing_recovery_recipient_is_noted() {
        Witness::isolate_for_tests();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.cbor");
        Vault::init(&path, b"pass pass pass", 32_768).unwrap();
        let status = Status::probe(&path, SessionView::default(), HostPosture::measure());
        assert!(status.findings.iter().any(|f| f.id == "NO_RECOVERY"));
    }

    #[test]
    fn findings_are_ordered_worst_first() {
        Witness::isolate_for_tests();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.cbor");
        Vault::init(&path, b"pass pass pass", 32_768).unwrap();
        let status = Status::probe(&path, SessionView::default(), HostPosture::measure());
        let ranks: Vec<u8> = status
            .findings
            .iter()
            .map(|f| match f.severity {
                Severity::Alert => 0,
                Severity::Warn => 1,
                Severity::Note => 2,
                Severity::Ok => 3,
            })
            .collect();
        let mut sorted = ranks.clone();
        sorted.sort_unstable();
        assert_eq!(ranks, sorted);
    }
}
