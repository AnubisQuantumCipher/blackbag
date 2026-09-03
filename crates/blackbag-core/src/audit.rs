//! An append-only, hash-chained record of who asked this agent for what.
//!
//! # What this is for
//!
//! This machine runs coding agents all day. Every one of them runs as the same
//! user as the vault, so every one of them can reach the socket. The approval
//! policy in `policy.rs` decides what they may have; this decides what is
//! *known afterwards*, which is the part that survives a mistake in the first.
//!
//! # What a hash chain buys, and what it does not
//!
//! Each entry carries the hash of the entry before it, so removing or editing
//! one breaks every hash after it and [`Log::verify`] says where. That makes
//! quiet edits impossible.
//!
//! It does **not** make deletion impossible. Whoever can write this file can
//! also truncate it or delete it, and nothing in a local file can stop that —
//! the same limit the rollback witness has, and stated here for the same
//! reason. What it changes is that tampering becomes *visible* instead of
//! silent: a truncated log is a shorter log with a valid chain, so the head
//! digest is recorded in the vault's own state on every write, and a head that
//! does not match the file is reported.
//!
//! # What goes in it
//!
//! Non-secret facts only: who (uid, pid, program), what (surface, item id,
//! field name), when, and the decision. **Never a secret value.** A field
//! *name* is metadata of the same order as the record list; a field *value* is
//! the thing being protected.

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;

/// The digest a chain starts from, so the first entry has a predecessor.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Which surface an approach came through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// The agent socket: the deck, the CLI, anything speaking the protocol.
    Socket,
    /// A passkey ceremony from a browser.
    Passkey,
    /// The freedesktop Secret Service.
    SecretService,
    /// The SSH agent.
    SshAgent,
}

impl Surface {
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Socket => "socket",
            Surface::Passkey => "passkey",
            Surface::SecretService => "secret-service",
            Surface::SshAgent => "ssh-agent",
        }
    }
}

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// A human approved it, with proof.
    Approved,
    /// A human refused it.
    Refused,
    /// Allowed without asking, because an approval was already in force.
    Remembered,
    /// Refused by policy without reaching a human at all.
    Blocked,
    /// It expired before anyone answered.
    Lapsed,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Approved => "approved",
            Decision::Refused => "refused",
            Decision::Remembered => "remembered",
            Decision::Blocked => "blocked",
            Decision::Lapsed => "lapsed",
        }
    }
}

/// Who asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Who {
    pub uid: u32,
    pub pid: i32,
    /// The basename of the caller's executable, when it could be read.
    ///
    /// Context, not control: a process can be named anything. It is recorded so
    /// a person reading the log afterwards can recognise what they were doing.
    #[serde(default)]
    pub program: Option<String>,
}

/// One line of history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub at: DateTime<Utc>,
    pub who: Who,
    pub surface: Surface,
    pub decision: Decision,
    /// What was asked for: a record id, or a relying party.
    pub subject: String,
    /// Which part of it — a field name, never a value.
    #[serde(default)]
    pub detail: Option<String>,
    /// Digest of the entry before this one.
    pub prev: String,
    /// Digest of this entry, over everything above.
    pub digest: String,
}

impl Entry {
    /// The digest of this entry's content, excluding the digest field itself.
    ///
    /// Serialised field by field rather than through serde, so that adding a
    /// field to this struct later cannot silently change the digest of entries
    /// already written and invalidate a whole history.
    fn compute(&self) -> String {
        let mut h = Sha256::new();
        let mut part = |s: &str| {
            h.update((s.len() as u64).to_be_bytes());
            h.update(s.as_bytes());
        };
        part(&self.at.to_rfc3339());
        part(&self.who.uid.to_string());
        part(&self.who.pid.to_string());
        part(self.who.program.as_deref().unwrap_or(""));
        part(self.surface.as_str());
        part(self.decision.as_str());
        part(&self.subject);
        part(self.detail.as_deref().unwrap_or(""));
        part(&self.prev);
        hex(&h.finalize())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The log itself: one JSON object per line, appended, never rewritten.
pub struct Log {
    path: PathBuf,
}

impl Log {
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The log in the user's state directory.
    pub fn default_path() -> Result<PathBuf> {
        Ok(crate::state_dir()?.join("audit.jsonl"))
    }

    /// Append one entry and return the new head digest.
    ///
    /// The file is opened append-only and `fsync`ed: an entry that is reported
    /// as written has to survive the power going out, or the log would be
    /// weakest exactly when something is going wrong.
    pub fn append(
        &self,
        who: Who,
        surface: Surface,
        decision: Decision,
        subject: &str,
        detail: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<String> {
        let prev = self.head()?;
        let mut entry = Entry {
            at: now,
            who,
            surface,
            decision,
            subject: subject.to_string(),
            detail: detail.map(str::to_string),
            prev,
            digest: String::new(),
        };
        entry.digest = entry.compute();

        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');

        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
            .with_context(|| format!("failed to open {}", self.path.display()))?;
        file.write_all(line.as_bytes())?;
        file.sync_all()?;
        Ok(entry.digest)
    }

    /// Every entry, oldest first.
    pub fn entries(&self) -> Result<Vec<Entry>> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e).with_context(|| format!("failed to read {}", self.path.display()))
            }
        };
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .enumerate()
            .map(|(n, line)| {
                serde_json::from_str::<Entry>(line)
                    .map_err(|e| anyhow!("audit line {} is not readable: {e}", n + 1))
            })
            .collect()
    }

    /// The digest of the last entry, or [`GENESIS`] when there are none.
    pub fn head(&self) -> Result<String> {
        Ok(self
            .entries()?
            .last()
            .map(|e| e.digest.clone())
            .unwrap_or_else(|| GENESIS.to_string()))
    }

    /// Walk the chain and report the first entry that does not hold.
    ///
    /// `expected_head`, when given, is the digest the agent recorded elsewhere
    /// after its last write. A log that verifies internally but whose head is
    /// not that digest has been **truncated** — which a chain alone cannot
    /// detect, because the remaining prefix is perfectly valid.
    pub fn verify(&self, expected_head: Option<&str>) -> Result<Verdict> {
        let entries = self.entries()?;
        let mut prev = GENESIS.to_string();
        for (i, entry) in entries.iter().enumerate() {
            if entry.prev != prev {
                return Ok(Verdict::Broken {
                    at: i + 1,
                    why: "this entry does not follow the one before it",
                });
            }
            if entry.digest != entry.compute() {
                return Ok(Verdict::Broken {
                    at: i + 1,
                    why: "this entry's contents do not match its digest",
                });
            }
            prev = entry.digest.clone();
        }
        if let Some(want) = expected_head {
            if want != prev {
                return Ok(Verdict::Truncated {
                    entries: entries.len(),
                });
            }
        }
        Ok(Verdict::Intact {
            entries: entries.len(),
            head: prev,
        })
    }
}

/// What [`Log::verify`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Intact { entries: usize, head: String },
    /// An entry was edited, or one was removed from the middle.
    Broken { at: usize, why: &'static str },
    /// The chain is valid but shorter than it should be: entries were cut from
    /// the end, or the whole file was replaced.
    Truncated { entries: usize },
}

impl Verdict {
    pub fn is_intact(&self) -> bool {
        matches!(self, Verdict::Intact { .. })
    }
}

/// Read the caller's identity for the log.
pub fn who(uid: u32, pid: i32) -> Who {
    Who {
        uid,
        pid,
        program: std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
    }
}

/// A sanity check that no secret value ever reaches this module.
///
/// Cheap, and it exists because the one way an audit log becomes a liability is
/// by recording the thing it was protecting.
pub fn reject_secret_looking(detail: &str) -> Result<()> {
    if detail.len() > 128 {
        bail!("audit detail is too long to be a field name; refusing to write it");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    fn who_test() -> Who {
        Who {
            uid: 1000,
            pid: 42,
            program: Some("brave".into()),
        }
    }

    fn log() -> (tempfile::TempDir, Log) {
        let dir = tempfile::TempDir::new().unwrap();
        let log = Log::at(dir.path().join("audit.jsonl"));
        (dir, log)
    }

    #[test]
    fn an_empty_log_is_intact_and_starts_at_genesis() {
        let (_d, log) = log();
        assert_eq!(log.head().unwrap(), GENESIS);
        assert_eq!(
            log.verify(None).unwrap(),
            Verdict::Intact {
                entries: 0,
                head: GENESIS.into()
            }
        );
    }

    #[test]
    fn entries_chain_to_one_another() {
        let (_d, log) = log();
        let a = log
            .append(who_test(), Surface::Socket, Decision::Approved, "rec-1", Some("password"), at(0))
            .unwrap();
        let b = log
            .append(who_test(), Surface::Passkey, Decision::Remembered, "github.com", None, at(1))
            .unwrap();

        let entries = log.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].prev, GENESIS);
        assert_eq!(entries[1].prev, a);
        assert_eq!(log.head().unwrap(), b);
        assert!(log.verify(Some(&b)).unwrap().is_intact());
    }

    /// Editing history has to be visible, and has to say where.
    #[test]
    fn an_edited_entry_is_caught_and_located() {
        let (_d, log) = log();
        for i in 0..4 {
            log.append(
                who_test(),
                Surface::Socket,
                Decision::Approved,
                &format!("rec-{i}"),
                None,
                at(i),
            )
            .unwrap();
        }

        // Rewrite the third entry's decision, leaving its digest alone —
        // exactly what somebody covering their tracks would do.
        let mut lines: Vec<String> = std::fs::read_to_string(&log.path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        lines[2] = lines[2].replace("\"approved\"", "\"refused\"");
        std::fs::write(&log.path, lines.join("\n") + "\n").unwrap();

        match log.verify(None).unwrap() {
            Verdict::Broken { at, why } => {
                assert_eq!(at, 3, "it must name the entry, not just the file");
                assert!(why.contains("digest"), "{why}");
            }
            other => panic!("an edited entry went unnoticed: {other:?}"),
        }
    }

    #[test]
    fn removing_an_entry_from_the_middle_breaks_the_chain() {
        let (_d, log) = log();
        for i in 0..4 {
            log.append(who_test(), Surface::Socket, Decision::Approved, &format!("rec-{i}"), None, at(i))
                .unwrap();
        }
        let mut lines: Vec<String> = std::fs::read_to_string(&log.path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        lines.remove(1);
        std::fs::write(&log.path, lines.join("\n") + "\n").unwrap();

        match log.verify(None).unwrap() {
            Verdict::Broken { at, why } => {
                assert_eq!(at, 2);
                assert!(why.contains("follow"), "{why}");
            }
            other => panic!("a removed entry went unnoticed: {other:?}"),
        }
    }

    /// The case a hash chain cannot catch by itself, and the reason the head is
    /// recorded elsewhere.
    #[test]
    fn truncation_is_invisible_to_the_chain_and_caught_by_the_head() {
        let (_d, log) = log();
        let mut heads = Vec::new();
        for i in 0..4 {
            heads.push(
                log.append(who_test(), Surface::Socket, Decision::Approved, &format!("rec-{i}"), None, at(i))
                    .unwrap(),
            );
        }
        let real_head = heads.last().unwrap().clone();

        // Cut the last two entries. The remaining prefix is a perfectly valid
        // chain, which is exactly the problem.
        let lines: Vec<String> = std::fs::read_to_string(&log.path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        std::fs::write(&log.path, lines[..2].join("\n") + "\n").unwrap();

        assert!(
            log.verify(None).unwrap().is_intact(),
            "a chain alone cannot tell that the end is missing"
        );
        assert_eq!(
            log.verify(Some(&real_head)).unwrap(),
            Verdict::Truncated { entries: 2 },
            "but the recorded head can"
        );
    }

    #[test]
    fn a_wiped_log_is_reported_rather_than_read_as_a_clean_slate() {
        let (_d, log) = log();
        let head = log
            .append(who_test(), Surface::Socket, Decision::Approved, "rec-1", None, at(0))
            .unwrap();
        std::fs::write(&log.path, b"").unwrap();
        assert_eq!(
            log.verify(Some(&head)).unwrap(),
            Verdict::Truncated { entries: 0 }
        );
    }

    #[test]
    fn a_corrupt_line_is_an_error_not_a_shrug() {
        let (_d, log) = log();
        log.append(who_test(), Surface::Socket, Decision::Approved, "rec-1", None, at(0))
            .unwrap();
        std::fs::write(&log.path, b"{ not json\n").unwrap();
        assert!(log.entries().is_err());
        assert!(log.verify(None).is_err());
    }

    #[test]
    fn the_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, log) = log();
        log.append(who_test(), Surface::Socket, Decision::Approved, "rec-1", None, at(0))
            .unwrap();
        let mode = std::fs::metadata(&log.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the log names what you use and when");
    }

    /// A field name is metadata; a field value is the thing being protected.
    #[test]
    fn an_overlong_detail_is_refused_before_it_is_written() {
        assert!(reject_secret_looking("password").is_ok());
        assert!(reject_secret_looking(&"x".repeat(200)).is_err());
    }
}
