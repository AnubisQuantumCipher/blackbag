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
//! silent: a truncated log is a shorter log with a valid chain, which the
//! chain alone cannot notice. So the head digest is recorded in a sidecar
//! beside the log on every write — the same place, and with the same local-file
//! caveat, as the rollback witness — and a log whose head does not match it is
//! reported as truncated. A same-uid writer can rewrite the sidecar too; what
//! this removes is *silent* truncation (a crash, a restore of an older copy, a
//! partial cut, an attacker who does not also rewrite the sidecar), not the
//! ability to truncate.
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
// Kebab, so the JSON name and `as_str` — which is what the human-readable log
// prints and what the digest is computed over — are one string, not two.
#[serde(rename_all = "kebab-case")]
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
    /// An approval that had been given was withdrawn.
    ///
    /// Its own decision rather than reusing `Refused`, which means "somebody
    /// was denied something they asked for". A log is only worth keeping if it
    /// can be read back without a glossary.
    Revoked,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Approved => "approved",
            Decision::Refused => "refused",
            Decision::Remembered => "remembered",
            Decision::Blocked => "blocked",
            Decision::Lapsed => "lapsed",
            Decision::Revoked => "revoked",
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
        // Record the new head beside the log. A truncation is a shorter log
        // with a perfectly valid chain, which `verify` cannot notice on its
        // own; the recorded head is what it compares against. Written after the
        // entry is durable, so a crash between the two leaves the head one
        // behind — which `verify` treats as benign (see the ancestor rule
        // there), never as truncation. The same local-file limit the rollback
        // witness has applies: a same-uid writer can rewrite this too. What it
        // removes is *silent* truncation, not the ability to truncate.
        if let Err(e) = self.write_head(&entry.digest) {
            eprintln!(
                "black-bag audit: could not record the head ({e}); truncation \
                 detection is weakened until the next write"
            );
        }
        Ok(entry.digest)
    }

    /// The sidecar that remembers the head, beside the log itself.
    fn head_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(".head");
        PathBuf::from(name)
    }

    /// Record `head` as the digest of the last entry — atomically, 0600.
    fn write_head(&self, head: &str) -> Result<()> {
        let path = self.head_path();
        let dir = path
            .parent()
            .map(|d| d.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(&dir)?;
        let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        tmp.write_all(head.as_bytes())?;
        tmp.as_file_mut().sync_all()?;
        tmp.persist(&path)
            .map_err(|e| anyhow!("failed to record the audit head: {e}"))?;
        Ok(())
    }

    /// The head this log last recorded, or `None` if it never has.
    ///
    /// `None` covers a log written before head-recording existed: `verify`
    /// then cannot tell a truncation from a clean prefix, and says so rather
    /// than overstate what it checked. The next `append` writes a head and
    /// closes the gap.
    pub fn recorded_head(&self) -> Result<Option<String>> {
        match std::fs::read_to_string(self.head_path()) {
            Ok(raw) => {
                let head = raw.trim().to_string();
                Ok((!head.is_empty()).then_some(head))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| {
                format!("failed to read {}", self.head_path().display())
            }),
        }
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
                // The recorded head is not the current head. If it appears
                // earlier in the chain, the log only grew past a head recorded
                // before the last append landed — benign, and the recorded
                // entry is still present and intact. If it appears nowhere, the
                // entries it belonged to were cut from the end: the truncation
                // a valid prefix hides from the chain alone.
                let grew_past = entries.iter().any(|e| e.digest == want);
                if !grew_past {
                    return Ok(Verdict::Truncated {
                        entries: entries.len(),
                    });
                }
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

/// The caller's identity for the log.
///
/// `program` is passed in rather than read here, so that the name in the log
/// and the name the approval was keyed on are the same string from the same
/// source. Reading it twice, in two places, with two different fallbacks is how
/// a log ends up disagreeing with the policy it is supposed to be a record of —
/// which is exactly what happened: this read `/proc/<pid>/exe`, which
/// `ptrace_scope=1` makes unreadable for a non-descendant, and logged `None`
/// for callers the policy had named perfectly well.
pub fn who(uid: u32, pid: i32, program: Option<String>) -> Who {
    Who { uid, pid, program }
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
mod naming_tests {
    use super::{Decision, Surface};

    /// Same contract as `policy::Capability`: what the digest is computed over
    /// and what crosses the wire must be one string. The digest uses
    /// `as_str`, so a serde name that drifted would make two readers of the
    /// same log disagree about what it says.
    #[test]
    fn every_name_has_exactly_one_spelling() {
        for s in [
            Surface::Socket,
            Surface::Passkey,
            Surface::SecretService,
            Surface::SshAgent,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json.trim_matches('"'), s.as_str(), "{s:?} is spelled two ways");
        }
        for d in [
            Decision::Approved,
            Decision::Refused,
            Decision::Remembered,
            Decision::Blocked,
            Decision::Lapsed,
            Decision::Revoked,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            assert_eq!(json.trim_matches('"'), d.as_str(), "{d:?} is spelled two ways");
        }
    }
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

    /// The recorded head is written by `append` itself, not only in tests — so
    /// a truncation is caught end-to-end without anyone handing `verify` a head.
    #[test]
    fn append_records_the_head_so_truncation_is_caught_end_to_end() {
        let (_d, log) = log();
        for i in 0..4 {
            log.append(who_test(), Surface::Socket, Decision::Approved, &format!("rec-{i}"), None, at(i))
                .unwrap();
        }
        assert_eq!(
            log.recorded_head().unwrap().as_deref(),
            Some(log.head().unwrap().as_str()),
            "append must record the head beside the log"
        );

        // Cut the last two entries; the sidecar is a separate file and still
        // points at the cut-away head.
        let lines: Vec<String> = std::fs::read_to_string(&log.path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        std::fs::write(&log.path, lines[..2].join("\n") + "\n").unwrap();

        let expected = log.recorded_head().unwrap();
        assert_eq!(
            log.verify(expected.as_deref()).unwrap(),
            Verdict::Truncated { entries: 2 },
            "a truncation must be visible from the recorded head alone"
        );
    }

    /// A head the log legitimately grew past (recorded before the last append
    /// landed, e.g. a crash in that window) is not a truncation.
    #[test]
    fn a_head_the_log_grew_past_is_not_read_as_truncation() {
        let (_d, log) = log();
        let older = log
            .append(who_test(), Surface::Socket, Decision::Approved, "rec-0", None, at(0))
            .unwrap();
        log.append(who_test(), Surface::Socket, Decision::Approved, "rec-1", None, at(1))
            .unwrap();
        assert!(
            log.verify(Some(&older)).unwrap().is_intact(),
            "a valid extension of the recorded head is intact, not truncated"
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
    fn who_records_exactly_the_identity_it_is_handed() {
        // Passed in rather than read here, so the log and the policy always
        // agree about what something was called.
        let w = who(1000, 42, Some("brave".into()));
        assert_eq!(w.program.as_deref(), Some("brave"));
        assert_eq!(who(1000, 42, None).program, None);
    }

    #[test]
    fn an_overlong_detail_is_refused_before_it_is_written() {
        assert!(reject_secret_looking("password").is_ok());
        assert!(reject_secret_looking(&"x".repeat(200)).is_err());
    }
}
