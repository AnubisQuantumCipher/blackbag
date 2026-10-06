//! What is known about copies of this vault that exist somewhere else.
//!
//! This module exists to answer one question honestly: *is this credential
//! backed up right now?* WebAuthn asks it on every ceremony through the BS
//! flag, and the easy answer — always say yes, look like a synced passkey —
//! tells relying parties something untrue in order to look better.
//!
//! ## Why the log lives outside the vault
//!
//! A record of backups kept *inside* the vault would be copied into the
//! backup, which makes it circular: the backup would claim to know about
//! itself. It also travels with the file, so a vault carried to another
//! machine would arrive asserting that it is backed up on a disk that machine
//! cannot see. Keeping it beside the witness, in the state directory, means
//! the claim is scoped to the machine that can actually check it. A restored
//! vault on a new machine reports BS=0 until a backup is taken there, which is
//! the truth.
//!
//! ## What "backed up" is taken to mean
//!
//! A recorded backup whose file is still where it was left, still the size it
//! was, and taken at a vault epoch at or after the one the credential was
//! written in. A file that still exists but has been *replaced* is not caught
//! until `black-bag backup --verify` re-reads it: a digest on every assertion
//! would put a disk read in the signing path. That limit is stated rather
//! than papered over.

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// How many backups are remembered per vault. Older entries fall off: the log
/// answers "is it backed up now", not "what has ever happened".
const KEEP: usize = 8;

/// One successful copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub at: DateTime<Utc>,
    pub vault_id: Uuid,
    /// The vault's write counter at the moment the copy was taken. A record
    /// written at epoch N is in every backup whose epoch is N or greater.
    pub epoch: u64,
    /// Where the copy was written.
    pub path: PathBuf,
    /// SHA-256 of the copy, checked by `--verify`.
    pub digest: String,
    pub bytes: u64,
}

/// What is at the recorded path now.
///
/// Three outcomes, not two: a file that is missing and a file that is there
/// but different are different things to tell someone, and collapsing them
/// into "gone" sends people looking for a disk that is plugged in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Nothing is at that path any more.
    Missing,
    /// Something is there, at the size it was.
    Present,
    /// Something is there, but it is not what was written.
    Changed,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Missing => "GONE",
            State::Present => "present",
            State::Changed => "CHANGED",
        }
    }
}

impl Entry {
    /// What is at the path, judged by existence and size alone.
    ///
    /// Deliberately not a digest: this is consulted while answering a
    /// ceremony, and a disk read does not belong in the signing path. See the
    /// module comment for what that does and does not catch.
    pub fn state(&self) -> State {
        match fs::metadata(&self.path) {
            Ok(m) if m.is_file() && m.len() == self.bytes => State::Present,
            Ok(_) => State::Changed,
            Err(_) => State::Missing,
        }
    }

    /// Whether this copy still counts as a backup of what was written.
    pub fn still_present(&self) -> bool {
        self.state() == State::Present
    }

    /// What is at the path, judged by reading all of it. The slow, certain
    /// answer that `--verify` exists to give.
    pub fn verify(&self) -> Result<State> {
        match fs::read(&self.path) {
            Ok(bytes) if digest_of(&bytes) == self.digest => Ok(State::Present),
            Ok(_) => Ok(State::Changed),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::Missing),
            Err(e) => Err(anyhow!("failed to read {}: {e}", self.path.display())),
        }
    }
}

/// The append-and-trim log, one file for every vault this machine has backed up.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Log {
    #[serde(default)]
    pub entries: Vec<Entry>,
}

/// Set once by a test so the default path is a scratch directory.
///
/// Same shape as the witness's isolation, and for the same reason: a test that
/// read the operator's real backup log would pass or fail depending on what is
/// plugged into this machine, and one that wrote to it would put fiction in a
/// file whose only value is that it is true.
static DIR_OVERRIDE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

impl Log {
    pub fn default_path() -> Result<PathBuf> {
        if let Some(dir) = DIR_OVERRIDE.get() {
            return Ok(dir.join("backups.json"));
        }
        Ok(crate::state_dir()?.join("backups.json"))
    }

    /// Point [`Log::default_path`] at a scratch directory for the rest of this
    /// process. Idempotent, and never reaches the operator's state directory.
    pub fn isolate_for_tests() {
        DIR_OVERRIDE.get_or_init(|| {
            let dir = std::env::temp_dir()
                .join(format!("black-bag-test-backups-{}", std::process::id()));
            let _ = fs::create_dir_all(&dir);
            dir
        });
    }

    pub fn load(path: &Path) -> Result<Self> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("failed to parse {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow!("failed to read {}: {e}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        write_owner_only(path, &json)
    }

    /// Add one, keeping only the newest [`KEEP`] for each vault.
    pub fn push(&mut self, entry: Entry) {
        // A second backup to the same path replaces the first: the file it
        // described no longer exists.
        self.entries
            .retain(|e| !(e.vault_id == entry.vault_id && e.path == entry.path));
        self.entries.push(entry);
        self.entries.sort_by_key(|e| std::cmp::Reverse(e.at));
        let mut kept = 0;
        let id = self.entries.first().map(|e| e.vault_id);
        if let Some(id) = id {
            self.entries.retain(|e| {
                if e.vault_id != id {
                    return true;
                }
                kept += 1;
                kept <= KEEP
            });
        }
    }

    /// Backups of one vault that are still on disk, newest first.
    pub fn live_for(&self, vault_id: Uuid) -> Vec<&Entry> {
        let mut found: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| e.vault_id == vault_id && e.still_present())
            .collect();
        found.sort_by_key(|e| std::cmp::Reverse(e.epoch));
        found
    }

    /// The highest epoch this vault is known to be backed up at, if any.
    ///
    /// This is the whole input to the BS flag: a credential written at or
    /// before this epoch is in a copy that still exists.
    pub fn backed_up_through(&self, vault_id: Uuid) -> Option<u64> {
        self.live_for(vault_id).first().map(|e| e.epoch)
    }
}

/// Write atomically at 0600, fsyncing before the rename.
///
/// Same shape as the vault's own writer, for the same reason: a crash
/// mid-write must not leave a half-parsed file that is then read as "nothing
/// is backed up".
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("invalid path {}", path.display()))?;
    fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.as_file_mut()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    tmp.write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(path)
        .map_err(|e| anyhow!("failed to replace {}: {e}", path.display()))?;
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub fn digest_of(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

// ── the offsite step ───────────────────────────────────────────────────────

/// Where the owner may put an offsite step: `$XDG_CONFIG_HOME/black-bag/offsite`,
/// or `~/.config/black-bag/offsite`.
///
/// A copy on the same disk survives a deleted file, not a dead disk. Getting it
/// further away is different on every machine — a NAS, a phone, a backup tool
/// the owner already trusts — so this program does not pretend to know how. It
/// runs one executable the owner put there, hands it the path of the copy it
/// has just checked, and repeats what that executable says.
pub fn offsite_hook_path() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_CONFIG_HOME") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir).join("black-bag/offsite"));
        }
    }
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".config/black-bag/offsite"))
}

/// The offsite step at `path`, if there is one and it can be trusted.
///
/// `Ok(None)` when nothing is there: no step configured, which is not an
/// error. An error when something is there that this program will not run —
/// a symlink, a file another account owns, or one that anyone but the owner
/// could rewrite. The deck runs it when asked to back up, so whoever can
/// change this file can run code as the owner the next time they press it.
pub fn trusted_offsite_hook(path: &Path) -> Result<Option<PathBuf>> {
    use std::os::unix::fs::MetadataExt;

    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!("failed to look at {}: {e}", path.display())),
    };
    let uid = unsafe { libc::geteuid() };
    let refuse = |why: &str| Err(anyhow!("the offsite step {} was not run: {why}", path.display()));
    if meta.file_type().is_symlink() {
        return refuse("it is a symlink; put the program itself there");
    }
    if !meta.is_file() {
        return refuse("it is not a regular file");
    }
    if meta.uid() != uid {
        return refuse("another account owns it");
    }
    if meta.mode() & 0o022 != 0 {
        return refuse("someone other than its owner can change it (chmod go-w)");
    }
    if meta.mode() & 0o100 == 0 {
        return refuse("it is not executable (chmod u+x)");
    }
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("invalid path {}", path.display()))?;
    let dmeta = fs::metadata(dir).with_context(|| format!("failed to look at {}", dir.display()))?;
    if dmeta.uid() != uid || dmeta.mode() & 0o022 != 0 {
        return refuse("its directory is not the owner's alone, so the file could be swapped");
    }
    Ok(Some(path.to_path_buf()))
}

/// What the offsite step said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offsite {
    pub ok: bool,
    /// Its last line of output — the verdict on success, the reason on failure.
    pub said: String,
}

/// Run the offsite step on `copy` and wait for it.
///
/// Nothing is read from the terminal and no secret is passed: the copy is the
/// sealed file, already encrypted, and its path is the only argument.
pub fn run_offsite(hook: &Path, copy: &Path) -> Result<Offsite> {
    let out = std::process::Command::new(hook)
        .arg(copy)
        .stdin(std::process::Stdio::null())
        .output()
        .with_context(|| format!("failed to start {}", hook.display()))?;
    let last = |bytes: &[u8]| {
        String::from_utf8_lossy(bytes)
            .lines()
            .map(str::trim)
            .rfind(|l| !l.is_empty())
            .unwrap_or("")
            .to_string()
    };
    let ok = out.status.success();
    let mut said = if ok { last(&out.stdout) } else { last(&out.stderr) };
    if said.is_empty() {
        said = if ok { last(&out.stderr) } else { last(&out.stdout) };
    }
    if said.is_empty() {
        said = match out.status.code() {
            Some(c) => format!("it said nothing and exited {c}"),
            None => "it said nothing and was killed by a signal".to_string(),
        };
    }
    Ok(Offsite { ok, said })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: Uuid, epoch: u64, path: &Path, bytes: u64) -> Entry {
        Entry {
            at: Utc::now(),
            vault_id: id,
            epoch,
            path: path.to_path_buf(),
            digest: "0".repeat(64),
            bytes,
        }
    }

    #[test]
    fn a_backup_that_was_deleted_is_not_a_backup() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("copy.cbor");
        fs::write(&file, b"hello").unwrap();
        let id = Uuid::new_v4();

        let mut log = Log::default();
        log.push(entry(id, 7, &file, 5));
        assert_eq!(log.backed_up_through(id), Some(7));

        fs::remove_file(&file).unwrap();
        assert_eq!(
            log.backed_up_through(id),
            None,
            "a recorded backup whose file is gone must not keep asserting itself"
        );
        assert_eq!(log.entries[0].state(), State::Missing);
        assert_eq!(log.entries[0].verify().unwrap(), State::Missing);
    }

    #[test]
    fn a_backup_that_changed_size_is_not_the_one_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("copy.cbor");
        fs::write(&file, b"hello").unwrap();
        let id = Uuid::new_v4();
        let mut log = Log::default();
        log.push(entry(id, 3, &file, 5));
        assert_eq!(log.backed_up_through(id), Some(3));

        fs::write(&file, b"hello, and more").unwrap();
        assert_eq!(log.backed_up_through(id), None);
        assert_eq!(
            log.entries[0].state(),
            State::Changed,
            "a file that is there but different is not the same as one that is gone"
        );
        assert_eq!(log.entries[0].verify().unwrap(), State::Changed);
    }

    #[test]
    fn the_newest_epoch_wins_and_other_vaults_are_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.cbor");
        let b = dir.path().join("b.cbor");
        fs::write(&a, b"aa").unwrap();
        fs::write(&b, b"bbb").unwrap();
        let mine = Uuid::new_v4();
        let theirs = Uuid::new_v4();

        let mut log = Log::default();
        log.push(entry(mine, 2, &a, 2));
        log.push(entry(mine, 9, &b, 3));
        log.push(entry(theirs, 40, &b, 3));

        assert_eq!(log.backed_up_through(mine), Some(9));
        assert_eq!(
            log.backed_up_through(Uuid::new_v4()),
            None,
            "a vault nobody has backed up is not backed up"
        );
        assert_eq!(log.backed_up_through(theirs), Some(40));
    }

    #[test]
    fn backing_up_to_the_same_path_replaces_the_earlier_record() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("copy.cbor");
        fs::write(&file, b"hello").unwrap();
        let id = Uuid::new_v4();

        let mut log = Log::default();
        log.push(entry(id, 4, &file, 5));
        log.push(entry(id, 11, &file, 5));

        assert_eq!(log.entries.len(), 1, "the older copy was overwritten");
        assert_eq!(log.backed_up_through(id), Some(11));
    }

    #[test]
    fn the_log_survives_a_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("copy.cbor");
        fs::write(&file, b"hello").unwrap();
        let path = dir.path().join("backups.json");
        let id = Uuid::new_v4();

        let mut log = Log::default();
        log.push(entry(id, 5, &file, 5));
        log.save(&path).unwrap();

        let back = Log::load(&path).unwrap();
        assert_eq!(back.backed_up_through(id), Some(5));

        // Owner-only: it names paths on removable media and when they were used.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the backup log is owner-only");
        }
    }

    #[test]
    fn a_missing_log_is_an_empty_log_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::load(&dir.path().join("nope.json")).unwrap();
        assert!(log.entries.is_empty());
    }

    fn hook(dir: &Path, body: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("offsite");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn private_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn no_offsite_step_is_not_an_error() {
        let dir = private_dir();
        assert_eq!(trusted_offsite_hook(&dir.path().join("offsite")).unwrap(), None);
    }

    #[test]
    fn an_offsite_step_anyone_could_rewrite_is_not_run() {
        let dir = private_dir();
        let path = hook(dir.path(), "echo ran", 0o772);
        let err = trusted_offsite_hook(&path).unwrap_err().to_string();
        assert!(err.contains("other than its owner"), "{err}");
    }

    #[test]
    fn an_offsite_step_in_a_shared_directory_is_not_run() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_dir();
        let path = hook(dir.path(), "echo ran", 0o700);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let err = trusted_offsite_hook(&path).unwrap_err().to_string();
        assert!(err.contains("directory"), "{err}");
    }

    #[test]
    fn a_symlinked_offsite_step_is_not_run() {
        let dir = private_dir();
        let real = hook(dir.path(), "echo ran", 0o700);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = trusted_offsite_hook(&link).unwrap_err().to_string();
        assert!(err.contains("symlink"), "{err}");
    }

    #[test]
    fn a_non_executable_offsite_step_is_named_not_ignored() {
        let dir = private_dir();
        let path = hook(dir.path(), "echo ran", 0o600);
        let err = trusted_offsite_hook(&path).unwrap_err().to_string();
        assert!(err.contains("not executable"), "{err}");
    }

    #[test]
    fn the_offsite_step_gets_the_copy_and_its_verdict_is_repeated() {
        let dir = private_dir();
        let path = hook(dir.path(), "echo working; echo \"sent $1\"", 0o700);
        let hook = trusted_offsite_hook(&path).unwrap().unwrap();
        let got = run_offsite(&hook, Path::new("/copy/vault.cbor")).unwrap();
        assert_eq!(got, Offsite { ok: true, said: "sent /copy/vault.cbor".into() });
    }

    #[test]
    fn a_failed_offsite_step_reports_its_reason() {
        let dir = private_dir();
        let path = hook(dir.path(), "echo progress; echo 'disk is offline' >&2; exit 3", 0o700);
        let got = run_offsite(&path, Path::new("/copy")).unwrap();
        assert_eq!(got, Offsite { ok: false, said: "disk is offline".into() });
    }

    #[test]
    fn a_silent_failure_still_says_something() {
        let dir = private_dir();
        let path = hook(dir.path(), "exit 4", 0o700);
        let got = run_offsite(&path, Path::new("/copy")).unwrap();
        assert!(!got.ok);
        assert!(got.said.contains("exited 4"), "{}", got.said);
    }
}
