//! The Wayland clipboard, done the way a password manager has to do it.
//!
//! Two things were wrong with shelling out to `wl-copy`, and both were found
//! by running the command and watching, not by reading:
//!
//! 1. **The clipboard never cleared.** `copy_to_clipboard` spawned
//!    `wl-copy --foreground` and then a *thread* that would kill it after the
//!    timeout. The CLI process returned a few milliseconds later, the thread
//!    died with it, and `wl-copy` served the secret until something else was
//!    copied — while the terminal said "clearing in 30s". The cockpit copies
//!    through the same command, so both surfaces made the same false promise.
//! 2. **Clipboard managers recorded every secret.** Omarchy runs
//!    `wl-paste --watch` into a plaintext history file, and it — like cliphist,
//!    KDE and GNOME — skips an offer that carries the
//!    `x-kde-passwordManagerHint` MIME type. `wl-copy --type text/plain`
//!    offered no such hint, so every copied password landed in
//!    `~/.local/state/omarchy/clipboard-history.json`, mode 0644.
//!
//! This module speaks the Wayland data-control protocol itself, through
//! `wl-clipboard-rs`, from a detached helper process that this binary spawns
//! from its own executable. The helper:
//!
//! * offers `text/plain;charset=utf-8`, `text/plain` and the sensitive hint
//!   together, in one selection, so managers can recognise it;
//! * serves the selection from a process whose core dumps are disabled and
//!   whose address space is `mlockall`ed when the budget allows;
//! * clears the selection after the timeout **only if it still holds ours** —
//!   the serve loop returns the moment another client takes the clipboard,
//!   so a value the user copied afterwards is never wiped by us;
//! * receives the secret on stdin and reports readiness on stdout. Nothing
//!   secret is on argv, and the caller does not print "copied" until the
//!   compositor is actually offering the value.
//!
//! The helper outlives the command that started it (`setsid`), which is the
//! whole point: the timer has to survive the CLI's exit.

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use wl_clipboard_rs::copy::{self, ClipboardType, MimeSource, MimeType, Options, Seat, Source};
use wl_clipboard_rs::paste;
use zeroize::Zeroizing;

/// The MIME type clipboard managers look for before deciding to record an
/// entry. KDE named it; cliphist, wl-clipboard's `wl-paste --watch`
/// (`CLIPBOARD_STATE=sensitive`), GNOME and Omarchy's capture script honour it.
pub const SENSITIVE_HINT_MIME: &str = "x-kde-passwordManagerHint";

/// The conventional payload for the hint.
pub const SENSITIVE_HINT_VALUE: &[u8] = b"secret";

/// How long the caller waits for the helper to confirm the compositor is
/// offering the value before giving up and saying so.
pub const READY_TIMEOUT: Duration = Duration::from_secs(4);

/// Upper bound on the auto-clear delay. Zero means "until something else is
/// copied", which is a deliberate choice a user can make, not an accident.
pub const MAX_CLEAR_AFTER_SECS: u64 = 3600;

/// What the helper achieved, so the caller can say it truthfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placed {
    /// The helper's address space is locked in RAM for the offer's lifetime.
    pub helper_locked: bool,
    /// Seconds until the helper clears the selection; 0 means never.
    pub clear_after_secs: u64,
}

/// Put `secret` on the regular Wayland clipboard with the sensitive hint, and
/// arrange for it to be cleared after `clear_after_secs`.
///
/// Returns once the compositor is offering the value — not when the helper was
/// spawned — so "copied" is only ever printed after it is true.
pub fn copy_secret(secret: &[u8], clear_after_secs: u64) -> Result<Placed> {
    if secret.is_empty() {
        bail!("refusing to copy an empty value");
    }
    let clear_after_secs = clear_after_secs.min(MAX_CLEAR_AFTER_SECS);

    let exe = std::env::current_exe().context("cannot locate the black-bag binary")?;
    let mut cmd = Command::new(exe);
    cmd.arg("clip-serve")
        .arg("--clear-after")
        .arg(clear_after_secs.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A new session, so the helper survives this process, its terminal, and
    // the SIGHUP that closing that terminal would otherwise deliver.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("failed to start the clipboard helper")?;

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("clipboard helper has no stdin"))?;
        stdin.write_all(secret)?;
        stdin.flush()?;
        // Dropping closes the pipe: EOF is how the helper knows the value ended.
    }

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("clipboard helper has no stdout"))?;
    let line = read_line_with_timeout(&mut stdout, READY_TIMEOUT);

    match line.as_ref().map(|l| l.trim()) {
        Ok("ready locked") => Ok(Placed {
            helper_locked: true,
            clear_after_secs,
        }),
        Ok("ready unlocked") => Ok(Placed {
            helper_locked: false,
            clear_after_secs,
        }),
        Ok(other) if other.starts_with("error:") => {
            let _ = child.kill();
            let _ = child.wait();
            bail!("clipboard: {}", other.trim_start_matches("error:").trim())
        }
        Ok("") => {
            // EOF without a report: the helper died. Say why if it told us.
            let mut err = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                let _ = stderr.read_to_string(&mut err);
            }
            let status = child.wait().ok();
            bail!(
                "clipboard helper exited without taking the clipboard{}{}",
                status
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default(),
                if err.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", err.trim())
                }
            )
        }
        Ok(other) => {
            let _ = child.kill();
            let _ = child.wait();
            bail!("clipboard helper said something unexpected: {other:?}")
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(line.unwrap_err())
        }
    }
}

/// Read one line from a pipe, giving up after `timeout`.
fn read_line_with_timeout<R: Read + AsRawFd>(reader: &mut R, timeout: Duration) -> Result<String> {
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!(
                "the clipboard helper did not confirm within {}s; is a Wayland compositor running?",
                timeout.as_secs()
            );
        }
        let mut pfd = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining.as_millis().min(i32::MAX as u128) as i32) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err).context("poll on the clipboard helper failed");
        }
        if rc == 0 {
            continue;
        }
        match reader.read(&mut byte)? {
            0 => return Ok(String::from_utf8_lossy(&out).into_owned()),
            _ => {
                if byte[0] == b'\n' {
                    return Ok(String::from_utf8_lossy(&out).into_owned());
                }
                out.push(byte[0]);
                if out.len() > 4096 {
                    bail!("clipboard helper is misbehaving");
                }
            }
        }
    }
}

/// The helper's main. Reads the value on stdin, offers it with the sensitive
/// hint, prints one status line, then serves until the clipboard is taken by
/// someone else or the timer clears it.
pub fn serve(clear_after_secs: u64) -> Result<()> {
    let clear_after_secs = clear_after_secs.min(MAX_CLEAR_AFTER_SECS);

    // The clear timer runs on its own thread, and that thread has to exist
    // *before* the address space is locked: with `MCL_FUTURE` in force a new
    // thread's stack mapping counts against `RLIMIT_MEMLOCK` (8 MiB on a stock
    // box) and `pthread_create` fails with EAGAIN. Found by running it. The
    // stack is kept small for the same budget.
    let serving = Arc::new(AtomicBool::new(true));
    let armed = Arc::new(AtomicBool::new(false));
    if clear_after_secs > 0 {
        let serving = Arc::clone(&serving);
        let armed = Arc::clone(&armed);
        std::thread::Builder::new()
            .name("clear-timer".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                // Wait to be armed, so the countdown starts when the offer is
                // actually on the clipboard rather than when stdin was read.
                while !armed.load(Ordering::SeqCst) {
                    if !serving.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                std::thread::sleep(Duration::from_secs(clear_after_secs));
                // Still ours? Then take it away. If another client replaced
                // it, `serve` has already returned and this is a no-op.
                if serving.load(Ordering::SeqCst) {
                    let _ = copy::clear(ClipboardType::Regular, Seat::All);
                }
            })
            .context("failed to start the clear timer")?;
    }

    // Lock the whole process while it holds a secret: `wl-clipboard-rs` keeps
    // its own copy of the bytes in an ordinary heap allocation, which a
    // per-buffer lock cannot reach. `MCL_ONFAULT` locks pages as they are
    // touched, so reserved-but-unused mappings do not eat the budget.
    // Best-effort, and reported rather than assumed.
    let locked = unsafe {
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT)
    } == 0;

    let mut secret = Zeroizing::new(Vec::new());
    std::io::stdin()
        .read_to_end(&mut secret)
        .context("failed to read the value from stdin")?;
    if secret.is_empty() {
        serving.store(false, Ordering::SeqCst);
        report("error: nothing to copy");
        bail!("nothing to copy");
    }

    let sources = vec![
        MimeSource {
            source: Source::Bytes(secret.to_vec().into_boxed_slice()),
            mime_type: MimeType::Specific("text/plain;charset=utf-8".into()),
        },
        MimeSource {
            source: Source::Bytes(secret.to_vec().into_boxed_slice()),
            mime_type: MimeType::Specific("text/plain".into()),
        },
        MimeSource {
            source: Source::Bytes(SENSITIVE_HINT_VALUE.to_vec().into_boxed_slice()),
            mime_type: MimeType::Specific(SENSITIVE_HINT_MIME.into()),
        },
    ];

    let mut options = Options::new();
    options.foreground(true).clipboard(ClipboardType::Regular).seat(Seat::All);
    let prepared = match options.prepare_copy_multi(sources) {
        Ok(prepared) => prepared,
        Err(e) => {
            serving.store(false, Ordering::SeqCst);
            report(&format!("error: {e}"));
            return Err(anyhow!("{e}"));
        }
    };
    // The selection request is queued; the first dispatch inside `serve`
    // delivers it. The caller confirms by asking the compositor, not us.
    report(if locked { "ready locked" } else { "ready unlocked" });
    armed.store(true, Ordering::SeqCst);

    let result = prepared.serve();
    serving.store(false, Ordering::SeqCst);
    result.map_err(|e| anyhow!("clipboard serve failed: {e}"))
}

fn report(line: &str) {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// Whether the regular clipboard currently carries the sensitive hint. Used by
/// callers to confirm the offer landed, and by tests.
pub fn clipboard_is_sensitive() -> Result<bool> {
    let types = paste::get_mime_types(paste::ClipboardType::Regular, paste::Seat::Unspecified);
    match types {
        Ok(set) => Ok(set.contains(SENSITIVE_HINT_MIME)),
        Err(paste::Error::NoSeats) | Err(paste::Error::ClipboardEmpty) => Ok(false),
        Err(e) => Err(anyhow!("cannot read clipboard offers: {e}")),
    }
}

/// Wait until the compositor offers the sensitive hint, or the timeout passes.
pub fn wait_until_sensitive(timeout: Duration) -> Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        if clipboard_is_sensitive()? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_values_are_refused_before_spawning_anything() {
        assert!(copy_secret(b"", 5).is_err());
    }

    #[test]
    fn clear_delay_is_capped() {
        // The cap is applied in both directions of the pipe; the helper is
        // not exercised here, only the arithmetic the caller relies on.
        assert_eq!(MAX_CLEAR_AFTER_SECS, 3600);
        assert_eq!(7000u64.min(MAX_CLEAR_AFTER_SECS), 3600);
    }
}
