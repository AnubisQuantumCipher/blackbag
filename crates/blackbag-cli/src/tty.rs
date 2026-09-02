//! Where secrets are allowed to go.
//!
//! black-bagg 0.2.x routed revealed secrets to `/dev/tty` and the 0.4.x rewrite
//! replaced that with `println!`, which writes to stdout. The difference is not
//! cosmetic: stdout is redirectable, so `black-bag get X --reveal > notes.txt`
//! or a pipe into `tee`, a logger, or a shell recording silently persists the
//! secret. Writing to the controlling terminal cannot be redirected by the
//! shell, so the secret goes to the human and nowhere else.
//!
//! Anything other than the terminal requires the user to say so explicitly.

use std::fs::OpenOptions;
use std::io::Write;

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

/// Where a revealed secret should be delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Default)]
#[clap(rename_all = "kebab-case")]
pub enum Sink {
    /// The controlling terminal. Cannot be redirected. The default.
    #[default]
    Tty,
    /// The Wayland clipboard, cleared after a timeout.
    Clipboard,
    /// Standard output. Redirectable — you are asking for that.
    Stdout,
}

/// Deliver `secret` to the chosen sink.
///
/// The clipboard path prints its own confirmation, and only after the
/// compositor has been seen offering the value with the sensitive hint —
/// "copied" is a report, not a hope.
pub fn emit_secret(secret: &str, label: &str, sink: Sink, clip_seconds: u64) -> Result<()> {
    match sink {
        Sink::Tty => {
            let mut tty = OpenOptions::new()
                .write(true)
                .open("/dev/tty")
                .context("no controlling terminal; use --to clipboard or --to stdout")?;
            writeln!(tty, "{label}: {secret}")?;
            tty.flush()?;
            Ok(())
        }
        Sink::Stdout => {
            let mut out = std::io::stdout();
            writeln!(out, "{secret}")?;
            out.flush()?;
            Ok(())
        }
        Sink::Clipboard => {
            let placed = crate::clipboard::copy_secret(secret.as_bytes(), clip_seconds)?;
            if !crate::clipboard::wait_until_sensitive(std::time::Duration::from_secs(3))? {
                bail!("the compositor never offered the value; nothing was copied");
            }
            eprintln!(
                "copied {label} to the clipboard · marked sensitive so clipboard managers skip it · {}{}",
                if placed.clear_after_secs == 0 {
                    "stays until something else is copied".to_string()
                } else {
                    format!("clears in {}s", placed.clear_after_secs)
                },
                if placed.helper_locked { "" } else { " · helper could not lock its memory" }
            );
            Ok(())
        }
    }
}

/// Read a passphrase without echoing, from the terminal when there is one and
/// from stdin when there is not — so scripts and the cockpit can pipe it in.
///
/// There is deliberately no `--passphrase` flag anywhere in this CLI.
pub fn read_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    use is_terminal::IsTerminal;

    let value = if std::io::stdin().is_terminal() {
        Zeroizing::new(rpassword::prompt_password(prompt)?)
    } else {
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf)?;
        while buf.ends_with('\n') || buf.ends_with('\r') {
            buf.pop();
        }
        Zeroizing::new(buf)
    };

    if value.trim().is_empty() {
        bail!("passphrase cannot be empty");
    }
    Ok(value)
}

/// Read a passphrase twice and require agreement.
pub fn read_new_passphrase() -> Result<Zeroizing<String>> {
    use is_terminal::IsTerminal;

    let first = read_passphrase("New master passphrase: ")?;
    if !std::io::stdin().is_terminal() {
        // Piped input gets one line; asking twice would consume the next command.
        return Ok(first);
    }
    let second = read_passphrase("Confirm passphrase: ")?;
    if first.as_str() != second.as_str() {
        bail!("passphrases do not match");
    }
    warn_if_weak(&first);
    Ok(first)
}

/// A note, not a gate. Refusing a passphrase the user chose deliberately is
/// how people end up storing it in a file instead.
fn warn_if_weak(passphrase: &str) {
    let words = passphrase.split_whitespace().count();
    if passphrase.len() < 16 && words < 4 {
        eprintln!(
            "note: short passphrase ({} chars). A 6-word phrase resists offline \
             cracking far better than a short complex string.",
            passphrase.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_defaults_to_the_terminal() {
        assert_eq!(Sink::default(), Sink::Tty);
    }

}
