//! Black-Bag — hardened credential storage for Omarchy.
//!
//! This is a Linux-only rewrite of the `black-bagg` crate's engine. The public
//! crate targeted macOS (RAM disks via `hdiutil`, `/Volumes/...` paths) and its
//! 0.4.x line dropped a substantial amount of hardening that its own 0.2.x line
//! had shipped. `docs/AUDIT.md` records what was lost and what was restored.

pub mod crypto;
pub mod generate;
pub mod harden;
pub mod hygiene;
pub mod memlock;
pub mod record;
pub mod secmem;
pub mod session;
pub mod sleepwatch;
pub mod status;
pub mod vault;

use std::path::PathBuf;

use anyhow::{anyhow, Result};

/// `$XDG_STATE_HOME/black-bag`, or `~/.local/state/black-bag`.
pub fn state_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("BLACK_BAG_STATE_DIR") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    if let Ok(dir) = std::env::var("XDG_STATE_HOME") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir).join("black-bag"));
        }
    }
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".local/state/black-bag"))
}

/// Where the vault lives. `BLACK_BAG_VAULT_PATH` overrides.
pub fn vault_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("BLACK_BAG_VAULT_PATH") {
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir).join("black-bag/vault.cbor"));
        }
    }
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".local/share/black-bag/vault.cbor"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_path_honours_the_override() {
        std::env::set_var("BLACK_BAG_VAULT_PATH", "/tmp/bb-test/vault.cbor");
        assert_eq!(
            vault_path().unwrap(),
            PathBuf::from("/tmp/bb-test/vault.cbor")
        );
        std::env::remove_var("BLACK_BAG_VAULT_PATH");
    }
}
