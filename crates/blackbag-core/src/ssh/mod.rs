//! An SSH agent backed by the vault.
//!
//! `ssh` and every application that shells out to it already know how to talk
//! to `$SSH_AUTH_SOCK`. This presents that socket, serves the vault's SSH keys,
//! and signs through the same consent desk every other surface uses — so a
//! git push over SSH costs a glance at Black-Bag and the master passphrase,
//! not a key sitting unguarded in `~/.ssh`.
//!
//! Layered so the parts that have nothing to do with a socket are tested
//! without one:
//!
//! - [`wire`] — the SSH wire format, and the Ed25519 key and signature blobs.
//! - [`agent`] — the agent protocol, answered through a trait so the vault and
//!   the socket are both out of the way in tests.
//!
//! The socket itself lives in the CLI, next to the other daemons.
//!
//! ## Ed25519 only, on purpose
//!
//! Modern OpenSSH defaults to it, it is small, and its signatures are
//! deterministic — there is no per-signature nonce to get wrong. RSA and ECDSA
//! are not served; a client that asks for a key it was never offered is told
//! there is no such key, which is what any agent says.


pub mod agent;
pub mod key;
pub mod wire;

/// The vault field holding a key's 32-byte Ed25519 seed. The public half is
/// derived from it and never stored — see [`key`].
pub const SSH_SEED_FIELD: &str = "ssh_seed";

/// The client identity every SSH signing approval is keyed under.
///
/// Not the calling process: the deck approves and the ssh-agent daemon signs,
/// so a per-peer grant would never match. The user approves the KEY, and this
/// fixed identity is how the deck's grant and the daemon's check meet. It is
/// what the ACCESS panel shows the approval as, which is accurate.
pub const SSH_CLIENT: &str = "ssh-agent";

/// The standard OpenSSH key fingerprint: `SHA256:` + base64 of the SHA-256 of
/// the public-key blob, no padding. What `ssh-add -l` prints and what a human
/// recognises a key by, so an approval that names one is a fingerprint a person
/// can check against their own `ssh-keygen -lf`.
pub fn fingerprint(public_blob: &[u8]) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(public_blob);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    format!("SHA256:{b64}")
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    /// The format OpenSSH uses, checked against a known vector: the fingerprint
    /// of the all-zero 32-byte public key. Any drift from `ssh-keygen`'s output
    /// would make an approval name a key a person could not recognise.
    #[test]
    fn the_fingerprint_has_the_openssh_shape() {
        let blob = wire::ed25519_public_blob(&[0u8; 32]);
        let fp = fingerprint(&blob);
        assert!(fp.starts_with("SHA256:"), "{fp}");
        // base64 of a 32-byte SHA-256, unpadded, is 43 chars.
        assert_eq!(fp.len(), "SHA256:".len() + 43, "{fp}");
        assert!(!fp.ends_with('='), "OpenSSH fingerprints are unpadded");
        // Deterministic.
        assert_eq!(fp, fingerprint(&blob));
    }

    #[test]
    fn different_keys_have_different_fingerprints() {
        let a = fingerprint(&wire::ed25519_public_blob(&[1u8; 32]));
        let b = fingerprint(&wire::ed25519_public_blob(&[2u8; 32]));
        assert_ne!(a, b);
    }
}
