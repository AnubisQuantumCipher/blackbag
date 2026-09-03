//! Ed25519 keys for the SSH agent.
//!
//! A key is stored as its 32-byte seed and nothing else — the public half is
//! derived, never stored, so there is one source of truth and no way for a
//! stored public key to drift from the private one it claims to match.
//!
//! Ed25519 signatures are deterministic: the same key over the same message
//! yields the same 64 bytes, with no per-signature nonce to generate or get
//! wrong. That is a large part of why this agent serves Ed25519 and not ECDSA.

use anyhow::{Result, bail};
use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

/// A signing key held only as long as this value lives.
pub struct SshKey {
    signing: SigningKey,
}

impl SshKey {
    /// Mint a new key from the system CSPRNG. The seed is handed back wrapped
    /// so the caller can store it and have it wiped when the copy is dropped.
    pub fn generate() -> Result<(Self, Zeroizing<[u8; 32]>)> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut_slice())
            .map_err(|e| anyhow::anyhow!("the system CSPRNG refused: {e}"))?;
        let signing = SigningKey::from_bytes(&seed);
        Ok((Self { signing }, seed))
    }

    /// Rebuild a key from a stored 32-byte seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() != 32 {
            bail!("an Ed25519 seed is 32 bytes, not {}", seed.len());
        }
        let mut fixed = [0u8; 32];
        fixed.copy_from_slice(seed);
        let signing = SigningKey::from_bytes(&fixed);
        fixed.iter_mut().for_each(|b| *b = 0);
        Ok(Self { signing })
    }

    /// The raw 32-byte public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The SSH public-key blob, for an `authorized_keys` line and for matching
    /// a sign request.
    pub fn public_blob(&self) -> Vec<u8> {
        super::wire::ed25519_public_blob(&self.public_key())
    }

    /// The full `ssh-ed25519 <base64> <comment>` line.
    pub fn authorized_key_line(&self, comment: &str) -> String {
        super::wire::authorized_key_line(&self.public_key(), comment)
    }

    /// Sign `data`, returning the SSH signature blob.
    pub fn sign_blob(&self, data: &[u8]) -> Vec<u8> {
        let sig = self.signing.sign(data);
        super::wire::ed25519_signature_blob(&sig.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    /// A stored seed rebuilds the same key: same public half, same signatures.
    #[test]
    fn a_seed_round_trips_to_the_same_key() {
        let (key, seed) = SshKey::generate().unwrap();
        let again = SshKey::from_seed(seed.as_slice()).unwrap();
        assert_eq!(key.public_key(), again.public_key());
        assert_eq!(
            key.sign_blob(b"same message"),
            again.sign_blob(b"same message"),
            "Ed25519 is deterministic, so the two must agree byte for byte"
        );
    }

    /// The whole point: a signature this agent produces verifies under the
    /// public key it advertises, checked with the verifying half of the same
    /// library a client would use.
    #[test]
    fn a_signature_verifies_under_the_advertised_public_key() {
        let (key, _seed) = SshKey::generate().unwrap();
        let data = b"the bytes ssh handed the agent to sign";

        // Pull the raw signature back out of the SSH blob.
        let blob = key.sign_blob(data);
        let mut r = super::super::wire::Reader::new(&blob);
        assert_eq!(r.utf8().unwrap(), "ssh-ed25519");
        let raw = r.string().unwrap();
        assert_eq!(raw.len(), 64);

        let vk = VerifyingKey::from_bytes(&key.public_key()).unwrap();
        let sig = Signature::from_slice(&raw).unwrap();
        vk.verify(data, &sig).expect("the signature must verify");

        // And not over different bytes.
        assert!(vk.verify(b"other bytes", &sig).is_err());
    }

    #[test]
    fn a_seed_of_the_wrong_length_is_refused() {
        assert!(SshKey::from_seed(&[0u8; 31]).is_err());
        assert!(SshKey::from_seed(&[0u8; 33]).is_err());
        assert!(SshKey::from_seed(&[]).is_err());
        assert!(SshKey::from_seed(&[0u8; 32]).is_ok());
    }

    #[test]
    fn two_generated_keys_differ() {
        let (a, _) = SshKey::generate().unwrap();
        let (b, _) = SshKey::generate().unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    /// The advertised public blob is exactly what the seed produces, so an
    /// authorized_keys line pasted onto a server matches what the agent offers.
    #[test]
    fn the_public_blob_matches_the_seed() {
        let (key, seed) = SshKey::generate().unwrap();
        let derived = SshKey::from_seed(seed.as_slice()).unwrap();
        assert_eq!(key.public_blob(), derived.public_blob());
        assert!(key.authorized_key_line("me@host").starts_with("ssh-ed25519 "));
    }
}
