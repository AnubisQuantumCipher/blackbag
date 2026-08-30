//! Primitives: Argon2id KDF, XChaCha20-Poly1305 AEAD, header MAC, padding.

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Associated-data labels. Every AEAD use is bound to exactly one purpose so a
/// blob can never be replayed into a different slot.
pub const AAD_PAYLOAD: &[u8] = b"black-bag::v2::payload";
pub const AAD_RECIPIENT_PASSPHRASE: &[u8] = b"black-bag::v2::recipient::passphrase";
pub const AAD_RECIPIENT_PQ: &[u8] = b"black-bag::v2::recipient::mlkem1024-x25519";
pub const MAC_CONTEXT: &[u8] = b"black-bag::v2::header-mac";

/// Argon2id defaults. black-bagg 0.2.x shipped time=10 / lanes>=4; the 0.4.x
/// rewrite quietly cut these to time=3 / lanes=1, roughly a 3.3x reduction in
/// KDF work plus the loss of all parallelism. We restore the stronger figures.
pub const DEFAULT_MEM_KIB: u32 = 262_144; // 256 MiB
pub const DEFAULT_TIME_COST: u32 = 10;
pub const MIN_LANES: u32 = 4;
pub const MIN_MEM_KIB: u32 = 32_768; // 32 MiB floor

/// Hard caps applied before and after parsing, restored from 0.2.x. Without
/// these a hostile or corrupt vault file drives unbounded allocation in the
/// CBOR decoder.
pub const MAX_VAULT_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_PAYLOAD_PLAINTEXT_BYTES: usize = 32 * 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

/// Argon2id parameters as stored in the vault, so derivation is reproducible
/// on any host that opens the file.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArgonParams {
    pub mem_cost_kib: u32,
    pub time_cost: u32,
    pub lanes: u32,
    pub salt: [u8; 32],
}

impl ArgonParams {
    /// Fresh parameters with a random salt, lanes scaled to this machine.
    pub fn generate(mem_cost_kib: u32) -> Result<Self> {
        if mem_cost_kib < MIN_MEM_KIB {
            bail!("memory cost must be at least {MIN_MEM_KIB} KiB (32 MiB)");
        }
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        Ok(Self {
            mem_cost_kib,
            time_cost: DEFAULT_TIME_COST,
            lanes: recommended_lanes(),
            salt,
        })
    }

    /// Re-salt in place, used on rotation so the same passphrase yields a new KEK.
    pub fn reseed(&mut self) {
        OsRng.fill_bytes(&mut self.salt);
    }

    /// Canonical big-endian encoding, fed to the header MAC.
    pub fn mac_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(44);
        out.extend_from_slice(&self.mem_cost_kib.to_be_bytes());
        out.extend_from_slice(&self.time_cost.to_be_bytes());
        out.extend_from_slice(&self.lanes.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out
    }
}

/// Lanes for this host: at least [`MIN_LANES`], capped at 8 so a big server does
/// not produce a vault a laptop struggles to open.
pub fn recommended_lanes() -> u32 {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(MIN_LANES);
    cpus.clamp(MIN_LANES, 8)
}

/// Derive the 32-byte key-encryption key from a passphrase.
pub fn derive_kek(passphrase: &[u8], params: &ArgonParams) -> Result<Zeroizing<[u8; 32]>> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let cfg = Params::new(
        params.mem_cost_kib,
        params.time_cost,
        params.lanes,
        Some(32),
    )
    .map_err(|e| anyhow!("invalid Argon2 parameters: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, cfg);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, &params.salt, out.as_mut())
        .map_err(|e| anyhow!("argon2 derivation failed: {e}"))?;
    Ok(out)
}

/// An XChaCha20-Poly1305 ciphertext with its nonce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; 24],
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Encrypt under `key`, binding `aad`.
pub fn seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    if key.len() != 32 {
        bail!("AEAD key must be 32 bytes");
    }
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(Sealed { nonce, ciphertext })
}

/// Decrypt under `key`, requiring the same `aad`.
///
/// The error is deliberately uninformative: 0.2.x sanitised these and the 0.4.x
/// rewrite did not. A caller must not be able to distinguish "wrong passphrase"
/// from "tampered blob" by the message text.
pub fn open(key: &[u8], sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != 32 {
        bail!("AEAD key must be 32 bytes");
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("decryption failed"))?;
    Ok(Zeroizing::new(plaintext))
}

/// Header MAC keyed from the KEK, restored from 0.2.x. Authenticates the parts
/// of the header that no AEAD covers — epoch, Argon2 parameters, recipient
/// descriptors — so rollback and parameter tampering are detected rather than
/// silently accepted.
pub fn header_mac(kek: &[u8], canonical_header: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(kek).expect("HMAC accepts any key length");
    mac.update(MAC_CONTEXT);
    mac.update(canonical_header);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Constant-time MAC comparison.
pub fn mac_matches(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).unwrap_u8() == 1
}

/// Pad to a multiple of `block` so the file size stops leaking how much is
/// stored. Framing is a 4-byte big-endian length followed by the data, then
/// random filler. Restored from 0.2.x's `BLACK_BAG_PAD_BLOCK`.
pub fn pad(data: &[u8], block: usize) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() > MAX_PAYLOAD_PLAINTEXT_BYTES {
        bail!("payload too large");
    }
    let mut out = Vec::with_capacity(data.len() + 4 + block);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    if block > 1 {
        let target = out.len().div_ceil(block) * block;
        let mut filler = vec![0u8; target - out.len()];
        OsRng.fill_bytes(&mut filler);
        out.extend_from_slice(&filler);
    }
    Ok(Zeroizing::new(out))
}

/// Reverse [`pad`].
pub fn unpad(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 4 {
        bail!("padded payload truncated");
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if len > MAX_PAYLOAD_PLAINTEXT_BYTES || 4 + len > data.len() {
        bail!("padded payload length out of range");
    }
    Ok(Zeroizing::new(data[4..4 + len].to_vec()))
}

/// Default padding block, overridable per-vault via `BLACK_BAG_PAD_BLOCK`.
pub fn pad_block() -> usize {
    std::env::var("BLACK_BAG_PAD_BLOCK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|b| *b > 0 && *b <= 1024 * 1024)
        .unwrap_or(4096)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [9u8; 32];
        let sealed = seal(&key, b"mission ops", AAD_PAYLOAD).unwrap();
        let out = open(&key, &sealed, AAD_PAYLOAD).unwrap();
        assert_eq!(out.as_slice(), b"mission ops");
    }

    #[test]
    fn aad_is_binding() {
        let key = [9u8; 32];
        let sealed = seal(&key, b"x", AAD_PAYLOAD).unwrap();
        assert!(open(&key, &sealed, AAD_RECIPIENT_PASSPHRASE).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let key = [3u8; 32];
        let mut sealed = seal(&key, b"payload", AAD_PAYLOAD).unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(open(&key, &sealed, AAD_PAYLOAD).is_err());
    }

    #[test]
    fn padding_roundtrips_and_hides_length() {
        for len in [0usize, 1, 17, 4095, 4096, 4097] {
            let data = vec![0xabu8; len];
            let padded = pad(&data, 4096).unwrap();
            assert_eq!(padded.len() % 4096, 0, "len {len} not padded to a block");
            assert_eq!(unpad(&padded).unwrap().as_slice(), data.as_slice());
        }
    }

    #[test]
    fn unpad_rejects_bogus_length() {
        let mut bad = vec![0u8; 64];
        bad[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(unpad(&bad).is_err());
    }

    #[test]
    fn header_mac_detects_change() {
        let kek = [1u8; 32];
        let a = header_mac(&kek, b"epoch=1");
        let b = header_mac(&kek, b"epoch=2");
        assert!(!mac_matches(&a, &b));
        assert!(mac_matches(&a, &header_mac(&kek, b"epoch=1")));
    }

    #[test]
    fn lanes_are_at_least_the_floor() {
        assert!(recommended_lanes() >= MIN_LANES);
        assert!(recommended_lanes() <= 8);
    }

    #[test]
    fn argon_rejects_tiny_memory() {
        assert!(ArgonParams::generate(1024).is_err());
        assert!(ArgonParams::generate(MIN_MEM_KIB).is_ok());
    }
}
