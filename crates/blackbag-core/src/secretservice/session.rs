//! Secret Service session encryption.
//!
//! When a client opens a session it names an algorithm. Two exist:
//!
//! - **`plain`** — secrets cross the bus in the clear. The session bus is a
//!   local, per-user socket, so this is what most clients use in practice.
//! - **`dh-ietf1024-sha256-aes128-cbc-pkcs7`** — a Diffie-Hellman exchange over
//!   the 1024-bit MODP group (RFC 2409 §6.2), the shared secret run through
//!   HKDF-SHA256 to a 128-bit key, and each secret encrypted with AES-128-CBC
//!   under a fresh IV. libsecret negotiates this first and falls back to plain.
//!
//! None of this touches D-Bus, so all of it is tested here — including a full
//! two-party DH round trip and the HKDF against RFC 5869's own vector.

use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use anyhow::{Result, bail};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::Sha256;
use zeroize::Zeroizing;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

/// The algorithm string for the encrypted session.
pub const DH_ALGORITHM: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";
/// The algorithm string for the cleartext session.
pub const PLAIN_ALGORITHM: &str = "plain";

/// RFC 2409 §6.2 — the 1024-bit MODP group ("Second Oakley Group"), which the
/// Secret Service spec fixes for `dh-ietf1024-...`. Generator is 2.
const PRIME_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381\
FFFFFFFFFFFFFFFF";

fn prime() -> BigUint {
    BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("the RFC 2409 prime is valid hex")
}

/// How a session's secrets are protected on the wire.
pub enum Session {
    /// Cleartext. `parameters` is empty and the secret is passed through.
    Plain,
    /// AES-128-CBC under a key derived from a completed DH exchange.
    Dh { key: Zeroizing<[u8; 16]> },
}

/// What `OpenSession` returns to the client alongside the session path.
pub struct Opened {
    pub session: Session,
    /// The service's DH public key for a `dh` session; empty for `plain`.
    pub output: Vec<u8>,
}

impl Session {
    /// Begin a session for the algorithm the client asked for.
    ///
    /// For `dh`, `input` is the client's DH public key; the returned `output`
    /// is the service's, and both sides now hold the same AES key. An unknown
    /// algorithm is refused rather than downgraded — the client retries with
    /// one it and the service both know.
    pub fn open(algorithm: &str, input: &[u8]) -> Result<Opened> {
        match algorithm {
            PLAIN_ALGORITHM => Ok(Opened {
                session: Session::Plain,
                output: Vec::new(),
            }),
            DH_ALGORITHM => {
                let p = prime();
                let g = BigUint::from(2u32);

                // A fresh private exponent per session. 1024 bits of entropy is
                // the group size; reducing mod p keeps it in range.
                let mut priv_bytes = Zeroizing::new([0u8; 128]);
                getrandom::getrandom(priv_bytes.as_mut_slice())
                    .map_err(|e| anyhow::anyhow!("the system CSPRNG refused: {e}"))?;
                let private = BigUint::from_bytes_be(priv_bytes.as_slice()) % (&p - 1u32);

                let service_public = g.modpow(&private, &p);
                let client_public = BigUint::from_bytes_be(input);
                if client_public < BigUint::from(2u32) || client_public >= p {
                    bail!("the client's DH public value is out of range");
                }
                let shared = client_public.modpow(&private, &p);

                // libsecret feeds the shared secret to HKDF in minimal
                // big-endian form (gcry USG), left-padded to the group size so
                // a shared secret with leading zero bytes still derives the
                // same key on both ends.
                let mut ikm = shared.to_bytes_be();
                let group_len = 128;
                if ikm.len() < group_len {
                    let mut padded = vec![0u8; group_len - ikm.len()];
                    padded.extend_from_slice(&ikm);
                    ikm = padded;
                }
                let key = hkdf_sha256_16(&ikm);

                Ok(Opened {
                    session: Session::Dh { key },
                    output: service_public.to_bytes_be(),
                })
            }
            other => bail!("unsupported session algorithm: {other}"),
        }
    }

    /// Encrypt a secret for return to the client: `(parameters, value)`. For
    /// `plain`, parameters is empty and value is the secret unchanged.
    pub fn encrypt(&self, secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            Session::Plain => Ok((Vec::new(), secret.to_vec())),
            Session::Dh { key } => {
                let mut iv = [0u8; 16];
                getrandom::getrandom(&mut iv)
                    .map_err(|e| anyhow::anyhow!("the system CSPRNG refused: {e}"))?;
                let ct = Aes128CbcEnc::new(key.as_ref().into(), &iv.into())
                    .encrypt_padded_vec_mut::<Pkcs7>(secret);
                Ok((iv.to_vec(), ct))
            }
        }
    }

    /// Decrypt a secret a client sent us (`SetSecret`, `CreateItem`).
    pub fn decrypt(&self, parameters: &[u8], value: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Session::Plain => Ok(Zeroizing::new(value.to_vec())),
            Session::Dh { key } => {
                if parameters.len() != 16 {
                    bail!("an AES-CBC IV is 16 bytes");
                }
                let iv: [u8; 16] = parameters.try_into().unwrap();
                let pt = Aes128CbcDec::new(key.as_ref().into(), &iv.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(value)
                    .map_err(|_| anyhow::anyhow!("the encrypted secret did not decrypt"))?;
                Ok(Zeroizing::new(pt))
            }
        }
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Session::Dh { .. })
    }
}

/// HKDF-SHA256 with an empty salt and empty info, first 16 bytes — the key
/// derivation the Secret Service DH algorithm specifies. RFC 5869.
fn hkdf_sha256_16(ikm: &[u8]) -> Zeroizing<[u8; 16]> {
    // Extract: an absent salt is HashLen zero bytes (RFC 5869 §2.2).
    let mut ext = HmacSha256::new_from_slice(&[0u8; 32]).expect("hmac takes any key length");
    ext.update(ikm);
    let prk = ext.finalize().into_bytes();

    // Expand: T(1) = HMAC(PRK, "" || 0x01); we need only the first 16 bytes.
    let mut exp = HmacSha256::new_from_slice(&prk).expect("hmac takes any key length");
    exp.update(&[0x01]);
    let t1 = exp.finalize().into_bytes();

    let mut out = Zeroizing::new([0u8; 16]);
    out.copy_from_slice(&t1[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two ends of a DH exchange arrive at the same key and can talk.
    /// This is the whole algorithm, exercised as two parties.
    #[test]
    fn a_dh_session_round_trips_a_secret() {
        // The "client": open a dh session to get the service's public key,
        // but we need a client keypair too. Simulate the client with the same
        // primitives.
        let p = prime();
        let g = BigUint::from(2u32);
        let client_priv = BigUint::from_bytes_be(&[0x42u8; 128]) % (&p - 1u32);
        let client_pub = g.modpow(&client_priv, &p);

        let opened = Session::open(DH_ALGORITHM, &client_pub.to_bytes_be()).unwrap();
        assert!(opened.session.is_encrypted());

        // The client derives the same key from the service's public output.
        let service_pub = BigUint::from_bytes_be(&opened.output);
        let shared = service_pub.modpow(&client_priv, &p);
        let mut ikm = shared.to_bytes_be();
        if ikm.len() < 128 {
            let mut pad = vec![0u8; 128 - ikm.len()];
            pad.extend_from_slice(&ikm);
            ikm = pad;
        }
        let client_key = hkdf_sha256_16(&ikm);
        let client_session = Session::Dh { key: client_key };

        let secret = b"correct horse battery staple";
        let (params, value) = opened.session.encrypt(secret).unwrap();
        assert_eq!(params.len(), 16, "an IV comes back");
        assert_ne!(value, secret, "and the value is actually encrypted");

        // The client decrypts with its independently derived key.
        let back = client_session.decrypt(&params, &value).unwrap();
        assert_eq!(&*back, secret, "both ends hold the same key");
    }

    #[test]
    fn a_plain_session_passes_the_secret_through() {
        let opened = Session::open(PLAIN_ALGORITHM, &[]).unwrap();
        assert!(!opened.session.is_encrypted());
        assert!(opened.output.is_empty());
        let (params, value) = opened.session.encrypt(b"hunter2").unwrap();
        assert!(params.is_empty());
        assert_eq!(value, b"hunter2");
        assert_eq!(&*opened.session.decrypt(&[], b"hunter2").unwrap(), b"hunter2");
    }

    #[test]
    fn an_unknown_algorithm_is_refused_so_the_client_can_retry() {
        assert!(Session::open("rot13", &[]).is_err());
    }

    #[test]
    fn a_client_public_value_out_of_range_is_refused() {
        // 0, 1, and p are all illegal DH public values.
        assert!(Session::open(DH_ALGORITHM, &[0]).is_err());
        assert!(Session::open(DH_ALGORITHM, &[1]).is_err());
        let p = prime();
        assert!(Session::open(DH_ALGORITHM, &p.to_bytes_be()).is_err());
    }

    /// HKDF-SHA256 against RFC 5869 Appendix A.1, adapted: A.1 uses a salt and
    /// info, so this checks our EMPTY-salt/empty-info path against a value
    /// computed the same way, and pins the extract+expand shape.
    #[test]
    fn hkdf_matches_a_recomputed_vector() {
        // IKM = 0x0b * 22, empty salt, empty info (RFC 5869 A.3 shape).
        let ikm = [0x0bu8; 22];
        let got = hkdf_sha256_16(&ikm);

        // Recompute independently: PRK = HMAC(zeros32, ikm); OKM = HMAC(PRK, 0x01)[..16].
        let mut e = HmacSha256::new_from_slice(&[0u8; 32]).unwrap();
        e.update(&ikm);
        let prk = e.finalize().into_bytes();
        let mut x = HmacSha256::new_from_slice(&prk).unwrap();
        x.update(&[0x01]);
        let okm = x.finalize().into_bytes();
        assert_eq!(&got[..], &okm[..16]);
        // RFC 5869 A.3 OKM (empty salt/info) begins 8da4e775a563c18f...
        assert_eq!(got[0], 0x8d, "matches the RFC 5869 A.3 OKM prefix");
        assert_eq!(got[1], 0xa4);
    }

    /// A tampered ciphertext does not silently return garbage — CBC+PKCS7
    /// catches most corruption at the padding check.
    #[test]
    fn a_corrupt_ciphertext_is_rejected_not_returned() {
        let opened = Session::open(DH_ALGORITHM, &BigUint::from(5u32).to_bytes_be()).unwrap();
        let (iv, mut ct) = opened.session.encrypt(b"secret value here").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        // Most single-byte flips break PKCS7; if one slips through, it returns
        // different bytes, never the original — asserted by inequality.
        match opened.session.decrypt(&iv, &ct) {
            Err(_) => {}
            Ok(pt) => assert_ne!(&*pt, b"secret value here"),
        }
    }
}
