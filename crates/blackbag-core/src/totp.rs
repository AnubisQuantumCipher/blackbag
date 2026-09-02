//! RFC 6238 time-based one-time passwords, computed in locked memory.
//!
//! # Why this is not a dependency
//!
//! `totp-rs` takes its shared secret as an ordinary `Vec<u8>` and holds it for
//! the life of the `TOTP` object with no zeroization. Every code the deck
//! displayed therefore copied a 2FA shared secret — the long-lived credential,
//! not the six digits — into unlocked heap that was freed without being wiped.
//! The vault's whole memory design says secrets live in the arena and nowhere
//! else, and a dependency in the middle of the secret path made that false.
//!
//! HOTP is a HMAC, a truncation and a modulus. Implementing it here costs
//! about forty lines, removes a crate from the mandatory secret path, and lets
//! the shared secret stay in a [`SecretBuf`] from the vault to the HMAC and no
//! further. The RFC 6238 Appendix B vectors are asserted below for all three
//! hash functions, which is a stronger check than trusting a crate's own.

use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::record::TotpAlgorithm;
use crate::secmem::SecretBuf;

/// Digits a code may have. Wider than the RFC's 6, because issuers ship 7 and
/// 8, and narrower than a `u8`, because 10 digits overflows the truncation.
pub const MIN_DIGITS: u8 = 6;
pub const MAX_DIGITS: u8 = 8;

/// One HOTP code for `counter`, per RFC 4226 section 5.3.
///
/// `secret` stays borrowed from locked memory; nothing here copies it.
pub fn hotp(secret: &[u8], counter: u64, digits: u8, algorithm: TotpAlgorithm) -> Result<String> {
    if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        bail!("TOTP digits must be {MIN_DIGITS}-{MAX_DIGITS}");
    }
    let message = counter.to_be_bytes();

    // The MAC output is not secret — it is a function of a counter the world
    // can compute — but it is derived from one, so it goes in the arena too
    // and is wiped when this returns.
    let mac: SecretBuf = match algorithm {
        TotpAlgorithm::Sha1 => mac_with::<Sha1>(secret, &message),
        TotpAlgorithm::Sha256 => mac_with::<Sha256>(secret, &message),
        TotpAlgorithm::Sha512 => mac_with::<Sha512>(secret, &message),
    };

    // Dynamic truncation. The offset comes from the low nibble of the LAST
    // byte, which is why this works unchanged for 20-, 32- and 64-byte digests.
    let bytes = mac.as_slice();
    let offset = (bytes[bytes.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(bytes[offset]) & 0x7f) << 24)
        | (u32::from(bytes[offset + 1]) << 16)
        | (u32::from(bytes[offset + 2]) << 8)
        | u32::from(bytes[offset + 3]);

    let modulus = 10u32.pow(u32::from(digits));
    Ok(format!(
        "{:0width$}",
        binary % modulus,
        width = usize::from(digits)
    ))
}

fn mac_with<D>(secret: &[u8], message: &[u8]) -> SecretBuf
where
    D: digest::Digest + digest::core_api::BlockSizeUser + Clone + digest::FixedOutputReset,
{
    let mut mac = <Hmac<D> as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(message);
    SecretBuf::new(&mac.finalize().into_bytes())
}

/// The code for `unix_seconds`, and how many seconds of its step remain.
pub fn totp_at(
    secret: &[u8],
    unix_seconds: u64,
    step: u64,
    digits: u8,
    algorithm: TotpAlgorithm,
) -> Result<(String, u64)> {
    if step == 0 {
        bail!("TOTP step must be greater than zero");
    }
    let counter = unix_seconds / step;
    let ttl = step - (unix_seconds % step);
    Ok((hotp(secret, counter, digits, algorithm)?, ttl))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B seeds: ASCII "12345678901234567890", repeated to
    /// the hash's block size for the wider functions.
    fn seed(algorithm: TotpAlgorithm) -> Vec<u8> {
        let base = b"12345678901234567890";
        let len = match algorithm {
            TotpAlgorithm::Sha1 => 20,
            TotpAlgorithm::Sha256 => 32,
            TotpAlgorithm::Sha512 => 64,
        };
        base.iter().cycle().copied().take(len).collect()
    }

    /// Every vector in RFC 6238 Appendix B, all three algorithms.
    #[test]
    fn rfc_6238_appendix_b_vectors() {
        let cases: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (t, sha1, sha256, sha512) in cases {
            for (algorithm, expected) in [
                (TotpAlgorithm::Sha1, sha1),
                (TotpAlgorithm::Sha256, sha256),
                (TotpAlgorithm::Sha512, sha512),
            ] {
                let (code, _) = totp_at(&seed(algorithm), *t, 30, 8, algorithm).unwrap();
                assert_eq!(
                    &code, expected,
                    "RFC 6238 vector T={t} {algorithm:?} produced {code}"
                );
            }
        }
    }

    /// RFC 4226 Appendix D, the HOTP counter vectors.
    #[test]
    fn rfc_4226_appendix_d_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            let code = hotp(secret, counter as u64, 6, TotpAlgorithm::Sha1).unwrap();
            assert_eq!(&code, want, "HOTP counter {counter}");
        }
    }

    #[test]
    fn codes_keep_their_leading_zeros() {
        // Counter 0 of the RFC secret at 8 digits is 84755224: not itself a
        // leading-zero case, so construct one and check the width instead.
        for digits in MIN_DIGITS..=MAX_DIGITS {
            for counter in 0..64u64 {
                let code = hotp(b"a-secret", counter, digits, TotpAlgorithm::Sha1).unwrap();
                assert_eq!(code.len(), usize::from(digits), "width for {digits} digits");
                assert!(code.chars().all(|c| c.is_ascii_digit()));
            }
        }
    }

    #[test]
    fn ttl_counts_down_within_the_step() {
        let secret = seed(TotpAlgorithm::Sha1);
        let (_, ttl) = totp_at(&secret, 0, 30, 6, TotpAlgorithm::Sha1).unwrap();
        assert_eq!(ttl, 30, "the first instant of a step has the whole step left");
        let (_, ttl) = totp_at(&secret, 29, 30, 6, TotpAlgorithm::Sha1).unwrap();
        assert_eq!(ttl, 1);
        let (_, ttl) = totp_at(&secret, 30, 30, 6, TotpAlgorithm::Sha1).unwrap();
        assert_eq!(ttl, 30, "and the next step starts over");
    }

    #[test]
    fn the_code_is_constant_across_a_step_and_changes_at_the_boundary() {
        let secret = seed(TotpAlgorithm::Sha1);
        let at = |t| totp_at(&secret, t, 30, 6, TotpAlgorithm::Sha1).unwrap().0;
        assert_eq!(at(60), at(89));
        assert_ne!(at(89), at(90));
    }

    #[test]
    fn bad_parameters_are_refused() {
        assert!(hotp(b"k", 0, 5, TotpAlgorithm::Sha1).is_err());
        assert!(hotp(b"k", 0, 9, TotpAlgorithm::Sha1).is_err());
        assert!(totp_at(b"k", 0, 0, 6, TotpAlgorithm::Sha1).is_err());
    }

    #[test]
    fn an_empty_secret_still_produces_a_code_rather_than_panicking() {
        // Not a good secret, but a vault can hold one and the deck must not
        // crash on it.
        assert!(hotp(b"", 0, 6, TotpAlgorithm::Sha1).is_ok());
    }
}
