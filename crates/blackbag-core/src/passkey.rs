//! WebAuthn credentials — the signing half of being a passkey provider.
//!
//! # What this module is, and what it deliberately is not
//!
//! Black-Bag acts as a passkey provider through Chromium's supported
//! `chrome.webAuthenticationProxy` extension API. The browser hands the
//! extension a request as JSON; the extension marshals it here; this module
//! mints the credential or the assertion; the extension hands the result back.
//! **The extension performs no cryptography and holds no key material.** Every
//! private key lives in the vault, and every signature is produced in this
//! process, under the same locked-memory machinery as every other secret.
//!
//! This is not a CTAP authenticator. There is no HID transport, no PIN
//! protocol, no `authenticatorGetInfo`. A virtual USB authenticator was
//! considered and rejected: `/dev/uhid` needs root on this platform, and a
//! HID-discovered device is categorically excluded from `authenticatorAttachment:
//! "platform"` requests by Chromium, so it could only ever be a roaming
//! security key the user re-selects on every ceremony.
//!
//! # The security property that matters most
//!
//! **Chromium does not check what a proxy returns.** It verifies only that a
//! response is internally consistent — that `authenticatorData` matches the
//! copy inside `attestationObject`, that the algorithm matches the key. It does
//! not check that `clientDataJSON.origin` is the origin it asked about, that
//! `rpIdHash` corresponds to the requested RP, that the challenge is the one it
//! issued, or that the signature verifies. The relying party's server is the
//! only thing that catches a lying provider.
//!
//! So origin binding is *our* responsibility. [`rp_id_is_valid_for_origin`]
//! implements it, and [`Credential::assert`] refuses to sign unless it holds.
//! The origin itself must come from the browser — Chromium injects the true
//! caller origin into the request as `extensions.remoteDesktopClientOverride.origin`
//! — and never from a field a socket client could name for itself.
//!
//! # Signature counters
//!
//! Not implemented, on purpose. WebAuthn Level 3 §6.1.1 makes `signCount` a
//! SHOULD, and §7.2 step 22 skips the clone check entirely when both the
//! stored and reported counters are zero. For a vault that can legitimately be
//! restored from backup, a counter manufactures clone warnings for an event
//! that is not a clone, and hands relying parties a correlation handle. It is
//! constant zero.

use anyhow::{anyhow, bail, Context, Result};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::secmem::SecretBuf;

/// COSE algorithm identifier for ECDSA over P-256 with SHA-256.
///
/// The only algorithm this provider mints. Every relying party accepts it —
/// WebAuthn Level 3 §5.4 tells them to include it — so supporting exactly one
/// algorithm well beats supporting three of them approximately.
pub const ALG_ES256: i32 = -7;

/// The field a passkey's private key is stored under.
pub const PRIVATE_KEY_FIELD: &str = "private_key";

/// The field the PRF seed is stored under, when the credential has one.
pub const PRF_SEED_FIELD: &str = "prf_seed";

/// Authenticator data flag bits (WebAuthn Level 3 §6.1).
pub mod flags {
    /// User present.
    pub const UP: u8 = 0x01;
    /// User verified.
    pub const UV: u8 = 0x04;
    /// Backup eligible. Set at creation and immutable thereafter.
    pub const BE: u8 = 0x08;
    /// Backup state — whether the credential is currently backed up.
    pub const BS: u8 = 0x10;
    /// Attested credential data is present.
    pub const AT: u8 = 0x40;
}

/// Everything about a passkey that is not the private key.
///
/// Mirrors the shape of [`crate::record::TotpConfig`]: the non-secret
/// configuration rides on the record, the secret rides in a locked field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyConfig {
    /// Opaque handle the relying party gives back to identify this credential.
    pub credential_id: Vec<u8>,
    /// The relying party this credential belongs to, e.g. `github.com`.
    pub rp_id: String,
    /// Human-readable relying-party name, when one was supplied.
    pub rp_name: Option<String>,
    /// The relying party's own identifier for the user. Opaque bytes, and
    /// CTAP 2.2 §6.1.3 requires it to be returned for a discoverable credential.
    pub user_handle: Vec<u8>,
    /// Account name at the relying party, when supplied.
    pub user_name: Option<String>,
    /// Display name, when supplied.
    pub user_display_name: Option<String>,
    /// COSE algorithm. Always [`ALG_ES256`] for credentials this mints, but
    /// stored rather than assumed so an imported credential can say otherwise.
    pub algorithm: i32,
    /// Whether this credential carries a PRF seed.
    pub prf: bool,
}

/// Everything a create ceremony is asked for.
///
/// A struct rather than eight positional arguments, four of which are bools:
/// `create(rp, name, handle, user, display, true, true, false)` is a line
/// nobody can read, and transposing the last three would silently claim user
/// verification, or a PRF seed, or a backup that does not exist.
#[derive(Debug, Clone)]
pub struct NewCredential {
    pub rp_id: String,
    pub rp_name: Option<String>,
    /// 1-64 bytes, per WebAuthn.
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    /// Set only when a human answered on a surface this process controls.
    pub user_verified: bool,
    /// Mint a PRF seed alongside the key.
    pub with_prf: bool,
    /// Whether a copy of the vault containing this credential already exists.
    /// False for anything created now: a backup taken before this moment
    /// cannot contain it.
    pub backed_up: bool,
}

impl PasskeyConfig {
    /// A label for the deck: the account if there is one, else the RP.
    pub fn describe(&self) -> String {
        match self.user_name.as_deref() {
            Some(name) if !name.is_empty() => format!("{name} at {}", self.rp_id),
            _ => self.rp_id.clone(),
        }
    }
}

/// Is `rp_id` a valid relying-party identifier for `origin`?
///
/// WebAuthn Level 3 §5.1.3 step 8: the RP ID must equal the origin's effective
/// domain or be a registrable-domain suffix of it. This is the check that stops
/// `evil.example` asserting a credential belonging to `bank.example`, and on
/// the proxy path nothing else performs it — Chromium does not, and the relying
/// party only finds out afterwards.
///
/// The suffix test here is deliberately strict about labels: `oogle.com` is not
/// a suffix of `google.com`, because the match must fall on a dot boundary.
///
/// # What this does not do
///
/// It does not consult the Public Suffix List, so it will accept `co.uk` as an
/// RP ID for `shop.co.uk`. That is a real gap and it is why this returns a
/// decision rather than a bare bool in the caller's mind: a provider that wants
/// to close it must ship a PSL. It is recorded in the docs rather than papered
/// over here.
pub fn rp_id_is_valid_for_origin(rp_id: &str, origin: &str) -> bool {
    let Some(host) = origin_host(origin) else {
        return false;
    };
    let rp = rp_id.trim_end_matches('.').to_ascii_lowercase();
    if rp.is_empty() {
        return false;
    }
    if host == rp {
        return true;
    }
    // A registrable-domain suffix, and the match must land on a label boundary.
    host.strip_suffix(&rp)
        .and_then(|prefix| prefix.strip_suffix('.'))
        .is_some_and(|prefix| !prefix.is_empty())
}

/// The host of an `https://` (or `http://localhost`) origin, lowercased.
///
/// Returns `None` for anything that is not a secure context, so a passkey can
/// never be asserted to a plain-HTTP site. `http://localhost` is the exception
/// WebAuthn itself makes for development.
fn origin_host(origin: &str) -> Option<String> {
    let (scheme, rest) = origin.split_once("://")?;
    let host = rest.split('/').next()?;
    // Strip any port, and reject userinfo outright rather than parsing it.
    if host.contains('@') {
        return None;
    }
    let host = match host.rsplit_once(':') {
        // Only strip a trailing :port, never part of an IPv6 literal.
        Some((h, port)) if !h.ends_with(']') && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Some(host),
        "http" if host == "localhost" || host.ends_with(".localhost") => Some(host),
        _ => None,
    }
}

/// A passkey the vault holds: its configuration plus its private key.
pub struct Credential {
    pub config: PasskeyConfig,
    /// The PKCS#8 private key, in locked memory for as long as it is held.
    key: SecretBuf,
}

/// What a freshly minted credential hands back to the browser.
pub struct Created {
    pub credential: Credential,
    /// CBOR `{fmt: "none", attStmt: {}, authData: ..}`.
    pub attestation_object: Vec<u8>,
    /// The same authenticator data, which Chromium cross-checks against the
    /// copy inside `attestation_object`.
    pub authenticator_data: Vec<u8>,
    /// SPKI DER. Chromium requires this for ES256 and rejects the response
    /// without it.
    pub public_key_der: Vec<u8>,
}

/// What an assertion hands back.
pub struct Asserted {
    pub authenticator_data: Vec<u8>,
    /// DER-encoded ECDSA signature, which is what WebAuthn specifies for ES256.
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

impl Credential {
    /// Mint a new credential for `rp_id`.
    ///
    /// `user_verified` records whether a human was actually verified for *this*
    /// ceremony — see the note on [`Credential::assert`].
    pub fn create(req: NewCredential) -> Result<(Created, Option<Zeroizing<[u8; 32]>>)> {
        let NewCredential {
            rp_id,
            rp_name,
            user_handle,
            user_name,
            user_display_name,
            user_verified,
            with_prf,
            backed_up,
        } = req;
        let rp_id = rp_id.as_str();
        if rp_id.trim().is_empty() {
            bail!("a passkey needs a relying-party id");
        }
        if user_handle.is_empty() || user_handle.len() > 64 {
            bail!("a WebAuthn user handle is 1-64 bytes");
        }

        let signing = random_signing_key()?;
        let verifying = *signing.verifying_key();

        // 32 random bytes. WebAuthn Level 3 §4 permits either >=16 random bytes
        // with >=100 bits of entropy, or a key-wrapped credential source; this
        // takes the first option, which keeps the vault the only place the
        // mapping from id to key exists.
        let mut credential_id = [0u8; 32];
        os_random(&mut credential_id)?;

        let prf_seed = match with_prf {
            true => {
                let mut seed = Zeroizing::new([0u8; 32]);
                os_random(seed.as_mut())?;
                Some(seed)
            }
            false => None,
        };

        let config = PasskeyConfig {
            credential_id: credential_id.to_vec(),
            rp_id: rp_id.to_ascii_lowercase(),
            rp_name,
            user_handle,
            user_name,
            user_display_name,
            algorithm: ALG_ES256,
            prf: with_prf,
        };

        let cose = cose_key_es256(&verifying);
        let authenticator_data = authenticator_data(
            &config.rp_id,
            base_flags(user_verified, backed_up) | flags::AT,
            Some((&credential_id, &cose)),
        );
        let attestation_object = attestation_object_none(&authenticator_data)?;

        let public_key_der = verifying
            .to_public_key_der()
            .context("failed to encode the passkey public key as SPKI DER")?
            .as_bytes()
            .to_vec();

        // The PKCS#8 encoding goes straight into locked memory and the
        // intermediate is wiped: this is the byte string that IS the passkey.
        let pkcs8 = {
            use p256::pkcs8::EncodePrivateKey;
            let der = signing
                .to_pkcs8_der()
                .context("failed to encode the passkey private key")?;
            SecretBuf::new(der.as_bytes())
        };

        Ok((
            Created {
                credential: Credential { config, key: pkcs8 },
                attestation_object,
                authenticator_data,
                public_key_der,
            },
            prf_seed,
        ))
    }

    /// Reconstitute a stored credential.
    pub fn from_stored(config: PasskeyConfig, pkcs8: &[u8]) -> Result<Self> {
        // Parse once here so a corrupt key is an error at load rather than a
        // panic at signing time.
        signing_key_from(pkcs8)?;
        Ok(Self {
            config,
            key: SecretBuf::new(pkcs8),
        })
    }

    /// The stored private key, for writing into the vault.
    pub fn private_key(&self) -> &[u8] {
        self.key.as_slice()
    }

    /// Sign an assertion.
    ///
    /// `origin` must be the origin the browser reported, and it is checked
    /// against the credential's own RP ID before anything is signed. A caller
    /// that cannot supply a trustworthy origin must not call this.
    ///
    /// `user_verified` must mean *a human was verified for this ceremony*, not
    /// "the agent happens to be unlocked". An unlocked agent proves someone was
    /// present once; UV asserts they are present now, to the relying party, and
    /// asserting it on the strength of a 40-minute-old unlock would be a lie
    /// told to someone else's security decision.
    pub fn assert(
        &self,
        origin: &str,
        client_data_json: &[u8],
        user_verified: bool,
        backed_up: bool,
    ) -> Result<Asserted> {
        if !rp_id_is_valid_for_origin(&self.config.rp_id, origin) {
            bail!(
                "refusing to assert a passkey for {} to {origin}: the relying \
                 party id is not a registrable-domain suffix of the origin",
                self.config.rp_id
            );
        }

        let authenticator_data =
            authenticator_data(&self.config.rp_id, base_flags(user_verified, backed_up), None);

        // WebAuthn Level 3 §6.3.3: the signature is over
        // authenticatorData || SHA-256(clientDataJSON).
        let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
        signed.extend_from_slice(&authenticator_data);
        signed.extend_from_slice(&Sha256::digest(client_data_json));

        let signing = signing_key_from(self.key.as_slice())?;
        let signature: DerSignature = signing.sign(&signed);

        Ok(Asserted {
            authenticator_data,
            signature: signature.as_bytes().to_vec(),
            user_handle: self.config.user_handle.clone(),
        })
    }
}

/// Rebuild a usable credential from a stored record.
///
/// A passkey record is a [`crate::record::Kind::Passkey`] carrying its
/// [`PasskeyConfig`] and its private key in the [`PRIVATE_KEY_FIELD`] secret
/// field. Anything else is a record that only looks like one.
pub fn credential_from_record(record: &crate::record::Record) -> Result<Credential> {
    let config = record
        .passkey
        .as_ref()
        .ok_or_else(|| anyhow!("record {} carries no passkey configuration", record.id))?
        .clone();
    let key = record
        .field(PRIVATE_KEY_FIELD)
        .ok_or_else(|| anyhow!("passkey record {} has no private key", record.id))?;
    Credential::from_stored(config, &key.open())
}

/// The PRF evaluation a relying party asked for.
///
/// WebAuthn Level 3 §10.1.4 defines the input as
/// `SHA-256("WebAuthn PRF" || 0x00 || salt)`. Chromium hands the salt through
/// the proxy exactly as the relying party supplied it and does **not** apply
/// this derivation, so a provider that skips it produces outputs that no CTAP
/// authenticator would ever reproduce for the same credential.
///
/// The result is the HMAC of that under the credential's own seed, which is why
/// two relying parties asking for the same salt get different answers.
pub fn prf_evaluate(seed: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    use hmac::{Hmac, Mac};

    let mut input = Sha256::new();
    input.update(b"WebAuthn PRF");
    input.update([0x00]);
    input.update(salt);
    let input = input.finalize();

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(seed).expect("HMAC takes any key length");
    mac.update(&input);
    let out = mac.finalize().into_bytes();

    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(&out);
    result
}

/// Flags every ceremony sets.
///
/// **BE is always 1 and never changes for a credential.** This one is
/// multi-device capable by construction: the vault it lives in is a file, and
/// a file can be copied to another machine. That is a property of the design,
/// not of the moment, so it does not move.
///
/// **BS is computed and truthful.** It is 1 only when a copy of this vault
/// that contains this credential is currently known to exist — see
/// [`crate::backup`] for what "currently known" is allowed to mean. It is not
/// set to 1 to look like a synced passkey; a relying party reading BS=1 is
/// being told something, and it should be true.
///
/// BS is allowed to flip 0 → 1 later, when a backup is taken. WebAuthn Level 3
/// §6.1.3 permits that and it is the honest nudge toward taking one.
///
/// **`BE=0, BS=1` is forbidden by §6.1.3** and is unrepresentable here: BS is
/// only ever set inside the branch that has already set BE. If BE ever stops
/// being unconditional, this function has to be re-read — which is what the
/// state-machine tests are for.
fn base_flags(user_verified: bool, backed_up: bool) -> u8 {
    let mut f = flags::UP | flags::BE;
    if backed_up {
        f |= flags::BS;
    }
    if user_verified {
        f |= flags::UV;
    }
    f
}

/// `rpIdHash || flags || signCount || [attestedCredentialData]`.
fn authenticator_data(rp_id: &str, flags: u8, attested: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    out.push(flags);
    // Constant zero, deliberately — see the module note on signature counters.
    out.extend_from_slice(&0u32.to_be_bytes());

    if let Some((credential_id, cose_key)) = attested {
        // AAGUID. WebAuthn Level 3 §8.7 requires 16 zero bytes with the "none"
        // attestation format, so this identifies no authenticator model — which
        // is the privacy-preserving answer as well as the required one.
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        out.extend_from_slice(credential_id);
        out.extend_from_slice(cose_key);
    }
    out
}

/// `{fmt: "none", attStmt: {}, authData: bytes}` and nothing else.
fn attestation_object_none(authenticator_data: &[u8]) -> Result<Vec<u8>> {
    use ciborium::value::Value;

    let value = Value::Map(vec![
        (
            Value::Text("fmt".into()),
            Value::Text("none".into()),
        ),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (
            Value::Text("authData".into()),
            Value::Bytes(authenticator_data.to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out)
        .context("failed to encode the attestation object")?;
    Ok(out)
}

/// COSE_Key for an ES256 public key (RFC 9052 §7, WebAuthn Level 3 §5.8.5).
///
/// Keys are emitted in canonical order — 1, 3, -1, -2, -3 — because a relying
/// party that hashes the credential public key gets a different answer if the
/// map is serialised differently on a later run.
fn cose_key_es256(key: &p256::ecdsa::VerifyingKey) -> Vec<u8> {
    use ciborium::value::Value;

    // SEC1 uncompressed: 0x04 || x(32) || y(32). The shape is asserted rather
    // than assumed — a COSE key built from a compressed point is not the key
    // the relying party will verify against, and it would fail far from here.
    let sec1 = key.to_sec1_bytes();
    assert_eq!(
        sec1.len(),
        65,
        "a P-256 public key must encode as 65 uncompressed SEC1 bytes"
    );
    assert_eq!(sec1[0], 0x04, "the SEC1 point must be uncompressed");
    let x = &sec1[1..33];
    let y = &sec1[33..65];

    let value = Value::Map(vec![
        // kty: EC2
        (Value::Integer(1.into()), Value::Integer(2.into())),
        // alg: ES256
        (Value::Integer(3.into()), Value::Integer(ALG_ES256.into())),
        // crv: P-256
        (Value::Integer((-1).into()), Value::Integer(1.into())),
        (Value::Integer((-2).into()), Value::Bytes(x.to_vec())),
        (Value::Integer((-3).into()), Value::Bytes(y.to_vec())),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out).expect("a COSE key always encodes");
    out
}

/// Fill `out` from the operating system's CSPRNG.
fn os_random(out: &mut [u8]) -> Result<()> {
    getrandom::getrandom(out).map_err(|e| anyhow!("the system CSPRNG refused: {e}"))
}

/// A P-256 signing key from OS randomness.
///
/// `SigningKey::random` wants an RNG implementing `rand_core` 0.10's traits,
/// while this workspace is on the older line; rather than adapt one trait to
/// the other on the key-generation path, this draws bytes from the OS and asks
/// the curve to accept them. A scalar outside the field is rejected rather than
/// reduced — biasing a private key to avoid a retry would be a real weakness,
/// and the probability of even one retry is about 2^-32.
fn random_signing_key() -> Result<SigningKey> {
    for _ in 0..8 {
        let mut bytes = Zeroizing::new([0u8; 32]);
        os_random(bytes.as_mut())?;
        if let Ok(key) = SigningKey::from_slice(bytes.as_ref()) {
            return Ok(key);
        }
    }
    bail!("could not draw a valid P-256 scalar from the system CSPRNG")
}

fn signing_key_from(pkcs8: &[u8]) -> Result<SigningKey> {
    use p256::pkcs8::DecodePrivateKey;
    SigningKey::from_pkcs8_der(pkcs8).map_err(|e| anyhow!("stored passkey key is unusable: {e}"))
}

#[cfg(test)]
mod flag_state_machine {
    use super::{base_flags, flags};

    /// Every state the two backup flags can be in, and the one that is illegal.
    ///
    /// WebAuthn Level 3 §6.1.3: BS may only be 1 when BE is 1. `BE=0, BS=1` is
    /// "an invalid state" and a relying party is entitled to reject it. This
    /// walks the whole space rather than testing the two cases we happen to
    /// produce, because the point of a state machine test is the transitions
    /// nobody wrote code for.
    #[test]
    fn backup_eligible_is_always_set_and_backup_state_never_stands_alone() {
        for uv in [false, true] {
            for backed_up in [false, true] {
                let f = base_flags(uv, backed_up);

                assert_eq!(
                    f & flags::BE,
                    flags::BE,
                    "BE must be 1 in every state (uv={uv}, backed_up={backed_up})"
                );
                assert_eq!(
                    f & flags::BS != 0,
                    backed_up,
                    "BS must say exactly what it was told (uv={uv}, backed_up={backed_up})"
                );
                // The forbidden combination, stated as the invariant rather
                // than as a case: if BS is set, BE is set.
                if f & flags::BS != 0 {
                    assert_eq!(f & flags::BE, flags::BE, "BE=0 with BS=1 is invalid");
                }
                assert_eq!(f & flags::UP, flags::UP, "UP is set by every ceremony here");
                assert_eq!(f & flags::UV != 0, uv, "UV must not be claimed unearned");
            }
        }
    }

    /// The transition the specification allows and we rely on: a credential
    /// that was not backed up becomes backed up, and says so afterwards.
    #[test]
    fn backup_state_may_turn_on_later() {
        let before = base_flags(true, false);
        let after = base_flags(true, true);

        assert_eq!(before & flags::BS, 0, "nothing backed up yet");
        assert_eq!(after & flags::BS, flags::BS, "a backup was taken");
        assert_eq!(
            before & flags::BE,
            after & flags::BE,
            "BE does not move when BS does"
        );
    }

    /// And back off again, which is what makes it truthful rather than a
    /// one-way boast: deleting the backup is visible to the relying party.
    #[test]
    fn backup_state_may_turn_off_again() {
        assert_eq!(base_flags(true, true) & flags::BS, flags::BS);
        assert_eq!(
            base_flags(true, false) & flags::BS,
            0,
            "a deleted backup must stop being asserted"
        );
    }

    /// The bit positions themselves, against the specification's table.
    /// A transposition here would be invisible to every test above.
    #[test]
    fn the_bits_are_where_the_specification_puts_them() {
        assert_eq!(flags::UP, 0x01, "bit 0");
        assert_eq!(flags::UV, 0x04, "bit 2");
        assert_eq!(flags::BE, 0x08, "bit 3");
        assert_eq!(flags::BS, 0x10, "bit 4");
        assert_eq!(flags::AT, 0x40, "bit 6");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    fn a_credential() -> (Created, Option<Zeroizing<[u8; 32]>>) {
        backed_up_credential(false)
    }

    fn backed_up_credential(backed_up: bool) -> (Created, Option<Zeroizing<[u8; 32]>>) {
        Credential::create(NewCredential {
            rp_id: "example.com".into(),
            rp_name: Some("Example".into()),
            user_handle: b"user-handle-bytes".to_vec(),
            user_name: Some("ada".into()),
            user_display_name: Some("Ada Lovelace".into()),
            user_verified: true,
            with_prf: true,
            backed_up,
        })
        .unwrap()
    }

    /// A request that is valid except for whatever the caller overrides.
    fn a_request() -> NewCredential {
        NewCredential {
            rp_id: "example.com".into(),
            rp_name: None,
            user_handle: b"u".to_vec(),
            user_name: None,
            user_display_name: None,
            user_verified: true,
            with_prf: false,
            backed_up: false,
        }
    }

    #[test]
    fn an_assertion_verifies_under_the_public_key_the_ceremony_returned() {
        let (created, _) = a_credential();
        let client_data = br#"{"type":"webauthn.get","challenge":"abc","origin":"https://example.com"}"#;

        let asserted = created
            .credential
            .assert("https://example.com", client_data, true, false)
            .unwrap();

        let mut signed = asserted.authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(client_data));

        // Verify with the key the browser was given, not the one we kept: this
        // is the check a relying party performs.
        use p256::pkcs8::DecodePublicKey;
        let verifying =
            p256::ecdsa::VerifyingKey::from_public_key_der(&created.public_key_der).unwrap();
        let sig = DerSignature::from_bytes(&asserted.signature).unwrap();
        verifying
            .verify(&signed, &sig)
            .expect("the relying party must be able to verify what we signed");
    }

    #[test]
    fn authenticator_data_has_the_shape_the_spec_describes() {
        let (created, _) = a_credential();
        let ad = &created.authenticator_data;

        assert_eq!(&ad[..32], Sha256::digest(b"example.com").as_slice());
        let f = ad[32];
        assert_eq!(f & flags::UP, flags::UP, "user presence");
        assert_eq!(f & flags::UV, flags::UV, "user verified");
        assert_eq!(f & flags::BE, flags::BE, "backup eligible");
        assert_eq!(f & flags::AT, flags::AT, "attested credential data present");
        assert_eq!(&ad[33..37], &[0, 0, 0, 0], "the counter is constant zero");
        assert_eq!(&ad[37..53], &[0u8; 16], "AAGUID is 16 zero bytes for fmt none");

        let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        assert_eq!(id_len, 32);
        assert_eq!(&ad[55..55 + id_len], &created.credential.config.credential_id[..]);
    }

    #[test]
    fn an_assertion_carries_no_attested_credential_data() {
        let (created, _) = a_credential();
        let asserted = created
            .credential
            .assert("https://example.com", b"{}", false, false)
            .unwrap();
        assert_eq!(asserted.authenticator_data.len(), 37);
        assert_eq!(asserted.authenticator_data[32] & flags::AT, 0);
        assert_eq!(asserted.authenticator_data[32] & flags::UV, 0, "UV not claimed");
    }

    #[test]
    fn the_attestation_object_is_fmt_none() {
        let (created, _) = a_credential();
        let value: ciborium::value::Value =
            ciborium::de::from_reader(&created.attestation_object[..]).unwrap();
        let map = value.as_map().unwrap();
        let get = |k: &str| {
            map.iter()
                .find(|(key, _)| key.as_text() == Some(k))
                .map(|(_, v)| v)
                .unwrap()
        };
        assert_eq!(get("fmt").as_text(), Some("none"));
        assert!(get("attStmt").as_map().unwrap().is_empty());
        assert_eq!(
            get("authData").as_bytes().unwrap(),
            &created.authenticator_data
        );
    }

    #[test]
    fn a_passkey_is_never_asserted_to_the_wrong_origin() {
        let (created, _) = a_credential();
        for origin in [
            "https://evil.example",
            "https://notexample.com",
            "https://example.com.evil.test",
            "http://example.com", // not a secure context
            "https://oogle.com",
        ] {
            assert!(
                created.credential.assert(origin, b"{}", true, false).is_err(),
                "must refuse to sign for {origin}"
            );
        }
        // Subdomains of the RP are exactly what an RP ID is for.
        assert!(created
            .credential
            .assert("https://login.example.com", b"{}", true, false)
            .is_ok());
    }

    #[test]
    fn rp_id_suffix_matching_lands_on_label_boundaries() {
        assert!(rp_id_is_valid_for_origin("example.com", "https://example.com"));
        assert!(rp_id_is_valid_for_origin("example.com", "https://a.b.example.com"));
        assert!(rp_id_is_valid_for_origin("example.com", "https://example.com:8443"));
        // The classic near-miss: a suffix that is not a label boundary.
        assert!(!rp_id_is_valid_for_origin("ample.com", "https://example.com"));
        assert!(!rp_id_is_valid_for_origin("example.com", "https://example.com.evil"));
        assert!(!rp_id_is_valid_for_origin("", "https://example.com"));
        // Secure-context rule, with the localhost carve-out WebAuthn makes.
        assert!(!rp_id_is_valid_for_origin("example.com", "http://example.com"));
        assert!(rp_id_is_valid_for_origin("localhost", "http://localhost:8731"));
        // Credentials embedded in the origin are refused rather than parsed.
        assert!(!rp_id_is_valid_for_origin(
            "example.com",
            "https://evil.test@example.com"
        ));
    }

    #[test]
    fn the_prf_applies_the_webauthn_derivation_rather_than_hashing_the_salt_raw() {
        let seed = [7u8; 32];
        let salt = [9u8; 32];

        let got = prf_evaluate(&seed, &salt);

        use hmac::{Hmac, Mac};
        let mut expected_input = Sha256::new();
        expected_input.update(b"WebAuthn PRF");
        expected_input.update([0x00]);
        expected_input.update(salt);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&seed).unwrap();
        mac.update(&expected_input.finalize());
        assert_eq!(got.as_ref(), &mac.finalize().into_bytes()[..]);

        // A different salt, and a different credential seed, both change it.
        assert_ne!(prf_evaluate(&seed, &[1u8; 32]).as_ref(), got.as_ref());
        assert_ne!(prf_evaluate(&[1u8; 32], &salt).as_ref(), got.as_ref());
    }

    #[test]
    fn a_stored_credential_round_trips_and_still_signs() {
        let (created, _) = a_credential();
        let stored = Credential::from_stored(
            created.credential.config.clone(),
            created.credential.private_key(),
        )
        .unwrap();

        let a = stored
            .assert("https://example.com", b"{\"n\":1}", true, false)
            .unwrap();
        let mut signed = a.authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(b"{\"n\":1}"));

        use p256::pkcs8::DecodePublicKey;
        let verifying =
            p256::ecdsa::VerifyingKey::from_public_key_der(&created.public_key_der).unwrap();
        verifying
            .verify(&signed, &DerSignature::from_bytes(&a.signature).unwrap())
            .expect("a reloaded passkey signs as itself");
    }

    #[test]
    fn a_corrupt_stored_key_is_refused_at_load_rather_than_panicking_at_signing() {
        let (created, _) = a_credential();
        let mut key = created.credential.private_key().to_vec();
        key[10] ^= 0xff;
        assert!(Credential::from_stored(created.credential.config.clone(), &key).is_err());
        assert!(Credential::from_stored(created.credential.config, b"").is_err());
    }

    #[test]
    fn bad_ceremony_parameters_are_refused() {
        let bad_handle = Credential::create(NewCredential { user_handle: vec![], ..a_request() });
        assert!(bad_handle.is_err(), "an empty user handle is not a handle");

        let long = Credential::create(NewCredential { user_handle: vec![0; 65], ..a_request() });
        assert!(long.is_err(), "a user handle is at most 64 bytes");

        let no_rp = Credential::create(NewCredential { rp_id: "  ".into(), ..a_request() });
        assert!(no_rp.is_err());
    }

    #[test]
    fn two_credentials_never_share_a_key_or_an_id() {
        let (a, seed_a) = a_credential();
        let (b, seed_b) = a_credential();
        assert_ne!(
            a.credential.config.credential_id,
            b.credential.config.credential_id
        );
        assert_ne!(a.public_key_der, b.public_key_der);
        assert_ne!(a.credential.private_key(), b.credential.private_key());
        assert_ne!(seed_a.unwrap().as_ref(), seed_b.unwrap().as_ref());
    }

    /// A passkey stored as a vault record must come back able to sign, and a
    /// record that only resembles one must be refused rather than half-loaded.
    #[test]
    fn a_record_round_trips_into_a_signing_credential() {
        use crate::record::{Kind, Record, Secret};

        let (created, _) = a_credential();
        let mut record = Record::new(Kind::Passkey, Some("Example".into()));
        record.passkey = Some(created.credential.config.clone());
        record.set_field(PRIVATE_KEY_FIELD, Secret::new(created.credential.private_key()));

        let loaded = credential_from_record(&record).unwrap();
        assert_eq!(loaded.config.rp_id, "example.com");
        let a = loaded.assert("https://example.com", b"{}", true, false).unwrap();

        let mut signed = a.authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(b"{}"));
        use p256::pkcs8::DecodePublicKey;
        p256::ecdsa::VerifyingKey::from_public_key_der(&created.public_key_der)
            .unwrap()
            .verify(&signed, &DerSignature::from_bytes(&a.signature).unwrap())
            .expect("a passkey read back out of a record still signs as itself");

        // No config, or no key, and it must refuse.
        let mut no_config = record.clone();
        no_config.passkey = None;
        assert!(credential_from_record(&no_config).is_err());

        let mut no_key = Record::new(Kind::Passkey, None);
        no_key.passkey = Some(created.credential.config);
        assert!(credential_from_record(&no_key).is_err());
    }

    #[test]
    fn a_credential_without_prf_gets_no_seed() {
        let (created, seed) =
            Credential::create(a_request()).unwrap();
        assert!(seed.is_none());
        assert!(!created.credential.config.prf);
    }
}
