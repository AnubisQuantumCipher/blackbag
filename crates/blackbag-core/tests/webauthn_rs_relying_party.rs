//! A real relying party, from another project, accepting what we mint.
//!
//! Our own tests prove the two halves of this library agree with each other.
//! `tests/passkey_cross_check.py` goes further and rebuilds the key from the
//! COSE bytes with Python's `cbor2` and `cryptography`. This goes further
//! again: `webauthn-rs` is the library a Rust web service actually uses to
//! register and authenticate passkeys, it shares no code with ours, and it
//! applies the whole relying-party ruleset rather than the parts a test author
//! thought to check — challenge binding, origin binding, the rpIdHash, the
//! flag policy, the signature, and the algorithm negotiation.
//!
//! It is a dev-dependency: none of it ships.
//!
//! Two ceremonies are driven end to end for each case: `webauthn-rs` issues a
//! challenge, our authenticator answers it, and `webauthn-rs` decides. A
//! `finish_*` that returns `Ok` is the whole assertion — nothing here inspects
//! bytes, because the point is to let somebody else's rules do the inspecting.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use blackbag_core::passkey::{Credential, NewCredential, ALG_ED25519};
use webauthn_rs::prelude::*;

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

/// The bytes a browser would send, in the order a browser sends them.
fn client_data(kind: &str, challenge: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
        B64.encode(challenge)
    )
    .into_bytes()
}

fn webauthn() -> Webauthn {
    WebauthnBuilder::new(RP_ID, &Url::parse(ORIGIN).unwrap())
        .unwrap()
        .rp_name("Example")
        .build()
        .unwrap()
}

/// Register a credential of ours with a real relying party, and hand back
/// what it stored plus the credential that can sign for it.
fn register(w: &Webauthn, backed_up: bool) -> (Passkey, Credential) {
    register_with(w, backed_up, Vec::new())
}

fn register_with(w: &Webauthn, backed_up: bool, algorithms: Vec<i32>) -> (Passkey, Credential) {
    let (challenge, state) = w
        .start_passkey_registration(Uuid::new_v4(), "ada", "Ada Lovelace", None)
        .unwrap();

    // The user handle the relying party chose, not one we invented: a passkey
    // that came back with a different one would be a different account.
    let user_handle = challenge.public_key.user.id.clone().into();
    let challenge_bytes: Vec<u8> = challenge.public_key.challenge.clone().into();

    let (created, _seed) = Credential::create(NewCredential {
        rp_id: RP_ID.into(),
        rp_name: Some("Example".into()),
        user_handle,
        user_name: Some("ada".into()),
        user_display_name: Some("Ada Lovelace".into()),
        user_verified: true,
        with_prf: false,
        backed_up,
        algorithms,
    })
    .expect("our ceremony must succeed");

    let id = B64.encode(&created.credential.config.credential_id);
    let response: RegisterPublicKeyCredential = serde_json::from_value(serde_json::json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "extensions": {},
        "response": {
            "attestationObject": B64.encode(&created.attestation_object),
            "clientDataJSON": B64.encode(client_data("webauthn.create", &challenge_bytes)),
        },
    }))
    .unwrap();

    let stored = w
        .finish_passkey_registration(&response, &state)
        .expect("a real relying party must accept our registration");
    (stored, created.credential)
}

/// Sign one of that relying party's challenges, and let it decide.
fn authenticate(w: &Webauthn, stored: &Passkey, credential: &Credential, backed_up: bool) {
    let (challenge, state) = w
        .start_passkey_authentication(std::slice::from_ref(stored))
        .unwrap();
    let challenge_bytes: Vec<u8> = challenge.public_key.challenge.clone().into();
    let client_data = client_data("webauthn.get", &challenge_bytes);

    let asserted = credential
        .assert(ORIGIN, &client_data, true, backed_up)
        .expect("our assertion must succeed");

    let id = B64.encode(&credential.config.credential_id);
    let response: PublicKeyCredential = serde_json::from_value(serde_json::json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "extensions": {},
        "response": {
            "authenticatorData": B64.encode(&asserted.authenticator_data),
            "clientDataJSON": B64.encode(&client_data),
            "signature": B64.encode(&asserted.signature),
            "userHandle": B64.encode(&credential.config.user_handle),
        },
    }))
    .unwrap();

    w.finish_passkey_authentication(&response, &state)
        .expect("a real relying party must accept our assertion");
}

#[test]
fn a_real_relying_party_registers_and_authenticates_our_passkey() {
    let w = webauthn();
    let (stored, credential) = register(&w, false);
    authenticate(&w, &stored, &credential, false);
}

/// The same, with the backup-state flag set. BS=1 with BE=1 is a legal state
/// and a relying party must not balk at it — this is the half of D2 that
/// cannot be checked by reading our own bytes back.
#[test]
fn a_backed_up_credential_is_accepted_too() {
    let w = webauthn();
    let (stored, credential) = register(&w, true);
    authenticate(&w, &stored, &credential, true);
}

/// A credential registered while not backed up, asserting later once it is.
/// This is the transition D2 relies on, seen from the relying party's side.
#[test]
fn a_credential_may_become_backed_up_between_ceremonies() {
    let w = webauthn();
    let (stored, credential) = register(&w, false);
    authenticate(&w, &stored, &credential, true);
}

/// The negative control. Without this, every assertion above would pass
/// equally well against a relying party that checks nothing.
#[test]
fn a_signature_over_the_wrong_challenge_is_rejected() {
    let w = webauthn();
    let (stored, credential) = register(&w, false);

    let (_challenge, state) = w
        .start_passkey_authentication(std::slice::from_ref(&stored))
        .unwrap();
    // Sign a challenge the relying party never issued.
    let client_data = client_data("webauthn.get", b"not the challenge that was asked");
    let asserted = credential.assert(ORIGIN, &client_data, true, false).unwrap();

    let id = B64.encode(&credential.config.credential_id);
    let response: PublicKeyCredential = serde_json::from_value(serde_json::json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "extensions": {},
        "response": {
            "authenticatorData": B64.encode(&asserted.authenticator_data),
            "clientDataJSON": B64.encode(&client_data),
            "signature": B64.encode(&asserted.signature),
            "userHandle": B64.encode(&credential.config.user_handle),
        },
    }))
    .unwrap();

    assert!(
        w.finish_passkey_authentication(&response, &state).is_err(),
        "a relying party that accepts any challenge proves nothing about the rest"
    );
}

/// And a tampered signature. Same reason: the positive results are only worth
/// something if the checker can fail.
#[test]
fn a_tampered_signature_is_rejected() {
    let w = webauthn();
    let (stored, credential) = register(&w, false);

    let (challenge, state) = w
        .start_passkey_authentication(std::slice::from_ref(&stored))
        .unwrap();
    let challenge_bytes: Vec<u8> = challenge.public_key.challenge.clone().into();
    let client_data = client_data("webauthn.get", &challenge_bytes);
    let asserted = credential.assert(ORIGIN, &client_data, true, false).unwrap();

    let mut signature = asserted.signature.clone();
    let last = signature.len() - 1;
    signature[last] ^= 0xff;

    let id = B64.encode(&credential.config.credential_id);
    let response: PublicKeyCredential = serde_json::from_value(serde_json::json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "extensions": {},
        "response": {
            "authenticatorData": B64.encode(&asserted.authenticator_data),
            "clientDataJSON": B64.encode(&client_data),
            "signature": B64.encode(&signature),
            "userHandle": B64.encode(&credential.config.user_handle),
        },
    }))
    .unwrap();

    assert!(
        w.finish_passkey_authentication(&response, &state).is_err(),
        "a tampered signature must not verify"
    );
}

/// A registration whose authenticator data names a different relying party.
///
/// The positive registrations above are only evidence if `finish_*` can
/// refuse one, and the rpIdHash is the field a relying party checks first.
#[test]
fn a_registration_for_another_relying_party_is_rejected() {
    let w = webauthn();
    let (challenge, state) = w
        .start_passkey_registration(Uuid::new_v4(), "ada", "Ada Lovelace", None)
        .unwrap();
    let challenge_bytes: Vec<u8> = challenge.public_key.challenge.clone().into();

    let (created, _) = Credential::create(NewCredential {
        // Everything else is honest; only the relying party is wrong.
        rp_id: "attacker.test".into(),
        rp_name: None,
        user_handle: challenge.public_key.user.id.clone().into(),
        user_name: None,
        user_display_name: None,
        user_verified: true,
        with_prf: false,
        backed_up: false,
        algorithms: Vec::new(),
    })
    .unwrap();

    let id = B64.encode(&created.credential.config.credential_id);
    let response: RegisterPublicKeyCredential = serde_json::from_value(serde_json::json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "extensions": {},
        "response": {
            "attestationObject": B64.encode(&created.attestation_object),
            "clientDataJSON": B64.encode(client_data("webauthn.create", &challenge_bytes)),
        },
    }))
    .unwrap();

    assert!(
        w.finish_passkey_registration(&response, &state).is_err(),
        "a relying party that registers a credential minted for someone else \
         would make every registration above meaningless"
    );
}

/// A registration answering a challenge nobody issued.
#[test]
fn a_registration_over_the_wrong_challenge_is_rejected() {
    let w = webauthn();
    let (challenge, state) = w
        .start_passkey_registration(Uuid::new_v4(), "ada", "Ada Lovelace", None)
        .unwrap();

    let (created, _) = Credential::create(NewCredential {
        rp_id: RP_ID.into(),
        rp_name: None,
        user_handle: challenge.public_key.user.id.clone().into(),
        user_name: None,
        user_display_name: None,
        user_verified: true,
        with_prf: false,
        backed_up: false,
        algorithms: Vec::new(),
    })
    .unwrap();

    let id = B64.encode(&created.credential.config.credential_id);
    let response: RegisterPublicKeyCredential = serde_json::from_value(serde_json::json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "extensions": {},
        "response": {
            "attestationObject": B64.encode(&created.attestation_object),
            "clientDataJSON": B64.encode(client_data("webauthn.create", b"a challenge from nowhere")),
        },
    }))
    .unwrap();

    assert!(
        w.finish_passkey_registration(&response, &state).is_err(),
        "the challenge binds the ceremony; without that check it is not a ceremony"
    );
}

/// A real relying party parses the Ed25519 credential we mint.
///
/// `webauthn-rs`'s default passkey policy requests ES256/RS256, not EdDSA, so
/// it declines an Ed25519 credential — but only *after* decoding the
/// attestation object and the COSE OKP key and reading its algorithm. A
/// malformed OKP key would fail earlier and differently (a CBOR or
/// `COSEKeyEDDSA*` error); reaching `CredentialAlteredAlgFromRequest` proves an
/// independent library reads our Ed25519 encoding as well-formed EdDSA and
/// objects only on its own algorithm policy. Our Ed25519 *signatures* are
/// verified end-to-end by an independent `ed25519-dalek` verifier in
/// `passkey.rs`; this is the second-implementation check on the encoding.
#[test]
fn a_real_relying_party_reads_our_ed25519_cose_key_as_well_formed_eddsa() {
    let w = webauthn();
    let (challenge, state) = w
        .start_passkey_registration(Uuid::new_v4(), "ada", "Ada Lovelace", None)
        .unwrap();
    let user_handle = challenge.public_key.user.id.clone().into();
    let challenge_bytes: Vec<u8> = challenge.public_key.challenge.clone().into();

    let (created, _) = Credential::create(NewCredential {
        rp_id: RP_ID.into(),
        rp_name: Some("Example".into()),
        user_handle,
        user_name: Some("ada".into()),
        user_display_name: Some("Ada Lovelace".into()),
        user_verified: true,
        with_prf: false,
        backed_up: false,
        algorithms: vec![ALG_ED25519],
    })
    .expect("our ceremony must succeed");

    let id = B64.encode(&created.credential.config.credential_id);
    let response: RegisterPublicKeyCredential = serde_json::from_value(serde_json::json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "extensions": {},
        "response": {
            "attestationObject": B64.encode(&created.attestation_object),
            "clientDataJSON": B64.encode(client_data("webauthn.create", &challenge_bytes)),
        },
    }))
    .unwrap();

    let err = w
        .finish_passkey_registration(&response, &state)
        .expect_err("the default policy did not request EdDSA");
    // The objection is the algorithm policy, reached only after a clean decode —
    // not a malformation of the key or attestation.
    assert!(
        format!("{err:?}").contains("CredentialAlteredAlgFromRequest"),
        "expected an algorithm-policy rejection after a clean decode, got {err:?}"
    );
}
