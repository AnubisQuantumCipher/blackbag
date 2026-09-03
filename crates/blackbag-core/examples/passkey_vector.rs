//! Emit a real registration and assertion so an implementation that shares no
//! code with this one can check them.
//!
//! Our own tests verify our signatures with our own crate, which proves the two
//! halves of one library agree. What a relying party actually does is parse the
//! CBOR attestation object, pull the COSE key out of the authenticator data,
//! rebuild the public key from those bytes and verify. `tests/passkey_cross_check.py`
//! does exactly that with Python's `cbor2` and `cryptography`, and this is what
//! feeds it.
//!
//!     cargo run --release -p blackbag-core --example passkey_vector

use blackbag_core::passkey::{prf_evaluate, Credential};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let client_data = br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://login.example.com","crossOrigin":false}"#;

    let (created, seed) = Credential::create(
        "example.com",
        Some("Example Ltd".into()),
        b"\x01\x02\x03\x04user-handle".to_vec(),
        Some("ada".into()),
        Some("Ada Lovelace".into()),
        true,
        true,
    )
    .expect("the ceremony must succeed");

    let asserted = created
        .credential
        .assert("https://login.example.com", client_data, true)
        .expect("a subdomain of the RP is a legitimate origin");

    let seed = seed.expect("this credential asked for a PRF seed");
    let prf = prf_evaluate(seed.as_ref(), &[0x42; 32]);

    println!(
        r#"{{"attestation_object":"{}","authenticator_data_create":"{}","public_key_der":"{}","credential_id":"{}","rp_id":"{}","assertion_authenticator_data":"{}","assertion_signature":"{}","client_data_json":"{}","user_handle":"{}","prf_seed":"{}","prf_salt":"{}","prf_output":"{}"}}"#,
        hex(&created.attestation_object),
        hex(&created.authenticator_data),
        hex(&created.public_key_der),
        hex(&created.credential.config.credential_id),
        created.credential.config.rp_id,
        hex(&asserted.authenticator_data),
        hex(&asserted.signature),
        hex(client_data),
        hex(&asserted.user_handle),
        hex(seed.as_ref()),
        hex(&[0x42; 32]),
        hex(prf.as_ref()),
    );
}
