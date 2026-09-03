#!/usr/bin/env python3
"""Verify Black-Bag's passkeys the way a relying party would, with code that
shares nothing with Black-Bag.

Our Rust tests verify our own signatures with our own crate: that proves the
signing and verifying halves of one library agree with each other, which is a
weaker statement than it looks. A relying party does something different — it
parses the CBOR attestation object, walks the authenticator data by offset,
pulls the COSE key out of it, rebuilds a P-256 public key from those coordinates
and verifies the signature. Every one of those steps is an opportunity for a
plausible-looking encoding bug that our own verifier would never notice, because
it would make the same mistake in reverse.

Run:
    cargo run --release -p blackbag-core --example passkey_vector > vec.json
    python3 passkey_cross_check.py vec.json

Requires `cbor2` and `cryptography`, neither of which Black-Bag depends on.
"""

import hashlib
import json
import sys

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import hashes, serialization

FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, FLAG_AT = 0x01, 0x04, 0x08, 0x10, 0x40

failures = []


def check(condition, label):
    print(("  ok   " if condition else "  FAIL ") + label)
    if not condition:
        failures.append(label)


def parse_authenticator_data(blob):
    """Walk it by offset, exactly as a relying party must."""
    out = {
        "rp_id_hash": blob[0:32],
        "flags": blob[32],
        "sign_count": int.from_bytes(blob[33:37], "big"),
    }
    if blob[32] & FLAG_AT:
        out["aaguid"] = blob[37:53]
        id_len = int.from_bytes(blob[53:55], "big")
        out["credential_id"] = blob[55 : 55 + id_len]
        out["cose_key"] = cbor2.loads(blob[55 + id_len :])
    return out


def main(path):
    v = json.load(open(path))
    b = lambda k: bytes.fromhex(v[k])

    print("registration")
    att = cbor2.loads(b("attestation_object"))
    check(att["fmt"] == "none", 'attestation fmt is "none"')
    check(att["attStmt"] == {}, "attestation statement is empty")
    check(att["authData"] == b("authenticator_data_create"),
          "authData inside the attestation object matches the one returned alongside it")

    ad = parse_authenticator_data(att["authData"])
    check(ad["rp_id_hash"] == hashlib.sha256(v["rp_id"].encode()).digest(),
          "rpIdHash is SHA-256 of the relying-party id")
    check(ad["flags"] & FLAG_UP, "user-presence flag set")
    check(ad["flags"] & FLAG_UV, "user-verified flag set")
    check(ad["flags"] & FLAG_BE, "backup-eligible flag set")
    check(not (ad["flags"] & FLAG_BS) or (ad["flags"] & FLAG_BE),
          "BS is never set without BE (WebAuthn L3 6.1.3)")
    check(ad["flags"] & FLAG_AT, "attested-credential-data flag set")
    check(ad["sign_count"] == 0, "signature counter is zero")
    check(ad["aaguid"] == bytes(16), "AAGUID is 16 zero bytes, as fmt none requires")
    check(ad["credential_id"] == b("credential_id"), "credential id matches")

    print("COSE key")
    cose = ad["cose_key"]
    check(cose[1] == 2, "kty is EC2")
    check(cose[3] == -7, "alg is ES256 (-7)")
    check(cose[-1] == 1, "crv is P-256")
    x, y = cose[-2], cose[-3]
    check(len(x) == 32 and len(y) == 32, "coordinates are 32 bytes each")

    # Rebuild the key from the COSE coordinates alone — this is the key the
    # relying party stores, and nothing but those bytes went into it.
    from_cose = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
    ).public_key()

    from_der = serialization.load_der_public_key(b("public_key_der"))
    check(
        from_cose.public_numbers() == from_der.public_numbers(),
        "the COSE key and the SPKI DER describe the same public key",
    )

    print("assertion")
    aad = parse_authenticator_data(b("assertion_authenticator_data"))
    check(len(b("assertion_authenticator_data")) == 37,
          "an assertion carries no attested credential data")
    check(not (aad["flags"] & FLAG_AT), "AT flag clear on an assertion")
    check(aad["rp_id_hash"] == hashlib.sha256(v["rp_id"].encode()).digest(),
          "assertion rpIdHash matches the relying party")

    signed = b("assertion_authenticator_data") + hashlib.sha256(b("client_data_json")).digest()
    try:
        from_cose.verify(b("assertion_signature"), signed, ec.ECDSA(hashes.SHA256()))
        check(True, "signature verifies under the COSE key over authData || SHA-256(clientDataJSON)")
    except Exception as e:
        check(False, f"signature verification: {e}")

    # A relying party that is handed a tampered payload must reject it.
    tampered = bytearray(signed)
    tampered[-1] ^= 0x01
    try:
        from_cose.verify(b("assertion_signature"), bytes(tampered), ec.ECDSA(hashes.SHA256()))
        check(False, "a tampered challenge must NOT verify")
    except Exception:
        check(True, "a tampered challenge does not verify")

    print("client data")
    cd = json.loads(b("client_data_json"))
    check(cd["type"] == "webauthn.get", "clientData type is webauthn.get")
    check(cd["origin"] == "https://login.example.com", "clientData carries the caller origin")

    print("PRF")
    # WebAuthn L3 10.1.4: the PRF input is SHA-256("WebAuthn PRF" || 0x00 || salt),
    # and the output is HMAC-SHA-256 of that under the credential's seed.
    import hmac as _hmac

    expected_input = hashlib.sha256(b"WebAuthn PRF" + b"\x00" + b("prf_salt")).digest()
    expected = _hmac.new(b("prf_seed"), expected_input, hashlib.sha256).digest()
    check(expected == b("prf_output"),
          "PRF output matches the WebAuthn derivation computed independently")
    check(
        _hmac.new(b("prf_seed"), b("prf_salt"), hashlib.sha256).digest() != b("prf_output"),
        "PRF is not a bare HMAC of the raw salt (the derivation is actually applied)",
    )

    print()
    if failures:
        print(f"FAILED — {len(failures)} check(s): " + "; ".join(failures))
        return 1
    print("ALL PASS — an independent implementation accepts these credentials")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "vec.json"))
