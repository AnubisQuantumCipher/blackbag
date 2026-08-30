//! Reads a `black-bagg` 0.4.x (format v1) vault so nothing is stranded.
//!
//! The v1 structures are redeclared here rather than imported, because the
//! engine no longer models that format. This module is the only place that
//! knows about the self-directed ML-KEM lane: v1 wrapped the DEK under a KEM
//! shared secret whose decapsulation key was itself sealed under the
//! passphrase KEK and stored in the same header, so the unlock walk is
//! passphrase -> KEK -> dk -> shared -> DEK.

use anyhow::{anyhow, bail, Context, Result};
use blackbag_core::record::{Kind, Record, Secret, TotpAlgorithm, TotpConfig};
use chrono::{DateTime, Utc};
use ml_kem::array::Array;
use ml_kem::{Decapsulate, DecapsulationKey, ExpandedDecapsulationKey, MlKem1024};
// The v1 format only ever wrote the expanded decapsulation-key encoding, so
// this deprecated trait is the only way left to read it back.
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use serde::Deserialize;
use std::path::Path;
use zeroize::Zeroizing;

const V1_AAD_DEK: &[u8] = b"black-bag::sealed-dek";
const V1_AAD_DK: &[u8] = b"black-bag::sealed-dk";
const V1_AAD_PAYLOAD: &[u8] = b"black-bag::payload";

#[derive(Deserialize)]
struct V1File {
    version: u32,
    header: V1Header,
    payload: V1Blob,
}

#[derive(Deserialize)]
struct V1Header {
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    updated_at: DateTime<Utc>,
    argon: V1Argon,
    #[allow(dead_code)]
    kem_public: Vec<u8>,
    kem_ciphertext: Vec<u8>,
    sealed_decapsulation: V1Blob,
    sealed_dek: V1Blob,
}

#[derive(Deserialize)]
struct V1Argon {
    mem_cost_kib: u32,
    time_cost: u32,
    lanes: u32,
    salt: [u8; 32],
}

#[derive(Deserialize)]
struct V1Blob {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
struct V1Payload {
    records: Vec<V1Record>,
    #[allow(dead_code)]
    record_counter: u64,
}

#[derive(Deserialize)]
struct V1Record {
    #[allow(dead_code)]
    id: uuid::Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    title: Option<String>,
    tags: Vec<String>,
    metadata_notes: Option<String>,
    data: V1Data,
}

#[derive(Deserialize)]
struct V1Sensitive {
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum V1Data {
    Login {
        username: Option<String>,
        url: Option<String>,
        password: V1Sensitive,
    },
    Contact {
        full_name: String,
        emails: Vec<String>,
        phones: Vec<String>,
    },
    Id {
        id_type: Option<String>,
        name_on_doc: Option<String>,
        number: Option<String>,
        issuing_country: Option<String>,
        expiry: Option<String>,
        secret: Option<V1Sensitive>,
    },
    Note {
        body: V1Sensitive,
    },
    Bank {
        institution: Option<String>,
        account_name: Option<String>,
        routing_number: Option<String>,
        account_number: V1Sensitive,
    },
    Wifi {
        ssid: Option<String>,
        security: Option<String>,
        location: Option<String>,
        passphrase: V1Sensitive,
    },
    Api {
        service: Option<String>,
        environment: Option<String>,
        access_key: Option<String>,
        secret_key: V1Sensitive,
        scopes: Vec<String>,
    },
    Wallet {
        asset: Option<String>,
        address: Option<String>,
        network: Option<String>,
        secret_key: V1Sensitive,
    },
    Totp {
        issuer: Option<String>,
        account: Option<String>,
        secret: V1Sensitive,
        digits: u8,
        step: u64,
        skew: u8,
        algorithm: V1TotpAlgorithm,
    },
    Ssh {
        label: Option<String>,
        private_key: V1Sensitive,
        comment: Option<String>,
    },
    Pgp {
        label: Option<String>,
        fingerprint: Option<String>,
        armored_private_key: V1Sensitive,
    },
    Recovery {
        description: Option<String>,
        payload: V1Sensitive,
    },
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum V1TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<V1TotpAlgorithm> for TotpAlgorithm {
    fn from(value: V1TotpAlgorithm) -> Self {
        match value {
            V1TotpAlgorithm::Sha1 => TotpAlgorithm::Sha1,
            V1TotpAlgorithm::Sha256 => TotpAlgorithm::Sha256,
            V1TotpAlgorithm::Sha512 => TotpAlgorithm::Sha512,
        }
    }
}

fn v1_open(key: &[u8], blob: &V1Blob, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&blob.nonce),
            Payload {
                msg: &blob.ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("decryption failed (wrong passphrase, or the file is damaged)"))?;
    Ok(Zeroizing::new(plaintext))
}

/// Decrypt a v1 vault and return its records in the v2 shape.
pub fn read_v1(path: &Path, passphrase: &[u8]) -> Result<Vec<Record>> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let file: V1File =
        ciborium::de::from_reader(bytes.as_slice()).context("not a parseable black-bagg vault")?;
    if file.version != 1 {
        bail!("expected a v1 vault, found version {}", file.version);
    }

    // passphrase -> KEK
    let params = Params::new(
        file.header.argon.mem_cost_kib,
        file.header.argon.time_cost,
        file.header.argon.lanes,
        Some(32),
    )
    .map_err(|e| anyhow!("invalid Argon2 parameters in the old vault: {e}"))?;
    let mut kek = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, &file.header.argon.salt, kek.as_mut())
        .map_err(|e| anyhow!("argon2 derivation failed: {e}"))?;

    // KEK -> decapsulation key -> shared secret -> DEK
    let dk_bytes = v1_open(kek.as_ref(), &file.header.sealed_decapsulation, V1_AAD_DK)?;
    // black-bagg 0.4.x (ml-kem 0.3.0-pre) always stored the expanded
    // decapsulation key, never a seed. ml-kem 0.3.2 keeps that encoding
    // reachable only through the deprecated `ExpandedKeyEncoding` trait, which
    // is the only reason it appears here rather than `DecapsulationKey::from_seed`.
    let expected = std::mem::size_of::<ExpandedDecapsulationKey<MlKem1024>>();
    let encoded: ExpandedDecapsulationKey<MlKem1024> = Array::try_from(dk_bytes.as_slice())
        .map_err(|_| {
            anyhow!(
                "decapsulation key is {} bytes, expected {expected}",
                dk_bytes.len()
            )
        })?;
    #[allow(deprecated)]
    let dk = DecapsulationKey::<MlKem1024>::from_expanded_bytes(&encoded).map_err(|_| {
        anyhow!("decapsulation key failed validation (wrong passphrase, or the file is damaged)")
    })?;

    let shared = dk
        .decapsulate_slice(&file.header.kem_ciphertext)
        .map_err(|_| anyhow!("KEM ciphertext has the wrong length"))?;

    let dek = v1_open(shared.as_slice(), &file.header.sealed_dek, V1_AAD_DEK)?;
    let plaintext = v1_open(&dek, &file.payload, V1_AAD_PAYLOAD)?;
    let payload: V1Payload = ciborium::de::from_reader(plaintext.as_slice())
        .context("failed to parse the old payload")?;

    Ok(payload.records.into_iter().map(convert).collect())
}

fn convert(old: V1Record) -> Record {
    let (kind, attributes, fields, totp) = convert_data(old.data);
    let mut record = Record::new(kind, old.title);
    record.created_at = old.created_at;
    record.updated_at = old.updated_at;
    record.tags = old.tags;
    record.attributes = attributes;
    record.fields = fields;
    record.totp = totp;
    // v1's `metadata_notes` was stored in the clear inside the payload. It is a
    // secret field here, because "notes" on a credential routinely are one.
    if let Some(notes) = old.metadata_notes {
        record.notes = Some(Secret::from_str(&notes));
    }
    record
}

type Converted = (
    Kind,
    Vec<(String, String)>,
    Vec<blackbag_core::record::Field>,
    Option<TotpConfig>,
);

fn convert_data(data: V1Data) -> Converted {
    fn attr(out: &mut Vec<(String, String)>, key: &str, value: Option<String>) {
        if let Some(value) = value {
            if !value.is_empty() {
                out.push((key.to_string(), value));
            }
        }
    }
    fn field(name: &str, secret: V1Sensitive) -> blackbag_core::record::Field {
        blackbag_core::record::Field {
            name: name.to_string(),
            secret: Secret::new(&secret.data),
        }
    }

    let mut attributes = Vec::new();
    let mut fields = Vec::new();
    let mut totp = None;

    let kind = match data {
        V1Data::Login {
            username,
            url,
            password,
        } => {
            attr(&mut attributes, "username", username);
            attr(&mut attributes, "url", url);
            fields.push(field("password", password));
            Kind::Login
        }
        V1Data::Contact {
            full_name,
            emails,
            phones,
        } => {
            attributes.push(("full_name".into(), full_name));
            if !emails.is_empty() {
                attributes.push(("emails".into(), emails.join(",")));
            }
            if !phones.is_empty() {
                attributes.push(("phones".into(), phones.join(",")));
            }
            Kind::Contact
        }
        V1Data::Id {
            id_type,
            name_on_doc,
            number,
            issuing_country,
            expiry,
            secret,
        } => {
            attr(&mut attributes, "id_type", id_type);
            attr(&mut attributes, "name_on_doc", name_on_doc);
            attr(&mut attributes, "issuing_country", issuing_country);
            attr(&mut attributes, "expiry", expiry);
            // v1 kept the document number as an open string; it is secret here.
            if let Some(number) = number {
                fields.push(blackbag_core::record::Field {
                    name: "number".into(),
                    secret: Secret::from_str(&number),
                });
            }
            if let Some(secret) = secret {
                fields.push(field("secret", secret));
            }
            Kind::Id
        }
        V1Data::Note { body } => {
            fields.push(field("body", body));
            Kind::Note
        }
        V1Data::Bank {
            institution,
            account_name,
            routing_number,
            account_number,
        } => {
            attr(&mut attributes, "institution", institution);
            attr(&mut attributes, "account_name", account_name);
            attr(&mut attributes, "routing_number", routing_number);
            fields.push(field("account_number", account_number));
            Kind::Bank
        }
        V1Data::Wifi {
            ssid,
            security,
            location,
            passphrase,
        } => {
            attr(&mut attributes, "ssid", ssid);
            attr(&mut attributes, "security", security);
            attr(&mut attributes, "location", location);
            fields.push(field("passphrase", passphrase));
            Kind::Wifi
        }
        V1Data::Api {
            service,
            environment,
            access_key,
            secret_key,
            scopes,
        } => {
            attr(&mut attributes, "service", service);
            attr(&mut attributes, "environment", environment);
            attr(&mut attributes, "access_key", access_key);
            if !scopes.is_empty() {
                attributes.push(("scopes".into(), scopes.join(",")));
            }
            fields.push(field("secret_key", secret_key));
            Kind::Api
        }
        V1Data::Wallet {
            asset,
            address,
            network,
            secret_key,
        } => {
            attr(&mut attributes, "asset", asset);
            attr(&mut attributes, "address", address);
            attr(&mut attributes, "network", network);
            fields.push(field("seed", secret_key));
            Kind::Wallet
        }
        V1Data::Totp {
            issuer,
            account,
            secret,
            digits,
            step,
            skew,
            algorithm,
        } => {
            attr(&mut attributes, "issuer", issuer.clone());
            attr(&mut attributes, "account", account.clone());
            fields.push(field("totp", secret));
            totp = Some(TotpConfig {
                issuer,
                account,
                digits,
                step,
                skew,
                algorithm: algorithm.into(),
            });
            Kind::Totp
        }
        V1Data::Ssh {
            label,
            private_key,
            comment,
        } => {
            attr(&mut attributes, "label", label);
            attr(&mut attributes, "comment", comment);
            fields.push(field("private_key", private_key));
            Kind::Ssh
        }
        V1Data::Pgp {
            label,
            fingerprint,
            armored_private_key,
        } => {
            attr(&mut attributes, "label", label);
            attr(&mut attributes, "fingerprint", fingerprint);
            fields.push(field("private_key", armored_private_key));
            Kind::Pgp
        }
        V1Data::Recovery {
            description,
            payload,
        } => {
            attr(&mut attributes, "description", description);
            fields.push(field("payload", payload));
            Kind::Recovery
        }
    };

    (kind, attributes, fields, totp)
}
