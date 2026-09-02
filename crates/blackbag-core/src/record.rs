//! Record types and the secret buffer they are built from.

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::secmem::{Guarded, KeyBacking, SecretBuf};

/// Per-field caps, restored from black-bagg 0.2.x. Enforced on the way in *and*
/// on the way out, so a hostile vault file cannot blow memory during decode.
pub const MAX_FIELD_BYTES: usize = 8 * 1024;
pub const MAX_NOTE_BYTES: usize = 256 * 1024;
pub const MAX_RECORDS: usize = 100_000;
pub const MAX_TAGS_PER_RECORD: usize = 64;
pub const MAX_TAG_LEN: usize = 128;
pub const MAX_TITLE_LEN: usize = 256;

/// A secret byte string: ciphertext while it rests, plaintext only in a
/// locked buffer while it is used.
///
/// Storage is a [`Guarded`] — sealed under the per-process session key that
/// lives in kernel-invisible memory. [`Secret::open`] hands back the plaintext
/// in a [`SecretBuf`] from the locked arena, wiped when the caller drops it.
/// See `secmem.rs` for the design and what it does and does not buy.
///
/// Serialised as a map with one `data` entry holding the plaintext bytes,
/// exactly as the original `Vec<u8>` design was, so vault format v2 is
/// unchanged and the only place the plaintext is ever serialised is into a
/// payload that is itself about to be encrypted.
#[derive(Serialize, Deserialize)]
pub struct Secret {
    data: Guarded,
}

impl Secret {
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            data: Guarded::new(bytes),
        }
    }

    /// Not `FromStr`: that trait returns a `Result`, and building a secret from
    /// text cannot fail.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        Self::new(s.as_bytes())
    }

    /// The plaintext, decrypted into a locked buffer for as long as the
    /// caller holds it. Hold it briefly.
    pub fn open(&self) -> SecretBuf {
        self.data.open()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Interpret as UTF-8, into a string that is wiped when it is dropped.
    pub fn expose_str(&self) -> Result<Zeroizing<String>> {
        Ok(self.data.open().to_zeroizing_string()?)
    }

    /// Whether the plaintext exists anywhere but a locked buffer while this
    /// secret rests. It does not: the resting form is ciphertext. Kept for
    /// callers that ask the question, and answered from the thing that
    /// actually matters — the home of the session key.
    pub fn is_locked(&self) -> bool {
        !matches!(crate::secmem::session_key_backing(), KeyBacking::Unlocked)
    }

    /// A stable, non-reversible 8-hex-character handle, safe to show in a UI
    /// and safe to write to the status file. Domain-separated so the same
    /// secret in two fields does not produce the same handle.
    pub fn handle(&self, domain: &str) -> String {
        let mut hasher = blake3::Hasher::new_derive_key("black-bag::v2::secret-handle");
        hasher.update(domain.as_bytes());
        let opened = self.data.open();
        hasher.update(opened.as_slice());
        hex::encode(&hasher.finalize().as_bytes()[..4])
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}

impl PartialEq for Secret {
    /// Constant-time over the opened plaintexts. Derived equality on secrets
    /// is a timing oracle.
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Eq for Secret {}

impl std::fmt::Debug for Secret {
    /// Never print secret bytes, not even under `{:?}` in a panic message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({} bytes, redacted)", self.data.len())
    }
}

/// The kind of thing a record holds. Ordering here is the ordering the cockpit
/// rail uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Login,
    Totp,
    Api,
    Ssh,
    Pgp,
    Wallet,
    Bank,
    Wifi,
    Id,
    Contact,
    Note,
    Recovery,
}

impl Kind {
    pub const ALL: [Kind; 12] = [
        Kind::Login,
        Kind::Totp,
        Kind::Api,
        Kind::Ssh,
        Kind::Pgp,
        Kind::Wallet,
        Kind::Bank,
        Kind::Wifi,
        Kind::Id,
        Kind::Contact,
        Kind::Note,
        Kind::Recovery,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Login => "login",
            Kind::Totp => "totp",
            Kind::Api => "api",
            Kind::Ssh => "ssh",
            Kind::Pgp => "pgp",
            Kind::Wallet => "wallet",
            Kind::Bank => "bank",
            Kind::Wifi => "wifi",
            Kind::Id => "id",
            Kind::Contact => "contact",
            Kind::Note => "note",
            Kind::Recovery => "recovery",
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Kind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "login" => Kind::Login,
            "totp" => Kind::Totp,
            "api" => Kind::Api,
            "ssh" => Kind::Ssh,
            "pgp" => Kind::Pgp,
            "wallet" => Kind::Wallet,
            "bank" => Kind::Bank,
            "wifi" => Kind::Wifi,
            "id" => Kind::Id,
            "contact" => Kind::Contact,
            "note" => Kind::Note,
            "recovery" => Kind::Recovery,
            other => bail!("unknown record kind: {other}"),
        })
    }
}

/// TOTP hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            TotpAlgorithm::Sha1 => "sha1",
            TotpAlgorithm::Sha256 => "sha256",
            TotpAlgorithm::Sha512 => "sha512",
        }
    }
}

/// TOTP configuration stored alongside the shared secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpConfig {
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub digits: u8,
    pub step: u64,
    pub skew: u8,
    pub algorithm: TotpAlgorithm,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            account: None,
            digits: 6,
            step: 30,
            skew: 1,
            algorithm: TotpAlgorithm::Sha1,
        }
    }
}

/// A named secret field within a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub secret: Secret,
}

/// A vault record: open metadata plus zero or more secret fields.
///
/// Unlike 0.4.x's twelve-variant enum — where `Contact` had no secret field at
/// all and so was stored in the clear once the payload was open — every kind
/// here uses the same shape, and anything the user marks secret is a [`Secret`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub id: Uuid,
    pub kind: Kind,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub title: Option<String>,
    pub tags: Vec<String>,
    /// Non-secret attributes: username, url, issuer, ssid, address, …
    pub attributes: Vec<(String, String)>,
    /// Secret attributes, page-locked and wiped.
    pub fields: Vec<Field>,
    pub totp: Option<TotpConfig>,
    pub notes: Option<Secret>,
}

impl Record {
    pub fn new(kind: Kind, title: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            kind,
            created_at: now,
            updated_at: now,
            title,
            tags: Vec::new(),
            attributes: Vec::new(),
            fields: Vec::new(),
            totp: None,
            notes: None,
        }
    }

    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn field(&self, name: &str) -> Option<&Secret> {
        self.fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| &f.secret)
    }

    pub fn set_attribute(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        match self.attributes.iter_mut().find(|(k, _)| k == name) {
            Some(slot) => slot.1 = value,
            None => self.attributes.push((name.to_string(), value)),
        }
        self.updated_at = Utc::now();
    }

    pub fn set_field(&mut self, name: &str, secret: Secret) {
        match self.fields.iter_mut().find(|f| f.name == name) {
            Some(slot) => slot.secret = secret,
            None => self.fields.push(Field {
                name: name.to_string(),
                secret,
            }),
        }
        self.updated_at = Utc::now();
    }

    /// Non-secret one-line summary for list views.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = self
            .attributes
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        if parts.is_empty() {
            parts.push(format!("{} field(s)", self.fields.len()));
        }
        parts.join(" ")
    }

    /// Case-insensitive match over open metadata only. Secret bytes are never
    /// searched: a search that matched inside a password would leak it through
    /// timing and through the result set itself.
    pub fn matches(&self, needle: &str) -> bool {
        let needle = needle.to_ascii_lowercase();
        if self
            .title
            .as_deref()
            .is_some_and(|t| t.to_ascii_lowercase().contains(&needle))
        {
            return true;
        }
        if self
            .tags
            .iter()
            .any(|t| t.to_ascii_lowercase().contains(&needle))
        {
            return true;
        }
        if self.kind.as_str().contains(&needle) {
            return true;
        }
        self.attributes
            .iter()
            .any(|(k, v)| {
                k.to_ascii_lowercase().contains(&needle)
                    || v.to_ascii_lowercase().contains(&needle)
            })
    }

    pub fn has_tag(&self, tag: &str) -> bool {
        let tag = tag.to_ascii_lowercase();
        self.tags.iter().any(|t| t.to_ascii_lowercase() == tag)
    }

    /// Reject anything oversized. Called on add and again after decode.
    pub fn validate(&self) -> Result<()> {
        if let Some(title) = &self.title {
            if title.len() > MAX_TITLE_LEN {
                bail!("title too long (max {MAX_TITLE_LEN} bytes)");
            }
        }
        if self.tags.len() > MAX_TAGS_PER_RECORD {
            bail!("too many tags (max {MAX_TAGS_PER_RECORD})");
        }
        for tag in &self.tags {
            if tag.len() > MAX_TAG_LEN {
                bail!("tag too long (max {MAX_TAG_LEN} bytes)");
            }
        }
        for (k, v) in &self.attributes {
            if k.len() > MAX_TAG_LEN || v.len() > MAX_FIELD_BYTES {
                bail!("attribute {k} too large");
            }
        }
        for field in &self.fields {
            if field.secret.len() > MAX_NOTE_BYTES {
                bail!("field {} too large (max {MAX_NOTE_BYTES} bytes)", field.name);
            }
        }
        if let Some(notes) = &self.notes {
            if notes.len() > MAX_NOTE_BYTES {
                bail!("notes too large (max {MAX_NOTE_BYTES} bytes)");
            }
        }
        if let Some(totp) = &self.totp {
            if !(6..=8).contains(&totp.digits) {
                bail!("TOTP digits must be 6-8");
            }
            if totp.step == 0 {
                bail!("TOTP step must be greater than zero");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_never_prints_its_bytes() {
        let s = Secret::from_str("hunter2");
        let shown = format!("{s:?}");
        assert!(!shown.contains("hunter2"), "Debug leaked the secret: {shown}");
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn handles_are_stable_and_domain_separated() {
        let a = Secret::from_str("same-value");
        let b = Secret::from_str("same-value");
        assert_eq!(a.handle("password"), b.handle("password"));
        assert_ne!(a.handle("password"), a.handle("totp"));
        assert_eq!(a.handle("password").len(), 8);
    }

    #[test]
    fn secret_equality_is_length_then_content() {
        assert_eq!(Secret::from_str("abc"), Secret::from_str("abc"));
        assert_ne!(Secret::from_str("abc"), Secret::from_str("abd"));
        assert_ne!(Secret::from_str("abc"), Secret::from_str("abcd"));
    }

    #[test]
    fn search_never_matches_secret_material() {
        let mut r = Record::new(Kind::Login, Some("GitHub".into()));
        r.set_attribute("username", "octocat");
        r.set_field("password", Secret::from_str("correct-horse"));

        assert!(r.matches("github"));
        assert!(r.matches("octocat"));
        assert!(
            !r.matches("correct-horse"),
            "search must not reach into secret fields"
        );
    }

    #[test]
    fn validate_rejects_oversized_input() {
        let mut r = Record::new(Kind::Note, Some("x".into()));
        r.tags = vec!["t".repeat(MAX_TAG_LEN + 1)];
        assert!(r.validate().is_err());

        let mut r2 = Record::new(Kind::Note, None);
        r2.notes = Some(Secret::new(&vec![0u8; MAX_NOTE_BYTES + 1]));
        assert!(r2.validate().is_err());
    }

    #[test]
    fn kind_roundtrips_through_strings() {
        for kind in Kind::ALL {
            let parsed: Kind = kind.as_str().parse().unwrap();
            assert_eq!(parsed, kind);
        }
        assert!("nonsense".parse::<Kind>().is_err());
    }
}
