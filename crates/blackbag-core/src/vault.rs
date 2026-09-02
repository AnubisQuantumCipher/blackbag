//! Vault format v2.
//!
//! What changed from black-bagg 0.4.x (format v1), and why:
//!
//! * **Recipients are real.** v1 generated an ML-KEM keypair, encapsulated to
//!   its *own* public key, and stored the decapsulation key in the same header
//!   under the passphrase KEK. Every input needed to reach the DEK travelled
//!   with the file, so the KEM contributed exactly nothing — vault security was
//!   Argon2id + XChaCha20-Poly1305 either way. Here a recipient's private key
//!   lives *outside* the vault, so ML-KEM does actual work and the
//!   post-quantum claim is true rather than decorative.
//! * **The header is authenticated.** v1 left epoch-free, MAC-free header
//!   fields open to silent edit. v2 MACs the canonical header under the DEK,
//!   which every recipient recovers, so any unlock path can verify it.
//! * **Rotation rotates.** v1's `rotate` re-wrapped *the same* DEK and could
//!   not change the passphrase, so a DEK exposed once stayed valid forever.
//!   [`Vault::rekey`] mints a new DEK and re-encrypts the payload under it.
//! * **The payload is padded and capped**, so file size stops leaking how much
//!   is stored and a hostile file cannot drive unbounded allocation.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, KeyInit, MlKem1024, TryKeyInit};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{
    self, ArgonParams, Sealed, AAD_PAYLOAD, AAD_RECIPIENT_PASSPHRASE, AAD_RECIPIENT_PQ,
    MAX_VAULT_FILE_BYTES,
};
use crate::memlock;
use crate::record::{Kind, Record, MAX_RECORDS};

pub const VAULT_VERSION: u32 = 2;

/// How a given holder can reach the DEK.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Recipient {
    /// Unlocked by the master passphrase via Argon2id.
    Passphrase {
        argon: ArgonParams,
        sealed_dek: Sealed,
    },
    /// Unlocked by a recovery key file holding an X25519 secret and an ML-KEM-1024
    /// decapsulation key. Neither is stored here — only the public halves and
    /// the encapsulation to them — which is what makes this lane meaningful.
    Hybrid {
        label: String,
        /// X25519 public key of the recovery holder.
        x25519_public: Vec<u8>,
        /// ML-KEM-1024 encapsulation key of the recovery holder.
        mlkem_encapsulation_key: Vec<u8>,
        /// Ephemeral X25519 public key generated at wrap time.
        x25519_ephemeral: Vec<u8>,
        /// ML-KEM-1024 ciphertext produced at wrap time.
        mlkem_ciphertext: Vec<u8>,
        sealed_dek: Sealed,
    },
}

impl Recipient {
    pub fn label(&self) -> &str {
        match self {
            Recipient::Passphrase { .. } => "passphrase",
            Recipient::Hybrid { label, .. } => label,
        }
    }

    pub fn kind_str(&self) -> &'static str {
        match self {
            Recipient::Passphrase { .. } => "passphrase",
            Recipient::Hybrid { .. } => "hybrid-x25519-mlkem1024",
        }
    }

    /// Bytes fed to the header MAC. Covers everything an attacker could gain by
    /// editing: which recipients exist, their public material, their wrapped DEKs.
    fn mac_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.kind_str().as_bytes());
        out.push(0);
        out.extend_from_slice(self.label().as_bytes());
        out.push(0);
        match self {
            Recipient::Passphrase { argon, sealed_dek } => {
                out.extend_from_slice(&argon.mac_bytes());
                out.extend_from_slice(&sealed_dek.nonce);
                out.extend_from_slice(&sealed_dek.ciphertext);
            }
            Recipient::Hybrid {
                x25519_public,
                mlkem_encapsulation_key,
                x25519_ephemeral,
                mlkem_ciphertext,
                sealed_dek,
                ..
            } => {
                for part in [
                    x25519_public,
                    mlkem_encapsulation_key,
                    x25519_ephemeral,
                    mlkem_ciphertext,
                    &sealed_dek.ciphertext,
                ] {
                    out.extend_from_slice(&(part.len() as u32).to_be_bytes());
                    out.extend_from_slice(part);
                }
                out.extend_from_slice(&sealed_dek.nonce);
            }
        }
        out
    }
}

/// Everything outside the encrypted payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub vault_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Monotonic write counter. Compared against an out-of-band witness to
    /// notice a rollback; see [`Witness`].
    pub epoch: u64,
    pub recipients: Vec<Recipient>,
    /// HMAC-SHA256 over the canonical header, keyed by the DEK. Every recipient
    /// recovers the DEK, so every unlock path can check it.
    pub mac: [u8; 32],
}

impl Header {
    /// Canonical serialisation of everything except the MAC itself.
    ///
    /// The payload is bound in by hash, and that is not cosmetic. An earlier
    /// revision MACed the header alone, and because the payload AEAD binds no
    /// epoch, an old payload could be spliced onto a current header: it
    /// unlocked, reported the *current* epoch, raised no rollback suspicion,
    /// and returned stale records. Covering the ciphertext closes that.
    /// `updated_at` is covered for the same reason — it was previously free to
    /// edit without invalidating the tag.
    fn mac_input(&self, payload: &Sealed) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&VAULT_VERSION.to_be_bytes());
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(self.created_at.to_rfc3339().as_bytes());
        out.push(0);
        out.extend_from_slice(self.updated_at.to_rfc3339().as_bytes());
        out.push(0);

        let mut hasher = blake3::Hasher::new_derive_key("black-bag::v2::payload-binding");
        hasher.update(&payload.nonce);
        hasher.update(&payload.ciphertext);
        out.extend_from_slice(hasher.finalize().as_bytes());

        out.extend_from_slice(&(self.recipients.len() as u32).to_be_bytes());
        for recipient in &self.recipients {
            let bytes = recipient.mac_bytes();
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        out
    }
}

/// The on-disk file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    pub header: Header,
    pub payload: Sealed,
}

/// The decrypted contents.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Payload {
    pub records: Vec<Record>,
}

/// Recovery key material handed to the user, never stored in the vault.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryKey {
    pub label: String,
    pub vault_id: Uuid,
    #[serde(with = "serde_bytes")]
    pub x25519_secret: Vec<u8>,
    /// The 64-byte ML-KEM seed (`DecapsulationKey::to_bytes`/`KeyInit`), not the
    /// expanded decapsulation key — ml-kem 0.3.2 treats the seed as the
    /// canonical private-key encoding, and it reconstructs the full key
    /// deterministically.
    #[serde(with = "serde_bytes")]
    pub mlkem_decapsulation_key: Vec<u8>,
}

/// How a vault was unlocked, so the UI can say so truthfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMethod {
    Passphrase,
    RecoveryKey,
}

/// An open vault. The DEK is page-locked and wiped on drop.
pub struct Vault {
    pub path: PathBuf,
    pub file: VaultFile,
    pub payload: Payload,
    dek: Zeroizing<[u8; 32]>,
    _dek_lock: Option<memlock::Lock>,
    pub unlocked_by: UnlockMethod,
    /// Set when the stored epoch was behind the witness — a possible rollback.
    pub rollback_suspected: bool,
    /// Identity of the file as this handle last saw it. Used to notice that
    /// somebody else wrote the vault while we were holding it.
    seen: FileStamp,
}

/// A cheap fingerprint of the file on disk, so the common "nothing changed"
/// case costs a `stat` rather than a full read and decrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct FileStamp {
    len: u64,
    mtime: Option<std::time::SystemTime>,
    /// Every write lands through a rename, so the inode changes each time.
    /// Length alone is useless here — padding makes most writes the same size
    /// — and mtime resolution is the filesystem's, not ours.
    ino: u64,
}

impl FileStamp {
    fn of(path: &Path) -> Self {
        use std::os::unix::fs::MetadataExt;
        match fs::metadata(path) {
            Ok(meta) => Self {
                len: meta.len(),
                mtime: meta.modified().ok(),
                ino: meta.ino(),
            },
            Err(_) => Self::default(),
        }
    }
}

/// Hand-written, never derived: a derived impl would forward through
/// `Zeroizing<[u8; 32]>`'s `Debug` and print the live DEK, including in an
/// `unwrap_err()` panic message on the wrong branch of a test.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("vault_id", &self.file.header.vault_id)
            .field("epoch", &self.file.header.epoch)
            .field("unlocked_by", &self.unlocked_by)
            .field("rollback_suspected", &self.rollback_suspected)
            .field("dek", &"[redacted]")
            .finish()
    }
}

impl Vault {
    /// Create a new vault with a single passphrase recipient.
    pub fn init(path: &Path, passphrase: &[u8], mem_kib: u32) -> Result<()> {
        if path.exists() {
            bail!("vault already exists at {}", path.display());
        }
        let argon = ArgonParams::generate(mem_kib)?;
        let kek = crypto::derive_kek(passphrase, &argon)?;

        let mut dek_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut dek_bytes);
        let dek = Zeroizing::new(dek_bytes);
        let _lock = memlock::Lock::new(dek.as_ref());

        let sealed_dek = crypto::seal(kek.as_ref(), dek.as_ref(), AAD_RECIPIENT_PASSPHRASE)?;
        let now = Utc::now();
        let mut header = Header {
            vault_id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            epoch: 1,
            recipients: vec![Recipient::Passphrase { argon, sealed_dek }],
            mac: [0u8; 32],
        };
        let payload = Payload::default();
        let sealed_payload = seal_payload(dek.as_ref(), &payload)?;
        header.mac = crypto::header_mac(dek.as_ref(), &header.mac_input(&sealed_payload));

        let file = VaultFile {
            version: VAULT_VERSION,
            header,
            payload: sealed_payload,
        };
        write_vault_file(path, &file)?;
        Witness::record(path, file.header.vault_id, 1)?;
        Ok(())
    }

    /// Unlock with the master passphrase.
    pub fn unlock(path: &Path, passphrase: &[u8]) -> Result<Self> {
        let file = read_vault_file(path)?;
        for recipient in &file.header.recipients {
            let Recipient::Passphrase { argon, sealed_dek } = recipient else {
                continue;
            };
            let kek = crypto::derive_kek(passphrase, argon)?;
            let Ok(dek_bytes) = crypto::open(kek.as_ref(), sealed_dek, AAD_RECIPIENT_PASSPHRASE)
            else {
                continue;
            };
            return Self::finish_unlock(path, file, &dek_bytes, UnlockMethod::Passphrase);
        }
        bail!("unlock failed")
    }

    /// Unlock with a recovery key, without the passphrase.
    pub fn unlock_with_recovery(path: &Path, key: &RecoveryKey) -> Result<Self> {
        let file = read_vault_file(path)?;
        if file.header.vault_id != key.vault_id {
            bail!("recovery key belongs to a different vault");
        }
        for recipient in &file.header.recipients {
            let Recipient::Hybrid {
                label,
                x25519_ephemeral,
                mlkem_ciphertext,
                sealed_dek,
                ..
            } = recipient
            else {
                continue;
            };
            if label != &key.label {
                continue;
            }
            let shared = hybrid_decapsulate(key, x25519_ephemeral, mlkem_ciphertext)?;
            let Ok(dek_bytes) = crypto::open(shared.as_ref(), sealed_dek, AAD_RECIPIENT_PQ) else {
                continue;
            };
            return Self::finish_unlock(path, file, &dek_bytes, UnlockMethod::RecoveryKey);
        }
        bail!("unlock failed")
    }

    fn finish_unlock(
        path: &Path,
        file: VaultFile,
        dek_bytes: &[u8],
        method: UnlockMethod,
    ) -> Result<Self> {
        if dek_bytes.len() != 32 {
            bail!("unlock failed");
        }
        let mut dek = Zeroizing::new([0u8; 32]);
        dek.copy_from_slice(dek_bytes);
        let lock = memlock::Lock::new(dek.as_ref());

        // Header authentication. A mismatch means the header was edited after
        // it was written, so we refuse rather than decrypt under it.
        let expected = crypto::header_mac(dek.as_ref(), &file.header.mac_input(&file.payload));
        if !crypto::mac_matches(&expected, &file.header.mac) {
            bail!("vault header failed authentication (tampering or corruption)");
        }

        let payload = open_payload(dek.as_ref(), &file.payload)?;

        let rollback_suspected = Witness::check(path, file.header.vault_id, file.header.epoch)?;

        Ok(Self {
            seen: FileStamp::of(path),
            path: path.to_path_buf(),
            file,
            payload,
            dek,
            _dek_lock: lock,
            unlocked_by: method,
            rollback_suspected,
        })
    }

    /// Persist, bumping the epoch and re-MACing the header.
    ///
    /// Refuses to write over a version this handle has not seen. Without that
    /// check, a CLI write and a long-lived agent would race with the later
    /// saver silently discarding the other's records — and because both end at
    /// the same epoch, the rollback witness would not notice either.
    pub fn save(&mut self) -> Result<()> {
        if self.changed_on_disk() {
            bail!(
                "the vault changed on disk since this handle read it; \
                 refresh before saving so the other writer's records are not lost"
            );
        }
        self.file.header.epoch = self.file.header.epoch.saturating_add(1);
        self.file.header.updated_at = Utc::now();
        self.file.payload = seal_payload(self.dek.as_ref(), &self.payload)?;
        self.file.header.mac =
            crypto::header_mac(self.dek.as_ref(), &self.file.header.mac_input(&self.file.payload));
        write_vault_file(&self.path, &self.file)?;
        self.seen = FileStamp::of(&self.path);
        Witness::record(&self.path, self.file.header.vault_id, self.file.header.epoch)?;
        Ok(())
    }

    /// Whether the file differs from the version this handle last read or wrote.
    pub fn changed_on_disk(&self) -> bool {
        FileStamp::of(&self.path) != self.seen
    }

    /// Re-read the vault using the data key already held.
    ///
    /// Returns `false` when nothing changed. Errors when the file can no longer
    /// be opened with our key — which means it was re-keyed elsewhere, and the
    /// only honest response is to drop the session and ask for a fresh unlock.
    ///
    /// Safe to call at any point because every mutation is saved immediately,
    /// so a handle never holds unsaved work to lose.
    pub fn refresh(&mut self) -> Result<bool> {
        if !self.changed_on_disk() {
            return Ok(false);
        }

        let file = read_vault_file(&self.path)?;
        let expected = crypto::header_mac(self.dek.as_ref(), &file.header.mac_input(&file.payload));
        if !crypto::mac_matches(&expected, &file.header.mac) {
            bail!("the vault was re-keyed by another process; unlock again");
        }

        let payload = open_payload(self.dek.as_ref(), &file.payload)?;
        self.rollback_suspected =
            Witness::check(&self.path, file.header.vault_id, file.header.epoch)?;
        self.file = file;
        self.payload = payload;
        self.seen = FileStamp::of(&self.path);
        Ok(true)
    }

    /// Mint a fresh DEK and re-encrypt everything under it, re-wrapping for
    /// every recipient. Optionally change the passphrase and Argon2 cost at the
    /// same time. This is what 0.4.x's `rotate` claimed to be and was not.
    pub fn rekey(&mut self, new_passphrase: Option<&[u8]>, mem_kib: Option<u32>) -> Result<()> {
        let mut fresh = [0u8; 32];
        OsRng.fill_bytes(&mut fresh);
        let new_dek = Zeroizing::new(fresh);
        let new_lock = memlock::Lock::new(new_dek.as_ref());

        let mut rewrapped = Vec::with_capacity(self.file.header.recipients.len());
        for recipient in &self.file.header.recipients {
            rewrapped.push(match recipient {
                Recipient::Passphrase { argon, .. } => {
                    let mut argon = *argon;
                    if let Some(mem) = mem_kib {
                        if mem < crypto::MIN_MEM_KIB {
                            bail!("memory cost must be at least {} KiB", crypto::MIN_MEM_KIB);
                        }
                        argon.mem_cost_kib = mem;
                    }
                    // A new salt every rekey, so the same passphrase never
                    // reproduces the previous KEK.
                    argon.reseed();
                    let passphrase = new_passphrase.ok_or_else(|| {
                        anyhow!("a passphrase is required to re-wrap the passphrase recipient")
                    })?;
                    let kek = crypto::derive_kek(passphrase, &argon)?;
                    Recipient::Passphrase {
                        argon,
                        sealed_dek: crypto::seal(
                            kek.as_ref(),
                            new_dek.as_ref(),
                            AAD_RECIPIENT_PASSPHRASE,
                        )?,
                    }
                }
                Recipient::Hybrid {
                    label,
                    x25519_public,
                    mlkem_encapsulation_key,
                    ..
                } => wrap_hybrid(
                    label.clone(),
                    x25519_public,
                    mlkem_encapsulation_key,
                    new_dek.as_ref(),
                )?,
            });
        }

        self.file.header.recipients = rewrapped;
        self.dek = new_dek;
        self._dek_lock = new_lock;
        self.save()
    }

    /// Add a hybrid recovery recipient and return the key material to store
    /// offline. The vault keeps only public halves.
    pub fn add_recovery_recipient(&mut self, label: &str) -> Result<RecoveryKey> {
        if label.trim().is_empty() {
            bail!("recovery label cannot be empty");
        }
        if self
            .file
            .header
            .recipients
            .iter()
            .any(|r| r.label() == label)
        {
            bail!("a recipient named {label} already exists");
        }

        let x_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let x_public = x25519_dalek::PublicKey::from(&x_secret);
        let (mlkem_dk, mlkem_ek) = MlKem1024::generate_keypair();

        let recipient = wrap_hybrid(
            label.to_string(),
            x_public.as_bytes(),
            &mlkem_ek.to_bytes(),
            self.dek.as_ref(),
        )?;
        self.file.header.recipients.push(recipient);
        self.save()?;

        Ok(RecoveryKey {
            label: label.to_string(),
            vault_id: self.file.header.vault_id,
            x25519_secret: x_secret.to_bytes().to_vec(),
            mlkem_decapsulation_key: mlkem_dk.to_bytes().to_vec(),
        })
    }

    /// Remove a recipient by label. The passphrase recipient cannot be removed —
    /// doing so would leave a vault only a key file can open, which is a
    /// lockout waiting to happen.
    pub fn remove_recipient(&mut self, label: &str) -> Result<()> {
        if label == "passphrase" {
            bail!("the passphrase recipient cannot be removed");
        }
        let before = self.file.header.recipients.len();
        self.file.header.recipients.retain(|r| r.label() != label);
        if self.file.header.recipients.len() == before {
            bail!("no recipient named {label}");
        }
        self.save()
    }

    pub fn records(&self) -> &[Record] {
        &self.payload.records
    }

    pub fn add_record(&mut self, record: Record) -> Result<()> {
        record.validate()?;
        if self.payload.records.len() >= MAX_RECORDS {
            bail!("vault is full (max {MAX_RECORDS} records)");
        }
        self.payload.records.push(record);
        Ok(())
    }

    pub fn get(&self, id: Uuid) -> Option<&Record> {
        self.payload.records.iter().find(|r| r.id == id)
    }

    pub fn get_mut(&mut self, id: Uuid) -> Option<&mut Record> {
        self.payload.records.iter_mut().find(|r| r.id == id)
    }

    pub fn remove_record(&mut self, id: Uuid) -> Result<Record> {
        let idx = self
            .payload
            .records
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| anyhow!("record {id} not found"))?;
        Ok(self.payload.records.remove(idx))
    }

    /// Counts per kind, for the cockpit rail.
    pub fn counts_by_kind(&self) -> Vec<(Kind, usize)> {
        Kind::ALL
            .iter()
            .map(|kind| {
                (
                    *kind,
                    self.payload.records.iter().filter(|r| r.kind == *kind).count(),
                )
            })
            .collect()
    }
}

/// Wrap `dek` to a hybrid X25519 + ML-KEM-1024 recipient.
///
/// The two shared secrets are combined with a domain-separated BLAKE3 KDF, so
/// the result is secure if *either* primitive holds — the standard hybrid
/// argument, and the reason this lane is worth having.
fn wrap_hybrid(
    label: String,
    x25519_public: &[u8],
    mlkem_encapsulation_key: &[u8],
    dek: &[u8],
) -> Result<Recipient> {
    let peer: [u8; 32] = x25519_public
        .try_into()
        .map_err(|_| anyhow!("invalid X25519 public key length"))?;
    let peer = x25519_dalek::PublicKey::from(peer);
    let ephemeral = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral);
    let x_shared = ephemeral.diffie_hellman(&peer);

    let ek = ml_kem::EncapsulationKey::<MlKem1024>::new_from_slice(mlkem_encapsulation_key)
        .map_err(|_| anyhow!("invalid ML-KEM encapsulation key"))?;
    let (mlkem_ct, mlkem_shared) = ek.encapsulate();

    let combined = combine_shared(
        x_shared.as_bytes(),
        mlkem_shared.as_slice(),
        ephemeral_public.as_bytes(),
        &mlkem_ct,
    );

    Ok(Recipient::Hybrid {
        label,
        x25519_public: x25519_public.to_vec(),
        mlkem_encapsulation_key: mlkem_encapsulation_key.to_vec(),
        x25519_ephemeral: ephemeral_public.as_bytes().to_vec(),
        mlkem_ciphertext: mlkem_ct.to_vec(),
        sealed_dek: crypto::seal(combined.as_ref(), dek, AAD_RECIPIENT_PQ)?,
    })
}

fn hybrid_decapsulate(
    key: &RecoveryKey,
    x25519_ephemeral: &[u8],
    mlkem_ciphertext: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let secret: [u8; 32] = key
        .x25519_secret
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid X25519 secret length in recovery key"))?;
    let secret = x25519_dalek::StaticSecret::from(secret);
    let ephemeral: [u8; 32] = x25519_ephemeral
        .try_into()
        .map_err(|_| anyhow!("invalid X25519 ephemeral length"))?;
    let x_shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral));

    // `key.mlkem_decapsulation_key` is the 64-byte seed (see `RecoveryKey`), so
    // `KeyInit` reconstructs the full decapsulation key deterministically.
    let dk = ml_kem::DecapsulationKey::<MlKem1024>::new_from_slice(&key.mlkem_decapsulation_key)
        .map_err(|_| anyhow!("invalid ML-KEM decapsulation seed in recovery key"))?;
    let mlkem_shared = dk
        .decapsulate_slice(mlkem_ciphertext)
        .map_err(|_| anyhow!("invalid ML-KEM ciphertext length"))?;

    Ok(combine_shared(
        x_shared.as_bytes(),
        mlkem_shared.as_slice(),
        x25519_ephemeral,
        mlkem_ciphertext,
    ))
}

/// KDF over both shared secrets plus both ciphertexts, so the derived key is
/// bound to the exact encapsulation it came from.
fn combine_shared(
    x_shared: &[u8],
    mlkem_shared: &[u8],
    x_ephemeral: &[u8],
    mlkem_ct: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key("black-bag::v2::hybrid-recipient");
    for part in [x_shared, mlkem_shared, x_ephemeral, mlkem_ct] {
        hasher.update(&(part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    hasher.finalize_xof().fill(out.as_mut());
    out
}

fn seal_payload(dek: &[u8], payload: &Payload) -> Result<Sealed> {
    let mut buf = Zeroizing::new(Vec::new());
    ciborium::ser::into_writer(payload, &mut *buf).context("failed to serialise payload")?;
    let padded = crypto::pad(&buf, crypto::pad_block())?;
    crypto::seal(dek, &padded, AAD_PAYLOAD)
}

fn open_payload(dek: &[u8], sealed: &Sealed) -> Result<Payload> {
    let padded = crypto::open(dek, sealed, AAD_PAYLOAD)?;
    let plain = crypto::unpad(&padded)?;
    let mut payload: Payload =
        ciborium::de::from_reader(plain.as_slice()).context("failed to parse payload")?;
    if payload.records.len() > MAX_RECORDS {
        bail!("payload declares too many records");
    }
    for record in &payload.records {
        record.validate()?;
    }
    // `Secret`'s lock guard is #[serde(skip)], so everything deserialised from
    // the vault arrives unlocked. Without this pass "secrets are page-locked"
    // would be true of the data key and false of every record it protects.
    for record in payload.records.iter_mut() {
        record.relock();
    }
    Ok(payload)
}

fn read_vault_file(path: &Path) -> Result<VaultFile> {
    let meta = fs::metadata(path)
        .with_context(|| format!("vault not found at {}", path.display()))?;
    if meta.len() > MAX_VAULT_FILE_BYTES {
        bail!(
            "vault file is larger than the {} MiB cap",
            MAX_VAULT_FILE_BYTES / (1024 * 1024)
        );
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(meta.len() as usize));
    File::open(path)?.read_to_end(&mut buf)?;
    let file: VaultFile =
        ciborium::de::from_reader(buf.as_slice()).context("failed to parse vault")?;
    if file.version != VAULT_VERSION {
        bail!(
            "unsupported vault version {} (this build reads v{VAULT_VERSION}; run `black-bag migrate`)",
            file.version
        );
    }
    if file.header.recipients.is_empty() {
        bail!("vault has no recipients");
    }
    Ok(file)
}

/// Write atomically with 0600 permissions, fsyncing before the rename so a
/// crash mid-write cannot leave a truncated vault.
fn write_vault_file(path: &Path, file: &VaultFile) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("invalid vault path {}", path.display()))?;
    fs::create_dir_all(parent)?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.as_file_mut()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    ciborium::ser::into_writer(file, &mut tmp).context("failed to serialise vault")?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(path)
        .map_err(|e| anyhow!("failed to replace vault: {e}"))?;

    // Durability of the rename itself.
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Out-of-band record of the highest epoch seen for a vault.
///
/// Honest scope: this is a **tripwire, not a guarantee**. It lives in the user's
/// own state directory, so an attacker who can rewrite the vault can usually
/// rewrite this too. What it reliably catches is the realistic case — a stale
/// file restored from a backup, a sync conflict, a snapshot rollback — which
/// 0.4.x could not detect at all.
pub struct Witness;

#[derive(Serialize, Deserialize, Default)]
struct WitnessFile {
    #[serde(default)]
    entries: Vec<WitnessEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct WitnessEntry {
    vault_id: Uuid,
    epoch: u64,
    updated_at: DateTime<Utc>,
}

/// Process-wide override of where the witness lives. Set once by tests so a
/// test vault never writes into the operator's real state directory — which is
/// exactly what every test in this crate used to do.
static WITNESS_DIR_OVERRIDE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

impl Witness {
    fn path() -> Result<PathBuf> {
        let dir = match WITNESS_DIR_OVERRIDE.get() {
            Some(dir) => dir.clone(),
            None => crate::state_dir()?,
        };
        fs::create_dir_all(&dir)?;
        Ok(dir.join("witness.json"))
    }

    /// Point the witness at a private temporary directory for the life of
    /// this process. Idempotent; the first call wins.
    #[doc(hidden)]
    pub fn isolate_for_tests() {
        WITNESS_DIR_OVERRIDE.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!(
                "black-bag-test-witness-{}",
                std::process::id()
            ));
            let _ = fs::create_dir_all(&dir);
            dir
        });
    }

    fn load() -> WitnessFile {
        Self::path()
            .ok()
            .and_then(|p| fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Record `epoch` as the newest seen. Never lowers a stored value.
    pub fn record(_vault_path: &Path, vault_id: Uuid, epoch: u64) -> Result<()> {
        let mut file = Self::load();
        match file.entries.iter_mut().find(|e| e.vault_id == vault_id) {
            Some(entry) => {
                if epoch > entry.epoch {
                    entry.epoch = epoch;
                    entry.updated_at = Utc::now();
                }
            }
            None => file.entries.push(WitnessEntry {
                vault_id,
                epoch,
                updated_at: Utc::now(),
            }),
        }
        let path = Self::path()?;
        let mut tmp = tempfile::NamedTempFile::new_in(
            path.parent().unwrap_or_else(|| Path::new(".")),
        )?;
        tmp.write_all(serde_json::to_string_pretty(&file)?.as_bytes())?;
        tmp.as_file_mut().sync_all()?;
        tmp.persist(&path)
            .map_err(|e| anyhow!("failed to write witness: {e}"))?;
        Ok(())
    }

    /// True when the vault's epoch is *behind* what we last saw.
    pub fn check(_vault_path: &Path, vault_id: Uuid, epoch: u64) -> Result<bool> {
        Ok(Self::load()
            .entries
            .iter()
            .find(|e| e.vault_id == vault_id)
            .is_some_and(|e| epoch < e.epoch))
    }

    pub fn seen_epoch(vault_id: Uuid) -> Option<u64> {
        Self::load()
            .entries
            .iter()
            .find(|e| e.vault_id == vault_id)
            .map(|e| e.epoch)
    }
}

/// Exclusive advisory lock so two processes do not interleave writes.
///
/// This previously opened the file and returned it without taking any lock at
/// all, while the doc comment claimed otherwise. The returned `File` owns the
/// lock: `flock` is released when the descriptor closes, so hold the handle for
/// as long as the critical section lasts.
pub fn lock_path(vault: &Path) -> PathBuf {
    let mut name = vault.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

pub fn open_lock(vault: &Path) -> Result<File> {
    let path = lock_path(vault);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("failed to open lock {}", path.display()))?;

    use std::os::unix::io::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("another process holds {}", path.display()));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Kind, Record, Secret};
    use tempfile::TempDir;

    fn temp_vault() -> (TempDir, PathBuf) {
        Witness::isolate_for_tests();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.cbor");
        (dir, path)
    }

    const PASS: &[u8] = b"correct horse battery staple";
    const MEM: u32 = 32_768;

    #[test]
    fn init_unlock_roundtrip() {
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();

        let mut vault = Vault::unlock(&path, PASS).unwrap();
        assert_eq!(vault.unlocked_by, UnlockMethod::Passphrase);
        let mut record = Record::new(Kind::Login, Some("GitHub".into()));
        record.set_attribute("username", "octocat");
        record.set_field("password", Secret::from_str("s3cret"));
        let id = record.id;
        vault.add_record(record).unwrap();
        vault.save().unwrap();
        drop(vault);

        let vault = Vault::unlock(&path, PASS).unwrap();
        let got = vault.get(id).expect("record survived the roundtrip");
        assert_eq!(got.attribute("username"), Some("octocat"));
        assert_eq!(got.field("password").unwrap().expose_str().unwrap(), "s3cret");
    }

    #[test]
    fn wrong_passphrase_is_refused() {
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();
        assert!(Vault::unlock(&path, b"wrong").is_err());
    }

    #[test]
    fn recovery_key_unlocks_without_the_passphrase() {
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();

        let mut vault = Vault::unlock(&path, PASS).unwrap();
        let mut record = Record::new(Kind::Note, Some("ops".into()));
        record.set_field("body", Secret::from_str("launch codes"));
        let id = record.id;
        vault.add_record(record).unwrap();
        vault.save().unwrap();
        let key = vault.add_recovery_recipient("yubi-offline").unwrap();
        drop(vault);

        // This is the property 0.4.x could not offer: the private half lives
        // outside the file, so ML-KEM is doing real work.
        let recovered = Vault::unlock_with_recovery(&path, &key).unwrap();
        assert_eq!(recovered.unlocked_by, UnlockMethod::RecoveryKey);
        assert_eq!(
            recovered.get(id).unwrap().field("body").unwrap().expose_str().unwrap(),
            "launch codes"
        );
    }

    #[test]
    fn recovery_key_from_another_vault_is_refused() {
        let (_d1, path1) = temp_vault();
        let (_d2, path2) = temp_vault();
        Vault::init(&path1, PASS, MEM).unwrap();
        Vault::init(&path2, PASS, MEM).unwrap();

        let mut v1 = Vault::unlock(&path1, PASS).unwrap();
        let key = v1.add_recovery_recipient("offsite").unwrap();
        drop(v1);

        assert!(Vault::unlock_with_recovery(&path2, &key).is_err());
    }

    #[test]
    fn rekey_changes_the_dek_and_the_passphrase() {
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();

        let mut vault = Vault::unlock(&path, PASS).unwrap();
        let mut record = Record::new(Kind::Api, Some("prod".into()));
        record.set_field("secret_key", Secret::from_str("keep-me"));
        vault.add_record(record).unwrap();
        vault.save().unwrap();
        let old_payload = vault.file.payload.ciphertext.clone();

        vault.rekey(Some(b"a brand new passphrase"), None).unwrap();
        assert_ne!(
            old_payload, vault.file.payload.ciphertext,
            "rekey must re-encrypt the payload under a fresh DEK"
        );
        drop(vault);

        assert!(Vault::unlock(&path, PASS).is_err(), "old passphrase must stop working");
        let vault = Vault::unlock(&path, b"a brand new passphrase").unwrap();
        assert_eq!(vault.records().len(), 1);
        assert_eq!(
            vault.records()[0].field("secret_key").unwrap().expose_str().unwrap(),
            "keep-me"
        );
    }

    #[test]
    fn rekey_keeps_recovery_recipients_working() {
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();
        let mut vault = Vault::unlock(&path, PASS).unwrap();
        let key = vault.add_recovery_recipient("offsite").unwrap();
        vault.rekey(Some(PASS), None).unwrap();
        drop(vault);

        // Re-wrapped under the new DEK, so the same recovery key still opens it.
        assert!(Vault::unlock_with_recovery(&path, &key).is_ok());
    }

    #[test]
    fn header_tampering_is_detected() {
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();

        let mut file = read_vault_file(&path).unwrap();
        file.header.epoch = 9_999; // rewind/advance the counter
        write_vault_file(&path, &file).unwrap();

        let err = Vault::unlock(&path, PASS).unwrap_err().to_string();
        assert!(
            err.contains("authentication"),
            "expected a MAC failure, got: {err}"
        );
    }

    #[test]
    fn splicing_an_old_payload_onto_a_current_header_is_detected() {
        // The attack this closes: the payload AEAD binds no epoch, so before
        // the MAC covered the ciphertext an attacker could keep the current
        // header (current epoch, no rollback suspicion) and swap in an older
        // payload sealed under the same DEK. It unlocked and returned stale
        // records. Found by testing, not by reading.
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();

        let mut vault = Vault::unlock(&path, PASS).unwrap();
        let mut first = Record::new(Kind::Note, Some("original".into()));
        first.set_field("body", Secret::from_str("before"));
        vault.add_record(first).unwrap();
        vault.save().unwrap();
        let stale_payload = vault.file.payload.clone();

        let mut second = Record::new(Kind::Note, Some("added later".into()));
        second.set_field("body", Secret::from_str("after"));
        vault.add_record(second).unwrap();
        vault.save().unwrap();
        drop(vault);

        let mut file = read_vault_file(&path).unwrap();
        assert_ne!(file.payload.ciphertext, stale_payload.ciphertext);
        file.payload = stale_payload;
        write_vault_file(&path, &file).unwrap();

        let err = Vault::unlock(&path, PASS).unwrap_err().to_string();
        assert!(
            err.contains("authentication"),
            "a spliced payload must fail the header MAC, got: {err}"
        );
    }

    #[test]
    fn editing_updated_at_invalidates_the_tag() {
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();

        let mut file = read_vault_file(&path).unwrap();
        file.header.updated_at = file.header.updated_at + chrono::Duration::days(365);
        write_vault_file(&path, &file).unwrap();

        assert!(Vault::unlock(&path, PASS).is_err());
    }

    #[test]
    fn secrets_loaded_from_disk_are_page_locked() {
        // `Secret`'s guard is #[serde(skip)], so without an explicit re-lock
        // pass every record read back from the vault would sit unlocked while
        // the documentation claimed otherwise.
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();

        let mut vault = Vault::unlock(&path, PASS).unwrap();
        let mut record = Record::new(Kind::Note, Some("n".into()));
        record.set_field("body", Secret::new(&vec![7u8; 4096]));
        vault.add_record(record).unwrap();
        vault.save().unwrap();
        drop(vault);

        let vault = Vault::unlock(&path, PASS).unwrap();
        let secret = vault.records()[0].field("body").expect("field survived");
        assert!(
            secret.is_locked(),
            "a secret read from disk must hold a page lock"
        );
        drop(vault);
    }

    #[test]
    fn a_handle_will_not_overwrite_a_write_it_never_saw() {
        // The data-loss case this closes: a long-lived agent holds the vault
        // while the CLI writes to the file. Before this check the agent's next
        // save discarded the CLI's records, and because both ended at the same
        // epoch the rollback witness saw nothing wrong.
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();

        let mut held = Vault::unlock(&path, PASS).unwrap();

        let mut other = Vault::unlock(&path, PASS).unwrap();
        let mut theirs = Record::new(Kind::Note, Some("written elsewhere".into()));
        theirs.set_field("body", Secret::from_str("keep me"));
        other.add_record(theirs).unwrap();
        other.save().unwrap();
        drop(other);

        assert!(held.changed_on_disk());
        let mut mine = Record::new(Kind::Note, Some("mine".into()));
        mine.set_field("body", Secret::from_str("also keep me"));
        held.add_record(mine).unwrap();
        assert!(
            held.save().is_err(),
            "saving over an unseen write must be refused, not silently win"
        );
    }

    #[test]
    fn refresh_picks_up_another_writers_records() {
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();

        let mut held = Vault::unlock(&path, PASS).unwrap();
        assert_eq!(held.records().len(), 0);
        assert!(!held.refresh().unwrap(), "an untouched file reports no change");

        let mut other = Vault::unlock(&path, PASS).unwrap();
        let mut theirs = Record::new(Kind::Note, Some("written elsewhere".into()));
        theirs.set_field("body", Secret::from_str("keep me"));
        other.add_record(theirs).unwrap();
        other.save().unwrap();
        drop(other);

        assert!(held.refresh().unwrap(), "a changed file reports a reload");
        assert_eq!(held.records().len(), 1);
        assert_eq!(held.records()[0].title.as_deref(), Some("written elsewhere"));
        assert!(
            held.records()[0].field("body").unwrap().is_locked(),
            "records pulled in by a refresh must be page-locked too"
        );

        // And the handle can now save again, on top of what it just read.
        let mut mine = Record::new(Kind::Note, Some("mine".into()));
        mine.set_field("body", Secret::from_str("also keep me"));
        held.add_record(mine).unwrap();
        held.save().unwrap();
        drop(held);

        let reopened = Vault::unlock(&path, PASS).unwrap();
        assert_eq!(reopened.records().len(), 2, "both writers' records survive");
    }

    #[test]
    fn refresh_refuses_after_someone_else_rekeys() {
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();
        let mut held = Vault::unlock(&path, PASS).unwrap();

        let mut other = Vault::unlock(&path, PASS).unwrap();
        other.rekey(Some(b"a different passphrase"), None).unwrap();
        drop(other);

        // Our data key no longer opens the file; holding it would be a lie.
        assert!(held.refresh().is_err());
    }

    #[test]
    fn epoch_advances_on_every_save() {
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();
        let mut vault = Vault::unlock(&path, PASS).unwrap();
        assert_eq!(vault.file.header.epoch, 1);
        vault.save().unwrap();
        assert_eq!(vault.file.header.epoch, 2);
        vault.save().unwrap();
        assert_eq!(vault.file.header.epoch, 3);
    }

    #[test]
    fn payload_is_padded_so_size_does_not_track_content() {
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();
        let mut vault = Vault::unlock(&path, PASS).unwrap();
        let baseline = vault.file.payload.ciphertext.len();

        let mut record = Record::new(Kind::Note, Some("n".into()));
        record.set_field("body", Secret::from_str("a short note"));
        vault.add_record(record).unwrap();
        vault.save().unwrap();

        assert_eq!(
            baseline,
            vault.file.payload.ciphertext.len(),
            "a small addition must not change the padded size"
        );
    }

    #[test]
    fn passphrase_recipient_cannot_be_removed() {
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();
        let mut vault = Vault::unlock(&path, PASS).unwrap();
        assert!(vault.remove_recipient("passphrase").is_err());
    }

    #[test]
    fn removing_a_recovery_recipient_revokes_it() {
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();
        let mut vault = Vault::unlock(&path, PASS).unwrap();
        let key = vault.add_recovery_recipient("temp").unwrap();
        vault.remove_recipient("temp").unwrap();
        drop(vault);
        assert!(Vault::unlock_with_recovery(&path, &key).is_err());
    }

    #[test]
    fn vault_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, path) = temp_vault();
        Vault::init(&path, PASS, MEM).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "vault must not be group/world readable");
    }
}
