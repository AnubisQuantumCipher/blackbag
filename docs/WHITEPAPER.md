# Black-Bag — technical whitepaper

Vault format v2 · engine version 2.5.0 · Linux (Omarchy, aarch64)

This document describes what Black-Bag does, how it does it, and — at greater
length than is usual — what it does not do. It is written for two readers: a
security engineer deciding whether to keep a credential here, and a reviewer
looking for something to disagree with. Both are given file and function names
so that every claim can be checked against the source rather than taken on
trust.

Where a statement rests on an assumption, the assumption is named. Where a
mechanism is a tripwire rather than a guarantee, it is called a tripwire. The
non-claims in [§13](#13-non-claims) are the part of this document that matters
most; if you read nothing else, read those.

---

## 1. Abstract and scope

Black-Bag stores credentials in a single authenticated file. The file is
encrypted with XChaCha20-Poly1305 under a 256-bit data-encryption key (DEK).
The DEK is wrapped once per *recipient*: always for the master passphrase, via
Argon2id; and optionally for one or more recovery holders, via a hybrid of
X25519 and ML-KEM-1024 whose private half is written to a separate file and
never stored in the vault. A keyed MAC covers the parts of the header that no
AEAD reaches, including a monotonic epoch counter that is compared against an
out-of-band witness.

Around that engine sit three surfaces: a command-line tool (`black-bag`), a
long-lived unlock agent behind a unix socket, and a Quickshell plugin
(`khephri.blackbag`) providing an Omarchy bar widget and a full-screen cockpit.
A plaintext status document, `status.json`, is published for the bar widget and
is constrained by construction and by test to carry no record data at all.

### 1.1 What this project is

A Linux-only rebuild of the engine behind the published `black-bagg` crate. A
close reading of all twenty-six published releases of that crate produced nine
findings, recorded in [`docs/AUDIT.md`](AUDIT.md). Three of them are
load-bearing:

* its ML-KEM lane encapsulated to its own public key and stored the
  decapsulation key in the same file under the same passphrase, so the KEM
  contributed nothing to at-rest security;
* its `rotate` re-wrapped the same data key and could not change the
  passphrase;
* its 0.4.x line was a security regression from its own 0.2.x line, dropping a
  header MAC, an anti-rollback epoch, core-dump suppression, parser size caps,
  payload padding, `/dev/tty` secret output, and roughly two thirds of its
  Argon2 cost.

This repository is the corrected rebuild. [§14](#14-comparison-with-black-bagg-0410)
sets the two side by side.

### 1.2 What this project is not

It is not formally verified. It is ordinary Rust with a test suite — 171 tests
across the workspace at the time of writing (156 in `blackbag-core`, 15 in
`blackbag-cli`, as `cargo test --workspace` reported on this machine), plus 183
assertions over the cockpit's `Model.js`. It has not
been audited by a third party, and no document in this repository claims
otherwise.

It is also not a replacement for a hardware token, a smartcard, or a system
keyring backed by a TPM. Every key it handles is software-held, in the address
space of an ordinary user process.

### 1.3 Source map

| Concern | File |
|---|---|
| Primitives, KDF, AEAD, header MAC, padding | `crates/blackbag-core/src/crypto.rs` |
| Vault format, recipients, unlock, rekey, witness | `crates/blackbag-core/src/vault.rs` |
| Record and `Secret` types, caps, handles | `crates/blackbag-core/src/record.rs` |
| Secrets at rest in memory: session key, `Guarded`, locked arena | `crates/blackbag-core/src/secmem.rs` |
| `RLIMIT_MEMLOCK` probe behind `doctor` | `crates/blackbag-core/src/memlock.rs` |
| Process hardening, host probes | `crates/blackbag-core/src/harden.rs` |
| Agent, socket protocol, TOTP, lock reasons, session ceiling | `crates/blackbag-core/src/session.rs` |
| Suspend and session-lock watcher (hand-written D-Bus client) | `crates/blackbag-core/src/sleepwatch.rs` |
| Breach check, k-anonymity protocol | `crates/blackbag-core/src/breach.rs`, `cmd_breach` in `crates/blackbag-cli/src/main.rs` |
| `status.json` construction and findings | `crates/blackbag-core/src/status.rs` |
| Generation and entropy accounting | `crates/blackbag-core/src/generate.rs` |
| Credential hygiene | `crates/blackbag-core/src/hygiene.rs` |
| CLI, subcommands, secret sinks | `crates/blackbag-cli/src/{main,tty}.rs` |
| Clipboard helper (`clip-serve`) | `crates/blackbag-cli/src/clipboard.rs` |
| Import and export formats | `crates/blackbag-cli/src/import.rs` |
| v1 (`black-bagg` 0.4.x) migration reader | `crates/blackbag-cli/src/migrate.rs` |
| Bar widget, cockpit, editor, service, screen-lock hook | `plugin/khephri.blackbag/*.qml`, `Model.js` |
| Agent unit and its sandbox | `plugin/khephri.blackbag/install.sh` |

---

## 2. Threat model

### 2.1 What is defended

**A. The vault file at rest, in the hands of someone who does not have the
passphrase or a recovery key.** This is the primary case: a stolen laptop, a
backup copied to a NAS, a synced file on someone else's cloud, a disk image in
an evidence bag. The attacker holds the complete file and unlimited time. The
defence is Argon2id with a per-vault random 32-byte salt at time=10 and at
least four lanes, feeding a 256-bit XChaCha20-Poly1305 key. Every guess costs
one full Argon2id evaluation; there is no cheaper oracle in the file, because
the only thing a candidate KEK can be tested against is a Poly1305 tag that
requires the derivation to have already happened.

**B. Silent modification of the file.** An attacker who can write to the vault
but not read its plaintext could otherwise downgrade the Argon2 parameters,
delete a recipient, splice in a recipient of their own, or rewind the epoch.
All of these are covered by an HMAC-SHA256 tag keyed by the DEK
(`crypto::header_mac`, `vault::Header::mac_input`). A modified header is
refused at unlock rather than decrypted under. The exact coverage, and its
limits, are in [§6](#6-authenticated-header-and-anti-rollback).

**C. Wholesale rollback to an earlier version of the vault.** Every write bumps
`header.epoch`, and the highest epoch seen for a given `vault_id` is recorded
in `~/.local/state/black-bag/witness.json`. Opening a file whose epoch is
behind the witness raises `rollback_suspected`, an `alert`-severity finding,
and a red state in the cockpit. This is a tripwire, not a guarantee — see
[§6.3](#63-the-witness-is-a-tripwire).

**D. Secrets reaching disk, logs, argv, or other processes by accident.** The
concrete mechanisms are: every secret at rest in memory held as ciphertext
under a per-process session key that lives in `memfd_secret` memory, with
plaintext confined to a locked arena while a field is in use
([§7.2](#72-encrypted-at-rest-in-memory)); `RLIMIT_CORE` set to zero and `PR_SET_DUMPABLE` cleared
before anything touches memory; `panic = "unwind"` so destructors actually run;
no `--passphrase` flag anywhere in the CLI, because `/proc/<pid>/cmdline` is
world-readable; secrets written to `/dev/tty` by default rather than to a
redirectable stdout; a status file whose contents are constrained by test; a
`Debug` impl on `Secret` and on `Vault` that redacts rather than prints. The
full surface-by-surface accounting is in [§10](#10-the-secret-flow-boundary).

**E. Another local user reaching the unlock agent.** The socket is `0600` in a
`0700` directory, and every connection is checked with `SO_PEERCRED` before a
single byte of request is read. Both conditions are verified at runtime, not
assumed.

**F. Metadata leakage through file size.** The payload is padded to a multiple
of 4096 bytes (`crypto::pad`, `BLACK_BAG_PAD_BLOCK` to override) before
encryption, so the file size stops tracking how much is stored, at block
granularity.

**G. A hostile or corrupt file driving resource exhaustion in the parser.**
Size caps are applied before parsing (64 MiB file cap, checked against
`stat` before the read) and after (32 MiB plaintext cap, 100,000-record cap,
and per-record `validate()` on every decoded record).

### 2.2 What is explicitly out of scope

**A compromised host.** If an attacker has arbitrary code execution as your
user, Black-Bag loses, and there is no configuration of it that changes that.
They can read the agent's memory, connect to the agent's socket as you (the
`SO_PEERCRED` check passes — they *are* you), replace the binary, or simply
wait for you to type the passphrase. Nothing in this document should be read as
a claim to the contrary.

**Live malware in the session.** A keylogger, a malicious Wayland client with
input capture, a compromised shell plugin, a rogue `LD_PRELOAD`. The cockpit's
passphrase field is an ordinary Qt text field in the Omarchy shell process; it
has no protected input path. A tracer attached at startup is detected and, in
the cockpit, blocks unlock outright with no override — because by the time you
have typed the passphrase into a traced process the harm is finished and an
override would only launder a refusal into a speed bump. A tracer that attaches
*after* startup is not detected.

**Side channels observable by a co-resident privileged process.** Cache timing,
page-fault patterns, DRAM row conflicts, performance counters, hypervisor
introspection. This box is itself a VMware Fusion guest; the host can read guest
memory. No countermeasure here addresses that, and the constant-time work that
does exist (`Secret`'s `PartialEq` via `subtle`, `crypto::mac_matches`) is aimed
at ordinary remote-ish timing distinguishers, not at a co-resident adversary.

**Coercion.** There is no duress passphrase, no plausible-deniability volume, no
decoy vault. `black-bagg` 0.2.x had a duress mode; it is not reproduced here,
because a duress feature that a determined adversary knows about is worse than
none, and one they do not know about is a claim this project cannot support.

**The witness file, against an attacker who can already rewrite the vault.**
Both files live in your own directories under your own uid. Anyone who can
truncate one can truncate the other. See [§6.3](#63-the-witness-is-a-tripwire).

**Anything about the account behind a credential.** The vault does not know
whether an account has 2FA enabled elsewhere or whether a key has been revoked.
Whether a password appears in a public breach corpus *can* be asked, but only
on request and only through a protocol that discloses twenty bits of a hash:
`black-bag agent breach --online` is the one network act in the project, and
[§8.9](#89-the-breach-check-what-leaves-the-machine) says exactly what it
sends. The hygiene analysis itself stays local, and the agent that holds the
key has no network family at all.

**The clipboard.** Once a secret is on the Wayland clipboard, every client that
can read the selection can read it, and every client that has read it holds a
copy of its own. The helper that serves it clears it after a configurable
interval (30 s by default), and only if the selection is still ours; in the
interval it is exposed, and what a pasting application or a clipboard manager
keeps afterwards is outside this project's reach. [§9](#9-the-clipboard) states
this in full.

---

## 3. Vault format v2, field by field

The file is CBOR (`ciborium`), written atomically: a `NamedTempFile` in the
same directory, `chmod 0600`, `fsync`, `rename`, then an `fsync` of the parent
directory. A crash mid-write cannot leave a truncated vault
(`vault::write_vault_file`).

### 3.1 Top level

```
VaultFile {
    version : u32          // must equal 2, checked before anything else
    header  : Header
    payload : Sealed       // XChaCha20-Poly1305 over the padded CBOR payload
}
```

`Sealed` is `{ nonce: [u8; 24], ciphertext: bytes }`. The nonce is drawn fresh
from `OsRng` on every seal; XChaCha20's 192-bit nonce makes random selection
safe without a counter.

### 3.2 Header

```
Header {
    vault_id   : Uuid           // v4, minted at init, stable for the file's life
    created_at : DateTime<Utc>
    updated_at : DateTime<Utc>
    epoch      : u64            // monotonic write counter, starts at 1
    recipients : [Recipient]    // at least one; a passphrase recipient always
    mac        : [u8; 32]       // HMAC-SHA256, keyed by the DEK
}
```

`updated_at` **is** covered by the MAC. See [§6.1](#61-what-the-mac-covers).

### 3.3 Recipients

Two variants, serialised with an internal `kind` tag.

```
Recipient::Passphrase {
    argon      : ArgonParams { mem_cost_kib: u32, time_cost: u32,
                               lanes: u32, salt: [u8; 32] }
    sealed_dek : Sealed        // AEAD key = Argon2id(passphrase, argon)
}

Recipient::Hybrid {
    label                   : String
    x25519_public           : bytes   // 32  — the holder's long-term public key
    mlkem_encapsulation_key : bytes   // 1568 — the holder's ML-KEM-1024 ek
    x25519_ephemeral        : bytes   // 32  — generated at wrap time
    mlkem_ciphertext        : bytes   // 1568 — produced at wrap time
    sealed_dek              : Sealed  // AEAD key = BLAKE3 combine of both shared secrets
}
```

The byte lengths above were read off a freshly minted vault, not inferred from
the specification. `sealed_dek.ciphertext` is 48 bytes in both variants: a
32-byte DEK plus a 16-byte Poly1305 tag. A fresh vault carrying one passphrase
recipient, one hybrid recipient and an empty payload is about 11 KB on disk
(10,973 bytes on one run; the label length and the timestamps' sub-second
digits shift it by a few bytes), of which 4,112 are the padded-and-sealed
payload.

The passphrase recipient carries no `label` field; `Recipient::label()` returns
the constant `"passphrase"` for it, and `Vault::remove_recipient` refuses that
label, so a vault can never be left openable only by a key file.

### 3.4 Associated data

Every AEAD use is bound to exactly one purpose, so a blob can never be replayed
from one slot into another (`crypto.rs`):

| Constant | Value | Used for |
|---|---|---|
| `AAD_PAYLOAD` | `black-bag::v2::payload` | the record payload |
| `AAD_RECIPIENT_PASSPHRASE` | `black-bag::v2::recipient::passphrase` | the passphrase-wrapped DEK |
| `AAD_RECIPIENT_PQ` | `black-bag::v2::recipient::mlkem1024-x25519` | the hybrid-wrapped DEK |
| `MAC_CONTEXT` | `black-bag::v2::header-mac` | prefixed to the header MAC input |

There is a test (`crypto::tests::aad_is_binding`) asserting that a blob sealed
under one label does not open under another.

### 3.5 The canonical MAC input

`Header::mac_input(&payload)` produces the following byte string. All
integers are big-endian. Nothing in it is length-ambiguous except the `label`
(NUL-terminated, see the note below) and the two RFC 3339 timestamps, which
are NUL-terminated as well.

```
  u32   VAULT_VERSION                      (= 2)
  [16]  vault_id                           (raw UUID bytes)
  u64   epoch
  ...   created_at.to_rfc3339()            (UTF-8, variable length)
  u8    0x00                               (terminator for the timestamp)
  ...   updated_at.to_rfc3339()            (UTF-8, variable length)
  u8    0x00                               (terminator for the timestamp)
  [32]  BLAKE3.derive_key("black-bag::v2::payload-binding",
                          payload.nonce || payload.ciphertext)
  u32   recipients.len()
  for each recipient, in stored order:
      u32   len(recipient_bytes)
      ...   recipient_bytes
```

and `recipient_bytes` is:

```
  ...   kind_str                           ("passphrase" | "hybrid-x25519-mlkem1024")
  u8    0x00
  ...   label                              (the constant "passphrase", or the holder's label)
  u8    0x00
  ── Passphrase ──────────────────────────────────────────
  u32   argon.mem_cost_kib
  u32   argon.time_cost
  u32   argon.lanes
  [32]  argon.salt
  [24]  sealed_dek.nonce
  ...   sealed_dek.ciphertext              (runs to the end of this recipient's blob)
  ── Hybrid ──────────────────────────────────────────────
  for part in [x25519_public, mlkem_encapsulation_key,
               x25519_ephemeral, mlkem_ciphertext,
               sealed_dek.ciphertext]:
      u32   len(part)
      ...   part
  [24]  sealed_dek.nonce
```

The tag is then

```
mac = HMAC-SHA256( key = DEK, message = MAC_CONTEXT || mac_input )
```

and is compared in constant time (`crypto::mac_matches`, via `subtle`).

**A framing note for reviewers.** Everything in the encoding is either
fixed-width or length-prefixed except the `label`, which is NUL-terminated. A
label containing an embedded NUL would therefore be ambiguous with the field
boundary. In practice this is unreachable: the only path that sets a label is
`black-bag recovery add <label>`, a positional argument, and argv strings are
NUL-terminated C strings that cannot contain one. The code does not enforce it
independently, and a second entry point that could would need to.

### 3.6 Payload

```
Payload { records: [Record] }
```

Serialised to CBOR, then padded (`crypto::pad`) as a 4-byte big-endian length
followed by the data followed by `OsRng` filler to the next 4096-byte boundary,
then sealed under the DEK with `AAD_PAYLOAD`. The block size is not stored in
the file; `unpad` reads the length prefix, so the format is self-describing and
changing `BLACK_BAG_PAD_BLOCK` does not strand an existing vault.

`Record` carries open metadata (`id`, `kind`, timestamps, `title`, `tags`,
`attributes`) and secret material (`fields: [{name, Secret}]`, `notes:
Option<Secret>`, `totp: Option<TotpConfig>`). Unlike the predecessor's
twelve-variant enum — in which a `Contact` had no secret field at all and was
therefore stored in the clear once the payload was open — every kind here uses
the same shape, and anything marked secret is a `Secret`.

### 3.7 Size caps

Applied on the way in and again on the way out, so a hostile file cannot drive
unbounded allocation (`crypto.rs`, `record.rs`, `vault::open_payload`):

| Cap | Value | Where enforced |
|---|---|---|
| Vault file | 64 MiB | `read_vault_file`, from `stat` before the read |
| Payload plaintext | 32 MiB | `pad` / `unpad` |
| Records per vault | 100,000 | `add_record`, and again in `open_payload` |
| Attribute key | 128 bytes | `Record::validate` |
| Attribute value | 8 KiB (`MAX_FIELD_BYTES`) | `Record::validate` |
| Secret field, notes | 256 KiB (`MAX_NOTE_BYTES`) | `Record::validate` |
| Tags per record | 64, each ≤ 128 bytes | `Record::validate` |
| Title | 256 bytes | `Record::validate` |
| TOTP digits | 6–8, step > 0 | `Record::validate` |

---

## 4. Key hierarchy and the unlock walks

There are exactly two ways to reach the DEK, and they are independent: each is
a separate door onto the same room.

```
                 ┌──────────────────────────┐
   passphrase ──►│ Argon2id                 │
                 │  salt (32B, per-vault)   │──► KEK ──┐
                 │  mem 256 MiB (default)   │          │
                 │  time 10, lanes 4..8     │          │  XChaCha20-Poly1305
                 └──────────────────────────┘          │  aad = ::recipient::passphrase
                                                       ▼
                                              [ Recipient::Passphrase.sealed_dek ]
                                                       │
                                                       ▼
                                                    ┌─────┐
                                                    │ DEK │  32 bytes, sealed in memory (§7.2)
                                                    └─────┘
                                                       ▲
                                              [ Recipient::Hybrid.sealed_dek ]
                                                       │  XChaCha20-Poly1305
                                                       │  aad = ::recipient::mlkem1024-x25519
   recovery key file ──┬── X25519 secret ──► DH ───────┤
   (outside the vault) │                               │  BLAKE3 derive_key
                       └── ML-KEM-1024 seed ─► Decaps ─┘  "black-bag::v2::hybrid-recipient"

                                     DEK
                                      │
                    ┌─────────────────┴──────────────────┐
                    ▼                                    ▼
        HMAC-SHA256 over the                 XChaCha20-Poly1305 over the
        canonical header  ──► header.mac     padded CBOR payload  ──► file.payload
```

### 4.1 Passphrase unlock

`Vault::unlock(path, passphrase)`:

1. `read_vault_file` — `stat` the file, refuse over 64 MiB, read, CBOR-decode,
   require `version == 2`, require at least one recipient.
2. For each `Recipient::Passphrase`: `crypto::derive_kek` runs Argon2id
   (`Algorithm::Argon2id`, `Version::V0x13`, output length 32) over the
   passphrase with the stored salt and cost parameters.
3. `crypto::open(kek, sealed_dek, AAD_RECIPIENT_PASSPHRASE)`. A failure is
   skipped silently and the loop continues; if no recipient yields, the call
   fails with the uninformative message `unlock failed`. A wrong passphrase and
   a tampered `sealed_dek` are indistinguishable to the caller.
4. `finish_unlock` (shared with the recovery path, below).

### 4.2 Recovery-key unlock

`Vault::unlock_with_recovery(path, key)`:

1. `read_vault_file`, as above.
2. Refuse immediately if `key.vault_id != header.vault_id`. A recovery key
   belongs to exactly one vault; each `recovery add` mints a fresh keypair.
3. Find the `Recipient::Hybrid` whose `label` matches the key's.
4. `hybrid_decapsulate`:
   * X25519: `StaticSecret(key.x25519_secret) · PublicKey(x25519_ephemeral)`;
   * ML-KEM-1024: reconstruct the decapsulation key from the stored 64-byte
     seed (`DecapsulationKey::new_from_slice`), then `decapsulate_slice` over
     `mlkem_ciphertext`. ML-KEM decapsulation is implicitly rejecting: a wrong
     ciphertext yields a pseudorandom shared secret rather than an error, so a
     wrong key surfaces at the Poly1305 tag in the next step, not here. The only
     error `decapsulate_slice` raises is a length mismatch.
   * combine both, plus both ciphertexts, through BLAKE3 —
     [§5.2](#52-the-combine).
5. `crypto::open(combined, sealed_dek, AAD_RECIPIENT_PQ)`.
6. `finish_unlock`.

### 4.3 `finish_unlock` — common to both

1. Require the recovered DEK to be exactly 32 bytes; otherwise `unlock failed`.
2. `Guarded::new(dek)` — seal the DEK under the per-process session key
   ([§7.2](#72-encrypted-at-rest-in-memory)). From here on the plaintext key
   exists only inside a `SecretBuf`, for the duration of each AEAD or MAC call
   that opens it.
3. Recompute `crypto::header_mac(dek, header.mac_input())` and compare in
   constant time. **A mismatch aborts the unlock**; the payload is never
   decrypted under a header we could not authenticate. The message is
   deliberately distinct — `vault header failed authentication (tampering or
   corruption)` — because by that point the caller has already demonstrated
   possession of a valid key, so there is nothing left to leak.
4. `open_payload`: AEAD-open with `AAD_PAYLOAD`, `unpad`, CBOR-decode, check the
   record-count cap, then `validate()` every decoded record.
5. `Witness::check` sets `rollback_suspected`. This never refuses; it reports.

### 4.4 Rekey

`Vault::rekey(new_passphrase, mem_kib)` mints a fresh 32-byte DEK from `OsRng`,
re-wraps **every** recipient under it — re-salting the Argon2 parameters so the
same passphrase never reproduces the previous KEK, and re-running
`wrap_hybrid` with a fresh ephemeral for every hybrid recipient — re-encrypts
the payload, re-MACs the header, and bumps the epoch. This is what the
predecessor's `rotate` claimed to be and was not: 0.4.x re-wrapped the *same*
DEK, so a DEK exposed once stayed valid for every future version of the file.

`black-bag recovery use --key <file>` unlocks with a recovery key and then
immediately requires a new passphrase and rekeys, so a recovery event does not
leave the old passphrase live.

---

## 5. The hybrid recipient

### 5.1 Why this is meaningful here and was not there

This is the finding from the audit that most needed a real answer, so it is
worth stating the distinction exactly.

In `black-bagg` 0.4.x, `Vault::init` generated an ML-KEM-1024 keypair and
encapsulated **to its own public key**. The decapsulation key was then sealed
under the passphrase-derived KEK and stored in the same header; the KEM
ciphertext sat beside it in the clear. The unlock walk was:

```
passphrase → KEK → dk → shared secret → DEK → payload
```

Every input the KEM needed travelled inside the file, unlocked by the KEK or
stored in plaintext. There was no external party — `grep -i recipient` over that
source returned nothing — so nothing was being encapsulated *to* anyone. The
consequence, stated precisely: an offline attacker never executes the KEM at
all. Vault-at-rest confidentiality was exactly Argon2id + XChaCha20-Poly1305,
with or without the KEM, and the cost per guess was one Argon2id evaluation
either way. The KEM was ~6.3 KB of header, two extra decrypt steps, and two
pre-release crates on the mandatory build path, in exchange for nothing.

**The distinguishing property in v2 is that the private half lives outside the
vault.** `Recipient::Hybrid` stores only public material and the two
ciphertexts:

* `x25519_public` and `mlkem_encapsulation_key` — the holder's public keys;
* `x25519_ephemeral` and `mlkem_ciphertext` — this wrap's ciphertexts;
* `sealed_dek` — the DEK under the combined shared secret.

The corresponding secrets — a 32-byte X25519 secret and a 64-byte ML-KEM seed —
are returned from `Vault::add_recovery_recipient` and written by the CLI to a
separate file with mode 0600, which the user is told in as many words to move
to offline media. `Recipient` has no field that could hold either. An attacker
who holds the vault file and nothing else must therefore break X25519 *and*
ML-KEM-1024 to use that lane, and no amount of passphrase guessing helps,
because the passphrase does not appear anywhere in the lane. That is a
statement 0.4.x could not make about its own KEM, and it is checked in
`vault::tests::recovery_key_unlocks_without_the_passphrase`.

**What this does not mean.** A recovery recipient is a second door, not a
stronger lock. The at-rest strength of the file is the *weaker* of its lanes,
and the attacker picks. Adding a recovery recipient can only lower or leave
unchanged the difficulty of opening the vault; what it buys is availability
(you can lose the passphrase and not the vault) and a lane that survives a
cryptographically relevant quantum computer. The passphrase lane was never at
risk from Shor's algorithm in the first place — Argon2id and XChaCha20-Poly1305
are symmetric — so the honest summary is:

> ML-KEM here does real cryptographic work on a lane whose private key is held
> externally. It does not, and cannot, improve the passphrase lane, and the
> overall file is only as strong as the easiest of its doors.

### 5.2 The combine

`vault::wrap_hybrid` / `vault::combine_shared`:

```
combined = BLAKE3.derive_key(
               context = "black-bag::v2::hybrid-recipient",
               material = ⨁ for part in [x25519_shared,
                                          mlkem_shared,
                                          x25519_ephemeral,
                                          mlkem_ciphertext]:
                              u32_be(len(part)) || part
           ).finalize_xof() → 32 bytes
```

Three properties are being bought:

* **Domain separation.** BLAKE3's `derive_key` mode with a fixed context string
  means this output cannot collide with any other BLAKE3 use in the project —
  notably the secret handles in `Secret::handle`, which use a different context.
* **Length-prefixed framing.** Concatenating variable-length inputs without
  prefixes is the classic way to make two different input tuples hash to the
  same bytes. Each part carries a 32-bit big-endian length.
* **Binding to the ciphertexts.** Both the X25519 ephemeral public key and the
  ML-KEM ciphertext go into the hash, so the derived key is bound to the exact
  encapsulation it came from. Without this, a hybrid combiner can be malleable:
  an attacker who can substitute one ciphertext for another that yields the same
  shared secret gets a key that verifies against a wrap it did not perform.

This is the standard "concatenate the shared secrets and both ciphertexts, then
run them through a KDF" hybrid pattern. It is secure if *either* primitive
holds, under the usual hybrid argument. It is **not** a standardised
construction — it is not X-Wing, not the hybrid KEM of RFC 9370, and not any
other named scheme — and it carries no proof. See non-claim
[13.6](#13-non-claims).

---

## 6. Authenticated header and anti-rollback

### 6.1 What the MAC covers

`mac = HMAC-SHA256(DEK, "black-bag::v2::header-mac" || mac_input)`, where
`mac_input` is the canonical encoding in [§3.5](#35-the-canonical-mac-input).
Concretely, the MAC covers:

* the format version;
* the `vault_id`;
* the `epoch`;
* `created_at` and `updated_at`;
* a BLAKE3 hash (context `black-bag::v2::payload-binding`) of the payload
  nonce and ciphertext;
* the number of recipients, and for each: its kind, its label, its Argon2
  parameters (memory, time, lanes, salt) or its four public/ciphertext blobs,
  and its wrapped DEK in full.

So the attacks it defeats are: downgrading Argon2 cost so a later unlock is
cheaper to attack; swapping in an attacker-chosen salt; deleting the recovery
recipient you rely on; **adding** a recipient whose private key the attacker
holds; rewinding or advancing the epoch to defeat the witness comparison;
retargeting the file's identity. Each of these changes `mac_input`, and the tag
is checked before the payload is opened. `vault::tests::header_tampering_is_detected`
pins the epoch case.

The MAC is keyed by the DEK, which is exactly the point: every recipient
recovers the DEK, so every unlock path — passphrase or recovery key — can verify
the same tag without any additional shared secret. The predecessor's `backup
verify` keyed a BLAKE3 MAC with `blake3::hash(kem_public)`, where `kem_public`
was an unencrypted header field inside the very bytes being tagged; that is a
checksum with per-vault domain separation, and anyone who could modify the file
could recompute it. This is not that.

### 6.2 What the MAC does not cover

Both of the omissions an earlier revision had here were confirmed by executing
them against a real vault, and both are now closed. They are recorded because
the reasoning is the interesting part.

**The payload ciphertext was outside the MAC input.** `mac_input` covered the
header alone, and the payload's own AEAD binds only a constant AAD label — no
epoch, no vault id. So an attacker holding two versions of a vault sealed under
the same DEK generation could keep the *current* header and splice in an
*older* payload. It unlocked, reported the current epoch, raised no rollback
suspicion, and returned stale records: a rollback that the anti-rollback
machinery could not see, because nothing tied the ciphertext to the counter.

`mac_input` now binds the payload by hash:

```rust
let mut hasher = blake3::Hasher::new_derive_key("black-bag::v2::payload-binding");
hasher.update(&payload.nonce);
hasher.update(&payload.ciphertext);
out.extend_from_slice(hasher.finalize().as_bytes());
```

`vault::tests::splicing_an_old_payload_onto_a_current_header_is_detected`
performs exactly the splice described above and asserts the unlock fails
authentication.

**`updated_at` was outside the MAC input**, so the timestamp could be shifted
in either direction by any amount without invalidating the tag. It is now part
of the canonical input, covered by
`vault::tests::editing_updated_at_invalidates_the_tag`.

What the MAC still does not cover is anything outside the file: the witness, the
status document, and the recovery key file are all separate artefacts with their
own trust stories, described in [§6.3](#63-the-witness-is-a-tripwire) and
[§10](#10-the-secret-flow-boundary).

### 6.3 The witness is a tripwire

`vault::Witness` keeps a JSON file at `$XDG_STATE_HOME/black-bag/witness.json`
mapping `vault_id → highest epoch seen`. `Witness::record` never lowers a stored
value. `Witness::check` returns true when a file's epoch is *behind* the
recorded one, which raises `rollback_suspected`, the `ROLLBACK` alert finding,
and a red cockpit state.

**Why it is a tripwire and not a guarantee.** The witness lives in your own
state directory, under your own uid, in an unauthenticated JSON file. An
attacker who can rewrite the vault can almost always rewrite the witness too —
same user, same machine, usually the same access. The witness catches the case
it was built for, which is also the case that actually happens: a stale file
restored from a backup, a Syncthing or Dropbox conflict resolving the wrong way,
a filesystem snapshot rolled back, a copy from a second machine. The predecessor
could not detect any of these.

Three further properties, stated because they change how the signal reads:

* **A rollback warns; it never blocks.** Restoring a legitimate backup must not
  lock you out of your own vault, so the cockpit's verb is "unlock anyway".
* **The witness is keyed by `vault_id`, not by path.** The `_vault_path`
  parameter on `Witness::record` and `Witness::check` is deliberately unused. A
  copy of a vault carries the same id, which is what makes rollback detection
  work — and it also means that legitimately opening an *older* copy of a vault
  you keep alongside the current one raises `ROLLBACK`.
* **The file grows without bound.** One entry per `vault_id` ever seen, never
  pruned. On this machine it holds 53 entries, most of them left by earlier
  test suites: until 2.5.0 every test vault recorded its epoch in the real
  file. The suite now redirects the witness to a private directory
  (`Witness::isolate_for_tests`), but the redirect is first-call-wins and one
  status test (`a_weak_kdf_is_flagged`) does not call it, so a test can still
  land here; `BLACK_BAG_STATE_DIR` remains the reliable guard. That is untidy rather than
  dangerous — the entries carry a UUID, an integer, and a timestamp, and no
  record data — but a reviewer should know it happens.

---

## 7. Memory and process hardening

### 7.1 Ordering: hardening happens first

`fn main()` in `blackbag-cli/src/main.rs` calls `harden::harden_process()` as
its very first statement, before `Cli::parse()` and therefore before any
argument, environment variable, or file content has been read into the process.

### 7.2 Encrypted at rest in memory

Until 2.4.1 the answer to "where do secrets live while the vault is open" was
page locking: every `Secret` owned a `Vec<u8>` with its own `mlock`, released
by `munlock` on drop, with the Drop ordering that `black-bagg` 0.4.10 got
wrong done right (`memlock::Lock` captures `(ptr, len)` at lock time and
unlocks with the captured values, and
`memlock::tests::lock_releases_even_after_buffer_is_cleared` still pins that).
That design had a hole of its own. `mlock` and `munlock` are page-granular and
**not reference-counted**. Two short secrets whose heap allocations share a
4 KiB page — the ordinary case for a password — each locked the page; dropping
the first unlocked it under the second, which went on believing itself locked.
Nothing counted the failure, because nothing failed: the lock was real at the
moment it was taken and silently gone a moment later. The predecessor's bug was
a lock that never released; this was a lock that released too early, and no
test on either side could see the difference. 2.5.0 replaces the design
(`crates/blackbag-core/src/secmem.rs`). It has three parts.

**Every resting secret is ciphertext.** `record::Secret` is now a `Guarded`:
XChaCha20-Poly1305 over the plaintext under a 32-byte per-process *session
key*, with a fresh 24-byte `OsRng` nonce per seal and the associated data
`black-bag::v2::guarded-memory`, so a guarded blob can never be mistaken for —
or replayed into — a vault ciphertext. The DEK is a `Guarded` too
(`Vault::dek`). The sealed bytes sit in an ordinary `Vec`: they may be
swapped, dumped or scraped without revealing anything. `Guarded::open`
decrypts into a `SecretBuf` (below) for exactly as long as the caller holds
it. A blob that fails authentication — which means this process's memory was
altered underneath it — makes `open` panic rather than serve, and because the
release profile unwinds ([§7.4](#74-panic--unwind-and-why-abort-was-wrong-here))
every `Zeroizing` and `SecretBuf` is wiped on the way out.
`secmem::tests::guarded_roundtrips_and_never_stores_plaintext` searches the
sealed buffer for the plaintext; `guarded_uses_a_fresh_nonce_every_time` and
`guarded_detects_tampering_in_memory` pin the other two properties.

**The session key lives where the kernel cannot read it.** `SessionKey::create`
draws 32 bytes from `OsRng` and calls `memfd_secret(2)` — syscall 447, by
number, because `libc` does not export it on every architecture — with no
flags; `ftruncate`s the descriptor to one page; maps it `PROT_READ |
PROT_WRITE, MAP_SHARED`; closes the descriptor, since the mapping keeps the
page alive; and copies the key in. Pages backing a secret memfd are removed
from the kernel's direct map: they are never swapped, never written to a core
file, never included in a hibernation image, and the paths that read another
process's memory through the direct map — `/proc/<pid>/mem`, `ptrace` reads —
do not reach them, root included. Where the kernel refuses (`CONFIG_SECRETMEM`
off, `secretmem.enable=0`, a seccomp filter that omits the call) the key falls
back to a 32-byte range in a locked arena slab, and if that lock also fails,
to an unlocked one. Which of the three happened is a fact, not a hope:
`secmem::KeyBacking` is `memfd_secret`, `locked-slab` or `unlocked`; `doctor`
and `status.json` carry it as `host.session_key_backing`; the deck's HOST
POSTURE card shows it; and `unlocked` raises the `SESSION_KEY_UNLOCKED`
warning. On this machine it is `memfd_secret`, inside the agent's sandbox as
well as outside it (Appendix A). `BLACK_BAG_NO_SECRETMEM=1` skips the call
deliberately, because **a process holding secret memory blocks hibernation
for the whole system** — the kernel refuses to write an image it cannot
include those pages in — and an operator who hibernates has to choose.

**Plaintext lives transiently in a locked arena.** `SecretBuf` is a growable
byte buffer carved from slabs the module maps itself: `mmap(MAP_PRIVATE |
MAP_ANONYMOUS)` of `SLAB_BYTES` (256 KiB), `mlock`ed once, then
`MADV_DONTDUMP` (kept out of any core file, on top of the process-level
`RLIMIT_CORE = 0`) and `MADV_DONTFORK` (a forked child never inherits it).
A slab is never unlocked while anything lives in it. Freed ranges are zeroed
with volatile writes, coalesced with their neighbours and reused; a request
larger than a slab gets a dedicated slab that is wiped again and unmapped
when it is freed. Because no ordinary allocation ever shares a page with a
secret, the shared-page defect cannot recur;
`secmem::tests::two_secrets_never_share_a_lock_they_can_lose` performs the
exact sequence that used to unlock a neighbour. A slab lock the kernel refuses
— `RLIMIT_MEMLOCK` is 8 MiB on a stock box — is counted, not hidden: the slab
is still used, `arena_failed_locks` and `arena_unlocked_bytes` appear in
`status.json`, and the `ARENA_UNLOCKED` warning names the amount.

The arena carries more than parsed fields. `seal_payload` serialises the whole
payload's CBOR into a `SecretBuf` before padding and sealing; `open_payload`
decrypts into one and hands `ciborium` a decoder scratch of
`MAX_NOTE_BYTES + 4096` bytes from the arena (`from_reader_with_buffer`) —
sized to the largest single field the format permits, so a definite-length
byte string is served from scratch when it fits and refused otherwise, which
is the behaviour wanted for a hostile file too; and `Guarded`'s deserializer
asks for `deserialize_bytes` rather than `deserialize_byte_buf`, so `ciborium`
serves each field straight out of that scratch instead of building an
intermediate `Vec`. Between the file and a record the only unlocked memory a
secret byte touches is the heap `Vec` that `Guarded::new` seals in place —
plaintext for the length of one XChaCha20-Poly1305 call, then overwritten by
its own ciphertext — and the register and stack state inside the AEAD. The
generator's `Scratch` is a `SecretBuf` as well.

What this buys, stated exactly. The set of bytes that must never reach disk
shrinks from every secret in the vault to 32 bytes, so the 8 MiB memlock
budget no longer bounds how large a vault can be while its *resting* secrets
keep their promise. The transient is still bounded by it: unlock and save
decrypt or serialise the whole payload into one arena slab, and a payload
larger than the budget sits in a slab the kernel refused to lock for the
length of that operation, which `ARENA_UNLOCKED` reports. A
memory scrape of an idle unlocked agent finds ciphertext where it would have
found passwords. And a secret's protection no longer depends on where its
neighbour was freed. The vault format is unchanged — `Secret` serialises as
the same one-entry map holding the plaintext bytes, into a payload that is
about to be encrypted in the arena — so a v2 file written by 2.4.1 opens as
before, and Argon2id at the defaults (256 MiB, `t = 10`, lanes
`clamp(cpus, 4, 8)`; `nproc` reports 8 here) costs what it did: three runs of
`black-bag list` on a fresh vault measured 1280, 1204 and 1201 ms wall clock
on this 8-vCPU aarch64 VM. That is a measurement of this machine, not a
property of the design.

**What the `/proc/self/mem` test proves, and what it cannot.**
`secmem::tests::a_resting_secret_is_nowhere_in_writable_memory` assembles a
needle at run time (so the literal is not sitting in `.rodata` for the scan to
trip over), seals it, opens it once, drops the opened buffer, re-enables
`PR_SET_DUMPABLE` for the test process, parses every `rw` mapping under
256 MiB out of `/proc/self/maps`, reads each through `/proc/self/mem` into a
scan buffer allocated once — a buffer that grew between mappings would leave
its own earlier contents in freed heap and then find them — and asserts the
needle occurs nowhere but its own allocation. That proves the property the
old design never had a test for: after a use ends, the plaintext is in none
of this process's heap, arena, stacks or other writable mappings. It cannot
prove that no copy existed in a **register or stack frame inside the AEAD**
while the seal or open was running, because the scan is taken afterwards. It
says nothing about **Argon2's working memory** — 256 MiB of ordinary heap
owned by the `argon2` crate during unlock, from which the KEK is derived and
which is not the arena's to wipe. It says nothing about the **QML surfaces**,
which are another process ([13.16](#13-non-claims)), or about the **clipboard
helper's copy**, which lives in `wl-clipboard-rs`'s heap under `mlockall`
([§9](#9-the-clipboard)). And it does not read the `memfd_secret` page at all:
that page is absent from `/proc/self/mem` by construction, which is the point.

`memlock.rs` remains, but only as the `RLIMIT_MEMLOCK` probe behind `doctor`'s
`mlock_working` line; no secret passes through `memlock::Lock` any more.

### 7.3 Core dumps, dumpability, tracer detection

`harden::harden_process()` performs four operations and returns a
`HardenReport` recording which of them actually succeeded, so the UI reports a
posture it achieved rather than one it intended:

| Operation | Effect |
|---|---|
| `setrlimit(RLIMIT_CORE, {0, 0})` | No core file for this process. Both the soft and hard limits are set to zero, so it cannot be raised again by this unprivileged process. |
| `prctl(PR_SET_DUMPABLE, 0)` | No core dump, and blocks `ptrace` attach by a same-uid process regardless of the `yama` scope setting. |
| `prctl(PR_SET_NO_NEW_PRIVS, 1)` | No privilege gain through `execve`. |
| read `/proc/self/status` `TracerPid:` | Records whether a debugger was attached *when we looked*. |

This matters concretely on this host and not merely in principle:
`/proc/sys/kernel/core_pattern` pipes to `systemd-coredump`, the socket is
active, and `ulimit -c` is unlimited. A crash while the vault is open, without
these measures, writes the DEK and every decrypted record into
`/var/lib/systemd/coredump`. `harden::host_core_pattern()` reads and displays
the host's actual pattern next to our own state, so the cockpit tells the truth
about the machine rather than about our intent.

Tracer detection is a **snapshot at startup**, not a monitor. `PR_SET_DUMPABLE
0` prevents a same-uid attach afterwards, but root and any process with
`CAP_SYS_PTRACE` are unaffected, and a missing or unreadable `TracerPid:` line
is reported as "no tracer seen", never as "safe".

Swap is reported rather than assumed away. `harden::swap_devices()` reads
`/proc/swaps`; on this machine `/dev/zram0` is active, which the cockpit shows
next to the mlock state under the finding `SWAP_ACTIVE` — "secrets stay off disk
only because of mlock". Since 2.5.0 that sentence reads as follows: what swap
could carry is the ciphertext of resting secrets, which is harmless without
the key; the session key, if and only if its backing is `unlocked`; and
plaintext in the arena, if and only if a slab lock failed — and each of those
conditions is reported by name ([§7.2](#72-encrypted-at-rest-in-memory)).

The report is threaded through to the status document. `main` obtains the
`HardenReport` before parsing arguments and passes it to every command; the
agent is built `with_hardening(report)`, and `Agent::publish` calls
`HostPosture::measure().with_harden(self.hardening)`, so `status.json`
describes the agent process rather than an unmeasured default. An earlier
revision omitted that call and published `core_dumps_disabled = false` against
a process that had disabled them; the defect is closed, and the test agent
publishes into a private directory (`Agent::with_status_dir`) so a test run no
longer overwrites the live document.

### 7.4 `panic = "unwind"`, and why abort was wrong here

The release profile in the workspace `Cargo.toml` sets `panic = "unwind"`,
against the usual instinct to prefer `abort` for smaller binaries and no
unwinding machinery.

`black-bagg` 0.4.x used `panic = "abort"`. That converts any panic into
`SIGABRT` with no unwinding, which means **no destructor runs** — no `Zeroizing`
drop, no `SecretBuf` wipe, no arena release. Combined with core dumps
enabled (which 0.4.x also no longer disabled, having dropped 0.2.x's
`setrlimit` call), a panic anywhere in a process holding an open vault writes
the DEK and the decrypted records to a file on disk. The two defects compose
into a worse one.

Unwinding is chosen so that scrubbing actually happens on the panic path, and
core-dump suppression is applied separately and independently. Neither is relied
on alone.

An `abort` still occurs on a double panic or on a panic in a destructor. In that
case the process dies without scrubbing, and `RLIMIT_CORE = 0` is the only thing
between that and a dump on disk. That is the reason both measures exist.

---

## 8. The agent

A cockpit that made you retype a six-word passphrase for every reveal would not
get used, so `session::Agent` holds an unlocked `Vault` in memory behind a unix
socket and expires it on a deadline.

### 8.1 Socket and peer authentication

* Path: `$XDG_RUNTIME_DIR/black-bag/agent.sock`, falling back to
  `<state dir>/runtime/` when `XDG_RUNTIME_DIR` is unset.
* The directory is `chmod 0700` (`status::set_owner_only`) before the bind; the
  socket is `chmod 0600` immediately after. Both were verified at runtime on
  this machine, not assumed from the code.
* A stale socket left by a dead agent is removed; a socket a live agent answers
  on causes a refusal to start a second one.
* **`SO_PEERCRED` is checked before a single byte of request is read**
  (`Agent::handle`, `session::peer_uid`). A connection from any uid other than
  our own is dropped with an error on stderr and nothing else. The kernel
  records the peer's credentials at `connect()` time, so this is not subject to
  a time-of-check race.

Directory permissions alone would be sufficient on a single-user box. The peer
check is what makes it safe when the box is not one.

### 8.2 Protocol

One request per connection, JSON on a single line, a JSON response on a single
line. The client sets a 30-second read timeout. The raw request line is
`zeroize`d immediately after parsing, because it may hold a passphrase or a
draft's plaintext secrets.

The accept loop is single-threaded and non-blocking with a 120 ms sleep, so
there is no request concurrency and no lock ordering to reason about. Idle
expiry, the session ceiling and any host lock signal are re-evaluated on every
tick of that loop, so a walked-away desk expires within about a tenth of a
second of the deadline when the agent is idle — or as soon as any in-flight
request finishes, at most a few seconds later — rather than at the next
connection.

**The peer I/O timeout.** A single thread has a cost that 2.4.1 paid without
knowing: a peer that connected and sent nothing held `Agent::handle` in
`read_line` for as long as it liked, and because expiry runs on the same loop
it held idle expiry hostage too. Found by opening the socket and waiting.
`Agent::handle` now sets `PEER_IO_TIMEOUT` — three seconds — as both the read
and the write timeout on the accepted stream: a peer gets three seconds to
deliver its line and three to take its reply, after which the connection is
dropped with one line on stderr and the loop continues. The half-read line is
zeroized on that path as on every other.
`session::tests::a_silent_peer_cannot_stall_the_agent` connects, sends
nothing, and asserts that a second client is answered within the timeout plus
a margin; before the timeout existed, that test hung.

**Secrets on the wire are `Zeroizing`.** `Request::Unlock { passphrase }`,
`Response::Secret { value }`, every entry of `RecordDraft::secrets`, and a
draft's `secret_base32` and `otpauth_uri` are `Zeroizing<String>`, so the
deserialised request and the serialised reply are wiped when they drop. The
reply goes one step further: after the response has been written — or has
failed to be written — `handle` zeroizes a `Secret` reply's value explicitly,
so a revealed value does not outlive its request in this process whatever
happened on the socket.

### 8.3 Idle expiry

`DEFAULT_IDLE_SECS` is 900 (fifteen minutes), floored at 30 seconds by
`Agent::new`. `expire_if_idle` drops the whole `OpenVault` — and with it the
`Vault`, its sealed DEK, every record, and the exposure map from any breach
check — then republishes status.

A design point worth naming: `Request::Status` does **not** extend the deadline.
The bar widget and cockpit poll status continuously; if polling counted as
activity the session would never expire while the shell was running. Only
operations that go through `Agent::opened()` — list, detail, reveal, TOTP, add,
update, delete, hygiene, and the two breach requests — and the explicit `Touch`
request push the deadline out.

### 8.4 The session ceiling

Idle expiry alone lets a session that is touched every few minutes stay open
for days, and a deck on a desk gets touched. `OpenVault` therefore carries two
instants: `deadline`, which slides forward on every request, and `ceiling`,
fixed at unlock as `now + max_session` and moved by nothing. The effective
deadline is the earlier of the two (`OpenVault::effective_deadline`);
`expire_if_idle` checks the ceiling first and locks with
`LockReason::SessionCeiling`, then the idle deadline with `LockReason::Idle`.

`agent serve --max-secs` sets it. `DEFAULT_MAX_SESSION_SECS` is 43,200 —
twelve hours; values below 60 are raised to 60 by `Agent::with_max_session_secs`;
and `0` disables the ceiling, which is a choice the operator makes out loud on
the command line and which the status document reports as
`max_session_secs: 0`. While unlocked, `status.json` carries
`session.session_ends_at`, the wall-clock ceiling, alongside `expires_at`, the
effective deadline; the deck's SESSION card shows the ceiling as *ends
regardless* with its countdown (`Model.sessionRows`).
`session::tests::the_session_ceiling_locks_a_busy_session` unlocks with a
60-second ceiling, touches, and asserts that the reported deadline never
passes the reported ceiling.

### 8.5 Lock reasons

`Agent::lock(reason)` is the only path that closes the vault, and it remembers
why — but only when there was something to close, so a `Lock` request against
an already locked agent does not overwrite the previous reason. The reasons
are `session::LockReason`, serialised in kebab case:

| Reason | When |
|---|---|
| `manual` | A `Lock` request: the CLI's `agent lock`, the deck's LOCK, or the plugin's screen-lock hook ([§8.7](#87-the-sleep-and-screen-lock-watcher)) |
| `idle` | No request through `opened()` or `Touch` within the idle timeout |
| `session-ceiling` | The ceiling of [§8.4](#84-the-session-ceiling) was reached |
| `suspend` | logind announced `PrepareForSleep(true)` |
| `session-lock` | logind announced `Session.Lock` |
| `rekeyed` | `Vault::refresh` failed after the file changed on disk — the held DEK no longer authenticates the header (another process re-keyed it), or the new file could not be read or parsed at all. The reason is named for the common case; a deleted or corrupted vault reports the same word. |
| `shutdown` | A `Shutdown` request, or the serve loop ending |

The last reason is published as `session.last_lock_reason`, and the deck shows
it — *locked before suspend*, *locked with the screen*, *locked at the session
ceiling* — instead of a generic "locked".
`session::tests::a_lock_signal_locks_and_names_its_reason` feeds a `Suspend`
through the watcher channel and asserts both that the vault locked and that
the reason reported is the one delivered.

### 8.6 The mutation lock

`Add`, `Update` and `Delete` each take `vault::open_lock` before touching the
vault and hold it across the refresh–modify–save sequence. `open_lock` opens —
creating if needed — `<vault>.lock` and takes `flock(LOCK_EX)` on it, blocking,
so a second writer waits for the first rather than racing it. The CLI takes
the same lock before every mutating command, and `import` holds it around the
whole batch. Inside the critical section `opened()` runs `Vault::refresh`,
which compares a `FileStamp` — length, mtime **and inode** — against the one
last seen. The inode is the load-bearing field: every write lands through a
rename, so the inode changes on every save, whereas padding makes most writes
the same length and mtime resolution belongs to the filesystem. A padded write
of identical length is therefore never mistaken for no change. `Vault::save`
performs the same stamp check and refuses to write over a version this handle
has not seen; the lock makes sure that case does not arise between
cooperating writers, and the stamp catches one that ignored the lock. Non-claim
[13.9](#13-non-claims) states what is *not* done: merging.

### 8.7 The sleep and screen-lock watcher

Every serious password manager locks when the machine sleeps, and until 2.5.0
this one did not: a lid closed on an unlocked deck carried the data key into
suspend, and a locked screen was not a locked vault.
`crates/blackbag-core/src/sleepwatch.rs` closes both.

**What it subscribes to.** `systemd-logind` announces both events on the
system bus: `PrepareForSleep(true)` as a signal on the
`org.freedesktop.login1.Manager` interface, and `Lock` on the
`org.freedesktop.login1.Session` interface of a session object. The watcher
adds two match rules —
`type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'`
and the same shape for `…login1.Session` / `Lock` — with no path constraint,
so a `Lock` on *any* session path is accepted and a user with several sessions
is locked by any of them. `classify` turns `PrepareForSleep(true)` into
`LockReason::Suspend`, `PrepareForSleep(false)` (the wake-up) into nothing,
and `Lock` into `LockReason::SessionLock`; anything that is not a signal is
ignored, so a method call carrying the same interface and member is never an
event (`sleepwatch::tests::a_method_call_is_never_an_event`). Events travel
over an `mpsc` channel; the serve loop drains it on every tick, next to idle
expiry, and locks with the delivered reason.

**Why it is hand-written.** A D-Bus library is a large dependency for two
signals, and the agent's sandbox is chosen to be small. The module speaks
exactly the subset it needs: connect to `/run/dbus/system_bus_socket` — or to
the `unix:path=` entry of `DBUS_SYSTEM_BUS_ADDRESS` when that is set —
authenticate with SASL `EXTERNAL` on the uid the kernel attaches to the
socket, send `Hello`, send the two `AddMatch` calls and wait for each reply,
then read and classify. It sends nothing derived from a secret and exposes no
interface of its own. The parser (`parse_message`) is bounds-checked at every
step, refuses a header or body over 1 MiB (`MAX_MESSAGE_BYTES`), and returns
`None` on anything malformed rather than panicking;
`sleepwatch::tests::malformed_bytes_never_panic` feeds it every prefix of a
valid signal and every single-byte corruption of one. The worst a hostile bus
can do is fail to mention a sleep — the position before this module existed —
or announce one that is not happening, which locks the vault. Both fail safe.
A connection that drops is retried every 20 s (`RETRY_DELAY`), and the
watcher's state — `connecting`, `watching org.freedesktop.login1 for suspend
and session lock`, `disconnected; reconnecting`, `unavailable: …` — is
published verbatim as `session.sleep_watch` in `status.json`, so the deck's
*suspend & screen lock* row says *locks the vault* only when the watcher is
actually connected and shows the failure text otherwise.

**What it does not do.** It takes **no inhibitor lock**. logind offers delay
inhibitors precisely so a client can finish work before the kernel suspends,
but taking one means receiving a file descriptor over the bus, which is out of
scope for a two-signal client. The consequence is a non-claim
([13.18](#13-non-claims)): the vault is locked on the serve loop's next tick
after the signal — up to about 120 ms when the agent is idle, but seconds if
it is mid-request: an Argon2id unlock or a peer that is slow to send or
receive (up to 3 s each way) holds the single-threaded loop first — and not
provably before the sleep. The sleeping image is not the exposure it once was, because
the session key is in `memfd_secret` memory that the kernel refuses to include
in a hibernation image ([§7.2](#72-encrypted-at-rest-in-memory)) and resting
secrets are ciphertext either way; the residual is the arena and whatever a
request had in flight.

**Omarchy's screen lock is caught elsewhere.** Omarchy's lock screen is the
shell's own service, not logind's: locking it never emits `Session.Lock` on
the system bus, so the watcher — which does catch suspend and `loginctl
lock-session` — cannot see it. The plugin's `Service.qml` resolves the shell's
`omarchy.lock` service in-process and, when its `locked` property becomes true
while the vault is reported unlocked, runs `black-bag agent lock`. From the
agent's side that is an ordinary lock request, so the reason recorded is
`manual`. The two mechanisms are independent, and the SESSION card shows
whether the watcher is connected; it cannot show whether the shell hook is,
because a hook inside the shell has no status of its own.

`sleepwatch::tests::a_real_bus_delivers_both_events` runs the whole client
against the session bus with no sender filter, emits both signals with
`busctl --user emit`, and asserts that the two reasons arrive in order and
that a wake-up delivers nothing. It skips — not fails — where there is no
session bus or no `busctl`.

### 8.8 Secrets leave one at a time, by explicit request

There is no "dump the vault" call, because a cockpit never needs one.

| Request | Returns |
|---|---|
| `Status` | Lock state, expiry, ceiling, last lock reason, watcher state, record count, per-kind counts, rollback flag |
| `List` / `Detail` | `RecordView` — id, kind, title, tags, attributes, TOTP parameters, and per-field *handles* plus each field's byte length; never secret bytes |
| `Reveal { id, field }` | **One** secret field's value, as a `Zeroizing<String>`. The only request that returns secret bytes. |
| `TotpCode { id }` | A derived six-to-eight digit code and its remaining validity |
| `Add` / `Update` | Secrets travel *inbound* here, inside the request |
| `Hygiene` | Handles and titles across the whole vault, plus `EXPOSED` issues from the last breach check — as sensitive as the open vault |
| `BreachPrefixes` | For every `password`, `passphrase` or `pin` field: record id, title, field name, and the first five hex characters of the field's SHA-1. Never the value, never the rest of the hash. |
| `BreachMatch { ranges }` | A `breach::Report`: counts, and per exposed field the record id, title, field name and breach count. No hash. |
| `Lock` / `Touch` / `Shutdown` | No record data |

`session::tests::record_view_carries_handles_not_secrets` serialises a
`RecordView` built from a record with a distinctive password and asserts the
JSON does not contain it.

There is deliberately no `--password` or `--passphrase` flag anywhere in the
CLI. Passphrases are read from `/dev/tty` when there is one and from stdin when
there is not; record drafts arrive as JSON on stdin. `/proc/<pid>/cmdline` is
world-readable, so an argv secret is a published secret.

### 8.9 The breach check: what leaves the machine

Every other analysis in the engine is local. This one is not, and it is built
so that the exception is as small as the protocol allows and so that the
agent — the process holding the key — is not the process that talks.

The protocol is Pwned Passwords' k-anonymity range query, in three round trips
(`cmd_breach` in `crates/blackbag-cli/src/main.rs`; `breach.rs` in the core):

1. **Prefixes out of the agent.** `Request::BreachPrefixes` returns a
   `Candidate` for every field named `password`, `passphrase` or `pin`
   (`CHECKED_FIELDS`) — an API key or an SSH key is not a password in the
   sense the corpus means. Each candidate carries the record id, title, field
   name and the first five uppercase hex characters of the field's SHA-1
   (`PREFIX_LEN`): twenty bits, naming a bucket of on the order of a thousand
   real leaked hashes. The CLI deduplicates and sorts the prefixes
   (`distinct_prefixes`), so two records sharing a value produce one request
   and the request order says nothing about the vault's order.
2. **Buckets in from the service.** For each prefix the CLI runs
   `curl --silent --show-error --fail --max-time 20 --header "Add-Padding: true"
   --user-agent black-bag/<version> https://api.pwnedpasswords.com/range/<prefix>`.
   `Add-Padding` asks the service to pad every response with fake entries so
   that bucket sizes carry no information about which bucket was fetched;
   padding entries have a count of zero and `parse_range` drops them, along
   with any line that is not a 35-hex-character suffix and an integer count.
   A fetch that fails is recorded by prefix and the check continues.
3. **Matching inside the agent.** `Request::BreachMatch { ranges }` hands the
   buckets back. `match_ranges` recomputes each candidate's full SHA-1 in the
   agent's own memory and looks its 35-character suffix up in the bucket for
   its prefix. The comparison is not constant-time and need not be: it is
   between a hash the agent holds and a public list, in the agent's process,
   with no observer. The result is a `Report` — checked, unchecked (no bucket
   arrived), and per exposed field the record id, title, field name and
   breach count — plus an `ExposureMap` keyed by `(record id, field name)`
   that lives in `OpenVault` until the vault locks. Every `Hygiene` request
   for the rest of the session folds it in as `Issue::Exposed { field,
   breaches }` — severity **High**, code `EXPOSED` — so the deck's hygiene
   card and `agent hygiene` carry the finding without asking the network
   again. A fresh check replaces the map wholesale, so a value that was
   exposed and has since been changed does not keep its old verdict.

**What the service sees, exactly.** From one IP address, in one burst: one
HTTPS request per *distinct* prefix, each carrying five hex characters, the
`Add-Padding` header and the user agent `black-bag/<version>`. That is: the
number of distinct prefixes, which is a lower bound on the number of distinct
password values in the vault; and for each, which bucket of about a thousand
candidate hashes yours would be in if it is in the corpus at all. It does not
see which suffix you hold, whether any matched, how many records share a
value, or any title. Nothing else leaves the machine — no full hash, no
value, no metadata — and `breach::tests::a_report_never_carries_a_hash_or_a_value`
asserts that neither the candidates the CLI sends nor the report it prints
contains the value or the full hash, and that the report does not even carry
the prefix.

**Consent and containment.** `agent breach` without `--online` prints what
would be sent and exits with status 2; nothing is fetched. In the deck, CHECK
BREACHES (also `Ctrl+B`) is armed on the first press — *SURE? CHECK ONLINE* —
and runs on the second, like delete, and a press while a check is running is
refused out loud. The requests are made by the CLI through `curl`, never by
the agent: the agent's unit carries `RestrictAddressFamilies=AF_UNIX` and an
empty capability set, so the process that holds the key has no way to open a
network socket however it is compromised ([§8.11](#811-the-systemd-unit)).
The rule in `hygiene.rs` stands — no network call in the hygiene analysis,
ever; the breach result reaches it as data the agent already holds.

**What the check cannot tell you.** A password absent from the corpus is not a
password nobody has leaked, only one Pwned Passwords has not seen.

### 8.10 Honest notes on the agent

* **The request line is bounded in time, not in size.** `PEER_IO_TIMEOUT`
  closes the window a silent peer used to hold open, but
  `BufReader::read_line` still reads until a newline with no size cap, so a
  same-uid peer that sends quickly can make the agent allocate arbitrarily.
  Same-uid is inside the trust boundary by construction
  ([§2.2](#22-what-is-explicitly-out-of-scope)); this is a robustness gap
  rather than a boundary crossing, and it is still a gap.
* **A revealed value leaves the agent as bytes on a socket.** The agent's own
  copy is `Zeroizing` and is zeroized after the write ([§8.2](#82-protocol));
  the copy in the kernel's socket buffer, and the CLI's copy at the other end,
  are outside this process. The CLI wraps its copy in `Zeroizing` too, and the
  clipboard path hands it to a helper whose address space is locked
  ([§9](#9-the-clipboard)).
* **The sender check is delegated to the bus.** logind's signals arrive with
  its unique name (`:1.6`) as sender rather than the well-known one, so
  `sleepwatch::classify` refuses only a message whose sender is a *different*
  `org.`-prefixed well-known name; enforcing `sender='org.freedesktop.login1'` is the
  bus-side match rule's job. The only effect of a forged signal is a lock.
* **The lock is advisory.** `flock` excludes cooperating writers — the CLI,
  the agent, `import`. A process that writes the vault file without taking
  `<vault>.lock` is caught by the `FileStamp` check at save time, which
  refuses rather than merges; it is not prevented.
* **Exposures are remembered until lock.** The `ExposureMap` says which fields
  are in a public breach corpus. It is as sensitive as the open vault, it
  never reaches `status.json`, and it dies with the `OpenVault`.
* **`status.json` describes the agent that wrote it.** The hardening report
  is threaded through ([§7.3](#73-core-dumps-dumpability-tracer-detection));
  the misreport an earlier revision carried is closed.
* **The socket path is subject to `SUN_LEN`.** A sufficiently long
  `XDG_RUNTIME_DIR` makes the agent fail to bind with `path must be shorter than
  SUN_LEN`. It reports the error and exits rather than falling back.

### 8.11 The systemd unit

`install.sh` writes `~/.config/systemd/user/black-bag-agent.service`, not
enabled by default because starting an agent is the user's decision. The unit
carries `Restart=always` with `RestartSec=2`: an agent that exits — after
`agent stop`, a crash, or a failed bind — comes back locked two seconds later
rather than leaving the deck without a door, so stopping the service is
`systemctl --user stop`, not `black-bag agent stop`. Beyond
the 2.4.1 set — `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict` with
an explicit `ReadWritePaths` list, `ProtectHome=read-only`,
`ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`,
`RestrictNamespaces`, `RestrictRealtime`, `LockPersonality`,
`MemoryDenyWriteExecute`, `SystemCallArchitectures=native`, `LimitCORE=0` —
2.5.0 carries:

| Directive | Why |
|---|---|
| `RestrictAddressFamilies=AF_UNIX` | The agent speaks to the deck over its socket and to logind over D-Bus, both unix sockets. Without `AF_INET`/`AF_INET6` there is no network path however the binary is compromised; the breach check runs in the CLI. |
| `CapabilityBoundingSet=` | An empty set. |
| `SystemCallFilter=@system-service memfd_secret` | The allow-list a service needs — it includes the memlock group and `@resources`, which `setrlimit(RLIMIT_CORE)` requires — plus `memfd_secret`, which is in no default group. |
| `SystemCallFilter=~@privileged` | Denied on top of the allow-list. |
| `SystemCallErrorNumber=EPERM` | A filtered call fails with `EPERM` instead of killing the process, so a refusal shows up in `doctor` rather than as a crash. |
| `PrivateDevices=yes`, `RemoveIPC=yes`, `UMask=0077` | No device nodes; no SysV or POSIX IPC left behind; every file the agent creates is owner-only by default, `<vault>.lock` included. |
| `ProtectClock`, `ProtectHostname`, `ProtectKernelLogs`, `RestrictSUIDSGID` | Present in the unit, listed so a reader can diff the file against this table. |

The set was validated as a transient unit — `systemd-run --user` with the same
properties, running `black-bag doctor --json` — before it replaced the
installed one. The command is in Appendix A; on this machine it reports
`session_key_backing: "memfd_secret"`, which is the observation that the
syscall filter admits the call.

---

## 9. The clipboard

`--to clipboard` is the path the deck uses for every COPY, so it is the path
most secrets actually take out of the vault. 2.5.0 rebuilt it after two
defects were found by running the command and watching, not by reading. The
code is `crates/blackbag-cli/src/clipboard.rs`.

### 9.1 The two defects

**The clear never happened.** 2.4.1 spawned `wl-copy --foreground` and a
thread that would kill it after the timeout. The CLI returned a few
milliseconds later, and a thread dies with its process; `wl-copy` went on
serving the secret until something else was copied, while the terminal had
just said *clearing in 30s*. The deck copies through the same command, so
both surfaces made the same false promise.

**Omarchy was recording every copy.** The shell's clipboard plugin runs a
capture script on every selection change and appends what it finds to
`~/.local/state/omarchy/clipboard-history.json` — a plaintext file, mode 0644
on this machine. The script skips an offer that carries the
`x-kde-passwordManagerHint` MIME type or arrives with
`CLIPBOARD_STATE=sensitive`
(`/usr/share/omarchy/shell/plugins/clipboard/capture.sh`, line 15, read on
this machine). `wl-copy --type text/plain` offered no such hint, so every
password copied through 2.4.1 landed in that file.

### 9.2 The helper

The clipboard is now served by `black-bag clip-serve`, a subcommand hidden
from `--help`, spawned from the binary's own path (`current_exe()`) and
speaking the Wayland data-control protocol through `wl-clipboard-rs`. The
caller, `clipboard::copy_secret`, refuses an empty value; caps the clear delay
at `MAX_CLEAR_AFTER_SECS` (3600 s); starts the helper with `setsid()` in
`pre_exec`, so it survives the CLI, its terminal, and the `SIGHUP` that
closing that terminal would deliver; writes the secret to the helper's
**stdin** and closes it — EOF is how the helper knows the value ended; and
waits up to `READY_TIMEOUT` (4 s), polling with `poll(2)`, for one status
line on the helper's stdout. Nothing secret is on argv, where
`/proc/<pid>/cmdline` would publish it: the only argument is
`--clear-after N`.

The helper, `clipboard::serve`, in order:

1. **Starts the clear-timer thread first**, with a 128 KiB stack. It has to
   exist before the address space is locked: with `MCL_FUTURE` in force a new
   thread's stack mapping counts against `RLIMIT_MEMLOCK` (8 MiB on a stock
   box) and `pthread_create` fails with `EAGAIN`. Found by running it. The
   thread waits to be *armed*, so the countdown starts when the offer is on
   the clipboard rather than when stdin was read.
2. **Locks the whole process** with `mlockall(MCL_CURRENT | MCL_FUTURE |
   MCL_ONFAULT)`. A per-buffer lock cannot reach the copies `wl-clipboard-rs`
   keeps in its own heap; locking everything can. `MCL_ONFAULT` locks pages
   as they are touched, so reserved-but-unused mappings do not eat the
   budget. Best-effort, and reported: the status line is `ready locked` or
   `ready unlocked`, and in the second case the CLI appends *helper could not
   lock its memory* to what it prints. Core dumps are already off and the
   process already non-dumpable, because `harden_process()` is the first
   statement of `main` in every invocation of this binary, `clip-serve`
   included.
3. **Reads the value** from stdin into a `Zeroizing<Vec<u8>>`.
4. **Offers three MIME types in one selection**: `text/plain;charset=utf-8`,
   `text/plain`, and `x-kde-passwordManagerHint` with the body `secret`.
   `wl-clipboard-rs` adds the X11-era aliases `STRING`, `UTF8_STRING` and
   `TEXT` to any text offer, so a client asking for those is served too. The
   offer goes to the regular clipboard on every seat.
5. **Reports `ready`**, arms the timer, and serves until either the timer
   clears the selection or another client takes it — at which point
   `prepared.serve()` returns and the process exits.

### 9.3 The hint

`x-kde-passwordManagerHint` is not an access control. It is a MIME type
offered alongside the text, by which a clipboard manager can recognise a
secret and decline to record it. KDE named it; the convention is shared by
cliphist, by `wl-paste --watch` (which sets `CLIPBOARD_STATE=sensitive` for
its child), and by Omarchy's capture script, which is the one read for this
document. A manager that does not look for it records the secret as before.
[§9.6](#96-the-residual) says what that means.

### 9.4 Clear only if it is still ours

When the timer fires it checks a `serving` flag that `prepared.serve()`
clears the moment another client has taken the selection. If the flag is
still set the selection is still ours and the thread calls `copy::clear` for
every seat; if it is not, the thread does nothing. A value the user copied
*after* the secret — a URL, a paragraph — is therefore never wiped by a timer
that outlived its purpose, which is the failure a naive "clear the clipboard
after 30 s" produces. A clear delay of `0` means no timer at all: the secret
stays until something else is copied. That is a choice a user can make on the
command line; the deck does not offer it, because its `clipboardClearSec`
setting is clamped to 5–600 s (`Model.clampSettings`).

### 9.5 What "copied" means

`copy_secret` returning is not the confirmation. After it returns,
`tty::emit_secret` polls the compositor itself — `paste::get_mime_types`,
every 25 ms for up to 3 s (`clipboard::wait_until_sensitive`) — until the
regular clipboard's offer list contains the hint. Only then does it print, to
stderr:

```
copied password to the clipboard · marked sensitive so clipboard managers skip it · clears in 30s
```

If the compositor never offers the value the command fails with *the
compositor never offered the value; nothing was copied*; if the helper dies
before reporting, its exit status and stderr are in the error. The word
*copied* is a report of something observed, not a hope.

### 9.6 The residual

What the helper cannot do is stated here rather than implied by its absence.

* **Every reader keeps its own copy.** A Wayland selection is served, not
  broadcast: each client that pastes receives the bytes over a pipe and holds
  them for as long as it likes, in memory this project neither locks nor
  wipes. The terminal you pasted into, the browser, the editor — each has the
  secret after the clear, until it decides otherwise.
* **A manager that snapshots the selection has a copy too.** Data-control
  clients exist precisely to read every offer as it appears and keep it after
  the source exits; `wl-paste --watch` is one. The hint asks them not to. It
  cannot make them not.
* **A manager that re-owns the selection may drop the hint.** Some managers
  take over the clipboard to keep it alive after the source goes away and
  re-offer only the text; GNOME's is reported to behave this way, and it was
  not tested here. On such a desktop the hint protects the first read, not
  the re-offered copy.
* **Any data-control client can read any offer.** Under the data-control
  protocols every client the compositor admits sees the same selection.
  Nothing in an offer is addressed to a particular reader.
* **The helper's copies are in `wl-clipboard-rs`'s heap.** The
  `Zeroizing<Vec<u8>>` the helper reads into is wiped on drop; the two
  `Box<[u8]>` copies handed to `wl-clipboard-rs` as `Source::Bytes` are
  ordinary allocations it owns and does not zeroize. `mlockall` keeps them off
  swap, and the process exits when serving ends, which frees them without
  scrubbing them. The helper is not the engine's arena, and this document does
  not claim it is.
* **The interval is exposure.** For the configured delay — 30 s by default,
  5 to 600 s from the deck, up to 3600 s from the CLI, or indefinitely at `0`
  — the value is readable by everything above. That is what a clipboard is.

---

## 10. The secret-flow boundary

Every surface, and whether it can hold a secret.

| Surface | Location | Holds a secret? |
|---|---|---|
| Vault file | `~/.local/share/black-bag/vault.cbor`, mode 0600 | Yes, encrypted. Never in plaintext. |
| `status.json` | `$XDG_RUNTIME_DIR/black-bag/status.json`, mode 0600 in a 0700 directory | **Never.** No titles, tags, attributes, counts, or values — only posture (including where the session key lives), KDF parameters, recipient labels and kinds, epoch, lock state, ceiling, last lock reason and the watcher's state string. |
| Bar widget (`Panel.qml`) | Omarchy shell process | Never. Reads `status.json` and shells out to `black-bag status --publish` to refresh it. The QML never opens the agent socket itself; the CLI it spawns asks the agent for lock state (`Request::Status`, which carries no record data) and writes the result to the file. |
| Cockpit (`Cockpit.qml`) | Omarchy shell process | Metadata always, while unlocked. A secret **only** during an explicit `SHOW`, held in a QML property behind a visible countdown, then cleared. `COPY` goes to the clipboard via the CLI and never enters the QML process. |
| Editor (`Editor.qml`) | Omarchy shell process | Yes, while you are typing. Every secret box is masked with a show/hide toggle that re-masks on the reveal countdown, and a multi-line secret is covered until shown; the draft is passed to `black-bag agent add`/`edit` on stdin. An empty secret box means "keep what is stored", so editing a record never loads its existing secret into the form. A successful save and a dismissal empty the boxes. |
| Agent | `black-bag agent serve` process | The DEK and every record field, as ciphertext under the session key; the session key itself, in `memfd_secret` memory (or a locked page, reported); plaintext only in the locked arena while a request uses it ([§7.2](#72-encrypted-at-rest-in-memory)), with two exceptions: a revealed value, in a `Zeroizing<String>` that is zeroized after the reply is written, and a TOTP shared secret, which is copied into an ordinary `Vec<u8>` for `totp-rs` on every `TotpCode` request and is not zeroized when that library drops it. The exposure map from a breach check — record id, field name, breach count — until lock. |
| Agent socket | `$XDG_RUNTIME_DIR/black-bag/agent.sock`, mode 0600 in a 0700 directory, `SO_PEERCRED` checked, 3 s peer I/O timeout | Yes, in transit — inbound passphrases and drafts, outbound revealed fields. Every such string is `Zeroizing` on both ends. |
| Clipboard | Wayland selection, served by the detached `black-bag clip-serve` helper ([§9](#9-the-clipboard)) | Yes, for the configured interval (30 s default; 5–600 s from the deck, up to 3600 s from the CLI, `0` for no timer), offered with `x-kde-passwordManagerHint`, cleared on time only if the selection is still ours. Every client that pasted keeps its copy. |
| Omarchy clipboard history | `~/.local/state/omarchy/clipboard-history.json`, mode 0644 | Never, provided the capture script honours the hint — which the one on this machine does, at line 15. Under 2.4.1 it held every copied secret. |
| Terminal | `/dev/tty`, the default sink | Yes, when you ask. Cannot be redirected by the shell, which is the point. |
| stdout | Only via `--to stdout`, `black-bag agent show`, or `black-bag gen` | Yes, when you ask for it explicitly. `gen` writes the value to stdout and the strength line to stderr, so a pipe captures the secret alone — and a redirect writes a password to a file, which is what a generator is for and worth knowing. |
| Witness file | `~/.local/state/black-bag/witness.json` | Never. `vault_id`, epoch, timestamp. |
| Lock file | `<vault>.lock`, empty, created with the process umask (0077 under the agent's unit) | Never. Zero bytes; `flock(LOCK_EX)` is held on it across every mutation ([§8.6](#86-the-mutation-lock)). |
| Export file | Wherever `export --to` put it, mode 0600, `O_EXCL` | **Yes — every secret in the vault, in plaintext, by design.** Requires `--plaintext-ok`, refuses to overwrite, and you are told to `shred -u` it. |
| Import source | The other manager's export, wherever it is | Yes — it is their plaintext. Read into a `Zeroizing<String>` that is dropped after the parse; skipped rows are reported by number and reason, never by value; you are told to `shred -u` it. |
| Breach request | HTTPS to `api.pwnedpasswords.com`, sent by `curl` from the CLI, only with `--online` | Five hex characters of the SHA-1 of each distinct password-like field — twenty bits — plus your IP, the moment, and the user agent. Never the value, never the full hash ([§8.9](#89-the-breach-check-what-leaves-the-machine)). |
| Recovery key file | Wherever `recovery add --out` put it, mode 0600 | **Yes — this file opens the vault without the passphrase.** Refuses to overwrite an existing file. |
| Process argv | — | Never. There is no flag anywhere in the CLI that takes a secret. |
| `Debug` output | Panics, logs, `unwrap_err()` | Never. `Secret`'s `Debug` prints `Secret(N bytes, redacted)`; `Vault`'s is hand-written (vault.rs) so a derived one cannot forward through the sealed DEK and print it in a panic message. `Secret`'s redaction is pinned by `record::tests::secret_never_prints_its_bytes`; `Vault`'s has no test. |
| Search index | — | Never. `Record::matches` covers titles, tags, kind, and attribute keys and values. A search that reached into a password would leak it through timing and through the result set itself; there is a test asserting it does not. |

Two properties of the socket boundary deserve stating outside the table.

**Wire strings are `Zeroizing`.** The passphrase in `Request::Unlock`, the value
in `Response::Secret`, and the secrets, `secret_base32` and `otpauth_uri` of a
`RecordDraft` are `Zeroizing<String>` on the agent side and on the CLI side,
so the deserialised request and the serialised reply are wiped when they drop;
the agent additionally zeroizes a `Secret` reply after writing it, and
zeroizes the raw request line after parsing it ([§8.2](#82-protocol)).

**A draft's secrets are wiped.** `RecordDraft::into_record` and
`RecordDraft::apply_to` copy each draft secret into a `Secret`, which seals it
at once; the draft is dropped — and with it every `Zeroizing` field — when the
request ends. Nothing about a draft survives in the agent except the sealed
record. On the deck side the editor's boxes are emptied on a successful save
and on dismissal (`clearSecrets`), which is assignment in a QML property, not
scrubbing ([13.16](#13-non-claims)).

### 10.1 The test that pins `status.json`

`status::tests::status_never_serialises_record_material` creates a vault, adds
a record with the title `VERY-DISTINCTIVE-TITLE`, the attribute
`DISTINCTIVE-USER`, and the password `DISTINCTIVE-SECRET`, saves, then builds a
`Status` from the file and serialises it. It asserts that none of the three
strings appears anywhere in the JSON, and that the document is otherwise
populated (`vault_present`, one recipient) so the test cannot pass by producing
nothing.

The module header states the rule the test enforces: *if you are tempted to add
a field here, ask whether you would be happy for it to survive in a
world-readable backup of `/run`.* Note that `Status::probe` never unlocks — it
parses the header only — so there is no code path in which it *could* see a
record. The test guards against a future change that adds one.

---

## 11. Generation and entropy accounting

### 11.1 The rule

`log2(charset^length)` is a true statement about a string drawn uniformly at
random. It is not a statement about a string a human chose. `generate::Strength`
is therefore only ever constructed from a **specification**, never from a value,
and every `Strength` carries a `basis` field stating the assumption in words for
display next to the number.

There is deliberately no function in `generate.rs` that takes a `&str` and
returns bits, and the module header says one should not be added: the moment
such a figure exists it gets rendered next to the honest one and the distinction
dies. This is a stronger commitment than it looks, and it is the reason the
cockpit has no strength meter on a typed password.

### 11.2 Uniform selection

`uniform_below(rng, n)` masks to the next power of two and redraws on overshoot.
`next_u32() % n` — the obvious implementation — gives the low residues one extra
chance for any `n` that is not a power of two, skewing output toward the front
of the charset. Acceptance probability exceeds one half for every `n`, so the
loop is expected to run fewer than twice; `MAX_DRAWS = 256` converts an RNG
malfunction into an error rather than a hang.

### 11.3 The inclusion–exclusion correction

Requiring every enabled character class to appear makes the output uniform over
a *smaller* set than `charset^length`, so it **lowers** entropy. A meter that
imposes the requirement and still quotes the unconstrained figure is
overstating. `generate::class_constraint_bits` computes the correction exactly:

```
P(all classes present) = Σ over subsets S of classes
                             (-1)^|S| · ((charset − Σ_{c ∈ S} |c|) / charset)^length

class_constraint_bits = log2 P            (always ≤ 0)
entropy_bits = length · log2(charset) + class_constraint_bits
```

The sum is factored by `charset^length` so it stays in `[0, 1]` and no big
integers are needed. When the constraint is unsatisfiable it returns
`NEG_INFINITY`, which callers map to `StrengthLabel::Unusable` — "the
specification generates nothing at all; not a weak secret, no secret" — rather
than to a zero that reads like a measurement.

The class requirement is met by **redrawing the whole value**, never by placing
one character per class and shuffling. The shuffle approach is not uniform over
the strings it can produce — it over-represents strings holding exactly one
character from a class — which would make the reported figure wrong. Rejection
keeps the draw uniform over precisely the set the figure counts.

### 11.4 The real default figures

Read off the binary, not computed here. `black-bag gen …` writes the value to
stdout and this line to stderr.

| Command | Alphabet | Reported |
|---|---|---|
| `gen password` (default: 20 chars, all four classes) | 90 symbols | **129.7 bits**, *very strong*; class constraint costs 0.148 bits |
| `gen password --exclude-ambiguous` | 83 symbols | **127.3 bits**, *strong*; constraint costs 0.208 bits |
| `gen password --no-symbols` | 62 symbols | **119.0 bits**, *strong*; constraint costs 0.044 bits |
| `gen passphrase` (default: 8 words) | 512-word list | **72.0 bits**, *moderate* |
| `gen pin` (default: 6 digits) | 10 digits | **19.9 bits**, *trivial* |
| `gen pin --digits 4` | 10 digits | **13.3 bits**, *trivial* |

Three things this table is saying deliberately:

* **Excluding ambiguous glyphs costs real entropy** (129.7 → 127.3 bits), which
  is why it is off by default. It only pays for itself when a human has to
  transcribe the secret by eye.
* **The passphrase default is eight words, not seven.** The wordlist is 512
  entries — a power of two by design, so nine bits per word is exact rather than
  a rounded logarithm, and `uniform_below` never has to reject a draw. Seven
  words is 63 bits, which lands one bit inside the `Weak` bucket. The threshold
  is the honest one, so the default moved rather than the bucket.
* **A four-digit PIN reports as 13.3 bits, *trivial*.** Short PINs are
  permitted, because this module reports what a generator is worth rather than
  enforcing a policy — but it says plainly what four digits is.

The `StrengthLabel` thresholds (under 32 / 32–63 / 64–79 / 80–127 / 128+) are a
**stated convention, not a prediction**. Turning bits into a cracking time
requires a guess rate and a hash cost, neither of which this module can observe;
anything that claims otherwise is guessing on the reader's behalf. `basis` is
the field that carries the content.

The wordlist invariant — 512 entries, sorted, no duplicates, four to seven
lowercase ASCII letters each — is asserted in the tests rather than trusted. A
single duplicated entry would make the true entropy lower than the nine bits per
word the module reports, which is precisely the class of quiet overstatement the
module exists to avoid.

Finally: the symbol set omits quote, backslash, backtick and space on purpose,
because these secrets get pasted into shells, YAML and `.env` files by people in
a hurry. That is a usability choice with an entropy cost, and the cost is in the
number.

---

## 12. Credential hygiene

`black-bag agent hygiene` analyses the whole vault locally. There is no network
call in `hygiene.rs` and there must never be one: "nothing leaves the machine"
is a property users are invited to rely on, and one lookup would end it. The
analysis reads secret bytes to *measure* them — length, whether every byte is an
ASCII digit — and emits only those measurements.

### 12.1 Handle construction

`Secret::handle(domain)` is

```
hex( BLAKE3.derive_key("black-bag::v2::secret-handle")
         .update(domain).update(secret_bytes)
         .finalize()[..4] )
```

— eight hex characters, 32 bits. The hygiene module passes the **field name** as
the domain, so two records whose `password` fields hold the same bytes produce
the same handle, and nothing else does. No secret is ever compared against
another, copied, or held outside its own buffer.

### 12.2 What a collision means, and every stated limit

* **A handle is 32 bits.** Two unrelated secrets share one with probability
  about 2⁻³² per pair. A `ReuseCluster` therefore states that its members
  *share a handle* — not that they provably hold the same bytes. The handle is
  short **because it is shown in the interface**; lengthening it to buy
  certainty would break the thing it is for.
* **The domain is the field name verbatim.** A `password` field and a
  `Password` field occupy different lanes, and reuse between a `password` and a
  `passphrase` field is invisible to this analysis. **An empty
  `reuse_clusters` is not evidence that nothing is reused.**
* **Non-reversible is not the same as safe to publish.** A handle over a
  low-entropy secret — a four-digit PIN has ten thousand candidates — falls to
  an offline search immediately. A `VaultReport` carries handles *and* record
  titles, so it lives in the same trust domain as the open vault: never in
  `status.json`, never in a log, never on argv. `hygiene::summary_line` carries
  counts alone and is what the CLI prints by default.
* **`notes` is excluded from handle computation**, because two records carrying
  the same boilerplate note is not credential reuse; and empty secrets are
  excluded, because every empty secret shares one handle and would manufacture
  a cluster out of nothing.
* **`Stale` is a lower bound.** It is measured from `Record::updated_at`, which
  moves when *anything* on the record is edited — a tag, a URL. The vault stores
  no per-field change time. The absence of a `Stale` issue does not mean the
  password is fresh.
* **`NoTotp` means no second factor is stored *in this vault*.** It says nothing
  about whether the account has 2FA enabled elsewhere.
* **Silence is silence, not a pass.** Rules are applied per kind and per field
  name. A field the module has no defensible expectation for — an API key, an
  SSH private key, a wallet seed, whose length is fixed by whoever issued it —
  is classified `Opaque` and left alone, because a length rule there would be
  advice the owner cannot act on.

### 12.3 Thresholds, and the one that is derived

Every threshold is a named constant, reachable and overridable through
`hygiene::Policy`, so a caller — or a test pinning a boundary — can state a
different one explicitly rather than patch a constant.

| Constant | Value | Applies to |
|---|---|---|
| `MIN_PASSPHRASE_BYTES` | 12 | A chosen, non-all-digit passphrase |
| `MIN_ALL_DIGIT_DIGITS` | 22 | A secret whose every byte is an ASCII digit |
| `MIN_PIN_DIGITS` | 6 | A field named as a PIN, on kinds where the owner chooses it |
| `STALE_AFTER_DAYS` | 365 | `Login`, `Api`, `Ssh`, `Pgp`, `Wifi` |

`MIN_ALL_DIGIT_DIGITS` is the only one derived rather than chosen. It is the
smallest `k` with `10^k ≥ 62^12`, so an all-numeric secret at that length has at
least as many candidates as a twelve-character alphanumeric one. The module docs
state `62^12 = 3226266762397899821056`; that value and both bounding
inequalities (`10^21 < 62^12 < 10^22`, giving `k = 22`) were re-checked here
with exact integer arithmetic and hold.

Kind-specific carve-outs are matched exhaustively, so a thirteenth `Kind` cannot
inherit an answer by default:

* `numeric_pin_is_issued` — `Bank` and `Id`. A bank card PIN is four digits
  because the bank made it four; telling the owner to lengthen it is advice they
  cannot take.
* `rotatable` — excludes `Wallet` (rotating a seed means moving funds) and
  `Bank`/`Id` (facts about the world, not credentials with an age).
* `second_factor_expected` — `Login` and `Bank` only. An API key or an SSH key
  is presented alone by construction.

### 12.4 The figure

There is no score out of a hundred. `HygieneScore` carries counts by severity
plus a demerit total:

```
demerits = 5 · (high issues) + 2 · (medium issues) + 1 · (low issues)
```

`contributions` lists what each record cost, so a caller can show the arithmetic
rather than assert it; the contributions sum to `demerits`, and the tests assert
both. Demerits rise as the vault gets worse and have no ceiling, so there is no
denominator to argue about and no way for a large tidy vault to score worse than
a small filthy one by an accident of scaling.

---

## 13. Non-claims

A numbered list of things this system does **not** prove. This section is the
point of the document.

**13.1 — No formal verification.** This is ordinary Rust with a test suite. It is
not SPARK, there are no proof obligations, and nothing about it has been
mechanically checked. The audit that motivated the rebuild
([`docs/AUDIT.md`](AUDIT.md)) is a careful read plus an adversarial second
opinion, and it should be treated as exactly that. There has been no third-party
security review, and no document in this repository asserts one — which is
itself a response to finding 9 of that audit.

**13.2 — No protection against a compromised host.** If an attacker runs code as
your user, they can read the agent's memory, connect to its socket (the
`SO_PEERCRED` check passes, because they are you), replace the binary, or wait
for you to type the passphrase. Every mechanism in this document assumes the
host is not already lost. None of them recovers if it is.

**13.3 — The witness is local and unauthenticated.** It is a JSON file in your
own state directory. An attacker who can rewrite the vault can usually rewrite
the witness. It reliably catches restored backups, sync conflicts and snapshot
rollbacks; it does not constitute an authenticated anti-rollback mechanism, and
it warns rather than blocks.

**13.4 — The MAC binds the file, not the world around it.** The header, the
payload ciphertext and `updated_at` are all covered. An earlier revision left
the payload and `updated_at` out, which permitted a silent rollback by splicing
an old payload onto a current header — see
[§6.2](#62-what-the-mac-does-not-cover). What remains uncovered is everything
outside the vault file: the witness, the status document and any recovery key
file are separate artefacts, and are only as trustworthy as the filesystem they
sit on.

**13.5 — Handles are 32 bits.** A shared handle means the two secrets *share a
handle*. It is not proof they are the same value, and the absence of a cluster
is not proof of no reuse — see [§12.2](#122-what-a-collision-means-and-every-stated-limit).

**13.6 — The hybrid combiner is not a standardised construction.** It is the
conventional concatenate-shared-secrets-and-ciphertexts-then-KDF pattern with
BLAKE3 in derive-key mode. It is not X-Wing, not the hybrid KEM of RFC 9370, and
it carries no security proof and no external review. The claim made for it is the
ordinary hybrid argument — secure if either primitive holds — and nothing
stronger. Relatedly, ML-KEM-1024 has been standardised for a short time and its
implementations are young; `ml-kem 0.3.2` is a stable release, which is more
than the predecessor's pre-release dependencies could say, but it is not
battle-tested code.

**13.7 — A recovery recipient is a second door, not a stronger lock.** The
at-rest strength of the file is the weaker of its lanes and the attacker
chooses. Adding a recovery recipient cannot make the vault harder to open. If
you keep the key file next to the vault, you have simply removed the passphrase
from the equation.

**13.8 — The session key's home is best-effort, and 32 bytes is what must
never leak, not all that can.** `memfd_secret` is requested, not assumed:
where the kernel lacks `CONFIG_SECRETMEM`, boots with `secretmem.enable=0`, or
runs the process under a seccomp filter that omits syscall 447, the key falls
back to one page-locked arena slab, and if that lock fails too, to ordinary
memory — each reported as `session_key_backing` (`memfd_secret` /
`locked-slab` / `unlocked`), the last as the `SESSION_KEY_UNLOCKED` warning,
never silently. Arena locks are best-effort in the same way (`RLIMIT_MEMLOCK`
is 8192 KiB on this machine; `arena_failed_locks`, `arena_unlocked_bytes`,
`ARENA_UNLOCKED`). And the guarantee is about *resting* secrets: plaintext
exists in the arena while a field is in use, in registers and stack frames
inside the AEAD during a seal or open, and in Argon2's 256 MiB working set
during unlock, none of which the `/proc/self/mem` test can see
([§7.2](#72-encrypted-at-rest-in-memory)). A hypervisor reads all of it
regardless.

**13.9 — Concurrency is detected, not merged.** `vault::open_lock` takes a real
`flock(LOCK_EX)` for a critical section, `Vault::save` refuses to write over a
version the handle has not seen, and the agent calls `Vault::refresh` before
serving any request that reads or writes records — so a CLI write and a cockpit write no longer silently
discard one another. What the system does *not* do is merge divergent record
sets: it detects the conflict and re-reads. Because every mutation is saved
immediately, there is never unsaved work to lose by re-reading, but a design
that batched edits in memory could not rely on that.

**13.10 — Padding hides size only to block granularity.** The payload is padded
to 4096 bytes. A vault with a thousand records is visibly larger than one with
three. What padding buys is that a small addition does not change the file size
at all — which is what `vault::tests::payload_is_padded_so_size_does_not_track_content`
pins — not that size carries no information.

**13.11 — The breach check is the one network act, and this is exactly what
it discloses.** Everything else about the account behind a credential —
revocation, reachability, whether 2FA is enabled elsewhere — is unknown to the
vault. `black-bag agent breach --online`, and the deck's CHECK BREACHES after
its two-step confirm, sends to `api.pwnedpasswords.com` over HTTPS through
`curl`: one request per distinct five-hex-character SHA-1 prefix among the
vault's `password`, `passphrase` and `pin` fields, from your address, in one
burst, with a `black-bag/<version>` user agent and `Add-Padding: true`. The
service therefore learns your address, the moment, the number of distinct
prefixes — a lower bound on the number of distinct password values — and
twenty bits of each; if it logs, it learns that a Black-Bag user at that
address holds passwords in those buckets. It does not learn which suffix you
hold, whether any matched, how many records share a value, or any title. The
matching happens in the agent; the full hash never leaves it, and the agent's
sandbox has no network family at all. Absence from the corpus is not absence
from every breach. Without `--online` nothing is sent and the command exits 2
([§8.9](#89-the-breach-check-what-leaves-the-machine)).

**13.12 — Entropy figures describe the generator, never a typed value.** They
are exact for values this project generated and are meaningless applied to
anything else. The `StrengthLabel` buckets are a stated convention, not a
prediction about cracking time.

**13.13 — Deletion is not secure erasure.** `black-bag remove` and `agent
delete` rewrite the vault without the record. The old ciphertext may persist in
the filesystem's free space, in a snapshot, in a backup, or in the flash
translation layer of the underlying device. Nothing here overwrites it.

**13.14 — There is no duress mode, no decoy vault, and no defence against
coercion.** A rubber hose beats this design, as it beats every design of this
shape.

**13.15 — The dependency tree is trusted.** `argon2`, `chacha20poly1305`,
`blake3`, `hmac`, `sha2`, `subtle`, `zeroize`, `ml-kem`, `x25519-dalek`,
`ciborium`, `totp-rs` and the rest are taken on faith, along with everything
they pull in. No vendoring, no reproducible-build attestation, no supply-chain
verification beyond `Cargo.lock`.

**13.16 — The Omarchy surfaces run inside the shell process.** The cockpit and
editor are QML in `omarchy-shell`, sharing an address space with every other
plugin loaded there. A secret shown with `SHOW`, and every keystroke typed into
the editor, lives in that process's memory with no page locking and no
scrubbing. The CLI path is the more defensible one; the cockpit is a
convenience, and the trade is real. Unchanged in 2.5.0: the editor's show/hide
toggle and the cover on a multi-line secret change what is painted, not where
the bytes are, and `clearSecrets()` on dismissal assigns empty strings to QML
properties, which is not a scrub.

**13.17 — Tracer detection is a snapshot.** Taken once at process start.
`PR_SET_DUMPABLE 0` blocks a subsequent same-uid attach, but root and
`CAP_SYS_PTRACE` are unaffected, and there is no ongoing monitor.

**13.18 — A lock is not guaranteed before the kernel sleeps, and secret memory
has a cost.** The sleep watcher takes no inhibitor lock
([§8.7](#87-the-sleep-and-screen-lock-watcher)): it locks on the serve loop's next
tick after `PrepareForSleep(true)` — about 120 ms when idle, seconds if a
request is in flight — and no proof is offered that this precedes the
suspend. The plugin's hook for
Omarchy's own screen lock runs `black-bag agent lock` as a subprocess and has
the same shape. What bounds the exposure is not the timing but the memory
design: the session key is in `memfd_secret` pages the kernel refuses to
include in a hibernation image, so an image taken with the vault open carries
ciphertext and no key. That property is bought with a system-wide side
effect — **a process holding secret memory blocks hibernation for the whole
machine** — which is why `BLACK_BAG_NO_SECRETMEM=1` exists and why an operator
who hibernates has to choose. On the clipboard side, the helper's copies of a
served value live in `wl-clipboard-rs`'s heap under `mlockall`, not in the
engine's arena, and are freed rather than wiped when serving ends
([§9.6](#96-the-residual)).

**13.19 — `black-bagg` on crates.io is unchanged.** This repository does not and
cannot alter what is already published there, including the API token in
releases 0.4.6 through 0.4.10 (audit finding 1) and the fabricated Trail of Bits
review shipped in 0.3.5 (audit finding 9). Both require the maintainer's hands.

**13.20 — No AEAD here is key-committing.** XChaCha20-Poly1305, as used for
the payload, the wrapped DEKs and the in-memory `Guarded` blobs, does not
commit to its key: a party who controls two keys can construct one ciphertext
that authenticates under both, which is the property behind the
partitioning-oracle class of attacks that RFC 9771 describes. No path in this
design hands an attacker an online decryption oracle to partition — the vault
is opened offline by its owner, and the header MAC keyed by the DEK is checked
before the payload is touched — so no concrete exploit is claimed to exist,
and no resistance is claimed either. A construction that needed commitment (a
committing wrap of the DEK, or a hash of the key bound into the header) would
be an explicit change to the format.

**13.21 — There are no per-item keys.** The payload is one AEAD blob under the
DEK. A field is not separately sealed, and nothing binds a field's ciphertext
to its record id or its field name; a swapped field inside the payload is
prevented only by the payload being one blob whose tag covers all of it — and
anyone who can rewrite that blob already holds the DEK. In memory, every
`Guarded` value carries its own nonce but the same session key and the same
AAD, so a process that can write the agent's memory could exchange two sealed
blobs between two `Secret`s and neither would notice. A process that can write
the agent's memory is the lost host of 13.2.

**13.22 — The import parsers are hand-written and only as good as their
tests.** `import.rs` parses Bitwarden's unencrypted JSON, KeePassXC's CSV,
Firefox's and Chrome's CSVs and a generic CSV by hand, mapping kinds by table;
an encrypted Bitwarden export is refused with advice, and a row that fails
`validate()` is reported by row number and reason, never by value. Ten tests
cover the formats the author had samples of — including a KeePassXC round trip
of every kind — and nothing else. A column the synonym table does not
recognise becomes an attribute; a format revision none of the tests saw may
mis-map a field silently or skip a row loudly. `--dry-run` exists so the
mapping can be read before it is committed, and the parsed text is a
`Zeroizing<String>` dropped after the parse.

**13.23 — Export is plaintext by design.** `black-bag export` writes every
secret in the vault, unencrypted, as JSON or KeePassXC CSV. It demands
`--plaintext-ok`, creates the file `O_EXCL` with mode 0600, refuses to
overwrite, and tells you to `shred -u` it afterwards — and that is the whole of
its protection. From the moment it exists the file is your problem: snapshots,
backups, sync clients and the flash translation layer all apply, as in 13.13.
There is no encrypted export, because every importer on the other side wants
plaintext, and an encrypted one would be a second vault format with none of
this document behind it.

**13.24 — The clipboard hint is a request.** `x-kde-passwordManagerHint` asks
a clipboard manager not to record an offer. A manager that ignores it records
the secret; a manager that re-owns the selection may drop it; every client
that pastes keeps a copy; every data-control client can read every offer. The
helper's clear removes *our* offer, on time and only if it is still ours, and
does nothing to any copy already taken ([§9.6](#96-the-residual)).

---

## 14. Comparison with `black-bagg` 0.4.10

Line references are to `black-bagg-0.4.10/src/lib.rs` as published; the full
derivation is in [`docs/AUDIT.md`](AUDIT.md).

| Property | `black-bagg` 0.4.10 | Black-Bag v2 | Why it changed |
|---|---|---|---|
| ML-KEM lane | Encapsulated to its own public key; decapsulation key sealed under the passphrase KEK in the same header (:930–933, :947, :877) | `Recipient::Hybrid` — X25519 + ML-KEM-1024, private half written to a separate 0600 file and never stored in the vault | A KEM whose every input travels with the file contributes zero bits. The external private key is the whole property. |
| Rotation | `rotate` re-wrapped **the same** DEK; could not change the passphrase; did not re-salt without `--mem-kib` (:1092–1116, :1780–1787) | `Vault::rekey` mints a fresh DEK, re-encrypts the payload, re-wraps every recipient, re-salts, and can change the passphrase | A DEK exposed once otherwise stays valid for every future version of the file. |
| Header authentication | None. Epoch-free, MAC-free header fields open to silent edit | HMAC-SHA256 over a canonical header encoding, keyed by the DEK, checked before the payload is opened | Argon2 downgrade, recipient injection and epoch tampering were all silent. |
| Integrity sidecar | `backup verify` keyed a BLAKE3 MAC with `blake3::hash(kem_public)` — a public header field inside the tagged bytes (:2051) | Dropped entirely | It was a checksum with per-vault domain separation, and printed `Integrity verified` for a tampered vault. |
| Anti-rollback | None (0.2.x had an epoch and a `.epoch` sidecar; 0.4.x dropped both) | Monotonic epoch in the MAC'd header, plus an out-of-band witness keyed by `vault_id` | A restored backup was undetectable. |
| `mlock` release | `Drop` zeroized the `Vec` then called `munlock` with the now-zero length, so the unlock silently no-opped (:834–842) | No per-secret `munlock` exists to get wrong: plaintext is carved from arena slabs that stay locked while anything lives in them, and resting secrets are ciphertext | With `ulimit -l` at 2048 pages, a long session exhausts the budget and later locks fail unnoticed. Black-Bag 2.4.1 fixed the ordering (`memlock::Lock`, still tested) and still had a hole — `mlock` is page-granular and not reference-counted, so two secrets sharing a page lost the lock when the first was dropped. |
| Secrets loaded from the vault | Constructed by `Deserialize` without ever being locked (:1220) | Decrypted into a locked buffer, decoded through a locked scratch (`from_reader_with_buffer`, `deserialize_bytes`), and sealed as `Guarded` values as they are constructed | A secret that passes through an ordinary `Vec` between the file and the record is a secret in swappable memory. |
| Core dumps | Nothing (0.2.x had `setrlimit`, lib.rs:116) | `setrlimit(RLIMIT_CORE, {0,0})` + `PR_SET_DUMPABLE 0` + `PR_SET_NO_NEW_PRIVS`, with a report of what actually took effect | `core_pattern` on this host pipes to systemd-coredump and `ulimit -c` is unlimited. |
| Panic strategy | `panic = "abort"` | `panic = "unwind"` | Abort means no destructor runs, so `Zeroizing` never fires; with core dumps enabled the DEK lands on disk. |
| Tracer detection | Removed (0.2.x had it, lib.rs:126) | `/proc/self/status` `TracerPid:` at startup, surfaced as an `alert` finding; the cockpit blocks unlock with no override | A live ptracer reads the passphrase keystroke by keystroke. |
| Parser size caps | Removed (0.2.x had them, lib.rs:59–66) | 64 MiB file cap pre-parse, 32 MiB plaintext cap, record-count cap, `validate()` on every decoded record | A hostile file otherwise drives unbounded allocation in the CBOR decoder. |
| Payload padding | Removed (0.2.x had `BLACK_BAG_PAD_BLOCK`, lib.rs:1681–1723) | Restored, 4096-byte default, same environment override | File size otherwise tracks how much you store. |
| Secret output | `println!` to stdout | `/dev/tty` by default; `--to clipboard` and `--to stdout` require asking | stdout is redirectable, so a pipe or a shell recording silently persists the secret. |
| Argon2 cost | time=3, lanes=1 | time=10, lanes = `clamp(cpus, 4, 8)`, 256 MiB default, 32 MiB floor | 0.2.x shipped time=10 / lanes≥4; the 0.4.x rewrite cut it by roughly a factor of 3.3 in work and lost all parallelism. |
| Record shape | Twelve-variant enum; `Contact` had no secret field, so contact data sat in the clear once the payload was open | One shape for every kind; anything marked secret is a `Secret` | A "kind with no secrets" is a kind whose data is unprotected inside the payload. |
| Decrypt error messages | Unsanitised | Uniform `decryption failed` / `unlock failed` | A caller must not distinguish "wrong passphrase" from "tampered blob" by message text. |
| `Debug` on secrets | Derived | Hand-written on both `Secret` and `Vault` | A derived `Debug` on `Vault` forwards through `Zeroizing<[u8; 32]>` and prints the live DEK in an `unwrap_err()` panic message. |
| Tests | `#[cfg(test)]` imported `proptest` and `serial_test` with **no `[dev-dependencies]` section at all**; `cargo test --no-run` exited 101 | `[dev-dependencies]` declared; 171 tests across the workspace pass, plus 183 cockpit assertions | Nobody downstream could run the test suite of a password manager from the published artefact. |
| Documented commands | README documented four commands that do not exist and a `--ram-drive` flag that was never implemented | README is hand-maintained and cross-checked against the clap-derived `--help`; no documented command is absent from the binary | It is the first thing a new user hits. |
| Platform | macOS-oriented (`hdiutil`, `diskutil`, `/Volumes/…`) | Linux only, Omarchy-targeted | The RAM-disk story never worked on Linux; sealed memory and a locked arena replace it. |
| Third-party review | A 1,090-line document naming Trail of Bits as the acting party eleven times, shipped in 0.3.5 | None claimed | `docs/AUDIT.md` is signed as what it is: the author's own review. |
| In-memory encryption | None; each secret a plaintext `Vec<u8>` | Every resting secret sealed (XChaCha20-Poly1305, AAD `black-bag::v2::guarded-memory`) under a 32-byte per-process key held in `memfd_secret` memory, falling back to a locked page, the backing reported either way | A memory scrape of an idle unlocked agent finds ciphertext; what must never reach disk is 32 bytes, not the vault. |
| Clipboard hint and clear | Not recorded in the audit | Detached `clip-serve` helper offering `x-kde-passwordManagerHint` beside the text, `mlockall`ed, clearing on time only if the selection is still ours; "copied" printed only after the compositor was seen offering it | Black-Bag 2.4.1's `wl-copy` carried no hint and its clear never fired; Omarchy's history file recorded every copy. |
| Sleep and screen lock | Not recorded in the audit | Hand-written D-Bus client on logind's `PrepareForSleep` and `Session.Lock`; the plugin hooks Omarchy's own lock service; the reason is reported | A closed lid carried the data key into suspend; a locked screen was not a locked vault. |
| Session ceiling | Not recorded in the audit | `--max-secs`, default 12 h, floor 60 s, `0` to disable; fixed at unlock and unmoved by activity | Idle expiry alone let a touched session stay open for days. |
| Breach check | Not recorded in the audit | Opt-in `--online` k-anonymity query: five hex characters of SHA-1 per distinct password, via `curl` from the CLI; matching in the agent, which has no network family | The one network act, made as small as the protocol allows and kept out of the process that holds the key. |
| Import / export | Not recorded in the audit | Bitwarden, KeePassXC, Firefox, Chrome and generic CSV in; JSON or KeePassXC CSV out with `--plaintext-ok`, 0600, never overwriting | A vault you cannot move into is one nobody switches to; one you cannot move out of is a trap. |

---

## Appendix A — verifying the claims in this document

```bash
cd ~/Projects/blackbag

# The whole suite. Tests redirect the witness and status.json to private
# directories themselves; the env var is a belt-and-braces guard for the one
# status test that does not.
BLACK_BAG_STATE_DIR=/tmp/bb-test cargo test --workspace

# The cockpit's pure-JS model.
plugin/khephri.blackbag/tests/run.sh

# The specific tests this document cites.
cargo test -p blackbag-core header_tampering_is_detected
cargo test -p blackbag-core status_never_serialises_record_material
cargo test -p blackbag-core recovery_key_unlocks_without_the_passphrase
cargo test -p blackbag-core rekey_changes_the_dek_and_the_passphrase
cargo test -p blackbag-core lock_releases_even_after_buffer_is_cleared
cargo test -p blackbag-core secret_never_prints_its_bytes
cargo test -p blackbag-core search_never_matches_secret_material
cargo test -p blackbag-core payload_is_padded_so_size_does_not_track_content

# 2.5.0 — memory (§7.2).
cargo test -p blackbag-core a_resting_secret_is_nowhere_in_writable_memory
cargo test -p blackbag-core two_secrets_never_share_a_lock_they_can_lose
cargo test -p blackbag-core guarded_roundtrips_and_never_stores_plaintext
cargo test -p blackbag-core guarded_detects_tampering_in_memory
cargo test -p blackbag-core the_session_key_has_a_named_home -- --nocapture   # prints the backing
black-bag doctor --json | jq '.host.session_key_backing'                     # "memfd_secret" here

# 2.5.0 — the agent (§8).
cargo test -p blackbag-core a_silent_peer_cannot_stall_the_agent
cargo test -p blackbag-core the_session_ceiling_locks_a_busy_session
cargo test -p blackbag-core a_lock_signal_locks_and_names_its_reason
cargo test -p blackbag-core malformed_bytes_never_panic
cargo test -p blackbag-core a_real_bus_delivers_both_events -- --nocapture   # needs a session bus and busctl; skips otherwise

# The screen-lock path end to end, against a running agent: unlock, ask
# logind to lock the session, read the reason back.
systemctl --user start black-bag-agent
black-bag agent unlock
loginctl lock-session
black-bag status | jq '.session.last_lock_reason, .session.sleep_watch'
# expected: "session-lock" and "watching org.freedesktop.login1 for suspend and session lock"

# 2.5.0 — the breach protocol (§8.9): what is and is not in the messages.
cargo test -p blackbag-core a_report_never_carries_a_hash_or_a_value
cargo test -p blackbag-core prefixes_are_deduplicated_and_sorted
cargo test -p blackbag-core a_bucket_parses_and_drops_padding
black-bag agent breach            # prints what would be sent and exits 2; nothing is fetched

# 2.5.0 — the clipboard (§9), observed rather than assumed.
black-bag agent reveal <id> password --to clipboard --clear-after 10
wl-paste --list-types             # must include x-kde-passwordManagerHint
sleep 11; wl-paste --list-types   # the selection is gone; nothing copied later is touched

# 2.5.0 — the agent's sandbox as a transient unit, before trusting the
# installed one. On this machine: "memfd_secret", true, true.
systemd-run --user --wait --pipe --quiet \
  -p RestrictAddressFamilies=AF_UNIX -p CapabilityBoundingSet= \
  -p "SystemCallFilter=@system-service memfd_secret" -p "SystemCallFilter=~@privileged" \
  -p SystemCallErrorNumber=EPERM -p PrivateDevices=yes -p RemoveIPC=yes -p UMask=0077 -p LimitCORE=0 \
  ~/.local/bin/black-bag doctor --json \
  | jq '.host | {session_key_backing, core_dumps_disabled, non_dumpable}'

# 2.5.0 — import and export (§13.22, §13.23).
cargo test -p blackbag-cli an_encrypted_bitwarden_export_is_refused_with_advice
cargo test -p blackbag-cli keepassxc                                          # the round-trip tests
black-bag import --format keepassxc --from export.csv --dry-run              # mapping and skips, nothing written
black-bag export --to out.json --format json                                 # refuses without --plaintext-ok

# The generator's own figures, on your machine.
black-bag gen password        # value on stdout, basis on stderr
black-bag gen passphrase
black-bag gen pin --digits 4

# Host and vault posture, as measured rather than as intended.
black-bag doctor
black-bag status | jq '.host, .findings'
```

To reproduce the two MAC-coverage findings in
[§6.2](#62-what-the-mac-does-not-cover), the shortest route is a temporary test
module inside `crates/blackbag-core/src/vault.rs`, where `read_vault_file` and
`write_vault_file` are in scope: read the file, change `header.updated_at` (or
swap in a `payload` captured from an earlier save), write it back, and unlock.
Both succeed.

## Appendix B — environment variables

| Variable | Effect |
|---|---|
| `BLACK_BAG_VAULT_PATH` | Vault location. Also settable as `--vault`. |
| `BLACK_BAG_STATE_DIR` | State directory, holding `witness.json`. |
| `XDG_DATA_HOME` | Default vault directory when the above is unset. |
| `XDG_STATE_HOME` | Default state directory. |
| `XDG_RUNTIME_DIR` | Where `status.json` and `agent.sock` live. Subject to `SUN_LEN` for the socket. |
| `BLACK_BAG_PAD_BLOCK` | Payload padding block, 1 to 1,048,576 bytes; default 4096. Not stored in the file, so changing it does not strand a vault. |
| `BLACK_BAG_NO_SECRETMEM` | When set to any value, the session key is not placed in `memfd_secret` memory; it goes to a page-locked arena slab instead (or, if that lock fails, to ordinary memory — reported as `unlocked`). Set it when the machine must be able to hibernate while an agent runs: a process holding secret memory blocks hibernation system-wide ([§7.2](#72-encrypted-at-rest-in-memory)). |
| `DBUS_SYSTEM_BUS_ADDRESS` | Honoured by the sleep watcher: the first `unix:path=` entry names the system bus socket; otherwise `/run/dbus/system_bus_socket`. |
