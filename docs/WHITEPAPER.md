# Black-Bag — technical whitepaper

Vault format v2 · engine version 2.0.0 · Linux (Omarchy, aarch64)

This document describes what Black-Bag does, how it does it, and — at greater
length than is usual — what it does not do. It is written for two readers: a
security engineer deciding whether to keep a credential here, and a reviewer
looking for something to disagree with. Both are given file and function names
so that every claim can be checked against the source rather than taken on
trust.

Where a statement rests on an assumption, the assumption is named. Where a
mechanism is a tripwire rather than a guarantee, it is called a tripwire. The
non-claims in [§12](#12-non-claims) are the part of this document that matters
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

This repository is the corrected rebuild. [§13](#13-comparison-with-black-bagg-0410)
sets the two side by side.

### 1.2 What this project is not

It is not formally verified. It is ordinary Rust with a test suite — 120 tests
across the workspace at the time of writing (116 in `blackbag-core`, 4 in
`blackbag-cli`), plus 117 assertions over the cockpit's `Model.js`. It has not
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
| Page locking | `crates/blackbag-core/src/memlock.rs` |
| Process hardening, host probes | `crates/blackbag-core/src/harden.rs` |
| Agent, socket protocol, TOTP | `crates/blackbag-core/src/session.rs` |
| `status.json` construction and findings | `crates/blackbag-core/src/status.rs` |
| Generation and entropy accounting | `crates/blackbag-core/src/generate.rs` |
| Credential hygiene | `crates/blackbag-core/src/hygiene.rs` |
| CLI, subcommands, secret sinks | `crates/blackbag-cli/src/{main,tty}.rs` |
| v1 (`black-bagg` 0.4.x) migration reader | `crates/blackbag-cli/src/migrate.rs` |
| Bar widget, cockpit, editor, service | `plugin/khephri.blackbag/*.qml`, `Model.js` |

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
concrete mechanisms are: page-locked buffers for the DEK and for secrets
created in-process; `RLIMIT_CORE` set to zero and `PR_SET_DUMPABLE` cleared
before anything touches memory; `panic = "unwind"` so destructors actually run;
no `--passphrase` flag anywhere in the CLI, because `/proc/<pid>/cmdline` is
world-readable; secrets written to `/dev/tty` by default rather than to a
redirectable stdout; a status file whose contents are constrained by test; a
`Debug` impl on `Secret` and on `Vault` that redacts rather than prints. The
full surface-by-surface accounting is in [§9](#9-the-secret-flow-boundary).

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
whether a password has been breached, whether an account has 2FA enabled
elsewhere, or whether a key has been revoked. Nothing in this project makes a
network call, by design, and adding one would end the "nothing leaves the
machine" property that the hygiene analysis rests on.

**The clipboard.** Once a secret is on the Wayland clipboard, every client that
can read the selection can read it. It is cleared after a configurable interval
(30 s by default) by terminating the `wl-copy --foreground` process that serves
it, which is the only reliable way to clear a Wayland selection. In the interval
it is exposed.

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
recipient, one hybrid recipient and an empty payload is 10,973 bytes on disk,
of which 4,112 are the padded-and-sealed payload.

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

`Header::mac_input()` produces the following byte string. All integers are
big-endian. Nothing in it is length-ambiguous except the `label`, which is
NUL-terminated (see the note below).

```
  u32   VAULT_VERSION                      (= 2)
  [16]  vault_id                           (raw UUID bytes)
  u64   epoch
  ...   created_at.to_rfc3339()            (UTF-8, variable length)
  u8    0x00                               (terminator for the timestamp)
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
                                                    │ DEK │  32 bytes, page-locked
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
2. `memlock::Lock::new(dek)` — page-lock the DEK. Failure is recorded in a
   process-wide counter and surfaced by `doctor`, never fatal.
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
[12.6](#12-non-claims).

---

## 6. Authenticated header and anti-rollback

### 6.1 What the MAC covers

`mac = HMAC-SHA256(DEK, "black-bag::v2::header-mac" || mac_input)`, where
`mac_input` is the canonical encoding in [§3.5](#35-the-canonical-mac-input).
Concretely, the MAC covers:

* the format version;
* the `vault_id`;
* the `epoch`;
* `created_at`;
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
[§9](#9-the-secret-flow-boundary).

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
  pruned. On this machine it currently holds 252 entries, most of them from
  ephemeral test vaults, because the test suite writes to the real state
  directory unless `BLACK_BAG_STATE_DIR` is set. That is untidy rather than
  dangerous — the entries carry a UUID, an integer, and a timestamp, and no
  record data — but a reviewer should know it happens.

---

## 7. Memory and process hardening

### 7.1 Ordering: hardening happens first

`fn main()` in `blackbag-cli/src/main.rs` calls `harden::harden_process()` as
its very first statement, before `Cli::parse()` and therefore before any
argument, environment variable, or file content has been read into the process.

### 7.2 Page locking, and the Drop ordering the predecessor got wrong

`memlock::Lock` is an owned `mlock` over a byte range. The entire point of the
type is a single field-level decision:

```rust
pub struct Lock { ptr: *const u8, len: usize }
```

It captures `(ptr, len)` **at lock time** and unlocks with the captured values,
never with whatever the buffer looks like at drop time.

`black-bagg` 0.4.10's `impl Drop for Sensitive` called `self.data.zeroize()` and
*then* `munlock(self.data.as_ptr(), self.data.len())`. `Zeroize for Vec<u8>`
calls `clear()`, so by that point `len()` was already zero and the unlock
returned without calling `munlock` at all. Every secret leaked its lock for the
life of the process. On this machine `ulimit -l` is 8192 KiB — 2048 pages — so a
long-lived process eventually exhausts the budget and further locks fail
unnoticed.

The correct ordering is used in both places that own secret memory:

* `record::Secret::drop` — `self.data.zeroize()` first, then
  `drop(self.lock.take())`. The comment records why this is safe:
  `Vec::zeroize` clears the length but does not free or move the allocation, so
  the captured pointer is still the right address.
* `generate::Scratch::drop` — same ordering, and the buffer is allocated at its
  final length and only indexed into, never pushed to, so it cannot reallocate
  and strand a plaintext copy at the old address.

`memlock::tests::lock_releases_even_after_buffer_is_cleared` performs exactly
the 0.4.10 sequence — clear the buffer, then drop the guard — and asserts the
guard still holds the length it captured. The test deliberately inspects the
guard's own field rather than the process-wide `locked_bytes()` counter, because
that counter is shared with every other test in the binary and cannot be
asserted on exactly under parallel execution.

Failures are counted, not swallowed: `FAILED_LOCKS` and `LOCKED_BYTES` are
process-wide atomics, `memlock::probe()` attempts a 32-byte lock on demand, and
`doctor` and the cockpit both display the result and the `RLIMIT_MEMLOCK`
ceiling.

**What is locked, and what is not.** This is the sharpest limit in this section
and it is stated in full in non-claim [12.8](#12-non-claims). The DEK is locked.
A `Secret` constructed in-process — by the generator, by a record draft arriving
over the agent socket — is locked. A `Secret` deserialised from the vault arrives with
`lock: None`, because the field carries `#[serde(skip)]` — so `open_payload`
runs an explicit re-lock pass over every record before returning. Without it
"secrets are page-locked" would have been true of the data key and false of
every record it protects, which is the same class of gap the audit found in
0.4.x. Covered by `vault::tests::secrets_loaded_from_disk_are_page_locked`,
which asserts on the loaded `Secret` itself rather than on the process-global
byte counter that parallel tests perturb.

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
only because of mlock". Given [§7.2](#72-page-locking-and-the-drop-ordering-the-predecessor-got-wrong),
that sentence should be read as applying to the DEK, not to loaded records.

### 7.4 `panic = "unwind"`, and why abort was wrong here

The release profile in the workspace `Cargo.toml` sets `panic = "unwind"`,
against the usual instinct to prefer `abort` for smaller binaries and no
unwinding machinery.

`black-bagg` 0.4.x used `panic = "abort"`. That converts any panic into
`SIGABRT` with no unwinding, which means **no destructor runs** — no `Zeroizing`
drop, no `Secret::drop`, no `memlock::Lock` release. Combined with core dumps
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
expiry is re-evaluated on every tick of that loop, so a walked-away desk expires
within about a tenth of a second of the deadline rather than at the next
connection.

### 8.3 Idle expiry

`DEFAULT_IDLE_SECS` is 900 (fifteen minutes), floored at 30 seconds by
`Agent::new`. `expire_if_idle` drops the whole `OpenVault` — and with it the
`Vault`, its `Zeroizing` DEK, and its `memlock::Lock` — then republishes status.

A design point worth naming: `Request::Status` does **not** extend the deadline.
The bar widget and cockpit poll status continuously; if polling counted as
activity the session would never expire while the shell was running. Only
operations that go through `Agent::opened()` — list, detail, reveal, TOTP, add,
update, delete, hygiene — and the explicit `Touch` request push the deadline
out.

### 8.4 Secrets leave one at a time, by explicit request

There is no "dump the vault" call, because a cockpit never needs one.

| Request | Returns |
|---|---|
| `Status` | Lock state, expiry, record count, per-kind counts, rollback flag |
| `List` / `Detail` | `RecordView` — id, kind, title, tags, attributes, and per-field *handles*; never secret bytes |
| `Reveal { id, field }` | **One** secret field's value. The only request that returns secret bytes. |
| `TotpCode { id }` | A derived six-to-eight digit code and its remaining validity |
| `Add` / `Update` | Secrets travel *inbound* here, inside the request |
| `Hygiene` | Handles and titles across the whole vault — as sensitive as the open vault |
| `Lock` / `Touch` / `Shutdown` | No record data |

`session::tests::record_view_carries_handles_not_secrets` serialises a
`RecordView` built from a record with a distinctive password and asserts the
JSON does not contain it.

There is deliberately no `--password` or `--passphrase` flag anywhere in the
CLI. Passphrases are read from `/dev/tty` when there is one and from stdin when
there is not; record drafts arrive as JSON on stdin. `/proc/<pid>/cmdline` is
world-readable, so an argv secret is a published secret.

### 8.5 Honest notes on the agent

* **The request line is unbounded.** `BufReader::read_line` reads until a
  newline with no size cap, so a same-uid peer can make the agent allocate
  arbitrarily. Same-uid is inside the trust boundary by construction
  ([§2.2](#22-what-is-explicitly-out-of-scope)), so this is a robustness gap
  rather than a boundary crossing — but it is a gap.
* **The agent's copy of a revealed secret is not zeroized.**
  `Response::Secret { value: String }` is built from `Secret::expose_str()`,
  which clones the bytes into a fresh `String`. That `String` is serialised to
  the socket and dropped without wiping. The CLI *client* wraps its copy in
  `Zeroizing`; the agent does not. A revealed secret therefore leaves a
  plaintext residue on the agent's heap.
* **The agent under-reports its own hardening.** `Agent::publish` calls
  `HostPosture::measure().with_harden(report)`, using the report the agent was
  started with, so `status.json` describes the agent process rather than an
  unmeasured default. An earlier revision omitted `.with_harden`, which made the
  agent publish `core_dumps_disabled=false` and raise a spurious `CORE_DUMPS`
  finding against a process that had in fact disabled them.
  warning. `black-bag status --publish` writes the same file with the correct
  values, so the finding appears and disappears depending on which process
  published last. Verified by running an agent against a scratch vault and
  reading both versions of the file.
* **The socket path is subject to `SUN_LEN`.** A sufficiently long
  `XDG_RUNTIME_DIR` makes the agent fail to bind with `path must be shorter than
  SUN_LEN`. It reports the error and exits rather than falling back.
* **Advisory locking is not implemented.** `vault::open_lock` opens (and
  creates) `<vault>.lock` and returns the handle; it never calls `flock` or
  `fcntl`, and `fd-lock` is declared as a dependency but used nowhere in the
  workspace. The doc comment on the function says "advisory lock so two
  processes do not interleave writes", and the CLI binds its result to `_lock`
  before every mutating command, but the file excludes nothing. Writes are
  atomic — `NamedTempFile` plus `rename` — so a concurrent CLI write and agent
  write cannot corrupt the vault; they produce a lost update, with the last
  writer winning. See non-claim [12.9](#12-non-claims).

### 8.6 The systemd unit

`install.sh` writes `~/.config/systemd/user/black-bag-agent.service`, not
enabled by default because starting an agent is the user's decision. It carries
`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict` with an explicit
`ReadWritePaths` list, `ProtectHome=read-only`, `ProtectKernelTunables`,
`ProtectKernelModules`, `ProtectControlGroups`, `RestrictNamespaces`,
`RestrictRealtime`, `LockPersonality`, `MemoryDenyWriteExecute`,
`SystemCallArchitectures=native`, and `LimitCORE=0`.

---

## 9. The secret-flow boundary

Every surface, and whether it can hold a secret.

| Surface | Location | Holds a secret? |
|---|---|---|
| Vault file | `~/.local/share/black-bag/vault.cbor`, mode 0600 | Yes, encrypted. Never in plaintext. |
| `status.json` | `$XDG_RUNTIME_DIR/black-bag/status.json`, mode 0600 in a 0700 directory | **Never.** No titles, tags, attributes, counts, or values — only posture, KDF parameters, recipient labels and kinds, epoch, and lock state. |
| Bar widget (`Panel.qml`) | Omarchy shell process | Never. Reads `status.json` and shells out to `black-bag status --publish` to refresh it. It never contacts the agent. |
| Cockpit (`Cockpit.qml`) | Omarchy shell process | Metadata always, while unlocked. A secret **only** during an explicit `SHOW`, held in a QML property behind a visible countdown, then cleared. `COPY` goes to the clipboard via the CLI and never enters the QML process. |
| Editor (`Editor.qml`) | Omarchy shell process | Yes, while you are typing. The draft is passed to `black-bag agent add`/`edit` on stdin. An empty secret box means "keep what is stored", so editing a record never loads its existing secret into the form. |
| Agent | `black-bag agent serve` process | The DEK, page-locked. The decrypted records, **not** page-locked (see [§7.2](#72-page-locking-and-the-drop-ordering-the-predecessor-got-wrong)). One revealed value per `Reveal`, and a non-zeroized residue of it. |
| Agent socket | `$XDG_RUNTIME_DIR/black-bag/agent.sock`, mode 0600 in a 0700 directory, `SO_PEERCRED` checked | Yes, in transit — inbound passphrases and drafts, outbound revealed fields. |
| Clipboard | Wayland selection, served by `wl-copy --foreground` | Yes, for the configured interval (30 s default), then the serving process is killed. |
| Terminal | `/dev/tty`, the default sink | Yes, when you ask. Cannot be redirected by the shell, which is the point. |
| stdout | Only via `--to stdout`, `black-bag agent show`, or `black-bag gen` | Yes, when you ask for it explicitly. `gen` writes the value to stdout and the strength line to stderr, so a pipe captures the secret alone — and a redirect writes a password to a file, which is what a generator is for and worth knowing. |
| Witness file | `~/.local/state/black-bag/witness.json` | Never. `vault_id`, epoch, timestamp. |
| Lock file | `<vault>.lock`, mode 0644, empty | Never. Zero bytes, and see [§8.5](#85-honest-notes-on-the-agent). |
| Recovery key file | Wherever `recovery add --out` put it, mode 0600 | **Yes — this file opens the vault without the passphrase.** Refuses to overwrite an existing file. |
| Process argv | — | Never. There is no flag anywhere in the CLI that takes a secret. |
| `Debug` output | Panics, logs, `unwrap_err()` | Never. `Secret`'s `Debug` prints `Secret(N bytes, redacted)`; `Vault`'s is hand-written specifically so a derived one cannot forward through `Zeroizing<[u8; 32]>` and print the live DEK in a panic message. Both are tested. |
| Search index | — | Never. `Record::matches` covers titles, tags, kind, and attribute keys and values. A search that reached into a password would leak it through timing and through the result set itself; there is a test asserting it does not. |

### 9.1 The test that pins `status.json`

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

## 10. Generation and entropy accounting

### 10.1 The rule

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

### 10.2 Uniform selection

`uniform_below(rng, n)` masks to the next power of two and redraws on overshoot.
`next_u32() % n` — the obvious implementation — gives the low residues one extra
chance for any `n` that is not a power of two, skewing output toward the front
of the charset. Acceptance probability exceeds one half for every `n`, so the
loop is expected to run fewer than twice; `MAX_DRAWS = 256` converts an RNG
malfunction into an error rather than a hang.

### 10.3 The inclusion–exclusion correction

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

### 10.4 The real default figures

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

## 11. Credential hygiene

`black-bag agent hygiene` analyses the whole vault locally. There is no network
call in `hygiene.rs` and there must never be one: "nothing leaves the machine"
is a property users are invited to rely on, and one lookup would end it. The
analysis reads secret bytes to *measure* them — length, whether every byte is an
ASCII digit — and emits only those measurements.

### 11.1 Handle construction

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

### 11.2 What a collision means, and every stated limit

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

### 11.3 Thresholds, and the one that is derived

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

### 11.4 The figure

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

## 12. Non-claims

A numbered list of things this system does **not** prove. This section is the
point of the document.

**12.1 — No formal verification.** This is ordinary Rust with a test suite. It is
not SPARK, there are no proof obligations, and nothing about it has been
mechanically checked. The audit that motivated the rebuild
([`docs/AUDIT.md`](AUDIT.md)) is a careful read plus an adversarial second
opinion, and it should be treated as exactly that. There has been no third-party
security review, and no document in this repository asserts one — which is
itself a response to finding 9 of that audit.

**12.2 — No protection against a compromised host.** If an attacker runs code as
your user, they can read the agent's memory, connect to its socket (the
`SO_PEERCRED` check passes, because they are you), replace the binary, or wait
for you to type the passphrase. Every mechanism in this document assumes the
host is not already lost. None of them recovers if it is.

**12.3 — The witness is local and unauthenticated.** It is a JSON file in your
own state directory. An attacker who can rewrite the vault can usually rewrite
the witness. It reliably catches restored backups, sync conflicts and snapshot
rollbacks; it does not constitute an authenticated anti-rollback mechanism, and
it warns rather than blocks.

**12.4 — The MAC binds the file, not the world around it.** The header, the
payload ciphertext and `updated_at` are all covered. An earlier revision left
the payload and `updated_at` out, which permitted a silent rollback by splicing
an old payload onto a current header — see
[§6.2](#62-what-the-mac-does-not-cover). What remains uncovered is everything
outside the vault file: the witness, the status document and any recovery key
file are separate artefacts, and are only as trustworthy as the filesystem they
sit on.

**12.5 — Handles are 32 bits.** A shared handle means the two secrets *share a
handle*. It is not proof they are the same value, and the absence of a cluster
is not proof of no reuse — see [§11.2](#112-what-a-collision-means-and-every-stated-limit).

**12.6 — The hybrid combiner is not a standardised construction.** It is the
conventional concatenate-shared-secrets-and-ciphertexts-then-KDF pattern with
BLAKE3 in derive-key mode. It is not X-Wing, not the hybrid KEM of RFC 9370, and
it carries no security proof and no external review. The claim made for it is the
ordinary hybrid argument — secure if either primitive holds — and nothing
stronger. Relatedly, ML-KEM-1024 has been standardised for a short time and its
implementations are young; `ml-kem 0.3.2` is a stable release, which is more
than the predecessor's pre-release dependencies could say, but it is not
battle-tested code.

**12.7 — A recovery recipient is a second door, not a stronger lock.** The
at-rest strength of the file is the weaker of its lanes and the attacker
chooses. Adding a recovery recipient cannot make the vault harder to open. If
you keep the key file next to the vault, you have simply removed the passphrase
from the equation.

**12.8 — `mlock` is best-effort.** Page locking can fail: `RLIMIT_MEMLOCK` on
this machine is 8192 KiB (2048 pages), failures are counted and reported by
`doctor` rather than treated as fatal, and a locked page can still reach a
hibernation image or be captured by a hypervisor regardless. Records read back
from the vault *are* locked — `Secret`'s guard is `#[serde(skip)]`, so
`open_payload` re-locks every record explicitly — but that pass is best-effort
for the same reason and its failure is silent to the caller. Secrets are
zeroized on drop either way.

**12.9 — Concurrency is detected, not merged.** `vault::open_lock` takes a real
`flock(LOCK_EX)` for a critical section, `Vault::save` refuses to write over a
version the handle has not seen, and the agent calls `Vault::refresh` before
serving any request — so a CLI write and a cockpit write no longer silently
discard one another. What the system does *not* do is merge divergent record
sets: it detects the conflict and re-reads. Because every mutation is saved
immediately, there is never unsaved work to lose by re-reading, but a design
that batched edits in memory could not rely on that.

**12.10 — Padding hides size only to block granularity.** The payload is padded
to 4096 bytes. A vault with a thousand records is visibly larger than one with
three. What padding buys is that a small addition does not change the file size
at all — which is what `vault::tests::payload_is_padded_so_size_does_not_track_content`
pins — not that size carries no information.

**12.11 — Nothing here says anything about the account behind a credential.**
No breach checking, no revocation checking, no reachability checking. The
hygiene report describes what is in the vault, and only that.

**12.12 — Entropy figures describe the generator, never a typed value.** They
are exact for values this project generated and are meaningless applied to
anything else. The `StrengthLabel` buckets are a stated convention, not a
prediction about cracking time.

**12.13 — Deletion is not secure erasure.** `black-bag remove` and `agent
delete` rewrite the vault without the record. The old ciphertext may persist in
the filesystem's free space, in a snapshot, in a backup, or in the flash
translation layer of the underlying device. Nothing here overwrites it.

**12.14 — There is no duress mode, no decoy vault, and no defence against
coercion.** A rubber hose beats this design, as it beats every design of this
shape.

**12.15 — The dependency tree is trusted.** `argon2`, `chacha20poly1305`,
`blake3`, `hmac`, `sha2`, `subtle`, `zeroize`, `ml-kem`, `x25519-dalek`,
`ciborium`, `totp-rs` and the rest are taken on faith, along with everything
they pull in. No vendoring, no reproducible-build attestation, no supply-chain
verification beyond `Cargo.lock`.

**12.16 — The Omarchy surfaces run inside the shell process.** The cockpit and
editor are QML in `omarchy-shell`, sharing an address space with every other
plugin loaded there. A secret shown with `SHOW`, and every keystroke typed into
the editor, lives in that process's memory with no page locking and no
scrubbing. The CLI path is the more defensible one; the cockpit is a
convenience, and the trade is real.

**12.17 — Tracer detection is a snapshot.** Taken once at process start.
`PR_SET_DUMPABLE 0` blocks a subsequent same-uid attach, but root and
`CAP_SYS_PTRACE` are unaffected, and there is no ongoing monitor.

**12.18 — The agent's `status.json` misreports its own hardening.** Documented
in [§8.5](#85-honest-notes-on-the-agent). It reads as a defect in the reporting
layer, not the hardening layer, but a reader trusting `status.json` would draw
the wrong conclusion about a running agent.

**12.19 — `black-bagg` on crates.io is unchanged.** This repository does not and
cannot alter what is already published there, including the API token in
releases 0.4.6 through 0.4.10 (audit finding 1) and the fabricated Trail of Bits
review shipped in 0.3.5 (audit finding 9). Both require the maintainer's hands.

---

## 13. Comparison with `black-bagg` 0.4.10

Line references are to `black-bagg-0.4.10/src/lib.rs` as published; the full
derivation is in [`docs/AUDIT.md`](AUDIT.md).

| Property | `black-bagg` 0.4.10 | Black-Bag v2 | Why it changed |
|---|---|---|---|
| ML-KEM lane | Encapsulated to its own public key; decapsulation key sealed under the passphrase KEK in the same header (:930–933, :947, :877) | `Recipient::Hybrid` — X25519 + ML-KEM-1024, private half written to a separate 0600 file and never stored in the vault | A KEM whose every input travels with the file contributes zero bits. The external private key is the whole property. |
| Rotation | `rotate` re-wrapped **the same** DEK; could not change the passphrase; did not re-salt without `--mem-kib` (:1092–1116, :1780–1787) | `Vault::rekey` mints a fresh DEK, re-encrypts the payload, re-wraps every recipient, re-salts, and can change the passphrase | A DEK exposed once otherwise stays valid for every future version of the file. |
| Header authentication | None. Epoch-free, MAC-free header fields open to silent edit | HMAC-SHA256 over a canonical header encoding, keyed by the DEK, checked before the payload is opened | Argon2 downgrade, recipient injection and epoch tampering were all silent. |
| Integrity sidecar | `backup verify` keyed a BLAKE3 MAC with `blake3::hash(kem_public)` — a public header field inside the tagged bytes (:2051) | Dropped entirely | It was a checksum with per-vault domain separation, and printed `Integrity verified` for a tampered vault. |
| Anti-rollback | None (0.2.x had an epoch and a `.epoch` sidecar; 0.4.x dropped both) | Monotonic epoch in the MAC'd header, plus an out-of-band witness keyed by `vault_id` | A restored backup was undetectable. |
| `mlock` release | `Drop` zeroized the `Vec` then called `munlock` with the now-zero length, so the unlock silently no-opped (:834–842) | `memlock::Lock` captures `(ptr, len)` at lock time; `Drop` zeroizes first, then releases the captured range | With `ulimit -l` at 2048 pages, a long session exhausts the budget and later locks fail unnoticed. There is a regression test that clears the buffer first. |
| Secrets loaded from the vault | Constructed by `Deserialize` without ever being locked (:1220) | Re-locked explicitly by `open_payload` after decode | Fixed. `#[serde(skip)]` still drops the guard, so the pass is deliberate and tested. |
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
| Tests | `#[cfg(test)]` imported `proptest` and `serial_test` with **no `[dev-dependencies]` section at all**; `cargo test --no-run` exited 101 | `[dev-dependencies]` declared; 120 tests across the workspace pass, plus 117 cockpit assertions | Nobody downstream could run the test suite of a password manager from the published artefact. |
| Documented commands | README documented four commands that do not exist and a `--ram-drive` flag that was never implemented | README and `--help` are generated from the same source | It is the first thing a new user hits. |
| Platform | macOS-oriented (`hdiutil`, `diskutil`, `/Volumes/…`) | Linux only, Omarchy-targeted | The RAM-disk story never worked on Linux; page locking replaces it. |
| Third-party review | A 1,090-line document naming Trail of Bits as the acting party eleven times, shipped in 0.3.5 | None claimed | `docs/AUDIT.md` is signed as what it is: the author's own review. |

---

## Appendix A — verifying the claims in this document

```bash
cd ~/Projects/blackbag

# The whole suite, without polluting your real witness file.
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
