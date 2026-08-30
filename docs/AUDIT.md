# Audit — `black-bagg` on crates.io

Every finding below was read out of the published tarballs, not inferred. Each
was then put to an independent reviewer whose instructions were to *refute* it;
the wording here is what survived that. Line numbers refer to
`black-bagg-0.4.10/src/lib.rs` unless stated otherwise.

Versions examined: all 26 published releases, `0.1.0` through `0.4.10`.

---

## 1. A crates.io API token is published in five releases

`PUBLISH_INSTRUCTIONS.md` was packaged into the crate tarball and contains a
live-format crates.io API token on its `cargo login` line.

Affected: **0.4.6, 0.4.7, 0.4.8, 0.4.9, 0.4.10**. Confirmed by downloading every
published version and scanning each one. The earlier `0.1.x`–`0.3.x` releases are
clean.

crates.io releases are immutable. They cannot be edited or withdrawn, and
yanking does not remove the files, so the tarballs remain fetchable by anyone.

> **The token value and the steps to extract it are deliberately withheld from
> this public document** until the maintainer confirms revocation. The full
> unredacted finding is retained privately. Publishing a signpost to a
> credential that may still be valid would make this document part of the
> problem it describes.

If you maintain this crate: revoke every token at
<https://crates.io/settings/tokens> and review
<https://crates.io/settings/profile> for publishes you did not make.

Severity: **critical**, and unrelated to the quality of the code.

---

## 2. The post-quantum lane does nothing for the vault

This is the finding I most wanted to be wrong, so it went to three reviewers
independently, one of them briefed to steelman the design. None could refute it.

`Vault::init` generates an ML-KEM-1024 keypair and encapsulates **to its own
public key** (:930–933). The decapsulation key is then sealed under the
passphrase-derived KEK and stored in the same header (:947, :877); the KEM
ciphertext sits beside it in the clear (:876). `Vault::load` (:991–1010)
therefore walks:

```
passphrase → KEK → dk → shared secret → DEK → payload
```

Every input the KEM needs travels inside the file, unlocked by the KEK or stored
in plaintext. `grep -i recipient src/lib.rs` returns nothing — there is no
external party, so nothing is being encapsulated *to* anyone.

Consequences, stated precisely:

- Vault-at-rest confidentiality is exactly **Argon2id + XChaCha20-Poly1305**,
  with or without the KEM. This is not a weakness — 256-bit XChaCha is a
  conservative post-quantum symmetric choice — but ML-KEM contributes no bits.
- An offline attacker never executes the KEM at all. The Poly1305 tag on
  `sealed_decapsulation` is a direct passphrase oracle, so the cost per guess is
  one Argon2id evaluation either way.
- The lane is not free: ~6.3 KB of header per vault, two extra decrypt steps in
  the unlock path, and two pre-release crates (`ml-kem 0.3.0-pre`,
  `kem 0.3.0-pre.0`) on the mandatory build path.
- README.md:159 calls the KEM "optional via `pq`", but :29–30 import it
  unconditionally and `cargo check --no-default-features --features mlock`
  fails. The feature gate does not work.
- README.md:127, :178 and :204 describe "ML-KEM recipients" as a shipped
  capability. No such code or CLI flag exists.

Your own README documents the *correct* construction — step 2 of "Key Hierarchy
and Data Flow" says "KEK wraps the DEK". The code does something else.

Untouched by this finding: the **ML-DSA-87 detached-signature lane** (:2037,
:2217) is a real post-quantum authenticity mechanism and works as described.

Severity: **medium** — a misrepresented security property and dead weight in the
critical path, not a decryptable vault.

---

## 3. `rotate` does not rotate

Surfaced by a reviewer while checking finding 2, and the most consequential
item after the token.

`Vault::rotate` (:1092–1116) regenerates the KEM keypair and re-wraps
**the same DEK** (:1107). Without `--mem-kib` it does not even re-roll the
Argon2 salt (:1093–1099). `rotate_vault` (:1780–1787) reuses the one prompted
passphrase for both unlock and re-seal, so it cannot change the passphrase
either.

A DEK exposed once — a core dump, a memory scrape, a stolen unlocked session —
grants plaintext access to every future version of the vault, and no command in
0.4.10 revokes it. The subcommand help promises "Rewrap the master key with
fresh randomness", which is literally true and materially misleading.

Severity: **medium-high**.

---

## 4. `backup verify` reports integrity it cannot check

`compute_public_integrity_tag` (:2051) keys a BLAKE3 MAC with
`blake3::hash(kem_public)` — but `kem_public` is an unencrypted header field
(:875, :959) inside the very bytes being tagged. The tag is a deterministic
public function of the file: a checksum with per-vault domain separation, not a
MAC. Anyone who can modify the vault can recompute a matching `.int`.

So `black-bag backup verify --path X` without `--pub-key` prints
`Integrity verified` for a tampered vault (:1997–1998). It detects accidental
corruption; it cannot detect tampering, and the message does not say so.

Two aggravations found during verification:

- `backup_sign` matches `Err(_)` (:2009), so it silently regenerates the sidecar
  whenever the existing one is missing, empty, malformed, *or* the wrong length.
- The sidecar is written at :2011 **before** `read_key_bytes` at :2016, so a
  `backup sign` that fails still leaves a freshly minted, tamper-passing `.int`
  behind. The reviewer forged one this way with a garbage key file: exit code 1,
  error printed, sidecar created.
- If a well-formed `.int` exists that does not match the file, `backup_sign`
  takes the `Ok(tag)` branch and signs the stale tag, producing a signature that
  can never verify, with no warning.

Severity: **medium**.

---

## 5. The published crate cannot be tested

`#[cfg(test)] mod tests` (:2421) imports `proptest` (:2424–2426) and
`serial_test` (:2427), but the published `Cargo.toml` has **no
`[dev-dependencies]` section at all**. `Cargo.toml.orig` is byte-identical, so
this is in the source manifest, not a packaging artefact.

`cargo test --no-run` on the unpacked crate exits 101 with three errors
(E0433/E0432 on `proptest`, E0432 on `serial_test`). `cargo build` is
unaffected, so users are fine — but nobody downstream, and no auditor, can run
the test suite of a password manager from the published artefact.

The same build emits four `unexpected_cfgs` warnings: `feature = "fuzzing"`
(:2364, :2369) and `feature = "fhe"` (:1969, :1972) are never declared, so
`cargo build --features fuzzing` is rejected outright and the two `fuzz_*` entry
points cannot be compiled by anyone.

Severity: **medium** (verification, not exploitation).

---

## 6. The `mlock` on every secret is never released

`impl Drop for Sensitive` (:834–842) calls `self.data.zeroize()` and *then*
`memlock::unlock_region(self.data.as_ptr(), self.data.len())`. `Zeroize for
Vec<T>` calls `clear()`, so `len()` is already 0 and `unlock_region` returns at
:58 without calling `munlock`. The lock persists until the process exits.

Stated honestly, and smaller than it first looks: this is a hardening defect,
not memory unsafety. `clear()` does not deallocate, so the pointer stays valid.
mlock is page-granular and not refcounted, so 20,000 sequential small secrets
leak one 4 KiB page, not 20,000. Against a short-lived CLI it is unlikely to
exhaust `RLIMIT_MEMLOCK`. Note also that `Sensitive` derives `Clone` and
`Deserialize`, and everything loaded from the vault via `decrypt_payload`
(:1220) is constructed *without* ever being locked — so most secrets in a
running process were never mlocked in the first place.

Severity: **low**.

---

## 7. The README documents commands that do not exist

Each of these fails with a clap error and exit code 2 against the crate's own
binary:

| README | Reality |
|---|---|
| `black-bag init --ram-drive` (:58) | `InitCommand` (:169–174) has only `--mem-kib`. `BLACK_BAG_RAM_SIZE` appears nowhere in the source. |
| `black-bag backup split … --out ./shares/` (:284) | `backup` has only verify/sign/keygen (:255–264). The real command is `recovery split`, which has no `--out` and prints shares to stdout (:1850–1858). |
| `black-bag backup combine --in … --out …` (:286) | The real command is `recovery combine --threshold N --shares …` (:1861). |
| `black-bag totp code --id <UUID>` (:279) | `id` is positional (:249). |

Also: "Added: Built-in RAM drive support" in the 0.4.5 notes describes a feature
that is not in the binary, and `black-bag-setup` on Linux only prints a `mount`
command for you to run yourself — every other path in it is macOS-only
(`hdiutil`, `diskutil`, `/Volumes/...`).

Severity: **low**, but it is the first thing a new user hits.

---

## 8. 0.4.x is a security regression from 0.2.x

This is the finding that reframes the rest. The 0.2.x line was substantially
more hardened than what is currently the default version. File counts tell the
story: **0.2.10 shipped 35 files, 0.3.5 shipped 18, 0.4.10 ships 9.**

Dropped between 0.2.10 and 0.4.10, all verified present in the older tarball:

| Protection | 0.2.10 | 0.4.10 |
|---|---|---|
| Header MAC over epoch + KDF params | `compute_header_mac`, lib.rs:1608 | gone |
| Anti-rollback epoch + `.epoch` sidecar | lib.rs:1178, :1377–1398 | gone |
| `setrlimit(RLIMIT_CORE, 0)` | lib.rs:116 | gone |
| `prctl(PR_SET_DUMPABLE, 0)` | lib.rs:120 | gone |
| Tracer detection | lib.rs:126 | gone |
| Pre/post-parse size caps | lib.rs:59–66 | gone |
| Payload padding (`BLACK_BAG_PAD_BLOCK`) | lib.rs:1681–1723 | gone |
| Secrets written to `/dev/tty` | `output.rs` | `println!` to stdout |
| Argon2 defaults | time=10, lanes≥4 (auto) | **time=3, lanes=1** |
| Duress mode, emit modes, policy modes | `config.rs` | gone |
| `LICENSE-MIT` / `LICENSE-APACHE` | present | absent despite `license = "MIT OR Apache-2.0"` |
| `tests/cli_smoke.rs`, `docs/` | present | gone |

Two of these matter concretely **on this machine**, measured today:

- `/proc/sys/kernel/core_pattern` pipes to `systemd-coredump`, the socket is
  active, and `ulimit -c` is `unlimited`. Combined with `panic = "abort"` in
  0.4.10's release profile — which turns any panic into SIGABRT with no
  unwinding, so `Zeroizing` destructors never run — a crash while the vault is
  open writes the DEK and decrypted records to `/var/lib/systemd/coredump`.
- zram swap is active (23.4 GiB, 7.4 GiB in use). The README's "no swap"
  premise does not hold here, so mlock is load-bearing — and per finding 6 it is
  also leaking.

`ulimit -l` on this box is 8192 KiB, which JACKAL confirms is
`8192*1024/4096 = 2048` pages (status: `exact`).

---

## 9. A fabricated security review is published under a real firm's name

`black-bagg-0.3.5` — and only that release — ships
`Trail_of_Bits_Security_Review_Black-Bag_2025-09-30.md` (1,090 lines). The
header says "Prepared by: Trail of Bits-Style Security Review", but the body
names Trail of Bits as the acting party eleven times ("conducted" ×3,
"performed", "identified", "evaluated", "analyzed", "employed", "assessed",
"rates", "recommends"), asserting the engagement as fact:

> "Trail of Bits conducted a security assessment of **black-bagg** … This
> engagement, which spanned from September 23 to September 30, 2025 …"
> "The assessment **did not uncover any security vulnerabilities of High or
> Medium severity**."

Trail of Bits is a real company. A document published on crates.io under their
name, asserting an engagement and a clean result, is a false attribution
regardless of the qualifier in the header — and the "0 High, 0 Medium" verdict
is contradicted by findings 2, 3, and 4 above, which are all in code that
document claims to have reviewed.

I am not raising this as a style note. Publishing it exposes you to a trademark
and false-advertising complaint, and it undermines every genuine security claim
the project makes. The underlying document is decent self-assessment work —
it should say so in its own name.

Recommendation: rename it (`SELF_ASSESSMENT.md`), strip every sentence that
asserts a third party performed it, and never republish 0.3.5's text as-is.

---

## What this rebuild does about it

| Finding | Response in this repo |
|---|---|
| 1 · token | Yours to revoke. Nothing here can undo it. |
| 2 · fake PQ | Recipients are real: an ML-KEM-1024 + X25519 hybrid whose private key is written to a recovery file and **never stored in the vault**. See `vault.rs::wrap_hybrid`. |
| 3 · rotate | `Vault::rekey` mints a new DEK, re-encrypts the payload, re-wraps every recipient, and can change the passphrase. |
| 4 · integrity | Dropped entirely. The header MAC is keyed by the DEK, which only a real recipient can recover, so it authenticates rather than checksums. |
| 5 · tests | `[dev-dependencies]` declared; the suite runs. |
| 6 · mlock | `memlock::Lock` captures `(ptr, len)` at lock time and unlocks with the captured values. There is a regression test that zeroizes the buffer *first*. |
| 7 · docs | The README documents only commands that exist; `--help` is generated from the same source. |
| 8 · regression | Header MAC, epoch + witness, `RLIMIT_CORE`/`PR_SET_DUMPABLE`, size caps, payload padding, `/dev/tty` output, and Argon2 time=10/lanes≥4 are all restored. `panic = "unwind"` so destructors run. |
| 9 · fake audit | Not carried over. This file is signed as what it is: my own review. |

Nothing here is a formal verification. It is a careful read plus an adversarial
second opinion, and it should be treated as exactly that.

---

## Appendix: why the sealed screen shows so little

The first cut of the locked state was the full deck with a passphrase box
dropped into the hole — four cards on the left, two on the right, five header
chips, and an empty box reading "record counts are only known while unlocked".
The owner's verdict was "does it have to have all that info and boxes around
it". It did not. Three things decided the rebuild:

**Silence has to be reachable.** A design premised on "quiet unless something is
wrong" only works if quiet is achievable. On this machine zram swap is
permanently active, so a screen that surfaces every finding is never quiet, and
a screen that always shouts teaches you to stop reading it. Notes therefore do
not appear on the sealed screen at all — only conditions that should stop your
fingers. `Model.unlockVerdict` is where that line is drawn.

**Staleness must modify, never mask.** `deckState()` checks staleness first and
returns UNKNOWN, which is right for a status chip and wrong for a hazard: a
stale *and* rolled-back vault rendered grey. A stale all-clear is worthless; a
stale alarm still alarms. `unlockVerdict` is deliberately not built on
`deckState`, and there are tests for exactly this.

**A planted vault picks its own id.** The fingerprint under the field says which
vault this *claims* to be; the witness word says whether this machine agrees.
Only the second is a fact a forger cannot choose, so the screen states the
comparison ("epoch 9 witnessed" / "unwitnessed" / "ROLLED BACK") rather than
printing two epoch numbers and hoping someone compares them.

Two consequences worth stating plainly:

- **A rollback warns but never blocks.** Restoring a legitimate backup must not
  lock the owner out of his own vault, so the verb becomes "unlock anyway".
- **An attached debugger blocks completely**, and no "proceed anyway" is
  offered. A live ptracer reads the passphrase keystroke by keystroke, so the
  harm is finished before Enter is pressed; an override would only launder a
  refusal into a speed bump.

---

## Appendix: a settings schema that did nothing

Worth recording because it is the same class of defect as finding 7 — a
surface advertising something it does not do.

`manifest.json` declares five settings with a full schema. The cockpit read
none of them; every value was hardcoded. The settings panel wrote the user's
choice into `shell.json` correctly, so it looked like it worked, while the deck
kept using its own constants.

Three separate reasons, each of which fails silently:

1. Omarchy injects `settings` into **bar widgets only**. An overlay declaring
   `property var settings` never has it filled (`shell.qml:216-221`, `:629-637`).
2. `shell.serviceFor(pluginId)` does not reach the plugin's own service from
   its overlay — an on-screen probe showed `service === null` despite the
   manifest declaring a service kind.
3. `shell.listShellConfig()` is not callable from QML: it lives on an
   `IpcHandler` (`shell.qml:994`), so a `typeof … === "function"` guard is false
   and the call is skipped without error.

Fixed by resolving the settings from `shell.shellConfig` — a plain root
property — in `Model.resolvePluginSettings()`, a pure function both the cockpit
and the service call, with tests. Verified end to end by setting
`revealSeconds: 4` through `omarchy-shell shell setBarWidget` and watching the
on-screen reveal countdown change from 10 to 4.
