# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] — 2026-08-30

### Fixed (concurrency)

- **A long-lived agent could silently discard a CLI write.** The agent held its
  own unlocked copy while `black-bag add` wrote the file directly; the agent's
  next save incremented from its stale epoch and overwrote the other record.
  Both ended at the same epoch, so the rollback witness saw nothing wrong — it
  was silent credential loss. `Vault::save` now refuses to write over a version
  the handle has not seen, and the agent re-reads before serving any request, so
  a record added in a terminal shows up in the deck without a restart. If
  another process re-keys the vault the agent's session drops rather than
  holding a key that no longer opens it.

[2.0.1]: https://github.com/AnubisQuantumCipher/blackbag/releases/tag/v2.0.1

## [2.0.0] — 2026-08-30

First release of the rebuilt engine and the Omarchy surfaces. This is a
different program from the `black-bagg` crate it descends from; the vault format
is new and is read as v2. See [`docs/AUDIT.md`](docs/AUDIT.md) for why.

### Added

- **Hybrid post-quantum recovery recipients.** X25519 + ML-KEM-1024, combined
  through a domain-separated BLAKE3 KDF. The private half is written to a key
  file and is verifiably absent from the vault, so a recovery key opens the
  vault without the passphrase and can be revoked.
- **Authenticated header.** HMAC-SHA256 over a canonical encoding of the epoch,
  the Argon2 parameters and every recipient descriptor, keyed from the data key
  so any unlock path can verify it.
- **Anti-rollback epoch** with an out-of-band witness. A restored older vault is
  noticed. Stated as a tripwire, not a guarantee.
- **A full-screen cockpit** (`SUPER+SHIFT+K`): sealed screen, record browser,
  inspector, live TOTP with a countdown arc, host posture, and findings.
- **Record authoring from the plugin.** Twelve kinds with per-kind field
  templates, create/edit/delete, and `otpauth://` enrolment.
- **Password generation with honest entropy accounting.** The reported figure
  includes an inclusion-exclusion correction for the class-presence
  requirement. There is deliberately no function that scores a typed string.
- **Local credential hygiene.** Reuse detection via non-reversible per-field
  handles, so two records can be shown to share a password without any secret
  being compared or displayed. No network call is involved.
- **Migration** from the v1 (`black-bagg` 0.4.x) format.
- **Payload padding**, so the file size stops leaking how much is stored.
- A hardened systemd user unit for the unlock agent.

### Changed

- **Rekeying actually rekeys.** `black-bag rekey` mints a new data key,
  re-encrypts the payload, re-wraps every recipient, and can change the
  passphrase. The predecessor's `rotate` re-wrapped the same data key and could
  not change the passphrase at all.
- **Argon2id restored to time = 10, lanes ≥ 4** (scaled to the host, capped at
  8). The 0.4.x line had reduced these to time = 3, lanes = 1.
- **Secrets are written to `/dev/tty`**, not to stdout, so a shell redirect
  cannot capture them by accident.
- **`panic = "unwind"`.** The predecessor used `panic = "abort"`, which turns any
  panic into SIGABRT without unwinding, so `Zeroizing` destructors never ran.
- Moved from pre-release `ml-kem 0.3.0-pre` / `kem 0.3.0-pre.0` to the stable
  `ml-kem 0.3.2`.

### Fixed

- **Page locks are released.** The predecessor zeroized a `Vec` and then called
  `munlock` with its now-zero length, so the unlock silently never happened. The
  guard here captures `(ptr, len)` at lock time; a regression test clears the
  buffer first and asserts the range is still released.
- Pre- and post-parse size caps restored, so a hostile or corrupt vault cannot
  drive unbounded allocation in the CBOR decoder.
- Core dumps disabled (`RLIMIT_CORE`, `PR_SET_DUMPABLE`) and tracer detection
  restored.
- `[dev-dependencies]` declared, so the test suite compiles. The published
  predecessor's did not.

### Fixed (post-release, folded into 2.0.0)

- **Escape was a dead key on the sealed screen.** The passphrase field takes
  focus the moment the deck opens, and a QML `Keys` handler only fires while
  the item holding it has active focus — so from that instant every key the
  cockpit defined was silent, including the one that closes it. Escape, lock
  and refresh are now window-scoped `Shortcut` items, which are independent of
  focus. Plain letter keys deliberately stay in the focus-scoped handler: they
  must remain inert while you are typing into a field.
- Escape is now layered, doing the smallest useful thing first: it hides a
  revealed secret, then cancels a pending delete, then clears a search query,
  and only then closes the deck.

### Fixed (found by writing the documentation)

Writing the manual and whitepaper meant executing every claim rather than
reading it, which turned up seven defects. All are fixed; the whitepaper records
the reasoning.

- **A silent rollback was possible by splicing a payload.** The header MAC
  covered the header only, and the payload's AEAD binds no epoch — so an old
  payload could be pasted onto a current header, unlock cleanly, report the
  current epoch and raise no rollback suspicion. The MAC now binds the payload
  by hash, and `updated_at` with it. Regression test:
  `splicing_an_old_payload_onto_a_current_header_is_detected`.
- **Records read from the vault were never page-locked.** `Secret`'s lock guard
  is `#[serde(skip)]`, so everything deserialised arrived unlocked — the claim
  "secrets are page-locked" was true of the data key and false of the records it
  protects. `open_payload` now re-locks explicitly.
- **`open_lock` took no lock at all.** It opened a file and returned it while
  its own doc comment claimed otherwise, and `fd-lock` was a declared dependency
  used nowhere. It now takes `flock(LOCK_EX)`.
- **Copying a 2FA record failed.** `COPY` asked for the stored shared secret,
  which is binary, and died with `invalid utf-8 sequence`. It now copies the
  current code via `black-bag agent totp --to clipboard`.
- **`add --totp-secret` accepted secret material on argv**, the one exception to
  a rule this project otherwise holds absolutely. The flag is gone; the secret
  is prompted for.
- **The agent misreported its own hardening.** `Agent::publish` omitted
  `.with_harden`, so `status.json` always said core dumps were enabled and the
  cockpit raised a spurious `CORE_DUMPS` finding against a process that had
  disabled them.
- **Escape was a dead key on the sealed screen** — see above.

### Security

- `status.json` contains no record titles, tags, counts, or secret values. A
  test asserts this against a vault seeded with distinctive strings.
- The agent socket is `0600` inside a `0700` directory and checks `SO_PEERCRED`
  on every connection.
- Passphrases and record drafts cross process boundaries on stdin or the agent
  socket, never in an argument vector.

[2.0.0]: https://github.com/AnubisQuantumCipher/blackbag/releases/tag/v2.0.0
