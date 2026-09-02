# Black-Bag against the field

Black-Bag 2.5.0 · vault format v2 · Linux (Omarchy, aarch64)

This document places Black-Bag next to five other password managers on the
properties that decide whether a vault survives contact with an attacker. Every
Black-Bag cell was checked against the 2.5.0 source and names the file that
implements it. Every competitor cell comes from the primary-source review
compiled on 2026-09-02 (cited as *report §n*), which in turn cites vendor
whitepapers, source repositories, specifications and papers; those are listed
at the end. Where the review did not cover something, the cell says **not
researched** rather than guessing. A comparison that flatters its author is
worthless, so the section on what Black-Bag lacks is as concrete as the section
on what it has.

---

## 1. Framing

A local-first manager does not face the adversary that broke the cloud ones. In
May 2026 Scarlata, Torrisi, Backendal and Paterson published 27 attacks against
Bitwarden, LastPass, Dashlane and 1Password under a malicious-server model —
key escrow, KDF-parameter downgrade, item swapping, replay, sharing-key
substitution — and every one of them needs a server that the client trusts to
hand it ciphertext, public keys and KDF settings (report §2.1, ePrint
2026/058). A vault that is one file on one machine has no such party. That
removes an attack surface; it does not remove attackers. It also opens a
possibility the paper says cloud products cannot have: real anti-rollback,
because a local client may keep state (report headline finding 3). Black-Bag
is a single XChaCha20-Poly1305 file with an authenticated header, a
per-process session key held in `memfd_secret`, an agent that, when run from
its systemd unit, cannot open a network socket
(`RestrictAddressFamilies=AF_UNIX`; an agent started by hand has no such
restriction, and the unit is not enabled by default), and no sync, browser,
hardware-key or passkey surface at all.
It is ahead of every product in the matrix on memory hygiene and header
authentication, and behind most of them on integration. Both halves are
stated below.

---

## 2. Property matrix

Columns: **Black-Bag 2.5.0** (verified in source), **KeePassXC 2.7.12**,
**1Password 8**, **Bitwarden**, **Proton Pass**, **pass / gopass**. Competitor
cells carry the report section they come from; the report's own citations are
reproduced in §6.

| Property | Black-Bag 2.5.0 | KeePassXC | 1Password | Bitwarden | Proton Pass | pass / gopass |
|---|---|---|---|---|---|---|
| **KDF and parameters** | Argon2id, m = 256 MiB, t = 10, lanes = clamp(cpus, 4, 8); floor 32 MiB; random salt per recipient (`crates/blackbag-core/src/crypto.rs`, `DEFAULT_MEM_KIB`, `DEFAULT_TIME_COST`, `recommended_lanes`). Unlock measured at about 1.3 s on this 8-vCPU aarch64 VM; that figure is for this machine, not a promise | Argon2**d** default, m = 64 MiB, t benchmarked to 1000 ms, p = min(cores, 4), 32-byte salt re-randomised on every save (report §1.1, §2.2) | PBKDF2-HMAC-SHA256, 650,000 iterations, XOR'd with an HKDF expansion of the 128-bit client-side Secret Key (report §1.1, §2.2) | PBKDF2-SHA256 600,000 default; Argon2id opt-in at m = 32 MiB, t = 6, p = 4 — weakened from 64 MiB / t = 3 without announcement (report §1.1, §2.2) | bcrypt on the account password plus SRP; no memory-hard client KDF (report §1.1, §2.2) | GPG asymmetric per file; age scrypt in password mode (report §1.1) |
| **Header / KDF-parameter authentication** | HMAC-SHA256 under the DEK over the canonical header: version, vault id, epoch, timestamps, every recipient's Argon2 parameters and wrapped DEK, and a BLAKE3 hash of the payload nonce and ciphertext; checked before the payload is opened (`crates/blackbag-core/src/vault.rs`, `Header::mac_input`; `crypto.rs`, `header_mac`) | Header HMAC-SHA-256 under a master-key-derived key; a KDF downgrade is detected before a single cipher operation (report §2.2, headline 2) | None at the vault level; a server can force 10,000 iterations (1P04), which the Secret Key makes impractical to exploit (report §1.1, §2.1) | None; a server can force 5,000 iterations, `PRELOGIN_ITERATIONS_MIN` (BW07) (report §1.1, §2.2) | Not applicable in the report's matrix — there is no client-side vault KDF to authenticate (report §1.1) | Not applicable (report §1.1) |
| **Anti-rollback** | Monotonic epoch inside the MAC'd header, compared against `$XDG_STATE_HOME/black-bag/witness.json`. The witness is an unauthenticated tripwire: it catches restored backups and sync conflicts, warns rather than blocks, and an attacker who can rewrite the vault can usually rewrite it too (`vault.rs`, `Witness`) | None — the report finds no manager in its survey with anti-rollback (report §3.1 item 2) | None (report §3.1 item 2; 1P02 item dropping/duplication, §2.1) | None (report §3.1 item 2) | None (report §3.1 item 2) | None; git history is readable, and revoked recipients can check out old revisions (report §2.2, gopass `docs/security.md`) |
| **In-memory encryption of resting secrets** | Yes. Every record field and the DEK rest as XChaCha20-Poly1305 ciphertext (AAD `black-bag::v2::guarded-memory`) under a 32-byte per-process session key; plaintext exists only inside a `SecretBuf` while in use (`crates/blackbag-core/src/secmem.rs`, `Guarded`). A test scans `/proc/self/mem` across every readable writable mapping under 256 MiB for a resting secret's plaintext (`a_resting_secret_is_nowhere_in_writable_memory`; larger and unreadable mappings are skipped). Not covered: the Argon2 working set and the QML surfaces | No. Entry passwords are plain `QString` in a `QMap`; Qt containers allocate with `malloc`/`realloc`, which the scrubbing `operator delete` never sees (report §1.3, §2.3; CVE-2024-33900/33901) | Not documented (report §1.3) | No (report §1.3) | XOR obfuscation only, which the report does not count as a boundary (report §1.3) | Not applicable — gpg-agent holds the key, not the tool (report §1.3) |
| **Where the master / session key lives** | Session key in one `memfd_secret` page (syscall 447, `ftruncate` + `mmap MAP_SHARED`, descriptor closed), removed from the kernel direct map; falls back to a page-locked arena slab, then to ordinary memory, and `doctor` / `status.json` report which (`memfd_secret`, `locked-slab`, `unlocked`). `BLACK_BAG_NO_SECRETMEM=1` opts out. The DEK itself rests as guarded ciphertext (`secmem.rs`, `SessionKey`, `KeyBacking`; `status.rs`, `session_key_backing`) | Botan `secure_vector` in an mlock pool only if built with `BOTAN_HAS_LOCKING_ALLOCATOR`; unconditional scrub on free (report §1.3) | Rust core with `ring`; kernel keyring for the browser channel; no hardware backing on Linux (report §1.3) | Not researched (report §1.3 leaves the cell empty) | `zeroize` / `ZeroizeOnDrop`; Linux keyring via keyutils by default (report §1.3) | gpg-agent's memory (report §1.3) |
| **Core-dump / ptrace posture** | `setrlimit(RLIMIT_CORE, 0)`, `prctl(PR_SET_DUMPABLE, 0)` (blocks same-uid ptrace), `PR_SET_NO_NEW_PRIVS`, tracer snapshot at start (`crates/blackbag-core/src/harden.rs`); arena slabs `MADV_DONTDUMP` + `MADV_DONTFORK` (`secmem.rs`, `Slab::map`); unit `LimitCORE=0` (`plugin/khephri.blackbag/install.sh`). Root and `CAP_SYS_PTRACE` are unaffected | `RLIMIT_CORE=0` + `PR_SET_DUMPABLE 0`, exempt on Snap; `strings -e b` on a dump still recovers secrets — 100 % unlocked, about 40 % after lock (report §1.3, §2.2) | Not documented (report §1.3) | Not researched (report §1.3) | Not researched (report §1.3) | Not researched (report §1.3) |
| **Clipboard hint and clear semantics** | Detached `clip-serve` helper (hidden subcommand) speaks the data-control protocol via `wl-clipboard-rs`; offers `text/plain;charset=utf-8`, `text/plain` and `x-kde-passwordManagerHint=secret`; `mlockall(MCL_CURRENT\|MCL_FUTURE\|MCL_ONFAULT)` after starting a 128 KiB-stack clear timer; clears via `copy::clear` only if the selection is still ours; caller waits up to 4 s (`READY_TIMEOUT`) for the helper to report ready, then polls the compositor for the hint for up to 3 s (`tty.rs`, `wait_until_sensitive`) before printing "copied"; cap 3600 s, 0 = never (`crates/blackbag-cli/src/clipboard.rs`). Regular clipboard only — the primary selection is not touched. The hint is advisory: any `ext-data-control` client can still read the selection | Sets `x-kde-passwordManagerHint=secret` on both Clipboard and Selection; `ClearClipboardTimeout` default 10 s (report §4.1, `src/gui/Clipboard.cpp`) | Not researched | Not researched | Not researched | Not researched |
| **Lock on suspend / screen lock** | Agent subscribes to logind `PrepareForSleep` and `Session.Lock` (any session path) on the system bus through a hand-written client: SASL EXTERNAL, `Hello`, two `AddMatch`; reconnects every 20 s; 1 MiB message cap; `DBUS_SYSTEM_BUS_ADDRESS` honoured. **No delay inhibitor is taken**, so the lock lands when the agent is next scheduled, not provably before the kernel suspends (`crates/blackbag-core/src/sleepwatch.rs`). The plugin also locks when the shell's `omarchy.lock` service reports locked (`plugin/khephri.blackbag/Service.qml`). State appears in `status.json` as `session.sleep_watch` | Listens on `org.freedesktop.ScreenSaver` and `org.gnome.ScreenSaver` `ActiveChanged` and `org.gnome.SessionManager.Presence.StatusChanged`; idle auto-lock on by default only since 2.7.11 (900 s) (report §3.2, §4.9) | Not researched | Not researched | Not researched | Not researched |
| **Session ceiling** | Idle 900 s default (`DEFAULT_IDLE_SECS`, floored at 30) and a hard ceiling of 43,200 s (`DEFAULT_MAX_SESSION_SECS`, `agent serve --max-secs`, floored at 60, 0 disables). Lock reasons: `manual`, `idle`, `session-ceiling`, `suspend`, `session-lock`, `rekeyed`, `shutdown`. Each peer gets 3 s to send and receive (`PEER_IO_TIMEOUT`) (`crates/blackbag-core/src/session.rs`) | Idle auto-lock 900 s default; no ceiling reported (report §3.2) | `op` CLI: 10-minute idle, 12-hour cap, TTY and start-time binding (report §1.5) | `bw` CLI: `BW_SESSION` environment variable, no expiry, readable from `/proc/<pid>/environ` (report §1.5, §2.2) | Not researched | Not researched |
| **Breach check: protocol and what leaves the machine** | HIBP k-anonymity, opt-in per run (`--online`; exit 2 otherwise). Agent hands the CLI one entry per `password` / `passphrase` / `pin` field (record id, title, field name, 5-hex-character SHA-1 prefix); the CLI deduplicates and sorts the prefixes (`breach::distinct_prefixes`) before fetching; CLI fetches each bucket with `curl --max-time 20`, `Add-Padding: true`, `User-Agent: black-bag/<version>`; padding entries (count 0) dropped; agent matches the full hash it never disclosed and folds hits into hygiene as `EXPOSED` (severity High) until lock. Under its systemd unit the agent has no network family at all; an agent started by hand is not so restricted (`crates/blackbag-core/src/breach.rs`; `crates/blackbag-cli/src/main.rs`, `cmd_breach`; `hygiene.rs`, `Issue::Exposed`). Service sees: IP, time, at most one request per distinct prefix | HIBP k-anonymity, opt-in, behind a networking build flag (report §1.5) | HIBP k-anonymity, 5-character SHA-1 prefix, compared locally (report §1.5) | HIBP (report §1.5; protocol detail not given) | Server-side lookup; custom addresses shared with third parties (report §1.5, §3.4) | `pass audit` / `gopass audit` (report §1.5; protocol not researched) |
| **Hardware key** | None | YubiKey / OnlyKey HMAC-SHA1 challenge-response, folded into the key before the KDF; FIDO2 hmac-secret not shipped (issue #3560 open since 2019) (report §1.3, §2.2) | None; the Secret Key is the second factor (report §1.3) | Partial: WebAuthn PRF unlock, needs a PRF-capable browser and key (report §1.3) | None (report §1.3) | OpenPGP card / `age-plugin-yubikey` (report §1.3) |
| **SSH agent** | None. `Kind::Ssh` stores a private key as a record field; nothing serves it (`crates/blackbag-core/src/record.rs`) | Client only: pushes keys into your `ssh-agent` with `ADD_ID_CONSTRAINED`; the key leaves the manager (report §1.4, §3.1 item 5) | Is the agent: `~/.1password/agent.sock`, keys never enter another process, per-use consent (report §1.4) | None (report §1.4) | None; ssh-key items only (report §1.4) | Not applicable (report §1.4) |
| **Browser integration** | None. No extension, no native-messaging host (`docs/MANUAL.md` §1) | Native messaging → `keepassxc-proxy` → AF_UNIX socket, libsodium `crypto_box`, no peer-credential check on the socket (report §1.4, §4.3) | Extension, sandboxed background page (report §1.4) | Extension (report §1.4) | Extension (report §1.4) | Community extensions (report §1.4) |
| **Passkeys** | None | Yes since 2.7.7; export is unencrypted `.passkey` JSON (report §1.4) | Yes, own `passkey-rs`, PRF for relying parties (report §1.4) | Yes, `fido2Credentials` (report §1.4) | Yes, on 1Password's `passkey-rs` (report §1.4) | No (report §1.4) |
| **Import / export** | Import: Bitwarden unencrypted JSON (encrypted export refused with advice), KeePassXC CSV (group → tags; a `kind: x` notes line round-trips non-login kinds), Firefox `logins.csv`, Chrome CSV, generic CSV with column synonyms; `--dry-run`; skipped rows reported by row number (CSV) or item number and title (Bitwarden) plus reason, never by a secret value. Export: `json` or `keepassxc` CSV, plaintext, requires `--plaintext-ok`, created 0600 with `create_new`, refuses to overwrite. No CXF (`crates/blackbag-cli/src/import.rs`; `main.rs`, `cmd_export`) | Imports KDBX3/4, KDB, CSV, 1PUX, OpVault, Bitwarden JSON, Proton Pass; exports CSV, HTML, XML, all plaintext (report §1.5) | Many importers; 1PUX export is an unencrypted ZIP (report §1.5) | Many importers; JSON and password-protected JSON export (report §1.5) | Many importers; CXF/CXP export in Rust (report §1.5, §1 "Standards interop") | `pass-import` reads 63 managers; 8 export formats (report §1.5) |
| **Audit status** | None. No third-party review has been performed or is claimed; `docs/AUDIT.md` is the author's own review of the predecessor crate (`docs/WHITEPAPER.md` §12.1) | Not researched as an audit; open source; CVE-2024-33900/33901 disputed and unfixed, CVE-2026-4158 fixed in 2.7.12 (report §2.2) | Pentest reports moved behind `trust.1password.io` as of 2025-11-03 (report §2.2) | Open source; 2025 audits including ETH Zürich's Applied Cryptography Group and two RustCrypto audits (report §2.2) | Cure53 PRO-01 (2023): 10 issues, one High (report §2.2) | Not researched |

Two rows the matrix does not carry, stated once: Black-Bag has no sharing of
any kind and no attachments. Both are absences by design at this version, not
partial features.

Three further Black-Bag facts the matrix compresses, verified in source
because a reader of the deck will meet them: the unlock passphrase, reveal
replies, draft secrets and TOTP inputs cross the agent socket as
`Zeroizing<String>` and `Add` / `Update` / `Delete` take the same `flock` the
CLI takes (`session.rs`, `vault::open_lock`); the deck's `clearSecrets` empties
both sheets and the record list, "locked" is announced only after `agent lock`
exits 0, a second copy or reveal while one is in flight is refused aloud (a
second TOTP fetch is dropped silently — `fetchTotp` returns without a note),
the breach check is armed and confirmed in two steps (`Ctrl+B`), and
settings from disk are clamped — `revealSeconds` 3..120, `clipboardClearSec`
5..600, `staleAfterSec` 10..3600, `pollIntervalSec` 2..120 (default 15 s in
`manifest.json`), `uiScale` 0 or 0.7..3.0 (`Cockpit.qml`, `Model.js`
`clampSettings`); every secret box in the editor has a show/hide toggle and
multi-line secrets are covered until revealed (`Editor.qml`); the first-run
sheet has a 120 s watchdog, Esc always leaves it, and skipping the recovery
key takes two presses (`Onboard.qml`).

---

## 3. Where Black-Bag is ahead

Each item names the file that implements it and the test that pins it where
one exists.

**The session key lives in `memfd_secret`.** `secmem.rs::secretmem_page`
issues syscall 447, `ftruncate`s the descriptor to one page, maps it
`MAP_SHARED`, closes the descriptor and writes the 32-byte key into the
mapping. The kernel removes secretmem pages from its direct map, and
`mm/gup.c` refuses `get_user_pages` on them, so `/proc/<pid>/mem`,
`process_vm_readv` and `PTRACE_PEEKDATA` fail even for root (report §4.8).
None of the products in the matrix does this on Linux; the report's own
Tier 1 recommendation (§3.1 item 4) is exactly this construction. When the
syscall is unavailable the key drops to a page-locked slab, then to ordinary
memory, and `KeyBacking` names which one happened — `doctor` and the deck's
HOST POSTURE card show it, and an `unlocked` key raises `SESSION_KEY_UNLOCKED`
in `status.rs`.

**Every resting secret is ciphertext, and a test proves it the hard way.**
`Guarded` seals each field and the DEK under the session key with
XChaCha20-Poly1305 and the AAD `black-bag::v2::guarded-memory`; `open()` hands
back a `SecretBuf` in a locked slab (256 KiB, `mmap` + `mlock` +
`MADV_DONTDUMP` + `MADV_DONTFORK`, zeroed free lists, dedicated slabs for
oversize buffers) that is wiped on drop. The decrypted payload, the serialised
payload and the CBOR decoder's scratch — `MAX_NOTE_BYTES` + 4096 bytes — are
built in the same arena, so no secret byte crosses unlocked memory between
file and record. `secmem::tests::a_resting_secret_is_nowhere_in_writable_memory`
creates a guarded secret, opens and drops it, then reads `/proc/self/mem`
across every writable mapping it can read that is under 256 MiB (larger
mappings and unreadable ones are skipped) and asserts the plaintext appears
nowhere. The
ISE 2019 study and KeePassXC's CVE-2024-33900/33901 are the industry baseline
this replaces: secrets recoverable from a process image after lock (report
§2.3). What the arena does not cover is said in the module header: the Argon2
working set and the QML surfaces are ordinary memory.

**The header is authenticated, and the witness watches the epoch.**
`Header::mac_input` covers version, vault id, epoch, `created_at`,
`updated_at`, the recipient list with each recipient's Argon2 parameters and
wrapped DEK, and a BLAKE3 hash of the payload nonce and ciphertext;
`crypto::header_mac` is HMAC-SHA256 under the DEK, verified before the payload
is opened. This is the KDBX4 property that made BW07 / 1P04 / DL04 impossible
(report headline 2) plus payload binding, which KDBX4's header HMAC does not
provide by itself. `vault::tests::header_tampering_is_detected` and
`splicing_an_old_payload_onto_a_current_header_is_detected` pin the two cases.
The witness (`vault::Witness`) is the local-state anti-rollback the USENIX
paper says cloud clients cannot keep — and it is a tripwire, not an
authenticated counter; see §4.

**The hybrid post-quantum recovery recipient is real.** `Recipient::Hybrid`
stores only the holder's X25519 and ML-KEM-1024 public keys, the two
ciphertexts, and the DEK sealed under a BLAKE3 combine of both shared secrets
(`vault.rs`, `wrap_hybrid`, `combine_shared`). The private halves are written
to a separate 0600 file and never appear in the vault — the predecessor
encapsulated to its own public key and stored the decapsulation key in the
same header, which contributed nothing (`docs/AUDIT.md` finding 2). An
attacker holding the file must break both X25519 and ML-KEM-1024 to use that
lane; `vault::tests::recovery_key_unlocks_without_the_passphrase` pins it. The
combiner is not a standardised construction and carries no proof
(`docs/WHITEPAPER.md` §12.6).

**Under its unit, the agent runs in a sandbox that cannot reach a network.**
The sandbox is a property of the systemd unit, not of the binary: `black-bag
agent serve` started by hand applies no address-family restriction, and the
unit is not enabled by default. The unit written by
`plugin/khephri.blackbag/install.sh` sets `RestrictAddressFamilies=AF_UNIX`,
`CapabilityBoundingSet=` (empty), `SystemCallFilter=@system-service
memfd_secret` with `SystemCallFilter=~@privileged` and
`SystemCallErrorNumber=EPERM`, `PrivateDevices`, `RemoveIPC`, `UMask=0077`,
`ProtectClock`, `ProtectHostname`, `ProtectKernelLogs`, `RestrictSUIDSGID`,
`MemoryDenyWriteExecute`, `NoNewPrivileges`, `LimitCORE=0`. The breach check
was designed around this: the agent computes prefixes and matches buckets; the
CLI fetches them with `curl`. Every peer connection is checked with
`SO_PEERCRED` before a byte is read (`session.rs`, `peer_uid`). The report's
survey found no manager whose local IPC authorisation it considered sound
(§3.2 item 7); `SO_PEERCRED` is the fallback it names, not the `SO_PEERPIDFD`
it prefers.

**The clipboard hint is served from a locked helper that clears only its own
value.** `clipboard.rs::serve` offers `x-kde-passwordManagerHint=secret`
alongside the text in one selection — the hint cliphist, Klipper and
Omarchy's capture script honour (report §4.1) — from a `setsid` process with
`mlockall` and core dumps off; the clear timer fires `copy::clear` only if
`serve()` has not already returned because another client took the
selection. The caller does not print "copied" until
`wait_until_sensitive` has seen the compositor offer the hint. 2.4.1 made the
same promise and did not keep it (`CHANGELOG.md` [2.5.0]).

**The attack surface is hand-written and small.** The D-Bus client in
`sleepwatch.rs` implements SASL EXTERNAL, `Hello`, two `AddMatch` calls and a
bounds-checked parser that drops what it cannot read; it exposes no interface
and sends nothing derived from a secret. There is no D-Bus crate, no HTTP
crate and no TLS crate in `Cargo.toml`; the one network act shells out to
`curl` from the CLI. `sleepwatch::tests::malformed_bytes_never_panic` flips
every byte and cuts every prefix of a valid message.

**Posture is reported, not assumed.** `harden::harden_process` returns which
of its three hardening operations succeeded and whether a tracer was attached
at start; `secmem` counts lock failures and reports
unlocked bytes; `status.json` carries the session key's backing, the sleep
watcher's state string, the last lock reason and the ceiling; the deck's
SESSION card renders `Model.sessionRows` from that document, HOST POSTURE
shows the key's backing as *kernel-invisible*, *locked page* or *UNLOCKED*
(`Model.js`), the hygiene card has a *HYGIENE — UNAVAILABLE* state, and an
unmeasured posture row reads `UNKNOWN` rather than showing a pass
(`docs/MANUAL.md` §10). The report's
closing advice on memory hardening is "say that, rather than claiming more"
(§4.8); this is the mechanism for saying it.

---

## 4. Where Black-Bag is behind, and what it would take

**No hardware key.** There is no FIDO2 `hmac-secret`, no YubiKey
challenge-response, no smartcard. The passphrase and the recovery file are the
only doors. The report's design (§3.1 item 3, §4.4) is specific: enrol with
`FIDO_EXT_HMAC_SECRET`, store a 32-byte salt and the UV mode in the header,
mix `fido_assert_hmac_secret_ptr` output into the composite key before Argon2,
and keep the passphrase lane authoritative because an hmac-secret credential
cannot be duplicated. That is a new `Recipient` variant, a libfido2 or
`libwebauthn` dependency, a udev rule, and a change to the header MAC input.
KeePassXC has shipped HMAC-SHA1 challenge-response for years and pass gets it
through gpg; Black-Bag has nothing.

**No SSH agent.** `Kind::Ssh` is storage. 1Password's model — own the socket,
never release the key, approve each signature — is the one the report calls
correct (§3.1 item 5), and it now has a Proposed Standard to implement against:
RFC 9987, including `session-bind@openssh.com`, without which OpenSSH's agent
restrictions silently do not cover the keys. The agent already has a
peer-checked AF_UNIX socket and locked memory; what is missing is the wire
protocol, a signing path that keeps the key inside a `SecretBuf`, per-signature
consent in the deck, and `SSH_AUTH_SOCK` arbitration against gpg-agent.

**No browser extension.** Black-Bag has no autofill, no native-messaging host
and no page integration; you copy and paste. The report documents both the
KeePassXC protocol and its weaknesses — a bearer public key for association,
`request-autotype` with no association guard, `endsWith` host matching (§4.3)
— and the 2025 DOM-clickjacking results that hit twelve extensions (§2.3).
Doing this properly means an extension, a host with `SO_PEERPIDFD` peer
authentication and a private association key, and a public-suffix check. It
is a large amount of new attack surface and it is the single most-used feature
Black-Bag does not have.

**No passkeys.** Every product in the matrix except pass stores and asserts
WebAuthn credentials. The report finds two working Linux routes today
(`chrome.webAuthenticationProxy` on Chromium, `navigator.credentials` override
on Firefox) and an emerging portal, `credentialsd`, not yet in
xdg-desktop-portal (§4.5). This depends on the browser work above.

**No per-item keys and no key commitment.** The whole payload is one
XChaCha20-Poly1305 blob under one DEK (`vault.rs`, `seal_payload`,
`AAD_PAYLOAD`). Because there is one ciphertext and one MAC over the file,
item field-swapping (BW05) and item dropping (1P02) have no purchase — but
that is a consequence of the monolith, not of key separation, and it means
the format cannot do item-level sync or partial decryption without giving the
property up. The USENIX paper's Section 5 asks for separate keys per vault
item derived by a standard KDF, and AEAD associated data binding each
ciphertext to its item and field (report §2.1). Separately, XChaCha20-Poly1305
is not key-committing: RFC 9771 (CFRG, May 2025) names password-based
encryption as the headline case where a non-committing AEAD turns a decryption
oracle into a multi-key guess (report §2.3). Black-Bag's header MAC under the
DEK functions as a commitment for the DEK in the same way KDBX4's header HMAC
does, but the per-recipient `sealed_dek` blobs under the Argon2-derived KEK
carry no such commitment. A format revision would add HKDF-derived item keys
with `(uuid, field, version)` in the AAD and an explicit CMT-4 construction.
Nothing in 2.5.0 does this.

**No CXF.** FIDO Credential Exchange Format v1.0 has been a Proposed Standard
since 2025-08-14; Apple ships it, Proton Pass has a Rust implementation
(report §1 "Standards interop"). Black-Bag's exports are plaintext JSON and
KeePassXC CSV, and the import list is five formats. A CXF importer and an
HPKE-protected CXP export would make it a better migration target than
KeePassXC, which does not ship CXF either. It is a parser and a serialiser;
it is not hard, and it is not done.

**No attachments, no sharing.** There is no field type for a file and no
recipient model for a second person; the hybrid recipient is a recovery lane
for the same user. The report's prescriptions — chunked STREAM AEAD for
attachments (§3.1 item 1), signed and context-bound sharing on the Proton
Pass pattern (§3.2 item 9) — are both format work.

**The witness is unauthenticated.** `witness.json` is plain JSON under your
own uid. It catches the accidental rollbacks — backup restores, sync
conflicts, snapshot reverts — and nothing deliberate. The report names the
anchor: a TPM2 NV index with `TPMA_NV_COUNTER`, 64-bit, increment-only,
initialised on creation to the highest value any counter on that TPM has ever
held, so deleting and recreating it does not reset it (§3.1 item 2, §4.8).
Refuse to open a vault whose epoch is below the counter; log an explicit
"accept older backup" override. That requires `tss-esapi` or a shell-out to
`tpm2-tools`, salted encrypted sessions, and a policy for machines without a
TPM — this VM among them.

**No delay inhibitor on sleep.** `sleepwatch.rs` says it in its own header:
without `org.freedesktop.login1.Manager.Inhibit("sleep", …, "delay")` there
is no guarantee the vault is locked before the kernel suspends, only that it
locks when the agent is next scheduled after `PrepareForSleep(true)`. The
inhibitor needs file-descriptor passing over the bus, which the hand-written
client does not do. The report lists the delay inhibitor as part of a complete
auto-lock (§3.2 item 10). Relatedly, `mlock(2)` states that suspend-to-disk
saves RAM regardless of locks; the `memfd_secret` page is the one thing here
that is not written, and it blocks hibernation system-wide for as long as the
agent process holds it — the page is allocated once per process and is not
released on lock, so a machine that must hibernate has to run with
`BLACK_BAG_NO_SECRETMEM=1`.

**Smaller gaps, stated because a reader would find them anyway.** The clipboard
helper serves the regular clipboard only; the primary selection is never
cleared (report §4.1 recommends both). The Omarchy deck runs inside the shell
process, where a revealed secret and every keystroke into the editor sit in
ordinary Qt memory with no locking (`docs/WHITEPAPER.md` §12.16). The Argon2
working set is ordinary heap. There is no screen-capture exclusion, and the
report finds no Linux mechanism for one (§4.9). There is no offline breach
corpus; the check needs the network every time. There is no third-party
review.

---

## 5. Marketing we refuse to use

The report's list (§3.4), with Black-Bag's position on each.

- **"Zero-knowledge."** Meaningless for a local file; there is no server to
  know anything. Black-Bag does not use the phrase.
- **"Military-grade" or "bank-grade."** Black-Bag uses XChaCha20-Poly1305 for
  the payload, the recipients and in-memory guarding; HMAC-SHA256 for the
  header; BLAKE3 for hashing and key combination; Argon2id for the passphrase.
  Those are the names it uses.
- **"XChaCha20 is more secure than AES-256."** No cryptanalytic basis. The
  reason Black-Bag uses it is constant-time software performance without
  AES-NI on this aarch64 VM and a 192-bit nonce; that argument is sufficient
  and is the only one made.
- **An algorithm name with no parameters.** m = 256 MiB, t = 10, lanes =
  clamp(cpus, 4, 8), floor 32 MiB, and the parameters are stored per recipient
  and covered by the header MAC (`crypto.rs`, `vault.rs`). `doctor` reports
  whether an existing vault's parameters meet the current defaults
  (`status.rs`, `KdfView::meets_current_defaults`).
- **Iteration-count addition.** Not applicable: there is one KDF, run once, on
  the client. There is nothing to add.
- **"FIPS 140-3 certified."** No certification is held or claimed.
- **Passwordless or biometric unlock presented as cryptography.** Black-Bag has
  no biometric unlock. If it gains one it will be a gate on re-exposing a key
  already held, and will be described as such — fprintd, polkit and PAM return
  a string, a boolean and an int, never key material (report §4.7).
- **"Local scan" / "on-device."** Hygiene and TOTP are computed in the
  agent, which under its unit has `RestrictAddressFamilies=AF_UNIX`; the
  generator and its entropy accounting run in the CLI process (`cmd_gen`),
  which contains no network code other than the `curl` shell-out. The breach
  check is the one exception, it is
  opt-in per run, and §2 above states exactly what leaves.
- **Plausible deniability and duress vaults.** None. The predecessor had a
  duress mode; it was not reproduced, because a decoy a determined adversary
  knows about is worse than none (`docs/WHITEPAPER.md` §2.2, §12.14).
- **Post-quantum badges.** Black-Bag's ML-KEM-1024 lane is real for one
  reason: the recipient's private key lives outside the vault, so an attacker
  with the file must break the KEM to use that door. It does nothing for the
  passphrase lane, which is Argon2id and XChaCha20-Poly1305 — symmetric
  primitives that were never at risk from Shor's algorithm — and a vault
  without a recovery recipient contains no post-quantum cryptography at all.
  The file is as strong as its weakest door and the attacker picks. The report
  is right that for a local file with no key transport a KEM buys nothing;
  the recovery recipient is key transport to an offline holder, which is the
  narrow case where it does. Black-Bag will not describe itself as a
  post-quantum password manager.
- **Patent counts.** None held, none pending, none relevant.
- **Audits commissioned and not published.** None commissioned. The
  predecessor crate shipped a fabricated third-party review; this repository
  claims no review at all (`docs/AUDIT.md` finding 9, `docs/WHITEPAPER.md`
  §12.1).

---

## 6. Sources

The subset of the research report's source list that this document draws on.
Report section numbers refer to the 2026-09-02 review; each of its cells is
traced to one of the items below.

**Papers and security research**

- eprint.iacr.org/2026/058 and zkae.io — Scarlata, Torrisi, Backendal, Paterson, *Zero Knowledge (About) Encryption*, USENIX Security '26 (report §2.1; attacks BW05, BW06, BW07, 1P02, 1P04, DL04; Section 5 mitigations)
- eprint.iacr.org/2020/1491 — Len, Grubbs, Ristenpart, *Partitioning Oracle Attacks*, USENIX Security '21 (report §2.3)
- ise.io/casestudies/password-manager-hacking/ — ISE, *Password Managers: Under the Hood of Secrets Management*, 2019 (report §2.3)
- marektoth.com/blog/dom-based-extension-clickjacking/ — DEF CON 33, 2025 (report §2.3)
- palant.info/2023/01/23/bitwarden-design-flaw-server-side-iterations/ (report §2.2)

**Standards and specifications**

- rfc-editor.org/rfc/rfc9771.txt — AEAD properties and commitment (report §2.3)
- rfc-editor.org/rfc/rfc9987.txt — SSH Agent Protocol, Proposed Standard, May 2026 (report §4.6)
- rfc-editor.org/rfc/rfc9106.html — Argon2 (report §2.2, §3.1)
- fidoalliance.org/specs/cx/cxf-v1.0-ps-20250814.html and cxp-v1.0-wd-20241003.html (report §1 "Standards interop")
- haveibeenpwned.com/API/v3 (report §3.1 item 6)

**Vendor primary sources**

- agilebits.github.io/security-design; support.1password.com/1password-security, /watchtower-privacy, /1pux-format; 1password.dev/ssh/agent, /cli/biometric-security (report §1.1–§1.5, §2.2)
- bitwarden.com/help/bitwarden-security-white-paper, /kdf-algorithms; bitwarden/clients `libs/legacy-crypto/src/models/kdf-config.ts`, `libs/common/src/vault/models/domain/cipher.ts` (report §1.1–§1.5, §2.2)
- proton.me/blog/proton-pass-security-model; github.com/protonpass/proton-pass-common, pass-cli (report §1.1–§1.5, §2.2)
- passwordstore.org; github.com/gopasspw/gopass `docs/security.md` (report §1.1–§1.5, §2.2)
- keepass.info/help/kb/kdbx_4.html, kdbx_4.1.html (report §2.2)

**KeePassXC source (via the GitHub API)**

- `src/format/Kdbx4Reader.cpp`, `src/streams/HmacBlockStream.cpp`, `src/crypto/kdf/Argon2Kdf.cpp`, `src/keys/ChallengeResponseKey`, `src/core/Alloc.cpp`, `src/gui/Clipboard.cpp`, `src/gui/osutils/nixutils/ScreenLockListenerDBus.cpp`, `src/browser/BrowserShared.cpp`, `src/sshagent/SSHAgent.cpp`; `docs/topics/{BrowserIntegration,Passkeys,ImportExport}.adoc`; keepassxc.org/blog/2019-02-21-memory-security/; NVD for CVE-2024-33900, CVE-2024-33901, CVE-2026-4158 (GHSA-4gr2-cr97-q9fx); keepassxc issue #3560 (report §1.3–§1.5, §2.2, §4.1, §4.3, §4.9)

**Linux platform**

- man7.org man2/memfd_secret, mlock, madvise, prctl, ptrace; torvalds/linux `mm/secretmem.c`, `mm/gup.c` (report §4.8)
- kernel.org Documentation/admin-guide/LSM/Yama.rst (report §4.8)
- tpm2-tools `tpm2_nvincrement`, `tpm2_nvdefine`; man.archlinux.org systemd-cryptenroll.1 (report §3.1 item 2, §4.8)
- developers.yubico.com/libfido2/Manuals/; systemd `src/shared/libfido2-util.h` (report §4.4)
- invent.kde.org plasma-workspace `klipper/historymodel.cpp`; sentriz/cliphist `cliphist.go`; bugaevc/wl-clipboard; wayland.app ext-data-control-v1 (report §4.1)
- qt.io qtbase `src/corelib/tools/qarraydata.cpp` (report §2.3)
- github.com/linux-credentials/credentialsd, libwebauthn; chromium.googlesource.com `_permission_features.json` (report §4.5)

**Black-Bag**

- `CHANGELOG.md` [2.5.0]; `docs/WHITEPAPER.md` §2.2, §5, §6, §7, §8, §12; `docs/AUDIT.md`; `docs/MANUAL.md` §1. `docs/WHITEPAPER.md` §2.2, §8.5, §12.8 and §12.11 predate 2.5.0's breach check, clipboard helper, guarded memory and `flock`; where they disagree with this document, the 2.5.0 source is what was checked.
- `crates/blackbag-core/src/{secmem,session,sleepwatch,breach,vault,crypto,harden,status,hygiene,record}.rs`; `crates/blackbag-cli/src/{clipboard,import,main}.rs`; `plugin/khephri.blackbag/{install.sh,Service.qml,Cockpit.qml,Model.js}`
