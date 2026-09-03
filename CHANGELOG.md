# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Credential Exchange Format (CXF)

- **`black-bag export --format cxf` and `import --format cxf`** — the FIDO
  Alliance's standard for moving credentials, passkeys with their private keys
  included, between managers. Every item carries a standard CXF credential
  (basic-auth, totp, note, ssh-key, passkey) so another manager can read it,
  plus a `_blackbag` extension that makes a Black-Bag-to-Black-Bag round trip
  exact. A foreign CXF with no extension still imports its common types.
  Offered in the deck's IMPORT and EXPORT choosers too.
- Verified live: eight records including three passkeys with their private keys
  exported to CXF and re-imported into a fresh vault, and a round-trip test
  covering login, TOTP, note, SSH and passkey.

### Fixed — passkeys did not survive an export

- A latent gap the CXF work surfaced: the Black-Bag JSON export omitted the
  passkey configuration (relying party, credential id, user handle), so a
  passkey re-imported from an export lost everything but its private key. The
  export now carries the config, and a round-trip test holds it there.

### Added — the vault as the freedesktop Secret Service

- **`black-bag secretservice serve`** is a full `org.freedesktop.secrets` D-Bus
  provider (Service, Collection, Item, Session interfaces), so applications
  using libsecret — browsers, mail clients, `secret-tool` — store and fetch
  their secrets in the vault. Verified against real `secret-tool`: `store`,
  `search`, and a lookup all work end to end, the lookup returning the exact
  secret after a GUI approval.
- **Both session encryptions:** `plain` and
  `dh-ietf1024-sha256-aes128-cbc-pkcs7`. The DH exchange (1024-bit MODP group,
  HKDF-SHA256, AES-128-CBC) is in `blackbag_core::secretservice::session`, with
  a full two-party round-trip test and an HKDF vector; the over-the-bus
  negotiation was confirmed with `busctl` (a 128-byte service key comes back).
- **Consent-gated reads, through the deck.** Reading an item raises the deck's
  approval sheet ("an app wants a stored secret") and costs the master
  passphrase, remembered until the vault locks — the `Reveal` model, keyed under
  one fixed `secret-service` identity so the deck's grant and the D-Bus daemon's
  read meet. Storing needs no approval: it is the application's own secret.
- **`black-bag secretservice doctor`** reports whether Black-Bag can own the bus
  name and, when something else (gnome-keyring) holds it, the exact steps to
  hand it over. `packaging/org.freedesktop.secrets.service` is the D-Bus
  activation file for going live.

### Security — a door for apps' own secrets, not for your passwords

- The Secret Service exposes and mutates **only items it created** (vault records
  it tags). Your logins, TOTP seeds, SSH keys and passkeys are never reachable
  or overwritable through it — an application asking for `service=myapp` cannot
  read or clobber your bank password.
- Only one process may own `org.freedesktop.secrets`; Black-Bag never wrests it
  from a running gnome-keyring. Every test above ran on a private, isolated
  D-Bus — the live session bus and its keyring were left untouched.

### Added — an SSH agent backed by the vault

- **`black-bag ssh serve`** binds `$SSH_AUTH_SOCK` and serves the vault's SSH
  keys, so `git push`, `ssh`, and everything that shells out to them use a key
  that lives encrypted in the vault instead of unguarded in `~/.ssh`. Verified
  against real OpenSSH: `ssh-add -l` lists the key, `ssh-add -T` signs a
  challenge that OpenSSH itself then verifies (exit 0), and the fingerprint
  matches `ssh-keygen -lf` byte for byte.
- **`black-bag ssh generate`** mints an Ed25519 key in the vault and prints its
  `authorized_keys` line; **`black-bag ssh list`** shows what the vault holds.
- **First-use approval, through the deck.** The first time a key signs, the deck
  raises an approval sheet and it costs the master passphrase; after that the
  key is remembered until the vault locks — the same `Reveal` model, and the
  same `Capability::SshSign` the policy already carried. `ssh` blocks on the
  socket while you answer, so from its side the key simply takes a moment.
- Built in layers that test without a socket: `ssh::wire` (the SSH wire format
  and the Ed25519 key/signature blobs), `ssh::agent` (the agent protocol), and
  `ssh::key` (Ed25519, deterministic). The full first-use → approve → sign →
  verify flow is an agent integration test as well as a live OpenSSH one.

### Fixed — a modal prompt could not receive a keystroke when it auto-raised

- The deck's main key handler claimed keyboard focus unconditionally, so a
  prompt raised by a **status update** rather than a keypress — which is how an
  SSH signing prompt appears while you are in your terminal — could not get
  focus, and silently swallowed everything typed into it. The handler now
  yields focus whenever the approval or passkey-consent sheet is up. This
  hardens every prompt, not just the SSH one.
- Ed25519 keys are stored as their 32-byte seed only; the public half is derived
  on demand, so a stored public key can never drift from its private key.

### Security — the SSH lane names the key, never a host

- CTAP-style origin binding does not exist for SSH: the agent is asked to prove
  a key, and `ssh` decides which host that key reaches. The approval prompt says
  exactly that — it shows the key's `SHA256:` fingerprint (which a person can
  check against `ssh-keygen -lf`) and states plainly that Black-Bag proves the
  key is yours while `ssh` chooses where it is used.
- The signing approval is keyed under one fixed `ssh-agent` identity so the
  deck (which approves) and the daemon (which signs) — different processes —
  meet at a single grant, and it reads as `ssh-agent` in the ACCESS panel, which
  is the truth. Revoking it or locking the vault withdraws it.

### Added — the vault as a virtual security key (lane B)

- **`black-bag key serve`** presents the vault as a virtual FIDO2 security key
  over `/dev/uhid`. Every browser and application that already talks to a
  security key can use it with no extension, which reaches where the extension
  cannot: Electron apps, Firefox, `ssh -sk`. Watched working end to end through
  the real kernel — an independent Python CTAP client drove INIT, PING,
  getInfo, makeCredential and getAssertion, and verified the signatures with
  `cryptography`, approved on the deck's own consent screen.
- **`black-bag key doctor`** says whether this machine can present one and what
  is stopping it — the device, the module, the permission — with the exact
  commands to fix each.
- **`packaging/70-blackbag-uhid.rules`** grants `/dev/uhid` to whoever is
  logged in at the seat via `TAG+="uaccess"`, **not** the `input` group, which
  would give every program you run raw access to your keyboard.
  **`packaging/blackbag-uhid.conf`** loads the `uhid` module at boot, which has
  to happen first: the static `/dev/uhid` node is root-only, so a non-root open
  fails before it can autoload the driver, and until the driver is loaded there
  is no device for udev to grant.
- The whole CTAP stack is built in layers that test without a device —
  `ctap::hid` (CTAPHID framing), `ctap::cbor` (CTAP2 encoding), and
  `ctap::authenticator` (the commands) — and the CTAPHID loop is driven over a
  fake wire. The `/dev/uhid` ABI marshalling is the only device-bound part, and
  its byte offsets were **measured with `offsetof`** against `linux/uhid.h` and
  pinned in a compile-time assertion block.

### Security — the CTAP lane binds the origin differently, and says so

- **CTAP carries no origin.** An authenticator is handed a relying-party id and
  a hash of bytes it never sees, so on this lane the *browser* binds the origin
  — exactly as it does for a hardware key, no worse and no better. The
  browser-extension lane remains the one where Black-Bag builds the signed
  bytes itself.
- The consent screen renders the two differently: over the security key it
  shows the relying party and says, in red, "through the virtual security key ·
  no web address was given", and never fabricates a plausible origin from the
  relying-party id.
- A ceremony records **exactly one** binding — an origin or a client-data hash,
  never both and never neither — enforced at registration. A browser ceremony
  therefore cannot reach the prehashed signing path, where a caller would get
  to choose the signed bytes.
- With no origin to check against, the relying party must still be a name
  somebody could own: a public suffix like `com` or `co.uk` is refused, so a
  page cannot mint a credential scoped to every site under it. A bare
  single-label name is accepted **only** with an origin the browser vouched for
  — never on the CTAP lane, where nothing vouched for it.

### Fixed — two ways the device could have failed silently

- **A cloned descriptor could destroy the device.** The keepalive path wrapped
  a cloned fd in a `Device`, whose `Drop` sends `UHID_DESTROY` — so the first
  keepalive of the first ceremony tore the key down mid-request. Sending a
  report is a free function on a plain `File` now; only the one owning value is
  a `Device`.
- **An unknown request field was silently dropped.** A newer client sent
  `client_data_hash` to an older agent, serde ignored it, and the request was
  read as a browser request with an empty origin. `Request` now refuses unknown
  fields; a version mismatch is named as one rather than passed through as
  serde's wording.
- **`getInfo` claimed `U2F_V2`** while the INIT capabilities set NMSG (no U2F).
  A client that believed the version list would try the one command that is
  refused. The version list no longer claims it, pinned by a test that the two
  must agree.

### Added — a way through when you want your security key

- **`^K` on the consent screen** returns `NotAllowedError` to the site, hands
  the proxy back to Chromium for a minute so a hardware key or a phone can
  actually be reached, and re-attaches on its own. While any extension holds
  the passkey proxy, nothing in Chromium can reach either — there is no
  pass-through, and that is a property of the browser's API rather than a
  choice made here. Costs no passphrase, for the same reason refusing does
  not: saying "not with this authenticator" on someone's behalf denies nobody
  anything they had.
- **A kill switch in the extension's popup**, which is the same capability
  without the timer, and a mode indicator that says which of attached, off,
  standing aside, or blocked by another extension is true right now.
- **`docs/COMPAT.md`** — what Black-Bag depends on in other people's software,
  quoted from their source with the line numbers it was read at: Chromium
  writing the caller origin itself and refusing a pre-filled one, its
  conditional-mediation refusal, and the ungated permission. The site matrix is
  deliberately empty until each row is a ceremony somebody completed.

### Fixed — the extension, three ways, each found by running it

- **Every login opened two full-screen ceremony windows.** A large block of
  `sw.js` had been pasted twice: the request listeners were registered twice,
  and the stale copy of every function silently won, because a duplicate
  function declaration in JavaScript is a redefinition rather than an error.
  Two identical fullscreen windows stacked look exactly like one.
- **Standing aside did nothing at all**, three times over: the detach happened
  before the request was completed and Chromium refuses that (reporting it by
  *resolving* with an error string, which was dropped); `detach()` was guarded
  on an in-memory `attached` flag that a revived service worker starts with
  false while Chromium still has the extension attached; and the re-attach was
  a `setTimeout` in a worker that is torn down long before a minute is up, with
  nothing else able to wake it because no ceremony arrives while detached. It
  takes an alarm — hence the one new permission.
- **Opening the popup took the proxy back.** It called `attach()` to find out
  whether it was attached, so checking the status mid-stand-down cancelled the
  stand-down. It asks the worker now.
- **The kill switch worked exactly once from the keyboard.** Disabling a
  focused element hands focus to the document.

### Changed — a reply from another build says so

- `session::ask` turns an unknown response variant into "these are different
  versions" rather than passing serde's wording through. "unknown variant
  `passkey_use_security_key`, expected one of …" is accurate and sends a reader
  hunting for a protocol bug; what it means is that a browser spawned the
  *installed* binary as its native messaging host while a freshly built agent
  was serving.

### Added — checks earned by the above

- **`extension/tests/structure.test.js`** — one listener per event, one
  definition per function, no surface that can approve, no permission that is
  not used, and reading state does not change it. Every rule was checked
  against the code that broke it.
- **`extension/tests/api-surface.test.js`** — the API members `sw.js` calls and
  the table in `docs/COMPAT.md` must be the same set. Documentation that has
  quietly stopped matching sends the next reader to check the wrong thing.
- The `chrome` stub in the encoding tests is a Proxy now, so reaching for one
  more browser API is only a failure when a test actually depends on it.

### Added — nothing reads a secret without being asked about, once, per use

- **An approval is per (program, item, capability).** Reading a value onto the
  screen and copying it onto the clipboard are different exposures — the
  clipboard is readable by every other process in the session and outlives the
  glance — so approving one does not approve the other, in either direction.
  Live TOTP codes go through the same gate; they were previously served to
  anything that asked.
- **An approval costs the master passphrase, never a click.** A same-uid
  process can synthesise a click with `wtype` or `hyprctl`, so a click proves
  nothing about who is at the keyboard. The proof is checked against the *open
  vault's own header*, not by re-reading the file at the path, which any
  same-uid process can swap between the check and the read.
- **`black-bag audit`** — an append-only hash-chained record of every decision,
  read from the file rather than asked of the agent, because a history you can
  only get by asking the thing being audited is not much of a history.
  `--verify` says whether the chain still holds and where it breaks.
- **`black-bag backup`** — a copy of the sealed vault. Nothing is decrypted, so
  it needs no passphrase and works while you are locked out, which is exactly
  when you may want it. The copy is read back and its digest checked before it
  is recorded; `--list` and `--verify` say what is known and whether it is
  still true. A recovery key is not a substitute: that opens this vault, and is
  no use if the file itself is gone.
- **The deck grew two sections** (`^M`): **ACCESS** shows what is approved right
  now, what happened, and whether the record still holds — with revoke, a
  lockdown switch that denies everything including approved and trusted
  programs, and a keyboard path for all of it, because a security control you
  can only work with a mouse is one that does not get used in the moment it is
  needed. **BACKUP** takes and checks copies. Both exist because the owner
  drives the GUI; a control that lives only in a terminal does not get used.

### Changed — the backup-state flag now means something

- **BS is computed and truthful.** It is 1 only while a recorded copy of this
  vault, taken at or after the epoch this credential was written in, is still
  where it was left. It is read live on every ceremony, so deleting the copy
  turns it off again — which is what makes it a fact rather than a one-way
  boast. Setting it unconditionally would tell relying parties something untrue
  in order to look like a synced passkey.
- **BE stays 1 and never moves.** This credential is multi-device capable by
  construction: the vault it lives in is a file, and a file can be copied.
  `BE=0, BS=1` is forbidden by WebAuthn L3 §6.1.3 and is unrepresentable here;
  the whole flag space is walked in `passkey::flag_state_machine`.
- **Known limit, stated rather than papered over:** a copy that still exists
  but has been *replaced* is not detected until `backup --verify` re-reads it.
  A digest on every assertion would put a disk read in the signing path.

### Fixed — a status refresh could take a master passphrase out of the sheet

- **The passkey status handler tore down the record approval sheet.** The agent
  republishes status on every state change, so any refresh — including the
  deck's own thirty-second safety net — cancelled an approval somebody was
  part-way through typing. The sheet vanished mid-passphrase, the deck's key
  gate reopened, and the rest of the passphrase arrived as shortcuts: `e`
  opened the record editor and the remaining characters were typed into a
  record field. Reproduced on the rig, fixed, and pinned by a structural test.
- **A management section could arrive without a verb.** BACKUP reached the rail
  and the `Ctrl+Return` action but not its label, so the chord worked and the
  footer said nothing about it. Now every section must appear in all three
  lists, checked by `tests/structure.py`.
- **`audit --json` printed a sentence on the JSON stream** when the log was
  empty. A reader parsing one object per line should never have to skip prose.

### Added — checks that would have caught the above

- **`plugin/khephri.blackbag/tests/structure.py`** — invariants about the QML
  that no type checker can see. Each rule is there because breaking it caused a
  real failure, each names that failure in a comment, and every rule was
  mutation-tested to confirm it bites. Run by `tests/run.sh` and by CI.
- **A tracked pre-commit secret scan** (`.githooks/pre-commit`, enabled with
  `git config core.hooksPath .githooks`). This project published a crates.io
  token in six releases; the hook uses `gitleaks` when installed and a smaller
  built-in scan when not, so a machine without `gitleaks` is not a machine
  without a check.
- **CI now runs the extension's encoding tests**, which were never running
  there.
- **One name per thing.** `Capability` and `Surface` serialise to exactly what
  their `as_str` writes — the audit digest is computed over one and the wire
  carries the other, and two spellings of one capability is what makes a log
  hard to trust. Pinned by tests in both modules.

### Added — passkeys, and the WebAuthn core that makes them possible

- **`Kind::Passkey` and `crates/blackbag-core/src/passkey.rs`** — ES256
  credential creation and assertion, COSE key encoding, `fmt: "none"`
  attestation, authenticator-data assembly, and the WebAuthn PRF. Private keys
  live in the vault in locked memory and are signed with in-process; nothing
  outside ever holds key material.
- **Verified against an implementation that shares no code with ours.**
  `cargo run --example passkey_vector` emits a real registration and assertion;
  `crates/blackbag-core/tests/passkey_cross_check.py` parses them with Python's
  `cbor2` and `cryptography` the way a relying party does — walking the
  authenticator data by offset, rebuilding the P-256 key from the COSE
  coordinates alone, verifying the signature over
  `authData || SHA-256(clientDataJSON)` — and accepts them. Our own tests only
  prove the two halves of one library agree with each other.
- **Origin binding is enforced here, because nothing else enforces it.**
  Chromium's proxy API does not check that a returned assertion names the
  origin it asked about, that the `rpIdHash` matches, or that the signature
  verifies — measured, not assumed. `Credential::assert` refuses to sign unless
  the relying-party id is a registrable-domain suffix of the caller origin, the
  suffix match lands on a label boundary, and the origin is a secure context.
- **No signature counter**, deliberately: WebAuthn L3 §6.1.1 makes it a SHOULD
  and §7.2 skips the clone check when it is zero. On a vault that can be
  restored from backup a counter invents clone warnings and hands relying
  parties a correlation handle.

### Fixed — the rollback tripwire could be disarmed with `rm`

- **The witness failed open.** `Witness::load` ended in
  `.ok().and_then(..).unwrap_or_default()`, so an unreadable, truncated or
  malformed witness silently became an *empty* one — and an empty witness has
  seen no epochs, so `check` reported no rollback. Deleting or corrupting a
  file turned the anti-rollback mechanism off, which is strictly easier than
  the restore-an-old-vault attack it exists to catch. It now distinguishes
  absent (first run, benign) from unusable (reported), and the decision is
  tested against its own file rather than the one every other test shares.
- **`ed25519-dalek` was a declared dependency with no references anywhere** —
  pure supply-chain surface on a security-critical path. Removed. The workspace
  MSRV was also declared as 1.82 while `ml-kem` 0.3.2 requires 1.85.


### Added — the deck can now manage the vault, not just its records

- **A management sheet on `Ctrl+M`** with six sections: passphrase, recovery
  keys, import, export, generator and settings. Everything the engine could
  already do to a vault had, until now, no surface in the deck at all — a
  GUI-only owner could not change a passphrase, raise a work factor, mint or
  revoke a recovery key, import from another manager, or take a backup.
- **Raise the work factor without changing the passphrase.** The hygiene card
  has always been able to say "Argon2 cost is below the current default"; it
  now has a button that acts on it. Both this and a passphrase change re-wrap
  every recipient, so existing recovery keys keep working.
- **Import previews before it writes.** PREVIEW parses the file and reports
  what it found and what it skipped *without opening the vault*, and IMPORT
  stays disabled until it has. `Ctrl+Enter` walks the two steps in order.
- **The sheet is fully keyboard-driven**, like the rest of the deck:
  `Ctrl+1`–`Ctrl+6` jump to a section, `Ctrl+↑`/`Ctrl+↓` walk them, and
  `Ctrl+Enter` runs the section's primary verb. The accelerators are drawn on
  the rail and the footer names the verb, so neither is a chord to remember.
  Buttons take `Tab` focus and draw a focus ring; a chooser is one tab stop
  that arrows within itself, the way a radio group should.

### Fixed

- **A chooser never showed which option was selected, and its chips did
  nothing when clicked.** The chip delegate reached for `parent.parent`, but a
  `Repeater` parents its delegates to the `Flow` itself, so the binding read
  one level too high: `active` was never true and the tap handler's target
  came back `undefined`. Bound to the flow directly.
- **The management sheet's rail ate the whole window.** A nested layout
  defaults to `Layout.fillWidth: true` in Qt, so a bare `preferredWidth` was
  only a hint and the content panel was squeezed to a few pixels at the right
  edge. The rail is pinned at all three widths.
- **A successful import reported what it had parsed, not what it had
  written.** The engine prints the parse summary first and the write
  confirmation second; the deck took line one, so the one moment the user
  needed to be told "3 records went in" said "3 records were read".
- **The installer never actually deployed the plugin.** Omarchy's registry
  scans `~/.config/omarchy/plugins` and nowhere else, but `install.sh` only
  wired up `shell.json`, the keybinding and the unit — the surfaces themselves
  had been copied by hand. A whole new sheet could be written, built, tested
  and "installed" while the live shell went on loading the previous version.
  It now copies every surface it finds, rather than a hand-kept list.
- **The generated systemd unit had the character it was explaining removed
  from it.** The heredoc was unquoted, so the backticks in the
  `ReadWritePaths` comment ran as command substitution: the install printed
  `-: command not found` and wrote `# Leading  so a directory…` into the unit.
- **Two memory tests asserted on process-global counters** that every other
  test in the binary moves, so they failed under load and at high
  `--test-threads` while the code was working. `many_small_secrets_pack_into_
  one_slab` now asserts packing on the addresses themselves, and the
  `/proc/self/mem` scan's coverage floor is absolute instead of a fraction of
  a mapped total that grows with the harness's thread count. Ten consecutive
  runs at `--test-threads=64` are clean.
- `clippy`: an `assign_op_pattern` in `vault.rs`.

## [2.5.0] — 2026-09-02

The release that came out of treating the product as a target. Every item
below was found by running the thing and watching, and each fix carries a
test that fails on the old behaviour.

### Fixed — the clipboard never cleared, and Omarchy was recording it

- **The 30-second clear was a fiction.** `--to clipboard` spawned `wl-copy`
  and a thread that would kill it after the timeout; the command returned a
  few milliseconds later and took the thread with it. The value stayed on
  the clipboard until something else was copied. Both surfaces made the
  same promise through the same command.
- **Every copied secret landed in Omarchy's clipboard history**, a
  plaintext file in `~/.local/state`. The shell's capture script skips
  offers that carry the `x-kde-passwordManagerHint` MIME type — as cliphist,
  KDE and GNOME do — and `wl-copy --type text/plain` offered no such hint.
- The clipboard is now served by a detached helper spawned from this binary
  (`clip-serve`, hidden from help), speaking the data-control protocol
  through `wl-clipboard-rs`. It offers the hint alongside the text, runs
  with core dumps off and its memory locked, clears on time **only if the
  selection is still ours** — a value you copied later is never wiped — and
  the caller does not say "copied" until the compositor has been seen
  offering the value.

### Changed — every resting secret is ciphertext in memory

- Page-locking was the predecessor's answer and it had a hole: `mlock` is
  page-granular and not reference-counted, so two short secrets sharing a
  page each locked it, and dropping the first unlocked the page under the
  second. Now every secret this process holds — each record field, the
  vault's data key — rests sealed under a 32-byte per-process session key.
- **The key lives in `memfd_secret` memory**, which the kernel removes from
  its own direct map: never swapped, never dumped, never in a hibernation
  image, unreadable through `/proc/<pid>/mem` even for root. Where the
  kernel does not offer it, one locked page holds the key and `doctor`
  says so. Set `BLACK_BAG_NO_SECRETMEM=1` to opt out (secret memory blocks
  hibernation system-wide while held).
- Plaintext exists only while a field is in use, in a small locked arena of
  slabs the engine maps itself, and is wiped when the use ends. The
  decrypted payload, the serialised payload and the decoder's scratch live
  there too, so no secret byte crosses unlocked memory between the file and
  a record. What must never reach disk shrank from the whole vault to 32
  bytes, and the 8 MiB memlock budget no longer bounds a vault's size.
- A test reads `/proc/self/mem` across every writable mapping and asserts a
  resting secret's plaintext is found nowhere. The vault format is
  unchanged; a v2 file written by 2.4.1 opens as before.

### Added — the vault seals when the machine does

- **Suspend and screen lock lock the vault.** The agent subscribes to
  logind's `PrepareForSleep` and `Session.Lock` signals through a
  hand-written minimal D-Bus client (SASL EXTERNAL, `Hello`, two
  `AddMatch` calls, a bounds-checked parser that drops what it cannot read),
  and the Omarchy plugin additionally watches the shell's own lock service,
  which never touches logind. The reason for the last lock is reported —
  *locked before suspend*, *locked with the screen* — in the deck.
- **A hard session ceiling.** Idle expiry alone let a session that was
  touched every few minutes stay open for days. `agent serve --max-secs`
  (default 12 h, 0 to disable) ends the session regardless of activity; the
  deck shows when.
- **A silent peer can no longer stall the agent.** One connection that sent
  nothing used to hold every other client — and idle expiry — hostage. Each
  peer now gets three seconds to send its line and take its reply.
- The agent holds the vault's advisory lock across every mutation, the same
  lock the CLI takes, and the file stamp includes the inode so a padded
  write of identical length is never mistaken for no change.

### Added — breach checking, on request, with the hash kept at home

- `black-bag agent breach --online` and the deck's CHECK BREACHES button
  (armed and confirmed like a delete) check password fields against Pwned
  Passwords by k-anonymity. The agent hands out five-character SHA-1
  prefixes; `curl` fetches the buckets with padding; the agent matches
  against the full hash it never disclosed, and folds exposures into the
  hygiene report for the rest of the session. The agent itself has no
  network access at all (`RestrictAddressFamilies=AF_UNIX`).

### Added — import and export

- `black-bag import --format bitwarden|keepassxc|firefox|chrome|csv --from
  FILE` (with `--dry-run`), parsed by hand and mapped kind by kind; skipped
  rows are reported by reason, never by value.
- `black-bag export --to FILE --format json|keepassxc --plaintext-ok`,
  0600, never overwrites, and tells you to shred it afterwards. Our own
  KeePassXC CSV round-trips every kind.

### Changed — the deck, after an adversarial review

- Dismissing the deck now empties both sheets and the record list; a
  host-initiated close used to leave a half-typed master passphrase in the
  first-run sheet.
- "locked" is announced only when the agent confirmed the lock.
- A reveal or 2FA code that arrives for a record no longer selected is
  dropped rather than rendered under the new name; a second copy, reveal or
  fetch while one is in flight is refused out loud instead of silently.
- Settings are clamped: a file cannot pin a secret on screen forever or set
  a clear delay of zero.
- The first-run sheet has a two-minute watchdog and can always be left;
  skipping the recovery key takes two presses.
- Multi-line secrets are covered until revealed; Copy is disabled for any
  masked field; generated passwords are shown for the reveal window and
  then masked again; every secret box has a show/hide toggle.
- The hygiene card has an *unavailable* state, orders findings worst-first,
  and a finding for a filtered-out record clears the filter to reach it.
- The SESSION card shows the ceiling, the last lock reason and whether
  suspend and screen lock are watched; HOST POSTURE shows where the session
  key lives.
- Buttons take focus, a focus ring, Space and Enter, and carry names for
  assistive technology. Footer notes expire. The status file is polled
  every 15 s instead of 5 (it is watched anyway).

### Changed — the agent's sandbox

- `RestrictAddressFamilies=AF_UNIX`, an empty capability set,
  `SystemCallFilter=@system-service memfd_secret` with `@privileged`
  denied, private devices, no IPC, `UMask=0077`. Validated as a transient
  unit before it replaced the installed one.

### Added — the deck can finally use a recovery key

The first-run sheet would talk you into minting a recovery key, and the deck
then had no way to use one. A person who only ever opens the app, and who
forgets the passphrase, was locked out of their own vault by the surface that
had asked them to make the key — the key sitting on their desk, which opens
it. The CLI could always do it, which is no help to someone who does not use
a terminal.

- **`Ctrl+K` on the sealed screen**, and a visible *forgotten it? unlock with
  a recovery key* line, shown **only when `status.json` lists a recipient
  whose private key is held outside the vault**. A deck that offers to
  recover a vault that cannot be recovered would be worse than a quiet one.
- A two-step sheet: the key file (defaulting to where first run writes it,
  and naming the labels this vault accepts), then a new master passphrase
  twice with a show toggle and a live character count. It runs
  `black-bag recovery use`, so the vault is re-keyed and the recovery key is
  re-wrapped and keeps working.
- The passphrase reaches the engine on stdin, never argv. Nothing is retained:
  `clear()` runs on every exit path and the deck's own `clearSecrets()` calls
  it. `Esc` always works, including while the engine is busy, and a
  two-minute watchdog releases the sheet if the engine never answers.
- Verified headless end to end: the offer appears, the sheet drives, the
  vault is re-keyed, the deck unlocks itself with the new passphrase, the old
  one stops working and the recovery key still opens the vault.

### Fixed — what an adversarial review of the above then found

Everything in this release was put through a multi-agent review in which each
reported defect faced three independent reviewers instructed to refute it.
Twenty-five findings survived that and are fixed here; sixty did not survive
and were dropped. Several of the survivors were in the new work itself, which
is the point of running it.

- **The central memory claim was false at the point of encryption.**
  `crypto::seal` called `aead::Aead::encrypt`, whose blanket implementation
  stages the entire plaintext in a fresh heap `Vec` before encrypting it, so
  every save put the whole padded vault — and every wrap the data key — into
  swappable memory. `Guarded::new` did `plain.to_vec()` on a locked buffer,
  copying each record field straight back out. Both now encrypt in place
  inside the arena. `crypto.rs` no longer imports `Aead` at all.
- **The `/proc/self/mem` test could not see what it existed to catch.** Its
  setup ran after the secret work, reusing exactly the frames and heap chunks
  a residue occupies, and one unreadable page discarded its whole mapping — a
  528-page worker stack thrown away for the sake of 16. It now does the secret
  work on a parked worker thread, builds the scanner afterwards, reads chunked
  with a page-level fallback, accounts for every page it could not read, and
  must find a deliberately planted needle before its silence counts as
  evidence. `memfd_secret`'s guarantee is asserted directly in a test of its
  own.
- **`SecretBuf::zeroed` returned uninitialised memory** on the fallback path —
  a `&[u8]` over a recycled allocation, undefined behaviour whatever the
  caller does next. `round_up` and `Slab::map` wrapped near `usize::MAX`.
- **A local process could blind the sleep watcher.** Any parse or size failure
  ended the connection, after which it slept a flat twenty seconds: one
  malformed unicast signal every nineteen seconds kept the vault's suspend
  guard off the bus indefinitely. Unreadable messages are now consumed and
  skipped, oversized ones drained, unknown header fields stepped over per the
  specification, and the backoff starts at one second.
- **A local process could forge a lock.** The bus rewrites `SENDER` to a
  unique name, so the check against `org.freedesktop.login1` never fired, and
  match rules are never consulted for a signal addressed to one connection.
  The watcher now learns logind's unique name, re-learns it on
  `NameOwnerChanged`, requires it, and refuses signals carrying a destination.
  `Session.Lock` is scoped to this process's own session where logind knows
  of one. All measured against the real system bus, before and after.
- **Breach verdicts lied in both directions.** A failed or partial fetch
  erased earlier findings — one HTTP 429 downgraded a known-exposed password
  to *not exposed*. And a verdict outlived the password it described. Both
  fixed; verdicts now survive a fetch they could not make and die with the
  value they described.
- **The breach request counted your passwords.** One request per distinct
  password revealed exactly how many there were, and successive runs revealed
  when one changed. The list is now padded with random decoys to a multiple
  of eight and shuffled. `curl` also ran without `-q`, so an `-o` line in the
  user's `~/.curlrc` sent the body to a file and the empty result read as
  "not in the corpus".
- **The 2FA shared secret went into an unwiped dependency.** `totp-rs` is
  gone; HOTP is computed here against the RFC 6238 and RFC 4226 vectors, with
  the secret borrowed from the arena. The full SHA-1 of every password is
  now built in a `Zeroizing` buffer too.
- **Import and export.** The exporter and importer disagreed about which
  field the Password column holds, so a key with a passphrase came back
  swapped; a CSV export was open to spreadsheet formula injection; a
  Bitwarden custom field named `password` or `totp` silently replaced the
  real one; blank lines and unrecognisable headers imported junk. All fixed,
  and the JSON export now imports back whole, so a backup is restorable.
- **Six defects in the deck**, including a first-run sheet that could be
  stranded past step one with no way forward, a multi-line "cover" that was
  paint over a field still accepting keystrokes, a 2FA fetch that was dropped
  and never re-issued, results that repopulated a closed deck, and a
  screen-lock hook that missed an unlock completing behind the lock screen.

### Fixed — tests wrote into the operator's state

- Every test that created a vault used to record its epoch in the real
  `~/.local/state/black-bag/witness.json`, and a test agent overwrote the
  live `status.json`. Both now go to a private directory.

[2.5.0]: https://github.com/AnubisQuantumCipher/blackbag/releases/tag/v2.5.0

## [2.4.1] — 2026-08-30

### Added — deleting a record is now a first-class act

Deleting was keyboard-only, and worse, its confirmation step was invisible:
the first `del` changed nothing on screen, so the safety asked its question in
silence and the whole flow read as a dead key.

- **The two-step confirm is drawn.** The first `del` — or the first click —
  arms it visibly: the DELETE button flips to `SURE? CLICK AGAIN` and an
  urgent banner names the record: *delete "Email Two"? — no undo and no trash
  — del or the button confirms · esc backs out.* Key and click arm and
  confirm the same state, so whichever hand started it, either can finish it.
- **The inspector has EDIT and DELETE buttons.** A lifecycle you can only
  drive from the keyboard is half a lifecycle.
- **Right-click on a record row opens a menu**: copy the primary field, show
  it on the countdown, copy the 2FA code (when there is one), edit, delete.
  Every entry is a verb the keyboard already had; the menu is how the mouse
  gets them.
- Selecting a different record, pressing Esc, or locking disarms a pending
  delete; nothing is ever deleted by a single input.

[2.4.1]: https://github.com/AnubisQuantumCipher/blackbag/releases/tag/v2.4.1

## [2.4.0] — 2026-08-30

### Fixed — "I hit CREATE and nothing happened"

Driven by a field report of exactly that, reproduced live, and each fix
verified against a throwaway vault.

- **A not-ready save button swallowed clicks silently.** CREATE/SAVE was
  disabled while validation had complaints, and a disabled button eats the
  click and says nothing — which reads as a broken app, not as "you left the
  title empty". The button now takes the click even while dimmed, and answers
  with exactly what is missing ("still needs a title"), loudly. The first-run
  sheet's CREATE VAULT had the same defect and got the same fix.
- **The app never showed a saved record — CREATE looked dead even when it
  worked.** The desktop app's stdout collector accumulated across runs of the
  same process instead of starting each run empty the way Quickshell's does.
  The first successful save triggered a list refresh whose output landed
  appended to the previous run's, the JSON parse threw, and the record list
  was broken for the rest of the session — so a record could save perfectly
  and never appear. Sinks now reset at the start of every run, and the reset
  overwrites the old buffer before releasing it, since it routinely holds a
  revealed secret. App-only; the plugin always used Quickshell's collectors.
- **Enter in a field did nothing.** It now moves to the next field, and on the
  last field it saves — the same rhythm the first-run sheet already taught.
  When the form is not ready it says what is missing instead of silence.
- **The form remembered the previous visit.** The attribute fields seed by
  binding, and a binding on a text field dies the first time someone types in
  it — so a form once used showed that session's values forever after: the
  previous record's username on a fresh "new login", one record's attributes
  under another's edit, and a saved password still sitting in the widget.
  Every open now reseeds every field imperatively, secret boxes always open
  empty, and a successful save wipes them before closing.
- **An idle-lock during an edit wedged Esc.** The editor sat open invisibly
  under the sealed screen — holding whatever password was mid-type — and the
  sealed screen's own shortcuts are gated on the editor being closed, so Esc
  went completely dead. A lock now dismisses the editor, which also wipes its
  fields.
- **Esc-Esc from the search box closed the whole window.** First Esc clears
  the query; the second used to fall through to dismiss. It now hands the
  keyboard back to the record list, which is where every instinct expects to
  land.

### Fixed — from the keyboard audit

A 19-agent adversarial audit traced every advertised key to its handler and
drove the real QML in compiled harnesses. It also caught a defect introduced
and removed within this same cycle — a duplicate set of editor shortcuts that
Qt would have resolved as ambiguous, deadening Esc, ^⏎ and ^G whenever the
editor was open — before it ever shipped. What did ship:

- **An invisible passphrase field could eat the whole keyboard.** Three ways
  in: opening the deck while `status.json` was stale focused a field that was
  not on screen; an unlock arriving from outside (the CLI, a status catch-up)
  left focus on the now-hidden field; and the first-run sheet standing down
  stranded focus on its own hidden input. In each, every footer key silently
  accumulated in a hidden passphrase buffer — and Enter shipped that garbage
  to the agent. Focus now goes only to fields that are visible, and every
  transition hands the keyboard back to the deck.
- **After ^L, the sealed screen's "⏎ unlock" was a lie** — the passphrase box
  came up unfocused on the in-session lock path, so typing went nowhere until
  you clicked it. Locking now focuses it, matching a fresh open.
- **Enter on the sealed screen now always means "the way in"** — unlock, or
  reopen the offer to create a vault — instead of falling through to "copy
  the selected record" with nothing selected.
- **Advertised verbs answer instead of going silent.** e / del / ⏎ / ⇧⏎ with
  no record selected now say "no record selected"; before, they did nothing
  at all — the same silent-swallow pattern as the CREATE button.
- **Clicking a census row, hygiene entry or the filter chip now hands the
  keyboard back to the list**, so j/k work immediately instead of typing into
  the search box the caret happened to be in.
- **Tab could walk out of the editor into the deck behind it.** Qt's built-in
  window-wide focus chain moved the caret into the search box one Tab past
  the last field. Tab is now fenced inside the sheet and follows the form's
  own field order.
- **A wedged save could silently eat the next draft.** Saving while a
  previous save process was still running was a silent no-op that left the
  button reading SAVING… forever. It now says "the previous save is still
  finishing".
- **The saved deck size never survived a restart** (application only): the
  settings reader copies known keys, and `uiScale` was not one of them — so
  ⌘+/⌘- persisted a value that was then filtered out on every launch.

### Added — mouse paste

- **Right-click works in every text input** — Cut, Copy, Paste, Select all —
  in the deck, the editor and the first-run sheet, both surfaces. Qt Quick's
  text controls ship with no context menu at all, which in a password manager
  means the one thing everyone does — paste a password in with the mouse —
  silently did nothing. Cut and copy stay disabled while a field is masking
  its contents: a reveal has a countdown and an audit trail, and a context
  menu must not become the quiet way around either.

### Fixed — build system

- **A same-second write-and-build could ship stale compiled QML.** When the
  port script's write and the build landed in the same second, make read the
  tie as "up to date" and kept the old qmlcache — so a fix could be present in
  every source file and absent from the running program. The port script now
  waits out the second. This cost a full debugging session to find; the
  changelog entry is the warning shot for anyone who removes the sleep.

[2.4.0]: https://github.com/AnubisQuantumCipher/blackbag/releases/tag/v2.4.0

## [2.3.0] — 2026-08-30

### Added

- **The deck has its own type scale, and you can change it.** `⌘ +` / `⌘ -`
  (or `Ctrl`) resize the whole surface live, in 0.05 steps; `⌘ 0` clears the
  override. It applies immediately and is remembered — in the application under
  `uiScale` in `~/.config/black-bag/desktop.json`, in the plugin through the
  shell's config.
  - Command is bound alongside Ctrl deliberately: on a Mac keyboard, including
    one driving a Linux VM, Command is the key people reach for, and it arrives
    as Meta. Binding only Ctrl would make the obvious gesture do nothing.
- **A sensible default size.** The deck picks a scale from the viewport —
  about 1.5× on a 1920×1200 display — rather than inheriting the shell's, and
  normalises against the host's own base font so the same screen produces the
  same size in both surfaces and `uiScale: 1.4` means one thing rather than two.

### Fixed

- **The whole deck was sized for a bar widget.** Every surface read the shell's
  `Style` tokens directly. Those are correct in a 24px bar and far too small on
  a full-screen deck: the login screen was a postage stamp in the middle of a
  large display. `DeckMetrics.qml` now mirrors `Style`'s API and multiplies it
  by the deck's own scale, so resizing the deck does **not** resize the bar.
  296 call sites moved across.
- **The login column was pinned at 520px** however large the screen. Both terms
  of its width now scale.
- **Text inputs did not scale with the rest.** They inherit Qt Quick Controls'
  defaults, which follow the host, so their font and padding are now set
  explicitly from the deck's metric.
- **The window title never said "no vault"** — it compared against `NO_VAULT`
  while the model returns `NO VAULT`, so an empty slot read as "sealed".
- **The first-run sheet stayed open over a vault it had not created.** If a
  vault appears while the sheet is on step one — another process, or a status
  that was merely stale when it opened — it now withdraws instead of offering
  to create something that already exists.

[2.3.0]: https://github.com/AnubisQuantumCipher/blackbag/releases/tag/v2.3.0

## [2.2.0] — 2026-08-30

### Added

- **First-run vault creation in the deck.** Creating a vault was the one thing
  both surfaces handed back to a terminal, which made the terminal a required
  part of a graphical password manager. It is not any more: with no vault
  present the deck offers to make one — set a master passphrase, mint the
  offline recovery key, land in the deck. `Onboard.qml`, shared by the plugin
  and the application like the rest of the surface.
  - The passphrase reaches `black-bag init` on **stdin**, twice, and the pipe
    closes behind it. As everywhere else in this project, it never appears in
    an argument vector.
  - A **generated** passphrase is shown in plain text, deliberately. This is
    the one moment where the secret has to leave the machine and land on paper,
    and a creation screen that masks the thing you are meant to write down is a
    creation screen that guarantees a lost vault.
  - No invented strength meter. The generator's own entropy verdict is carried
    through verbatim, and a **typed** passphrase gets no score at all — the
    engine rates only what it generated, and says so.
  - Step two is the recovery recipient, because it cannot be added later to a
    vault you can no longer open. Skipping is possible and says what it costs.
- `Ctrl+G` generates and `Ctrl+↵` commits, the same chords the record editor
  already uses for the same jobs.

### Fixed

- **The `NO VAULT` screen told you to go and run `black-bag init`.** It now
  offers to do it, and `↵` on an empty slot starts the flow.
- **The generator's entropy verdict was read from the wrong stream.** The value
  goes to stdout so `black-bag gen passphrase | ...` pipes the passphrase and
  nothing else; the verdict goes to stderr. The sheet read line two of stdout
  and so displayed nothing.
- **The sheet reopened on top of the vault it had just created.** `status.json`
  is republished asynchronously, so for a moment after creation the deck still
  holds a status saying there is no vault. Unlocking after creation now goes
  through a `beginUnlock()` that skips the no-vault branch, and the offer is
  suppressed for the rest of the visit.
- **A failed record list kept asserting itself after a successful one.** The
  footer went on showing "could not read the record list" over a record list
  that was plainly on screen. A list that succeeds now clears it.
- **The agent unit could not start on a machine with no vault yet.** Its
  sandbox names `~/.local/share/black-bag` and `~/.local/state/black-bag` in
  `ReadWritePaths`, and systemd refuses to start a unit whose `ReadWritePaths`
  do not exist — with a bare `status=226/NAMESPACE` that names no path. Anyone
  who enabled the agent before running `init` hit it. The installer now creates
  both directories, and the paths carry a leading `-` so a directory removed by
  hand degrades into a readable engine-level error instead.

[2.2.0]: https://github.com/AnubisQuantumCipher/blackbag/releases/tag/v2.2.0

## [2.1.0] — 2026-08-30

### Added

- **A standalone desktop application**, `blackbag-desktop`, in `desktop/`. The
  same deck in an ordinary window rather than a Quickshell overlay, for
  desktops that are not running the Omarchy shell. Qt 6 / QML, built with
  CMake, installed under `~/.local` with a desktop entry, a scalable icon and
  AppStream metadata. It drives the engine as a child process exactly as the
  plugin does: no key material, no cryptography, and it never opens the vault
  file.
- **`desktop/port-from-plugin.py`**, which generates the application's
  `Cockpit.qml`, `Editor.qml` and `Model.js` from the plugin's. The deck is one
  implementation with two hosts, and the transformations a host is allowed to
  make are now an explicit, checkable list rather than a hand-maintained copy.
  CI runs it with `--check`.
- **CI coverage for the new surface**: a `desktop` job that builds the
  application warning-free on a clean tree and validates its desktop entry, and
  a step in the existing `plugin logic` job that fails if the shared QML has
  drifted from the plugin's.

### Note on versions

The engine is **unchanged** in this release — 2.1.0 adds a surface, not a
behaviour. The version is bumped across the workspace, the plugin manifest and
the application so that one number identifies the release, but nothing in
`crates/` differs from 2.0.1.

### Fixed

- **Two `MouseArea`s inside layouts.** The census rows and the hygiene rows each
  declared an `anchors.fill: parent` `MouseArea` as a direct child of a layout,
  which Qt reports as undefined behaviour: the `MouseArea` is given a layout
  cell of its own *and* anchored across the row it is sitting inside, quietly
  widening every affected row by an empty column. Replaced with `HoverHandler`
  and `TapHandler`, which are not items and take no cell. The plugin had the
  same defect; the standalone build is simply where Qt's warning was visible.

### Changed

- The plugin's launcher entry is now named **Black-Bag Overlay**. The standalone
  application ships an entry also called Black-Bag, and two launcher rows with
  the same name and the same icon is a coin flip rather than a choice.

[2.1.0]: https://github.com/AnubisQuantumCipher/blackbag/releases/tag/v2.1.0

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
