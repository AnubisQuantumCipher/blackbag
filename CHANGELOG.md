# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
