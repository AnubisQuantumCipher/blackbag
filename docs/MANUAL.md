# Black-Bag — user manual

For version 2.5.0 of the engine and the `khephri.blackbag` plugin.

---

## 1. What this is

Black-Bag stores credentials in a single encrypted file on this machine and
gives you two ways to reach them: a command-line tool, `black-bag`, and a
full-screen Quickshell deck bound to `SUPER+SHIFT+K`. The file is sealed with
XChaCha20-Poly1305 under a data key that is wrapped for your Argon2id-derived
passphrase key and, optionally, for one or more recovery key files you keep
offline. While the vault is open, a small agent holds the data key behind a
`0600` unix socket — sealed in memory, like every other resting secret, under
a per-process session key that lives in memory the kernel itself cannot read
where the kernel offers that (§11) — and forgets it on an idle deadline, at a
hard session ceiling, and when the machine suspends or the screen locks (§4).

What it is not, stated plainly because these absences are the design:

- **Not a sync service.** Nothing is uploaded, mirrored or backed up for you.
  If you want the vault on two machines you copy the file yourself, and the
  anti-rollback witness (§10) will notice when the two copies disagree.
- **Not a browser extension.** There is no autofill, no native messaging host,
  no page integration. You copy a value and paste it.
- **Not networked, with one exception you have to ask for by name.** The
  agent opens no sockets except the local unix socket it listens on and the
  system D-Bus socket it watches for suspend and session-lock signals; its
  systemd unit carries `RestrictAddressFamilies=AF_UNIX`, so it has no
  network path however the binary is compromised. Credential hygiene, entropy
  accounting and TOTP are all computed in this process. The one thing that
  goes online is the breach check (§7): it runs in the CLI, not the agent,
  refuses without `--online`, and sends five-character SHA-1 prefixes to
  Have I Been Pwned. Nothing about your passwords leaves the machine any
  other way.

There is no formal verification here. This is ordinary Rust with tests.

---

## 2. Requirements and install

### What you need

| | |
|---|---|
| Rust | 1.82 or newer, with `cargo` |
| OS | Linux. The engine uses `mlock`, `memfd_secret`, `prctl`, `/proc` and `SO_PEERCRED` and is not portable off it. Without `memfd_secret` (kernel 5.14+, and the agent unit allows the syscall) it falls back to a locked page and says so |
| A Wayland compositor with data-control | for `--to clipboard` and for COPY in the deck. The binary serves the clipboard itself through `wl-clipboard-rs`; `wl-copy` is no longer used and `wl-clipboard` is not required. Hyprland offers data-control |
| `curl` | only for `black-bag agent breach --online`. Nothing else in the engine touches the network |
| Omarchy shell | Quickshell with `omarchy-shell`, for the bar widget and the in-shell deck. Only the plugin needs it |
| Qt 6.5+, CMake 3.21+ | only for the standalone desktop application. Core, Gui, Qml, Quick, QuickControls2, Network, Svg |
| `python3` | used by the plugin installer to edit `shell.json`, and by the desktop port check |
| `libnotify` | optional; the plugin service uses `notify-send` for the rollback warning |

### Build and install the engine

```bash
git clone <this repo> ~/Projects/blackbag
cd ~/Projects/blackbag
cargo build --release
install -Dm755 target/release/black-bag ~/.local/bin/black-bag
```

Make sure `~/.local/bin` is on your `PATH`; the plugin invokes `black-bag` by
name and its installer refuses to run if it cannot find it.

### Install the Omarchy surfaces

```bash
cp -r plugin/khephri.blackbag ~/.config/omarchy/plugins/
~/.config/omarchy/plugins/khephri.blackbag/install.sh
```

The installer is idempotent and does five things:

1. Adds `{"id": "khephri.blackbag"}` to `bar.layout.right` in
   `~/.config/omarchy/shell.json`.
2. Appends a managed block to `~/.config/hypr/bindings.lua` binding
   `SUPER + SHIFT + K` to `omarchy-shell shell summon khephri.blackbag`.
3. Writes `~/.config/systemd/user/black-bag-agent.service`.
4. Installs `~/.local/share/applications/black-bag.desktop`.
5. Publishes a first `status.json`, rescans the shell's plugins and reloads
   Hyprland.

### Install the standalone desktop application

Optional, and independent of the plugin. Use it if you are not on the Omarchy
shell, or if you would rather have a window you can put on a workspace than an
overlay you summon.

```bash
desktop/install.sh
```

It checks that the engine is on `PATH`, verifies the shared QML is in step with
the plugin's, builds with CMake, and installs under `~/.local`: the
`blackbag-desktop` binary, a `dev.blackbag.Deck` desktop entry with "Lock the
vault now" and "Show vault and host posture" actions, a scalable icon and
AppStream metadata. `PREFIX=/usr/local desktop/install.sh` installs elsewhere.

It is the same deck as the plugin's, with three differences that follow from
being a window rather than an overlay:

- Its settings live in `~/.config/black-bag/desktop.json` rather than in the
  shell's config. The four deck settings keep the same names and the same
  defaults; see [`desktop/README.md`](../desktop/README.md).
- `Esc` at the outermost layer closes the window, and `Ctrl+Q` or `Ctrl+W`
  quits. Closing does **not** lock — the agent holds the session, and locking
  stays a deliberate act.
- A second launch raises the running window instead of opening a second one.

Like the plugin, it holds no key material and performs no cryptography: it
drives `black-bag` as a child process and renders what the engine reports.

### The agent unit

The unit is written but **not enabled**, because starting it is a decision:
a running agent is what lets an unlocked vault survive between commands.

```bash
systemctl --user enable --now black-bag-agent
systemctl --user status black-bag-agent
```

It runs `black-bag agent serve --idle-secs 900` under a strict sandbox —
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only` with three
explicit `ReadWritePaths`, `MemoryDenyWriteExecute`, `LimitCORE=0`, and,
since 2.5.0: `RestrictAddressFamilies=AF_UNIX` (the agent can open unix
sockets and nothing else — no network path exists), an empty
`CapabilityBoundingSet=`, `SystemCallFilter=@system-service memfd_secret`
with `SystemCallFilter=~@privileged` and `SystemCallErrorNumber=EPERM`,
`PrivateDevices`, `RemoveIPC`, `UMask=0077`, `ProtectClock`,
`ProtectHostname`, `ProtectKernelLogs` and `RestrictSUIDSGID`. The unit is
in `plugin/khephri.blackbag/install.sh` if you want to read the whole thing.

To change the idle timeout, or to set the session ceiling
(`--max-secs`, default 43200 — twelve hours — and `0` to disable), edit
`ExecStart` in that file and `systemctl --user daemon-reload`.

The CLI does not need the agent. `black-bag list`, `get`, `add` and the rest
open the vault themselves and ask for the passphrase every time. The agent
exists so that the deck, and repeated CLI use, do not.

### Settings

The plugin reads its settings from the `khephri.blackbag` entry in
`~/.config/omarchy/shell.json` (`bar.layout.right`), merged over the defaults
in its `manifest.json`. The standalone application reads the same names from
`~/.config/black-bag/desktop.json`. Every value is clamped by
`Model.clampSettings` in `plugin/khephri.blackbag/Model.js`; a file cannot
push past these bounds, because a reveal timeout of zero would leave a secret
on screen forever and a clear delay of zero would never clear.

| Setting | Default | Accepted | What it does |
|---|---|---|---|
| `pollIntervalSec` | 15 | 2–120 | How often the service runs `black-bag status --publish`. The file is also watched, so this is a floor on freshness, not the only source |
| `staleAfterSec` | 120 | 10–3600 | Age at which `status.json` is drawn desaturated rather than trusted |
| `clipboardClearSec` | 30 | 5–600 | Seconds before a copied value is cleared. The CLI accepts up to 3600 and `0` for never; the deck does not |
| `revealSeconds` | 10 | 3–120 | How long SHOW, the editor's eye, and a freshly generated password stay readable |
| `uiScale` | 0 | 0, or 0.7–3.0 | Deck size. `0` means "from the viewport"; anything else is an absolute scale, never above what the window can hold |
| `motionEnabled` | true | boolean | Animations on or off |

Out-of-range numbers are rounded and pinned to the nearest bound, and a value
that is not a number is dropped so the default applies. The poll default was
5 s before 2.5.0.

---

## 3. First run

### From the deck (no terminal needed)

Open the deck with nothing at the vault path and it offers to create one.
`↵` on the empty slot, or the sheet appears on its own.

1. **Set a master passphrase.** Type one, or press `Ctrl+G` to have the engine
   generate one. A generated passphrase is shown in **plain text** on purpose —
   this is the moment to write it down, and it is the last time it is displayed.
   The engine's own entropy verdict is shown beside it. A passphrase you typed
   gets no score, because the engine rates only what it generated.
2. **Mint the recovery key.** This cannot be added later to a vault you can no
   longer open, so it is step two and not an afterthought. Move the file to
   offline media.
3. **Open the deck.** It unlocks with the passphrase you just proved.

`Ctrl+↵` commits either step; `Esc` abandons. Nothing is written until you
commit, and the passphrase crosses to the engine on stdin.

### From the terminal

```bash
black-bag init
```

You are asked for a passphrase twice. Nothing is echoed. The vault is created
at `~/.local/share/black-bag/vault.cbor` with mode `0600`, with Argon2id at
256 MiB, time cost 10, and lanes set to your core count clamped to 4–8. On the
machine this manual was written on — an 8-vCPU aarch64 virtual machine — an
unlock at those parameters measured about 1.3 s; your hardware will differ.

`--mem-kib` changes the memory cost; the floor is 32768 (32 MiB) and the
default is 262144 (256 MiB). Choosing less than the default is legal and will
show up forever after as a `KDF_BELOW_DEFAULT` warning in `doctor` and in the
deck, until you `rekey` upward.

### Choosing a passphrase

This is the one secret nothing else can recover for you. If it is short, a
note is printed — a note, not a refusal, because a tool that rejects your
passphrase is a tool you end up storing your passphrase in a file to satisfy.
The advice is the honest one: a six-word phrase drawn at random resists
offline cracking far better than a short complex string.
`black-bag gen passphrase` will mint one and tell you exactly what it is
worth.

### Add a recovery recipient before you need it

```bash
black-bag recovery add offsite --out ~/black-bag-recovery.key
```

Do this on day one. It writes a `0600` JSON file containing an X25519 secret
and an ML-KEM-1024 seed. Those private halves exist **only** in that file —
the vault keeps the public halves and the encapsulations to them. That is why
this lane is worth having, and it is the specific thing the predecessor crate
got wrong.

That file opens your vault without the passphrase. Treat it exactly as you
would treat the vault plus the passphrase together. §6 covers where to put it.

---

## 4. Everyday use in the cockpit

Press `SUPER+SHIFT+K`, or click the lock in the bar. The deck is a full-screen
overlay that takes exclusive keyboard focus.

The deck is **keyboard-first**, and honestly so: everything except choosing a
record kind in the editor has a key, and the mouse is a convenience layered on
top. If you drive it with the pointer you will find yourself reaching for keys
anyway.

### The sealed screen

While the vault is locked you get a wordmark, a rule, and a passphrase field —
and nothing else, unless there is something worth saying. What can appear
above the wordmark:

| Condition | What it says | Can you still type? |
|---|---|---|
| No status published | `NO STATUS PUBLISHED` | no field is shown |
| No vault at that path | `NO VAULT AT THIS PATH` | no field is shown |
| Status has no host section | `HOST POSTURE UNKNOWN` | yes |
| A debugger is attached | `A DEBUGGER IS ATTACHED TO THIS SESSION` | **no — input is blocked** |
| `mlock` is not working | `MEMORY LOCKING IS NOT WORKING` | yes |
| Vault epoch is behind the witness | `THIS FILE IS OLDER THAN THE LAST ONE SEEN HERE` | yes, and the button reads *unlock anyway* |

Swap being active, a tight memlock budget and a below-default KDF are real
findings and are deliberately **not** shown here. They are permanent facts of
this machine, and a sealed screen that always shouts is a sealed screen nobody
reads. They live in the left rail once you are in.

Typing the passphrase and pressing Enter runs `black-bag agent unlock` and
sends the passphrase on the child's stdin. Argon2id at time cost 10 takes a
noticeable moment; the rule animates so the screen does not look dead.

### Once open

- **Left rail** — vault state, format and epoch against the witness, a
  twelve-kind census, the recipient list marked `OFFLINE KEY` or `PASSPHRASE`,
  and host posture. Clicking a census row filters the table to that kind;
  clicking it again clears it.
- **Centre** — a search box and the record table. Search covers titles, kind
  names, tags and the subtitle built from open attributes (username, service,
  URL, SSID, account). It cannot reach secrets: the deck never has them.
- **Right rail** — the inspector for the selected record, the live TOTP card
  when there is one, the HYGIENE card with findings worst-first and the
  CHECK BREACHES button, and the SESSION card.

### The cards

**SESSION** carries LOCK NOW and REFRESH and, under them, rows built by
`Model.sessionRows` from what the agent reported — never inferred:

| Row | What it shows |
|---|---|
| `idle timeout` | The agent's `--idle-secs` (900 by default) |
| `unlocked by` | How the session was opened, as the agent reports it, while open |
| `ends regardless` | The clock time and countdown at which the session ceiling closes it, however busy you are (`--max-secs`, twelve hours by default). Reads `session ceiling · off` if the agent runs with `--max-secs 0` |
| `last lock` | While locked: why — *locked by hand*, *locked after idling*, *locked at the session ceiling*, *locked before suspend*, *locked with the screen*, *locked: re-keyed elsewhere*, *locked: agent stopped* |
| `suspend & screen lock` | `locks the vault` when the agent's D-Bus watcher is connected to logind; `not watched` with the watcher's own reason when it is not (§4, *How the vault locks*) |

**HOST POSTURE** gained a `session key` row: `kernel-invisible` when the
per-process key lives in `memfd_secret` memory, `locked page` when it lives in
one locked arena page instead, and `UNLOCKED` — drawn as a warning — when
neither was possible and the key may be swapped. Every resting secret is
ciphertext under that key, so this row is the one that says what the rest of
the memory posture is worth. §10 covers the other rows.

**HYGIENE** is computed locally (§7). Its CHECK BREACHES button is the one
act in the deck that goes online, and it is armed like a delete: the first
press, or `Ctrl+B`, flips it to `SURE? CHECK ONLINE` and prints what is about
to leave the machine — the first five characters of each password's SHA-1,
and nothing else; the second press or `Ctrl+B` runs
`black-bag agent breach --online --json`; `Esc` backs out. Exposures are
folded into the card as `EXPOSED` findings for the rest of the session.

Footer notes such as *copied password* expire after seven seconds, so the
footer never asserts a clipboard state that has long since changed. Every
button in the deck takes focus with `Tab`, shows a focus ring, and can be
pressed with `Space` or `Enter`.

### Copying, showing, and 2FA

`Enter` copies the selected record's primary secret field to the clipboard via
`black-bag agent reveal --to clipboard --clear-after <clipboardClearSec>`. The
value never renders in the deck. What happens, exactly
(`crates/blackbag-cli/src/clipboard.rs`):

1. The command spawns a detached helper from its own executable
   (`black-bag clip-serve`, hidden from `--help` and not for hand use) in a
   new session, so it outlives the command and the terminal. The value goes
   to the helper on stdin, never on argv.
2. The helper offers the value on the regular Wayland clipboard through
   `wl-clipboard-rs` as `text/plain;charset=utf-8` and `text/plain`, and
   alongside them a third offer, `x-kde-passwordManagerHint` with the payload
   `secret`. That hint is what clipboard managers check before recording an
   entry: Omarchy's own capture script, cliphist, KDE and GNOME skip an offer
   that carries it. Before 2.5.0 the value went through `wl-copy` with no
   hint and every copied password landed in
   `~/.local/state/omarchy/clipboard-history.json`. A manager that does not
   honour the hint will still record it; the hint is a convention, not an
   enforcement.
3. The helper disables core dumps and locks its whole address space with
   `mlockall(MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT)` while it holds the value.
   If the lock is refused the copy still happens and the confirmation line
   adds `helper could not lock its memory`.
4. After `clipboardClearSec` seconds (default 30) the helper clears the
   clipboard — **only if the selection is still its own**. If you copied
   something else in the meantime the helper has already exited and your
   newer value is left alone. Before 2.5.0 the clear never happened at all:
   the timer thread died with the command.
5. The command does not say "copied" on hope. It polls the compositor for the
   sensitive hint, and only once the compositor is seen offering the value
   does it print `copied password to the clipboard · marked sensitive so
   clipboard managers skip it · clears in 30s`. If the helper does not report
   within four seconds, or the compositor never offers the value within three
   more, the command fails and says nothing was copied. The deck's footer
   repeats that line verbatim.

The clear is a wipe of the clipboard offer, not of anything that already read
it: an application that pasted the value, or a manager that ignores the hint,
keeps its copy. A second copy while one is still being placed is refused out
loud (*still placing the previous copy*) rather than dropped.

`Shift+Enter`, or the SHOW button, puts the value on screen for
`revealSeconds` (default 10) with a countdown; `Esc` hides it immediately. A
reveal or 2FA code that arrives after you have moved to another record is
dropped rather than rendered under the new name.

TOTP codes are fetched for the selected record and shown in the right rail
with a countdown arc that turns red in the last five seconds. The deck
re-fetches just after the step rolls, never faster.

Copying a 2FA record copies the **current code**, not the stored shared
secret. The secret is raw binary and would be the wrong thing on a clipboard
in any case, so `COPY` on a `totp` field routes through
`black-bag agent totp --to clipboard`. `SHOW` on that field declines and points
at the card, where the live code already is.

```bash
black-bag totp <uuid> --to clipboard        # opens the vault itself
black-bag agent totp <uuid> --to clipboard  # via the agent
black-bag agent totp <uuid>                 # prints JSON: code, ttl, step
```

### How the vault locks

Four ways, each reported by name in the SESSION card's `last lock` row
(`LockReason` in `crates/blackbag-core/src/session.rs`):

| Way | Trigger | Caught by |
|---|---|---|
| **manual** | `Ctrl+L`, LOCK NOW, `black-bag agent lock` | the agent |
| **idle** | no request that touches the vault for `--idle-secs` (900 by default). Status polls do not extend it | the agent |
| **session ceiling** | `--max-secs` after the unlock (43200 — twelve hours — by default), regardless of activity. Idle expiry alone let a session touched every few minutes stay open for days | the agent |
| **suspend / screen lock** | logind's `PrepareForSleep(true)` and `Session.Lock` signals, from any session path — `systemctl suspend`, a lid, `loginctl lock-session` | the agent, over the system D-Bus |
| | Omarchy's own lock screen, which is the shell's and never tells logind | the plugin: `Service.qml` watches the shell's `omarchy.lock` service and runs `black-bag agent lock` the moment it reports locked |

Two more reasons appear but are not things you do: *re-keyed elsewhere*
(another process re-keyed the file, so the key the agent held is no longer
the right one) and *agent stopped*.

The suspend watcher (`crates/blackbag-core/src/sleepwatch.rs`) is a
hand-written D-Bus client — SASL `EXTERNAL`, `Hello`, two `AddMatch` calls,
a bounds-checked parser that drops any message it cannot read and caps
messages at 1 MiB. It connects to the system bus (honouring
`DBUS_SYSTEM_BUS_ADDRESS`), retries every 20 s if the bus is unreachable, and
reports its state in `status.json` as `session.sleep_watch`, which is what
the SESSION card's `suspend & screen lock` row draws. It takes **no inhibitor
lock**: the vault is locked as soon as the agent is scheduled after the
signal, which is milliseconds in practice, not provably before the kernel
suspends. Without the agent unit running, nothing watches for suspend.

Locking, however it happens, is announced in the deck only after the agent
confirmed it: the lock command's exit code is checked, and the deck empties
both sheets and the record list on every lock and on every dismiss.

### Size

The deck sizes itself from the screen. If it is still not right:

| | |
|---|---|
| `⌘ +` / `Ctrl +` | bigger |
| `⌘ -` / `Ctrl -` | smaller |
| `⌘ 0` / `Ctrl 0` | back to automatic |

It applies immediately and is remembered. In the application the value lives in
`~/.config/black-bag/desktop.json` as `uiScale`; in the plugin it is written to
the shell's config for `khephri.blackbag`. Either way, `⌘ 0` clears it.

The deck deliberately does **not** use the shell's own type scale directly:
that is sized for a 24px bar, and a full-screen surface that inherits it is a
postage stamp in the middle of a large display. Changing the deck's size does
not change the bar's.

### Keyboard map

Deck, with the record list focused:

| Key | Action |
|---|---|
| `/` | focus the search box |
| `↓` / `j` | next record |
| `↑` / `k` | previous record |
| `PageDown` / `PageUp` | move ten |
| `Home` / `End` | first / last record |
| `Enter` | copy the primary secret field to the clipboard |
| `Shift+Enter` | show the primary secret field on screen |
| `n` | new record |
| `e` | edit the selected record |
| `Delete` or `Ctrl+D` | remove the selected record — press twice |
| `Backspace` | clear the kind filter |
| `u` | focus the passphrase field (only while locked) |
| `Ctrl+B` | check breaches — press twice; the first press arms and explains |
| `Ctrl+L` | lock the agent now |
| `Ctrl+R` | re-publish status and re-read the record list |
| `Esc` | step back (see below) |

`Ctrl+B`, `Ctrl+L`, `Ctrl+R` and `Esc` are window-scoped and work wherever
the caret is. The plain letter keys are deliberately dead while a text field
has focus. The footer shows the map: `n new · e edit · del remove · / search
· ↑↓ move · ⏎ copy · ⇧⏎ show · ^B breaches · ^L lock · esc close`.

`Esc` does the smallest useful thing first: hide a revealed secret, then
cancel a pending delete, then disarm a pending breach check, then bring focus
back from a button to the record list, then clear the search box, then close
the deck.

In the search box:

| Key | Action |
|---|---|
| `Enter` or `↓` | leave the box and select the first result |
| `Esc` | clear the query; if already empty, leave the box |

In the editor sheet:

| Key | Action |
|---|---|
| `Tab` / `Shift+Tab` | next / previous field |
| `Enter` | next field; on the last field, save |
| `Ctrl+G` | generate into the focused secret field |
| `Ctrl+Enter` | save |
| `Esc` | cancel |

Mouse: click a row to select, double-click to copy its primary field,
right-click for a menu; COPY and SHOW buttons per secret field; LOCK NOW and
REFRESH in the SESSION card; CHECK BREACHES in the HYGIENE card; clicking a
hygiene finding jumps to its record, clearing the kind filter if the record is
hidden behind one. Every button is also reachable with `Tab` and pressed with
`Space` or `Enter`.

---

## 5. Adding and editing records

`n` opens the editor. Pick a kind, give it a title, optionally tags, fill the
open attributes and the secret fields, `Ctrl+Enter` to save. The draft travels
to the agent as JSON on stdin — never as command-line arguments.

### The twelve kinds

`attrs` are open metadata; they live inside the encrypted payload, sit in
ordinary memory while the vault is open, and are searchable. `secrets` rest
as ciphertext under the per-process session key (§11), are decrypted into
locked scratch only for the moment they are used, and are never searched.

| Kind | Open attributes | Secret fields |
|---|---|---|
| Login | username, url | password |
| 2FA code | issuer, account | *(the shared secret, via `otpauth://` or base32)* |
| API key | service, environment, access_key, scopes | secret_key |
| SSH key | label, comment | private_key *(multi-line)* |
| PGP key | label, fingerprint | private_key *(multi-line)* |
| Wallet | asset, address, network | seed *(multi-line)* |
| Bank | institution, account_name, routing_number | account_number |
| Wi-Fi | ssid, security, location | passphrase |
| ID document | id_type, name_on_doc, issuing_country, expiry | number |
| Contact | full_name, emails, phones, address, company | notes *(multi-line)* |
| Secure note | — | body *(multi-line)* |
| Recovery kit | description | payload *(multi-line)* |

A document number and a contact's notes are treated as secret because in
practice they are. Every kind uses the same record shape, so nothing is stored
in the clear inside the payload merely because its kind has no obvious secret.

### The generator

`Ctrl+G`, or the *generate* button beside a single-line secret field, runs
`black-bag gen password` with its defaults — twenty characters over lowercase,
uppercase, digits and symbols — and drops the result into the field. The
generated value is **shown** for `revealSeconds` and then masked again: a
password written into a masked box is a password nobody can read, verify or
write down. Multi-line fields are not generatable.

### Secret boxes in the editor

Every secret box has a *show* / *hide* toggle beside it (the eye). A
single-line box masks like a password field. A multi-line box — a private
key, a seed, a note body — cannot be masked character by character, so it is
covered instead: the cover reads *hidden · N characters · click to reveal and
edit*, and typing is not possible until it is opened, because you should see
what you are about to store. Both mask themselves again on the same countdown
the inspector's SHOW uses. Copy from the field's context menu is disabled
while a box is masked or covered, so Copy is not the quiet way around the
countdown.

The editor does not display the entropy figure; the CLI does, on stderr:

```
$ black-bag gen password
129.7 bits · very strong · uniform random over 90 symbols, 20 long, redrawn
until all 4 enabled classes appear (costs 0.148 bits); generated values only,
never a typed one
```

That last clause is load-bearing. The figure is `log2(charset^length)`
corrected downward for the class-presence requirement, and it is a statement
about the *generator*, not about any particular string. There is deliberately
no function anywhere in this project that takes a typed password and returns
bits, because that number would be a guess wearing a measurement's clothes.

### `otpauth://` enrolment

For a 2FA record, paste the enrolment URI into the first field and everything
else follows from it: the secret, issuer, account, digits, period and
algorithm. If the site only prints a key, put that in the base32 box instead —
spaces, hyphens, case and padding are all tolerated. Digits outside 6–8 and a
zero period are rejected.

### Editing keeps what you do not retype

**A blank secret box on an edit means "keep the stored value."** The editor
never pre-fills a secret field, and the deck never asks the agent for one when
opening the form, so you can fix a title or add a tag without the cockpit ever
holding your password. The form says so under the heading: *keeps stored
secrets unless you type over them*.

Two consequences worth knowing. Removing a secret field entirely (rather than
blanking it) is what deletes it — the draft lists the fields that survive.
And on a 2FA record, leaving both TOTP boxes blank on an edit keeps the
existing secret and configuration.

Deleting a record from the deck takes two presses of `Delete` and is not
undoable.

---

## 6. Recovery

### What a recovery key file is

A JSON file, mode `0600`, containing four things: a label, the vault's id, an
X25519 secret key, and a 64-byte ML-KEM-1024 seed. It contains no ciphertext
and no records. Its only power is that the vault carries a copy of the data
key wrapped to the matching public halves.

The two shared secrets — the X25519 Diffie-Hellman result and the ML-KEM
decapsulation — are combined through a domain-separated BLAKE3 KDF that also
covers both ciphertexts. The wrap is secure if *either* primitive holds.

### It opens the vault without the passphrase

That is the entire point, and it is also the entire risk. Anyone who holds
this file and a copy of your vault file can read everything in it. There is no
second factor on the recovery lane.

Where to put it: printed and in a safe, or on a USB stick in a drawer that is
not this desk, or in a bank box. Not in your home directory, not in the
directory you back up to the same cloud the vault might reach, and not in a
password manager whose master password is the thing you are protecting against
forgetting.

### Using it

```bash
black-bag recovery use --key /media/usb/black-bag-recovery.key
```

This unlocks with the key, then **requires** you to set a new master
passphrase and re-keys the vault on the spot: a fresh data key, the payload
re-encrypted under it, and every recipient re-wrapped. You cannot use a
recovery key to browse and walk away; using it is a recovery event and the
tool treats it as one.

### Revoking

```bash
black-bag recovery list
black-bag recovery remove offsite
black-bag rekey --change-passphrase
```

`recovery remove` drops the recipient from the header and writes the vault
again. From that moment the key file cannot open **the current file**.

State the limit plainly: it cannot reach into copies. If someone has both the
key file and an older copy of `vault.cbor` taken before the revocation, that
pair still opens. Revocation protects everything written afterwards, which is
why `rekey` belongs in the same sitting — it mints a new data key so the one
the revoked holder could have reached no longer protects anything current.

The passphrase recipient cannot be removed. A vault that only a key file can
open is a lockout waiting to happen, so the engine refuses.

---

## 7. Credential hygiene

`black-bag agent hygiene`, or the HYGIENE card in the deck. Everything is
computed in the agent process from records already decrypted in memory. There
is no network call — except the breach check at the end of this section,
which runs only when you ask, and only in the CLI.

Reuse is found without comparing secrets. Every secret field carries a
non-reversible eight-hex-character BLAKE3 handle, domain-separated by the field
name, so two records holding the same password produce the same handle — and
the vault can tell you they match without any secret being compared, copied or
displayed.

### The findings

| Code | Severity | What it means | What to do |
|---|---|---|---|
| `REUSED` | high | Another record's field of the same name produces the same handle | Change one of them. Generated values are the cheap fix |
| `WEAK_PIN` | high | An all-digit secret under its floor: 22 digits for a password-role field, 6 for a PIN-role field | Lengthen it, or move to a non-numeric secret |
| `SHORT` | medium | A password-role field under 12 bytes and not all digits | Regenerate at 20 characters |
| `STALE` | low | The record has not been modified for 365 days or more | Rotate it, or accept it deliberately |
| `NO_TOTP` | low | A login or bank record with no second factor stored in this vault | Enrol 2FA and store it here, if the account offers it |
| `DUPLICATE_TITLE` | low | Another record of the same kind has the same title | Rename one; you cannot tell them apart in a list |
| `EXPOSED` | high | The field's full SHA-1 matched a Pwned Passwords bucket during a breach check you ran this session; the count of breaches is carried | Change it. The finding lasts until the vault locks |

Field role follows the field **name**, not the kind: `password`, `passphrase`,
`pass` and `pw` are password-role; `pin`, `pin_code` and `passcode` are
PIN-role; everything else — keys, seeds, tokens, note bodies — is opaque and
is not judged on length, because its length was chosen by whoever issued it.
Bank and ID PINs are exempt from the PIN floor for the same reason.

`STALE` applies only to kinds whose secret can be rotated on request: login,
API, SSH, PGP, Wi-Fi. A wallet seed is excluded because rotating one means
moving funds; a bank account number and an ID number because they are facts
about the world.

The score is counts by severity plus a demerit total, `5×high + 2×medium +
1×low`, with each record's contribution listed so you can check the
arithmetic. There is no score out of a hundred, and no cracking-time estimate,
because both would require guessing on your behalf.

### Its stated limits

- A handle match means *these share a handle*, not *these are provably
  identical*. The handle is 32 bits, so collisions exist. It is short because
  it is shown in the interface.
- Absence of a cluster is not absence of reuse. The domain is the field name
  verbatim, so a `password` and a `passphrase` holding the same value do not
  cluster, and `Password` is a different lane from `password`.
- `STALE` is a lower bound. The vault stores no per-field change time, so a
  record you touched to fix a tag reports as fresh.
- `NO_TOTP` means *not stored in this vault*. It says nothing about whether
  the account has 2FA enabled.
- A field this analysis has no defensible expectation for is left alone.
  Silence about it is silence, not a pass.
- The full report carries handles and titles, so it is as sensitive as the
  open vault. It travels over the agent socket only. `--json` prints all of
  it; the default human form is counts and per-record lines. It is never
  written to `status.json`.

### The breach check

```bash
black-bag agent breach --online          # human summary
black-bag agent breach --online --json   # the report, as sensitive as --json hygiene
```

This is the one command in the program that talks to the network, and it
refuses with exit code 2 unless `--online` is given, printing what would be
sent instead. What happens (`crates/blackbag-core/src/breach.rs` and
`cmd_breach` in `crates/blackbag-cli/src/main.rs`):

1. The CLI asks the agent for candidates. The agent hashes every field named
   `password`, `passphrase` or `pin` with SHA-1 and hands back only the
   **first five hex characters** of each — twenty bits. The prefixes are
   deduplicated and sorted, so two records sharing a password send one
   prefix and the order tells nothing.
2. The CLI runs `curl` once per prefix against
   `https://api.pwnedpasswords.com/range/<prefix>` with the header
   `Add-Padding: true`, a `User-Agent` of `black-bag/2.5.0`, and
   `--max-time 20`. Padding makes every response the same shape so its size
   reveals nothing; padding entries (count `0`) are dropped on receipt. The
   agent itself cannot do this: its unit has no network address family.
3. The buckets go back to the agent, which compares them against the full
   hashes it never disclosed. A hit becomes an `EXPOSED` finding with its
   breach count, kept in the open session and folded into every hygiene
   report until the vault locks. Nothing is written to the vault.

What the service learns: that some client holds a password whose SHA-1
begins with each prefix, and how many distinct prefixes were asked about. It
cannot learn which password you hold, whether it matched, or which records
exist. A prefix that could not be fetched is reported as *not checked*, never
as clean. The deck's CHECK BREACHES button runs exactly this command, after
a two-step confirmation (§4).

---

## 8. CLI reference

Every command takes the global `--vault <PATH>` (also read from
`BLACK_BAG_VAULT_PATH`) and `-h`/`--help`. Flags below are the real ones,
taken from `--help`.

### Vault lifecycle

| Command | Flags | Notes |
|---|---|---|
| `black-bag init` | `--mem-kib <KIB>` (default 262144) | Prompts for the new passphrase twice. Refuses if the file exists |
| `black-bag rekey` | `--change-passphrase`, `--mem-kib <KIB>` | New data key, payload re-encrypted, every recipient re-wrapped, Argon2 salt re-drawn |
| `black-bag migrate` | `--from <PATH>`, `--to <PATH>` | Reads a `black-bagg` 0.4.x v1 vault. See §9 |
| `black-bag import` | `--from <FILE>` (required), `--format bitwarden\|keepassxc\|firefox\|chrome\|csv` (required), `--dry-run` | Opens the vault itself (passphrase prompt), parses the export by hand, adds every record it could map. Skipped rows are reported on stderr by reason, never by value. `--dry-run` parses, prints the counts by kind, writes nothing. Afterwards it tells you to `shred -u` the export |
| `black-bag export` | `--to <FILE>` (required), `--format json\|keepassxc` (json), `--plaintext-ok` (required) | Every record and every secret in plaintext. Refuses without `--plaintext-ok`, refuses to overwrite, creates the file `0600` with `O_EXCL`, and tells you to shred it once the other tool has read it |

Import formats: `bitwarden` is the unencrypted JSON export (an encrypted one
is refused with instructions to export it unencrypted); `keepassxc` is the
CSV export (Group, Title, Username, Password, URL, Notes, TOTP, …), with the
group path becoming tags and a trailing `kind: <name>` line in Notes — which
our own export writes — restoring non-login kinds, so a KeePassXC CSV
round-trips every kind; `firefox` is `logins.csv`; `chrome` is the
Chrome/Chromium/Brave `Chrome Passwords.csv`; `csv` is any file with a header
row, matched case-insensitively against synonyms — title: `title`, `name`,
`account`, `site`, `service`; username: `username`, `user`, `login`, `email`,
`user name`; password: `password`, `pass`, `secret`, `pwd`; URL: `url`,
`website`, `web site`, `login_uri`, `uri`; notes: `notes`, `note`, `comment`,
`extra`; TOTP: `totp`, `otp`, `otpauth`, `2fa` — with unrecognised columns
kept as attributes. The parser lives in
`crates/blackbag-cli/src/import.rs`.

### Records

| Command | Arguments and flags | Notes |
|---|---|---|
| `black-bag add <KIND>` | `--title`, `--tags a,b`, `--attr KEY=VALUE` (repeatable), `--secret NAME` (repeatable), `--totp-digits` (6), `--totp-step` (30) | Prompts for the master passphrase first, then each secret. `--secret` defaults to the kind's usual field |
| `black-bag list` | `--kind`, `--query`, `--json` | `--query` matches titles, tags, kind and attributes — never secrets |
| `black-bag get <ID>` | `--reveal <FIELD>`, `--to tty\|clipboard\|stdout` (tty), `--clear-after <SECS>` (30), `--json` | Without `--reveal` it prints metadata and per-field handles. `--json` returns early, so it ignores `--reveal` |
| `black-bag remove <ID>` | `--yes` (required) | Not undoable |
| `black-bag totp <ID>` | `--to tty\|clipboard\|stdout` (tty), `--json` | Opens the vault directly; prints the code and its remaining validity |

There is no flag anywhere in this CLI that accepts secret material. A shared
TOTP secret is prompted for, like every other secret, because
`/proc/<pid>/cmdline` is world-readable and your shell history is a file.

### Recovery

| Command | Flags | Notes |
|---|---|---|
| `black-bag recovery add <LABEL>` | `--out <PATH>` (required) | Refuses to overwrite an existing file. Writes mode 0600 |
| `black-bag recovery use` | `--key <PATH>` (required) | Unlocks, then requires a new passphrase and re-keys |
| `black-bag recovery remove <LABEL>` | — | The `passphrase` recipient cannot be removed |
| `black-bag recovery list` | — | Reads the header only; no passphrase needed |

### The agent

| Command | Arguments and flags | Notes |
|---|---|---|
| `black-bag agent serve` | `--idle-secs <SECS>` (900), `--max-secs <SECS>` (43200) | Foreground. The systemd unit runs this. `--max-secs` is the session ceiling: lock this long after an unlock however busy the session is; values under 60 are raised to 60, and `0` disables it. A peer that sends nothing for 3 s is dropped so it cannot stall the others |
| `black-bag agent unlock` | — | Passphrase from the terminal, or one line on stdin |
| `black-bag agent lock` | — | Forgets the data key immediately |
| `black-bag agent status` | — | JSON: lock state, deadline, session ceiling, last lock reason, sleep-watch state, record count, counts by kind |
| `black-bag agent stop` | — | Stops the agent |
| `black-bag agent list` | `--json`, `--kind`, `--query` | Titles, tags, attributes and per-field handles. Never secret bytes |
| `black-bag agent reveal <ID> <FIELD>` | `--to tty\|clipboard\|stdout` (**clipboard**), `--clear-after <SECS>` (30) | |
| `black-bag agent show <ID> <FIELD>` | — | The one command that writes a secret to stdout |
| `black-bag agent totp <ID>` | — | JSON: `code`, `ttl_secs`, `step` |
| `black-bag agent add` | — | Reads a JSON record draft on stdin |
| `black-bag agent edit <ID>` | — | Reads a JSON record draft on stdin |
| `black-bag agent delete <ID>` | `--yes` (required) | |
| `black-bag agent hygiene` | `--json` | Default output is counts and per-record lines; `--json` is as sensitive as the open vault |
| `black-bag agent breach` | `--online` (required), `--json` | The one networked command. Exit 2 without `--online`. Needs `curl`. See §7 |

`black-bag clip-serve` also exists, hidden from `--help`: it is the clipboard
helper that `--to clipboard` spawns from the binary itself, reading the value
on stdin. It is not meant to be run by hand, and it is hidden precisely so
that nobody reaches for it with a secret on the command line.

### Posture and generation

| Command | Flags | Notes |
|---|---|---|
| `black-bag doctor` | `--json` | Vault header, KDF, recipients, host posture, findings |
| `black-bag status` | `--publish` | Prints the status document, or writes it to `$XDG_RUNTIME_DIR/black-bag/status.json` and echoes the path on stderr |
| `black-bag gen password` | `--length` (20), `--no-lowercase`, `--no-uppercase`, `--no-digits`, `--no-symbols`, `--exclude-ambiguous` | |
| `black-bag gen passphrase` | `--words` (8), `--separator` (`-`), `--capitalise` | 512-word list, exactly 9 bits per word |
| `black-bag gen pin` | `--digits` (6) | |

All three generators print the value on stdout and the strength line on
stderr, so a pipe captures the secret alone — which also means a shell
redirect writes a password to a file. `--capitalise` is deterministic and
therefore worth zero bits; the strength line says so.

### Scripting

There is no `--passphrase` flag anywhere, on purpose. When stdin is not a
terminal, passphrases are read one line at a time in prompt order:

```bash
printf '%s\n%s\n' "$MASTER" "$RECORD_PASSWORD" |
  black-bag add login --title GitHub --attr username=octocat
```

When stdin is a pipe, `init`, `rekey --change-passphrase` and `recovery use`
read the new passphrase **once**, without the confirmation prompt.

---

## 9. Migrating from `black-bagg`

The old crate's v1 format is readable, and the reader is the only part of this
project that still knows about it.

```bash
black-bag migrate \
  --from ~/.config/black_bag/vault.cbor \
  --to   ~/.local/share/black-bag/vault.cbor
```

You are asked for the old passphrase, then for a passphrase for the new vault;
reusing the old one is fine. The command refuses if `--to` already exists.

What happens to your data:

- Every v1 record kind maps onto the corresponding v2 kind, keeping its
  `created_at`, `updated_at`, title and tags.
- The old `metadata_notes` field — which v1 stored in the clear inside the
  payload — becomes a secret field, sealed in memory like every other,
  because notes on a credential routinely are one.
- The new vault gets a fresh vault id, a fresh Argon2 salt at the current
  default cost, a fresh data key, an authenticated header and an epoch.
- No recovery recipient is created. Add one afterwards (§3).

Verify the new vault opens and that the record count matches, then destroy the
old file. `migrate` does not delete anything.

Note that the v1 format's ML-KEM lane contributed nothing to its security —
the decapsulation key travelled inside the same file under the same
passphrase — so this migration does not lose a protection you had. It replaces
a decorative one with a real one, once you add a recipient.

---

## 10. Troubleshooting

### "no agent listening at /run/user/1000/black-bag/agent.sock"

The agent is not running. `systemctl --user status black-bag-agent`, and
`systemctl --user enable --now black-bag-agent` if it was never enabled. The
CLI still works without it; every command will just ask for the passphrase.

### The agent failed at boot with `status=226/NAMESPACE`

Observed on this machine:

```
black-bag-agent.service: Failed to set up mount namespacing:
  /run/user/1000/black-bag: No such file or directory
black-bag-agent.service: Failed at step NAMESPACE spawning ...
```

The unit lists `%t/black-bag` in `ReadWritePaths`, and at the moment the unit
starts on a fresh login that directory may not exist yet. The vault is not
harmed. Create the directory and restart:

```bash
black-bag status --publish          # creates $XDG_RUNTIME_DIR/black-bag
systemctl --user restart black-bag-agent
```

`Restart=on-failure` usually wins this race on its own — the log will show one
failure followed by a successful start two seconds later.

### "vault is locked"

The agent is running but holds no key. Unlock it — from the deck, or
`black-bag agent unlock`. The session expires after the idle timeout (900
seconds by default) and is extended by operations that touch the vault; asking
for status alone does not extend it. It also ends at the session ceiling
(twelve hours after the unlock by default, `--max-secs`), when the machine
suspends, when the screen locks, on `Ctrl+L`, on LOCK NOW, on
`black-bag agent lock`, and whenever the agent process restarts. The SESSION
card's `last lock` row, and `last_lock_reason` in `agent status`, say which
it was (§4, *How the vault locks*).

### `mlock` failures

`doctor` reports the memlock ceiling, whether a probe lock succeeds right
now, and how much of the secret arena is locked, unlocked, and how many locks
were refused. On a stock Omarchy box `ulimit -l` is 8192 KiB, which is 2048
pages; `MEMLOCK_TIGHT` is a note, not an error. `MLOCK_FAILED` is a warning
and means the probe itself failed; `ARENA_UNLOCKED` means a slab of transient
plaintext scratch could not be locked. Failures are reported rather than
swallowed; the engine keeps working, because refusing to open your vault
because a resource limit is low would be worse than telling you about it.

Since 2.5.0 the memlock budget matters less than it did: resting secrets are
ciphertext, so what must never reach swap is the 32-byte session key (see the
next entry) and whatever plaintext is in use at the moment. The arena's slabs
are 256 KiB each and the decoder's scratch is one 260 KiB buffer, so the
8 MiB default is not normally exhausted.

Raise it with `ulimit -l` before starting the agent, or with `LimitMEMLOCK=` in
the unit, if your policy allows it.

### "session key: unlocked", or `SESSION_KEY_UNLOCKED`

The per-process key that every resting secret is sealed under has three
possible homes, reported by `doctor` and by the HOST POSTURE `session key`
row: `memfd_secret` (kernel-invisible), `locked-slab` (one page-locked arena
page), or `unlocked`. `unlocked` means `memfd_secret` was unavailable **and**
the arena could not lock a page either, so the key sits in memory the kernel
may swap. Causes: a kernel older than 5.14, or built without
`CONFIG_SECRETMEM`, or with secret memory turned off by its `secretmem.enable`
boot parameter; a seccomp filter that does not allow syscall 447 — the
shipped unit allows it explicitly; and, for the fallback, a memlock limit
that refuses even one page. `BLACK_BAG_NO_SECRETMEM=1` in the environment also skips
`memfd_secret`, deliberately, and lands on the locked slab.

### Hibernation is refused while the agent runs

While any process holds `memfd_secret` memory the kernel refuses to
hibernate, system-wide — that is the mechanism by which the key can never
land in a hibernation image. Suspend-to-RAM is unaffected. If you hibernate
this machine and would rather the agent did not stand in the way, set
`BLACK_BAG_NO_SECRETMEM=1` in the unit's `Environment=`; the key then lives in
a locked page instead, `doctor` reports `locked-slab`, and the trade is that a
locked page is still visible to the kernel and to root through
`/proc/<pid>/mem`.

### The rollback warning

`ROLLBACK` in `doctor`, a red epoch line in the deck, and a desktop
notification mean the vault file's epoch is *behind* the highest epoch this
machine has recorded for that vault id. Realistically this means one of: a
backup was restored, a sync tool resolved a conflict badly, or a filesystem
snapshot was rolled back.

You can still unlock — the button reads *unlock anyway* — because locking you
out of your own restored backup would be the wrong failure. Check the record
you expect to be newest, and if the file really is the one you want, the next
write bumps the epoch past the witness and the warning clears.

**This is a tripwire, not a guarantee.** The witness lives in your own state
directory. An attacker who can rewrite the vault can usually rewrite the
witness too. What it reliably catches is the accident.

### Stale status

The bar widget and the deck desaturate rather than assert a state when
`status.json` is older than `staleAfterSec` (default 120). Stale weakens an
all-clear; it never suppresses an alarm. Causes: the agent is not running and
nothing else is publishing, the shell's polling service is not loaded, or
`black-bag status --publish` is failing. Run it by hand and read the error.

Note also that `black-bag status` asks the agent for the lock state and falls
back to "locked" if it cannot reach it, so a status document that says locked
while the agent holds a key means the two could not talk.

### Host-posture rows

| Row | Reading | What it means |
|---|---|---|
| `mlock` | `working` / `FAILED` | Whether a 32-byte probe lock succeeded just now. `FAILED` is an alert: secrets may reach swap |
| `core dumps` | `disabled` / `ENABLED` | Whether *this process* set `RLIMIT_CORE` to 0. When enabled, the row shows the host's `core_pattern` |
| `swap` | device list / `none` | Non-empty means "secrets never touch disk" holds only because of `mlock` |
| `memlock` | a size or `unlimited` | `RLIMIT_MEMLOCK`. Below 64 MiB is flagged as a note |
| `tracer` | `none` / `ATTACHED` | `TracerPid` from `/proc/self/status`. `ATTACHED` blocks typing on the sealed screen |
| `session key` | `kernel-invisible` / `locked page` / `UNLOCKED` | Where the per-process key lives: `memfd_secret`, a locked arena page, or neither. `UNLOCKED` is a warning: the key may be swapped |
| any row | `UNKNOWN` | Not measured. An unmeasured host is not a healthy host, and the row says so rather than showing a pass |

On a stock Omarchy install `core_pattern` pipes to systemd-coredump and zram
swap is active. Black-Bag disables core dumps and clears `PR_SET_DUMPABLE` for
its own processes; it cannot fix the host, so it shows you the host.

### Other findings you may see

`KDF_BELOW_DEFAULT` — the vault's Argon2 parameters are below 256 MiB / time
10 / 4 lanes. Fix with `black-bag rekey --mem-kib 262144`.
`NO_RECOVERY` — no recipient whose private key is held outside the vault.
`VAULT_UNREADABLE` — the file exists but does not parse; the detail carries the
reason.
`SESSION_KEY_UNLOCKED` and `ARENA_UNLOCKED` — see the `mlock` and session-key
entries above.

### "copied" was printed but the clipboard is empty

The command prints *copied* only after it has seen the compositor offering
the value with the sensitive hint, so this is rare. When it happens, the
usual cause is a compositor without the `wlr-data-control` protocol, or a
sandbox that hides the Wayland socket from the helper: the helper's offer
lands on a clipboard nobody else can see. Hyprland has data-control. Check
`wl-paste --list-types` (from `wl-clipboard`, if installed) right after a
copy: it should list `x-kde-passwordManagerHint`. Also remember the clear is
a clear: if `clipboardClearSec` has passed, the clipboard being empty is the
feature.

If the command instead fails with *the clipboard helper did not confirm
within 4s* or *the compositor never offered the value; nothing was copied*,
there is no Wayland compositor reachable from that shell — an SSH session, a
TTY, `WAYLAND_DISPLAY` unset — and nothing was copied.

### "breach check failed" / `curl is required`

`black-bag agent breach` shells out to `curl`; install it. Offline, or behind
a proxy `curl` does not know about, each prefix fetch fails and is reported
as *not checked* — never as clean — and the command's summary counts them.
The deck shows the CLI's stderr in the footer as *breach check: …*. Without
`--online` the command exits 2 and prints what it would send; that is not a
failure, it is the consent gate.

### "the engine did not answer in two minutes" on first run

The first-run sheet runs `black-bag init` and, for the recovery step,
`black-bag recovery add`, and waits. If neither returns within 120 s the
sheet's watchdog abandons the work, re-enables the buttons and shows this
line. Two minutes is longer than any Argon2 cost the deck configures, so the
cause is not slowness: the binary is not on the `PATH` the shell was started
with, the vault directory is not writable, or the process is stuck. Run
`black-bag doctor` in a terminal and read what it says. `Esc` always works on
that sheet, even while it is busy.

---

## 11. Where things live, and what is in them

| Path | Mode | Contents |
|---|---|---|
| `~/.local/share/black-bag/vault.cbor` | 0600 | The vault: version, header (id, timestamps, epoch, recipients, MAC) and the sealed, padded payload. Everything secret is inside the payload |
| `~/.local/share/black-bag/vault.cbor.lock` | — | Advisory lock file so two writers do not interleave. Empty |
| `~/.local/state/black-bag/witness.json` | 0600 | The highest epoch seen per vault id, and when. No key material |
| `$XDG_RUNTIME_DIR/black-bag/status.json` | 0600, dir 0700 | The status document. **No titles, tags, attributes, record counts or secrets** |
| `$XDG_RUNTIME_DIR/black-bag/agent.sock` | 0600, dir 0700 | The agent socket. `SO_PEERCRED` is checked on every connection; a different uid is dropped before a byte is read |
| `~/.config/systemd/user/black-bag-agent.service` | — | The agent unit |
| `~/.config/omarchy/plugins/khephri.blackbag/` | — | The plugin: bar widget, cockpit, editor, service |
| `~/.config/omarchy/shell.json` | — | Where the widget is enabled |
| `~/.config/hypr/bindings.lua` | — | The `SUPER+SHIFT+K` managed block |

Environment overrides: `BLACK_BAG_VAULT_PATH`, `BLACK_BAG_STATE_DIR`,
`XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_RUNTIME_DIR`, `BLACK_BAG_PAD_BLOCK`
(payload padding block, default 4096, accepted from 1 to 1048576),
`BLACK_BAG_NO_SECRETMEM` (set to skip `memfd_secret` and keep the session key
in a locked page; see §10) and `DBUS_SYSTEM_BUS_ADDRESS` (where the agent
looks for logind).

### The security boundary, stated so you can act on it

**`status.json` is plaintext and is what the bar widget reads.** It carries
only: schema and engine version, the vault path, format, id and timestamps,
the epoch and the witnessed epoch, recipient *labels* and whether each one's
private key is held externally, the Argon2 parameters, the session's lock
state, deadline, ceiling, last lock reason and sleep-watch state, host posture
including where the session key lives, and the derived findings. It carries
no record titles, no tags, no counts, and no secrets. There is a test that
asserts this.
The test to apply to any future field is: would you be happy for it to survive
in a world-readable backup of `/run`?

**Everything about your records exists only while the vault is unlocked**, in
the agent's memory, and reaches the deck over the socket. The census in the
left rail is computed from the list the agent returned, which is why it is
blank while locked. Secret *bytes* leave the agent only through `Reveal`, one
field at a time, by explicit request. There is no "dump the vault" call.

**There is no `--passphrase` flag** because `/proc/<pid>/cmdline` is
world-readable: an argv passphrase is a passphrase published to every process
on the machine. Passphrases come from the terminal, or from stdin when there
is no terminal, and there is no exception anywhere in the CLI.

**You can use the CLI and the cockpit together.** `black-bag add`, `remove` and
`rekey` open the vault file directly, while a running agent keeps its own
unlocked copy in memory — so the agent checks the file before serving any
request and re-reads it if another writer got there first. A record you add in
a terminal appears in the deck without restarting anything, and neither side
overwrites the other.

Two consequences worth knowing. If another process re-keys the vault, the
agent's data key no longer opens it, so the session drops and you are asked to
unlock again — that is deliberate, since the alternative is holding a key that
is quietly wrong. And if a write lands between the moment a handle reads and
the moment it saves, the save is refused rather than allowed to win; the agent
handles this for you by refreshing first.

**Revealed secrets default to `/dev/tty`**, which the shell cannot redirect,
so `black-bag get X --reveal password > notes.txt` writes the metadata and not
the secret. `--to stdout` exists for when you mean it, and `agent show` is the
one command whose entire job is that.

**The clipboard timeout** (30 seconds by default, `clipboardClearSec` in the
widget settings; up to 3600, or 0 for never, from the CLI) is kept by the
detached helper that serves the selection, which clears it only if the
selection is still its own. The offer carries `x-kde-passwordManagerHint`, so
managers that honour the hint — Omarchy's, cliphist, KDE, GNOME — never record
it. It is a wipe of your clipboard, not of a manager that ignores the hint,
and not of an application that has already read the value. §4 has the whole
sequence.

**Secrets in memory are ciphertext** (`crates/blackbag-core/src/secmem.rs`).
Every secret the agent holds — each record field, the vault's data key — rests
as XChaCha20-Poly1305 ciphertext, with the associated data
`black-bag::v2::guarded-memory`, under a 32-byte session key drawn once per
process. The key lives in one page of `memfd_secret` memory (syscall 447;
`ftruncate` to a page, `mmap` `MAP_SHARED`, then the descriptor is closed),
which the kernel removes from its own direct map: never swapped, never in a
core file or a hibernation image, unreadable through `/proc/<pid>/mem` even
by root. Where the kernel does not offer it, the key sits in one locked arena
page and `doctor` says `locked-slab`; if that fails too it says `unlocked`.
Plaintext exists only while a field is in use, in `SecretBuf` slabs the
engine maps itself — 256 KiB each, `mmap` + `mlock` + `MADV_DONTDUMP` +
`MADV_DONTFORK`, free ranges zeroed and reused, an oversize value getting a
dedicated slab — and the decrypted payload, the serialised payload and the
decoder's scratch (one buffer of the 256 KiB field maximum plus 4096) live in
the same arena, so no secret byte crosses unlocked memory between the file and
a record. A test reads `/proc/self/mem` across every writable mapping of the
test process and asserts a resting secret's plaintext appears nowhere. What
this does not cover: the Argon2 working set, the compositor's copy of a
pasted value, the QML surfaces, and a debugger attached with ptrace — the
`tracer` row exists for that. The vault file format is unchanged; a v2 file
written by 2.4.1 opens as before.

**The witness is a tripwire and the deck says so.** Memory locking is
best-effort and the deck says so. The host can still betray you — core dumps
for other processes, an active swap device — and the deck shows both rather
than claiming a posture it did not achieve.
