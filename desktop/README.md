# BLACK-BAG — desktop application

The credential command deck as a standalone window, for a desktop that is not
running the Omarchy shell.

![The deck, unlocked](../docs/screenshots/desktop-deck.png)

It is the same deck. `Cockpit.qml`, `Editor.qml` and `Model.js` are the
plugin's files, generated from them by `port-from-plugin.py`, and CI fails if
the two copies disagree. The plugin wraps them in a Wayland layer-shell
overlay; this wraps them in a window. Nothing else differs, which is the point:
a fix belongs to the deck, not to one of its hosts.

## What it is, and what it deliberately is not

This program is a renderer and a process driver.

It holds no key material. It derives no key. It performs no cryptography. It
never opens the vault file. Every posture on screen is `black-bag`'s own JSON,
carried through verbatim, and where the engine declines to state something the
deck draws it as unknown rather than filling in a pass.

Driving the engine as a child process rather than linking the library is a
deliberate choice. It keeps the audited JSON boundary, and it keeps plaintext
out of this process's address space — a GUI is a large, long-lived program full
of caches, and it is the wrong place for a decryption key to live.

Three rules follow from that and are enforced throughout:

1. **No secret is stored here.** Record metadata — titles, tags, usernames, and
   non-reversible *handles* for secret fields — comes from the agent. Secret
   bytes are fetched only on an explicit `COPY` or `SHOW`, and a `SHOW` clears
   itself on a countdown you can watch.
2. **A passphrase crosses on stdin.** Never in an argument vector:
   `/proc/<pid>/cmdline` is world-readable, so a `--passphrase` flag would
   publish the passphrase to every process on the machine. There is no such
   flag, in this program or in the engine.
3. **Unknown is drawn as UNKNOWN.** A status older than the stale threshold
   desaturates rather than asserting a posture it cannot vouch for.

The one thing this process puts on the clipboard itself is non-secret text — a
username, a URL. Secrets go to the clipboard through
`black-bag agent copy --to clipboard`, so the plaintext is written by the
engine and wiped by the engine on its own timer, and this process never sees
it.

## Requirements

- `black-bag` on `PATH` (`cargo build --release` in the repository root)
- Qt 6.5 or newer: Core, Gui, Qml, Quick, QuickControls2, Network, Svg
- CMake 3.21 or newer, a C++20 compiler

## Install

```sh
./install.sh
```

Builds and installs under `~/.local` — binary, desktop entry, scalable icon,
AppStream metadata. No root, no system directories. `PREFIX=/usr/local
./install.sh` if you would rather it go elsewhere.

Then start the unlock agent, so the deck and the CLI share one unlocked vault:

```sh
systemctl --user enable --now black-bag-agent
```

## First run

With no vault at the path, the deck offers to create one — passphrase, then the
offline recovery key, then it opens. There is no step that requires a terminal.

A generated passphrase is shown in plain text so you can write it down, and the
engine's entropy verdict is shown with it. A passphrase you typed gets no
score: the engine rates only what it generated, and inventing a
character-class estimate for a phrase a person chose reliably overstates it.

## Keys

| | |
|---|---|
| `⏎` | unlock (sealed) · copy the selected record's primary field (deck) |
| `⇧⏎` | reveal the primary field, on a countdown |
| `u` | focus the passphrase field (sealed) |
| `/` | search titles, tags, usernames — never secrets |
| `↑` `↓` / `k` `j` | move the selection |
| `PgUp` `PgDn` | move ten · `Home` `End` first and last |
| `n` | new record |
| `e` | edit the selected record |
| `Del` / `Ctrl+D` | remove it — asked twice, and there is no trash |
| `⌫` | clear the kind filter |
| `Ctrl+L` | lock now |
| `Ctrl+R` | refresh status and records |
| `Esc` | back out one layer; close when there is nothing left to back out of |
| `Ctrl+Q` / `Ctrl+W` | quit |

During first run: `Ctrl+G` generates a passphrase, `Ctrl+↵` commits the step,
`Esc` abandons it.

In the editor: `⌃⏎` saves, `⌃G` generates into the focused field, `Tab` and
`⇧Tab` move between fields, `Esc` abandons the sheet.

A 2FA code is not a key — selecting a record that has one fetches it, and it
re-fetches itself just after its step rolls over rather than on a timer of its
own.

`Esc` never closes more than you meant: it drops a revealed secret first, then
a pending delete, then a search, and only then the window.

Closing the window does **not** lock the vault. The agent holds the session —
that is what the agent is for — and locking is a deliberate act: `Ctrl+L`, the
`LOCK NOW` chip, `black-bag agent lock`, or the launcher's "Lock the vault now"
action.

## Settings

`~/.config/black-bag/desktop.json`, watched, so an edit lands without a
restart.

```json
{
  "revealSeconds": 10,
  "clipboardClearSec": 30,
  "staleAfterSec": 120,
  "motionEnabled": true,

  "fontFamily": "monospace",
  "fontBaseSize": 12,
  "spacingScale": 1.0,
  "cornerRadius": 4,

  "theme": { "accent": "#7fd7a0" }
}
```

The first four are the plugin's settings under the same names and the same
defaults, restated in `Model.js` so the two surfaces cannot disagree about how
long a revealed secret stays on screen. The palette follows the desktop theme
(`~/.local/state/omarchy/current/theme/colors.toml`) when there is one; the
`theme` block overrides individual colours. `window` is written by the
application and is its own business.

An unrecognised key is ignored rather than surfaced — a typo that silently
becomes a setting is a setting nobody can find again.

## Working on it

`Cockpit.qml`, `Editor.qml` and `Model.js` in `qml/` are **generated**. Edit
`plugin/khephri.blackbag/` and run:

```sh
./port-from-plugin.py           # regenerate
./port-from-plugin.py --check   # what CI runs
```

Everything else here is the application's own:

| | |
|---|---|
| `src/app.*` | the desktop: engine lookup, clipboard, settings, palette, geometry |
| `src/process.*` | an async child process, API-compatible with Quickshell's `Process` |
| `src/fileview.*` | a watched file, API-compatible with Quickshell's `FileView` |
| `src/datastream.*` | `StdioCollector` and `SplitParser`, same API |
| `qml/Main.qml` | the window |
| `qml/Color.qml` `Style.qml` `Util.qml` | the palette, the metric scale, colour arithmetic |
| `qml/InputField.qml` | the text input the shell's widget kit used to supply |

The C++ shims exist so the deck's QML does not have to know which host it is
in. They spawn, watch and buffer; they do not parse the engine's output and
never decide that a command succeeded.
