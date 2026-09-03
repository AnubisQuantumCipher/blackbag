# Contributing

## Before anything else

Read [`docs/WHITEPAPER.md`](docs/WHITEPAPER.md), particularly the **non-claims**
section. The character of this project is that it does not overclaim, and a
change that quietly widens a claim is a regression even if the code is correct.

## The rules that are not negotiable

1. **A secret never reaches argv, a log, an error message, or a `Debug` impl.**
   `/proc/<pid>/cmdline` is world-readable. There is no `--passphrase` flag and
   there will not be one.
2. **`status.json` carries no record data.** No titles, tags, counts, or values.
   There is a test that asserts this; it is not decoration.
3. **Absence renders as absence.** "Not measured" must never look like
   "measured and fine". Unknown is drawn as UNKNOWN.
4. **The agent never touches the network, and nothing goes online unasked.**
   The agent's unit forbids every address family but `AF_UNIX`, and that is
   not to be loosened. The one sanctioned network act in the whole program is
   the breach check: opt-in per run (`--online`, or the deck's two-step
   button), five-character hash prefixes only, fetched by `curl` from the
   CLI, matched inside the agent. No telemetry, no update checks, no favicon
   fetching — ever. A change that adds a second network path needs a
   whitepaper section stating exactly what leaves the machine before it
   needs code.
5. **Comments state constraints the code cannot show.** Not what the next line
   does, not why a change was made, not who made it.

## First, once per clone

```sh
git config core.hooksPath .githooks
```

That enables the pre-commit secret scan. It is not box-ticking: a crates.io
token was published in six releases of this project before anyone noticed, and
it got there as an ordinary-looking line in an ordinary-looking file. The hook
uses `gitleaks` when it is installed and falls back to a smaller built-in scan
when it is not, so a machine without `gitleaks` is not a machine without a
check.

## Building and testing

```sh
cargo build --release
cargo test --workspace              # must pass
cargo build --release 2>&1 | grep -c warning   # must be 0

plugin/khephri.blackbag/tests/run.sh           # QML assertions + structural invariants
node extension/tests/encoding.test.js          # browser-extension encoding
python3 desktop/port-from-plugin.py --check    # the two QML hosts agree
qmllint -I ~/.local/share/omarchy/shell -I /usr/lib/qt6/qml plugin/khephri.blackbag/*.qml
```

All of them must be clean before a pull request.

`tests/structure.py`, which `run.sh` runs, holds invariants about the QML that
no type checker can see — each one is there because breaking it caused a real
failure, and each says which failure in a comment. Add to it when you find the
next one.

## Testing the QML surfaces

The plugin runs inside a live Quickshell process, so changes need a shell
restart to load — the shell runs with its file watcher disabled:

```sh
cp -r plugin/khephri.blackbag ~/.config/omarchy/plugins/
~/.local/share/omarchy/bin/omarchy-restart-shell
omarchy-shell shell summon khephri.blackbag '{}'
```

If you automate UI checks, **verify that your pointer actually moved** before
trusting a click test. On at least one development machine `ydotool mousemove -a`
silently does nothing while `hyprctl cursorpos` keeps reporting the old
position, which produces an extremely convincing false negative. Keyboard
injection is reliable; mouse injection may not be.

## Style

Match the surrounding code. `anyhow::Result` and `bail!` in the engine, doc
comments on public items, plain prose in documentation with limits stated as
prominently as capabilities.

## Cryptographic changes

Changes to the vault format, the key hierarchy, the recipient construction, or
the entropy accounting need more than a passing test suite. Say in the pull
request what property you believe the change preserves, and what would have to
be true for you to be wrong.
