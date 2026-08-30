# Black-Bag — user manual

For version 2.0.0 of the engine and the `khephri.blackbag` plugin.

---

## 1. What this is

Black-Bag stores credentials in a single encrypted file on this machine and
gives you two ways to reach them: a command-line tool, `black-bag`, and a
full-screen Quickshell deck bound to `SUPER+SHIFT+K`. The file is sealed with
XChaCha20-Poly1305 under a data key that is wrapped for your Argon2id-derived
passphrase key and, optionally, for one or more recovery key files you keep
offline. While the vault is open, a small agent holds the data key in
page-locked memory behind a `0600` unix socket and forgets it on a deadline.

What it is not, stated plainly because these absences are the design:

- **Not a sync service.** Nothing is uploaded, mirrored or backed up for you.
  If you want the vault on two machines you copy the file yourself, and the
  anti-rollback witness (§10) will notice when the two copies disagree.
- **Not a browser extension.** There is no autofill, no native messaging host,
  no page integration. You copy a value and paste it.
- **Not networked at all.** The engine opens no sockets except the local unix
  socket the agent listens on. Credential hygiene, entropy accounting and
  TOTP are all computed in this process. There is no breach lookup, because
  adding one would mean sending something about your passwords somewhere.

There is no formal verification here. This is ordinary Rust with tests.

---

## 2. Requirements and install

### What you need

| | |
|---|---|
| Rust | 1.82 or newer, with `cargo` |
| OS | Linux. The engine uses `mlock`, `prctl`, `/proc` and `SO_PEERCRED` and is not portable off it |
| `wl-clipboard` | for `--to clipboard` and for COPY in the deck. Without `wl-copy` on `PATH`, copying fails with a clear error |
| Omarchy shell | Quickshell with `omarchy-shell`, for the bar widget and the deck. The CLI works without it |
| `python3` | used by the plugin installer to edit `shell.json` |
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

### The agent unit

The unit is written but **not enabled**, because starting it is a decision:
a running agent is what lets an unlocked vault survive between commands.

```bash
systemctl --user enable --now black-bag-agent
systemctl --user status black-bag-agent
```

It runs `black-bag agent serve --idle-secs 900` under a strict sandbox —
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only` with three
explicit `ReadWritePaths`, `MemoryDenyWriteExecute`, and `LimitCORE=0`. To
change the idle timeout, edit `ExecStart` in that file and
`systemctl --user daemon-reload`.

The CLI does not need the agent. `black-bag list`, `get`, `add` and the rest
open the vault themselves and ask for the passphrase every time. The agent
exists so that the deck, and repeated CLI use, do not.

---

## 3. First run

```bash
black-bag init
```

You are asked for a passphrase twice. Nothing is echoed. The vault is created
at `~/.local/share/black-bag/vault.cbor` with mode `0600`, with Argon2id at
256 MiB, time cost 10, and lanes set to your core count clamped to 4–8.

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
  when there is one, hygiene findings worst-first, and session controls.

### Copying, showing, and 2FA

`Enter` copies the selected record's primary secret field to the clipboard via
`black-bag agent reveal --to clipboard`. The value never renders. The
clipboard is cleared after `clipboardClearSec` (default 30) by killing the
`wl-copy` process that is serving the selection.

`Shift+Enter`, or the SHOW button, puts the value on screen for
`revealSeconds` (default 10) with a countdown; `Esc` hides it immediately.

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
| `Ctrl+L` | lock the agent now |
| `Ctrl+R` | re-publish status and re-read the record list |
| `Esc` | step back (see below) |

`Ctrl+L`, `Ctrl+R` and `Esc` are window-scoped and work wherever the caret is.
The plain letter keys are deliberately dead while a text field has focus.

`Esc` does the smallest useful thing first: hide a revealed secret, then
cancel a pending delete, then clear the search box, then close the deck.

In the search box:

| Key | Action |
|---|---|
| `Enter` or `↓` | leave the box and select the first result |
| `Esc` | clear the query; if already empty, leave the box |

In the editor sheet:

| Key | Action |
|---|---|
| `Tab` / `Shift+Tab` | next / previous field |
| `Ctrl+G` | generate into the focused secret field |
| `Ctrl+Enter` | save |
| `Esc` | cancel |

Mouse: click a row to select, double-click to copy its primary field; COPY and
SHOW buttons per secret field; LOCK NOW and REFRESH in the session card;
clicking a hygiene finding jumps to its record.

---

## 5. Adding and editing records

`n` opens the editor. Pick a kind, give it a title, optionally tags, fill the
open attributes and the secret fields, `Ctrl+Enter` to save. The draft travels
to the agent as JSON on stdin — never as command-line arguments.

### The twelve kinds

`attrs` are open metadata; they live inside the encrypted payload but are not
page-locked and are searchable. `secrets` are page-locked fields, wiped on
drop, and never searched.

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
uppercase, digits and symbols — and drops the result into the field.
Multi-line fields are not generatable.

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
is no network call.

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
| `black-bag agent serve` | `--idle-secs <SECS>` (900) | Foreground. The systemd unit runs this |
| `black-bag agent unlock` | — | Passphrase from the terminal, or one line on stdin |
| `black-bag agent lock` | — | Forgets the data key immediately |
| `black-bag agent status` | — | JSON: lock state, deadline, record count, counts by kind |
| `black-bag agent stop` | — | Stops the agent |
| `black-bag agent list` | `--json`, `--kind`, `--query` | Titles, tags, attributes and per-field handles. Never secret bytes |
| `black-bag agent reveal <ID> <FIELD>` | `--to tty\|clipboard\|stdout` (**clipboard**), `--clear-after <SECS>` (30) | |
| `black-bag agent show <ID> <FIELD>` | — | The one command that writes a secret to stdout |
| `black-bag agent totp <ID>` | — | JSON: `code`, `ttl_secs`, `step` |
| `black-bag agent add` | — | Reads a JSON record draft on stdin |
| `black-bag agent edit <ID>` | — | Reads a JSON record draft on stdin |
| `black-bag agent delete <ID>` | `--yes` (required) | |
| `black-bag agent hygiene` | `--json` | Default output is counts and per-record lines; `--json` is as sensitive as the open vault |

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
  payload — becomes a page-locked secret field, because notes on a credential
  routinely are one.
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
for status alone does not extend it. Locking also happens on `Ctrl+L`, on
LOCK NOW, on `black-bag agent lock`, and whenever the agent process restarts.

### `mlock` failures

`doctor` reports the memlock ceiling and whether a probe lock succeeds right
now. On a stock Omarchy box `ulimit -l` is 8192 KiB, which is 2048 pages;
`MEMLOCK_TIGHT` is a note, not an error, and means large secrets may fail to
lock. `MLOCK_FAILED` is a warning and means the probe itself failed — secrets
may be paged out while the vault is open. Failures are reported rather than
swallowed; the engine keeps working, because refusing to open your vault
because a resource limit is low would be worse than telling you about it.

Raise it with `ulimit -l` before starting the agent, or with `LimitMEMLOCK=` in
the unit, if your policy allows it.

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

### Clipboard copying does nothing

`wl-copy` must be on `PATH`; install `wl-clipboard`. Copying works by leaving
`wl-copy --foreground` running to serve the selection, and clearing works by
killing it after the timeout — so if something else takes ownership of the
clipboard in the meantime, the timeout has nothing left to clear.

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
`XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_RUNTIME_DIR`, and `BLACK_BAG_PAD_BLOCK`
(payload padding block, default 4096, accepted from 1 to 1048576).

### The security boundary, stated so you can act on it

**`status.json` is plaintext and is what the bar widget reads.** It carries
only: schema and engine version, the vault path, format, id and timestamps,
the epoch and the witnessed epoch, recipient *labels* and whether each one's
private key is held externally, the Argon2 parameters, the session's lock state
and deadline, host posture, and the derived findings. It carries no record
titles, no tags, no counts, and no secrets. There is a test that asserts this.
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
widget settings) works by killing the `wl-copy` process that is serving the
selection. It is a wipe of your clipboard, not of any clipboard manager's
history, and not of an application that has already read the value.

**The witness is a tripwire and the deck says so.** `mlock` is best-effort and
the deck says so. The host can still betray you — core dumps for other
processes, an active swap device — and the deck shows both rather than
claiming a posture it did not achieve.
