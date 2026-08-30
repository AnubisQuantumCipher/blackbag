# Black-Bag

Credential storage for Omarchy, with a full-screen command deck.

This is a Linux-only rebuild of the engine behind the [`black-bagg`][crate]
crate, plus a Quickshell plugin (`khephri.blackbag`) that gives it a bar widget
and a mission-control cockpit.

It exists because reading the published crate closely turned up nine findings,
several of them load-bearing. They are written up in **[`docs/AUDIT.md`][audit]**
— including one that needs your hands rather than mine.

[crate]: https://crates.io/crates/black-bagg
[audit]: docs/AUDIT.md

## Documentation

| | |
|---|---|
| [User manual](docs/MANUAL.md) | Install, everyday use, the full keyboard map, the CLI reference, recovery, troubleshooting. |
| [Whitepaper](docs/WHITEPAPER.md) | Threat model, vault format, key hierarchy, the hybrid recipient construction, and a thorough list of what this system does **not** prove. |
| [Audit](docs/AUDIT.md) | The nine findings in the predecessor crate that this rebuild answers. |
| [Changelog](CHANGELOG.md) | What changed, and why. |
| [Security policy](SECURITY.md) | How to report something, and what is in and out of scope. |

If you read one thing before trusting this with a credential, read the
**non-claims** section of the whitepaper.

---

## What is different from `black-bagg` 0.4.10

**Post-quantum protection that actually protects something.** 0.4.x generated an
ML-KEM keypair, encapsulated to its own public key, and stored the decapsulation
key in the same file under the same passphrase — so the KEM contributed nothing.
Here, recovery recipients are a hybrid of X25519 and ML-KEM-1024 whose private
half is written to a key file you keep offline and is **never stored in the
vault**. That key opens the vault without the passphrase, and revoking it takes
one command.

**Rotation that rotates.** `black-bag rekey` mints a new data key, re-encrypts
the payload under it, re-wraps every recipient, and can change your passphrase in
the same step. 0.4.x's `rotate` re-wrapped the *same* data key and could not
change the passphrase at all.

**An authenticated header.** The epoch, the Argon2 parameters, and every
recipient descriptor are covered by an HMAC keyed from the data key. Editing any
of them is detected at unlock.

**An anti-rollback epoch.** Every write bumps a counter, and the highest counter
seen is recorded outside the vault. Restoring an old file is noticed. This is a
tripwire, not a guarantee — an attacker who can rewrite the vault can usually
rewrite the witness too — and the cockpit says so.

**Hardening restored from the 0.2.x line**, which the 0.4.x rewrite dropped:
core dumps disabled, `PR_SET_DUMPABLE` cleared, tracer detection, pre- and
post-parse size caps, payload padding so the file size stops leaking how much you
store, secrets written to `/dev/tty` rather than stdout, and Argon2id back to
time=10 / lanes≥4 from 0.4.x's time=3 / lanes=1.

**`panic = "unwind"`.** 0.4.x used `panic = "abort"`, which turns any panic into
SIGABRT with no unwinding — so `Zeroizing` destructors never run and, with core
dumps enabled, secrets land in the dump.

**The mlock bug is fixed.** 0.4.x zeroized a `Vec` and then tried to `munlock` it
using its now-zero length, so the unlock never happened. There is a regression
test that clears the buffer first and asserts the page is still released.

---

## Install

```bash
git clone <this repo> ~/Projects/blackbag
cd ~/Projects/blackbag
cargo build --release
install -Dm755 target/release/black-bag ~/.local/bin/black-bag

# the Omarchy surfaces
cp -r plugin/khephri.blackbag ~/.config/omarchy/plugins/
~/.config/omarchy/plugins/khephri.blackbag/install.sh
```

The installer adds the bar widget, binds `SUPER+SHIFT+K`, writes a hardened
systemd user unit for the unlock agent, and rescans the shell.

---

## Use

```bash
black-bag init                       # create a vault (Argon2id, 256 MiB default)
black-bag recovery add offsite --out ~/recovery.key   # do this before you need it

black-bag add login --title GitHub --attr username=octocat
black-bag list
black-bag get <uuid> --reveal password --to clipboard

black-bag doctor                     # vault + host posture
black-bag rekey --change-passphrase
```

Coming from `black-bagg`:

```bash
black-bag migrate --from ~/.config/black_bag/vault.cbor --to ~/.local/share/black-bag/vault.cbor
```

There is deliberately **no `--passphrase` flag**. Passphrases are read from the
terminal, or from stdin when there is no terminal — never from `argv`, because
`/proc/<pid>/cmdline` is world-readable.

---

## Authoring

The deck fills its own vault — there is no step where you have to drop to the
CLI. `n` opens the editor, `e` edits the selected record, `Delete` removes one
(twice, deliberately).

Twelve kinds, each with the fields it actually needs: logins, 2FA codes, API
keys, SSH and PGP keys, wallets, bank details, Wi-Fi, ID documents, contacts
with several numbers and addresses, secure notes, and recovery kits.

- **`Ctrl+G` generates** into the focused field, and reports honest entropy.
  The figure is `log2(charset^length)` corrected for the class-presence
  requirement, and it is quoted for **generated values only**. There is
  deliberately no function that takes a typed string and returns bits, because
  that number would be a guess wearing a measurement's clothes.
- **`otpauth://` paste** sets up 2FA in one field — secret, issuer, account,
  digits, period and algorithm all come from the URI. A bare base32 secret works
  too, and spaces, hyphens and case are all tolerated.
- **Editing never loads a secret.** A blank secret box means "keep what is
  stored", so the form can exist without the cockpit ever holding your password.

## Credential hygiene

Computed entirely on this machine. There is no network call in this crate and
adding one would defeat the point.

The interesting one is **reuse detection**. Every secret field carries a
non-reversible 8-character BLAKE3 handle, domain-separated by field name, so two
records holding the same password produce the same handle — and the vault can
tell you they match **without ever comparing, storing or displaying a secret**.
It also flags short passphrases, all-numeric secrets that are too short to be
worth their length, staleness, duplicate titles, and logins with no second
factor stored alongside them.

Honest limits, all of which are in the module docs:

- A handle match means *these share a handle*, not *these are provably
  identical* — 32 bits, so collisions exist.
- Absence of a reuse cluster is not absence of reuse: the domain is the field
  name verbatim, so a `password` and a `passphrase` holding the same value do
  not cluster.
- Staleness is a lower bound. The vault stores no per-field change time, so a
  record touched to fix a tag reports as fresh.
- "No second factor" means *not stored in this vault*, never *this account
  lacks 2FA*.
- The report carries handles and titles, so it is as sensitive as the open
  vault. It travels over the agent socket only and is **never** written to
  `status.json`.

## The cockpit

`SUPER+SHIFT+K`, or click the lock in the bar.

- **Left rail** — vault state, format, epoch against the witness, a twelve-kind
  census, recipients (marked by whether their private key is held offline), and
  host posture: mlock, core dumps, swap, memlock budget, tracer.
- **Centre** — the unlock panel when sealed; a searchable record table when open.
  Search covers titles, tags, and usernames, and by construction cannot reach
  secrets.
- **Right rail** — inspector for the selected record, findings worst-first, and
  session controls. TOTP codes come with a countdown arc that turns red in the
  last five seconds.

Keys: `n` new · `e` edit · `Del` remove · `/` search · `↑↓` move · `⏎` copy ·
`⇧⏎` show · `^L` lock · `Esc` close. In the editor: `Tab` moves · `^G` generates
· `^⏎` saves · `Esc` cancels.

### Where secrets are, and are not

| Surface | Holds a secret? |
|---|---|
| `status.json` in `$XDG_RUNTIME_DIR` | **Never.** No titles, tags, counts, or values — only posture, parameters, recipient labels, and lock state. There is a test that asserts this. |
| Bar widget | Never. Reads only `status.json`. |
| Cockpit | Only during an explicit `SHOW`, on a visible countdown, then cleared. `COPY` goes straight to the clipboard and never renders. |
| Agent | Holds the data key in page-locked memory while unlocked, behind a `0600` socket in a `0700` directory, with `SO_PEERCRED` checked on every connection. |
| Clipboard | For the configured interval (30 s default), then wiped. |

The record *metadata* the cockpit shows arrives over the agent socket and lives
in the shell's memory, never on disk. Secret fields are shown as a name, a size,
and an 8-character non-reversible handle — enough to see that two entries share
a password without either being displayed.

---

## Honest limits

- **The witness is a tripwire.** It catches restored backups, sync conflicts, and
  snapshot rollbacks. It does not stop an attacker who can write both files.
- **`mlock` is best-effort.** This box allows 8 MiB (2048 pages). Failures are
  reported in `doctor` and the cockpit rather than swallowed.
- **The host can still betray you.** Core dumps are disabled for our own process,
  but `core_pattern` on this machine pipes to systemd-coredump for everything
  else, and zram swap is active. The cockpit shows both rather than claiming
  "zero trace".
- **No formal verification.** Unlike `attest` or the SPARK work elsewhere on this
  machine, this is ordinary Rust with tests. The audit is a careful read plus an
  adversarial second opinion. Treat it as that and nothing more.
- **`black-bagg` on crates.io is unchanged.** This repo does not and cannot alter
  what is already published there.

---

## Licence

MIT OR Apache-2.0, matching the original crate.
