# Security policy

## Reporting a vulnerability

Report privately, not in a public issue: **khephri.labs@proton.me**.

Include what you need to make the case — a description, the affected version or
commit, and ideally the smallest reproduction you can manage. If you would like
an encrypted reply, say so and include a key.

Expect an acknowledgement within a few days. This is a single-maintainer
project, so a fix may take longer than an acknowledgement; you will be told
which of those you are waiting on.

If you would like credit in the changelog, say so. If you would prefer not to be
named, that is the default.

## What is in scope

Anything that breaks a property this project actually claims. The claims, and
just as importantly the **non-claims**, are enumerated in
[`docs/WHITEPAPER.md`](docs/WHITEPAPER.md). Worth reading before reporting,
because several plausible-sounding findings are already documented as things
this system deliberately does not defend against.

Particularly interesting:

- Recovering vault plaintext without the passphrase or a recovery key.
- Any path by which a secret reaches `status.json`, a log, a command line, or
  the process's own `Debug` output.
- Defeating the authenticated header, or making a modified vault unlock.
- Reaching the agent socket as a different user.
- A generated password with less entropy than the generator reports.
- Hygiene reporting reuse that is not reuse, or missing reuse that is.
- A resting secret's plaintext appearing in the process's writable memory
  while the vault is unlocked and the field is not in use.
- A copied secret offered without the sensitive hint, or surviving its clear
  while the selection is still ours.
- The agent process opening any network socket, or the breach check sending
  more than five-character SHA-1 prefixes.
- The vault staying unlocked across a suspend or a session lock the agent was
  told about.

## The boundary this program has, stated plainly

Black-Bag's agent listens on a Unix socket, `0600` inside a `0700` directory,
and checks `SO_PEERCRED` on every connection so that only the same uid can
speak to it. That check is correct and **it is not a security boundary**,
because everything in your desktop session already runs as that uid: your
browser, your editor, your shell, and every coding agent you start.

So be exact about what the pieces do.

### What actually stops something

- **A different uid.** A process running as another user cannot open the
  socket. This is the real boundary.
- **A sandbox with no path to the socket.** `bwrap` without
  `$XDG_RUNTIME_DIR/black-bag` bind-mounted in, a container, a VM. The agent is
  friendly to this: it needs nothing but its own runtime directory and its
  vault file.
- **The master passphrase.** Reading a secret for the first time, and every
  passkey signature, costs the passphrase — not a click. A click can be
  synthesised by anything in your session with `wtype` or `hyprctl`; typing
  cannot be, without a keylogger.
- **`ptrace_scope=1` and `dumpable=0`.** With Yama set to 1
  (`/proc/sys/kernel/yama/ptrace_scope`), a process cannot attach to a
  non-descendant, and the agent sets `PR_SET_DUMPABLE=0` so it cannot be dumped
  or attached to at all. Without these, everything below is moot: a process that
  can `ptrace` the agent can read the data key out of it and no policy matters.

If you run agents on this machine, run them under a different uid or in a
sandbox that cannot see the socket. That is worth more than every control in
this program combined.

### What does NOT stop something, and is not claimed to

- **Per-program identity is context, not control.** The agent names the caller
  from `/proc/<pid>/exe`, or `/proc/<pid>/comm` when `ptrace_scope` makes the
  first unreadable. A hostile process running as you can be called anything it
  likes: `comm` is settable with `prctl`, and a program can be copied to any
  path. The name is shown so *you* can recognise what is asking. It is never
  used to grant anything a passphrase did not.
- **Trusting the browser is trusting anything that can look like it.** The one
  place blanket trust is offered is the interactive browser, because a person
  made to type a passphrase for every form fill will switch the whole thing off.
  Understand what you are accepting: a **headless Chromium loading an unpacked
  copy of our extension, carrying our public key, is indistinguishable from
  your real browser** — same executable name, same extension id, same native
  messaging manifest. If that matters to you, do not grant blanket trust, and
  answer each prompt.
- **The audit log records; it does not prevent.** It is hash-chained, so edits
  and removals are detectable and `black-bag audit --verify` says where. It
  cannot stop deletion: whoever can write the file can truncate it. The head
  digest is kept separately so truncation is *visible*, which is the honest
  limit of a local file.
- **A passkey assertion is a login.** It is gated behind a fresh passphrase for
  that ceremony, and bound to the process that asked. Neither survives an
  attacker who already has your passphrase.

### Where the vault is genuinely strong

At rest, and against anyone who does not have the passphrase: Argon2id to a key
encryption key, XChaCha20-Poly1305 over the payload with an authenticated
header, secrets held in locked memory encrypted under a `memfd_secret` session
key, and recovery recipients that are hybrid X25519 + ML-KEM-1024. A copy of
the vault file is not a copy of your secrets.

## What is out of scope

These are stated in the whitepaper as explicitly undefended, and a report that
assumes them will be closed as working-as-documented:

- A compromised host, or malware already running in the session. The vault
  cannot defend itself from a machine that is already lost.
- Side channels observable only by a privileged co-resident process.
- Coercion of the operator.
- The witness file being editable by someone who can already rewrite the vault.
  It is a tripwire against restored backups and sync accidents, not an
  authenticated anti-rollback mechanism, and the documentation says so.
- `memfd_secret` or `mlock` being unavailable on a host. Both are reported
  rather than silently swallowed, which is the intended behaviour.
- A clipboard manager that ignores `x-kde-passwordManagerHint`, or a compositor
  that re-offers the selection without it (GNOME's does). The hint is a
  convention the desktop honours or does not; Black-Bag offers it correctly.
- A paste target keeping its own copy of what was pasted into it.

## Supported versions

The most recent release. This project has one maintainer and no capacity to
backport.

## A note on the predecessor

This project exists because a close reading of the earlier `black-bagg` crate
turned up nine findings, written up in [`docs/AUDIT.md`](docs/AUDIT.md). One of
them concerns a credential exposed in published artefacts. Its specifics are
withheld from the public document pending remediation, which is the same
courtesy extended to anyone reporting here.
