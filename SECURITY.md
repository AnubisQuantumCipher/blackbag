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
- `mlock` failing on a host with no memory-lock budget. This is reported rather
  than silently swallowed, which is the intended behaviour.

## Supported versions

The most recent release. This project has one maintainer and no capacity to
backport.

## A note on the predecessor

This project exists because a close reading of the earlier `black-bagg` crate
turned up nine findings, written up in [`docs/AUDIT.md`](docs/AUDIT.md). One of
them concerns a credential exposed in published artefacts. Its specifics are
withheld from the public document pending remediation, which is the same
courtesy extended to anyone reporting here.
