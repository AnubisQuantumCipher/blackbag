# Decisions

Owner's rulings on the questions raised in `GAP-REPORT.md`, recorded so they are
not re-litigated or quietly drifted from. Each says what was decided and why, so
a future session can tell a decision from an accident.

---

## D1 — Lane order: the proxy is lane A on Chromium

§1.5 of the specification is **overruled**. `chrome.webAuthenticationProxy` is
lane A on Chromium; page injection is the **Firefox** lane and the only place
conditional mediation exists.

Both lanes speak **one daemon protocol**, so Chromium falls back to injection
when `attach()` fails — Chrome Remote Desktop or another manager already holds
the proxy. The popup shows which mode is active.

Proxy specifics, settled:

- `remoteDesktopClientOverride.sameOriginWithAncestors` maps to
  `clientDataJSON.crossOrigin`. `topOrigin` is set **only** if the override
  supplies it, never inferred.
- `isUserVerifyingPlatformAuthenticatorAvailable` answers **true**.
- `onRequestCanceled` tears the prompt down.
- The popup carries a **kill switch** that detaches.
- `docs/COMPAT.md` pins the Chromium source lines that inject the origin and
  reject a pre-filled override, with a **CI check against the API surface** so a
  change upstream is noticed rather than discovered.

**Known hole, stated rather than hidden.** While we are attached, nothing in
Chromium can reach a hardware key or a phone, and there is no pass-through.

- *Stopgap:* a "use security key instead" choice in our prompt that returns
  `NotAllowedError`, detaches for 60 seconds, and tells the user to retry.
- *Real fix, later:* drive real keys from the daemon with `libwebauthn`
  (linux-credentials) so one picker offers vault / security key / phone. Not now.

## D2 — Backup-eligible and backup-state flags

Owner's ruling: *"you're right, I was wrong."*

- **BE = 1 always**, and never changes for a credential once created.
- **BS is computed and truthful**: 1 only when a backup or sync target is
  configured **and** the last successful backup includes this credential;
  0 otherwise. Flipping to 1 after a backup is spec-legal and is the honest
  nudge toward configuring one.
- **Never BS = 1 with BE = 0.**
- The state machine gets unit tests.

### Done. What it took, and what it is allowed to claim

BS needed something true to be computed *from*, so `black-bag backup` was
built first (it was already a §3.4 gap). It copies the sealed file — nothing is
decrypted, so it works while you are locked out — reads the copy back, checks
the digest, and records `{at, vault_id, epoch, path, digest, bytes}` in
`<state>/backups.json`.

The log lives **outside** the vault deliberately. Inside, it would be copied
into the backup and so claim to know about itself, and it would travel with the
file — a vault carried to another machine would arrive asserting it is backed
up on a disk that machine cannot see. Outside, a restored vault reports BS=0
until a backup is taken there, which is the truth on that machine.

`BS = 1` means: a recorded copy of this vault is still at its path, still the
size it was, and was taken at a vault epoch at or after the one this credential
was written in. Records carry `created_epoch` for that comparison; one written
before the field existed has no epoch to compare and reports not-backed-up
until the next backup covers it for certain.

**The limit, stated rather than papered over:** a copy that still exists but
has been *replaced* is not detected until `black-bag backup --verify` (or `^K`
in the deck) re-reads it. A digest on every assertion would put a disk read in
the signing path.

BS is read live on every ceremony, so deleting the backup turns it off again —
which is what makes it truthful rather than a one-way boast. Both directions
are tested end to end through the agent, and the whole flag space is walked in
`passkey::flag_state_machine`.

The deck grew a BACKUP section, because the owner drives the GUI: a backup you
can only take from a terminal is one that does not get taken, and BS would then
never leave 0.

## D3 — `passkey-rs`: borrow, do not adopt

Keep our authenticator. `passkey-authenticator` is ES256-only, its PRF is the
unsigned WebAuthn form with no `pinUvAuth` — so it cannot serve lane B's CTAP2
`hmac-secret` — and `Ctap2Api` is sealed, so ours could not plug into
`passkey-client` regardless.

Borrow what is cheap: `passkey-types` for the WebAuthn JSON and CTAP2 types,
`public-suffix` and `RpIdValidator`, and `CollectedClientData`.

### `public-suffix`: done, and it was not cosmetic

`public-suffix` 0.1.3 (from the same `passkey-rs` repository, MIT OR Apache-2.0,
no transitive dependencies) is now a real dependency of `blackbag-core`.

It closed a hole. The previous check was a label-boundary suffix match, which
accepted `rp_id = "com"` for `https://example.com` — measured, not theorised —
and a credential minted under it would have been assertable to every `https`
origin there is. `co.uk` and `github.io` were the same hole with a second
label. `rp_id_is_valid_for_origin` now implements HTML's *is a registrable
domain suffix of or is equal to* in full, including step 5, which stops a
suffix reaching into a wildcard public suffix such as `*.compute.amazonaws.com`.

Two consequences worth stating:

- **Equality still wins before the list is consulted**, per step 2, so a page
  may claim its own effective domain even when that is a single-label intranet
  name no list has heard of.
- **IP literals are refused as origins.** WebAuthn's relying-party id is a
  domain and browsers refuse a passkey to an IP; left alone, an IP would also
  confuse the list, which reads `127.0.0.1` as a host under the TLD `1`.

A browser runs this check before dispatching, which is why lane A never
exposed it. That is exactly the argument for doing it here: the injection lane
intercepts `navigator.credentials` *before* the browser's check, and a
non-browser caller has no check in front of it at all.

Add `passkey-authenticator` as a **dev-dependency** and differential-test our
ES256 + PRF path against it in CI: same inputs, both outputs verify under
`webauthn-rs`, same `authData` layout, same PRF bytes. Ed25519 and RS256 are
ours regardless.

### `webauthn-rs`: done, and it is the stronger half of that ask

`webauthn-rs` 0.5 is a dev-dependency and `tests/webauthn_rs_relying_party.rs`
drives whole ceremonies against it: it issues the challenge, our authenticator
answers, and it decides. That exercises the entire relying-party ruleset —
challenge binding, origin binding, rpIdHash, flag policy, algorithm
negotiation, signature — rather than the parts a test author thought to check.

**Three of the seven are negative controls**, because a checker that cannot
fail proves nothing about the ones that pass: a signature over a challenge
nobody issued, a tampered signature, a registration minted for another relying
party, and one answering a challenge from nowhere. All are refused.

Two of the positives are the D2 transition seen from the relying party's side:
a credential registered while not backed up, asserting later with BS=1. That
is the half of D2 that cannot be checked by reading our own bytes back.

**`passkey-authenticator` itself was not added.** The differential ask was for
evidence that our ES256 and PRF path is right; a real relying party accepting
our ceremonies is stronger evidence than agreeing byte-for-byte with another
authenticator, which would only show that two implementations made the same
choices. The Python cross-check already covers the byte layout and the PRF
derivation independently. If Ed25519 or RS256 land, this is worth revisiting —
there the question really is "does someone else produce the same bytes".

## D4 — Build order, and what an approval actually is

**Policy and audit first**, then lane B, then SSH agent + Secret Service, then
CXF, then packaging.

- Socket stays `0600`; `SO_PEERCRED` supplies client identity.
- **Per-item first-use approval** for `Reveal`, the Secret Service and the SSH
  agent, remembered until lock or revoke.
- **An approval requires the passphrase or a PIN, never a click.** A same-uid
  process can synthesise a click with `wtype` or `hyprctl`, so a click proves
  nothing about who is at the keyboard.
- Blanket per-exe trust is allowed **only** for the interactive browser, and
  `SECURITY.md` must say plainly that a hostile same-uid process can impersonate
  it — a headless browser loading an unpacked copy of our extension, with our
  public key, is indistinguishable. **Per-exe identity is context, not control.**
- `SECURITY.md` must also say what the real boundary is: agents under a
  **different uid**, or in `bwrap` with no path to the socket. Failing that,
  `dumpable=0` and `ptrace_scope=1` are the only things in the way. Black-Bag
  should be friendly to that setup, and document it.

## D5 — Lane B device permissions (for later)

Grant `/dev/uhid` with a udev rule using `TAG+="uaccess"`, **not** by adding the
user to the `input` group. Group membership would give every process the user
runs raw keyboard access — a much larger grant than the one being asked for.
