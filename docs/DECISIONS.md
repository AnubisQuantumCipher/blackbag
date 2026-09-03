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

## D3 — `passkey-rs`: borrow, do not adopt

Keep our authenticator. `passkey-authenticator` is ES256-only, its PRF is the
unsigned WebAuthn form with no `pinUvAuth` — so it cannot serve lane B's CTAP2
`hmac-secret` — and `Ctap2Api` is sealed, so ours could not plug into
`passkey-client` regardless.

Borrow what is cheap: `passkey-types` for the WebAuthn JSON and CTAP2 types,
`public-suffix` and `RpIdValidator`, and `CollectedClientData`.

Add `passkey-authenticator` as a **dev-dependency** and differential-test our
ES256 + PRF path against it in CI: same inputs, both outputs verify under
`webauthn-rs`, same `authData` layout, same PRF bytes. Ed25519 and RS256 are
ours regardless.

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
