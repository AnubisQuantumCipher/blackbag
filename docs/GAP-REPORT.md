# Gap report — black-bag against the passkey specification

**Date:** 2026-09-03 · **Repo at:** `5efac91` · **Author:** this session

## How to read this

Every "works" below was **run**, not inferred, and says how. Everything I could
not check says so. Where the specification and the machine disagree, the machine
wins and I say what I observed rather than what I expected.

Two conventions from the rest of this project apply here. A refusal is an
answer: where something cannot be done on Linux, that is stated rather than
planned around. And nothing claims a security property it cannot demonstrate.

---

## 1. The one §1 decision that is wrong in practice

The specification says (§1.5) that `chrome.webAuthenticationProxy` is a
"Chromium-only optional experiment", to be prototyped **only after** the page
injection path works, and asks whether the request JSON carries the calling
origin.

**It is not experimental here, it is already built, and it already works.**
Measured on this machine today:

- `strings /opt/brave-bin/brave | grep webAuthenticationProxy` returns the
  complete embedded API schema. Brave 1.93.138 ships it.
- `chrome/common/extensions/api/_permission_features.json` gates it as
  `"channel": "stable"`, `platforms: [linux, mac, win]`, and — unlike its
  neighbours two lines away — carries **no allowlist**. No enterprise policy, no
  Web Store listing, no flag.
- An unpacked extension declaring only `webAuthenticationProxy` attached in
  Brave, and a real `navigator.credentials.create()` from a page was routed to
  it. Credentials were minted into the vault repeatedly through this path
  (12 of them, during testing).

**And the origin question is answered: yes, it does.** Chromium injects the true
caller origin into the request as
`extensions.remoteDesktopClientOverride.origin`, taken from `caller_origin`
immediately before dispatch, and it refuses to proxy a request that already
carries one. A web page cannot forge it. This was captured live.

### Why this matters for the plan

The proxy route is not a lesser sibling of page injection — on Chromium it is
strictly better, for reasons that are about correctness, not taste:

| | page injection (§1.2) | `webAuthenticationProxy` |
|---|---|---|
| Origin | derived from the page or tab; must be inferred | **supplied by the browser**, correct inside cross-origin iframes |
| Reach | a content script in `world: MAIN` on **every page**, racing page scripts for `navigator.credentials` | no page injection at all |
| Robustness | 1Password's hardened accessor already breaks Bitwarden's override when both are installed | one attached provider, arbitrated by the browser |
| Standing | working around the absence of an API | the API Chromium provides |

The specification's own §1.2 evidence supports this: it lists four products that
all monkey-patch `navigator.credentials`, and Bitwarden is migrating **to**
`webAuthenticationProxy` (PR #20849, open, unmerged, flag-off). Nobody has
shipped that migration. We have it running.

**What the proxy route costs, measured, and not fixable by us:**

1. While any provider is attached, Chromium **disables passkey autofill
   (conditional mediation) for the entire profile**. `isConditionalMediationAvailable()`
   returns false and a `mediation: "conditional"` request is rejected before the
   extension ever sees it. This directly contradicts §3.1's conditional-mediation
   requirement: on the proxy route that requirement **cannot be met**, because
   Chromium does not deliver those requests.
2. Only one extension may attach per profile. Black-Bag and any other passkey
   extension are mutually exclusive, and whoever attaches first wins.

**Recommendation.** Keep the proxy as lane A on Chromium — it is built, tested
and honest about the origin. Add page injection as **lane A′ for Firefox**,
which has no equivalent API (confirmed: zero Bugzilla entries for a provider
API; `w3c/webextensions#361` open since 2023 with Safari opposed), and as the
Chromium fallback for anyone who wants conditional mediation more than they want
browser-supplied origins. That inverts the specification's ordering and I would
rather you overruled it deliberately than have me quietly follow it.

---

## 2. What exists and works

Proven by running it, this session unless noted.

| Capability | State | Evidence |
|---|---|---|
| Vault: Argon2id → KEK, XChaCha20-Poly1305, atomic writes, authenticated header, anti-rollback epoch | works | 216 Rust tests |
| Hybrid X25519 + ML-KEM-1024 recovery recipients | works | combiner is structurally NIST SP 800-227 §4.6.2 Eq. 15, which BSI TR-02102-1 (2026-01) names as recommended |
| Locked-memory secrets: `memfd_secret` session key, encrypted-at-rest `Guarded`, locked arena | works | `/proc/self/mem` scan test with a positive control |
| CLI: init/add/list/get/remove/totp/rekey/recovery/agent/doctor/status/gen/migrate/import/export | works | `--help` above |
| Agent over a Unix socket, `SO_PEERCRED`, 0600 in 0700, idle + session ceiling, lock on suspend and screen-lock | works | live |
| Import from Bitwarden, KeePassXC, Firefox, Chrome, any CSV, own JSON; export JSON + KeePassXC CSV | works | GUI import drove 3 records in, verified against the vault |
| TOTP (RFC 6238/4226, in-tree, no dependency) | works | RFC vectors |
| Clipboard: detached helper, `x-kde-passwordManagerHint`, timed clear | works | Omarchy's history records nothing |
| Breach check, HIBP k-anonymity with decoy padding | works | matching happens in the agent |
| Omarchy plugin + standalone Qt deck; management sheet; recovery from the deck | works | live on Hyprland |
| **Passkeys, WebAuthn core** — ES256, COSE, `fmt: "none"`, authenticator data, PRF | works | verified by Python `cbor2` + `cryptography`, sharing no code |
| **Passkeys, lane A (proxy)** — extension, native host, agent verbs, consent | works to the vault | real Brave ceremony minted credentials; see §4 for the one unwitnessed step |
| Consent: frozen ceremony, master passphrase per signature, origin binding, expiry | works | live, and the bypass tests fail without it |

### Security properties I can demonstrate

- A signature requires the **master passphrase, re-entered for that ceremony**,
  checked against the *open vault's own header* — not the file at the path,
  which any same-uid process can swap.
- The **agent builds `clientDataJSON`**, so the origin a human approved and the
  origin the relying party verifies are the same string by construction.
- The relying party must be a registrable-domain suffix of the browser-supplied
  origin, and an allow-listed credential must still belong to that relying party.
- A ceremony belongs to the process that registered it; another process cannot
  collect the answer.
- Passkey key material is refused by `Reveal` at the engine, not merely hidden.

---

## 3. What §3 requires and is missing

Ordered by how much of §3 it leaves unbuilt.

| § | Requirement | State |
|---|---|---|
| 3.1 | Firefox support (extension + native host manifest) | **missing** — no equivalent API exists; needs the injection lane |
| 3.1 | `isUserVerifyingPlatformAuthenticatorAvailable` | partial — answered, but from host reachability, not vault state |
| 3.1 | Conditional mediation | **impossible on the proxy route** (§1 above); needs the injection lane |
| 3.1 | Signal API (`signalUnknownCredential` etc.) | missing |
| 3.1 | Fallback to the browser's own path when the user declines | missing — we return `NotAllowedError` (D1 records the stopgap) |
| 3.1 | `excludeCredentials`, `residentKey`, `userVerification` levels, `AbortSignal` | partial — allowCredentials and UV honoured; the rest not implemented |
| 3.1 | Ed25519 (-8) and RS256 (-257) | missing — ES256 only |
| 3.1 | **BE=1 and BS=1** | **done, D2** — BE=1 always; BS computed from a real backup and read live on every ceremony, so it turns off again when the copy is deleted |
| 3.1 | `credProtect`, `credProps` | `credProps` yes; `credProtect` not persisted |
| 3.2 | Virtual FIDO2 HID device over `/dev/uhid` | **missing entirely** |
| 3.3 | `credentialsd` seam / `PasskeyProvider` trait | missing — no trait boundary yet |
| 3.4 | CXF v1.0 import/export, 1PUX, KDBX | missing |
| 3.4 | Optional TPM sealing, `fprintd` | missing (correctly absent on this hardware, but no runtime detection either) |
| 3.4 | `black-bag backup` | **done** — copies the sealed file (works while locked out), reads it back, records epoch + digest; `--list`/`--verify`; BACKUP section in the deck |
| 3.5 | Per-client approval policy, "deny all agents" switch | **done** — per (client, item, capability), passphrase-proved, lockdown switch; ACCESS section in the deck shows and revokes it |
| 3.5 | Append-only hash-chained audit log | **done** — every decision recorded, read from the file rather than from the agent, `audit --verify` and the deck both check the chain |
| 3.6 | SSH agent | missing |
| 3.6 | `org.freedesktop.secrets` | missing |
| 3.6 | Autotype via `wtype` | missing (clipboard fill works) |
| 4 | `webauthn-rs` relying-party integration test | missing — verification is done by an independent Python implementation instead, which is equivalent evidence but not the specified tool |
| 4 | `docs/COMPAT.md` site matrix | missing |
| 4 | Fresh-box CI, PKGBUILD | missing |
| 4 | `cargo audit`, `cargo deny`, `cargo-fuzz` | missing (clippy is clean and enforced) |

**Crates:** none of §1.6's suggested crates are in use. The WebAuthn core is
hand-written on `p256` + `ciborium`. That was the right call for one algorithm
and it is the wrong call for three — see §5.

---

## 4. The one step I have not witnessed

Through a real Brave ceremony: the extension attaches, Chromium routes the
request, the agent registers it, the deck prompts, the passphrase approves it,
and **the credential is minted and stored**. The full-screen ceremony page then
resolves and closes itself, which it only does when it has an outcome.

I have not seen the *site's* own success line. Three separate MV3 lifetime bugs
were found and fixed getting this far (`sendMessage` spawning a host per message
and breaking peer binding; a service worker torn down mid-ceremony; an exception
escaping the error handler so no outcome was ever recorded). The remaining
uncertainty is browser-side and needs the service-worker console, which I cannot
open in the nested compositor I test in. **In your own Brave it is one click:**
`brave://extensions` → Black-Bag → "service worker".

---

## 5. Decisions I need from you

1. **Lane order.** §1 says injection first. I recommend keeping the working
   proxy as lane A on Chromium and building injection for Firefox and for
   conditional mediation. Confirm or overrule.
2. **BE/BS flags.** §3.1 wants BE=1, BS=1. We set BE=1, BS=0, because BS means
   "this credential is currently backed up" and a local vault with no sync is
   not. Setting BS=1 would tell relying parties something untrue in order to
   look like a synced passkey. I would rather be honest and be told I am wrong
   than quietly assert it.
3. **Adopt `passkey-rs`?** It would bring Ed25519/RS256, `excludeCredentials`,
   PRF and public-suffix handling that we would otherwise write. Against it: our
   core is tested against an independent implementation, and `passkey-rs`'s
   authenticator would need our `CredentialStore` and `UserValidation` anyway.
   My inclination is to adopt it for the *client* rules and keep our
   authenticator. Say if you want it wholesale.
4. **Two unfixed findings** from the adversarial review, neither a signature
   bypass, both real: `refuse` is unauthenticated, so a local process can evict
   the browser's prompt and queue its own in the slot (mitigation: show *which
   process asked* on the consent screen); and a peer trickling bytes can pin the
   single-threaded agent and defeat idle-lock and lock-on-suspend. I propose
   fixing both before any new surface.

---

## 6. Proposed slice order

Revised from §5 of the specification to reflect what already exists.

0. **Fix the two findings above.** Nothing new until the agent cannot be pinned.
1. **Witness lane A end-to-end** in your Brave, with the console open. Record it
   in `docs/COMPAT.md`.
2. **Policy + audit (§3.5).** This machine runs coding agents all day; per-client
   approval and a hash-chained log matter more here than another surface.
3. **Lane B, the virtual HID key (§3.2).** Biggest capability gain: works with no
   extension, in Electron apps, and with `ssh -sk`.
4. **Firefox lane via injection (§3.1),** reusing the agent verbs unchanged.
5. **SSH agent, then Secret Service (§3.6).**
6. **CXF import/export (§3.4).**
7. **Packaging and fresh-box CI (§4).**

Slices 3 through 7 are independent of each other and can be reordered freely.
