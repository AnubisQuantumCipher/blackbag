# Compatibility

What Black-Bag depends on in other people's software, quoted from their source
rather than from their documentation, with the line numbers it was read at. The
point is not that these lines are stable — they are not — but that when one
moves, this file says exactly what to go and re-read.

Every claim below was read out of the source, or run, on the date given.

---

## 1. The Chromium passkey-provider API

**Measured on:** 2026-09-03
**Browser:** Brave `151.1.93.138`, Chromium `151.0.7922.173`, Linux aarch64
**Source read:** `content/browser/webauth/authenticator_common_impl.cc` and
`chrome/browser/extensions/api/web_authentication_proxy/web_authentication_proxy_service.cc`
at the revision matching that Chromium, plus
`chrome/common/extensions/api/_permission_features.json`.

### 1.1 The permission is not gated

```json
"webAuthenticationProxy": {
  "channel": "stable",
  "extension_types": ["extension"],
  "min_manifest_version": 3,
  "platforms": ["linux", "mac", "win"]
}
```

*(`_permission_features.json`, line 1097.)*

No `allowlist`, unlike several of its neighbours in the same file. No
enterprise policy, no Web Store listing, no flag. An unpacked extension
declaring only `webAuthenticationProxy` attaches and receives real requests —
run, not inferred.

### 1.2 The browser supplies the caller origin, and refuses a pre-filled one

This is the single most important line in this file. It is why Black-Bag never
builds `clientDataJSON` from anything a page said.

```cpp
if (proxy) {
  if (options->remote_desktop_client_override ||
      options->remote_client_data_json) {
    // Don't allow proxying of an already proxied request.
    req_state_->request_outcome = MakeCredentialOutcome::kOtherFailure;
    CompleteMakeCredentialRequest(
        blink::mojom::AuthenticatorStatus::NOT_ALLOWED_ERROR);
    return;
  }
  options->remote_desktop_client_override =
      blink::mojom::RemoteDesktopClientOverride::New(
          /*origin=*/req_state_->caller_origin,
          /*same_origin_with_ancestors=*/!is_cross_origin_iframe);
```

*(`authenticator_common_impl.cc`, lines 1283–1295, `create()`. The `get()` path
is the same shape at lines 1947–1961, with `mediation == CONDITIONAL` added to
the refusal.)*

Two things follow, and both are load-bearing:

- **A page cannot forge the origin.** It is written by the browser from
  `caller_origin` immediately before dispatch, and a request that already
  carries one is refused outright rather than passed along.
- **`sameOriginWithAncestors` is authoritative** for whether the ceremony is
  inside a cross-origin iframe. Black-Bag maps it straight to
  `clientDataJSON.crossOrigin` and never infers it.

**What to check if this moves:** that the override is still written by the
browser and still refused when pre-filled. If a future Chromium ever passed a
page-supplied override through, the extension would have to reject any request
carrying one — because at that point the origin on the consent screen would no
longer be a fact about the caller.

### 1.3 Conditional mediation is off while any provider is attached

```cpp
if (options->mediation == Mediation::CONDITIONAL ||
    public_key_options->extensions->remote_desktop_client_override ||
    public_key_options->extensions->remote_client_data_json) {
  // Don't allow proxying of an already proxied or conditional request.
```

*(`authenticator_common_impl.cc`, lines 1948–1951.)*

A `mediation: "conditional"` request is rejected **before the extension sees
it**, and `isConditionalMediationAvailable()` answers false for the whole
profile. This is not something Black-Bag can work around on this route: the
requests are never delivered. It is the reason D1 puts conditional mediation on
the injection lane instead.

### 1.4 One provider per profile, and no pass-through

`ProxyMayAttachToHost` (`web_authentication_proxy_service.cc`, line 40) and
`IsActive` (line 521) mean exactly one extension is the provider at a time, and
while it is, **nothing in Chromium can reach a hardware key or a phone**.

Black-Bag's answer is to stand aside on request: the consent screen has a
*security key* choice (`^K`) that declines the request, detaches the extension
for 60 seconds, and tells the person to ask the site again. See D1 in
[DECISIONS.md](DECISIONS.md). The popup's switch does the same thing without a
timer.

### 1.5 The API surface we call

`extension/sw.js` calls exactly these, and `tests/api-surface.test.js` checks
that this list and the code still agree:

| Member | Used for |
|---|---|
| `attach()` | become the profile's provider; **resolves with an error string** rather than rejecting |
| `detach()` | the kill switch, and standing aside for a security key |
| `onCreateRequest` | a registration ceremony |
| `onGetRequest` | an authentication ceremony |
| `onIsUvpaaRequest` | asked whether a platform authenticator exists |
| `completeIsUvpaaRequest()` | answered true while Black-Bag is reachable |
| `onRequestCanceled` | the page gave up; take the prompt off the screen |
| `onRemoteSessionStateChange` | re-read attachment state |
| `completeCreateRequest()` | hand back a registration, or an error |
| `completeGetRequest()` | hand back an assertion, or an error |

The one that has actually bitten: **`attach()` resolves with an error rather
than rejecting.** An extension that treats the resolved value as success
believes it is attached, never sees a request, and reports nothing wrong.

---

## 2. Firefox

**Measured on:** 2026-09-03. There is no equivalent API, and none is being
built: zero Bugzilla entries for a passkey-provider API, and
`w3c/webextensions#361` has been open since 2023 with Safari opposed.

Firefox is therefore the injection lane, per D1. It is also the only place
conditional mediation can work, because there the content script sees the
request the browser would otherwise handle itself.

---

## 3. What we depend on elsewhere

| Thing | Where | Why it matters if it moves |
|---|---|---|
| `chrome.runtime.connectNative` keeping the worker alive | MV3 | An open port is the documented keepalive. Without it the worker is torn down mid-ceremony and the site waits forever — measured. |
| 4-byte native-endian length prefix, 1 MB cap | native messaging | The host framing. A larger message is dropped silently. |
| `public-suffix` 0.1.3's embedded list | `blackbag-core` | A stale list under-blocks: a newly delegated suffix would be claimable as a relying party until the crate is updated. |
| `/dev/uhid` | lane B (`black-bag key serve`) | Needs a `TAG+="uaccess"` udev rule **and** the `uhid` module loaded — the static node is root-only, so it cannot autoload the driver on a non-root open. Never the `input` group. `key doctor` diagnoses both. |
| `struct uhid_event` layout | lane B | The ABI marshalling uses byte offsets **measured with `offsetof`** on this machine, pinned by a compile-time `const _` block. A layout written from memory put `rd_size` after the descriptor and the kernel answered `EINVAL` with nothing else. If a future kernel changes the struct, that block fails to compile. |
| CTAPHID report descriptor | lane B | The FIDO U2F HID descriptor from the CTAP appendix (usage page `0xF1D0`). A browser matches a security key on exactly this; `udevadm` confirmed the kernel tags the device `ID_FIDO_TOKEN=1`. |

---

## 4. Sites

Left deliberately empty until each row is a ceremony somebody actually
completed, in a named browser, on a named date. A compatibility table filled in
from expectations is worse than no table.
