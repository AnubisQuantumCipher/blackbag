// Black-Bag's passkey provider for Chromium.
//
// WHAT THIS FILE IS ALLOWED TO DO
//
// Marshal JSON. That is all. It holds no key material, performs no
// cryptography, and decides nothing about whether a signature may happen. It
// takes what Chromium hands it, passes it to the native host, and hands back
// what the agent returns.
//
// The consent prompt is NOT here. It is in Black-Bag itself, on a layer-shell
// surface that genuinely takes the keyboard, showing the origin this file
// claimed. That arrangement is deliberate: an extension is the most exposed
// component in the chain, so it must not be the thing that says yes. If this
// file were replaced by a hostile one, the most it could do is ask for a
// ceremony and be refused by the person looking at the screen — and if it lied
// about the origin, that is the lie the person would see.
//
// THE ONE THING IN HERE THAT IS SECURITY-CRITICAL
//
// The origin. Chromium injects the true caller origin into the request as
// `extensions.remoteDesktopClientOverride.origin`. That is authoritative: it
// comes from the browser, it is correct for cross-origin iframes, and it is
// what must be signed. A tab URL is not a substitute — the request may come
// from an iframe whose origin differs from the top-level page.

const HOST = 'com.khephri.blackbag';

// Chromium abandons a request at 180s. Poll a little faster than the agent's
// own 120s ceremony expiry so a lapsed ceremony is reported rather than
// silently pending.
const POLL_MS = 700;
const POLL_CEILING_MS = 115_000;

// ── base64url, the encoding WebAuthn's JSON forms use ───────────────────────
// Not plain base64: `+` and `/` would be re-encoded by the relying party's own
// parser into something that no longer matches what was signed.

function b64urlToBytes(s) {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function bytesToB64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

const hexFromB64url = s => bytesToHex(b64urlToBytes(s));
const b64urlFromHex = h => bytesToB64url(hexToBytes(h));

// ── the native host ─────────────────────────────────────────────────────────

function callHost(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(HOST, message, reply => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!reply) {
        reject(new Error('Black-Bag sent no reply'));
        return;
      }
      resolve(reply);
    });
  });
}

// ── attachment ──────────────────────────────────────────────────────────────
//
// Only one extension may be the passkey provider for a profile. attach()
// RESOLVES with an error string rather than rejecting, which is easy to miss
// and produces an extension that believes it is attached and never sees a
// request. Attach/detach are serialized through one promise chain so two
// events cannot interleave them, and a refusal latches so we do not spin.

let chain = Promise.resolve();
let attached = false;
let attachBlocked = null;

function serialize(work) {
  chain = chain.then(work).catch(e => {
    console.warn('Black-Bag:', e);
  });
  return chain;
}

async function attach() {
  if (attached || attachBlocked) return;
  const error = await chrome.webAuthenticationProxy.attach();
  if (error) {
    // Almost always: another passkey extension got there first.
    attachBlocked = error;
    attached = false;
    return;
  }
  attached = true;
}

async function detach() {
  if (!attached) return;
  await chrome.webAuthenticationProxy.detach();
  attached = false;
}

// ── ceremonies ──────────────────────────────────────────────────────────────

/** Ceremonies Chromium has asked for and not yet cancelled. */
const live = new Map(); // requestId -> {nonce, cancelled}

const sleep = ms => new Promise(r => setTimeout(r, ms));

/**
 * Wait for the human, in Black-Bag.
 *
 * Polling rather than a push: the native host is a short-lived process spawned
 * per message, and a long-lived port that sat open for the life of the browser
 * would be a standing invitation to the agent socket for as long as the browser
 * ran.
 */
async function awaitAnswer(requestId, nonce) {
  const started = Date.now();
  while (Date.now() - started < POLL_CEILING_MS) {
    const entry = live.get(requestId);
    if (!entry || entry.cancelled) throw new Error('the request was cancelled');
    const reply = await callHost({ type: 'collect', nonce });
    if (reply.type === 'result') return reply;
    if (reply.type === 'error') throw new Error(reply.message);
    await sleep(POLL_MS);
  }
  throw new Error('Black-Bag was not answered in time');
}

/**
 * The client data the relying party will verify.
 *
 * Built here and returned verbatim alongside the signature, so the bytes the
 * agent hashed are exactly the bytes the relying party hashes. Anything that
 * regenerated this string on the way back — different key order, different
 * escaping — would produce a signature that does not verify, and the failure
 * would look like a broken key rather than a broken encoder.
 */
function clientDataJSON(type, challengeB64url, origin, crossOrigin) {
  return new TextEncoder().encode(
    JSON.stringify({ type, challenge: challengeB64url, origin, crossOrigin: !!crossOrigin }),
  );
}

/** The true caller origin, from the browser rather than from us. */
function callerOrigin(details) {
  const override = details?.extensions?.remoteDesktopClientOverride;
  if (!override?.origin) return null;
  return { origin: override.origin, crossOrigin: override.sameOriginWithAncestors === false };
}

async function onCreate(info) {
  const { requestId, requestDetailsJson } = info;
  const details = JSON.parse(requestDetailsJson);
  const caller = callerOrigin(details);
  if (!caller) throw new Error('Chromium did not report a caller origin');

  const rpId = details.rp?.id;
  if (!rpId) throw new Error('the relying party did not name itself');

  const cdj = clientDataJSON('webauthn.create', details.challenge, caller.origin, caller.crossOrigin);
  const wantPrf = !!details.extensions?.prf;

  const begun = await callHost({
    type: 'begin',
    operation: 'create',
    origin: caller.origin,
    rp_id: rpId,
    rp_name: details.rp?.name ?? null,
    client_data_json: bytesToHex(cdj),
    user_handle: hexFromB64url(details.user.id),
    user_name: details.user.name ?? null,
    user_display_name: details.user.displayName ?? null,
    want_prf: wantPrf,
  });
  if (begun.type === 'error') throw new Error(begun.message);

  live.set(requestId, { nonce: begun.nonce, cancelled: false });
  const result = await awaitAnswer(requestId, begun.nonce);

  return {
    type: 'public-key',
    id: b64urlFromHex(result.credential_id),
    rawId: b64urlFromHex(result.credential_id),
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: bytesToB64url(cdj),
      attestationObject: b64urlFromHex(result.attestation_object),
      authenticatorData: b64urlFromHex(result.authenticator_data),
      // Chromium REQUIRES this for ES256 and rejects the response without it.
      publicKey: b64urlFromHex(result.public_key_der),
      publicKeyAlgorithm: -7,
      // Not a roaming key and not on a wire: the credential lives in a file on
      // this machine, which is what "internal" means here.
      transports: ['internal'],
    },
    clientExtensionResults: {
      credProps: { rk: true },
      ...(wantPrf ? { prf: { enabled: true } } : {}),
    },
  };
}

async function onGet(info) {
  const { requestId, requestDetailsJson } = info;
  const details = JSON.parse(requestDetailsJson);
  const caller = callerOrigin(details);
  if (!caller) throw new Error('Chromium did not report a caller origin');

  const rpId = details.rpId;
  if (!rpId) throw new Error('the relying party did not name itself');

  const cdj = clientDataJSON('webauthn.get', details.challenge, caller.origin, caller.crossOrigin);

  // The PRF salts arrive RAW, exactly as the relying party supplied them.
  // Chromium does not apply SHA-256("WebAuthn PRF" || 0x00 || salt); the agent
  // does, so that an output is the same value a CTAP authenticator would give
  // for the same credential and salt.
  const evalSalts = details.extensions?.prf?.eval;

  const begun = await callHost({
    type: 'begin',
    operation: 'assert',
    origin: caller.origin,
    rp_id: rpId,
    client_data_json: bytesToHex(cdj),
    allow_credentials: (details.allowCredentials ?? []).map(c => hexFromB64url(c.id)),
    want_prf: !!evalSalts,
    prf_first_salt: evalSalts?.first ? hexFromB64url(evalSalts.first) : null,
    prf_second_salt: evalSalts?.second ? hexFromB64url(evalSalts.second) : null,
  });
  if (begun.type === 'error') throw new Error(begun.message);

  live.set(requestId, { nonce: begun.nonce, cancelled: false });
  const result = await awaitAnswer(requestId, begun.nonce);

  const extensionResults = {};
  if (result.prf_first) {
    extensionResults.prf = {
      results: {
        first: b64urlFromHex(result.prf_first),
        ...(result.prf_second ? { second: b64urlFromHex(result.prf_second) } : {}),
      },
    };
  }

  return {
    type: 'public-key',
    id: b64urlFromHex(result.credential_id),
    rawId: b64urlFromHex(result.credential_id),
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: bytesToB64url(cdj),
      authenticatorData: b64urlFromHex(result.authenticator_data),
      signature: b64urlFromHex(result.signature),
      userHandle: result.user_handle ? b64urlFromHex(result.user_handle) : null,
    },
    clientExtensionResults: extensionResults,
  };
}

/**
 * Answer a request, turning any failure into a DOMException.
 *
 * NotAllowedError for everything, deliberately. A page must not be able to
 * tell "you refused" from "there is no such credential" from "the vault is
 * locked" — each of those is a fact about the contents of someone's vault, and
 * a site that could distinguish them could enumerate it.
 */
async function answer(info, work, complete) {
  try {
    const responseJson = JSON.stringify(await work(info));
    await complete({ requestId: info.requestId, responseJson });
  } catch (e) {
    console.warn('Black-Bag:', e);
    await complete({
      requestId: info.requestId,
      error: { name: 'NotAllowedError', message: 'Black-Bag did not complete this request.' },
    });
  } finally {
    live.delete(info.requestId);
  }
}

// ── events ──────────────────────────────────────────────────────────────────
//
// Registered synchronously at load. A listener added inside an async callback
// is not registered when the service worker is revived to deliver an event,
// and the event is lost.

chrome.webAuthenticationProxy.onCreateRequest.addListener(info =>
  answer(info, onCreate, d => chrome.webAuthenticationProxy.completeCreateRequest(d)),
);

chrome.webAuthenticationProxy.onGetRequest.addListener(info =>
  answer(info, onGet, d => chrome.webAuthenticationProxy.completeGetRequest(d)),
);

chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener(async info => {
  // Truthfully: a platform authenticator is available exactly when Black-Bag
  // is running, whether or not the vault happens to be open this second.
  let available = false;
  try {
    const status = await callHost({ type: 'status' });
    available = status.type === 'status';
  } catch {
    available = false;
  }
  await chrome.webAuthenticationProxy.completeIsUvpaaRequest({
    requestId: info.requestId,
    isUvpaa: available,
  });
});

chrome.webAuthenticationProxy.onRequestCanceled.addListener(requestId => {
  const entry = live.get(requestId);
  if (!entry) return;
  entry.cancelled = true;
  // Take the prompt off the user's screen: they should not be asked to approve
  // something the browser has already given up waiting for.
  callHost({ type: 'cancel', nonce: entry.nonce }).catch(() => {});
  live.delete(requestId);
});

// Black-Bag touches a file named after this extension when it locks or unlocks,
// which is how a suspended service worker gets woken.
chrome.webAuthenticationProxy.onRemoteSessionStateChange.addListener(() => {
  serialize(attach);
});

chrome.runtime.onStartup.addListener(() => serialize(attach));
chrome.runtime.onInstalled.addListener(() => serialize(attach));
serialize(attach);

// Exported for the test harness; unused in the browser.
if (typeof module !== 'undefined') {
  module.exports = { b64urlToBytes, bytesToB64url, hexToBytes, bytesToHex, clientDataJSON, callerOrigin };
}
