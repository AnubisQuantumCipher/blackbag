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
// claimed, and it will not approve without the vault passphrase. That
// arrangement is deliberate: an extension is the most exposed component in the
// chain, so it must not be the thing that says yes. If this file were replaced
// by a hostile one, the most it could do is ask for a ceremony — and if it lied
// about the origin, that lie is what the person reads before typing.
//
// One thing a hostile replacement COULD still do: lie about the challenge.
// Chromium does not authenticate requestDetailsJson to anything downstream, so
// freshness rests on this file being honest. Consent does not close that, and
// the docs say so rather than implying otherwise.
//
// THE ONE THING IN HERE THAT IS SECURITY-CRITICAL
//
// The origin. Chromium injects the true caller origin into the request as
// `extensions.remoteDesktopClientOverride.origin`. That is authoritative: it
// comes from the browser, it is correct for cross-origin iframes, and it is
// what must be signed. A tab URL is not a substitute — the request may come
// from an iframe whose origin differs from the top-level page.

const HOST = 'com.khephri.blackbag';

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

// One-shot, for questions with no follow-up. Chromium starts a fresh host
// process for every sendNativeMessage.
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

/**
 * One host process for one ceremony.
 *
 * This is not an optimisation. Black-Bag binds a ceremony to the process that
 * registered it, so that a human who approves a login approves it for the thing
 * that asked, and some other local process cannot poll for the answer and take
 * the signature. `sendNativeMessage` starts a NEW host process per message — so
 * `begin` and `collect` arrived as two different peers, the agent refused to
 * hand the answer to the second one, and every ceremony hung forever after
 * being approved. The symptom was a page that waited and a vault that never
 * gained a credential.
 *
 * A port keeps one process alive across both, and is closed the moment the
 * ceremony ends, so nothing holds a channel to the agent between ceremonies.
 */
function openCeremonyPort() {
  const port = chrome.runtime.connectNative(HOST);
  const waiting = [];
  let closed = null;

  port.onMessage.addListener(msg => {
    const next = waiting.shift();
    if (next) next.resolve(msg);
  });
  port.onDisconnect.addListener(() => {
    closed = new Error(chrome.runtime.lastError?.message ?? 'Black-Bag closed the connection');
    while (waiting.length) waiting.shift().reject(closed);
  });

  return {
    send(message) {
      if (closed) return Promise.reject(closed);
      return new Promise((resolve, reject) => {
        waiting.push({ resolve, reject });
        port.postMessage(message);
      });
    },
    /// Await the next message without sending one — for the heartbeats the
    /// host emits while a human decides.
    next() {
      if (closed) return Promise.reject(closed);
      return new Promise((resolve, reject) => waiting.push({ resolve, reject }));
    },
    close() {
      try { port.disconnect(); } catch { /* already gone */ }
    },
  };
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
  // Standing aside means standing aside. A startup event, an install, or the
  // popup's own status read would otherwise grab the proxy straight back and
  // the security key would never get a look in.
  if (Date.now() < (await standDownRemaining())) return;
  // No `if (attached) return`. Attaching when already attached is harmless and
  // resolves undefined, and the flag is in-memory state about a fact that
  // lives in the browser — see `detach`.
  const error = await chrome.webAuthenticationProxy.attach();
  if (error) {
    // Almost always: another passkey extension got there first.
    attachBlocked = error;
    await setAttached(false);
    return;
  }
  attachBlocked = null;
  await setAttached(true);
}

/**
 * Give the proxy back.
 *
 * DELIBERATELY unguarded. This used to begin `if (!attached) return`, and that
 * turned the security-key choice into a no-op: `attached` is a variable in a
 * Manifest V3 service worker, the worker is torn down and revived freely, and
 * a revived worker starts with `attached === false` while Chromium still has
 * the extension attached — which is exactly why requests kept arriving. So the
 * one moment somebody most needed us out of the way was the moment we did
 * nothing. Measured live: stand aside, ask again immediately, and our own
 * ceremony screen came up.
 *
 * Detaching when not attached resolves with an error string rather than
 * throwing, so calling it unconditionally costs nothing.
 */
async function detach() {
  // The resolved value is not ignored, for the same reason `attach`'s is not:
  // this API reports failure by resolving with a string. Silently dropping it
  // is how "we stood aside" became something we believed and had not done.
  const error = await chrome.webAuthenticationProxy.detach();
  await chrome.storage.session.set({ lastDetach: error ?? 'ok' });
  if (error) {
    console.warn('Black-Bag: detach refused:', error);
    return false;
  }
  await setAttached(false);
  return true;
}

/**
 * Remember attachment where a torn-down worker cannot forget it.
 *
 * Session storage, not local: it is a fact about this browser session, and a
 * stale "attached" carried across a restart would be a lie in the popup.
 */
async function setAttached(on) {
  attached = on;
  await chrome.storage.session.set({ attached: on });
}

/**
 * When the current stand-down ends, as a timestamp; 0 when there is none.
 *
 * Read from session storage rather than from the variable alone: this worker
 * is torn down freely, and a stand-down that evaporated with it would let the
 * next event re-attach in the middle of somebody reaching for their key.
 */
async function standDownRemaining() {
  const stored = (await chrome.storage.session.get('standDownUntil')).standDownUntil ?? 0;
  return Math.max(standDownUntil, stored);
}

/**
 * The kill switch, and the way back.
 *
 * OFF hands the proxy to Chromium's own passkey path and stays off — no timer,
 * because a switch that turned itself back on would not be a switch. ON clears
 * any stand-down as well, since asking for it back is an explicit answer to
 * the question a stand-down was waiting on.
 */
async function setEnabled(on) {
  await chrome.storage.local.set({ enabled: on });
  if (on) {
    standDownUntil = 0;
    await chrome.storage.session.remove('standDownUntil');
    attachBlocked = null;
    await serialize(attach);
  } else {
    await serialize(detach);
  }
}

/** Whether the owner has left this extension switched on. Default: yes. */
async function isEnabled() {
  return (await chrome.storage.local.get('enabled')).enabled !== false;
}

// ── ceremonies ──────────────────────────────────────────────────────────────

/** Ceremonies Chromium has asked for and not yet cancelled. */
const live = new Map(); // requestId -> {nonce, cancelled}

/**
 * Wait for the human.
 *
 * ONE outstanding request, not a poll loop. A poll loop lived here once and it
 * did not survive: an MV3 service worker is torn down when it looks idle, and
 * the loop went with it — measured, the polling stopped four requests in and
 * twenty-five seconds before the person answered, so the page waited forever
 * for a ceremony that had already completed. The waiting now happens in the
 * native host, a process the browser keeps alive for the life of this port, and
 * a single outstanding request is itself what keeps this worker alive.
 */
async function awaitAnswer(port, requestId, nonce) {
  let reply = await port.send({ type: 'collect', nonce });
  // The host sends 'waiting' periodically while the person decides. Those are
  // not the answer; they exist so this worker is not torn down for looking
  // idle. Keep reading until the real one arrives.
  while (reply.type === 'waiting') reply = await port.next();

  const entry = live.get(requestId);
  if (!entry || entry.cancelled) throw new Error('the request was cancelled');
  if (reply.type === 'result') return reply;
  if (reply.type === 'use_security_key') throw new StandDown();
  throw new Error(reply.message ?? 'Black-Bag did not answer');
}

/**
 * The person asked for the browser's own path instead.
 *
 * A class rather than a message, because `answer` has to *act* on it and a
 * security decision taken by comparing prose breaks the first time somebody
 * improves the wording.
 */
class StandDown extends Error {
  constructor() {
    super('Black-Bag stood aside so you can use a security key.');
    this.name = 'StandDown';
  }
}

/**
 * How long to stay out of the way.
 *
 * Long enough to find a key, plug it in, and press it; short enough that
 * forgetting to press it does not leave the profile without a passkey provider
 * for the rest of the session. A minute is the figure the owner set.
 */
const STAND_DOWN_MS = 60_000;
let standDownUntil = 0;

/**
 * Give the proxy back to Chromium for a minute.
 *
 * There is no pass-through: while any extension is attached, nothing in
 * Chromium can reach a hardware key or a phone. Standing down is the only way
 * to let one through, and re-attaching afterwards is what stops this being a
 * one-way switch a person has to undo by hand.
 *
 * The timer is `setTimeout` in a worker that may well be torn down before it
 * fires, so `standDownUntil` is the real record: every path that would attach
 * checks it. The timeout is only the fast path.
 */
async function standDown() {
  standDownUntil = Date.now() + STAND_DOWN_MS;
  await chrome.storage.session.set({ standDownUntil });
  await serialize(detach);
  // An ALARM, not setTimeout.
  //
  // A Manifest V3 service worker is torn down after about thirty seconds of
  // looking idle, and a worker waiting out a minute with nothing to do looks
  // idle from the first second. `setTimeout` went with it — measured: the
  // extension stood aside correctly and then never came back, because nothing
  // was left alive to bring it back. Nor could anything else: while detached,
  // no ceremony arrives to wake the worker, so this is the one path that can
  // end a stand-down. An alarm is the documented way to be woken.
  await chrome.alarms.create(REATTACH_ALARM, { when: Date.now() + STAND_DOWN_MS + 500 });
}

/** The alarm that ends a stand-down. */
const REATTACH_ALARM = 'blackbag-reattach';

/** Re-attach, but only once standing down has actually run its course. */
async function reattachIfDue() {
  if (Date.now() < (await standDownRemaining())) return;
  await chrome.alarms.clear(REATTACH_ALARM);
  standDownUntil = 0;
  await chrome.storage.session.remove('standDownUntil');
  // Do not undo the kill switch on the way back. Cleared first regardless, so
  // a stand-down taken before the switch was thrown does not linger.
  if (!(await isEnabled())) return;
  await attach();
}

// NOTE: this extension does NOT build clientDataJSON, and must not start.
//
// Those are the bytes that get hashed into the signature. Black-Bag builds them
// itself, from the challenge and the origin it showed the human, and returns
// them with the result for us to hand to Chromium verbatim. If this file
// supplied them instead, the origin a person read on the consent screen would
// bear no mechanical relationship to the origin the relying party verifies —
// they would merely be two strings that usually agree — and a compromised
// extension would have a signing oracle with attacker-chosen content in a fixed
// position of the signed message.

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

  const wantPrf = !!details.extensions?.prf;

  const port = openCeremonyPort();
  try {
  const begun = await port.send({
    type: 'begin',
    operation: 'create',
    origin: caller.origin,
    rp_id: rpId,
    rp_name: details.rp?.name ?? null,
    challenge: details.challenge,
    cross_origin: caller.crossOrigin,
    user_handle: hexFromB64url(details.user.id),
    user_name: details.user.name ?? null,
    user_display_name: details.user.displayName ?? null,
    want_prf: wantPrf,
  });
  if (begun.type === 'error') throw new Error(begun.message);

  live.set(requestId, { nonce: begun.nonce, cancelled: false });
  const result = await awaitAnswer(port, requestId, begun.nonce);

  return {
    type: 'public-key',
    id: b64urlFromHex(result.credential_id),
    rawId: b64urlFromHex(result.credential_id),
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: b64urlFromHex(result.client_data_json),
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
  } finally {
    // Nothing holds a channel to the agent between ceremonies.
    port.close();
  }
}

async function onGet(info) {
  const { requestId, requestDetailsJson } = info;
  const details = JSON.parse(requestDetailsJson);
  const caller = callerOrigin(details);
  if (!caller) throw new Error('Chromium did not report a caller origin');

  const rpId = details.rpId;
  if (!rpId) throw new Error('the relying party did not name itself');

  // The PRF salts arrive RAW, exactly as the relying party supplied them.
  // Chromium does not apply SHA-256("WebAuthn PRF" || 0x00 || salt); the agent
  // does, so that an output is the same value a CTAP authenticator would give
  // for the same credential and salt.
  const evalSalts = details.extensions?.prf?.eval;

  const port = openCeremonyPort();
  try {
  const begun = await port.send({
    type: 'begin',
    operation: 'assert',
    origin: caller.origin,
    rp_id: rpId,
    challenge: details.challenge,
    cross_origin: caller.crossOrigin,
    allow_credentials: (details.allowCredentials ?? []).map(c => hexFromB64url(c.id)),
    want_prf: !!evalSalts,
    prf_first_salt: evalSalts?.first ? hexFromB64url(evalSalts.first) : null,
    prf_second_salt: evalSalts?.second ? hexFromB64url(evalSalts.second) : null,
  });
  if (begun.type === 'error') throw new Error(begun.message);

  live.set(requestId, { nonce: begun.nonce, cancelled: false });
  const result = await awaitAnswer(port, requestId, begun.nonce);

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
      clientDataJSON: b64urlFromHex(result.client_data_json),
      authenticatorData: b64urlFromHex(result.authenticator_data),
      signature: b64urlFromHex(result.signature),
      userHandle: result.user_handle ? b64urlFromHex(result.user_handle) : null,
    },
    clientExtensionResults: extensionResults,
  };
  } finally {
    port.close();
  }
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
  let outcome;
  let standingDown = false;
  try {
    const responseJson = JSON.stringify(await work(info));
    await complete({ requestId: info.requestId, responseJson });
    outcome = { ok: true };
  } catch (e) {
    console.warn('Black-Bag:', e);
    // Standing aside is not a failure, and the page is told so — but the SITE
    // still learns only NotAllowedError, because "use a security key instead"
    // is a fact about what is in someone's vault too.
    if (e instanceof StandDown) {
      // NOTE the order: the request is completed below, and only then do we
      // stand aside. Chromium refuses to detach while a proxied request is
      // still outstanding — measured, the detach resolved with an error, was
      // dropped on the floor, and the very next request came straight back to
      // us. Standing aside has to be the last thing that happens.
      standingDown = true;
      outcome = {
        ok: false,
        standDown: true,
        message: 'Black-Bag has stood aside for a minute. Ask the site to try again '
               + 'and Chromium will offer your security key or phone.',
      };
    } else {
      // The page may say more than the site may. A site learns only
      // NotAllowedError, because "you refused", "no such credential" and "the
      // vault is locked" are each a fact about the contents of a vault.
      outcome = { ok: false, message: String(e.message ?? e) };
    }
    try {
      await complete({
        requestId: info.requestId,
        error: { name: 'NotAllowedError', message: 'Black-Bag did not complete this request.' },
      });
    } catch (also) {
      // Completing can itself fail — Chromium refuses a response for a request
      // it has already abandoned. Nested, because an exception thrown from the
      // handler for an exception escapes this function entirely, and then the
      // outcome is never recorded and the page that is waiting for it waits
      // forever. That is not hypothetical: it is what this code did.
      console.warn('Black-Bag: could not report the failure either:', also);
    }
  } finally {
    live.delete(info.requestId);
  }
  // After the request is finished with, never before. See the note above.
  if (standingDown) await standDown();
  return outcome;
}

// ── events ──────────────────────────────────────────────────────────────────
//
// Registered synchronously at load. A listener added inside an async callback
// is not registered when the service worker is revived to deliver an event,
// and the event is lost.

chrome.webAuthenticationProxy.onCreateRequest.addListener(info => park(info, 'create'));
chrome.webAuthenticationProxy.onGetRequest.addListener(info => park(info, 'assert'));

/**
 * Park a request and put a full-screen page in front of the person.
 *
 * The ceremony is NOT run here. A Manifest V3 service worker is torn down when
 * it looks idle, and waiting for a human to decide looks idle — measured, the
 * worker went silent mid-ceremony and the page that asked waited forever for an
 * answer nobody could deliver. So the worker only records the job and opens
 * `ceremony.html`; that page is a live extension context, and it asks the
 * worker to do the work while it is on screen to keep it alive.
 */
async function park(info, operation) {
  try {
    const details = JSON.parse(info.requestDetailsJson);
    const caller = callerOrigin(details);
    if (!caller) throw new Error('Chromium did not report a caller origin');

    await chrome.storage.session.set({
      [String(info.requestId)]: {
        operation,
        origin: caller.origin,
        rpName: (operation === 'create' ? details.rp?.name : null) ?? null,
        requestDetailsJson: info.requestDetailsJson,
      },
    });
    jobs.set(info.requestId, { info, operation });

    await chrome.windows.create({
      url: chrome.runtime.getURL(`ceremony.html?requestId=${info.requestId}`),
      type: 'popup',
      state: 'fullscreen',
    });
  } catch (e) {
    console.warn('Black-Bag:', e);
    await chrome.webAuthenticationProxy[
      operation === 'create' ? 'completeCreateRequest' : 'completeGetRequest'
    ]({
      requestId: info.requestId,
      error: { name: 'NotAllowedError', message: 'Black-Bag did not complete this request.' },
    });
  }
}

/** Requests parked and not yet run. */
const jobs = new Map();

// The ceremony page asks for the work to happen, over a PORT.
//
// A port, specifically, and not `sendMessage`. An open extension page does not
// keep a Manifest V3 service worker alive — an open port does, which is the
// documented keepalive and the only reason this worker survives the seconds or
// minutes a person spends deciding. Measured the other way first: with
// `sendMessage`, the vault minted the credential and the worker was gone before
// it could hand the result back, so the site waited forever.
chrome.runtime.onConnect.addListener(port => {
  if (!port.name.startsWith('ceremony:')) return;
  const requestId = Number(port.name.slice('ceremony:'.length));
  const job = jobs.get(requestId);
  if (!job) {
    port.postMessage({ ok: false, message: 'This request is no longer waiting.' });
    return;
  }
  jobs.delete(requestId);

  const complete =
    job.operation === 'create'
      ? d => chrome.webAuthenticationProxy.completeCreateRequest(d)
      : d => chrome.webAuthenticationProxy.completeGetRequest(d);

  answer(job.info, job.operation === 'create' ? onCreate : onGet, complete)
    .then(async outcome => {
      // Written to storage as well as posted: the port dies with the page, and
      // the page closes itself the moment it has an answer.
      await chrome.storage.session.set({ [`outcome:${requestId}`]: outcome });
      try { port.postMessage(outcome); } catch { /* page already gone */ }
    })
    .finally(() => chrome.storage.session.remove(String(requestId)));
});

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
  jobs.delete(requestId);
  chrome.storage.session.remove(String(requestId));
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

/** Attach on the way in, unless the owner switched it off. */
async function attachIfEnabled() {
  if (await isEnabled()) await attach();
}

// Every revival of this worker, not only startup and install.
//
// `onStartup` and `onInstalled` do not fire when the worker is merely revived
// to deliver an event, so the in-memory flags began every revival wrong. This
// reads back what was true and reconciles: attaching is idempotent, and
// `attach` itself refuses while standing aside.
serialize(async () => {
  attached = (await chrome.storage.session.get('attached')).attached === true;
  await attachIfEnabled();
});

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === REATTACH_ALARM) serialize(reattachIfDue);
});

chrome.runtime.onStartup.addListener(() => serialize(attachIfEnabled));
chrome.runtime.onInstalled.addListener(() => serialize(attachIfEnabled));

// The popup asks what is going on, and can switch the provider off.
//
// Reading is not attaching: the popup used to call `attach()` to find out
// whether it was attached, which meant opening it took the proxy back from
// Chromium mid-stand-down.
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'state') {
    (async () => {
      const until = await standDownRemaining();
      const session = await chrome.storage.session.get(['lastDetach', 'attached']);
      sendResponse({
        enabled: await isEnabled(),
        // What was remembered, not what this worker happens to hold: a revived
        // worker starts with the flag false while Chromium still has us.
        attached: session.attached === true,
        blocked: attachBlocked ?? null,
        standDownSecs: Math.max(0, Math.ceil((until - Date.now()) / 1000)),
        // Empty until a stand-down has been attempted. "ok" means Chromium
        // took the proxy back; anything else is what it said instead.
        lastDetach: session.lastDetach ?? '',
      });
    })();
    return true;
  }
  if (message?.type === 'enable') {
    setEnabled(message.on === true).then(() => sendResponse({ ok: true }));
    return true;
  }
  return false;
});
serialize(attach);

// Exported for the test harness; unused in the browser.
if (typeof module !== 'undefined') {
  module.exports = { b64urlToBytes, bytesToB64url, hexToBytes, bytesToHex, callerOrigin };
}
