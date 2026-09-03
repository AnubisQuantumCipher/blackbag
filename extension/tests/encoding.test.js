// The encoding boundary is where a passkey provider quietly breaks.
//
// WebAuthn's JSON forms use base64url; the agent socket uses hex. Every value
// crossing this extension is re-encoded at least once, and a mistake produces a
// credential id the relying party does not recognise or a signature over bytes
// nobody else can reproduce — failures that look like broken cryptography and
// are not. So the conversions are tested directly.
//
//     node extension/tests/encoding.test.js

const assert = require('node:assert');

// The service worker touches `chrome` at load, so stub the surface it uses.
// A stub browser, built so it does not have to be edited every time the
// extension reaches for one more API.
//
// It was a hand-written literal once, and adding `chrome.alarms` to sw.js
// broke this suite with "Cannot read properties of undefined" — a failure that
// says nothing about the code under test. Anything not named below answers
// with a namespace whose every member is a harmless no-op, so a new API is
// only ever a real failure when the test actually depends on it.
const noop = () => {};

const listener = { addListener: noop, removeListener: noop, hasListener: () => false };
const anyNamespace = () =>
  new Proxy({}, {
    get(_t, name) {
      if (typeof name !== 'string') return undefined;
      if (name.startsWith('on')) return listener;
      return async () => undefined;
    },
  });

const stub = {
  webAuthenticationProxy: {
    attach: async () => undefined,
    detach: async () => undefined,
    onCreateRequest: listener,
    onGetRequest: listener,
    onIsUvpaaRequest: listener,
    onRequestCanceled: listener,
    onRemoteSessionStateChange: listener,
  },
  runtime: {
    onStartup: listener,
    onInstalled: listener,
    onMessage: listener,
    onConnect: listener,
    sendNativeMessage: noop,
    connectNative() {
      return { onMessage: listener, onDisconnect: listener,
               postMessage: noop, disconnect: noop };
    },
    getURL: p => 'chrome-extension://test/' + p,
  },
  storage: {
    session: { set: async () => {}, get: async () => ({}), remove: async () => {} },
    local: { set: async () => {}, get: async () => ({}), remove: async () => {} },
  },
};

globalThis.chrome = new Proxy(stub, {
  get: (target, name) => (name in target ? target[name] : anyNamespace()),
});

const {
  b64urlToBytes,
  bytesToB64url,
  hexToBytes,
  bytesToHex,
  callerOrigin,
} = require('../sw.js');

let failures = 0;
function check(label, fn) {
  try {
    fn();
    console.log('  ok   ' + label);
  } catch (e) {
    failures++;
    console.log('  FAIL ' + label + ': ' + e.message);
  }
}

check('base64url round-trips arbitrary bytes, including every byte value', () => {
  const all = new Uint8Array(256).map((_, i) => i);
  assert.deepStrictEqual(Array.from(b64urlToBytes(bytesToB64url(all))), Array.from(all));
});

check('base64url uses -_ and never +/ or padding', () => {
  // 0xfb 0xff encodes to "+/8" in standard base64; base64url must not.
  const encoded = bytesToB64url(new Uint8Array([0xfb, 0xff, 0xfe]));
  assert.ok(!/[+/=]/.test(encoded), `got ${encoded}`);
});

check('base64url accepts input with or without padding', () => {
  assert.deepStrictEqual(Array.from(b64urlToBytes('YQ')), [0x61]);
  assert.deepStrictEqual(Array.from(b64urlToBytes('YQ==')), [0x61]);
});

check('hex round-trips and is lower-case, two characters per byte', () => {
  const bytes = new Uint8Array([0x00, 0x0f, 0xa0, 0xff]);
  assert.strictEqual(bytesToHex(bytes), '000fa0ff');
  assert.deepStrictEqual(Array.from(hexToBytes('000fa0ff')), Array.from(bytes));
});

check('hex and base64url agree through a full conversion', () => {
  const bytes = new Uint8Array([1, 2, 3, 250, 251, 252, 0, 255]);
  const hex = bytesToHex(bytes);
  const b64 = bytesToB64url(bytes);
  assert.strictEqual(bytesToHex(b64urlToBytes(b64)), hex);
  assert.strictEqual(bytesToB64url(hexToBytes(hex)), b64);
});

// The extension deliberately does NOT build client data any more — the agent
// does, so the origin a human approved and the origin a relying party verifies
// are the same string by construction. Assert the capability is really gone
// rather than leaving a stale test passing.
check('the extension exports no client-data builder', () => {
  const mod = require('../sw.js');
  assert.strictEqual(mod.clientDataJSON, undefined);
});

check('the caller origin comes from the browser override, not from a tab', () => {
  const details = {
    rpId: 'bank.example',
    extensions: {
      remoteDesktopClientOverride: {
        origin: 'https://bank.example',
        sameOriginWithAncestors: true,
      },
    },
  };
  assert.deepStrictEqual(callerOrigin(details), {
    origin: 'https://bank.example',
    crossOrigin: false,
  });
});

check('a cross-origin iframe is reported as cross-origin', () => {
  const details = {
    extensions: {
      remoteDesktopClientOverride: {
        origin: 'https://widget.example',
        sameOriginWithAncestors: false,
      },
    },
  };
  assert.strictEqual(callerOrigin(details).crossOrigin, true);
});

check('a request with no browser-reported origin yields nothing to sign for', () => {
  assert.strictEqual(callerOrigin({ rpId: 'bank.example' }), null);
  assert.strictEqual(callerOrigin({ extensions: {} }), null);
  assert.strictEqual(callerOrigin(undefined), null);
});

console.log();
if (failures) {
  console.log(`FAILED — ${failures} check(s)`);
  process.exit(1);
}
console.log('ALL PASS');
