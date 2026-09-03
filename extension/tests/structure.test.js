// Invariants about the extension that reading it does not reliably reveal.
//
// Each rule is here because breaking it caused a real failure. A large block of
// sw.js was once pasted twice: the request listeners were registered twice, so
// every login opened TWO full-screen ceremony windows — stacked, identical, and
// therefore invisible in a screenshot — and the stale copy of every function
// silently won, because a duplicate function declaration is not an error in
// JavaScript, it is a redefinition.
//
//   node extension/tests/structure.test.js

const fs = require('fs');
const path = require('path');

const DIR = path.join(__dirname, '..');
const read = f => fs.readFileSync(path.join(DIR, f), 'utf8');

let fails = 0;
const fail = (rule, detail) => {
  console.log(`FAIL  ${rule}\n      ${detail}`);
  fails++;
};
const ok = what => console.log(`ok   ${what}`);

/** Source with comments and string bodies blanked, lengths preserved. */
function stripComments(text) {
  const out = [...text];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === '/' && text[i + 1] === '/') {
      while (i < n && text[i] !== '\n') out[i++] = ' ';
    } else if (c === '/' && text[i + 1] === '*') {
      while (i < n && !(text[i] === '*' && text[i + 1] === '/')) {
        if (text[i] !== '\n') out[i] = ' ';
        i++;
      }
      for (let k = 0; k < 2 && i < n; k++) out[i++] = ' ';
    } else if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      i++;
      while (i < n && text[i] !== quote) {
        if (text[i] === '\\') i++;
        i++;
      }
      i++;
    } else {
      i++;
    }
  }
  return out.join('');
}

const sw = stripComments(read('sw.js'));

// 1. One listener per event.
//
// Chromium calls every registered listener. Two registrations for
// onCreateRequest meant park() ran twice per login, and park() opens a
// full-screen window.
const listeners = [...sw.matchAll(/chrome\.([\w.]+)\.addListener\(/g)].map(m => m[1]);
const seen = new Map();
for (const event of listeners) seen.set(event, (seen.get(event) ?? 0) + 1);
let dupeListener = false;
for (const [event, count] of seen) {
  if (count > 1) {
    fail('one listener per event', `chrome.${event}.addListener is registered ${count} times`);
    dupeListener = true;
  }
}
if (!dupeListener) ok(`each of ${seen.size} events has exactly one listener`);

// 2. One definition per function.
//
// A duplicate `function f()` is not an error: the last one wins, silently, and
// the code a reader is looking at may not be the code that runs.
const declared = [...sw.matchAll(/^(?:async\s+)?function\s+(\w+)\s*\(/gm)].map(m => m[1]);
const counts = new Map();
for (const name of declared) counts.set(name, (counts.get(name) ?? 0) + 1);
let dupeFn = false;
for (const [name, count] of counts) {
  if (count > 1) {
    fail('one definition per function', `${name}() is declared ${count} times in sw.js`);
    dupeFn = true;
  }
}
if (!dupeFn) ok(`each of ${counts.size} top-level functions is declared once`);

// 3. Only the worker may complete a request.
//
// The popup and the ceremony page are surfaces a person looks at. Neither may
// answer a relying party: the decision is taken in Black-Bag itself, on a
// surface no web page and no extension can reach or drive.
for (const file of ['popup.js', 'ceremony.js']) {
  const src = stripComments(read(file));
  for (const forbidden of ['completeCreateRequest', 'completeGetRequest']) {
    if (src.includes(forbidden)) {
      fail('only the worker completes a request', `${file} calls ${forbidden}`);
    }
  }
}
ok('neither the popup nor the ceremony page can complete a request');

// 4. Reading state does not change it.
//
// The popup called `attach()` to find out whether it was attached, so opening
// it took the proxy back from Chromium in the middle of somebody reaching for
// a security key. A status read asks the worker; only the worker attaches.
const popup = stripComments(read('popup.js'));
for (const forbidden of ['webAuthenticationProxy.attach', 'webAuthenticationProxy.detach']) {
  if (popup.includes(forbidden)) {
    fail('reading state does not change it', `popup.js calls ${forbidden} directly`);
  }
}
ok('the popup reads state without taking the proxy');

// 5. The ceremony page has no approve button.
//
// Stated in that file's own header as a promise. A button there would be a
// click, and a click can be synthesised by anything running as the user.
const ceremonyHtml = read('ceremony.html');
if (/<button/i.test(ceremonyHtml)) {
  fail('the ceremony page has no buttons', 'ceremony.html contains a <button>');
} else {
  ok('the ceremony page has no buttons to press');
}

// 6. The manifest asks for no more than it needs.
const manifest = JSON.parse(read('manifest.json'));
// Every one of these is used, and each is here on purpose:
//   webAuthenticationProxy — the whole point
//   nativeMessaging        — talking to the vault
//   storage                — surviving a torn-down service worker
//   alarms                 — the only way to be woken after standing aside;
//                            a setTimeout dies with the worker, and while
//                            detached nothing else arrives to wake it
const allowed = new Set(['webAuthenticationProxy', 'nativeMessaging', 'storage', 'alarms']);
for (const p of manifest.permissions ?? []) {
  if (!allowed.has(p)) {
    fail('no permission beyond what is used', `manifest.json asks for "${p}"`);
  }
}
if ((manifest.host_permissions ?? []).length > 0) {
  fail('no host permissions', 'this extension never touches a page');
}
if ((manifest.content_scripts ?? []).length > 0) {
  fail('no content scripts', 'the proxy route injects nothing into any page');
}
ok('the manifest asks for nothing it does not use');

console.log(fails === 0 ? '\nALL PASS' : `\n${fails} FAILURES`);
process.exit(fails === 0 ? 0 : 1);
