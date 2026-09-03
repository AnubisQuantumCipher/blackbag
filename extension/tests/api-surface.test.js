// The API surface this extension depends on, checked against the code and
// against what docs/COMPAT.md says it is.
//
// Chromium's passkey-provider API is not a stable contract. What this cannot
// do is notice a change upstream — nothing running here can. What it CAN do is
// make sure the list in COMPAT.md, which is what a person reads when a browser
// update breaks passkeys, still describes the code. A documentation file that
// has quietly stopped matching is worse than none: it sends the next reader to
// check something that is no longer true.
//
//   node extension/tests/api-surface.test.js

const fs = require('fs');
const path = require('path');

const DIR = path.join(__dirname, '..');
const sw = fs.readFileSync(path.join(DIR, 'sw.js'), 'utf8');
const compat = fs.readFileSync(path.join(DIR, '..', 'docs', 'COMPAT.md'), 'utf8');

let fails = 0;
const fail = (rule, detail) => {
  console.log(`FAIL  ${rule}\n      ${detail}`);
  fails++;
};

// Everything sw.js reaches for on the proxy API, comments and strings removed
// so a mention is not mistaken for a call.
const code = sw
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/^[ \t]*\/\/.*$/gm, '');
const used = new Set(
  [...code.matchAll(/chrome\.webAuthenticationProxy\.(\w+)/g)].map(m => m[1])
);

// What COMPAT.md's table claims, as `member` in the first column.
const documented = new Set(
  [...compat.matchAll(/^\| `(\w+)\(?\)?` \|/gm)].map(m => m[1])
);

for (const member of used) {
  if (!documented.has(member)) {
    fail(
      'every API member used is documented',
      `sw.js calls chrome.webAuthenticationProxy.${member}, and docs/COMPAT.md `
        + `does not list it. Add a row saying what it is for and what to check `
        + `if it moves.`
    );
  }
}
for (const member of documented) {
  if (!used.has(member)) {
    fail(
      'every documented API member is used',
      `docs/COMPAT.md lists ${member}, and sw.js no longer calls it. `
        + `Stale documentation sends the next reader to check the wrong thing.`
    );
  }
}

if (used.size === 0) {
  fail('the extension uses the proxy API', 'sw.js calls nothing on it at all');
}

// The trap this API sets, kept in front of whoever edits attach() next.
if (!/attach\(\)\s*RESOLVES|resolves with an error/i.test(sw)) {
  fail(
    'the attach() trap is written down where it bites',
    'sw.js no longer explains that attach() resolves with an error rather than '
      + 'rejecting. An extension that misses this believes it is attached, never '
      + 'sees a request, and reports nothing wrong.'
  );
}

console.log(
  fails === 0
    ? `ok   ${used.size} API members, code and COMPAT.md agree\n\nALL PASS`
    : `\n${fails} FAILURES`
);
process.exit(fails === 0 ? 0 : 1);
