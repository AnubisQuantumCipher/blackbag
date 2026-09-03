// The full-screen ceremony page.
//
// WHY THIS PAGE EXISTS, AND WHY IT IS NOT A DIALOG
//
// Two reasons, and only one of them is about looks.
//
// 1. It is the thing that stays alive. A Manifest V3 service worker is torn
//    down when Chromium decides it looks idle, and a worker waiting for a human
//    to make up their mind looks extremely idle. Measured: the worker went
//    silent mid-ceremony, the vault produced the signature anyway, and the page
//    that asked waited forever for an answer nobody could deliver. An open
//    extension page is a live extension context; while it is on screen the
//    ceremony cannot be collected by a worker that no longer exists.
//
// 2. Full screen is the honest shape for it. Being asked to sign in somewhere
//    is not a notification. It stops what you were doing, it names the site,
//    and it does not compete for attention with the page that asked.
//
// WHAT IT DOES NOT DO
//
// Approve anything. There is no button here and there never will be. The
// decision is taken in Black-Bag itself, on a surface no web page and no
// extension can reach or drive, and it costs the master passphrase. This page
// holds the connection open and tells you where to look.

const params = new URLSearchParams(location.search);
const requestId = Number(params.get('requestId'));

const el = id => document.getElementById(id);

/**
 * Render an origin so a lookalike is visible.
 *
 * The registrable domain — approximated as the last two labels — is bright and
 * everything else is dimmed, so `https://bank.example.evil.test` reads as
 * **evil.test**. Black-Bag's own screen does the same thing; this one agrees
 * with it so the two never disagree about what a person is looking at.
 *
 * Built with DOM nodes, never innerHTML: an origin arrives from a web page.
 */
function renderOrigin(node, origin) {
  node.textContent = '';
  const scheme = origin.indexOf('://');
  if (scheme < 0) {
    node.append(Object.assign(document.createElement('span'), {
      className: 'core', textContent: origin,
    }));
    return;
  }
  const head = origin.slice(0, scheme + 3);
  const rest = origin.slice(scheme + 3);
  const cut = rest.indexOf('/') < 0 ? rest.length : rest.indexOf('/');
  const hostPort = rest.slice(0, cut);
  const tail = rest.slice(cut);

  let host = hostPort, port = '';
  const colon = hostPort.lastIndexOf(':');
  if (colon > 0 && !hostPort.slice(0, colon).endsWith(']')) {
    host = hostPort.slice(0, colon);
    port = hostPort.slice(colon);
  }
  const labels = host.split('.');
  const core = labels.length > 2 ? labels.slice(-2).join('.') : host;
  const lead = labels.length > 2 ? labels.slice(0, -2).join('.') + '.' : '';

  const span = (text, cls) => {
    if (!text) return;
    const s = document.createElement('span');
    s.className = cls;
    s.textContent = text;
    node.append(s);
  };
  span(head, 'dim');
  span(lead, 'dim');
  span(core, 'core');
  span(port, 'dim');
  span(tail, 'dim');
}

let settled = false;

/** Show the outcome once, from whichever path reports it first. */
function finish(outcome) {
  if (settled) return;
  settled = true;
  chrome.storage.session.remove(`outcome:${requestId}`);
  if (outcome?.ok) setState('Approved. Returning you to the site.', 'done');
  else setState(outcome?.message ?? 'Black-Bag did not complete this request.', 'err');
  setTimeout(() => window.close(), 1400);
}

function setState(text, cls) {
  el('state').textContent = text;
  el('state').className = cls ?? '';
  if (cls) el('pulse').style.animation = 'none';
}

// The worker parked everything about this ceremony here before opening us.
chrome.storage.session.get(String(requestId)).then(async stored => {
  const job = stored[String(requestId)];
  if (!job) {
    setState('This request is no longer waiting.', 'err');
    return;
  }

  el('kind').textContent =
    job.operation === 'create' ? 'CREATE A PASSKEY' : 'SIGN IN';
  renderOrigin(el('origin'), job.origin);
  el('detail').textContent = job.rpName ? job.rpName : '';

  // Ask the worker to run the ceremony now that a live context exists, then
  // watch session storage for the outcome. The worker owns the browser-facing
  // call — completeCreateRequest must be paired with the event it answers —
  // and it can only survive long enough to make it because this page is open.
  //
  // Not just the reply: a `sendMessage` reply travels down a channel that dies
  // if the worker is torn down, and the worker is waiting on a human. The
  // outcome is written to storage precisely so it survives that, and this page
  // — which is what keeps the worker alive in the first place — reads it there.
  // A PORT, not a message. An open port is what keeps the service worker
  // alive while a person decides; an open page alone does not. With
  // `sendMessage` the vault minted the credential and the worker was gone
  // before it could hand back the result, so the site waited forever.
  const port = chrome.runtime.connect({ name: `ceremony:${requestId}` });
  port.onMessage.addListener(outcome => finish(outcome));

  const key = `outcome:${requestId}`;
  const started = Date.now();
  while (!settled && Date.now() - started < 130_000) {
    const got = (await chrome.storage.session.get(key))[key];
    if (got) { finish(got); return; }
    await new Promise(r => setTimeout(r, 300));
  }
  if (!settled) {
    setState('Black-Bag was not answered in time.', 'err');
    setTimeout(() => window.close(), 1800);
  }
});
