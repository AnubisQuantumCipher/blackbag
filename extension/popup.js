// Status only. This page deliberately has no approve button: consent happens in
// Black-Bag, on a surface a web page and an extension cannot reach or drive.

const set = (id, text, cls) => {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = 'v ' + cls;
};

chrome.webAuthenticationProxy.attach().then(error => {
  // attach() RESOLVES with an error string rather than rejecting. Calling it
  // when already attached is harmless and returns undefined, so this doubles as
  // a status read.
  if (error) {
    set('attached', 'not this one', 'off');
    document.getElementById('note').innerHTML =
      'Another extension is already the passkey provider for this profile. ' +
      'Only one can be. Disable it to use <b>Black-Bag</b>.';
  } else {
    set('attached', 'Black-Bag', 'on');
  }
});

chrome.runtime.sendNativeMessage('com.khephri.blackbag', { type: 'status' }, reply => {
  if (chrome.runtime.lastError || !reply) {
    set('vault', 'not running', 'off');
    return;
  }
  if (reply.type === 'error') {
    set('vault', 'unreachable', 'off');
    return;
  }
  set('vault', reply.unlocked ? 'unlocked' : 'sealed', reply.unlocked ? 'on' : 'unknown');
});
