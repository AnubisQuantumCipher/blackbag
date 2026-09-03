// Status, and one switch.
//
// This page deliberately has no approve button, and never will: consent happens
// in Black-Bag, on a surface a web page and an extension cannot reach or drive.
// The switch here is the opposite of consent — it takes capability away.
//
// Reading state does NOT attach. An earlier version called `attach()` to find
// out whether it was attached, which meant opening the popup took the proxy
// back from Chromium in the middle of somebody reaching for a security key.

const set = (id, text, cls) => {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = 'v ' + cls;
};

const note = text => {
  document.getElementById('note').textContent = text;
};

function render(state) {
  const button = document.getElementById('toggle');

  if (!state.enabled) {
    set('provider', 'switched off', 'off');
    note(
      'Chromium is handling passkeys itself. Your vault is untouched — nothing '
      + 'was deleted, and turning this back on restores it.'
    );
  } else if (state.lastDetach && state.lastDetach !== 'ok' && state.standDownSecs > 0) {
    // Being unable to stand aside is worth saying out loud: the person is
    // holding a security key that cannot be reached, and silence would leave
    // them pressing it at a browser that is not listening.
    set('provider', 'could not stand aside', 'off');
    note(`Chromium refused to hand the proxy back: ${state.lastDetach}`);
  } else if (state.standDownSecs > 0) {
    set('provider', `standing aside · ${state.standDownSecs}s`, 'unknown');
    note(
      'You asked for a security key. Black-Bag is out of the way so Chromium '
      + 'can reach it. Ask the site to try again.'
    );
  } else if (state.attached) {
    set('provider', 'Black-Bag', 'on');
    note('Every signature is approved by you in Black-Bag, not here. This page cannot approve anything.');
  } else if (state.blocked) {
    set('provider', 'not this one', 'off');
    note(
      'Another extension is already the passkey provider for this profile. '
      + 'Only one can be. Disable it to use Black-Bag.'
    );
  } else {
    set('provider', 'not attached', 'unknown');
    note('Black-Bag is switched on but has not taken the proxy yet.');
  }

  button.textContent = state.enabled ? 'SWITCH OFF' : 'SWITCH ON';
  button.className = state.enabled ? 'danger' : 'go';
  const hadFocus = button.disabled && button.dataset.refocus === 'yes';
  button.disabled = false;
  // Disabling a focused element hands focus to the document, so without this
  // the switch works exactly once from the keyboard and then goes dead —
  // which on a control whose whole job is to be reachable in a hurry is the
  // wrong failure.
  if (hadFocus) {
    button.dataset.refocus = 'no';
    button.focus();
  }
}

function refresh() {
  chrome.runtime.sendMessage({ type: 'state' }, state => {
    if (chrome.runtime.lastError || !state) {
      set('provider', 'unknown', 'unknown');
      note('The extension’s background worker did not answer.');
      return;
    }
    render(state);
  });
}

document.getElementById('toggle').addEventListener('click', () => {
  const button = document.getElementById('toggle');
  button.dataset.refocus = document.activeElement === button ? 'yes' : 'no';
  button.disabled = true;
  chrome.runtime.sendMessage({ type: 'state' }, state => {
    chrome.runtime.sendMessage({ type: 'enable', on: !state?.enabled }, () => refresh());
  });
});

// A separate message per host invocation is fine here: this is a status read,
// not a ceremony, so nothing is bound to the process it spawns.
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

refresh();
// While standing aside, the countdown is the interesting part.
setInterval(refresh, 1000);
