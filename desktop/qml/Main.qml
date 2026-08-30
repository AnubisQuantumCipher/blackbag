import QtQuick
import QtQuick.Controls
import BlackBag

// The window. Everything of substance is in Cockpit; this file decides how big
// it opens, what it is called, and what closing it means.
ApplicationWindow {
  id: window

  // Sized so the deck's three rails are three columns at a comfortable reading
  // width. The minimum is the point below which they stop being columns and
  // start being a queue.
  //
  // Applied once, at startup, and never bound to the settings. A binding here
  // means every later settings change re-asserts a size the operator has since
  // moved on from — including while the window is maximised, where the result
  // is a surface that shrinks away from its own frame.
  width: 1560
  height: 980
  minimumWidth: 1100
  minimumHeight: 720

  visible: true
  color: Color.background

  // The title is the posture, because a taskbar entry that says only
  // "Black-Bag" tells you the one thing you already knew and not the one thing
  // you wanted: whether the vault is currently open.
  title: {
    var state = deck.deckState
    if (state === "UNLOCKED") return "Black-Bag — unlocked"
    if (state === "ROLLBACK") return "Black-Bag — ROLLBACK SUSPECTED"
    if (state === "UNREADABLE") return "Black-Bag — vault unreadable"
    if (state === "NO VAULT") return "Black-Bag — no vault"
    if (deck.stale) return "Black-Bag — status stale"
    return "Black-Bag — sealed"
  }

  function restoreGeometry() {
    var saved = App.settings.window
    if (!saved) return
    var w = Number(saved.width)
    var h = Number(saved.height)
    if (isFinite(w) && w >= window.minimumWidth) window.width = w
    if (isFinite(h) && h >= window.minimumHeight) window.height = h
    if (saved.maximized === true) window.showMaximized()
  }

  Cockpit {
    id: deck
    anchors.fill: parent

    // The deck asks; the window decides. Closing is all a dismissal means
    // here — the vault stays unlocked in the agent, which is the whole reason
    // the agent exists, and locking is a separate deliberate act (Ctrl+L, or
    // the LOCK chip).
    onCloseRequested: window.close()
  }

  Component.onCompleted: {
    restoreGeometry()
    deck.open("{}")
  }

  // A second launch of this program raises this window rather than opening one
  // of its own.
  Connections {
    target: App
    function onRaiseRequested() {
      if (window.visibility === Window.Minimized) window.showNormal()
      window.raise()
      window.requestActivate()
    }
  }

  // Every exit path runs through here, so nothing sensitive outlives the
  // window regardless of how it was closed — the ✕ chip, the window manager's
  // button, Ctrl+Q, or a SIGTERM the event loop gets to see.
  Connections {
    target: Qt.application
    function onAboutToQuit() {
      App.rememberGeometry(window.width, window.height,
                           window.visibility === Window.Maximized)
      deck.close()
    }
  }

  Shortcut {
    sequences: [StandardKey.Quit, "Ctrl+W"]
    context: Qt.ApplicationShortcut
    onActivated: window.close()
  }
}
