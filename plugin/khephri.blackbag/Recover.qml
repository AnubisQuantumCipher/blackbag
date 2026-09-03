// BLACK-BAG — the way back in.
//
// The deck could mint a recovery key in first run and then could not use one.
// A person who only ever opens the app, and who forgets the passphrase, was
// locked out of their own vault by the surface that had talked them into
// making the key — the key sitting on their desk, which opens it. That is the
// worst failure this program can have, and it existed until this file did.
//
// What happens here is `black-bag recovery use --key <file>`: the hybrid
// X25519 + ML-KEM-1024 recipient's private half opens the vault without the
// passphrase, and a new passphrase is set immediately, because a vault opened
// by a key nobody had to remember must not stay open on those terms.
//
// The rules it inherits from the rest of the deck:
//
//   1. The new passphrase reaches the engine on STDIN and never as an
//      argument. /proc/<pid>/cmdline is world-readable.
//   2. Nothing is stored here. clear() wipes on every exit path, failure
//      included, and the deck's clearSecrets() calls it.
//   3. The sheet says what it is about to do before it does it. Re-keying is
//      not reversible and the old passphrase stops working.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

Item {
  id: recover
  anchors.fill: parent
  visible: open_

  property bool open_: false
  property int motionMs: 160

  property real uiScale: 1.0
  readonly property QtObject metric: DeckMetrics { uiScale: recover.uiScale }

  // Handed down, because how a surface asks for $HOME is the one thing that
  // differs between the shell plugin and the application.
  property string homeDir: ""

  // The labels of the recipients whose private key is held outside the vault,
  // straight from status.json. A vault with none of these cannot be recovered
  // and this sheet is never offered for it.
  property var recoverableLabels: []

  // The vault is open again and re-keyed. The passphrase comes back because
  // `recovery use` has just proved it opens the file; asking for it a second
  // time one second later would be ceremony, not security.
  signal recovered(string passphrase)
  signal dismissed()

  // key → passphrase → done
  property string step: "key"

  property string keyPath: ""
  property string pass: ""
  property string confirmPass: ""
  property bool showPass: false

  property string errorText: ""
  property bool busy: false

  readonly property int minLength: 12
  readonly property bool matches:
    recover.pass.length > 0 && recover.pass === recover.confirmPass
  readonly property bool longEnough: recover.pass.length >= recover.minLength
  readonly property bool canRecover:
    recover.keyPath.trim().length > 0 && recover.longEnough
    && recover.matches && !recover.busy

  function begin() {
    recover.step = "key"
    recover.pass = ""
    recover.confirmPass = ""
    recover.errorText = ""
    recover.showPass = false
    recover.busy = false
    // The place `recovery add` writes by default, which is where a key most
    // often still is. It is also the place the manual says it should not
    // stay, and the note below says so.
    recover.keyPath = (recover.homeDir.length > 0 ? recover.homeDir : "~")
                    + "/black-bag-recovery.key"
    keyInput.text = recover.keyPath
    passInput.text = ""
    confirmInput.text = ""
    recover.open_ = true
    Qt.callLater(function () { keyInput.forceActiveFocus() })
  }

  // Everything sensitive this component can hold, dropped at once. Called on
  // every exit path — success, failure and abandonment alike — and by the
  // deck's own clearSecrets().
  function clear() {
    recover.pass = ""
    recover.confirmPass = ""
    passInput.text = ""
    confirmInput.text = ""
  }

  function abandon() {
    // Leaving while the engine is working kills the work rather than trapping
    // the person behind a modal that may never answer.
    if (recoverProcess.running) recoverProcess.running = false
    recover.busy = false
    busyWatchdog.stop()
    recover.clear()
    recover.open_ = false
    recover.dismissed()
  }

  function advance() {
    if (recover.busy) return
    if (recover.step === "key") {
      if (recover.keyPath.trim().length === 0) {
        recover.errorText = "give the path of your recovery key file"
        return
      }
      recover.errorText = ""
      recover.step = "passphrase"
      Qt.callLater(function () { passInput.forceActiveFocus() })
      return
    }
    recover.run()
  }

  function run() {
    if (recover.busy) return
    if (!recover.longEnough) {
      recover.errorText = "the new passphrase needs at least "
                        + recover.minLength + " characters — "
                        + Math.max(0, recover.minLength - recover.pass.length)
                        + " more to go"
      return
    }
    if (!recover.matches) {
      recover.errorText = recover.confirmPass.length === 0
        ? "type it again in the second box, to be sure"
        : "the two passphrases do not match"
      return
    }
    recover.errorText = ""
    recover.busy = true
    busyWatchdog.restart()
    recoverProcess.command = ["black-bag", "recovery", "use",
                              "--key", recover.keyPath.trim()]
    recoverProcess.running = true
  }

  function finish() {
    var p = recover.pass
    recover.clear()
    recover.open_ = false
    recover.recovered(p)
  }

  // ── the engine ─────────────────────────────────────────────────────────────

  Process {
    id: recoverProcess
    running: false
    stdinEnabled: true
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onStarted: {
      // `recovery use` reads the new passphrase once when stdin is not a
      // terminal — it does not ask twice, because a piped second line would
      // be the next command. This sheet did the confirming.
      write(recover.pass + "\n")
      stdinEnabled = false
    }
    onExited: function (code) {
      recover.busy = false
      busyWatchdog.stop()
      if (code === 0) {
        recover.step = "done"
        recover.errorText = ""
        return
      }
      var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
      // The engine's own words. Its failures here are specific and useful —
      // a key for another vault, an unreadable file, a malformed key — and
      // rewording them would only blur what went wrong.
      recover.errorText = err.length > 0 ? err : "the recovery key did not open this vault"
    }
  }

  // If the engine never answers — missing binary, a hung process — `busy`
  // would otherwise stay true forever and with it every exit disabled.
  Timer {
    id: busyWatchdog
    interval: 120000
    repeat: false
    onTriggered: {
      if (!recover.busy) return
      if (recoverProcess.running) recoverProcess.running = false
      recover.busy = false
      recover.errorText = "the engine did not answer in two minutes — check `black-bag doctor`"
    }
  }

  // ── keys ───────────────────────────────────────────────────────────────────
  //
  // Shortcuts rather than a Keys handler, for the reason the sealed screen
  // learned the hard way: a Keys handler fires only while the item declaring
  // it holds focus, and this sheet focuses a text field the moment it opens.

  Shortcut {
    sequences: ["Esc"]
    enabled: recover.open_
    context: Qt.WindowShortcut
    onActivated: recover.step === "done" ? recover.finish() : recover.abandon()
  }

  Shortcut {
    sequences: ["Ctrl+Return", "Ctrl+Enter"]
    enabled: recover.open_ && !recover.busy
    context: Qt.WindowShortcut
    onActivated: recover.step === "done" ? recover.finish() : recover.advance()
  }

  Shortcut {
    sequences: ["Return", "Enter"]
    enabled: recover.open_ && recover.step === "done"
    context: Qt.WindowShortcut
    onActivated: recover.finish()
  }

  // ── surface ────────────────────────────────────────────────────────────────

  MouseArea {
    anchors.fill: parent
    hoverEnabled: true
    acceptedButtons: Qt.AllButtons
    onClicked: {}      // swallow: nothing behind this sheet is reachable
  }

  Rectangle {
    anchors.fill: parent
    color: Color.background
  }

  ColumnLayout {
    width: Math.min(parent.width * 0.5, metric.space(560))
    anchors.horizontalCenter: parent.horizontalCenter
    anchors.verticalCenter: parent.verticalCenter
    spacing: metric.space(18)

    Text {
      Layout.alignment: Qt.AlignHCenter
      text: "B L A C K - B A G"
      color: Util.alpha(Color.foreground, 0.85)
      font.family: metric.font.family
      font.pixelSize: metric.font.display
      font.bold: true
      font.letterSpacing: metric.spaceReal(1)
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
    }

    Text {
      Layout.alignment: Qt.AlignHCenter
      Layout.bottomMargin: metric.space(6)
      text: recover.step === "done" ? "you are back in"
          : (recover.step === "passphrase" ? "step 2 of 2  ·  a new master passphrase"
                                           : "step 1 of 2  ·  the way back in")
      color: Util.alpha(Color.foreground, 0.4)
      font.family: metric.font.family
      font.pixelSize: metric.font.caption
      font.letterSpacing: metric.spaceReal(0.8)
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
    }

    // ── step 1: the key file ────────────────────────────────────────────────
    ColumnLayout {
      Layout.fillWidth: true
      spacing: metric.space(10)
      visible: recover.step === "key"

      Text {
        Layout.fillWidth: true
        text: "A recovery key opens this vault WITHOUT the passphrase. Point at the "
            + "file you were given when the vault was made, and a new master "
            + "passphrase will be set straight afterwards — a vault opened by a key "
            + "nobody had to remember must not stay open on those terms."
        color: Util.alpha(Color.foreground, 0.55)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      Text {
        text: "recovery key file"
        color: Util.alpha(Color.foreground, 0.45)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      TextField {
        id: keyInput
        TapHandler {
          acceptedButtons: Qt.RightButton
          onTapped: {
            keyInput.forceActiveFocus()
            fieldMenu.target = keyInput
            fieldMenu.popup()
          }
        }
        font.pixelSize: recover.metric.font.body
        topPadding: recover.metric.spacing.inputPaddingY
        bottomPadding: recover.metric.spacing.inputPaddingY
        leftPadding: recover.metric.spacing.controlPaddingX
        rightPadding: recover.metric.spacing.controlPaddingX
        Layout.fillWidth: true
        enabled: !recover.busy
        onTextChanged: recover.keyPath = text
        onAccepted: recover.advance()
      }

      Text {
        Layout.fillWidth: true
        text: "If it is on a USB stick, the path usually starts /run/media/ or /media/. "
            + "The default shown is where the deck writes it during first run, which is "
            + "also the one place it should not have stayed."
        color: Util.alpha(Color.foreground, 0.55)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      Text {
        Layout.fillWidth: true
        visible: recover.recoverableLabels.length > 0
        text: "this vault accepts: " + Model.asList(recover.recoverableLabels).join(", ")
        color: Util.alpha(Color.accent, 0.7)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
    }

    // ── step 2: the new passphrase ──────────────────────────────────────────
    ColumnLayout {
      Layout.fillWidth: true
      spacing: metric.space(10)
      visible: recover.step === "passphrase"

      Text {
        Layout.fillWidth: true
        text: "This replaces the passphrase you cannot use. Everything in the vault is "
            + "re-encrypted under a fresh data key, both recipients are re-wrapped, and "
            + "your recovery key keeps working. The old passphrase stops working, which "
            + "cannot be undone."
        color: Util.alpha(Color.foreground, 0.55)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      TextField {
        id: passInput
        TapHandler {
          acceptedButtons: Qt.RightButton
          onTapped: {
            passInput.forceActiveFocus()
            fieldMenu.target = passInput
            fieldMenu.popup()
          }
        }
        font.pixelSize: recover.metric.font.body
        topPadding: recover.metric.spacing.inputPaddingY
        bottomPadding: recover.metric.spacing.inputPaddingY
        leftPadding: recover.metric.spacing.controlPaddingX
        rightPadding: recover.metric.spacing.controlPaddingX
        Layout.fillWidth: true
        enabled: !recover.busy
        password: !recover.showPass
        placeholderText: "new master passphrase"
        onTextChanged: recover.pass = text
        onAccepted: confirmInput.forceActiveFocus()
      }

      TextField {
        id: confirmInput
        TapHandler {
          acceptedButtons: Qt.RightButton
          onTapped: {
            confirmInput.forceActiveFocus()
            fieldMenu.target = confirmInput
            fieldMenu.popup()
          }
        }
        font.pixelSize: recover.metric.font.body
        topPadding: recover.metric.spacing.inputPaddingY
        bottomPadding: recover.metric.spacing.inputPaddingY
        leftPadding: recover.metric.spacing.controlPaddingX
        rightPadding: recover.metric.spacing.controlPaddingX
        Layout.fillWidth: true
        enabled: !recover.busy
        password: !recover.showPass
        placeholderText: "again, to be sure"
        onTextChanged: recover.confirmPass = text
        onAccepted: recover.run()
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: metric.space(10)
        Text {
          text: recover.showPass ? "hide" : "show"
          color: Util.alpha(Color.accent, showHover.hovered ? 1.0 : 0.6)
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          HoverHandler { id: showHover; cursorShape: Qt.PointingHandCursor }
          TapHandler { onTapped: recover.showPass = !recover.showPass }
        }
        Item { Layout.fillWidth: true }
        Text {
          text: recover.pass.length === 0 ? ""
              : (recover.longEnough
                 ? (recover.matches ? "ready" : "the two do not match yet")
                 : recover.pass.length + " of " + recover.minLength + " characters")
          color: recover.longEnough && recover.matches
            ? Color.accent : Util.alpha(Color.foreground, 0.5)
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
      }
    }

    // ── done ────────────────────────────────────────────────────────────────
    ColumnLayout {
      Layout.fillWidth: true
      spacing: metric.space(10)
      visible: recover.step === "done"

      Text {
        Layout.fillWidth: true
        text: "The vault is open and re-keyed under your new passphrase. Your recovery "
            + "key still works — it was re-wrapped under the new data key — so keep it. "
            + "Move it to offline media if it is still sitting in your home directory."
        color: Util.alpha(Color.foreground, 0.6)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
    }

    // ── error ───────────────────────────────────────────────────────────────
    Text {
      Layout.fillWidth: true
      visible: recover.errorText.length > 0
      text: recover.errorText
      color: Color.urgent
      font.family: metric.font.family
      font.pixelSize: metric.font.caption
      wrapMode: Text.WrapAtWordBoundaryOrAnywhere
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
    }

    // ── actions ─────────────────────────────────────────────────────────────
    RowLayout {
      Layout.fillWidth: true
      Layout.topMargin: metric.space(6)
      spacing: metric.space(10)

      Text {
        text: recover.busy ? "opening the vault and re-keying — this is meant to be slow" : ""
        color: Util.alpha(Color.accent, 0.7)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      Item { Layout.fillWidth: true }

      SheetButton {
        label: recover.busy ? "ABANDON" : "CANCEL"
        visible: recover.step !== "done"
        tone: Util.alpha(Color.foreground, 0.6)
        onActivated: recover.abandon()
      }

      SheetButton {
        label: {
          if (recover.step === "key") return "NEXT"
          if (recover.step === "passphrase") return "RECOVER"
          return "OPEN THE DECK"
        }
        enabledAction: recover.step === "key"
          ? recover.keyPath.trim().length > 0
          : (recover.step === "passphrase" ? recover.canRecover : true)
        // Clickable even while dim: the handler says what is missing, where a
        // disabled button would say nothing at all.
        tappable: !recover.busy
        tone: Color.accent
        onActivated: recover.step === "done" ? recover.finish() : recover.advance()
      }
    }
  }

  // ── small parts ────────────────────────────────────────────────────────────

  FieldMenu { id: fieldMenu }

  component FieldMenuItem: MenuItem {
    id: fmi
    implicitHeight: recover.metric.spacing.controlHeight
    implicitWidth: recover.metric.space(170)
    contentItem: Text {
      text: fmi.text
      color: fmi.enabled ? Color.foreground : Util.alpha(Color.foreground, 0.3)
      font.family: recover.metric.font.family
      font.pixelSize: recover.metric.font.caption
      verticalAlignment: Text.AlignVCenter
      leftPadding: recover.metric.space(10)
      renderType: Text.NativeRendering
    }
    background: Rectangle {
      color: fmi.highlighted ? Util.alpha(Color.accent, 0.15) : "transparent"
    }
  }

  component FieldMenu: Menu {
    id: fmenu
    property Item target: null
    // Masked unless the target is showing its contents. Cut and Copy stay
    // disabled while it is masked, so the menu is not the quiet way around
    // a field the surface is deliberately hiding.
    readonly property bool masked:
      !(fmenu.target && fmenu.target.echoMode === TextInput.Normal)
    background: Rectangle {
      implicitWidth: recover.metric.space(170)
      color: Color.background
      border.color: Util.alpha(Color.accent, 0.4)
      border.width: Math.max(1, recover.metric.spacing.hairline)
      radius: recover.metric.cornerRadius
    }
    FieldMenuItem {
      text: "Cut"
      enabled: fmenu.target && !fmenu.masked && fmenu.target.selectedText.length > 0
      onTriggered: fmenu.target.cut()
    }
    FieldMenuItem {
      text: "Copy"
      enabled: fmenu.target && !fmenu.masked && fmenu.target.selectedText.length > 0
      onTriggered: fmenu.target.copy()
    }
    FieldMenuItem {
      text: "Paste"
      enabled: fmenu.target && fmenu.target.canPaste
      onTriggered: fmenu.target.paste()
    }
    FieldMenuItem {
      text: "Select all"
      enabled: fmenu.target && fmenu.target.length > 0
      onTriggered: fmenu.target.selectAll()
    }
  }

  component SheetButton: Rectangle {
    id: btn
    property string label: ""
    property bool enabledAction: true
    property bool tappable: enabledAction
    property color tone: Color.foreground
    signal activated()

    implicitWidth: btnText.implicitWidth + metric.space(22)
    implicitHeight: metric.spacing.controlHeight
    radius: metric.cornerRadius
    color: btn.enabledAction && btnHover.hovered
      ? Util.alpha(btn.tone, 0.2) : Util.alpha(btn.tone, 0.09)
    border.color: Util.alpha(btn.tone, btn.enabledAction ? 0.5 : 0.15)
    border.width: Math.max(1, metric.spacing.hairline)

    Text {
      id: btnText
      anchors.centerIn: parent
      text: btn.label
      color: Util.alpha(btn.tone, btn.enabledAction ? 1.0 : 0.35)
      font.family: metric.font.family
      font.pixelSize: metric.font.caption
      font.bold: true
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
    }

    HoverHandler {
      id: btnHover
      enabled: btn.tappable
      cursorShape: Qt.PointingHandCursor
    }
    TapHandler {
      enabled: btn.tappable
      onTapped: btn.activated()
    }
  }
}
