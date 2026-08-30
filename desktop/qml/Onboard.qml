// BLACK-BAG — first run.
//
// Creating a vault is the one thing the deck used to hand back to a terminal,
// which made the terminal a required part of a graphical password manager. It
// is not. This sheet owns the whole of first run: set a master passphrase,
// mint the offline recovery key, and land in the deck.
//
// Three things it inherits from the rest of the deck, and one it adds:
//
//   1. The passphrase reaches the engine on STDIN and never as an argument.
//      /proc/<pid>/cmdline is world-readable. `black-bag init` reads it twice
//      from stdin and `recovery add` reads it once; that is the entire
//      channel.
//   2. Nothing is stored here. The passphrase lives in this component for as
//      long as the two steps take and is wiped by clear() on every exit path,
//      including a failure.
//   3. No invented strength score. The engine rates what its own generator
//      produced and explicitly refuses to rate a typed one — "generated values
//      only, never a typed one" is its wording, and this sheet repeats its
//      verdict rather than making up a meter of its own.
//
//   4. A generated passphrase is shown in PLAIN TEXT, on purpose. This is the
//      one moment where the secret has to leave the machine and land on paper,
//      and a creation screen that masks the thing you are supposed to write
//      down is a creation screen that guarantees you lose the vault.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import BlackBag
import "Model.js" as Model

Item {
  id: onboard
  anchors.fill: parent
  visible: open_

  property bool open_: false
  property int motionMs: 160

  // Handed down by the deck so both sheets are the same size as the
  // surface behind them.
  property real uiScale: 1.0
  readonly property QtObject metric: DeckMetrics { uiScale: onboard.uiScale }

  // Resolved by the host and handed down, because how you ask for $HOME is the
  // one thing that differs between the shell plugin and the application. This
  // file stays host-neutral so it is the same file in both.
  property string homeDir: ""

  // The vault now exists and the passphrase is known-good, because init
  // accepted it. The deck unlocks with it rather than asking a second time.
  signal created(string passphrase)
  signal dismissed()

  // passphrase → recovery → done
  property string step: "passphrase"

  property string pass: ""
  property string confirmPass: ""
  property bool showPass: false

  // A generated candidate, held in the clear so it can be read off the screen
  // and written down. Cleared with everything else.
  property string generated: ""
  property string generatedNote: ""

  property string errorText: ""
  property bool busy: false

  property string recoveryPath: ""
  property string recoveryWritten: ""

  readonly property int minLength: 12
  readonly property bool matches:
    onboard.pass.length > 0 && onboard.pass === onboard.confirmPass
  readonly property bool longEnough: onboard.pass.length >= onboard.minLength
  readonly property bool canCreate:
    onboard.longEnough && onboard.matches && !onboard.busy

  function begin() {
    onboard.step = "passphrase"
    onboard.pass = ""
    onboard.confirmPass = ""
    onboard.generated = ""
    onboard.generatedNote = ""
    onboard.errorText = ""
    onboard.recoveryWritten = ""
    onboard.showPass = false
    onboard.busy = false
    onboard.recoveryPath = (onboard.homeDir.length > 0 ? onboard.homeDir : "~")
                           + "/black-bag-recovery.key"
    onboard.open_ = true
    Qt.callLater(function () { passInput.forceActiveFocus() })
  }

  // Everything sensitive this component can be holding, dropped at once. Called
  // on every exit path — success, failure, and abandonment alike.
  function clear() {
    onboard.pass = ""
    onboard.confirmPass = ""
    onboard.generated = ""
    onboard.generatedNote = ""
    passInput.text = ""
    confirmInput.text = ""
  }

  function abandon() {
    var hadVault = onboard.step !== "passphrase"
    onboard.clear()
    onboard.open_ = false
    // Abandoning the recovery step still leaves a usable vault behind, so the
    // deck is told it was created; abandoning the first step leaves nothing.
    if (hadVault) onboard.created("")
    else onboard.dismissed()
  }

  // A vault appeared that this sheet did not create — another process, or a
  // status that was merely stale when the sheet opened. Step one is now an
  // offer to create something that already exists, so it withdraws rather than
  // inviting a `init` that would fail. Later steps are left alone: they belong
  // to a vault this sheet has already made.
  function standDown() {
    if (onboard.step !== "passphrase") return
    onboard.clear()
    onboard.open_ = false
  }

  function generate() {
    if (onboard.busy) return
    onboard.errorText = ""
    genProcess.running = true
  }

  function applyGenerated() {
    if (onboard.generated.length === 0) return
    onboard.pass = onboard.generated
    onboard.confirmPass = onboard.generated
    passInput.text = onboard.generated
    confirmInput.text = onboard.generated
    onboard.showPass = true
  }

  function createVault() {
    if (!onboard.canCreate) return
    onboard.errorText = ""
    onboard.busy = true
    initProcess.running = true
  }

  function createRecovery() {
    if (onboard.busy) return
    if (onboard.recoveryPath.trim().length === 0) {
      onboard.errorText = "give the recovery key somewhere to go"
      return
    }
    onboard.errorText = ""
    onboard.busy = true
    recoveryProcess.command = ["black-bag", "recovery", "add", "offsite",
                               "--out", onboard.recoveryPath.trim()]
    recoveryProcess.running = true
  }

  function finish() {
    var p = onboard.pass
    onboard.clear()
    onboard.open_ = false
    onboard.created(p)
  }

  // ── processes ───────────────────────────────────────────────────────────────

  Process {
    id: genProcess
    command: ["black-bag", "gen", "passphrase"]
    running: false
    // The generator puts the value on stdout and its entropy verdict on
    // stderr, so that `black-bag gen passphrase | ...` pipes the passphrase
    // and nothing else. Both are read; neither is treated as the other.
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      var out = String(this.stdout && this.stdout.text ? this.stdout.text : "").trim()
      var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
      if (code !== 0 || out.length === 0) {
        onboard.errorText = err.length > 0 ? err : "could not generate a passphrase"
        return
      }
      onboard.generated = out
      // Carried verbatim: it is the engine's claim about its own output, not
      // this sheet's, and rewording it would be inventing a rating.
      onboard.generatedNote = err
      onboard.applyGenerated()
    }
  }

  Process {
    id: initProcess
    command: ["black-bag", "init"]
    running: false
    stdinEnabled: true
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onStarted: {
      // init asks twice and compares them itself, so both lines go across and
      // the pipe closes immediately behind them.
      write(onboard.pass + "\n" + onboard.pass + "\n")
      stdinEnabled = false
    }
    onExited: function (code) {
      onboard.busy = false
      if (code === 0) {
        onboard.step = "recovery"
        onboard.errorText = ""
        Qt.callLater(function () { recoveryInput.forceActiveFocus() })
      } else {
        var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
        onboard.errorText = err.length > 0 ? err : "could not create the vault"
      }
    }
  }

  Process {
    id: recoveryProcess
    running: false
    stdinEnabled: true
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onStarted: {
      write(onboard.pass + "\n")
      stdinEnabled = false
    }
    onExited: function (code) {
      onboard.busy = false
      if (code === 0) {
        onboard.recoveryWritten = onboard.recoveryPath.trim()
        onboard.step = "done"
        onboard.errorText = ""
      } else {
        var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
        onboard.errorText = err.length > 0 ? err : "could not write the recovery key"
      }
    }
  }

  // ── keys ────────────────────────────────────────────────────────────────────
  //
  // Shortcuts rather than a Keys handler, for the reason the sealed screen
  // learned the hard way: a Keys handler only fires while the item declaring it
  // holds focus, and this sheet focuses a text field the moment it opens. A
  // window-scoped Shortcut works wherever the caret is.

  Shortcut {
    sequences: ["Esc"]
    enabled: onboard.open_ && !onboard.busy
    context: Qt.WindowShortcut
    onActivated: onboard.abandon()
  }

  // The last step has no field to press Enter in, so Enter needs a home of its
  // own there. On the earlier steps the fields' own onAccepted already handles
  // it, and this stays out of their way.
  Shortcut {
    sequences: ["Return", "Enter"]
    enabled: onboard.open_ && onboard.step === "done"
    context: Qt.WindowShortcut
    onActivated: onboard.finish()
  }

  // Ctrl+Enter commits from anywhere, which matters most right after the
  // generator has filled both fields and the caret is wherever it happened to
  // be. Ctrl+G generates, the same chord the record editor uses for the same
  // job, so the gesture is worth learning once.
  Shortcut {
    sequences: ["Ctrl+Return", "Ctrl+Enter"]
    enabled: onboard.open_ && !onboard.busy
    context: Qt.WindowShortcut
    onActivated: {
      if (onboard.step === "passphrase") onboard.createVault()
      else if (onboard.step === "recovery") onboard.createRecovery()
      else onboard.finish()
    }
  }

  Shortcut {
    sequences: ["Ctrl+G"]
    enabled: onboard.open_ && !onboard.busy && onboard.step === "passphrase"
    context: Qt.WindowShortcut
    onActivated: onboard.generate()
  }

  // ── surface ─────────────────────────────────────────────────────────────────

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

    // ── wordmark ────────────────────────────────────────────────────────────
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
      text: onboard.step === "done" ? "your vault is ready"
          : (onboard.step === "recovery" ? "step 2 of 2  ·  the way back in"
                                         : "step 1 of 2  ·  no vault here yet")
      color: Util.alpha(Color.foreground, 0.4)
      font.family: metric.font.family
      font.pixelSize: metric.font.caption
      font.letterSpacing: metric.spaceReal(0.8)
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
    }

    // ── step 1: the master passphrase ───────────────────────────────────────
    ColumnLayout {
      Layout.fillWidth: true
      spacing: metric.space(10)
      visible: onboard.step === "passphrase"

      Text {
        Layout.fillWidth: true
        text: "This passphrase is the only thing between this file and whoever "
            + "has it. It is not stored anywhere and it cannot be reset — if it "
            + "is lost, the recovery key on the next screen is the only way "
            + "back."
        color: Util.alpha(Color.foreground, 0.55)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      InputField {
        id: passInput
        font.pixelSize: onboard.metric.font.body
        topPadding: onboard.metric.spacing.inputPaddingY
        bottomPadding: onboard.metric.spacing.inputPaddingY
        leftPadding: onboard.metric.spacing.controlPaddingX
        rightPadding: onboard.metric.spacing.controlPaddingX
        Layout.fillWidth: true
        enabled: !onboard.busy
        password: !onboard.showPass
        placeholderText: "master passphrase"
        onTextChanged: onboard.pass = text
        onAccepted: confirmInput.forceActiveFocus()
      }

      InputField {
        id: confirmInput
        font.pixelSize: onboard.metric.font.body
        topPadding: onboard.metric.spacing.inputPaddingY
        bottomPadding: onboard.metric.spacing.inputPaddingY
        leftPadding: onboard.metric.spacing.controlPaddingX
        rightPadding: onboard.metric.spacing.controlPaddingX
        Layout.fillWidth: true
        enabled: !onboard.busy
        password: !onboard.showPass
        placeholderText: "again, to be sure"
        onTextChanged: onboard.confirmPass = text
        onAccepted: onboard.createVault()
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: metric.space(12)

        LinkText {
          text: onboard.showPass ? "hide" : "show what I typed"
          onActivated: onboard.showPass = !onboard.showPass
        }
        LinkText {
          text: "generate a strong one  (^G)"
          onActivated: onboard.generate()
        }
        Item { Layout.fillWidth: true }
        Text {
          text: {
            if (onboard.pass.length === 0) return ""
            if (!onboard.longEnough)
              return onboard.minLength - onboard.pass.length + " more characters"
            if (onboard.confirmPass.length === 0) return "now confirm it"
            if (!onboard.matches) return "the two do not match"
            return "ready"
          }
          color: (onboard.pass.length > 0 && onboard.confirmPass.length > 0
                  && !onboard.matches)
            ? Color.urgent
            : (onboard.canCreate ? Color.accent : Util.alpha(Color.foreground, 0.4))
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
      }

      // The generated candidate, in the clear. See the note at the top of this
      // file: this is the moment the secret is supposed to leave the machine.
      Rectangle {
        Layout.fillWidth: true
        Layout.topMargin: metric.space(4)
        visible: onboard.generated.length > 0
        implicitHeight: genCol.implicitHeight + metric.space(20)
        radius: metric.cornerRadius
        color: Util.alpha(Color.accent, 0.07)
        border.color: Util.alpha(Color.accent, 0.35)
        border.width: Math.max(1, metric.spacing.hairline)

        ColumnLayout {
          id: genCol
          anchors.left: parent.left
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          anchors.margins: metric.space(12)
          spacing: metric.space(6)

          Text {
            Layout.fillWidth: true
            text: "WRITE THIS DOWN NOW"
            color: Color.accent
            font.family: metric.font.family
            font.pixelSize: metric.font.caption
            font.bold: true
            font.letterSpacing: metric.spaceReal(0.8)
            textFormat: Text.PlainText
            renderType: Text.NativeRendering
          }
          TextEdit {
            Layout.fillWidth: true
            text: onboard.generated
            readOnly: true
            selectByMouse: true
            wrapMode: TextEdit.WrapAnywhere
            color: Color.foreground
            font.family: metric.font.family
            font.pixelSize: metric.font.subtitle
            textFormat: TextEdit.PlainText
            renderType: Text.NativeRendering
          }
          Text {
            Layout.fillWidth: true
            visible: onboard.generatedNote.length > 0
            text: onboard.generatedNote
            color: Util.alpha(Color.foreground, 0.45)
            font.family: metric.font.family
            font.pixelSize: metric.font.caption
            wrapMode: Text.WrapAtWordBoundaryOrAnywhere
            textFormat: Text.PlainText
            renderType: Text.NativeRendering
          }
        }
      }

      Text {
        Layout.fillWidth: true
        visible: onboard.generated.length === 0 && onboard.pass.length > 0
        text: "No strength score is shown for a passphrase you typed: the "
            + "engine rates only what its own generator produced, and a "
            + "character-class guess at a phrase a person invented reliably "
            + "overstates it."
        color: Util.alpha(Color.foreground, 0.3)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
    }

    // ── step 2: the recovery key ────────────────────────────────────────────
    ColumnLayout {
      Layout.fillWidth: true
      spacing: metric.space(10)
      visible: onboard.step === "recovery"

      Text {
        Layout.fillWidth: true
        text: "A recovery key is a file that opens this vault WITHOUT the "
            + "passphrase — a hybrid X25519 + ML-KEM-1024 recipient whose "
            + "private half lives in the file and not in the vault. It is the "
            + "only way back from a forgotten passphrase, and it cannot be "
            + "added later to a vault you can no longer open. Make it now, "
            + "then move it to offline media."
        color: Util.alpha(Color.foreground, 0.55)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      Text {
        text: "write it to"
        color: Util.alpha(Color.foreground, 0.45)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      InputField {
        id: recoveryInput
        font.pixelSize: onboard.metric.font.body
        topPadding: onboard.metric.spacing.inputPaddingY
        bottomPadding: onboard.metric.spacing.inputPaddingY
        leftPadding: onboard.metric.spacing.controlPaddingX
        rightPadding: onboard.metric.spacing.controlPaddingX
        Layout.fillWidth: true
        enabled: !onboard.busy
        text: onboard.recoveryPath
        onTextChanged: onboard.recoveryPath = text
        onAccepted: onboard.createRecovery()
      }
    }

    // ── done ────────────────────────────────────────────────────────────────
    ColumnLayout {
      Layout.fillWidth: true
      spacing: metric.space(10)
      visible: onboard.step === "done"

      Text {
        Layout.fillWidth: true
        text: onboard.recoveryWritten.length > 0
          ? "Recovery key written to " + onboard.recoveryWritten + " (mode 0600). "
            + "It is not backed up anywhere else. Move it to offline media now, "
            + "and treat it exactly as you would the passphrase — anyone "
            + "holding that file can open this vault."
          : "Your vault is ready."
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
      visible: onboard.errorText.length > 0
      text: onboard.errorText
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
        text: onboard.busy
          ? (onboard.step === "passphrase" ? "deriving the key — this is meant to be slow"
                                           : "writing the recovery key")
          : ""
        color: Util.alpha(Color.accent, 0.7)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      Item { Layout.fillWidth: true }

      SheetButton {
        label: onboard.step === "recovery" ? "SKIP" : "CANCEL"
        visible: onboard.step !== "done"
        enabledAction: !onboard.busy
        tone: Util.alpha(Color.foreground, 0.6)
        onActivated: onboard.abandon()
      }

      SheetButton {
        label: {
          if (onboard.step === "passphrase") return "CREATE VAULT"
          if (onboard.step === "recovery") return "CREATE KEY"
          return "OPEN THE DECK"
        }
        enabledAction: onboard.step === "passphrase"
          ? onboard.canCreate : !onboard.busy
        tone: Color.accent
        onActivated: {
          if (onboard.step === "passphrase") onboard.createVault()
          else if (onboard.step === "recovery") onboard.createRecovery()
          else onboard.finish()
        }
      }
    }
  }

  // ── small parts ─────────────────────────────────────────────────────────────

  component LinkText: Text {
    id: link
    signal activated()
    color: Util.alpha(Color.accent, linkHover.hovered ? 1.0 : 0.6)
    font.family: metric.font.family
    font.pixelSize: metric.font.caption
    font.underline: linkHover.hovered
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    HoverHandler { id: linkHover; cursorShape: Qt.PointingHandCursor }
    TapHandler { onTapped: link.activated() }
  }

  component SheetButton: Rectangle {
    id: btn
    property string label: ""
    property bool enabledAction: true
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
      enabled: btn.enabledAction
      cursorShape: Qt.PointingHandCursor
    }
    TapHandler {
      enabled: btn.enabledAction
      onTapped: btn.activated()
    }
  }
}
