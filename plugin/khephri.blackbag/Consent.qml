// BLACK-BAG — the one screen that decides whether you get signed in.
//
// A browser has asked Black-Bag to prove you are you, to a website. Every other
// sheet in this deck hands you a copy of something you already have. This one
// performs an act: approve it and a signature goes out that logs someone in.
//
// So it is built around a single question the person can actually answer:
// **is this the site you think you are on?** Everything else on screen is
// subordinate to the origin, because the origin is the only field an attacker
// must lie about and the only one a human can check.
//
// Three rules this sheet exists to enforce:
//
//   1. Approving costs the master passphrase, every time. Not because the
//      vault is locked — it is open, or this prompt would not be here — but
//      because the agent socket only establishes that the caller runs as you,
//      and everything in your session does. Without a proof, any process could
//      register a ceremony, approve its own ceremony and be signed into your
//      bank in silence. It is typed here, it crosses on stdin, and three wrong
//      answers refuse the request outright.
//
//      This is a bar, not a boundary: a keylogger running as you defeats it,
//      as it defeats every other use of that passphrase. What it removes is
//      the silent case.
//
//   1b. Nothing is approved by pressing Return alone. Approval is Ctrl+Y, it
//      is stated on screen, and there is a button for the mouse — a person
//      clearing a stack of dialogs must not sign a login by reflex.
//   2. The origin is rendered so a lookalike is visible: the registrable
//      domain is bright and the rest is dimmed, so `bank.example.evil.test`
//      reads as `evil.test` at a glance.
//   3. It expires on screen. A prompt that has quietly lapsed must not look
//      like one that still works, so the countdown is shown and the sheet
//      closes itself.
//
// The prompt is delivered through `status.json`, which the deck already
// watches, so it appears the moment the browser asks — see `consent.rs` for
// why the agent, and not the extension, is the thing that shows it.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

Item {
  id: consent
  anchors.fill: parent
  visible: open_

  property bool open_: false
  property int motionMs: 160
  property real uiScale: 1.0
  readonly property QtObject metric: DeckMetrics { uiScale: consent.uiScale }

  /// The ceremony being asked about: one entry of `session.pending_passkeys`.
  property var ceremony: null
  /// Which credential the person has selected, when there is more than one.
  property string chosenCredential: ""
  /// The proof. Never stored, never logged, wiped on every exit path.
  property string passphrase: ""

  property string errorText: ""
  property bool busy: false

  /// The vault changed: a create writes a new record.
  signal changed()
  signal dismissed()

  readonly property bool isCreate: consent.ceremony
    && String(consent.ceremony.operation) === "create"

  readonly property var choices: consent.ceremony && consent.ceremony.choices
    ? consent.ceremony.choices : []

  // ── the countdown ──────────────────────────────────────────────────────────
  //
  // Driven by a clock rather than a fixed duration so a suspended session comes
  // back with the truth rather than resuming a stale animation.
  property int secondsLeft: 0
  Timer {
    running: consent.open_
    interval: 250
    repeat: true
    triggeredOnStart: true
    onTriggered: {
      if (!consent.ceremony || !consent.ceremony.expires_at) { consent.secondsLeft = 0; return }
      var end = Date.parse(consent.ceremony.expires_at)
      consent.secondsLeft = Math.max(0, Math.round((end - Date.now()) / 1000))
      if (consent.secondsLeft <= 0 && consent.open_) consent.lapse()
    }
  }

  function begin(entry) {
    consent.ceremony = entry
    consent.errorText = ""
    consent.busy = false
    // Read the choices off `entry` rather than off `consent.choices`: that is
    // a binding on `ceremony`, and it has not re-evaluated yet inside the same
    // call that assigned it — which left a single-choice prompt with nothing
    // selected and an APPROVE that refused itself.
    var offered = (entry && entry.choices) ? entry.choices : []
    consent.chosenCredential = offered.length === 1
      ? String(offered[0].credential_id) : ""
    consent.open_ = true
    Qt.callLater(function () { passField.forceActiveFocus() })
  }

  /// Host-initiated close: the ceremony went away underneath us, because it was
  /// answered elsewhere, expired, or the vault locked.
  function standDown() {
    consent.open_ = false
    consent.ceremony = null
    consent.chosenCredential = ""
    consent.errorText = ""
    consent.passphrase = ""
    passField.text = ""
  }

  function lapse() {
    consent.standDown()
    consent.dismissed()
  }

  function approve() {
    if (consent.busy || !consent.ceremony) return
    if (!consent.isCreate && consent.chosenCredential.length === 0) {
      consent.errorText = "choose which passkey to use"
      return
    }
    if (consent.passphrase.length === 0) {
      consent.errorText = "type your master passphrase to approve"
      passField.forceActiveFocus()
      return
    }
    consent.errorText = ""
    consent.busy = true
    answerProcess.approving = true
    answerProcess.command = consent.chosenCredential.length > 0
      ? ["black-bag", "agent", "passkey-answer", String(consent.ceremony.nonce),
         "--credential", consent.chosenCredential]
      : ["black-bag", "agent", "passkey-answer", String(consent.ceremony.nonce)]
    answerProcess.running = true
  }

  function refuse() {
    if (consent.busy || !consent.ceremony) { consent.lapse(); return }
    consent.errorText = ""
    consent.busy = true
    answerProcess.approving = false
    answerProcess.command = ["black-bag", "agent", "passkey-answer",
                             String(consent.ceremony.nonce), "--refuse"]
    answerProcess.running = true
  }

  Process {
    id: answerProcess
    property bool approving: true
    running: false
    stdinEnabled: true
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onStarted: {
      // The passphrase crosses on stdin and the pipe closes immediately. There
      // is no --passphrase flag anywhere in this project: /proc/<pid>/cmdline
      // is world-readable, so an argv secret is a published secret.
      if (answerProcess.approving) write(consent.passphrase + "\n")
      stdinEnabled = false
    }
    onExited: function (code) {
      consent.busy = false
      // Wiped whether it worked or not, so a wrong answer does not leave the
      // master passphrase sitting in a property until the next prompt.
      consent.passphrase = ""
      passField.text = ""
      if (code !== 0) {
        var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
        consent.errorText = err.length > 0 ? err : "the answer did not reach the vault"
        return
      }
      // A create writes a record; tell the deck to re-read.
      if (answerProcess.approving && consent.isCreate) consent.changed()
      consent.standDown()
      consent.dismissed()
    }
  }

  // ── keys ───────────────────────────────────────────────────────────────────
  //
  // Deliberately NOT Return. See the note at the top of this file.

  Shortcut {
    sequences: ["Ctrl+Y"]
    enabled: consent.open_ && !consent.busy
    context: Qt.WindowShortcut
    onActivated: consent.approve()
  }

  Shortcut {
    sequences: ["Esc"]
    enabled: consent.open_
    context: Qt.WindowShortcut
    onActivated: consent.refuse()
  }

  // Pick between accounts without reaching for the mouse.
  Shortcut {
    sequences: ["Ctrl+Down"]
    enabled: consent.open_ && consent.choices.length > 1
    context: Qt.WindowShortcut
    onActivated: consent.step(1)
  }
  Shortcut {
    sequences: ["Ctrl+Up"]
    enabled: consent.open_ && consent.choices.length > 1
    context: Qt.WindowShortcut
    onActivated: consent.step(-1)
  }

  function step(delta) {
    var n = consent.choices.length
    if (n === 0) return
    var i = 0
    for (var k = 0; k < n; k++)
      if (String(consent.choices[k].credential_id) === consent.chosenCredential) { i = k; break }
    consent.chosenCredential = String(consent.choices[(i + delta + n) % n].credential_id)
  }

  // ── surface ────────────────────────────────────────────────────────────────

  MouseArea {
    anchors.fill: parent
    hoverEnabled: true
    acceptedButtons: Qt.AllButtons
    onClicked: {}
  }
  Rectangle { anchors.fill: parent; color: Color.background }

  ColumnLayout {
    anchors.centerIn: parent
    width: Math.min(parent.width - metric.space(80), metric.space(720))
    spacing: metric.space(18)

    // ── what is being asked ─────────────────────────────────────────────────
    ColumnLayout {
      Layout.fillWidth: true
      spacing: metric.space(2)
      Text {
        text: consent.isCreate ? "A SITE WANTS TO CREATE A PASSKEY"
                               : "A SITE WANTS YOU TO SIGN IN"
        color: Util.alpha(Color.foreground, 0.5)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        font.letterSpacing: metric.spaceReal(1.6)
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
    }

    // ── the origin, which is the whole point ────────────────────────────────
    Rectangle {
      Layout.fillWidth: true
      implicitHeight: originCol.implicitHeight + metric.space(28)
      radius: metric.cornerRadius
      color: Util.alpha(Color.accent, 0.07)
      border.width: Math.max(1, metric.spacing.hairline)
      border.color: Util.alpha(Color.accent, 0.45)

      ColumnLayout {
        id: originCol
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        anchors.leftMargin: metric.space(20)
        anchors.rightMargin: metric.space(20)
        spacing: metric.space(4)

        // The registrable domain is bright; scheme, subdomains and path are
        // dimmed. A lookalike origin fails this reading, which is the point.
        Text {
          Layout.fillWidth: true
          text: Model.originMarkup(consent.ceremony ? consent.ceremony.origin : "",
                                   Util.alpha(Color.foreground, 0.35), Color.accent)
          textFormat: Text.StyledText
          font.family: metric.font.family
          font.pixelSize: metric.font.title
          font.bold: true
          elide: Text.ElideMiddle
          renderType: Text.NativeRendering
        }
        Text {
          Layout.fillWidth: true
          visible: text.length > 0
          text: consent.ceremony && consent.ceremony.rp_name
            ? String(consent.ceremony.rp_name) : ""
          color: Util.alpha(Color.foreground, 0.55)
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
          elide: Text.ElideRight
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
      }
    }

    // ── who as ───────────────────────────────────────────────────────────────
    ColumnLayout {
      Layout.fillWidth: true
      spacing: metric.space(6)
      visible: consent.choices.length > 0 || consent.isCreate

      Text {
        text: consent.isCreate ? "IT WILL BE SAVED AS" : "SIGN IN AS"
        color: Util.alpha(Color.foreground, 0.45)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        font.letterSpacing: metric.spaceReal(1.2)
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      // A create has exactly one identity and nothing to choose.
      Text {
        visible: consent.isCreate
        Layout.fillWidth: true
        text: consent.ceremony && consent.ceremony.account
          ? String(consent.ceremony.account)
          : (consent.ceremony ? String(consent.ceremony.rp_id) : "")
        color: Color.foreground
        font.family: metric.font.family
        font.pixelSize: metric.font.body
        font.bold: true
        elide: Text.ElideRight
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      Repeater {
        model: consent.isCreate ? [] : consent.choices
        delegate: Rectangle {
          required property var modelData
          readonly property bool current:
            String(modelData.credential_id) === consent.chosenCredential
          Layout.fillWidth: true
          implicitHeight: rowCol.implicitHeight + metric.space(16)
          radius: metric.cornerRadius
          color: current ? Util.alpha(Color.accent, 0.12)
               : (rowHover.hovered ? Util.alpha(Color.foreground, 0.06) : "transparent")
          border.width: Math.max(1, metric.spacing.hairline) * (current ? 2 : 1)
          border.color: current ? Color.accent : Util.alpha(Color.muted, 0.4)

          ColumnLayout {
            id: rowCol
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: metric.space(16)
            anchors.rightMargin: metric.space(16)
            spacing: 0
            Text {
              text: String(modelData.label)
              color: parent.parent.current ? Color.accent : Color.foreground
              font.family: metric.font.family
              font.pixelSize: metric.font.body
              font.bold: parent.parent.current
              elide: Text.ElideRight
              Layout.fillWidth: true
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
            }
          }
          HoverHandler { id: rowHover; cursorShape: Qt.PointingHandCursor }
          TapHandler {
            onTapped: consent.chosenCredential = String(modelData.credential_id)
          }
          Accessible.role: Accessible.RadioButton
          Accessible.name: String(modelData.label)
        }
      }
    }

    // ── the second thing being asked, when there is one ─────────────────────
    Rectangle {
      Layout.fillWidth: true
      visible: consent.ceremony && consent.ceremony.want_prf === true
      implicitHeight: prfCol.implicitHeight + metric.space(20)
      radius: metric.cornerRadius
      color: Util.alpha(Color.urgent, 0.06)
      border.width: Math.max(1, metric.spacing.hairline)
      border.color: Util.alpha(Color.urgent, 0.4)

      ColumnLayout {
        id: prfCol
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        anchors.leftMargin: metric.space(18)
        anchors.rightMargin: metric.space(18)
        spacing: metric.space(3)
        Text {
          text: "AND AN ENCRYPTION KEY"
          color: Util.alpha(Color.urgent, 0.9)
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
          font.bold: true
          font.letterSpacing: metric.spaceReal(1.2)
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
        Text {
          Layout.fillWidth: true
          text: "This site is also asking this passkey to derive a key for it. "
              + "Sites use that to encrypt your data so only this passkey can "
              + "read it back. It is not your vault key and it never leaves as "
              + "one — but it is a second thing you are agreeing to."
          color: Util.alpha(Color.foreground, 0.6)
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
          wrapMode: Text.WrapAtWordBoundaryOrAnywhere
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
      }
    }

    // ── the honest sentence ─────────────────────────────────────────────────
    Text {
      Layout.fillWidth: true
      text: consent.isCreate
        ? "Approving stores a new passkey in this vault and tells the site it exists. "
        + "Nothing else is sent."
        : "Approving signs a challenge from that origin. It proves you hold this "
        + "passkey, and it logs you in there."
      color: Util.alpha(Color.foreground, 0.55)
      font.family: metric.font.family
      font.pixelSize: metric.font.caption
      wrapMode: Text.WrapAtWordBoundaryOrAnywhere
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
    }

    // ── the proof ────────────────────────────────────────────────────────────
    ColumnLayout {
      Layout.fillWidth: true
      spacing: metric.space(6)

      Text {
        text: "YOUR MASTER PASSPHRASE"
        color: Util.alpha(Color.foreground, 0.45)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        font.letterSpacing: metric.spaceReal(1.2)
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      TextField {
        id: passField
        Layout.fillWidth: true
        echoMode: TextInput.Password
        enabled: !consent.busy
        placeholderText: "required to approve"
        font.family: metric.font.family
        font.pixelSize: metric.font.body
        onTextChanged: consent.passphrase = text
        // Return in this field approves, because reaching it took a deliberate
        // act — typing the passphrase — which is the opposite of reflex.
        Keys.onReturnPressed: consent.approve()
        Keys.onEnterPressed: consent.approve()
      }

      Text {
        Layout.fillWidth: true
        text: "The vault is already open. This is asked because the socket "
            + "cannot tell you from anything else running as you, and a "
            + "signature is a login."
        color: Util.alpha(Color.foreground, 0.4)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
    }

    Text {
      Layout.fillWidth: true
      visible: consent.errorText.length > 0
      text: consent.errorText
      color: Color.urgent
      font.family: metric.font.family
      font.pixelSize: metric.font.caption
      wrapMode: Text.WrapAtWordBoundaryOrAnywhere
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
    }

    // ── answer ───────────────────────────────────────────────────────────────
    RowLayout {
      Layout.fillWidth: true
      spacing: metric.space(12)

      Text {
        text: consent.secondsLeft > 0
          ? "expires in " + consent.secondsLeft + "s" : "expired"
        color: consent.secondsLeft <= 15 ? Color.urgent
                                         : Util.alpha(Color.foreground, 0.45)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      Item { Layout.fillWidth: true }

      ConsentButton {
        label: "REFUSE"
        tone: Color.urgent
        tappable: !consent.busy
        onActivated: consent.refuse()
      }
      ConsentButton {
        label: consent.busy ? "WORKING…" : "APPROVE  ^Y"
        tone: Color.accent
        tappable: !consent.busy && consent.secondsLeft > 0
        onActivated: consent.approve()
      }
    }
  }

  // ── footer ─────────────────────────────────────────────────────────────────
  Text {
    anchors.right: parent.right
    anchors.bottom: parent.bottom
    anchors.margins: metric.space(28)
    text: consent.choices.length > 1
      ? "^↑↓ choose  ·  ^Y approve  ·  esc refuse"
      : "^Y approve  ·  esc refuse"
    color: Util.alpha(Color.foreground, 0.4)
    font.family: metric.font.family
    font.pixelSize: metric.font.caption
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
  }

  component ConsentButton: Rectangle {
    id: btn
    property string label: ""
    property bool tappable: true
    property color tone: Color.foreground
    signal activated()

    implicitWidth: btnText.implicitWidth + metric.space(28)
    implicitHeight: metric.spacing.controlHeight + metric.space(6)
    radius: metric.cornerRadius
    activeFocusOnTab: btn.tappable
    color: btn.tappable && (btnHover.hovered || btn.activeFocus)
      ? Util.alpha(btn.tone, 0.2) : Util.alpha(btn.tone, 0.09)
    border.color: btn.activeFocus ? btn.tone
                                  : Util.alpha(btn.tone, btn.tappable ? 0.55 : 0.15)
    border.width: Math.max(1, metric.spacing.hairline) * (btn.activeFocus ? 2 : 1)

    Text {
      id: btnText
      anchors.centerIn: parent
      text: btn.label
      color: Util.alpha(btn.tone, btn.tappable ? 1.0 : 0.35)
      font.family: metric.font.family
      font.pixelSize: metric.font.caption
      font.bold: true
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
    }
    Keys.onPressed: function (event) {
      if (!btn.tappable) return
      // Space activates a focused button; Return does not, so that the habit
      // of pressing Return cannot approve a login.
      if (event.key === Qt.Key_Space) { btn.activated(); event.accepted = true }
    }
    HoverHandler { id: btnHover; enabled: btn.tappable; cursorShape: Qt.PointingHandCursor }
    TapHandler { enabled: btn.tappable; onTapped: btn.activated() }
    Accessible.role: Accessible.Button
    Accessible.name: btn.label
  }
}
