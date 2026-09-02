// BLACK-BAG — record editor.
//
// The sheet that makes this a password manager rather than a viewer: pick a
// kind, fill the fields that kind actually needs, save.
//
// Two rules it inherits from the rest of the deck:
//
//   1. A secret leaves here on the process's STDIN, inside a JSON draft, and
//      never as a command-line argument.
//   2. Editing an existing record never loads its secrets. A blank secret box
//      means "keep what is stored", so the form can exist without the cockpit
//      ever holding the current password.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import BlackBag
import "Model.js" as Model

Item {
  id: editor
  anchors.fill: parent
  visible: open_

  property bool open_: false
  property string mode: "add"          // add | edit
  property string kind: "login"
  property string recordId: ""
  property var seedRecord: null        // the RecordView being edited, if any
  property int motionMs: 160

  // Handed down by the deck so both sheets are the same size as the
  // surface behind them.
  property real uiScale: 1.0
  readonly property QtObject metric: DeckMetrics { uiScale: editor.uiScale }
  // How long a generated or peeked secret stays readable before the box
  // masks itself again. The deck's setting, so the two countdowns agree.
  property int revealSeconds: 10

  property string errorText: ""
  property bool saving: false

  signal saved(string id)
  signal cancelled()

  readonly property var template: Model.templateFor(editor.kind)
  readonly property bool isEdit: mode === "edit"

  function begin(newMode, newKind, record) {
    editor.mode = newMode
    editor.kind = newKind
    editor.seedRecord = record || null
    editor.recordId = record ? String(record.id) : ""
    editor.errorText = ""
    editor.saving = false
    editor.open_ = true
    Qt.callLater(function () {
      titleField.text = record ? String(record.title || "") : ""
      tagsField.text = record ? Model.asList(record.tags).join(", ") : ""

      // Every field is (re)seeded imperatively, every time. The attribute
      // delegates declare a binding from seedRecord, but a binding on a text
      // field dies the first time someone types into it — so a form that was
      // typed in once would show that session's values forever after: the
      // previous record's username on a fresh "new login", one record's
      // attributes under another record's edit. The bindings only cover the
      // delegate's first creation; this covers every open after that.
      var seed = record ? Model.attrMap(record) : ({})
      for (var a = 0; a < attrRepeater.count; a++) {
        var ai = attrRepeater.itemAt(a)
        if (ai) ai.setText(seed[ai.fieldName] === undefined ? "" : String(seed[ai.fieldName]))
      }
      // Secret boxes always open empty. In edit mode blank means "keep what
      // is stored" — and in every mode, a password typed during an earlier
      // visit must not still be sitting in the widget now.
      for (var i = 0; i < secretRepeater.count; i++) {
        var si = secretRepeater.itemAt(i)
        if (si) si.reset()
      }

      totpUri.reset()
      totpSecret.reset()
      titleField.focusInput()
    })
  }

  // Enter in a single-line field moves to the next one, and on the last field
  // it saves — the same rhythm the first-run sheet already taught. Before
  // this, Enter in the editor did nothing at all, which reads as a broken
  // form to anyone whose hands expect Enter to mean "go on".
  function advanceOrSave() {
    var chain = fieldChain()
    var at = focusIndex()
    if (at >= 0 && at === chain.length - 1) editor.save()
    else editor.moveFocus(1)
  }

  function dismiss() {
    // Whatever was typed into the secret boxes dies with the sheet.
    for (var i = 0; i < secretRepeater.count; i++) {
      var item = secretRepeater.itemAt(i)
      if (item) item.reset()
    }
    totpUri.reset()
    totpSecret.reset()
    editor.open_ = false
    editor.errorText = ""
    editor.cancelled()
  }

  function attrValues() {
    var out = {}
    for (var i = 0; i < attrRepeater.count; i++) {
      var item = attrRepeater.itemAt(i)
      if (item) out[item.fieldName] = item.value
    }
    return out
  }

  function secretValues() {
    var out = {}
    for (var i = 0; i < secretRepeater.count; i++) {
      var item = secretRepeater.itemAt(i)
      if (item) out[item.fieldName] = item.value
    }
    return out
  }

  function totpInput() {
    return { uri: totpUri.text, secret: totpSecret.text }
  }

  // Explicit tab order. The fields are built by Repeaters, so there is no
  // static order for Qt to infer, and clicking a field inside the sheet does
  // not reliably move focus — keyboard traversal is the dependable path and
  // this deck is keyboard-first anyway.
  function fieldChain() {
    var chain = [titleField, tagsField]
    for (var a = 0; a < attrRepeater.count; a++) {
      var ai = attrRepeater.itemAt(a)
      if (ai) chain.push(ai)
    }
    for (var s = 0; s < secretRepeater.count; s++) {
      var si = secretRepeater.itemAt(s)
      if (si) chain.push(si)
    }
    if (editor.template.totp === true) { chain.push(totpUri); chain.push(totpSecret) }
    return chain
  }

  function focusIndex() {
    var chain = fieldChain()
    for (var i = 0; i < chain.length; i++)
      if (chain[i] && chain[i].inputFocused) return i
    return -1
  }

  function moveFocus(delta) {
    var chain = fieldChain()
    if (chain.length === 0) return
    var at = focusIndex()
    var next = at < 0 ? 0 : (at + delta + chain.length) % chain.length
    chain[next].focusInput()
  }

  readonly property var problems:
    Model.draftProblems(editor.kind, titleField.text,
                        editor.open_ ? editor.secretValues() : ({}),
                        editor.open_ ? editor.totpInput() : ({}),
                        editor.isEdit)

  function save() {
    // A previous save still in flight must be said out loud, not swallowed:
    // setting `running = true` on an already-running process is a silent
    // no-op, so without this the button would read SAVING… forever and the
    // new draft would simply vanish.
    if (saveProcess.running) {
      editor.errorText = "the previous save is still finishing"
      return
    }
    if (editor.saving) editor.saving = false   // stale flag from a dismissed sheet
    var missing = Model.draftProblems(editor.kind, titleField.text,
                                      editor.secretValues(), editor.totpInput(),
                                      editor.isEdit)
    if (missing.length > 0) {
      editor.errorText = "still needs " + missing.join(", ")
      return
    }

    var draft = Model.buildDraft(editor.kind, titleField.text, tagsField.text,
                                 editor.attrValues(), editor.secretValues(),
                                 editor.totpInput())

    editor.errorText = ""
    editor.saving = true
    saveProcess.payload = JSON.stringify(draft)
    saveProcess.command = editor.isEdit
      ? ["black-bag", "agent", "edit", editor.recordId]
      : ["black-bag", "agent", "add"]
    saveProcess.running = true
  }

  Process {
    id: saveProcess
    running: false
    stdinEnabled: true
    property string payload: ""
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onStarted: {
      write(payload)
      // Drop our copy the moment it is handed over, and close the pipe so the
      // engine's read_to_string returns.
      payload = ""
      stdinEnabled = false
    }
    onExited: function (code) {
      editor.saving = false
      if (code === 0) {
        var id = String(this.stdout && this.stdout.text ? this.stdout.text : "").trim()
        // The engine holds the record now; the widgets must not. A password
        // left in a closed sheet is a password the next `n` would exhume.
        for (var i = 0; i < secretRepeater.count; i++) {
          var item = secretRepeater.itemAt(i)
          if (item) item.reset()
        }
        editor.open_ = false
        editor.saved(id.length > 0 ? id : editor.recordId)
      } else {
        var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
        editor.errorText = err.length > 0 ? err : "save failed"
      }
    }
  }

  // Window-scoped shortcuts rather than a Keys handler.
  //
  // The cockpit's keyCatcher only sees keys while IT holds active focus; the
  // moment a field in this sheet is focused, that handler stops firing
  // entirely. (Tab appeared to work only because Qt's own focus navigation
  // handles it without us.) Shortcut is focus-independent, so these keep
  // working wherever the caret is.
  Shortcut {
    sequences: ["Esc"]
    enabled: editor.open_
    context: Qt.WindowShortcut
    onActivated: editor.dismiss()
  }
  Shortcut {
    sequences: ["Ctrl+Return", "Ctrl+Enter"]
    enabled: editor.open_
    context: Qt.WindowShortcut
    onActivated: editor.save()
  }
  Shortcut {
    sequences: ["Ctrl+G"]
    enabled: editor.open_
    context: Qt.WindowShortcut
    onActivated: editor.generateFocused()
  }

  // Swallows clicks so the deck behind cannot be operated while this is up.
  Rectangle {
    anchors.fill: parent
    color: Util.alpha(Color.background, 0.86)
    MouseArea { anchors.fill: parent; onClicked: {} }
  }

  Rectangle {
    id: sheet
    anchors.centerIn: parent
    width: Math.min(parent.width * 0.55, metric.space(620))
    height: Math.min(parent.height * 0.86,
                     sheetCol.implicitHeight + metric.space(36))
    // A hard floor so a kind with almost no fields still looks deliberate.
    implicitHeight: metric.space(260)
    radius: metric.cornerRadius
    color: Color.background
    border.color: Util.alpha(Color.accent, 0.35)
    border.width: Math.max(1, metric.spacing.hairline)

    ColumnLayout {
      id: sheetCol
      anchors.fill: parent
      anchors.margins: metric.space(18)
      spacing: metric.space(12)

      // ── header ─────────────────────────────────────────────────────────
      RowLayout {
        Layout.fillWidth: true
        spacing: metric.space(10)
        Text {
          text: Model.kindGlyph(editor.kind)
          color: Color.accent
          font.family: metric.font.family
          font.pixelSize: metric.font.heading
          renderType: Text.NativeRendering
        }
        Text {
          Layout.fillWidth: true
          text: (editor.isEdit ? "EDIT " : "NEW ")
              + Model.kindLabel(editor.kind).toUpperCase()
          color: Util.alpha(Color.foreground, 0.85)
          font.family: metric.font.family
          font.pixelSize: metric.font.subtitle
          font.bold: true
          font.letterSpacing: metric.spaceReal(0.8)
          elide: Text.ElideRight
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
        Text {
          visible: editor.isEdit
          text: "keeps stored secrets unless you type over them"
          color: Util.alpha(Color.foreground, 0.35)
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
      }

      Rectangle {
        Layout.fillWidth: true
        height: Math.max(1, metric.spacing.hairline)
        color: Util.alpha(Color.muted, 0.5)
      }

      // ── body ───────────────────────────────────────────────────────────
      Flickable {
        id: scroller
        Layout.fillWidth: true
        Layout.fillHeight: true
        // Without a preferred height this contributes 0 to the sheet's own
        // implicitHeight, the sheet collapses, and the form is never seen.
        Layout.preferredHeight: form.implicitHeight
        clip: true
        pixelAligned: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height
        contentWidth: width
        contentHeight: form.implicitHeight
        ScrollBar.vertical: ScrollBar { id: formBar; policy: ScrollBar.AsNeeded }

        ColumnLayout {
          id: form
          width: scroller.width - (formBar.visible ? metric.space(12) : 0)
          // A Layout inside a Flickable has no height imposed on it, so it
          // defaults to 0. Children still PAINT (Qt Quick does not clip by
          // default) but hit-testing never descends into a zero-height parent,
          // so every click falls through to the scrim behind. This one line is
          // the difference between a form you can click and one you cannot.
          height: implicitHeight
          spacing: metric.space(10)

          // Kind picker — only when creating; changing kind mid-edit would
          // silently discard fields the new kind does not have.
          ColumnLayout {
            Layout.fillWidth: true
            visible: !editor.isEdit
            spacing: metric.space(4)
            Text {
              text: "KIND"
              color: Util.alpha(Color.foreground, 0.45)
              font.family: metric.font.family
              font.pixelSize: metric.font.caption
              font.bold: true
              font.letterSpacing: metric.spaceReal(0.8)
              renderType: Text.NativeRendering
            }
            Flow {
              Layout.fillWidth: true
              spacing: metric.space(6)
              Repeater {
                model: Model.kindChoices()
                delegate: Rectangle {
                  required property var modelData
                  readonly property bool active: modelData.kind === editor.kind
                  implicitWidth: kindLabel.implicitWidth + metric.space(20)
                  implicitHeight: metric.spacing.controlHeight
                  radius: metric.cornerRadius
                  color: active ? Util.alpha(Color.accent, 0.18)
                       : (kindMouse.containsMouse ? Util.alpha(Color.foreground, 0.08)
                                                  : Util.alpha(Color.foreground, 0.04))
                  border.color: active ? Color.accent : Util.alpha(Color.foreground, 0.15)
                  border.width: Math.max(1, metric.spacing.hairline)
                  Text {
                    id: kindLabel
                    anchors.centerIn: parent
                    text: modelData.glyph + "  " + modelData.label
                    color: active ? Color.accent : Util.alpha(Color.foreground, 0.75)
                    font.family: metric.font.family
                    font.pixelSize: metric.font.caption
                    font.bold: active
                    textFormat: Text.PlainText
                    renderType: Text.NativeRendering
                  }
                  MouseArea {
                    id: kindMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: editor.kind = modelData.kind
                  }
                  Behavior on color { ColorAnimation { duration: editor.motionMs } }
                }
              }
            }
          }

          FormField {
            id: titleField
            Layout.fillWidth: true
            label: "title"
            placeholder: "what this is, in your words"
          }

          FormField {
            id: tagsField
            Layout.fillWidth: true
            label: "tags (comma separated)"
            placeholder: "work, email"
          }

          // Open attributes for this kind.
          Repeater {
            id: attrRepeater
            model: editor.template.attrs
            delegate: FormField {
              required property var modelData
              readonly property string fieldName: String(modelData)
              Layout.fillWidth: true
              label: Model.fieldLabel(modelData)
              text: {
                if (!editor.seedRecord) return ""
                var m = Model.attrMap(editor.seedRecord)
                return m[String(modelData)] === undefined ? "" : m[String(modelData)]
              }
            }
          }

          // Secret fields. Never pre-filled, on purpose.
          Repeater {
            id: secretRepeater
            model: editor.template.secrets
            delegate: FormField {
              id: secretField
              required property var modelData
              readonly property string fieldName: String(modelData)
              Layout.fillWidth: true
              label: Model.fieldLabel(modelData)
              secret: true
              multiline: Model.isMultiline(editor.kind, String(modelData))
              placeholder: editor.isEdit ? "leave blank to keep the stored value" : ""
              generatable: !multiline
              onGenerate: editor.generateInto(secretField)
            }
          }

          // TOTP enrolment.
          ColumnLayout {
            Layout.fillWidth: true
            visible: editor.template.totp === true
            spacing: metric.space(8)

            FormField {
              id: totpUri
              Layout.fillWidth: true
              label: "otpauth:// URI"
              placeholder: "paste the enrolment URI — fills in everything below"
              secret: true
            }
            Text {
              Layout.fillWidth: true
              text: "or, if the site only shows you the key:"
              color: Util.alpha(Color.foreground, 0.35)
              font.family: metric.font.family
              font.pixelSize: metric.font.caption
              renderType: Text.NativeRendering
            }
            FormField {
              id: totpSecret
              Layout.fillWidth: true
              label: "base32 secret"
              placeholder: "spaces, hyphens and case do not matter"
              secret: true
            }
          }
        }
      }

      // ── footer ─────────────────────────────────────────────────────────
      Rectangle {
        Layout.fillWidth: true
        height: Math.max(1, metric.spacing.hairline)
        color: Util.alpha(Color.muted, 0.5)
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: metric.space(10)

        Text {
          Layout.fillWidth: true
          text: editor.errorText.length > 0
            ? editor.errorText
            : (editor.problems.length > 0
               ? "needs " + editor.problems.join(", ")
               : "tab moves · ⌃G generate · ⌃⏎ save · esc cancel")
          color: editor.errorText.length > 0 ? Color.urgent
               : (editor.problems.length > 0 ? Util.alpha(Color.foreground, 0.4)
                                             : Util.alpha(Color.accent, 0.7))
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
          wrapMode: Text.WrapAtWordBoundaryOrAnywhere
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }

        SheetButton {
          label: "CANCEL"
          tone: Util.alpha(Color.foreground, 0.6)
          onActivated: editor.dismiss()
        }
        SheetButton {
          label: editor.saving ? "SAVING…" : (editor.isEdit ? "SAVE" : "CREATE")
          tone: Color.accent
          enabledAction: !editor.saving && editor.problems.length === 0
          // Clickable even while dim: save() itself says "still needs a
          // title" where a disabled button would say nothing at all.
          tappable: !editor.saving
          onActivated: editor.save()
        }
      }
    }
  }

  // ── generation ───────────────────────────────────────────────────────────

  property var generateTarget: null

  // Generate into whichever secret field currently has focus.
  function generateFocused() {
    var chain = fieldChain()
    var at = focusIndex()
    if (at < 0) return
    var field = chain[at]
    if (!field || !field.generatable) {
      editor.errorText = "generate works on a password field"
      return
    }
    generateInto(field)
  }

  function generateInto(field) {
    editor.generateTarget = field
    genProcess.running = true
  }

  function applyGenerated(value) {
    if (!editor.generateTarget) return
    editor.generateTarget.setText(value)
    // A generated password written into a masked box is a password nobody
    // can read, verify or write down. Show it for the reveal window, then
    // mask it again — the same countdown the inspector's SHOW uses.
    editor.generateTarget.peekFor(editor.revealSeconds)
    editor.generateTarget = null
  }

  Process {
    id: genProcess
    command: ["black-bag", "gen", "password"]
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var value = String(this.text || "").replace(/\n+$/, "")
        if (value.length > 0) editor.applyGenerated(value)
        else editor.generateTarget = null
      }
    }
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      if (code !== 0) {
        var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
        editor.errorText = err.length > 0 ? err : "could not generate"
        editor.generateTarget = null
      }
    }
  }

  // ── primitives ───────────────────────────────────────────────────────────

  FieldMenu { id: fieldMenu }

  // ── mouse paste ────────────────────────────────────────────────────────────
  //
  // Qt Quick's text controls ship with no context menu at all, which in a
  // password manager means the one thing everyone does — paste a password in
  // with the mouse — silently does nothing. Cut and copy stay disabled while
  // the field is masking its contents: a reveal has a countdown and an audit
  // trail, and a context menu must not become the quiet way around both.
  component FieldMenuItem: MenuItem {
    id: fmi
    implicitHeight: editor.metric.spacing.controlHeight
    implicitWidth: editor.metric.space(170)
    contentItem: Text {
      text: fmi.text
      color: fmi.enabled ? Color.foreground : Util.alpha(Color.foreground, 0.3)
      font.family: editor.metric.font.family
      font.pixelSize: editor.metric.font.caption
      verticalAlignment: Text.AlignVCenter
      leftPadding: editor.metric.space(10)
      renderType: Text.NativeRendering
    }
    background: Rectangle {
      color: fmi.highlighted ? Util.alpha(Color.accent, 0.15) : "transparent"
    }
  }

  component FieldMenu: Menu {
    id: fmenu
    property Item target: null
    // Masked unless the target is a text input showing its contents. A
    // TextArea has no echoMode; "no echoMode" used to read as unmasked, which
    // made Copy the quiet way around the countdown for every multi-line secret.
    readonly property bool masked:
      !(fmenu.target && fmenu.target.echoMode === TextInput.Normal)
    background: Rectangle {
      implicitWidth: editor.metric.space(170)
      color: Color.background
      border.color: Util.alpha(Color.accent, 0.4)
      border.width: Math.max(1, editor.metric.spacing.hairline)
      radius: editor.metric.cornerRadius
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
    property string label: ""
    property color tone: Color.foreground
    property bool enabledAction: true
    // Whether a click is ACCEPTED, as opposed to how the button LOOKS.
    // These were one property, and that is exactly how "I hit create and
    // nothing happened" happens: a not-ready button swallowed the click and
    // gave nothing back. Now a dimmed button still takes the click, and the
    // handler answers with what is missing.
    property bool tappable: enabledAction
    signal activated()
    implicitWidth: btnText.implicitWidth + metric.space(22)
    implicitHeight: metric.spacing.controlHeight
    radius: metric.cornerRadius
    color: btnMouse.containsMouse && enabledAction
      ? Util.alpha(tone, 0.2) : Util.alpha(tone, 0.09)
    border.color: Util.alpha(tone, enabledAction ? 0.5 : 0.15)
    border.width: Math.max(1, metric.spacing.hairline)
    opacity: enabledAction ? 1 : 0.4
    Text {
      id: btnText
      anchors.centerIn: parent
      text: parent.label
      color: parent.tone
      font.family: metric.font.family
      font.pixelSize: metric.font.caption
      font.bold: true
      renderType: Text.NativeRendering
    }
    MouseArea {
      id: btnMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: parent.tappable ? Qt.PointingHandCursor : Qt.ArrowCursor
      onClicked: if (parent.tappable) parent.activated()
    }
    Behavior on color { ColorAnimation { duration: editor.motionMs } }
  }

  component FormField: ColumnLayout {
    id: formField
    property string label: ""
    property string placeholder: ""
    property bool secret: false
    property bool multiline: false
    property bool generatable: false
    property alias text: singleLine.text
    property string value: multiline ? multiLine.text : singleLine.text
    signal generate()

    // A secret box shows its contents only while `peeking`: after a
    // generate, or while the operator holds the eye open. It masks itself
    // again on a countdown, and always when the sheet closes.
    property bool peeking: false
    property int peekLeft: 0
    readonly property bool showing: !secret || peeking

    function peekFor(seconds) {
      formField.peekLeft = Math.max(1, Number(seconds) || 10)
      formField.peeking = true
      peekTimer.restart()
    }
    function togglePeek() {
      if (formField.peeking) { formField.peeking = false; formField.peekLeft = 0; peekTimer.stop() }
      else formField.peekFor(editor.revealSeconds)
    }
    function reset() {
      setText("")
      formField.peeking = false
      formField.peekLeft = 0
      peekTimer.stop()
    }
    Timer {
      id: peekTimer
      interval: 1000
      repeat: true
      onTriggered: {
        formField.peekLeft -= 1
        if (formField.peekLeft <= 0) { formField.peeking = false; stop() }
      }
    }

    spacing: metric.space(3)

    // A click inside this component lands on the ColumnLayout, not on the
    // input it wraps — confirmed with an on-screen activeFocusItem probe — so
    // container focus is forwarded to whichever input is actually showing.
    function focusInput() {
      if (multiline) {
        if (!formField.showing) formField.peekFor(editor.revealSeconds)
        multiLine.forceActiveFocus()
      } else singleLine.forceActiveFocus()
    }

    // `activeFocus` on this ColumnLayout is always false — a plain Item is not
    // a FocusScope, so focus never shows up on the container. Ask the input.
    readonly property bool inputFocused:
      multiline ? multiLine.activeFocus : singleLine.activeFocus

    function setText(v) {
      if (multiline) multiLine.text = v
      else singleLine.text = v
    }
    TapHandler {
      // On the container, not the input: a click lands here first, and this
      // hands focus down. Verified against an activeFocusItem probe.
      onTapped: focusInput()
    }

    RowLayout {
      Layout.fillWidth: true
      spacing: metric.space(8)
      Text {
        text: parent.parent.label
        color: Util.alpha(Color.foreground, 0.5)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
      Item { Layout.fillWidth: true }
      Text {
        visible: formField.secret
        text: formField.peeking
          ? "hide" + (formField.peekLeft > 0 ? " · " + formField.peekLeft + "s" : "")
          : "show"
        color: Util.alpha(formField.peeking ? Color.urgent : Color.accent,
                          peekMouse.containsMouse ? 1.0 : 0.6)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        font.bold: peekMouse.containsMouse
        renderType: Text.NativeRendering
        Accessible.role: Accessible.Button
        Accessible.name: formField.peeking ? "hide " + formField.label : "show " + formField.label
        MouseArea {
          id: peekMouse
          anchors.fill: parent
          anchors.margins: -metric.space(4)
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: formField.togglePeek()
        }
      }
      Text {
        visible: parent.parent.generatable
        text: "generate"
        color: Util.alpha(Color.accent, genMouse.containsMouse ? 1.0 : 0.6)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        font.bold: genMouse.containsMouse
        renderType: Text.NativeRendering
        Accessible.role: Accessible.Button
        Accessible.name: "generate " + formField.label
        MouseArea {
          id: genMouse
          anchors.fill: parent
          anchors.margins: -metric.space(4)
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: parent.parent.parent.generate()
        }
      }
    }

    InputField {
      id: singleLine
      // Enter means "go on": next field, or save from the last one. It calls
      // up to the editor because which field is last is the form's knowledge,
      // not this component's.
      onAccepted: editor.advanceOrSave()
      // Tab is fenced inside the sheet. Left to Qt's window-wide focus chain
      // it walks in creation order — which, one Tab past the last field,
      // lands the caret in the deck's search box BEHIND the modal.
      activeFocusOnTab: false
      Keys.onPressed: function (event) {
        if (event.key === Qt.Key_Backtab
            || (event.key === Qt.Key_Tab && (event.modifiers & Qt.ShiftModifier))) {
          editor.moveFocus(-1); event.accepted = true
        } else if (event.key === Qt.Key_Tab) {
          editor.moveFocus(1); event.accepted = true
        }
      }
      font.pixelSize: editor.metric.font.body
      topPadding: editor.metric.spacing.inputPaddingY
      bottomPadding: editor.metric.spacing.inputPaddingY
      leftPadding: editor.metric.spacing.controlPaddingX
      rightPadding: editor.metric.spacing.controlPaddingX
      Layout.fillWidth: true
      visible: !parent.multiline
      password: !formField.showing
      placeholderText: parent.placeholder
      activeFocusOnPress: true
      TapHandler {
        // Cooperates with the enclosing Flickable, which a MouseArea would not.
        acceptedButtons: Qt.LeftButton
        onTapped: singleLine.forceActiveFocus()
      }
      TapHandler {
        acceptedButtons: Qt.RightButton
        onTapped: {
          singleLine.forceActiveFocus()
          fieldMenu.target = singleLine
          fieldMenu.popup()
        }
      }
    }

    Rectangle {
      Layout.fillWidth: true
      Layout.preferredHeight: metric.space(90)
      visible: parent.multiline
      color: Util.alpha(Color.foreground, 0.05)
      border.color: Util.alpha(Color.foreground, 0.15)
      border.width: Math.max(1, metric.spacing.hairline)
      radius: metric.cornerRadius

      // A TextArea cannot mask, so a multi-line secret gets a cover instead:
      // the text is hidden until the eye is opened, and masks itself again
      // on the same countdown. Typing while covered is not possible, which
      // is the point — you see what you are about to store.
      Rectangle {
        anchors.fill: parent
        visible: !formField.showing
        color: Util.alpha(Color.background, 0.9)
        radius: metric.cornerRadius
        Text {
          anchors.centerIn: parent
          width: parent.width - metric.space(24)
          text: multiLine.length > 0
            ? "hidden · " + multiLine.length + " characters · click to reveal and edit"
            : "hidden · click to reveal and type"
          color: Util.alpha(Color.foreground, 0.6)
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
          horizontalAlignment: Text.AlignHCenter
          wrapMode: Text.WrapAtWordBoundaryOrAnywhere
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
        MouseArea {
          anchors.fill: parent
          cursorShape: Qt.PointingHandCursor
          onClicked: { formField.peekFor(editor.revealSeconds); multiLine.forceActiveFocus() }
        }
      }

      ScrollView {
        anchors.fill: parent
        anchors.margins: metric.space(6)
        clip: true
        visible: formField.showing
        TextArea {
          id: multiLine
          // Same fence as the single-line fields; in a form, Tab means "next
          // field", not "insert a tab character into the note".
          activeFocusOnTab: false
          Keys.onPressed: function (event) {
            if (event.key === Qt.Key_Backtab
                || (event.key === Qt.Key_Tab && (event.modifiers & Qt.ShiftModifier))) {
              editor.moveFocus(-1); event.accepted = true
            } else if (event.key === Qt.Key_Tab) {
              editor.moveFocus(1); event.accepted = true
            }
          }
          topPadding: editor.metric.spacing.inputPaddingY
          bottomPadding: editor.metric.spacing.inputPaddingY
          activeFocusOnPress: true
          TapHandler {
            acceptedButtons: Qt.LeftButton
            onTapped: multiLine.forceActiveFocus()
          }
          TapHandler {
            acceptedButtons: Qt.RightButton
            onTapped: {
              multiLine.forceActiveFocus()
              fieldMenu.target = multiLine
              fieldMenu.popup()
            }
          }
          wrapMode: TextArea.WrapAnywhere
          color: Color.foreground
          font.family: metric.font.family
          font.pixelSize: metric.font.bodySmall
          background: null
          selectByMouse: true
        }
      }
    }
  }
}
