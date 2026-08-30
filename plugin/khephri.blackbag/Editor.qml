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
import Quickshell.Io
import qs.Commons
import qs.Ui
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
      totpUri.text = ""
      totpSecret.text = ""
      titleField.focusInput()
    })
  }

  function dismiss() {
    // Whatever was typed into the secret boxes dies with the sheet.
    for (var i = 0; i < secretRepeater.count; i++) {
      var item = secretRepeater.itemAt(i)
      if (item) item.setText("")
    }
    totpUri.text = ""
    totpSecret.text = ""
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
    if (editor.saving) return
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
    width: Math.min(parent.width * 0.55, Style.space(620))
    height: Math.min(parent.height * 0.86,
                     sheetCol.implicitHeight + Style.space(36))
    // A hard floor so a kind with almost no fields still looks deliberate.
    implicitHeight: Style.space(260)
    radius: Style.cornerRadius
    color: Color.background
    border.color: Util.alpha(Color.accent, 0.35)
    border.width: Math.max(1, Style.spacing.hairline)

    ColumnLayout {
      id: sheetCol
      anchors.fill: parent
      anchors.margins: Style.space(18)
      spacing: Style.space(12)

      // ── header ─────────────────────────────────────────────────────────
      RowLayout {
        Layout.fillWidth: true
        spacing: Style.space(10)
        Text {
          text: Model.kindGlyph(editor.kind)
          color: Color.accent
          font.family: Style.font.family
          font.pixelSize: Style.font.heading
          renderType: Text.NativeRendering
        }
        Text {
          Layout.fillWidth: true
          text: (editor.isEdit ? "EDIT " : "NEW ")
              + Model.kindLabel(editor.kind).toUpperCase()
          color: Util.alpha(Color.foreground, 0.85)
          font.family: Style.font.family
          font.pixelSize: Style.font.subtitle
          font.bold: true
          font.letterSpacing: Style.spaceReal(0.8)
          elide: Text.ElideRight
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
        Text {
          visible: editor.isEdit
          text: "keeps stored secrets unless you type over them"
          color: Util.alpha(Color.foreground, 0.35)
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
      }

      Rectangle {
        Layout.fillWidth: true
        height: Math.max(1, Style.spacing.hairline)
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
          width: scroller.width - (formBar.visible ? Style.space(12) : 0)
          // A Layout inside a Flickable has no height imposed on it, so it
          // defaults to 0. Children still PAINT (Qt Quick does not clip by
          // default) but hit-testing never descends into a zero-height parent,
          // so every click falls through to the scrim behind. This one line is
          // the difference between a form you can click and one you cannot.
          height: implicitHeight
          spacing: Style.space(10)

          // Kind picker — only when creating; changing kind mid-edit would
          // silently discard fields the new kind does not have.
          ColumnLayout {
            Layout.fillWidth: true
            visible: !editor.isEdit
            spacing: Style.space(4)
            Text {
              text: "KIND"
              color: Util.alpha(Color.foreground, 0.45)
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              font.bold: true
              font.letterSpacing: Style.spaceReal(0.8)
              renderType: Text.NativeRendering
            }
            Flow {
              Layout.fillWidth: true
              spacing: Style.space(6)
              Repeater {
                model: Model.kindChoices()
                delegate: Rectangle {
                  required property var modelData
                  readonly property bool active: modelData.kind === editor.kind
                  implicitWidth: kindLabel.implicitWidth + Style.space(20)
                  implicitHeight: Style.spacing.controlHeight
                  radius: Style.cornerRadius
                  color: active ? Util.alpha(Color.accent, 0.18)
                       : (kindMouse.containsMouse ? Util.alpha(Color.foreground, 0.08)
                                                  : Util.alpha(Color.foreground, 0.04))
                  border.color: active ? Color.accent : Util.alpha(Color.foreground, 0.15)
                  border.width: Math.max(1, Style.spacing.hairline)
                  Text {
                    id: kindLabel
                    anchors.centerIn: parent
                    text: modelData.glyph + "  " + modelData.label
                    color: active ? Color.accent : Util.alpha(Color.foreground, 0.75)
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
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
            spacing: Style.space(8)

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
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
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
        height: Math.max(1, Style.spacing.hairline)
        color: Util.alpha(Color.muted, 0.5)
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: Style.space(10)

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
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
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

  component SheetButton: Rectangle {
    property string label: ""
    property color tone: Color.foreground
    property bool enabledAction: true
    signal activated()
    implicitWidth: btnText.implicitWidth + Style.space(22)
    implicitHeight: Style.spacing.controlHeight
    radius: Style.cornerRadius
    color: btnMouse.containsMouse && enabledAction
      ? Util.alpha(tone, 0.2) : Util.alpha(tone, 0.09)
    border.color: Util.alpha(tone, enabledAction ? 0.5 : 0.15)
    border.width: Math.max(1, Style.spacing.hairline)
    opacity: enabledAction ? 1 : 0.4
    Text {
      id: btnText
      anchors.centerIn: parent
      text: parent.label
      color: parent.tone
      font.family: Style.font.family
      font.pixelSize: Style.font.caption
      font.bold: true
      renderType: Text.NativeRendering
    }
    MouseArea {
      id: btnMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: parent.enabledAction ? Qt.PointingHandCursor : Qt.ArrowCursor
      onClicked: if (parent.enabledAction) parent.activated()
    }
    Behavior on color { ColorAnimation { duration: editor.motionMs } }
  }

  component FormField: ColumnLayout {
    property string label: ""
    property string placeholder: ""
    property bool secret: false
    property bool multiline: false
    property bool generatable: false
    property alias text: singleLine.text
    property string value: multiline ? multiLine.text : singleLine.text
    signal generate()

    spacing: Style.space(3)

    // A click inside this component lands on the ColumnLayout, not on the
    // input it wraps — confirmed with an on-screen activeFocusItem probe — so
    // container focus is forwarded to whichever input is actually showing.
    function focusInput() {
      if (multiline) multiLine.forceActiveFocus()
      else singleLine.forceActiveFocus()
    }

    // `activeFocus` on this ColumnLayout is always false — a plain Item is not
    // a FocusScope, so focus never shows up on the container. Ask the input.
    readonly property bool inputFocused:
      multiline ? multiLine.activeFocus : singleLine.activeFocus

    function setText(v) {
      if (multiline) multiLine.text = v
      else singleLine.text = v
    }
    onActiveFocusChanged: if (activeFocus) focusInput()

    TapHandler {
      // On the container, not the input: a click lands here first, and this
      // hands focus down. Verified against an activeFocusItem probe.
      onTapped: focusInput()
    }

    RowLayout {
      Layout.fillWidth: true
      spacing: Style.space(8)
      Text {
        text: parent.parent.label
        color: Util.alpha(Color.foreground, 0.5)
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
      Item { Layout.fillWidth: true }
      Text {
        visible: parent.parent.generatable
        text: "generate"
        color: Util.alpha(Color.accent, genMouse.containsMouse ? 1.0 : 0.6)
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        font.bold: genMouse.containsMouse
        renderType: Text.NativeRendering
        MouseArea {
          id: genMouse
          anchors.fill: parent
          anchors.margins: -Style.space(4)
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: parent.parent.parent.generate()
        }
      }
    }

    TextField {
      id: singleLine
      Layout.fillWidth: true
      visible: !parent.multiline
      password: parent.secret
      placeholderText: parent.placeholder
      activeFocusOnPress: true
      TapHandler {
        // Cooperates with the enclosing Flickable, which a MouseArea would not.
        onTapped: singleLine.forceActiveFocus()
      }
    }

    Rectangle {
      Layout.fillWidth: true
      Layout.preferredHeight: Style.space(90)
      visible: parent.multiline
      color: Util.alpha(Color.foreground, 0.05)
      border.color: Util.alpha(Color.foreground, 0.15)
      border.width: Math.max(1, Style.spacing.hairline)
      radius: Style.cornerRadius
      ScrollView {
        anchors.fill: parent
        anchors.margins: Style.space(6)
        clip: true
        TextArea {
          id: multiLine
          activeFocusOnPress: true
          TapHandler { onTapped: multiLine.forceActiveFocus() }
          wrapMode: TextArea.WrapAnywhere
          color: Color.foreground
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
          background: null
          selectByMouse: true
        }
      }
    }
  }
}
