// BLACK-BAG — everything the engine can do, where you can reach it.
//
// The deck could unlock, browse, author and lock. The engine could also
// re-key, mint and revoke recovery keys, import from six other managers,
// export, and generate. None of that was reachable without a terminal, which
// for someone who lives in the app means it did not exist. Worse, the deck
// would tell you "Argon2 cost is below the current default — re-key to raise
// it" and then offer no way to re-key.
//
// One sheet, six sections, a nav on the left and a panel on the right. The
// rules are the deck's own:
//
//   1. Every secret — a passphrase, a generated value — crosses to the engine
//      on STDIN. Never argv.
//   2. Nothing is retained. clear() runs on every exit path and the deck's
//      clearSecrets() calls it.
//   3. Anything irreversible is armed and confirmed, and says what it will do
//      before it does it.
//   4. A capability the vault does not have is not offered.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

Item {
  id: manage
  anchors.fill: parent
  visible: open_

  property bool open_: false
  property int motionMs: 160
  property real uiScale: 1.0
  readonly property QtObject metric: DeckMetrics { uiScale: manage.uiScale }

  property string homeDir: ""
  /// The live status document, for the KDF figures and the recipient list.
  property var status: null
  /// Resolved settings, so the settings panel shows what is in force.
  property var settings: ({})

  /// The vault changed under the deck: re-read records and status.
  signal changed()
  /// A setting was edited. The host owns where settings live.
  signal settingChanged(string key, var value)
  signal dismissed()

  readonly property var sections: [
    { key: "passphrase", label: "PASSPHRASE",    hint: "change it, or raise the work factor" },
    { key: "keys",       label: "RECOVERY KEYS", hint: "mint one, or revoke one" },
    { key: "import",     label: "IMPORT",        hint: "from six other managers" },
    { key: "export",     label: "EXPORT",        hint: "plaintext, deliberately" },
    { key: "generate",   label: "GENERATE",      hint: "with honest entropy" },
    { key: "settings",   label: "SETTINGS",      hint: "how this deck behaves" }
  ]
  property string section: "passphrase"

  /// What Ctrl+Return would do right now, named in the footer so the chord is
  /// never a guess.
  readonly property string primaryLabel: {
    switch (manage.section) {
      case "passphrase": return "change"
      case "keys":       return "mint"
      case "import":     return manage.importPreview.length === 0 ? "preview" : "import"
      case "export":     return "export"
      case "generate":   return "generate"
      default:           return ""
    }
  }

  property string errorText: ""
  property string noteText: ""
  property bool busy: false

  // ── the fields every panel draws from ──────────────────────────────────────
  property string currentPass: ""
  property string newPass: ""
  property string confirmPass: ""
  property bool showPass: false

  property string keyLabel: ""
  property string keyPath: ""
  property string revokeArmed: ""

  property string importFormat: "bitwarden"
  property string importPath: ""
  property string importPreview: ""

  property string exportFormat: "json"
  property string exportPath: ""
  property bool exportArmed: false

  property string genKind: "password"
  property int genLength: 20
  property int genWords: 6
  property int genDigits: 6
  property bool genSymbols: true
  property bool genAmbiguous: false
  property string generated: ""
  property string generatedNote: ""

  readonly property int minLength: 12
  readonly property var recipients: Model.recipientRows(manage.status)
  readonly property var revocable: Model.revocableRecipients(manage.status)

  function begin(which) {
    manage.section = which && which.length > 0 ? which : "passphrase"
    manage.errorText = ""
    manage.noteText = ""
    manage.busy = false
    manage.revokeArmed = ""
    manage.exportArmed = false
    manage.importPreview = ""
    manage.generated = ""
    manage.generatedNote = ""
    manage.keyLabel = "offsite-" + Model.shortStamp()
    manage.keyPath = (manage.homeDir.length > 0 ? manage.homeDir : "~") + "/black-bag-recovery.key"
    manage.importPath = (manage.homeDir.length > 0 ? manage.homeDir : "~") + "/export.json"
    manage.exportPath = (manage.homeDir.length > 0 ? manage.homeDir : "~") + "/black-bag-export.json"
    manage.clear()
    manage.open_ = true
    Qt.callLater(function () { manage.forceActiveFocus() })
  }

  /// Everything sensitive this sheet can hold. Called on every exit path and
  /// by the deck's clearSecrets().
  function clear() {
    manage.currentPass = ""
    manage.newPass = ""
    manage.confirmPass = ""
    manage.generated = ""
    manage.showPass = false
    currentField.text = ""
    newField.text = ""
    confirmField.text = ""
  }

  function dismiss() {
    if (anyProcessRunning()) return   // a write is in flight; let it land
    manage.clear()
    manage.open_ = false
    manage.dismissed()
  }

  function anyProcessRunning() {
    return rekeyProcess.running || keyAddProcess.running || keyRemoveProcess.running
        || importProcess.running || exportProcess.running || genProcess.running
  }

  function go(which) {
    manage.section = which
    manage.errorText = ""
    manage.noteText = ""
    manage.revokeArmed = ""
    manage.exportArmed = false
  }

  // Index of the section on screen, so the rail can number itself and the
  // stepper knows where it is. -1 is impossible in practice; treated as 0.
  readonly property int sectionIndex: {
    for (var i = 0; i < manage.sections.length; i++)
      if (manage.sections[i].key === manage.section) return i
    return 0
  }

  // Ctrl+Up/Down walks the rail. It wraps, because six sections in a ring is
  // faster to reach than six sections in a line, and there is no scroll
  // position to lose.
  function step(delta) {
    var n = manage.sections.length
    manage.go(manage.sections[(manage.sectionIndex + delta + n) % n].key)
  }

  /// The one verb each section exists for. Kept beside the sections list so a
  /// new section cannot quietly arrive without one.
  function primary() {
    if (manage.busy) return
    switch (manage.section) {
      case "passphrase": manage.changePassphrase(); break
      case "keys":       manage.addRecoveryKey(); break
      case "import":
        if (manage.importPreview.length === 0) manage.previewImport()
        else manage.runImport()
        break
      case "export":     manage.runExport(); break
      case "generate":   manage.generate(); break
      // Settings apply as they are edited; there is nothing to commit.
      case "settings":   break
    }
  }

  // ── passphrase ─────────────────────────────────────────────────────────────

  function changePassphrase() {
    if (manage.busy) return
    if (manage.currentPass.length === 0) {
      manage.errorText = "the current passphrase is needed to open the vault before it can be re-keyed"
      return
    }
    if (manage.newPass.length < manage.minLength) {
      manage.errorText = "the new passphrase needs at least " + manage.minLength + " characters"
      return
    }
    if (manage.newPass !== manage.confirmPass) {
      manage.errorText = "the two new passphrases do not match"
      return
    }
    manage.errorText = ""
    manage.busy = true
    rekeyProcess.mode = "passphrase"
    rekeyProcess.command = ["black-bag", "rekey", "--change-passphrase"]
    rekeyProcess.running = true
  }

  function raiseKdf() {
    if (manage.busy) return
    if (manage.currentPass.length === 0) {
      manage.errorText = "the current passphrase is needed to open the vault before it can be re-keyed"
      return
    }
    manage.errorText = ""
    manage.busy = true
    rekeyProcess.mode = "kdf"
    rekeyProcess.command = ["black-bag", "rekey", "--mem-kib", String(Model.DEFAULT_MEM_KIB)]
    rekeyProcess.running = true
  }

  Process {
    id: rekeyProcess
    property string mode: "passphrase"
    running: false
    stdinEnabled: true
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onStarted: {
      // `rekey` reads the current passphrase, then — with
      // --change-passphrase — one more line for the new one, because a piped
      // stdin gets a single line rather than being asked twice.
      write(rekeyProcess.mode === "passphrase"
            ? manage.currentPass + "\n" + manage.newPass + "\n"
            : manage.currentPass + "\n")
      stdinEnabled = false
    }
    onExited: function (code) {
      manage.busy = false
      var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
      if (code !== 0) {
        manage.errorText = err.length > 0 ? err : "re-key failed"
        return
      }
      manage.clear()
      manage.errorText = ""
      manage.noteText = rekeyProcess.mode === "passphrase"
        ? "passphrase changed · the vault was re-encrypted under a fresh data key and every recipient re-wrapped"
        : "work factor raised · the vault was re-encrypted under a fresh data key"
      manage.changed()
    }
  }

  // ── recovery keys ──────────────────────────────────────────────────────────

  function addRecoveryKey() {
    if (manage.busy) return
    if (manage.keyLabel.trim().length === 0) { manage.errorText = "give the key a label"; return }
    if (manage.keyPath.trim().length === 0) { manage.errorText = "give the key file somewhere to go"; return }
    if (manage.currentPass.length === 0) {
      manage.errorText = "the master passphrase is needed: minting a recovery key changes who can open this vault"
      return
    }
    manage.errorText = ""
    manage.busy = true
    keyAddProcess.command = ["black-bag", "recovery", "add", manage.keyLabel.trim(),
                             "--out", manage.keyPath.trim()]
    keyAddProcess.running = true
  }

  Process {
    id: keyAddProcess
    running: false
    stdinEnabled: true
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onStarted: { write(manage.currentPass + "\n"); stdinEnabled = false }
    onExited: function (code) {
      manage.busy = false
      var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
      if (code !== 0) {
        manage.errorText = err.length > 0 ? err : "could not mint the recovery key"
        return
      }
      manage.clear()
      manage.noteText = "written to " + manage.keyPath.trim()
                      + " (mode 0600) · it opens this vault without the passphrase, so move it offline now"
      manage.changed()
    }
  }

  function revokeRecoveryKey(label) {
    if (manage.busy) return
    if (manage.revokeArmed !== label) {
      manage.revokeArmed = label
      manage.errorText = ""
      manage.noteText = ""
      return
    }
    if (manage.currentPass.length === 0) {
      manage.errorText = "the master passphrase is needed to revoke a recipient"
      manage.revokeArmed = ""
      return
    }
    manage.revokeArmed = ""
    manage.busy = true
    keyRemoveProcess.command = ["black-bag", "recovery", "remove", label]
    keyRemoveProcess.running = true
  }

  Process {
    id: keyRemoveProcess
    running: false
    stdinEnabled: true
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onStarted: { write(manage.currentPass + "\n"); stdinEnabled = false }
    onExited: function (code) {
      manage.busy = false
      var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
      if (code !== 0) {
        manage.errorText = err.length > 0 ? err : "could not revoke that recipient"
        return
      }
      manage.clear()
      manage.noteText = "revoked · that key file can no longer open this vault"
      manage.changed()
    }
  }

  // ── import ─────────────────────────────────────────────────────────────────

  function previewImport() {
    if (manage.busy) return
    if (manage.importPath.trim().length === 0) { manage.errorText = "point at the file to import"; return }
    manage.errorText = ""
    manage.importPreview = ""
    manage.busy = true
    importProcess.dryRun = true
    importProcess.command = ["black-bag", "import", "--from", manage.importPath.trim(),
                             "--format", manage.importFormat, "--dry-run"]
    importProcess.running = true
  }

  function runImport() {
    if (manage.busy) return
    if (manage.importPreview.length === 0) { manage.errorText = "preview it first"; return }
    manage.errorText = ""
    manage.busy = true
    importProcess.dryRun = false
    importProcess.command = ["black-bag", "import", "--from", manage.importPath.trim(),
                             "--format", manage.importFormat]
    importProcess.running = true
  }

  Process {
    id: importProcess
    property bool dryRun: true
    running: false
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      manage.busy = false
      var out = String(this.stdout && this.stdout.text ? this.stdout.text : "").trim()
      var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
      if (code !== 0) {
        manage.errorText = err.length > 0 ? err : "the import failed"
        return
      }
      if (importProcess.dryRun) {
        // Both streams: stdout counts what parsed, stderr names what did not.
        manage.importPreview = out + (err.length > 0 ? "\n" + err : "")
        manage.noteText = "nothing written yet"
        return
      }
      manage.importPreview = ""
      // The engine prints what it parsed first and what it WROTE second, so
      // taking line one reported "parsed 3 records" after a successful import
      // and never confirmed anything had been written. Prefer the line that
      // says it wrote; fall back to the last line rather than inventing one.
      var lines = out.split("\n").filter(function (l) { return l.trim().length > 0 })
      var wrote = lines.filter(function (l) { return l.indexOf("imported ") === 0 })
      manage.noteText = wrote.length > 0 ? wrote[0]
                      : (lines.length > 0 ? lines[lines.length - 1] : "imported")
      manage.changed()
    }
  }

  // ── export ─────────────────────────────────────────────────────────────────

  function runExport() {
    if (manage.busy) return
    if (manage.exportPath.trim().length === 0) { manage.errorText = "give the export somewhere to go"; return }
    if (!manage.exportArmed) {
      manage.exportArmed = true
      manage.errorText = ""
      manage.noteText = ""
      return
    }
    if (manage.currentPass.length === 0) {
      manage.errorText = "the master passphrase is needed: there is deliberately no way to read the whole vault over the agent socket"
      return
    }
    manage.exportArmed = false
    manage.busy = true
    exportProcess.command = ["black-bag", "export", "--to", manage.exportPath.trim(),
                             "--format", manage.exportFormat, "--plaintext-ok"]
    exportProcess.running = true
  }

  Process {
    id: exportProcess
    running: false
    stdinEnabled: true
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onStarted: { write(manage.currentPass + "\n"); stdinEnabled = false }
    onExited: function (code) {
      manage.busy = false
      var out = String(this.stdout && this.stdout.text ? this.stdout.text : "").trim()
      var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
      if (code !== 0) {
        manage.errorText = err.length > 0 ? err : "the export failed"
        return
      }
      manage.clear()
      manage.noteText = out.split("\n")[0] + " · shred it when the other tool has read it"
    }
  }

  // ── generate ───────────────────────────────────────────────────────────────

  function generate() {
    if (manage.busy) return
    manage.errorText = ""
    manage.busy = true
    var args = ["black-bag", "gen", manage.genKind]
    if (manage.genKind === "password") {
      args.push("--length", String(manage.genLength))
      if (!manage.genSymbols) args.push("--no-symbols")
      if (manage.genAmbiguous) args.push("--exclude-ambiguous")
    } else if (manage.genKind === "passphrase") {
      args.push("--words", String(manage.genWords))
    } else {
      args.push("--digits", String(manage.genDigits))
    }
    genProcess.command = args
    genProcess.running = true
  }

  function copyGenerated() {
    if (manage.generated.length === 0) return
    // Through the engine's own clipboard path, so the value is offered with
    // the sensitive hint and cleared on a timer exactly as a stored secret is.
    clipProcess.command = ["black-bag", "gen", manage.genKind, "--to", "clipboard"]
    manage.noteText = "generating a fresh value straight to the clipboard"
    clipProcess.running = true
  }

  Process {
    id: genProcess
    running: false
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      manage.busy = false
      var out = String(this.stdout && this.stdout.text ? this.stdout.text : "").replace(/\n+$/, "")
      var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
      if (code !== 0 || out.length === 0) {
        manage.errorText = err.length > 0 ? err : "could not generate"
        return
      }
      manage.generated = out
      // Carried verbatim: it is the engine's claim about its own output, and
      // rewording it would be inventing a rating.
      manage.generatedNote = err
    }
  }

  Process {
    id: clipProcess
    running: false
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
      manage.noteText = code === 0 && err.length > 0 ? err : ""
      if (code !== 0) manage.errorText = err.length > 0 ? err : "could not copy"
    }
  }

  // ── keys ───────────────────────────────────────────────────────────────────

  Shortcut {
    sequences: ["Esc"]
    enabled: manage.open_
    context: Qt.WindowShortcut
    onActivated: {
      if (manage.revokeArmed.length > 0) { manage.revokeArmed = ""; return }
      if (manage.exportArmed) { manage.exportArmed = false; return }
      manage.dismiss()
    }
  }

  // The rest of the deck is driven from the keyboard, so this sheet is too.
  // Ctrl+digit jumps; the digits are drawn on the rail so they are findable
  // without reading a manual. Ctrl is required because every panel here has
  // text fields, and a bare digit belongs to whichever field has the caret.
  Repeater {
    model: manage.sections
    delegate: Item {
      required property var modelData
      required property int index
      Shortcut {
        sequences: ["Ctrl+" + (index + 1)]
        enabled: manage.open_
        context: Qt.WindowShortcut
        onActivated: manage.go(modelData.key)
      }
    }
  }

  Shortcut {
    sequences: ["Ctrl+Down"]
    enabled: manage.open_
    context: Qt.WindowShortcut
    onActivated: manage.step(1)
  }

  Shortcut {
    sequences: ["Ctrl+Up"]
    enabled: manage.open_
    context: Qt.WindowShortcut
    onActivated: manage.step(-1)
  }

  // Ctrl+Return runs the section's primary verb, the way it already does in
  // the editor, the first-run sheet and the recovery sheet. Import is the one
  // section with two steps, and the chord follows them in order: it previews
  // first and only writes once you have seen what parsed.
  Shortcut {
    sequences: ["Ctrl+Return", "Ctrl+Enter"]
    enabled: manage.open_ && !manage.busy
    context: Qt.WindowShortcut
    onActivated: manage.primary()
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
    anchors.fill: parent
    anchors.margins: metric.space(28)
    spacing: metric.space(14)

    // ── header ──────────────────────────────────────────────────────────────
    RowLayout {
      Layout.fillWidth: true
      spacing: metric.space(14)
      ColumnLayout {
        spacing: 0
        Text {
          text: "B L A C K - B A G"
          color: Util.alpha(Color.foreground, 0.85)
          font.family: metric.font.family
          font.pixelSize: metric.font.heading
          font.bold: true
          font.letterSpacing: metric.spaceReal(1)
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
        Text {
          text: "VAULT MANAGEMENT"
          color: Util.alpha(Color.foreground, 0.45)
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
          font.letterSpacing: metric.spaceReal(1.2)
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
      }
      Item { Layout.fillWidth: true }
      Text {
        visible: manage.busy
        text: "working…"
        color: Util.alpha(Color.accent, 0.8)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        renderType: Text.NativeRendering
      }
      SheetButton {
        label: "✕"
        tone: Util.alpha(Color.foreground, 0.6)
        tappable: !manage.busy
        onActivated: manage.dismiss()
      }
    }

    Rectangle {
      Layout.fillWidth: true
      height: Math.max(1, metric.spacing.hairline)
      color: Util.alpha(Color.muted, 0.5)
    }

    // ── nav + panel ─────────────────────────────────────────────────────────
    RowLayout {
      Layout.fillWidth: true
      Layout.fillHeight: true
      spacing: metric.space(22)

      ColumnLayout {
        // A nested layout defaults to Layout.fillWidth TRUE in Qt, so a bare
        // preferredWidth is only a hint and the nav ate the whole row, leaving
        // the panel a few pixels at the right edge. The nav is a fixed rail:
        // pin all three so it cannot negotiate.
        Layout.fillWidth: false
        Layout.preferredWidth: metric.space(210)
        Layout.minimumWidth: metric.space(210)
        Layout.maximumWidth: metric.space(210)
        Layout.alignment: Qt.AlignTop
        spacing: metric.space(2)
        Repeater {
          model: manage.sections
          delegate: Rectangle {
            required property var modelData
            required property int index
            Layout.fillWidth: true
            implicitHeight: navCol.implicitHeight + metric.space(14)
            radius: metric.cornerRadius
            readonly property bool current: manage.section === modelData.key
            color: current ? Util.alpha(Color.accent, 0.12)
                 : (navHover.hovered ? Util.alpha(Color.foreground, 0.06) : "transparent")
            Rectangle {
              visible: parent.current
              anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
              width: metric.space(3)
              radius: width / 2
              color: Color.accent
            }
            ColumnLayout {
              id: navCol
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: metric.space(14)
              anchors.rightMargin: metric.space(26)
              spacing: 0
              Text {
                text: modelData.label
                color: parent.parent.current ? Color.accent : Util.alpha(Color.foreground, 0.75)
                font.family: metric.font.family
                font.pixelSize: metric.font.caption
                font.bold: true
                font.letterSpacing: metric.spaceReal(0.6)
                textFormat: Text.PlainText
                renderType: Text.NativeRendering
              }
              Text {
                Layout.fillWidth: true
                text: modelData.hint
                color: Util.alpha(Color.foreground, 0.4)
                font.family: metric.font.family
                font.pixelSize: metric.font.caption
                elide: Text.ElideRight
                textFormat: Text.PlainText
                renderType: Text.NativeRendering
              }
            }
            // The accelerator, drawn where the eye already is. A shortcut
            // nobody can discover is a shortcut nobody uses.
            Text {
              anchors.right: parent.right
              anchors.rightMargin: metric.space(10)
              anchors.verticalCenter: parent.verticalCenter
              text: "^" + (parent.index + 1)
              color: Util.alpha(Color.foreground, parent.current ? 0.55 : 0.25)
              font.family: metric.font.family
              font.pixelSize: metric.font.caption
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
            }
            HoverHandler { id: navHover; cursorShape: Qt.PointingHandCursor }
            TapHandler { onTapped: manage.go(modelData.key) }
            Accessible.role: Accessible.Button
            Accessible.name: modelData.label + ", " + modelData.hint
                             + ", control " + (index + 1)
          }
        }
      }

      Rectangle {
        Layout.preferredWidth: Math.max(1, metric.spacing.hairline)
        Layout.fillHeight: true
        color: Util.alpha(Color.muted, 0.35)
      }

      Flickable {
        Layout.fillWidth: true
        Layout.fillHeight: true
        clip: true
        contentHeight: panel.implicitHeight
        boundsBehavior: Flickable.StopAtBounds
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        ColumnLayout {
          id: panel
          width: parent.width - metric.space(12)
          spacing: metric.space(12)

          // ── PASSPHRASE ────────────────────────────────────────────────────
          ColumnLayout {
            Layout.fillWidth: true
            spacing: metric.space(10)
            visible: manage.section === "passphrase"

            Blurb {
              text: "Changing the passphrase mints a fresh data key, re-encrypts every "
                  + "record under it and re-wraps every recipient. Your recovery keys keep "
                  + "working. The old passphrase stops working, which cannot be undone."
            }

            KdfCard { }

            Field { id: currentField; label: "current master passphrase"; secret: true
                    onTextEdited: manage.currentPass = text }
            Field { id: newField; label: "new master passphrase"; secret: true
                    onTextEdited: manage.newPass = text }
            Field { id: confirmField; label: "again, to be sure"; secret: true
                    onTextEdited: manage.confirmPass = text }

            RowLayout {
              Layout.fillWidth: true
              spacing: metric.space(10)
              Text {
                text: manage.showPass ? "hide" : "show"
                color: Util.alpha(Color.accent, showHover.hovered ? 1.0 : 0.6)
                font.family: metric.font.family
                font.pixelSize: metric.font.caption
                renderType: Text.NativeRendering
                HoverHandler { id: showHover; cursorShape: Qt.PointingHandCursor }
                TapHandler { onTapped: manage.showPass = !manage.showPass }
              }
              Item { Layout.fillWidth: true }
              SheetButton {
                label: "RAISE WORK FACTOR"
                tone: Util.alpha(Color.foreground, 0.7)
                enabledAction: !manage.busy && !Model.kdfMeetsDefault(manage.status)
                tappable: !manage.busy
                onActivated: manage.raiseKdf()
              }
              SheetButton {
                label: "CHANGE PASSPHRASE"
                tone: Color.accent
                enabledAction: !manage.busy
                tappable: !manage.busy
                onActivated: manage.changePassphrase()
              }
            }
          }

          // ── RECOVERY KEYS ─────────────────────────────────────────────────
          ColumnLayout {
            Layout.fillWidth: true
            spacing: metric.space(10)
            visible: manage.section === "keys"

            Blurb {
              text: "A recovery key is a file that opens this vault WITHOUT the passphrase — "
                  + "a hybrid X25519 + ML-KEM-1024 recipient whose private half lives in the "
                  + "file and never in the vault. It is the only way back from a forgotten "
                  + "passphrase, and it cannot be added to a vault you can no longer open."
            }

            SectionLabel { text: "RECIPIENTS — " + manage.recipients.length }

            Repeater {
              model: manage.recipients
              delegate: Rectangle {
                required property var modelData
                Layout.fillWidth: true
                implicitHeight: recipCol.implicitHeight + metric.space(16)
                radius: metric.cornerRadius
                color: Util.alpha(Color.foreground, 0.04)
                border.width: Math.max(1, metric.spacing.hairline)
                border.color: manage.revokeArmed === modelData.label
                  ? Util.alpha(Color.urgent, 0.6) : Util.alpha(Color.muted, 0.4)
                RowLayout {
                  id: recipCol
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  anchors.margins: metric.space(12)
                  spacing: metric.space(10)
                  ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 0
                    Text {
                      text: modelData.label
                      color: Color.foreground
                      font.family: metric.font.family
                      font.pixelSize: metric.font.caption
                      font.bold: true
                      textFormat: Text.PlainText
                      renderType: Text.NativeRendering
                    }
                    Text {
                      Layout.fillWidth: true
                      text: modelData.note
                      color: Util.alpha(Color.foreground, 0.5)
                      font.family: metric.font.family
                      font.pixelSize: metric.font.caption
                      wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                      textFormat: Text.PlainText
                      renderType: Text.NativeRendering
                    }
                  }
                  Text {
                    text: modelData.external ? "OFFLINE KEY" : "PASSPHRASE"
                    color: modelData.external ? Color.accent : Util.alpha(Color.foreground, 0.5)
                    font.family: metric.font.family
                    font.pixelSize: metric.font.caption
                    renderType: Text.NativeRendering
                  }
                  SheetButton {
                    visible: modelData.external
                    label: manage.revokeArmed === modelData.label ? "SURE?" : "REVOKE"
                    tone: Color.urgent
                    tappable: !manage.busy
                    onActivated: manage.revokeRecoveryKey(modelData.label)
                  }
                }
              }
            }

            Text {
              Layout.fillWidth: true
              visible: manage.revokeArmed.length > 0
              text: "revoking \"" + manage.revokeArmed + "\" means that key file can never open this "
                  + "vault again · press REVOKE once more to confirm · esc backs out"
              color: Color.urgent
              font.family: metric.font.family
              font.pixelSize: metric.font.caption
              wrapMode: Text.WrapAtWordBoundaryOrAnywhere
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
            }

            SectionLabel { text: "MINT A NEW ONE" }
            Field { label: "label"; value: manage.keyLabel; onTextEdited: manage.keyLabel = text }
            Field { label: "write the key file to"; value: manage.keyPath
                    onTextEdited: manage.keyPath = text }
            Blurb {
              text: "Put it on removable media. In your home directory it is a second full key "
                  + "to the vault, sitting next to the vault."
              tone: Util.alpha(Color.foreground, 0.5)
            }
            PassphraseGate { why: "minting a recovery key changes who can open this vault" }
            RowLayout {
              Layout.fillWidth: true
              Item { Layout.fillWidth: true }
              SheetButton {
                label: "MINT THE KEY"
                tone: Color.accent
                enabledAction: !manage.busy
                tappable: !manage.busy
                onActivated: manage.addRecoveryKey()
              }
            }
          }

          // ── IMPORT ────────────────────────────────────────────────────────
          ColumnLayout {
            Layout.fillWidth: true
            spacing: metric.space(10)
            visible: manage.section === "import"

            Blurb {
              text: "Read an export from another manager. Nothing is written until you have "
                  + "seen what parsed: PREVIEW parses the file and reports what it found and "
                  + "what it skipped, without opening the vault at all."
            }

            SectionLabel { text: "FORMAT" }
            Chooser {
              options: Model.IMPORT_FORMATS
              current: manage.importFormat
              onChose: function (v) { manage.importFormat = v; manage.importPreview = "" }
            }
            Field { label: "file"; value: manage.importPath
                    onTextEdited: { manage.importPath = text; manage.importPreview = "" } }

            Rectangle {
              Layout.fillWidth: true
              visible: manage.importPreview.length > 0
              implicitHeight: previewText.implicitHeight + metric.space(20)
              radius: metric.cornerRadius
              color: Util.alpha(Color.accent, 0.06)
              border.width: Math.max(1, metric.spacing.hairline)
              border.color: Util.alpha(Color.accent, 0.3)
              Text {
                id: previewText
                anchors.fill: parent
                anchors.margins: metric.space(10)
                text: manage.importPreview
                color: Util.alpha(Color.foreground, 0.8)
                font.family: metric.font.family
                font.pixelSize: metric.font.caption
                wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                textFormat: Text.PlainText
                renderType: Text.NativeRendering
              }
            }

            RowLayout {
              Layout.fillWidth: true
              spacing: metric.space(10)
              Item { Layout.fillWidth: true }
              SheetButton {
                label: "PREVIEW"
                tone: Util.alpha(Color.foreground, 0.7)
                enabledAction: !manage.busy
                tappable: !manage.busy
                onActivated: manage.previewImport()
              }
              SheetButton {
                label: "IMPORT"
                tone: Color.accent
                enabledAction: !manage.busy && manage.importPreview.length > 0
                tappable: !manage.busy
                onActivated: manage.runImport()
              }
            }
            Blurb {
              text: "The export file still holds every secret in plaintext afterwards. Delete it."
              tone: Util.alpha(Color.urgent, 0.8)
            }
          }

          // ── EXPORT ────────────────────────────────────────────────────────
          ColumnLayout {
            Layout.fillWidth: true
            spacing: metric.space(10)
            visible: manage.section === "export"

            Blurb {
              text: "An export is every record and every secret, in the clear, in one file. "
                  + "It is how you leave, and how you take a backup you can restore — the "
                  + "JSON form imports back whole. Treat the file exactly as you would the "
                  + "vault plus the passphrase together."
              tone: Util.alpha(Color.urgent, 0.85)
            }

            SectionLabel { text: "FORMAT" }
            Chooser {
              options: Model.EXPORT_FORMATS
              current: manage.exportFormat
              onChose: function (v) { manage.exportFormat = v }
            }
            Field { label: "write to"; value: manage.exportPath
                    onTextEdited: manage.exportPath = text }
            PassphraseGate {
              why: "there is deliberately no way to read the whole vault over the agent socket, "
                 + "so an export asks for the passphrase even while the deck is unlocked"
            }
            RowLayout {
              Layout.fillWidth: true
              Item { Layout.fillWidth: true }
              SheetButton {
                label: manage.exportArmed ? "SURE? WRITE PLAINTEXT" : "EXPORT"
                tone: manage.exportArmed ? Color.urgent : Color.accent
                enabledAction: !manage.busy
                tappable: !manage.busy
                onActivated: manage.runExport()
              }
            }
          }

          // ── GENERATE ──────────────────────────────────────────────────────
          ColumnLayout {
            Layout.fillWidth: true
            spacing: metric.space(10)
            visible: manage.section === "generate"

            Blurb {
              text: "The entropy figure describes the generator, never a typed value. It is "
                  + "log2(choices^length) for exactly what was drawn, and there is deliberately "
                  + "no function anywhere that scores a password you thought of."
            }

            SectionLabel { text: "KIND" }
            Chooser {
              options: Model.GEN_KINDS
              current: manage.genKind
              onChose: function (v) { manage.genKind = v; manage.generated = ""; manage.generatedNote = "" }
            }

            Stepper {
              visible: manage.genKind === "password"
              label: "length"; value: manage.genLength; from: 8; to: 128; step: 4
              onChanged_: function (v) { manage.genLength = v }
            }
            Stepper {
              visible: manage.genKind === "passphrase"
              label: "words"; value: manage.genWords; from: 4; to: 16; step: 1
              onChanged_: function (v) { manage.genWords = v }
            }
            Stepper {
              visible: manage.genKind === "pin"
              label: "digits"; value: manage.genDigits; from: 4; to: 12; step: 1
              onChanged_: function (v) { manage.genDigits = v }
            }
            Toggle {
              visible: manage.genKind === "password"
              label: "symbols"; on_: manage.genSymbols
              onToggled_: manage.genSymbols = !manage.genSymbols
            }
            Toggle {
              visible: manage.genKind === "password"
              label: "avoid look-alike characters"; on_: manage.genAmbiguous
              onToggled_: manage.genAmbiguous = !manage.genAmbiguous
            }

            Rectangle {
              Layout.fillWidth: true
              visible: manage.generated.length > 0
              implicitHeight: genCol.implicitHeight + metric.space(22)
              radius: metric.cornerRadius
              color: Util.alpha(Color.accent, 0.07)
              border.width: Math.max(1, metric.spacing.hairline)
              border.color: Util.alpha(Color.accent, 0.35)
              ColumnLayout {
                id: genCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.margins: metric.space(12)
                spacing: metric.space(6)
                TextEdit {
                  Layout.fillWidth: true
                  text: manage.generated
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
                  visible: manage.generatedNote.length > 0
                  text: manage.generatedNote
                  color: Util.alpha(Color.foreground, 0.55)
                  font.family: metric.font.family
                  font.pixelSize: metric.font.caption
                  wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                  textFormat: Text.PlainText
                  renderType: Text.NativeRendering
                }
              }
            }

            RowLayout {
              Layout.fillWidth: true
              spacing: metric.space(10)
              Item { Layout.fillWidth: true }
              SheetButton {
                label: "COPY A FRESH ONE"
                tone: Util.alpha(Color.foreground, 0.7)
                enabledAction: !manage.busy
                tappable: !manage.busy
                onActivated: manage.copyGenerated()
              }
              SheetButton {
                label: "GENERATE"
                tone: Color.accent
                enabledAction: !manage.busy
                tappable: !manage.busy
                onActivated: manage.generate()
              }
            }
            Blurb {
              text: "COPY draws a NEW value straight to the clipboard rather than copying the "
                  + "one on screen, so a value you only glanced at is never the one you paste."
              tone: Util.alpha(Color.foreground, 0.5)
            }
          }

          // ── SETTINGS ──────────────────────────────────────────────────────
          ColumnLayout {
            Layout.fillWidth: true
            spacing: metric.space(10)
            visible: manage.section === "settings"

            Blurb {
              text: "These are clamped by the deck, so a value here cannot leave a secret on "
                  + "screen forever or set a clipboard that never clears."
            }

            Repeater {
              model: Model.SETTING_ROWS
              delegate: Stepper {
                required property var modelData
                label: modelData.label
                sub: modelData.hint
                value: Model.settingOf(manage.settings, modelData.key, modelData.fallback)
                from: modelData.from
                to: modelData.to
                step: modelData.step
                onChanged_: function (v) { manage.settingChanged(modelData.key, v) }
              }
            }
            Toggle {
              label: "cockpit motion"
              sub: "fades and countdown sweeps; off makes every change snap"
              on_: Model.settingOf(manage.settings, "motionEnabled", true) === true
              onToggled_: manage.settingChanged("motionEnabled",
                            !(Model.settingOf(manage.settings, "motionEnabled", true) === true))
            }
          }
        }
      }
    }

    // ── footer ──────────────────────────────────────────────────────────────
    Rectangle {
      Layout.fillWidth: true
      height: Math.max(1, metric.spacing.hairline)
      color: Util.alpha(Color.muted, 0.5)
    }
    RowLayout {
      Layout.fillWidth: true
      spacing: metric.space(12)
      Text {
        Layout.fillWidth: true
        visible: manage.errorText.length > 0
        text: manage.errorText
        color: Color.urgent
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
      Text {
        Layout.fillWidth: true
        visible: manage.errorText.length === 0 && manage.noteText.length > 0
        text: manage.noteText
        color: Util.alpha(Color.accent, 0.85)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
      Item { Layout.fillWidth: manage.errorText.length === 0 && manage.noteText.length === 0 }
      Text {
        text: "^1-^6 section  ·  ^\u2191\u2193 move"
             + (manage.primaryLabel.length > 0
                ? "  ·  ^\u23ce " + manage.primaryLabel : "")
             + "  ·  esc close"
        color: Util.alpha(Color.foreground, 0.4)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
    }
  }

  // ── parts ──────────────────────────────────────────────────────────────────

  component Blurb: Text {
    property color tone: Util.alpha(Color.foreground, 0.6)
    Layout.fillWidth: true
    color: tone
    font.family: manage.metric.font.family
    font.pixelSize: manage.metric.font.caption
    wrapMode: Text.WrapAtWordBoundaryOrAnywhere
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
  }

  component SectionLabel: Text {
    Layout.fillWidth: true
    Layout.topMargin: manage.metric.space(6)
    color: Util.alpha(Color.foreground, 0.45)
    font.family: manage.metric.font.family
    font.pixelSize: manage.metric.font.caption
    font.bold: true
    font.letterSpacing: manage.metric.spaceReal(0.8)
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
  }

  /// The current Argon2 figures, and whether they meet what this build would
  /// choose today — the finding the deck used to report with no way to act.
  component KdfCard: Rectangle {
    Layout.fillWidth: true
    implicitHeight: kdfCol.implicitHeight + manage.metric.space(20)
    radius: manage.metric.cornerRadius
    color: Util.alpha(Color.foreground, 0.04)
    border.width: Math.max(1, manage.metric.spacing.hairline)
    border.color: Model.kdfMeetsDefault(manage.status)
      ? Util.alpha(Color.accent, 0.3) : Util.alpha(Color.urgent, 0.4)
    ColumnLayout {
      id: kdfCol
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.margins: manage.metric.space(12)
      spacing: 0
      Text {
        text: Model.fmtKdf(manage.status ? manage.status.kdf : null)
        color: Color.foreground
        font.family: manage.metric.font.family
        font.pixelSize: manage.metric.font.caption
        font.bold: true
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
      Text {
        Layout.fillWidth: true
        text: Model.kdfMeetsDefault(manage.status)
          ? "meets what this build would choose today"
          : "below what this build would choose today — RAISE WORK FACTOR re-keys at the current default"
        color: Model.kdfMeetsDefault(manage.status)
          ? Util.alpha(Color.accent, 0.8) : Util.alpha(Color.urgent, 0.85)
        font.family: manage.metric.font.family
        font.pixelSize: manage.metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
    }
  }

  /// A labelled input. `secret` masks it and follows the sheet's show toggle.
  component Field: ColumnLayout {
    property string label: ""
    property bool secret: false
    property alias value: input.text
    signal textEdited(string text)
    Layout.fillWidth: true
    spacing: manage.metric.space(3)
    function setText(v) { input.text = v }
    property alias text: input.text
    Text {
      text: parent.label
      color: Util.alpha(Color.foreground, 0.5)
      font.family: manage.metric.font.family
      font.pixelSize: manage.metric.font.caption
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
    }
    TextField {
      id: input
      Layout.fillWidth: true
      enabled: !manage.busy
      password: parent.secret && !manage.showPass
      font.pixelSize: manage.metric.font.body
      topPadding: manage.metric.spacing.inputPaddingY
      bottomPadding: manage.metric.spacing.inputPaddingY
      leftPadding: manage.metric.spacing.controlPaddingX
      rightPadding: manage.metric.spacing.controlPaddingX
      onTextChanged: parent.textEdited(text)
    }
  }

  /// Says why a passphrase is being asked for, and takes it.
  component PassphraseGate: ColumnLayout {
    property string why: ""
    Layout.fillWidth: true
    spacing: manage.metric.space(3)
    Text {
      Layout.fillWidth: true
      text: "master passphrase — " + parent.why
      color: Util.alpha(Color.foreground, 0.5)
      font.family: manage.metric.font.family
      font.pixelSize: manage.metric.font.caption
      wrapMode: Text.WrapAtWordBoundaryOrAnywhere
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
    }
    TextField {
      Layout.fillWidth: true
      enabled: !manage.busy
      password: !manage.showPass
      font.pixelSize: manage.metric.font.body
      topPadding: manage.metric.spacing.inputPaddingY
      bottomPadding: manage.metric.spacing.inputPaddingY
      leftPadding: manage.metric.spacing.controlPaddingX
      rightPadding: manage.metric.spacing.controlPaddingX
      onTextChanged: manage.currentPass = text
    }
  }

  /// A row of mutually exclusive choices.
  component Chooser: Flow {
    id: chooser
    property var options: []
    property string current: ""
    signal chose(string value)
    Layout.fillWidth: true
    spacing: manage.metric.space(6)

    // One tab stop for the whole group, then arrows move within it — the way
    // a radio group is supposed to behave. Tabbing through six format chips
    // to reach the file field would be its own small punishment.
    activeFocusOnTab: true
    Keys.onPressed: function (event) {
      var n = chooser.options.length
      if (n === 0) return
      var i = 0
      for (var k = 0; k < n; k++)
        if (chooser.options[k].key === chooser.current) { i = k; break }
      var delta = 0
      if (event.key === Qt.Key_Right || event.key === Qt.Key_Down) delta = 1
      else if (event.key === Qt.Key_Left || event.key === Qt.Key_Up) delta = -1
      else return
      chooser.chose(chooser.options[(i + delta + n) % n].key)
      event.accepted = true
    }

    Repeater {
      model: parent.options
      delegate: Rectangle {
        required property var modelData
        // A Repeater parents its delegates to the Flow itself, so `parent` IS
        // the chooser. The old parent.parent reached past it: no chip ever drew
        // as selected, and chooserRoot came back undefined, so tapping a chip did
        // precisely nothing.
        readonly property bool active: chooser.current === modelData.key
        implicitWidth: chipText.implicitWidth + manage.metric.space(22)
        implicitHeight: manage.metric.spacing.controlHeight
        radius: manage.metric.cornerRadius
        color: active ? Util.alpha(Color.accent, 0.16)
             : (chipHover.hovered ? Util.alpha(Color.foreground, 0.1)
                                  : Util.alpha(Color.foreground, 0.05))
        border.width: Math.max(1, manage.metric.spacing.hairline)
                    * (active && chooser.activeFocus ? 2 : 1)
        border.color: active
          ? (chooser.activeFocus ? Color.accent : Util.alpha(Color.accent, 0.7))
          : Util.alpha(Color.muted, 0.4)
        Text {
          id: chipText
          anchors.centerIn: parent
          text: modelData.label
          color: parent.active ? Color.accent : Util.alpha(Color.foreground, 0.8)
          font.family: manage.metric.font.family
          font.pixelSize: manage.metric.font.caption
          font.bold: parent.active
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
        HoverHandler { id: chipHover; cursorShape: Qt.PointingHandCursor }
        TapHandler { onTapped: chooser.chose(modelData.key) }
        Accessible.role: Accessible.RadioButton
        Accessible.name: modelData.label
      }
    }
  }

  /// A number with two buttons. No free text, so a setting cannot be typed
  /// out of its range in the first place.
  component Stepper: RowLayout {
    property string label: ""
    property string sub: ""
    property int value: 0
    property int from: 0
    property int to: 100
    property int step: 1
    signal changed_(int v)
    Layout.fillWidth: true
    spacing: manage.metric.space(10)
    ColumnLayout {
      Layout.fillWidth: true
      spacing: 0
      Text {
        text: parent.parent.label
        color: Util.alpha(Color.foreground, 0.75)
        font.family: manage.metric.font.family
        font.pixelSize: manage.metric.font.caption
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
      Text {
        Layout.fillWidth: true
        visible: text.length > 0
        text: parent.parent.sub
        color: Util.alpha(Color.foreground, 0.45)
        font.family: manage.metric.font.family
        font.pixelSize: manage.metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
    }
    SheetButton {
      label: "−"
      tone: Util.alpha(Color.foreground, 0.7)
      enabledAction: stepRoot.value > stepRoot.from
      onActivated: stepRoot.changed_(Math.max(stepRoot.from, stepRoot.value - stepRoot.step))
    }
    Text {
      text: String(stepRoot.value)
      color: Color.foreground
      font.family: manage.metric.font.family
      font.pixelSize: manage.metric.font.body
      font.bold: true
      horizontalAlignment: Text.AlignHCenter
      Layout.preferredWidth: manage.metric.space(46)
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
    }
    SheetButton {
      label: "+"
      tone: Util.alpha(Color.foreground, 0.7)
      enabledAction: stepRoot.value < stepRoot.to
      onActivated: stepRoot.changed_(Math.min(stepRoot.to, stepRoot.value + stepRoot.step))
    }
    readonly property var stepRoot: this
  }

  component Toggle: RowLayout {
    property string label: ""
    property string sub: ""
    property bool on_: false
    signal toggled_()
    Layout.fillWidth: true
    spacing: manage.metric.space(10)
    ColumnLayout {
      Layout.fillWidth: true
      spacing: 0
      Text {
        text: parent.parent.label
        color: Util.alpha(Color.foreground, 0.75)
        font.family: manage.metric.font.family
        font.pixelSize: manage.metric.font.caption
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
      Text {
        Layout.fillWidth: true
        visible: text.length > 0
        text: parent.parent.sub
        color: Util.alpha(Color.foreground, 0.45)
        font.family: manage.metric.font.family
        font.pixelSize: manage.metric.font.caption
        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }
    }
    SheetButton {
      label: toggleRoot.on_ ? "ON" : "OFF"
      tone: toggleRoot.on_ ? Color.accent : Util.alpha(Color.foreground, 0.5)
      onActivated: toggleRoot.toggled_()
    }
    readonly property var toggleRoot: this
  }

  component SheetButton: Rectangle {
    id: btn
    property string label: ""
    property bool enabledAction: true
    property bool tappable: enabledAction
    property color tone: Color.foreground
    signal activated()

    implicitWidth: btnText.implicitWidth + manage.metric.space(22)
    implicitHeight: manage.metric.spacing.controlHeight
    radius: manage.metric.cornerRadius
    // Tab reaches it, Space and Return press it, and the focus ring says
    // where you are. A deck that is driven from the keyboard everywhere else
    // must not become mouse-only the moment you open its settings.
    activeFocusOnTab: btn.tappable
    color: btn.enabledAction && (btnHover.hovered || btn.activeFocus)
      ? Util.alpha(btn.tone, 0.2) : Util.alpha(btn.tone, 0.09)
    border.color: btn.activeFocus ? btn.tone
                                  : Util.alpha(btn.tone, btn.enabledAction ? 0.5 : 0.15)
    border.width: Math.max(1, manage.metric.spacing.hairline) * (btn.activeFocus ? 2 : 1)
    Keys.onPressed: function (event) {
      if (!btn.tappable) return
      if (event.key === Qt.Key_Space || event.key === Qt.Key_Return
          || event.key === Qt.Key_Enter) {
        btn.activated()
        event.accepted = true
      }
    }

    Text {
      id: btnText
      anchors.centerIn: parent
      text: btn.label
      color: Util.alpha(btn.tone, btn.enabledAction ? 1.0 : 0.35)
      font.family: manage.metric.font.family
      font.pixelSize: manage.metric.font.caption
      font.bold: true
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
    }
    HoverHandler { id: btnHover; enabled: btn.tappable; cursorShape: Qt.PointingHandCursor }
    TapHandler { enabled: btn.tappable; onTapped: btn.activated() }
    Accessible.role: Accessible.Button
    Accessible.name: btn.label
  }
}
