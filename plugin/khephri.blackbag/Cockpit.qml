// BLACK-BAG — credential command deck.
//
// Full-screen cockpit over the live vault. Three rules shape everything here:
//
//   1. This file never stores a secret. Record metadata (titles, usernames,
//      tags, secret-field *handles*) comes from the agent; secret bytes are
//      fetched only on an explicit COPY or SHOW, and SHOW clears itself on a
//      visible countdown.
//   2. The passphrase goes to the agent on stdin. Never in an argument vector —
//      /proc/<pid>/cmdline is world-readable.
//   3. Unknown is drawn as UNKNOWN. A stale status desaturates rather than
//      asserting a posture it cannot vouch for.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Ui
import "Model.js" as Model

Item {
  id: root

  property var shell: ({})
  property var manifest: ({})
  property bool opened: false

  // ── live state ─────────────────────────────────────────────────────────────
  property var status: null
  property var records: []
  property int selectedIndex: 0
  property string filterKind: ""
  property string searchText: ""
  property real nowMs: Date.now()

  property string passphrase: ""
  property string actionError: ""
  property string actionNote: ""
  property bool unlocking: false
  property bool listing: false

  // The only place a secret can live in this file, and only while the
  // countdown runs.
  property string revealedValue: ""
  property string revealedField: ""
  property string revealedFor: ""
  property int revealSecondsLeft: 0

  property var totpState: null   // { id, code, ttl, step, at }

  // Hygiene carries per-field handles and record titles, so it is as sensitive
  // as the record list itself: it comes over the agent socket, lives only in
  // this process, and never touches status.json.
  property var hygiene: null

  // Which record each in-flight request was issued FOR. Without these, moving
  // the selection while a reply is in flight lands one record's secret — or
  // one record's 2FA code — under a different record's name.
  // A pending delete, held until it is confirmed a second time. Deleting a
  // credential is not undoable and there is no trash.
  property string pendingDeleteId: ""

  // First run offers to create a vault, once per visit. Set when the sheet is
  // dismissed AND when it completes: the status file is republished
  // asynchronously, so for a moment after a vault is created the deck still
  // holds a status saying there is none, and without this the sheet reopens on
  // top of the vault it has just finished making.
  property bool onboardSuppressed: false

  property string totpPendingId: ""
  property string showPendingId: ""
  property string showPendingField: ""

  readonly property string runtimeDir: Quickshell.env("XDG_RUNTIME_DIR") || "/tmp"
  readonly property string homeDir: Quickshell.env("HOME") || ""
  readonly property string statusPath: runtimeDir + "/black-bag/status.json"

  // The shell does not inject `settings` into overlays, and `serviceFor()` does
  // not reach our own service from here either — the overlay observes
  // `service === null`. `shell.shellConfig` is what is actually reachable, so
  // the manifest schema is resolved off that. See Model.resolvePluginSettings.
  readonly property var settings:
    Model.resolvePluginSettings(shell ? shell.shellConfig : null,
                                manifest, "khephri.blackbag")

  function setting(name, fallback) {
    return Model.settingOf(root.settings, name, fallback)
  }

  readonly property bool motionEnabled: setting("motionEnabled", true) === true
  readonly property int motionMs: motionEnabled ? 160 : 0
  readonly property int clipboardClearSec: setting("clipboardClearSec", 30)
  readonly property int revealSeconds: setting("revealSeconds", 10)
  readonly property int staleAfterSec: setting("staleAfterSec", 120)

  readonly property bool stale: Model.isStale(root.status, root.nowMs, root.staleAfterSec)
  readonly property string deckState: Model.deckState(root.status, root.nowMs, root.staleAfterSec)
  readonly property bool unlocked: root.deckState === "UNLOCKED"
  readonly property var visibleRecords:
    Model.sortRecords(Model.filterRecords(root.records, root.filterKind, root.searchText))
  // Never render a code under a record it was not fetched for.
  readonly property var liveTotp:
    (root.totpState && root.selectedRecord
     && String(root.totpState.id) === String(root.selectedRecord.id))
      ? root.totpState : null

  readonly property var selectedRecord:
    visibleRecords.length > 0
      ? visibleRecords[Math.max(0, Math.min(selectedIndex, visibleRecords.length - 1))]
      : null

  // ── lifecycle ──────────────────────────────────────────────────────────────

  function open(payloadJson) {
    var payload = {}
    try {
      payload = typeof payloadJson === "string"
        ? JSON.parse(payloadJson || "{}") : (payloadJson || {})
    } catch (e) { payload = {} }

    root.opened = true
    root.actionError = ""
    root.actionNote = ""
    root.onboardSuppressed = false
    if (payload.kind) root.filterKind = String(payload.kind)

    statusFile.reload()
    root.applyStatus(statusFile.text())
    refreshProcess.running = true
    if (root.unlocked) root.refreshRecords()

    Qt.callLater(function () {
      keyCatcher.forceActiveFocus()
      if (!root.unlocked) passField.forceActiveFocus()
    })
  }

  // Host-initiated end of dismissal. Must not call back into shell.hide().
  function close() {
    root.opened = false
    root.clearSecrets()
  }

  // User-initiated. Routes out through the host so its bookkeeping stays right.
  function dismiss() {
    root.clearSecrets()
    if (shell && typeof shell.hide === "function") shell.hide("khephri.blackbag")
    else root.close()
  }

  // Everything sensitive this file can be holding, dropped at once.
  function clearSecrets() {
    root.passphrase = ""
    root.revealedValue = ""
    root.revealedField = ""
    root.revealedFor = ""
    root.revealSecondsLeft = 0
    root.totpState = null
    passField.text = ""
  }

  // There being no vault is a first run, not an error. The deck creates one
  // rather than telling anyone to go and find a terminal.
  function maybeOnboard() {
    if (!root.opened || root.onboardSuppressed) return
    if (onboardSheet.open_ || recordEditor.open_) return
    if (!root.status || root.status.vault_present === true) return
    if (root.status.error) return   // unreadable is a hazard, not an empty slot
    onboardSheet.homeDir = root.homeDir
    onboardSheet.begin()
  }

  function applyStatus(raw) {
    try {
      var parsed = JSON.parse(String(raw || ""))
      if (parsed.schema_version !== 1) return
      var wasUnlocked = root.unlocked
      root.status = parsed
      Qt.callLater(root.maybeOnboard)
      var nowUnlocked = !!(parsed.session && parsed.session.unlocked)
      if (nowUnlocked && !wasUnlocked) root.refreshRecords()
      if (!nowUnlocked && wasUnlocked) {
        root.records = []
        root.hygiene = null
        root.clearSecrets()
      }
    } catch (e) {
      // Partial read during the atomic replace; keep the last good document.
    }
  }

  function refreshRecords() {
    if (listProcess.running) return
    root.listing = true
    listProcess.running = true
    if (!hygieneProcess.running) hygieneProcess.running = true
  }

  function issuesFor(id) {
    if (!root.hygiene || !root.hygiene.records) return []
    var list = Model.asList(root.hygiene.records)
    for (var i = 0; i < list.length; i++)
      if (String(list[i].id) === String(id)) return Model.asList(list[i].issues)
    return []
  }

  // ── actions ────────────────────────────────────────────────────────────────

  // The unlock itself. The caller has already established that there is a vault
  // to unlock — or has just created one, which is the case the split exists
  // for: status.json is republished asynchronously, so for a moment after
  // creation the deck is still holding a status that says there is no vault,
  // and routing that through doUnlock() would re-offer to create the vault
  // that was just made.
  function beginUnlock() {
    if (root.unlocking) return
    if (root.passphrase.length === 0) {
      root.actionError = "passphrase required"
      return
    }
    root.actionError = ""
    root.unlocking = true
    unlockProcess.running = true
  }

  function doUnlock() {
    // Nothing to unlock yet: Enter on an empty slot is the offer to create one.
    if (root.status && root.status.vault_present !== true && !root.status.error) {
      root.onboardSuppressed = false
      root.maybeOnboard()
      return
    }
    root.beginUnlock()
  }

  // Esc does the smallest useful thing first, so it is never a dead key and
  // never throws away more than the user meant.
  function backOut() {
    if (root.revealedValue.length > 0) { root.clearReveal(); return }
    if (root.pendingDeleteId.length > 0) { root.pendingDeleteId = ""; return }
    if (root.unlocked && searchField.activeFocus && searchField.text.length > 0) {
      searchField.text = ""
      return
    }
    root.dismiss()
  }

  function doLock() {
    root.clearSecrets()
    lockProcess.running = true
    root.actionNote = "locking…"
  }

  function primaryField(record) {
    if (!record || !Array.isArray(record.secret_fields) || record.secret_fields.length === 0)
      return ""
    var preferred = ["password", "secret_key", "private_key", "passphrase",
                     "account_number", "seed", "body", "totp", "number", "payload"]
    for (var p = 0; p < preferred.length; p++)
      for (var i = 0; i < record.secret_fields.length; i++)
        if (record.secret_fields[i].name === preferred[p]) return preferred[p]
    return record.secret_fields[0].name
  }

  function copyField(record, field) {
    if (!record || !field) return
    root.actionError = ""

    // A `totp` field holds the raw shared secret, which is binary — copying it
    // through `reveal` fails to decode as UTF-8, and would be the wrong thing
    // to put on the clipboard anyway. What the user wants is the current code.
    var isTotp = String(field) === "totp"
    copyProcess.command = isTotp
      ? ["black-bag", "agent", "totp", String(record.id),
         "--to", "clipboard", "--clear-after", String(root.clipboardClearSec)]
      : ["black-bag", "agent", "reveal", String(record.id), String(field),
         "--to", "clipboard", "--clear-after", String(root.clipboardClearSec)]
    copyProcess.running = true
    root.actionNote = "copied " + (isTotp ? "current code" : field)
                    + " · clipboard clears in " + root.clipboardClearSec + "s"
  }

  function showField(record, field) {
    if (!record || !field) return
    if (String(field) === "totp") {
      // The live code is already on screen in the TOTP card; the stored secret
      // is binary and there is nothing useful to show.
      root.actionError = "the current code is shown above; the stored secret is binary"
      return
    }
    root.actionError = ""
    root.clearReveal()
    root.showPendingId = String(record.id)
    root.showPendingField = String(field)
    showProcess.command = ["black-bag", "agent", "show", String(record.id), String(field)]
    showProcess.running = true
  }

  function clearReveal() {
    root.revealedValue = ""
    root.revealedField = ""
    root.revealedFor = ""
    root.revealSecondsLeft = 0
  }

  function fetchTotp(record) {
    if (!record || !record.has_totp) return
    root.totpPendingId = String(record.id)
    totpProcess.command = ["black-bag", "agent", "totp", String(record.id)]
    totpProcess.running = true
  }

  function beginAdd() {
    if (!root.unlocked) return
    recordEditor.begin("add", root.filterKind.length > 0 ? root.filterKind : "login", null)
  }

  function beginEdit() {
    if (!root.unlocked || !root.selectedRecord) return
    recordEditor.begin("edit", String(root.selectedRecord.kind), root.selectedRecord)
  }

  function requestDelete() {
    if (!root.unlocked || !root.selectedRecord) return
    var id = String(root.selectedRecord.id)
    if (root.pendingDeleteId === id) {
      deleteProcess.command = ["black-bag", "agent", "delete", id, "--yes"]
      deleteProcess.running = true
      root.pendingDeleteId = ""
    } else {
      root.pendingDeleteId = id
      root.actionNote = ""
    }
  }

  function moveSelection(delta) {
    root.pendingDeleteId = ""
    var n = root.visibleRecords.length
    if (n === 0) return
    root.selectedIndex = Math.max(0, Math.min(n - 1, root.selectedIndex + delta))
    root.clearReveal()
    root.totpState = null
    if (root.selectedRecord && root.selectedRecord.has_totp) root.fetchTotp(root.selectedRecord)
  }

  // ── colour helpers ─────────────────────────────────────────────────────────

  function fg(a) { return Util.alpha(Color.foreground, a) }

  function stateTone() {
    if (root.stale) return root.fg(0.4)
    if (root.deckState === "ROLLBACK" || root.deckState === "UNREADABLE") return Color.urgent
    if (root.deckState === "UNLOCKED") return Color.accent
    if (root.deckState === "NO VAULT") return Color.muted
    return Color.foreground
  }

  function severityTone(severity) {
    if (severity === "alert") return Color.urgent
    if (severity === "warn")  return Util.alpha(Color.urgent, 0.8)
    if (severity === "note")  return Util.alpha(Color.foreground, 0.65)
    if (severity === "ok")    return Color.accent
    return Color.muted
  }

  function okTone(ok) { return ok ? Color.accent : Color.urgent }

  // ── file + timers ──────────────────────────────────────────────────────────

  FileView {
    id: statusFile
    path: root.statusPath
    watchChanges: true
    atomicWrites: true
    printErrors: false
    onLoaded: root.applyStatus(text())
    onFileChanged: statusApply.restart()
  }

  Timer {
    id: statusApply
    interval: 100
    repeat: false
    onTriggered: { statusFile.reload(); root.applyStatus(statusFile.text()) }
  }

  Timer {
    interval: 1000
    running: root.opened
    repeat: true
    onTriggered: {
      root.nowMs = Date.now()

      if (root.revealSecondsLeft > 0) {
        root.revealSecondsLeft -= 1
        if (root.revealSecondsLeft === 0) {
          root.revealedValue = ""
          root.revealedField = ""
          root.revealedFor = ""
        }
      }

      // Re-fetch a TOTP just after its step rolls, never faster.
      if (root.liveTotp && !totpProcess.running) {
        var elapsed = (root.nowMs - root.liveTotp.at) / 1000
        if (elapsed >= root.liveTotp.ttl) root.fetchTotp(root.selectedRecord)
      }
    }
  }

  Timer {
    interval: 4000
    running: root.opened
    repeat: true
    onTriggered: if (!refreshProcess.running) refreshProcess.running = true
  }

  // ── processes ──────────────────────────────────────────────────────────────

  Process {
    id: refreshProcess
    command: ["black-bag", "status", "--publish"]
    running: false
    onExited: statusApply.restart()
  }

  Process {
    id: unlockProcess
    command: ["black-bag", "agent", "unlock"]
    running: false
    stdinEnabled: true
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onStarted: {
      // Rule 2: the passphrase crosses on stdin and the pipe closes immediately.
      write(root.passphrase + "\n")
      stdinEnabled = false
    }
    onExited: function (code) {
      root.unlocking = false
      root.passphrase = ""
      passField.text = ""
      if (code === 0) {
        root.actionNote = "unlocked"
        root.actionError = ""
        refreshProcess.running = true
        root.refreshRecords()
        Qt.callLater(function () { keyCatcher.forceActiveFocus() })
      } else {
        var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
        root.actionError = err.length > 0 ? err : "unlock failed"
        Qt.callLater(function () { passField.forceActiveFocus() })
      }
    }
  }

  Process {
    id: lockProcess
    command: ["black-bag", "agent", "lock"]
    running: false
    onExited: {
      root.records = []
      root.actionNote = "locked"
      refreshProcess.running = true
    }
  }

  Process {
    id: listProcess
    command: ["black-bag", "agent", "list", "--json"]
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var parsed = JSON.parse(String(this.text || "[]"))
          root.records = Array.isArray(parsed) ? parsed : []
          // A list that succeeded clears a list that failed. Without this the
          // footer keeps asserting "could not read the record list" over a
          // record list that is plainly on screen — a stale alarm, which is
          // the one thing this surface must never show.
          root.actionError = ""
          if (root.selectedIndex >= root.visibleRecords.length) root.selectedIndex = 0
          if (root.selectedRecord && root.selectedRecord.has_totp)
            root.fetchTotp(root.selectedRecord)
        } catch (e) {
          root.actionError = "could not read the record list"
        }
      }
    }
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      root.listing = false
      if (code !== 0) {
        var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
        root.actionError = err.length > 0 ? err : "list failed"
      }
    }
  }

  Process {
    id: copyProcess
    running: false
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      if (code !== 0) {
        var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
        root.actionError = err.length > 0 ? err : "copy failed"
        root.actionNote = ""
      }
    }
  }

  Process {
    id: showProcess
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.revealedField = root.showPendingField
        root.revealedFor = root.showPendingId
        root.revealedValue = String(this.text || "").replace(/\n+$/, "")
        root.revealSecondsLeft = root.revealSeconds
      }
    }
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      if (code !== 0) {
        var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
        root.actionError = err.length > 0 ? err : "reveal failed"
        root.clearReveal()
      }
    }
  }

  Process {
    id: hygieneProcess
    command: ["black-bag", "agent", "hygiene", "--json"]
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try { root.hygiene = JSON.parse(String(this.text || "null")) }
        catch (e) { root.hygiene = null }
      }
    }
    onExited: function (code) { if (code !== 0) root.hygiene = null }
  }

  Process {
    id: deleteProcess
    running: false
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      if (code === 0) {
        root.actionNote = "record deleted"
        root.selectedIndex = 0
        root.refreshRecords()
        refreshProcess.running = true
      } else {
        var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
        root.actionError = err.length > 0 ? err : "delete failed"
      }
    }
  }

  Process {
    id: totpProcess
    running: false
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      if (code !== 0) {
        root.totpState = null
        var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
        root.actionError = err.length > 0 ? err : "totp unavailable"
      }
    }
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var parsed = JSON.parse(String(this.text || "{}"))
          if (parsed.code === undefined) return
          root.totpState = {
            id: root.totpPendingId,
            code: String(parsed.code),
            ttl: Number(parsed.ttl_secs) || 0,
            step: Number(parsed.step) || 30,
            at: Date.now()
          }
        } catch (e) { /* leave the previous code rather than blanking it */ }
      }
    }
  }

  // ── window ─────────────────────────────────────────────────────────────────

  PanelWindow {
    id: win
    visible: root.opened
    anchors { top: true; bottom: true; left: true; right: true }
    color: Color.background
    exclusionMode: ExclusionMode.Ignore
    WlrLayershell.namespace: "blackbag-cockpit"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive

    Item {
      id: keyCatcher
      anchors.fill: parent
      focus: true
      Keys.priority: Keys.BeforeItem

      // ── focus-independent shortcuts ──────────────────────────────────────────
      //
      // keyCatcher's Keys handler only fires while keyCatcher ITSELF holds active
      // focus. The sealed screen focuses the passphrase field the moment it opens,
      // and `/` focuses the search field, so from that point the handler is silent
      // — which is exactly why Esc could not close the sealed screen. Shortcut is
      // scoped to the window rather than to focus, so these work wherever the caret
      // is. Plain letter keys stay in keyCatcher on purpose: they MUST stay dead
      // while you are typing into a field.
      Shortcut {
        sequences: ["Esc"]
        enabled: root.opened && !recordEditor.open_ && !onboardSheet.open_
        context: Qt.WindowShortcut
        onActivated: root.backOut()
      }
      Shortcut {
        sequences: ["Ctrl+L"]
        enabled: root.opened && !recordEditor.open_ && !onboardSheet.open_ && root.unlocked
        context: Qt.WindowShortcut
        onActivated: root.doLock()
      }
      Shortcut {
        sequences: ["Ctrl+R"]
        enabled: root.opened && !recordEditor.open_ && !onboardSheet.open_
        context: Qt.WindowShortcut
        onActivated: {
          refreshProcess.running = true
          if (root.unlocked) root.refreshRecords()
        }
      }

      Keys.onPressed: function (event) {
        // The first-run sheet owns the keyboard while it is up. Esc abandons
        // it; everything else belongs to its own fields.
        if (onboardSheet.open_) {
          if (event.key === Qt.Key_Escape) {
            onboardSheet.abandon()
            event.accepted = true
          }
          return
        }

        // The editor owns the keyboard while it is open.
        if (recordEditor.open_) {
          if (event.key === Qt.Key_Escape) {
            recordEditor.dismiss()
            event.accepted = true
          } else if ((event.key === Qt.Key_Return || event.key === Qt.Key_Enter)
                     && (event.modifiers & Qt.ControlModifier)) {
            recordEditor.save()
            event.accepted = true
          } else if (event.key === Qt.Key_G && (event.modifiers & Qt.ControlModifier)) {
            recordEditor.generateFocused()
            event.accepted = true
          } else if (event.key === Qt.Key_Tab) {
            recordEditor.moveFocus(1)
            event.accepted = true
          } else if (event.key === Qt.Key_Backtab
                     || (event.key === Qt.Key_Tab && (event.modifiers & Qt.ShiftModifier))) {
            recordEditor.moveFocus(-1)
            event.accepted = true
          }
          return
        }


        // While the passphrase field has focus, only Esc and Enter are ours.
        if (passField.activeFocus) {
          if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
            root.doUnlock()
            event.accepted = true
          }
          return
        }
        if (searchField.activeFocus) {
          if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter
              || event.key === Qt.Key_Down) {
            keyCatcher.forceActiveFocus()
            if (root.visibleRecords.length > 0) root.selectedIndex = 0
            event.accepted = true
          }
          return
        }

        if (event.key === Qt.Key_Slash) {
          searchField.forceActiveFocus()
          event.accepted = true
        } else if (event.key === Qt.Key_Down || event.key === Qt.Key_J) {
          root.moveSelection(1); event.accepted = true
        } else if (event.key === Qt.Key_Up || event.key === Qt.Key_K) {
          root.moveSelection(-1); event.accepted = true
        } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
          if (event.modifiers & Qt.ShiftModifier)
            root.showField(root.selectedRecord, root.primaryField(root.selectedRecord))
          else
            root.copyField(root.selectedRecord, root.primaryField(root.selectedRecord))
          event.accepted = true
        } else if (event.key === Qt.Key_U && !root.unlocked) {
          passField.forceActiveFocus(); event.accepted = true
        } else if (event.key === Qt.Key_Home) {
          root.selectedIndex = 0; root.clearReveal(); root.totpState = null
          event.accepted = true
        } else if (event.key === Qt.Key_End) {
          root.selectedIndex = Math.max(0, root.visibleRecords.length - 1)
          root.clearReveal(); root.totpState = null
          event.accepted = true
        } else if (event.key === Qt.Key_PageDown) {
          root.moveSelection(10); event.accepted = true
        } else if (event.key === Qt.Key_PageUp) {
          root.moveSelection(-10); event.accepted = true
        } else if (event.key === Qt.Key_Backspace && root.filterKind.length > 0) {
          root.filterKind = ""; root.selectedIndex = 0; event.accepted = true
        } else if (event.key === Qt.Key_N && event.modifiers === Qt.NoModifier) {
          root.beginAdd(); event.accepted = true
        } else if (event.key === Qt.Key_E && event.modifiers === Qt.NoModifier) {
          root.beginEdit(); event.accepted = true
        } else if (event.key === Qt.Key_Delete
                   || (event.key === Qt.Key_D && (event.modifiers & Qt.ControlModifier))) {
          root.requestDelete(); event.accepted = true
        }
      }

      // ── reusable primitives ─────────────────────────────────────────────────

      component Card: Rectangle {
        default property alias content: cardInner.data
        property color tone: Util.alpha(Color.muted, 0.45)
        property bool live: false
        Layout.fillWidth: true
        implicitHeight: cardInner.implicitHeight + Style.spacing.md * 2
        color: live ? Util.alpha(Color.accent, 0.05) : Util.alpha(Color.foreground, 0.03)
        border.color: live ? Util.alpha(Color.accent, 0.28) : tone
        border.width: 1
        radius: Style.cornerRadius
        ColumnLayout {
          id: cardInner
          anchors.fill: parent
          anchors.margins: Style.spacing.md
          spacing: Style.spacing.xs
        }
      }

      component SectionTitle: Text {
        Layout.fillWidth: true
        color: Util.alpha(Color.foreground, 0.45)
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        font.bold: true
        font.letterSpacing: Style.space(0.8)
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
      }

      component KV: RowLayout {
        property string k: ""
        property string v: ""
        property color vColor: Color.foreground
        property bool strong: false
        property int elide: Text.ElideMiddle
        Layout.fillWidth: true
        spacing: Style.spacing.sm
        Text {
          text: parent.k
          color: Util.alpha(Color.foreground, 0.55)
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
        Item { Layout.fillWidth: true }
        Text {
          Layout.maximumWidth: Style.space(210)
          text: parent.v
          color: parent.vColor
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          font.bold: parent.strong
          elide: parent.elide
          horizontalAlignment: Text.AlignRight
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
      }

      component Chip: Rectangle {
        property string label: ""
        property color tone: Color.muted
        implicitWidth: chipText.implicitWidth + Style.spacing.md * 2
        implicitHeight: chipText.implicitHeight + Style.spacing.xs * 2
        radius: height / 2
        color: Util.alpha(tone, 0.14)
        border.color: Util.alpha(tone, 0.6)
        border.width: 1
        Text {
          id: chipText
          anchors.centerIn: parent
          text: parent.label
          color: parent.tone
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          font.bold: true
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
      }

      component Dot: Rectangle {
        // `var`, not `bool`: null means "not measured", and an unmeasured
        // check must not render the same as a passing one.
        property var ok: null
        property color badTone: Color.urgent
        width: Style.space(8)
        height: width
        radius: width / 2
        color: ok === true ? Color.accent : "transparent"
        border.color: ok === true ? Color.accent
                    : ok === false ? badTone
                    : Util.alpha(Color.foreground, 0.3)
        border.width: Math.max(1, Style.spacing.hairline)
      }

      component ActionButton: Rectangle {
        property string label: ""
        property color tone: Color.foreground
        property bool enabledAction: true
        signal activated()
        implicitWidth: actionText.implicitWidth + Style.spacing.lg * 2
        implicitHeight: Style.spacing.controlHeight
        radius: Style.cornerRadius
        color: mouse.containsMouse && enabledAction
          ? Util.alpha(tone, 0.18) : Util.alpha(tone, 0.08)
        border.color: Util.alpha(tone, enabledAction ? 0.45 : 0.15)
        border.width: 1
        opacity: enabledAction ? 1.0 : 0.4
        Text {
          id: actionText
          anchors.centerIn: parent
          text: parent.label
          color: parent.tone
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          font.bold: true
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
        MouseArea {
          id: mouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: parent.enabledAction ? Qt.PointingHandCursor : Qt.ArrowCursor
          onClicked: if (parent.enabledAction) parent.activated()
        }
        Behavior on color { ColorAnimation { duration: root.motionMs } }
      }

      // ── layout ──────────────────────────────────────────────────────────────

      // ── the deck, shown only once the vault is open ───────────────────────
      // The sealed screen below is a separate composition, not this layout with
      // its middle hollowed out. A lock screen that is 80% dashboard chrome
      // around a password box is the thing being avoided.
      ColumnLayout {
        anchors.fill: parent
        anchors.margins: Style.space(16)
        spacing: Style.spacing.md
        visible: root.unlocked

        // ── header ────────────────────────────────────────────────────────────
        RowLayout {
          Layout.fillWidth: true
          spacing: Style.spacing.lg

          ColumnLayout {
            spacing: 0
            Text {
              text: "B L A C K - B A G"
              color: root.stateTone()
              font.family: Style.font.family
              font.pixelSize: Style.font.display
              font.bold: true
              font.letterSpacing: Style.space(1)
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
              Behavior on color { ColorAnimation { duration: root.motionMs } }
            }
            Text {
              text: "CREDENTIAL COMMAND DECK"
              color: Util.alpha(Color.foreground, 0.45)
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              font.letterSpacing: Style.space(1.2)
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
            }
          }

          Item { Layout.fillWidth: true }

          Chip {
            label: root.deckState + (root.unlocked && Model.sessionRemaining(root.status, root.nowMs) !== null
              ? " · " + Model.fmtCountdown(Model.sessionRemaining(root.status, root.nowMs)) : "")
            tone: root.stateTone()
          }
          Chip {
            label: root.unlocked
              ? Model.totalRecords(agentCounts()) + " RECORDS"
              : "SEALED"
            tone: Util.alpha(Color.foreground, 0.7)
          }
          Chip {
            label: root.status && root.status.epoch !== null && root.status.epoch !== undefined
              ? "EPOCH " + root.status.epoch : "EPOCH —"
            tone: root.status && root.status.rollback_suspected
              ? Color.urgent : Util.alpha(Color.foreground, 0.7)
          }
          Chip {
            label: root.status && root.status.kdf
              ? Math.round(root.status.kdf.mem_cost_kib / 1024) + " MiB KDF" : "KDF —"
            tone: root.status && root.status.kdf && root.status.kdf.meets_current_defaults
              ? Color.accent : Util.alpha(Color.urgent, 0.75)
          }
          Chip {
            label: {
              var a = Model.countFindings(root.status, "alert")
              var w = Model.countFindings(root.status, "warn")
              if (a > 0) return a + " ALERT"
              if (w > 0) return w + " WARN"
              return "CLEAR"
            }
            tone: root.severityTone(Model.worstSeverity(root.status))
          }

          ActionButton {
            label: "✕"
            tone: Util.alpha(Color.foreground, 0.6)
            onActivated: root.dismiss()
          }
        }

        Rectangle {
          Layout.fillWidth: true
          height: 1
          color: Util.alpha(Color.muted, 0.5)
        }

        // ── body ──────────────────────────────────────────────────────────────
        Item {
          Layout.fillWidth: true
          Layout.fillHeight: true

          readonly property real gap: Style.space(12)
          readonly property real leftW: Style.space(250)
          readonly property real rightW: Style.space(330)

          // LEFT RAIL ─────────────────────────────────────────────────────────
          Flickable {
            id: leftRail
            anchors { top: parent.top; bottom: parent.bottom; left: parent.left }
            width: parent.leftW
            clip: true
            pixelAligned: true
            boundsBehavior: Flickable.StopAtBounds
            contentHeight: leftCol.implicitHeight
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

            ColumnLayout {
              id: leftCol
              width: leftRail.width - Style.spacing.md
              spacing: Style.spacing.md

              Card {
                SectionTitle { text: "VAULT" }
                KV {
                  k: "state"; v: root.deckState
                  vColor: root.stateTone(); strong: true
                }
                KV {
                  k: "format"
                  v: root.status && root.status.vault_format
                    ? "v" + root.status.vault_format : "—"
                }
                KV {
                  k: "epoch"
                  v: root.status
                    ? Model.orDash(root.status.epoch)
                      + (root.status.witness_epoch !== null && root.status.witness_epoch !== undefined
                         ? " / seen " + root.status.witness_epoch : "")
                    : "—"
                  vColor: root.status && root.status.rollback_suspected
                    ? Color.urgent : Color.foreground
                  strong: root.status && root.status.rollback_suspected
                }
                KV {
                  k: "updated"
                  v: root.status ? Model.fmtAgo(root.status.updated_at, root.nowMs) : "—"
                }
                KV {
                  k: "published"
                  v: root.status ? Model.fmtAgo(root.status.published_at, root.nowMs) : "—"
                  vColor: root.stale ? Color.urgent : Util.alpha(Color.foreground, 0.55)
                }
                KV {
                  k: "path"
                  v: root.status ? Model.orDash(root.status.vault_path) : "—"
                  elide: Text.ElideLeft
                }
              }

              Card {
                SectionTitle {
                  text: "CENSUS — " + (root.unlocked
                    ? Model.totalRecords(agentCounts()) + " RECORDS" : "SEALED")
                }
                Repeater {
                  model: root.unlocked
                    ? Model.census(agentCounts()).filter(function (c) { return c.count > 0 })
                    : []
                  delegate: RowLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    spacing: Style.spacing.sm
                    Text {
                      text: modelData.glyph
                      color: modelData.count > 0
                        ? Color.accent : Util.alpha(Color.foreground, 0.3)
                      font.family: Style.font.family
                      font.pixelSize: Style.font.caption
                      renderType: Text.NativeRendering
                    }
                    Text {
                      text: modelData.kind
                      color: root.filterKind === modelData.kind
                        ? Color.accent : Util.alpha(Color.foreground, 0.7)
                      font.family: Style.font.family
                      font.pixelSize: Style.font.caption
                      font.bold: root.filterKind === modelData.kind
                      textFormat: Text.PlainText
                      renderType: Text.NativeRendering
                    }
                    Item { Layout.fillWidth: true }
                    Text {
                      text: String(modelData.count)
                      color: modelData.count > 0
                        ? Color.foreground : Util.alpha(Color.foreground, 0.3)
                      font.family: Style.font.family
                      font.pixelSize: Style.font.caption
                      font.bold: modelData.count > 0
                      renderType: Text.NativeRendering
                    }
                    // Handlers rather than a MouseArea: a MouseArea here is a
                    // child of the RowLayout, so it is given a cell of its own
                    // and then anchored across the row it is sitting inside —
                    // which Qt reports as undefined behaviour and which quietly
                    // widens every census row by an empty column. Handlers are
                    // not items and take no cell.
                    HoverHandler { cursorShape: Qt.PointingHandCursor }
                    TapHandler {
                      onTapped: {
                        root.filterKind = root.filterKind === modelData.kind
                          ? "" : modelData.kind
                        root.selectedIndex = 0
                      }
                    }
                  }
                }
                Text {
                  visible: root.unlocked
                  Layout.fillWidth: true
                  Layout.topMargin: Style.spacing.xs
                  text: {
                    var all = Model.census(agentCounts())
                    var zero = 0
                    for (var i = 0; i < all.length; i++) if (all[i].count === 0) zero++
                    return all.length + " kinds tracked · " + zero + " with no records"
                  }
                  color: Util.alpha(Color.foreground, 0.3)
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  textFormat: Text.PlainText
                  renderType: Text.NativeRendering
                }

                Text {
                  visible: !root.unlocked
                  Layout.fillWidth: true
                  text: "record counts are only known while unlocked"
                  color: Util.alpha(Color.foreground, 0.35)
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                  renderType: Text.NativeRendering
                }
              }

              Card {
                SectionTitle {
                  text: "RECIPIENTS — " + (root.status && root.status.recipients
                    ? root.status.recipients.length : 0)
                }
                Repeater {
                  model: Model.recipientRows(root.status)
                  delegate: ColumnLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    spacing: 0
                    RowLayout {
                      Layout.fillWidth: true
                      spacing: Style.spacing.sm
                      Dot { ok: modelData.external === true ? true : null }
                      Text {
                        text: modelData.label
                        color: Color.foreground
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        font.bold: true
                        textFormat: Text.PlainText
                        renderType: Text.NativeRendering
                      }
                      Item { Layout.fillWidth: true }
                      Text {
                        text: modelData.external ? "OFFLINE KEY" : "PASSPHRASE"
                        color: modelData.external
                          ? Color.accent : Util.alpha(Color.foreground, 0.55)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        renderType: Text.NativeRendering
                      }
                    }
                    Text {
                      Layout.fillWidth: true
                      Layout.leftMargin: Style.space(13)
                      text: modelData.note
                      color: Util.alpha(Color.foreground, 0.35)
                      font.family: Style.font.family
                      font.pixelSize: Style.font.caption
                      wrapMode: Text.WordWrap
                      renderType: Text.NativeRendering
                    }
                  }
                }
                Text {
                  visible: !root.status || !root.status.recipients
                           || root.status.recipients.length === 0
                  Layout.fillWidth: true
                  text: "no recipients reported"
                  color: Util.alpha(Color.foreground, 0.35)
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  renderType: Text.NativeRendering
                }
              }

              Card {
                SectionTitle { text: "HOST POSTURE" }
                Repeater {
                  model: Model.postureRows(root.status)
                  delegate: ColumnLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    spacing: 0
                    RowLayout {
                      Layout.fillWidth: true
                      spacing: Style.spacing.sm
                      Dot {
                        ok: modelData.ok
                        badTone: root.severityTone(modelData.severity)
                      }
                      Text {
                        text: modelData.label
                        color: Util.alpha(Color.foreground, 0.7)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        textFormat: Text.PlainText
                        renderType: Text.NativeRendering
                      }
                      Item { Layout.fillWidth: true }
                      Text {
                        text: modelData.value
                        color: modelData.ok === null
                          ? Util.alpha(Color.foreground, 0.35)
                          : modelData.ok
                            ? Util.alpha(Color.foreground, 0.55)
                            : root.severityTone(modelData.severity)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        font.bold: modelData.ok === false && modelData.severity === "alert"
                        textFormat: Text.PlainText
                        renderType: Text.NativeRendering
                      }
                    }
                    // The explanation gets its own full-width line rather than
                    // being elided mid-word off the end of the value.
                    Text {
                      Layout.fillWidth: true
                      Layout.leftMargin: Style.space(8) + Style.spacing.sm
                      visible: String(modelData.detail || "").length > 0
                      text: modelData.detail
                      color: Util.alpha(Color.foreground, 0.35)
                      font.family: Style.font.family
                      font.pixelSize: Style.font.caption
                      wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                      textFormat: Text.PlainText
                      renderType: Text.NativeRendering
                    }
                  }
                }
              }
            }
          }

          // CENTRE ────────────────────────────────────────────────────────────
          Item {
            id: centre
            anchors {
              top: parent.top; bottom: parent.bottom
              left: leftRail.right; right: rightRail.left
              leftMargin: parent.gap; rightMargin: parent.gap
            }

            // Unlocked: search + record table.
            ColumnLayout {
              anchors.fill: parent
              spacing: Style.spacing.md
              visible: root.unlocked

              RowLayout {
                Layout.fillWidth: true
                spacing: Style.spacing.md
                TextField {
                  id: searchField
                  Layout.fillWidth: true
                  placeholderText: "/  search titles, tags, usernames — never secrets"
                  onTextChanged: {
                    root.searchText = text
                    root.selectedIndex = 0
                  }
                }
                Chip {
                  visible: root.filterKind.length > 0
                  label: root.filterKind.toUpperCase() + " ✕"
                  tone: Color.accent
                  MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: { root.filterKind = ""; root.selectedIndex = 0 }
                  }
                }
                Chip {
                  label: root.visibleRecords.length + " / " + root.records.length
                  tone: Util.alpha(Color.foreground, 0.6)
                }
              }

              Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                color: Util.alpha(Color.foreground, 0.03)
                border.color: Util.alpha(Color.foreground, 0.10)
                border.width: 1
                radius: Style.cornerRadius
                clip: true

                ListView {
                  id: recordList
                  anchors.fill: parent
                  anchors.margins: Style.spacing.xs
                  clip: true
                  pixelAligned: true
                  boundsBehavior: Flickable.StopAtBounds
                  model: root.visibleRecords
                  currentIndex: root.selectedIndex
                  highlightMoveDuration: root.motionMs
                  ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                  delegate: Rectangle {
                    required property var modelData
                    required property int index
                    width: recordList.width
                    // Two stacked lines (title + subtitle) plus breathing room;
                    // at 34 the subtitle was squeezed to zero height.
                    height: Style.space(42)
                    color: index === root.selectedIndex
                      ? Util.alpha(Color.accent, 0.12)
                      : (rowMouse.containsMouse
                         ? Util.alpha(Color.foreground, 0.06) : "transparent")
                    radius: Style.cornerRadius

                    Rectangle {
                      visible: index === root.selectedIndex
                      anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
                      width: Style.space(3)
                      color: Color.accent
                      radius: width / 2
                    }

                    RowLayout {
                      anchors.fill: parent
                      anchors.leftMargin: Style.spacing.md
                      anchors.rightMargin: Style.spacing.md
                      spacing: Style.spacing.md

                      Text {
                        text: Model.kindGlyph(modelData.kind)
                        color: index === root.selectedIndex
                          ? Color.accent : Util.alpha(Color.foreground, 0.6)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.body
                        renderType: Text.NativeRendering
                      }

                      ColumnLayout {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignVCenter
                        spacing: Style.space(1)
                        Text {
                          Layout.fillWidth: true
                          text: Model.recordLabel(modelData)
                          color: Color.foreground
                          font.family: Style.font.family
                          font.pixelSize: Style.font.bodySmall
                          font.bold: index === root.selectedIndex
                          elide: Text.ElideRight
                          textFormat: Text.PlainText
                          renderType: Text.NativeRendering
                        }
                        Text {
                          Layout.fillWidth: true
                          visible: text.length > 0
                          text: Model.recordSubtitle(modelData)
                          color: Util.alpha(Color.foreground, 0.45)
                          font.family: Style.font.family
                          font.pixelSize: Style.font.caption
                          elide: Text.ElideRight
                          textFormat: Text.PlainText
                          renderType: Text.NativeRendering
                        }
                      }

                      Text {
                        Layout.preferredWidth: Style.space(14)
                        opacity: modelData.has_totp ? 1 : 0
                        text: "⧗"
                        color: Color.accent
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        renderType: Text.NativeRendering
                      }

                      Text {
                        Layout.preferredWidth: Style.space(64)
                        horizontalAlignment: Text.AlignRight
                        text: Model.fmtAgo(modelData.updated_at, root.nowMs)
                        color: Util.alpha(Color.foreground, 0.35)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        textFormat: Text.PlainText
                        renderType: Text.NativeRendering
                      }
                    }

                    MouseArea {
                      id: rowMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: {
                        root.selectedIndex = index
                        root.pendingDeleteId = ""
                        root.clearReveal()
                        root.totpState = null
                        if (modelData.has_totp) root.fetchTotp(modelData)
                        keyCatcher.forceActiveFocus()
                      }
                      onDoubleClicked: root.copyField(modelData, root.primaryField(modelData))
                    }
                  }
                }

                Text {
                  anchors.centerIn: parent
                  visible: root.visibleRecords.length === 0
                  text: root.listing
                    ? "reading…"
                    : (root.records.length === 0
                       ? "no records in this vault"
                       : "nothing matches this filter")
                  color: Util.alpha(Color.foreground, 0.35)
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  renderType: Text.NativeRendering
                }
              }
            }
          }

          // RIGHT RAIL ────────────────────────────────────────────────────────
          Flickable {
            id: rightRail
            anchors { top: parent.top; bottom: parent.bottom; right: parent.right }
            width: parent.rightW
            clip: true
            pixelAligned: true
            boundsBehavior: Flickable.StopAtBounds
            contentHeight: rightCol.implicitHeight
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

            ColumnLayout {
              id: rightCol
              width: rightRail.width - Style.spacing.md
              spacing: Style.spacing.md

              // Inspector
              Card {
                live: root.selectedRecord !== null
                visible: root.unlocked

                SectionTitle {
                  text: root.selectedRecord
                    ? "INSPECTOR — " + String(root.selectedRecord.kind).toUpperCase()
                    : "INSPECTOR"
                }

                Text {
                  Layout.fillWidth: true
                  visible: root.selectedRecord !== null
                  text: root.selectedRecord ? Model.recordLabel(root.selectedRecord) : ""
                  color: Color.foreground
                  font.family: Style.font.family
                  font.pixelSize: Style.font.subtitle
                  font.bold: true
                  wrapMode: Text.WordWrap
                  textFormat: Text.PlainText
                  renderType: Text.NativeRendering
                }

                Text {
                  Layout.fillWidth: true
                  visible: root.selectedRecord === null
                  text: "no record selected"
                  color: Util.alpha(Color.foreground, 0.35)
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  renderType: Text.NativeRendering
                }

                Repeater {
                  model: root.selectedRecord && root.selectedRecord.attributes
                    ? root.selectedRecord.attributes : []
                  delegate: KV {
                    required property var modelData
                    k: String(modelData[0])
                    v: String(modelData[1])
                    elide: Text.ElideRight
                  }
                }

                KV {
                  visible: root.selectedRecord !== null
                  k: "updated"
                  v: root.selectedRecord
                    ? Model.fmtAgo(root.selectedRecord.updated_at, root.nowMs) : "—"
                }

                Rectangle {
                  visible: root.selectedRecord !== null
                  Layout.fillWidth: true
                  height: 1
                  color: Util.alpha(Color.muted, 0.4)
                }

                // Secret fields: name, handle, actions. The value is absent.
                Repeater {
                  model: root.selectedRecord && root.selectedRecord.secret_fields
                    ? root.selectedRecord.secret_fields : []
                  delegate: ColumnLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    spacing: Style.spacing.xs

                    RowLayout {
                      Layout.fillWidth: true
                      spacing: Style.spacing.sm
                      Text {
                        text: "◆ " + modelData.name
                        color: Color.foreground
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        font.bold: true
                        renderType: Text.NativeRendering
                      }
                      Item { Layout.fillWidth: true }
                      Text {
                        text: modelData.handle + " · " + Model.fmtBytes(modelData.bytes)
                        color: Util.alpha(Color.foreground, 0.4)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        renderType: Text.NativeRendering
                      }
                    }

                    RowLayout {
                      Layout.fillWidth: true
                      spacing: Style.spacing.sm
                      ActionButton {
                        label: "COPY"
                        tone: Color.accent
                        onActivated: root.copyField(root.selectedRecord, modelData.name)
                      }
                      ActionButton {
                        label: "SHOW"
                        tone: Util.alpha(Color.foreground, 0.7)
                        onActivated: root.showField(root.selectedRecord, modelData.name)
                      }
                      Item { Layout.fillWidth: true }
                    }

                    // The reveal, visible only while its countdown runs.
                    Rectangle {
                      Layout.fillWidth: true
                      visible: root.revealedValue.length > 0
                               && root.revealedField === modelData.name
                               && root.selectedRecord
                               && root.revealedFor === String(root.selectedRecord.id)
                      implicitHeight: revealCol.implicitHeight + Style.spacing.md
                      color: Util.alpha(Color.urgent, 0.08)
                      border.color: Util.alpha(Color.urgent, 0.4)
                      border.width: 1
                      radius: Style.cornerRadius

                      ColumnLayout {
                        id: revealCol
                        anchors.fill: parent
                        anchors.margins: Style.spacing.sm
                        spacing: Style.spacing.xs
                        Text {
                          Layout.fillWidth: true
                          text: root.revealedValue
                          color: Color.foreground
                          font.family: Style.font.family
                          font.pixelSize: Style.font.bodySmall
                          wrapMode: Text.WrapAnywhere
                          textFormat: Text.PlainText
                          renderType: Text.NativeRendering
                        }
                        Text {
                          Layout.fillWidth: true
                          text: "on screen for " + root.revealSecondsLeft + "s · Esc hides"
                          color: Util.alpha(Color.urgent, 0.8)
                          font.family: Style.font.family
                          font.pixelSize: Style.font.caption
                          renderType: Text.NativeRendering
                        }
                      }
                    }
                  }
                }

                // TOTP with a countdown arc.
                Rectangle {
                  Layout.fillWidth: true
                  visible: root.selectedRecord && root.selectedRecord.has_totp
                  implicitHeight: Style.space(64)
                  color: Util.alpha(Color.accent, 0.06)
                  border.color: Util.alpha(Color.accent, 0.3)
                  border.width: 1
                  radius: Style.cornerRadius

                  RowLayout {
                    anchors.fill: parent
                    anchors.margins: Style.spacing.md
                    spacing: Style.spacing.lg

                    Canvas {
                      id: totpArc
                      width: Style.space(40)
                      height: width
                      Layout.alignment: Qt.AlignVCenter

                      property real progress: {
                        if (!root.liveTotp) return 0
                        var elapsed = (root.nowMs - root.liveTotp.at) / 1000
                        var remaining = Math.max(0, root.liveTotp.ttl - elapsed)
                        return Model.totpProgress(remaining, root.liveTotp.step)
                      }
                      onProgressChanged: requestPaint()

                      onPaint: {
                        var ctx = getContext("2d")
                        ctx.reset()
                        var cx = width / 2, cy = height / 2
                        var r = Math.min(cx, cy) - 3
                        ctx.lineWidth = 3
                        ctx.strokeStyle = Util.alpha(Color.foreground, 0.15)
                        ctx.beginPath()
                        ctx.arc(cx, cy, r, 0, Math.PI * 2)
                        ctx.stroke()

                        var left = 1 - progress
                        ctx.strokeStyle = left < 0.17 ? Color.urgent : Color.accent
                        ctx.beginPath()
                        ctx.arc(cx, cy, r, -Math.PI / 2,
                                -Math.PI / 2 + Math.PI * 2 * left)
                        ctx.stroke()
                      }
                    }

                    ColumnLayout {
                      Layout.fillWidth: true
                      spacing: 0
                      Text {
                        text: root.liveTotp ? root.liveTotp.code : "······"
                        color: root.liveTotp ? Color.foreground : Util.alpha(Color.foreground, 0.3)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.display
                        font.bold: true
                        font.letterSpacing: Style.space(2)
                        renderType: Text.NativeRendering
                      }
                      Text {
                        text: {
                          if (!root.liveTotp)
                            return totpProcess.running ? "fetching…" : "unavailable"
                          var elapsed = (root.nowMs - root.liveTotp.at) / 1000
                          var remaining = Math.max(0, Math.round(root.liveTotp.ttl - elapsed))
                          return remaining + "s · step " + root.liveTotp.step + "s"
                        }
                        color: Util.alpha(Color.foreground, 0.5)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        renderType: Text.NativeRendering
                      }
                    }

                    ActionButton {
                      label: "COPY"
                      tone: Color.accent
                      enabledAction: root.liveTotp !== null
                      onActivated: root.copyField(root.selectedRecord, "totp")
                    }
                  }
                }
              }

              // Credential hygiene — computed locally, no network, ever.
              Card {
                visible: root.unlocked
                SectionTitle {
                  text: {
                    if (!root.hygiene) return "HYGIENE — READING"
                    var n = Model.hygieneCount(root.hygiene)
                    return "HYGIENE — " + (n === 0 ? "CLEAN" : n + " ISSUE" + (n === 1 ? "" : "S"))
                  }
                }

                Text {
                  Layout.fillWidth: true
                  visible: root.hygiene !== null && Model.hygieneCount(root.hygiene) === 0
                  text: "every rule passed on " + (root.hygiene ? root.hygiene.scanned : 0)
                      + " record(s)"
                  color: Color.accent
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  textFormat: Text.PlainText
                  renderType: Text.NativeRendering
                }

                Repeater {
                  model: root.hygiene ? Model.asList(root.hygiene.records) : []
                  delegate: ColumnLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    spacing: 0

                    RowLayout {
                      Layout.fillWidth: true
                      spacing: Style.spacing.sm
                      Text {
                        text: Model.kindGlyph(modelData.kind)
                        color: Util.alpha(Color.foreground, 0.5)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        renderType: Text.NativeRendering
                      }
                      Text {
                        Layout.fillWidth: true
                        text: Model.orDash(modelData.title)
                        color: Util.alpha(Color.foreground, 0.8)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        font.bold: true
                        elide: Text.ElideRight
                        textFormat: Text.PlainText
                        renderType: Text.NativeRendering
                      }
                    }

                    Repeater {
                      model: Model.asList(modelData.issues)
                      delegate: Text {
                        required property var modelData
                        Layout.fillWidth: true
                        Layout.leftMargin: Style.space(14)
                        text: Model.hygieneLine(modelData)
                        color: root.severityTone(Model.hygieneSeverity(modelData))
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                        textFormat: Text.PlainText
                        renderType: Text.NativeRendering
                      }
                    }

                    // Same reason as the census rows: an anchored MouseArea
                    // inside a layout is a cell as well as an overlay.
                    HoverHandler { cursorShape: Qt.PointingHandCursor }
                    TapHandler {
                      onTapped: {
                        var list = root.visibleRecords
                        for (var i = 0; i < list.length; i++) {
                          if (String(list[i].id) === String(modelData.id)) {
                            root.selectedIndex = i
                            root.clearReveal()
                            break
                          }
                        }
                      }
                    }
                  }
                }

                Text {
                  Layout.fillWidth: true
                  Layout.topMargin: Style.spacing.xs
                  text: "computed on this machine · nothing is sent anywhere"
                  color: Util.alpha(Color.foreground, 0.3)
                  font.family: Style.font.family
                  font.pixelSize: Style.font.caption
                  textFormat: Text.PlainText
                  renderType: Text.NativeRendering
                }
              }

              // Findings
              Card {
                SectionTitle {
                  text: "FINDINGS — " + (root.status && root.status.findings
                    ? root.status.findings.length : 0)
                }
                Repeater {
                  model: Model.sortFindings(root.status)
                  delegate: ColumnLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    spacing: 0
                    RowLayout {
                      Layout.fillWidth: true
                      spacing: Style.spacing.sm
                      Text {
                        text: Model.severityMark(modelData.severity)
                        color: root.severityTone(modelData.severity)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        font.bold: true
                        renderType: Text.NativeRendering
                      }
                      Text {
                        Layout.fillWidth: true
                        text: modelData.title
                        color: root.severityTone(modelData.severity)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        font.bold: modelData.severity === "alert"
                        wrapMode: Text.WordWrap
                        textFormat: Text.PlainText
                        renderType: Text.NativeRendering
                      }
                    }
                    Text {
                      Layout.fillWidth: true
                      Layout.leftMargin: Style.space(14)
                      visible: String(modelData.detail).length > 0
                      text: modelData.detail
                      color: Util.alpha(Color.foreground, 0.4)
                      font.family: Style.font.family
                      font.pixelSize: Style.font.caption
                      wrapMode: Text.WordWrap
                      textFormat: Text.PlainText
                      renderType: Text.NativeRendering
                    }
                  }
                }
              }

              // Session controls
              Card {
                SectionTitle { text: "SESSION" }
                KV {
                  k: "idle timeout"
                  v: root.status && root.status.session
                    ? Model.fmtCountdown(root.status.session.idle_timeout_secs) : "—"
                }
                KV {
                  k: "unlocked by"
                  v: root.status && root.status.session && root.status.session.method
                    ? root.status.session.method : "—"
                }
                RowLayout {
                  Layout.fillWidth: true
                  Layout.topMargin: Style.spacing.xs
                  spacing: Style.spacing.sm
                  ActionButton {
                    label: "LOCK NOW"
                    tone: Color.urgent
                    enabledAction: root.unlocked
                    onActivated: root.doLock()
                  }
                  ActionButton {
                    label: "REFRESH"
                    tone: Util.alpha(Color.foreground, 0.7)
                    onActivated: {
                      refreshProcess.running = true
                      if (root.unlocked) root.refreshRecords()
                    }
                  }
                  Item { Layout.fillWidth: true }
                }
              }
            }
          }
        }

        Rectangle {
          Layout.fillWidth: true
          height: 1
          color: Util.alpha(Color.muted, 0.5)
        }

        // ── footer ────────────────────────────────────────────────────────────
        RowLayout {
          Layout.fillWidth: true
          spacing: Style.spacing.lg

          Text {
            text: {
              var bits = []
              bits.push(root.deckState.toLowerCase())
              if (root.unlocked) bits.push(root.records.length + " records")
              if (root.status && root.status.recipients)
                bits.push(root.status.recipients.length + " recipients")
              bits.push("status " + (root.status
                ? Model.fmtAgo(root.status.published_at, root.nowMs) : "—"))
              return bits.join(" · ")
            }
            color: Util.alpha(Color.foreground, 0.5)
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            renderType: Text.NativeRendering
          }

          Text {
            visible: root.actionNote.length > 0 && root.actionError.length === 0
            text: root.actionNote
            color: Color.accent
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            renderType: Text.NativeRendering
          }

          Text {
            visible: root.actionError.length > 0
            Layout.fillWidth: true
            text: root.actionError
            color: Color.urgent
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            elide: Text.ElideRight
            renderType: Text.NativeRendering
          }

          Item { Layout.fillWidth: true }

          Text {
            text: root.unlocked
              ? "n new · e edit · del remove · / search · ↑↓ move · ⏎ copy · ⇧⏎ show · ^L lock · esc close"
              : "⏎ unlock · esc close"
            color: Util.alpha(Color.foreground, 0.4)
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            renderType: Text.NativeRendering
          }
        }
      }

      // ── record editor ─────────────────────────────────────────────────────
      // Last child, so it paints over the deck and the sealed screen alike.
      Editor {
        id: recordEditor
        motionMs: root.motionMs
        onSaved: function (id) {
          root.actionNote = "saved"
          root.refreshRecords()
          refreshProcess.running = true
          Qt.callLater(function () { keyCatcher.forceActiveFocus() })
        }
        onCancelled: Qt.callLater(function () { keyCatcher.forceActiveFocus() })
      }

    }

      // ── the sealed vault ──────────────────────────────────────────────────
      //
      // Its own screen, not the deck with a hole in it. Four things exist at
      // rest: the wordmark, the field, the rule under it, and one identity
      // line. Everything else appears only when there is a reason.
      //
      // The rule is pinned at a fixed fraction of the screen height and never
      // moves. Hazards grow upward from it and consequences downward, so the
      // caret is never chased by a warning appearing above it.
      Item {
        id: sealed
        anchors.fill: parent
        visible: !root.unlocked

        readonly property var verdict:
          Model.unlockVerdict(root.status, root.nowMs, root.staleAfterSec)
        readonly property bool alerting: verdict.severity === "alert"
        readonly property bool blocked: verdict.blockInput === true
        readonly property real anchorY: Math.round(height * 0.52)
        readonly property real colW: Math.min(width * 0.44, Style.space(520))
        readonly property color hazardTone: alerting ? Color.urgent : Color.accent

        function witnessTone() {
          if (verdict.witnessTone === "bad") return Color.urgent
          if (verdict.witnessTone === "good") return Util.alpha(Color.accent, 0.75)
          return Util.alpha(Color.foreground, 0.35)
        }

        // THE RULE — the fixed anchor for the whole composition.
        Rectangle {
          id: rule
          y: sealed.anchorY
          x: Math.round((parent.width - sealed.colW) / 2)
          width: sealed.colW
          height: Math.max(1, Style.spacing.hairline)
          // The rule follows the verdict, not just the focus. A green line under
          // a red warning would be the screen contradicting itself.
          color: {
            if (sealed.blocked) return Util.alpha(Color.urgent, 0.45)
            if (root.actionError.length > 0) return Color.urgent
            if (sealed.alerting) return passField.activeFocus
              ? Color.urgent : Util.alpha(Color.urgent, 0.55)
            if (root.unlocking) return Util.alpha(Color.accent, 0.3)
            if (passField.activeFocus) return Color.accent
            return Util.alpha(Color.foreground, 0.28)
          }
          Behavior on color { ColorAnimation { duration: root.motionMs } }

          // Argon2id at t=10 takes seconds; without this the screen looks dead
          // at exactly the moment the user is wondering whether it took.
          Rectangle {
            visible: root.unlocking
            width: parent.width * 0.3
            height: parent.height
            color: Color.accent
            SequentialAnimation on x {
              running: root.unlocking
              loops: Animation.Infinite
              NumberAnimation { from: 0; to: rule.width * 0.7; duration: 900
                                easing.type: Easing.InOutQuad }
              NumberAnimation { from: rule.width * 0.7; to: 0; duration: 900
                                easing.type: Easing.InOutQuad }
            }
          }
        }

        // FIELD — sits directly on the rule.
        TextField {
          id: passField
          width: sealed.colW
          x: rule.x
          anchors.bottom: rule.top
          anchors.bottomMargin: Style.space(6)
          visible: sealed.verdict.hasVault
          enabled: !root.unlocking && !sealed.blocked
          password: true
          placeholderText: sealed.blocked ? "" : "master passphrase"
          onTextChanged: root.passphrase = text
          onAccepted: if (!sealed.blocked) root.doUnlock()
        }

        // WORDMARK — above the field.
        Text {
          id: sealedMark
          anchors.horizontalCenter: parent.horizontalCenter
          anchors.bottom: passField.visible ? passField.top : rule.top
          anchors.bottomMargin: Style.space(40)
          text: "B L A C K - B A G"
          color: sealed.alerting ? Color.urgent
               : (sealed.verdict.stale ? root.fg(0.4) : Util.alpha(Color.foreground, 0.85))
          font.family: Style.font.family
          font.pixelSize: Style.font.display
          font.bold: true
          font.letterSpacing: Style.spaceReal(1)
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          Behavior on color { ColorAnimation { duration: root.motionMs } }
        }

        // HAZARD — grows upward from the wordmark. Absent when there is nothing
        // to say, which is the entire source of its authority.
        ColumnLayout {
          width: Math.min(parent.width * 0.7, Style.space(760))
          anchors.horizontalCenter: parent.horizontalCenter
          anchors.bottom: sealedMark.top
          anchors.bottomMargin: Style.space(32)
          spacing: Style.space(6)
          visible: sealed.verdict.headline.length > 0

          Text {
            Layout.fillWidth: true
            text: (sealed.alerting ? "!!  " : "") + sealed.verdict.headline
            color: sealed.hazardTone
            font.family: Style.font.family
            font.pixelSize: Style.font.heading
            font.bold: true
            font.letterSpacing: Style.spaceReal(0.6)
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WrapAtWordBoundaryOrAnywhere
            textFormat: Text.PlainText
            renderType: Text.NativeRendering
          }
          Text {
            Layout.fillWidth: true
            visible: sealed.verdict.detail.length > 0
            text: sealed.verdict.detail
            color: Util.alpha(sealed.hazardTone, 0.7)
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WrapAtWordBoundaryOrAnywhere
            textFormat: Text.PlainText
            renderType: Text.NativeRendering
          }
        }

        // IDENTITY — below the rule. The fingerprint says which vault this
        // claims to be; the witness word says whether this machine agrees.
        // A planted vault can choose its own id, so the witness is the half
        // that carries the weight, and the comparison is made here rather than
        // left to someone squinting at two epoch numbers.
        ColumnLayout {
          width: sealed.colW
          x: rule.x
          anchors.top: rule.bottom
          anchors.topMargin: Style.space(14)
          spacing: Style.space(4)

          RowLayout {
            Layout.fillWidth: true
            spacing: Style.space(12)
            Text {
              text: sealed.verdict.identity
              color: sealed.verdict.hasVault
                ? Util.alpha(Color.foreground, 0.6) : Util.alpha(Color.foreground, 0.25)
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              font.letterSpacing: Style.spaceReal(0.4)
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
            }
            Text {
              visible: sealed.verdict.witness.length > 0
              text: "·"
              color: Util.alpha(Color.foreground, 0.25)
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              renderType: Text.NativeRendering
            }
            Text {
              visible: sealed.verdict.witness.length > 0
              text: sealed.verdict.witness
              color: sealed.witnessTone()
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              font.bold: sealed.verdict.witnessTone === "bad"
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
            }
            Item { Layout.fillWidth: true }
            Text {
              visible: sealed.verdict.stale
              text: "status " + sealed.verdict.staleFor
              color: Util.alpha(Color.foreground, 0.3)
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
            }
          }

          // One slot, three states — the idiom Omarchy's own lock screen uses.
          Text {
            Layout.fillWidth: true
            visible: text.length > 0
            text: root.unlocking ? "deriving key…"
                : (root.actionError.length > 0 ? root.actionError : "")
            color: root.unlocking ? Util.alpha(Color.accent, 0.8) : Color.urgent
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            wrapMode: Text.WrapAtWordBoundaryOrAnywhere
            textFormat: Text.PlainText
            renderType: Text.NativeRendering
          }
        }

        Text {
          anchors.horizontalCenter: parent.horizontalCenter
          anchors.bottom: parent.bottom
          anchors.bottomMargin: Style.space(28)
          text: {
            if (!root.status || root.status.vault_present !== true)
              return "⏎ create a vault  ·  esc close"
            if (!sealed.verdict.hasVault) return "esc close"
            if (sealed.blocked) return "detach the debugger to continue  ·  esc close"
            return "⏎ " + sealed.verdict.verb + "  ·  esc close"
          }
          color: Util.alpha(Color.foreground, 0.35)
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
      }

    // ── first run ─────────────────────────────────────────────────────────
    Onboard {
      id: onboardSheet
      motionMs: root.motionMs

      // A vault now exists. The passphrase comes back only because `init`
      // has just proved it opens this file — asking for it a second time
      // one second later would be ceremony, not security. It is used once
      // and dropped.
      onCreated: function (passphrase) {
        root.onboardSuppressed = true
        refreshProcess.running = true
        if (passphrase.length > 0) {
          root.passphrase = passphrase
          root.beginUnlock()
        } else {
          Qt.callLater(function () { passField.forceActiveFocus() })
        }
      }
      onDismissed: {
        root.onboardSuppressed = true
        Qt.callLater(function () { keyCatcher.forceActiveFocus() })
      }
    }

  }

  // Counts come from the agent over the socket, never from status.json — the
  // file deliberately carries no record information at all.
  property var agentCountsCache: []
  function agentCounts() { return root.agentCountsCache }

  onRecordsChanged: {
    var map = {}
    for (var i = 0; i < root.records.length; i++) {
      var k = String(root.records[i].kind)
      map[k] = (map[k] || 0) + 1

    }
    var out = []
    for (var kind in map) out.push([kind, map[kind]])
    root.agentCountsCache = out
  }
}
