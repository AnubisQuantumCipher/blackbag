// BLACK-BAG — credential command deck.
//
// The deck itself, identical in the standalone application and in the Omarchy
// plugin: the plugin wraps this in a layer-shell overlay, the application
// wraps it in a window, and neither changes what is on screen. Three rules
// shape everything here:
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
import BlackBag
import "Model.js" as Model

Item {
  id: root

  // Raised when the operator asks to leave -- the ✕ chip, or Esc with nothing
  // left to back out of. The deck does not close its own window: what a
  // dismissal means belongs to whatever is hosting it.
  signal closeRequested()

  property bool opened: true

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
  // Why the last hygiene run produced nothing. "Not yet run" and "the agent
  // refused" used to be the same state, which drew a permanent READING.
  property string hygieneError: ""

  // The raw session flag from the last status document. Lock/unlock edges are
  // taken from this, not from deckState: a stale status reports UNKNOWN, and
  // an edge computed through UNKNOWN never fires — which left the record list
  // and the hygiene report resident under a sealed screen.
  property bool lastSessionUnlocked: false

  // The breach check is the one thing in this deck that goes online, so it is
  // armed and confirmed like a delete: first press explains, second press runs.
  property bool breachArmed: false
  property bool breachRunning: false

  // Which record each in-flight request was issued FOR. Without these, moving
  // the selection while a reply is in flight lands one record's secret — or
  // one record's 2FA code — under a different record's name.
  // A pending delete, held until it is confirmed a second time. Deleting a
  // credential is not undoable and there is no trash.
  property string pendingDeleteId: ""
  // True while the delete of the SELECTED record is armed and waiting for its
  // second confirmation. Drawn, not just stored: the first del used to change
  // nothing on screen, which made the confirmation step read as a dead key.
  readonly property bool deleteArmed:
    root.pendingDeleteId.length > 0 && root.selectedRecord !== null
    && root.pendingDeleteId === String(root.selectedRecord.id)

  // First run offers to create a vault, once per visit. Set when the sheet is
  // dismissed AND when it completes: the status file is republished
  // asynchronously, so for a moment after a vault is created the deck still
  // holds a status saying there is none, and without this the sheet reopens on
  // top of the vault it has just finished making.
  property bool onboardSuppressed: false

  property string totpPendingId: ""
  /// A record whose code was asked for while another fetch was in flight.
  property string totpWantedId: ""
  property string showPendingId: ""
  property string showPendingField: ""

  readonly property string runtimeDir: App.env("XDG_RUNTIME_DIR") || "/tmp"
  readonly property string homeDir: App.env("HOME") || ""
  readonly property string statusPath: runtimeDir + "/black-bag/status.json"

  // In the plugin these come from the shell's config, resolved against the
  // manifest schema. A standalone application owns its own settings file, so
  // they come from ~/.config/black-bag/desktop.json instead, defaulted to the
  // same values the manifest declares — the two surfaces must not disagree
  // about how long a revealed secret stays on screen.
  readonly property var settings: Model.desktopSettings(App.settings)

  function setting(name, fallback) {
    return Model.settingOf(root.settings, name, fallback)
  }

  // ── how big the deck is ────────────────────────────────────────────────────
  //
  // The shell's own metrics are sized for a bar. A full-screen deck that
  // inherits them is unreadable at a normal seating distance, so the deck
  // scales them by a factor of its own: from the viewport by default, from the
  // operator's setting once they have expressed a preference, and live with
  // ctrl +/- either way.
  readonly property real autoScale: {
    if (win.width <= 0 || win.height <= 0) return 1.0
    var byWidth = win.width / 1280
    var byHeight = win.height / 800
    var viewport = Math.max(1.0, Math.min(2.2, Math.min(byWidth, byHeight)))

    // Normalised against the host's own base size. The shell's base is set by
    // the theme and the application's default is 12, so without this the same
    // screen produces two different-sized decks — and `uiScale: 1.4` would mean
    // two different things depending on which surface read it. Dividing it out
    // makes the number an absolute size rather than a multiplier of whatever
    // the host happened to be using.
    var hostBase = Number(Style.fontBaseSize)
    if (!isFinite(hostBase) || hostBase <= 0) hostBase = 12
    return viewport * (12 / hostBase)
  }
  readonly property real settingScale: {
    var v = Number(setting("uiScale", 0))
    if (!isFinite(v) || v <= 0) return 0
    return Math.min(v, Model.maxScaleFor(win.width))
  }
  // Bound, not readonly, and deliberately so: a nudge assigns it directly and
  // breaks the binding, which is what makes ctrl/cmd +- feel instant. Writing
  // the value out and waiting for the settings file to be re-read would lose
  // every keypress that landed inside the round trip — pressing three times
  // quickly moved the scale by one step.
  property real uiScale:
    root.settingScale > 0 ? root.settingScale : root.autoScale

  readonly property QtObject metric: DeckMetrics { uiScale: root.uiScale }

  // Applied immediately and written back, so the next open starts where this
  // one left off. Rounded to a step the eye can actually distinguish.
  function nudgeScale(delta) {
    var next = Math.round((root.uiScale + delta) * 20) / 20
    // Never past the point where the rails no longer fit the window: a deck
    // that can be zoomed until its own record table vanishes is a deck that
    // gets zoomed there by accident.
    next = Math.max(0.7, Math.min(Model.maxScaleFor(win.width), next))
    root.uiScale = next           // now
    root.persistScale(next)       // and next time
    root.actionNote = "scale " + next.toFixed(2)
  }

  function resetScale() {
    root.persistScale(0)          // 0 means "back to whatever the viewport suggests"
    // Restore the binding the nudges broke, so the deck tracks the window again.
    root.uiScale = Qt.binding(function () {
      return root.settingScale > 0 ? root.settingScale : root.autoScale
    })
    root.actionNote = "scale auto"
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
      if (!root.unlocked) root.focusPass()
    })
  }

  // Host-initiated end of dismissal. Must not raise closeRequested again.
  function close() {
    root.opened = false
    root.clearSecrets()
  }

  // User-initiated. Everything sensitive goes first, then the host is told —
  // in that order, so a host that declines to close still leaves nothing
  // behind.
  function dismiss() {
    root.clearSecrets()
    root.closeRequested()
  }

  // Everything sensitive this file can be holding, dropped at once — and
  // everything the two sheets can be holding, because a host-initiated
  // dismissal used to leave a half-typed master passphrase sitting in the
  // first-run sheet and a password in the editor's boxes. Record metadata and
  // the hygiene report go too: titles, usernames and handles are as sensitive
  // as the vault that carries them.
  function clearSecrets() {
    root.passphrase = ""
    root.revealedValue = ""
    root.revealedField = ""
    root.revealedFor = ""
    root.revealSecondsLeft = 0
    root.totpState = null
    root.showPendingId = ""
    root.showPendingField = ""
    root.totpPendingId = ""
    root.pendingDeleteId = ""
    root.breachArmed = false
    root.records = []
    root.hygiene = null
    root.hygieneError = ""
    root.refreshPending = false
    root.totpWantedId = ""
    passField.text = ""
    if (recordEditor.open_) recordEditor.dismiss()
    // Past step one the vault already exists and `onboard.pass` is the only
    // copy of the passphrase that made it — the recovery step is about to
    // write it to the engine's stdin. Merely emptying the field left the
    // sheet reopening on the next visit still at "recovery" with nothing to
    // send, and no way forward. Abandoning it closes it and hands the deck
    // back its own unlock screen, which is the only honest outcome.
    if (onboardSheet.open_) onboardSheet.abandon()
    if (recoverSheet.open_) recoverSheet.clear()
  }

  // Focus the passphrase box only when it is actually on screen and usable.
  // Qt happily grants focus to an invisible field, which then eats every
  // keystroke the deck was advertising, silently accumulating them in a
  // hidden passphrase buffer until Enter ships the garbage to the agent.
  function focusPass() {
    if (passField.visible && passField.enabled) passField.forceActiveFocus()
    else keyCatcher.forceActiveFocus()
  }

  // There being no vault is a first run, not an error. The deck creates one
  // rather than telling anyone to go and find a terminal.
  function maybeOnboard() {
    // A vault that turned up on its own retires the offer to create one.
    if (onboardSheet.open_ && root.status && root.status.vault_present === true) {
      onboardSheet.standDown()
      return
    }
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
      if (parsed.schema_version !== 1) {
        root.actionError = "this deck reads status schema 1; the engine published schema "
                         + String(parsed.schema_version) + " — update the plugin"
        return
      }
      var wasUnlocked = root.lastSessionUnlocked
      root.status = parsed
      Qt.callLater(root.maybeOnboard)
      var nowUnlocked = !!(parsed.session && parsed.session.unlocked)
      root.lastSessionUnlocked = nowUnlocked
      if (nowUnlocked && !wasUnlocked) {
        // Only when the deck is actually on screen. An unlock from the CLI
        // used to fill this overlay's record list while it was hidden, and
        // the shell keeps it loaded.
        if (root.opened) root.refreshRecords()
        // Unlocked from outside — the CLI, or a stale status catching up. The
        // keyboard may still be sitting on the sealed screen's (now hidden)
        // passphrase field; hand it to the deck or every footer key is dead.
        Qt.callLater(function () { if (root.opened) keyCatcher.forceActiveFocus() })
      }
      if (!nowUnlocked && wasUnlocked) {
        // clearSecrets() also dismisses the editor: left open it sits
        // invisibly UNDER the sealed screen holding whatever password was
        // mid-type, and wedges Esc, whose sealed-screen shortcut is gated on
        // the editor being closed.
        root.clearSecrets()
        var reason = parsed.session ? Model.lockReasonLabel(parsed.session.last_lock_reason) : ""
        if (reason.length > 0) root.actionNote = reason
        // And the sealed screen must come up ready to type: the footer says
        // "⏎ unlock", which is a lie unless the passphrase box has the caret.
        Qt.callLater(function () { if (root.opened) root.focusPass() })
      }
    } catch (e) {
      // Partial read during the atomic replace; keep the last good document.
    }
  }

  property bool refreshPending: false
  function refreshRecords() {
    // A refresh asked for while one is running is not dropped: the running
    // one may predate the write that prompted this one, so it runs again.
    if (!root.opened || !root.unlocked) return
    if (listProcess.running) { root.refreshPending = true; return }
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
    if (root.breachArmed) { root.breachArmed = false; root.actionNote = ""; return }
    // Focus wandered to a button (Tab): the first Esc brings the keys home.
    if (root.unlocked && !keyCatcher.activeFocus && !searchField.activeFocus) {
      keyCatcher.forceActiveFocus()
      return
    }
    if (root.unlocked && searchField.activeFocus) {
      // First Esc clears the query; a second hands the keyboard back to the
      // list. It used to fall through to dismiss() when the box was already
      // empty — so Esc-Esc from a search closed the whole window, when every
      // instinct says it should have landed you back on the records.
      if (searchField.text.length > 0) searchField.text = ""
      else keyCatcher.forceActiveFocus()
      return
    }
    root.dismiss()
  }

  function doLock() {
    root.clearSecrets()
    lockProcess.running = true
    root.actionNote = "locking…"
  }

  function primaryField(record) { return Model.primaryField(record) }

  function copyField(record, field) {
    if (!record || !field) { root.actionNote = "no record selected"; return }
    // Setting `running` on a running Process is a silent no-op, so a second
    // copy while the first is in flight would be dropped while the footer
    // said "copied". Say what is actually happening instead.
    if (copyProcess.running) { root.actionNote = "still placing the previous copy"; return }
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
    root.actionNote = "copying " + (isTotp ? "the current code" : field) + "…"
  }

  function showField(record, field) {
    if (!record || !field) { root.actionNote = "no record selected"; return }
    if (String(field) === "totp") {
      // The live code is already on screen in the TOTP card; the stored secret
      // is binary and there is nothing useful to show.
      root.actionError = "the current code is shown above; the stored secret is binary"
      return
    }
    if (showProcess.running) { root.actionError = "a reveal is already in flight"; return }
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
    // One fetch at a time: overwriting the pending id mid-flight would stamp
    // the FIRST record's code with the SECOND record's id. But the second
    // request cannot simply be dropped either — nothing re-issued it, so
    // moving the selection while a fetch was in flight left the card empty
    // for good. Remember what was wanted and pick it up when the reply lands.
    if (totpProcess.running) {
      root.totpWantedId = String(record.id)
      return
    }
    root.totpWantedId = ""
    root.totpPendingId = String(record.id)
    totpProcess.command = ["black-bag", "agent", "totp", String(record.id)]
    totpProcess.running = true
  }

  // The breach check: the one deliberate network act in this deck. Armed
  // first, run second, exactly like delete.
  function requestBreachCheck() {
    if (!root.unlocked) return
    if (root.breachRunning) { root.actionNote = "breach check already running"; return }
    if (!root.breachArmed) {
      root.breachArmed = true
      root.actionError = ""
      root.actionNote = ""
      return
    }
    root.breachArmed = false
    root.breachRunning = true
    root.actionError = ""
    root.actionNote = "checking against Pwned Passwords…"
    breachProcess.running = true
  }

  function beginAdd() {
    if (!root.unlocked) return
    recordEditor.begin("add", root.filterKind.length > 0 ? root.filterKind : "login", null)
  }

  function beginEdit() {
    if (!root.unlocked) return
    if (!root.selectedRecord) { root.actionNote = "no record selected"; return }
    recordEditor.begin("edit", String(root.selectedRecord.kind), root.selectedRecord)
  }

  function requestDelete() {
    if (!root.unlocked) return
    if (!root.selectedRecord) { root.actionNote = "no record selected"; return }
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

  // A safety net only: the status file is watched, and the agent republishes
  // on every state change, so this catches nothing but a vault rewritten by
  // something that never told the agent.
  Timer {
    interval: 30000
    running: root.opened
    repeat: true
    onTriggered: if (!refreshProcess.running) refreshProcess.running = true
  }

  // Footer notes expire. "copied password" was still on screen ten minutes
  // later, asserting a clipboard state that had long since changed.
  Timer {
    id: noteTimer
    interval: 7000
    repeat: false
    onTriggered: root.actionNote = ""
  }
  onActionNoteChanged: if (root.actionNote.length > 0) noteTimer.restart()

  // Writing the scale back is the one thing that differs between the two
  // hosts: the plugin's settings live in the shell's config and are written
  // through the shell, the application owns a settings file of its own.
  // A value of 0 clears the override and returns the deck to the viewport.
  function persistScale(value) {
    // The application owns its settings file, so this is a direct write; the
    // watcher on that file feeds the new value straight back to Style.
    App.setSetting("uiScale", value)
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
        Qt.callLater(function () { root.focusPass() })
      }
    }
  }

  Process {
    id: lockProcess
    command: ["black-bag", "agent", "lock"]
    running: false
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      // Never announce a lock that did not happen. A missing agent, a dead
      // socket or a refused request used to clear the list and say "locked"
      // while the data key was still held.
      if (code !== 0) {
        var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
        root.actionError = "lock failed: " + (err.length > 0 ? err : "the agent did not confirm")
        root.actionNote = ""
        // The vault is still open, so the deck must stop showing an empty one.
        // clearSecrets() ran before the attempt; nothing else brings it back,
        // because the session never changed and no status edge follows.
        refreshProcess.running = true
        root.refreshRecords()
        return
      }
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
        // A reply that lands after the deck was closed or locked must not
        // repopulate it: titles, usernames and handles are as sensitive as
        // the vault they came from.
        if (!root.opened || !root.unlocked) return
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
      if (root.refreshPending) {
        root.refreshPending = false
        Qt.callLater(root.refreshRecords)
      }
    }
  }

  Process {
    id: copyProcess
    running: false
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
      if (code !== 0) {
        root.actionError = err.length > 0 ? err : "copy failed"
        root.actionNote = ""
        return
      }
      // The engine prints "copied … · clears in Ns" only after the compositor
      // has been seen offering the value with the sensitive hint. That line
      // is the truth about the clipboard; the footer repeats it verbatim.
      root.actionNote = err.length > 0 ? err : "copied"
    }
  }

  Process {
    id: breachProcess
    command: ["black-bag", "agent", "breach", "--online", "--json"]
    running: false
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      root.breachRunning = false
      var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
      if (code !== 0) {
        root.actionError = "breach check: " + (err.length > 0 ? err : "failed")
        root.actionNote = ""
        return
      }
      try {
        var report = JSON.parse(String(this.stdout.text || "{}"))
        var n = Number(report.checked) || 0
        var x = Model.asList(report.exposed).length
        root.actionNote = "checked " + n + " password" + (n === 1 ? "" : "s")
                        + " · " + (x === 0 ? "none seen in a breach" : x + " exposed")
                        + (Number(report.unchecked) > 0 ? " · " + report.unchecked + " not checked" : "")
      } catch (e) {
        root.actionNote = "breach check finished"
      }
      // The agent now folds exposures into hygiene; re-read it.
      if (!hygieneProcess.running) hygieneProcess.running = true
    }
  }

  Process {
    id: showProcess
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        // The selection may have moved while the agent was answering. A
        // value that arrives for a record that is no longer selected is
        // dropped on the floor, never rendered under the new name.
        if (!root.selectedRecord || String(root.selectedRecord.id) !== root.showPendingId) return
        root.revealedField = root.showPendingField
        root.revealedFor = root.showPendingId
        root.revealedValue = String(this.text || "").replace(/\n+$/, "")
        root.revealSecondsLeft = Math.max(1, root.revealSeconds)
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
        if (!root.opened || !root.unlocked) return
        try {
          root.hygiene = JSON.parse(String(this.text || "null"))
          root.hygieneError = ""
        } catch (e) {
          root.hygiene = null
          root.hygieneError = "the hygiene report could not be read"
        }
      }
    }
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      if (code !== 0) {
        root.hygiene = null
        var err = String(this.stderr && this.stderr.text ? this.stderr.text : "").trim()
        root.hygieneError = err.length > 0 ? err : "the agent did not answer"
      }
    }
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
      // A selection that moved while this was in flight asked for a code that
      // was never fetched. Pick it up now rather than leaving the card blank.
      if (root.totpWantedId.length > 0) {
        var wanted = root.totpWantedId
        root.totpWantedId = ""
        Qt.callLater(function () {
          if (root.selectedRecord && String(root.selectedRecord.id) === wanted)
            root.fetchTotp(root.selectedRecord)
        })
      }
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

  // In the plugin this is a layer-shell overlay that takes exclusive keyboard
  // focus. Here it is simply the window's content: the application already has
  // the keyboard when it is focused, and taking it exclusively from a normal
  // window would be a compositor-level grab no password manager has any
  // business asserting.
  Rectangle {
    id: win
    anchors.fill: parent
    color: Color.background

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
        enabled: root.opened && !recordEditor.open_ && !onboardSheet.open_ && !recoverSheet.open_
        context: Qt.WindowShortcut
        onActivated: root.backOut()
      }
      Shortcut {
        sequences: ["Ctrl+L"]
        enabled: root.opened && !recordEditor.open_ && !onboardSheet.open_ && !recoverSheet.open_ && root.unlocked
        context: Qt.WindowShortcut
        onActivated: root.doLock()
      }
      // Scale, live. Ctrl+0 hands it back to the viewport.
      //
      // Meta is bound alongside Ctrl because on a Mac keyboard — including one
      // driving this machine through a VM — the key people reach for is
      // Command, and Command arrives here as Meta. Binding only Ctrl would
      // make the obvious gesture do nothing. Both spellings of the plus key
      // are listed: whether shift+equals reports as Plus or as Equal depends
      // on the layout, and a zoom shortcut that works on one layout and not
      // another is worse than none.
      Shortcut {
        sequences: ["Ctrl+=", "Ctrl++", "Ctrl+Plus", "Meta+=", "Meta++", "Meta+Plus"]
        enabled: root.opened
        context: Qt.WindowShortcut
        onActivated: root.nudgeScale(0.1)
      }
      Shortcut {
        sequences: ["Ctrl+-", "Ctrl+Minus", "Meta+-", "Meta+Minus"]
        enabled: root.opened
        context: Qt.WindowShortcut
        onActivated: root.nudgeScale(-0.1)
      }
      Shortcut {
        sequences: ["Ctrl+0", "Meta+0"]
        enabled: root.opened
        context: Qt.WindowShortcut
        onActivated: root.resetScale()
      }

      Shortcut {
        sequences: ["Ctrl+R"]
        enabled: root.opened && !recordEditor.open_ && !onboardSheet.open_ && !recoverSheet.open_
        context: Qt.WindowShortcut
        onActivated: {
          refreshProcess.running = true
          if (root.unlocked) root.refreshRecords()
        }
      }
      // The way back in, from the sealed screen. Only when there is one.
      Shortcut {
        sequences: ["Ctrl+K"]
        enabled: root.opened && !root.unlocked && !recordEditor.open_
                 && !onboardSheet.open_ && !recoverSheet.open_
                 && Model.canRecover(root.status)
        context: Qt.WindowShortcut
        onActivated: recoverSheet.begin()
      }
      Shortcut {
        sequences: ["Ctrl+B"]
        enabled: root.opened && !recordEditor.open_ && !onboardSheet.open_ && !recoverSheet.open_ && root.unlocked
        context: Qt.WindowShortcut
        onActivated: root.requestBreachCheck()
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

        // Sealed, with keyCatcher holding the keys (the passphrase box hidden
        // or unfocused): the footer says ⏎ is the way in, so it is — unlock,
        // or reopen the offer to create a vault. Without this, Enter fell
        // through to "copy the selected record" with nothing selected.
        if (!root.unlocked
            && (event.key === Qt.Key_Return || event.key === Qt.Key_Enter)) {
          root.doUnlock()
          event.accepted = true
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
          root.focusPass(); event.accepted = true
        } else if (event.key === Qt.Key_Home) {
          root.selectedIndex = 0; root.clearReveal(); root.totpState = null
          root.pendingDeleteId = ""
          event.accepted = true
        } else if (event.key === Qt.Key_End) {
          root.selectedIndex = Math.max(0, root.visibleRecords.length - 1)
          root.clearReveal(); root.totpState = null
          root.pendingDeleteId = ""
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

      FieldMenu { id: fieldMenu }

      // Right-click on a record row. Every entry is a verb the keyboard
      // already has; the menu is how the mouse gets them.
      Menu {
        id: recordMenu
        property var record: null
        background: Rectangle {
          implicitWidth: root.metric.space(190)
          color: Color.background
          border.color: Util.alpha(Color.accent, 0.4)
          border.width: Math.max(1, root.metric.spacing.hairline)
          radius: root.metric.cornerRadius
        }
        FieldMenuItem {
          text: recordMenu.record
            ? "Copy " + String(root.primaryField(recordMenu.record)) : "Copy"
          onTriggered: root.copyField(recordMenu.record,
                                      root.primaryField(recordMenu.record))
        }
        FieldMenuItem {
          text: "Show for " + root.revealSeconds + "s"
          onTriggered: root.showField(recordMenu.record,
                                      root.primaryField(recordMenu.record))
        }
        FieldMenuItem {
          text: "Copy 2FA code"
          enabled: recordMenu.record ? recordMenu.record.has_totp === true : false
          onTriggered: root.copyField(recordMenu.record, "totp")
        }
        FieldMenuItem {
          text: "Edit"
          onTriggered: root.beginEdit()
        }
        FieldMenuItem {
          text: "Delete…"
          onTriggered: root.requestDelete()   // arms; the inspector asks to be sure
        }
      }

  // ── mouse paste ────────────────────────────────────────────────────────────
  //
  // Qt Quick's text controls ship with no context menu at all, which in a
  // password manager means the one thing everyone does — paste a password in
  // with the mouse — silently does nothing. Cut and copy stay disabled while
  // the field is masking its contents: a reveal has a countdown and an audit
  // trail, and a context menu must not become the quiet way around both.
  component FieldMenuItem: MenuItem {
    id: fmi
    implicitHeight: root.metric.spacing.controlHeight
    implicitWidth: root.metric.space(170)
    contentItem: Text {
      text: fmi.text
      color: fmi.enabled ? Color.foreground : Util.alpha(Color.foreground, 0.3)
      font.family: root.metric.font.family
      font.pixelSize: root.metric.font.caption
      verticalAlignment: Text.AlignVCenter
      leftPadding: root.metric.space(10)
      renderType: Text.NativeRendering
    }
    background: Rectangle {
      color: fmi.highlighted ? Util.alpha(Color.accent, 0.15) : "transparent"
    }
  }

  component FieldMenu: Menu {
    id: fmenu
    property Item target: null
    // Masked unless the target is a text input that is showing its contents.
    // A TextArea has no echoMode at all; treating "no echoMode" as unmasked
    // made Copy the quiet way around the reveal countdown for every
    // multi-line secret.
    readonly property bool masked:
      !(fmenu.target && fmenu.target.echoMode === TextInput.Normal)
    background: Rectangle {
      implicitWidth: root.metric.space(170)
      color: Color.background
      border.color: Util.alpha(Color.accent, 0.4)
      border.width: Math.max(1, root.metric.spacing.hairline)
      radius: root.metric.cornerRadius
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

      component Card: Rectangle {
        default property alias content: cardInner.data
        property color tone: Util.alpha(Color.muted, 0.45)
        property bool live: false
        Layout.fillWidth: true
        implicitHeight: cardInner.implicitHeight + metric.spacing.md * 2
        color: live ? Util.alpha(Color.accent, 0.05) : Util.alpha(Color.foreground, 0.03)
        border.color: live ? Util.alpha(Color.accent, 0.28) : tone
        border.width: 1
        radius: metric.cornerRadius
        ColumnLayout {
          id: cardInner
          anchors.fill: parent
          anchors.margins: metric.spacing.md
          spacing: metric.spacing.xs
        }
      }

      component SectionTitle: Text {
        Layout.fillWidth: true
        color: Util.alpha(Color.foreground, 0.45)
        font.family: metric.font.family
        font.pixelSize: metric.font.caption
        font.bold: true
        font.letterSpacing: metric.space(0.8)
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
        spacing: metric.spacing.sm
        Text {
          text: parent.k
          color: Util.alpha(Color.foreground, 0.55)
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
        Item { Layout.fillWidth: true }
        Text {
          Layout.maximumWidth: metric.space(210)
          text: parent.v
          color: parent.vColor
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
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
        implicitWidth: chipText.implicitWidth + metric.spacing.md * 2
        implicitHeight: chipText.implicitHeight + metric.spacing.xs * 2
        radius: height / 2
        color: Util.alpha(tone, 0.14)
        border.color: Util.alpha(tone, 0.6)
        border.width: 1
        Text {
          id: chipText
          anchors.centerIn: parent
          text: parent.label
          color: parent.tone
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
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
        width: metric.space(8)
        height: width
        radius: width / 2
        color: ok === true ? Color.accent : "transparent"
        border.color: ok === true ? Color.accent
                    : ok === false ? badTone
                    : Util.alpha(Color.foreground, 0.3)
        border.width: Math.max(1, metric.spacing.hairline)
      }

      component ActionButton: Rectangle {
        id: actionBtn
        property string label: ""
        property color tone: Color.foreground
        property bool enabledAction: true
        signal activated()
        implicitWidth: actionText.implicitWidth + metric.spacing.lg * 2
        implicitHeight: metric.spacing.controlHeight
        radius: metric.cornerRadius
        color: (mouse.containsMouse || actionBtn.activeFocus) && enabledAction
          ? Util.alpha(tone, 0.18) : Util.alpha(tone, 0.08)
        border.color: actionBtn.activeFocus ? tone : Util.alpha(tone, enabledAction ? 0.45 : 0.15)
        border.width: actionBtn.activeFocus ? Math.max(1, metric.spacing.hairline) * 2
                                            : Math.max(1, metric.spacing.hairline)
        opacity: enabledAction ? 1.0 : 0.4
        // Reachable by Tab and driven by Space or Enter, with a ring that
        // shows where the keyboard is. A mouse-only button in a keyboard-first
        // deck is half a button.
        activeFocusOnTab: true
        Accessible.role: Accessible.Button
        Accessible.name: label
        Accessible.focusable: true
        Keys.onPressed: function (event) {
          if (event.key === Qt.Key_Space || event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
            if (actionBtn.enabledAction) actionBtn.activated()
            event.accepted = true
          } else if (event.key === Qt.Key_Escape) {
            keyCatcher.forceActiveFocus()
            event.accepted = true
          }
        }
        Text {
          id: actionText
          anchors.centerIn: parent
          text: parent.label
          color: parent.tone
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
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
        anchors.margins: metric.space(16)
        spacing: metric.spacing.md
        visible: root.unlocked

        // ── header ────────────────────────────────────────────────────────────
        RowLayout {
          Layout.fillWidth: true
          spacing: metric.spacing.lg

          ColumnLayout {
            spacing: 0
            Text {
              text: "B L A C K - B A G"
              color: root.stateTone()
              font.family: metric.font.family
              font.pixelSize: metric.font.display
              font.bold: true
              font.letterSpacing: metric.space(1)
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
              Behavior on color { ColorAnimation { duration: root.motionMs } }
            }
            Text {
              text: "CREDENTIAL COMMAND DECK"
              color: Util.alpha(Color.foreground, 0.45)
              font.family: metric.font.family
              font.pixelSize: metric.font.caption
              font.letterSpacing: metric.space(1.2)
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

          readonly property real gap: metric.space(12)
          readonly property real leftW: metric.space(250)
          readonly property real rightW: metric.space(330)

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
              width: leftRail.width - metric.spacing.md
              spacing: metric.spacing.md

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
                  // All twelve kinds, always, so a zero reads as a measured
                  // zero rather than as a row that happened not to be drawn.
                  model: root.unlocked ? Model.census(agentCounts()) : []
                  delegate: RowLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    spacing: metric.spacing.sm
                    Text {
                      text: modelData.glyph
                      color: modelData.count > 0
                        ? Color.accent : Util.alpha(Color.foreground, 0.3)
                      font.family: metric.font.family
                      font.pixelSize: metric.font.caption
                      renderType: Text.NativeRendering
                    }
                    Text {
                      text: modelData.kind
                      color: root.filterKind === modelData.kind
                        ? Color.accent : Util.alpha(Color.foreground, 0.7)
                      font.family: metric.font.family
                      font.pixelSize: metric.font.caption
                      font.bold: root.filterKind === modelData.kind
                      textFormat: Text.PlainText
                      renderType: Text.NativeRendering
                    }
                    Item { Layout.fillWidth: true }
                    Text {
                      text: String(modelData.count)
                      color: modelData.count > 0
                        ? Color.foreground : Util.alpha(Color.foreground, 0.3)
                      font.family: metric.font.family
                      font.pixelSize: metric.font.caption
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
                        // Changing the filter is list navigation; the list
                        // keys must work immediately afterwards, even if the
                        // caret was in the search box.
                        keyCatcher.forceActiveFocus()
                      }
                    }
                  }
                }
                Text {
                  visible: !root.unlocked
                  Layout.fillWidth: true
                  text: "record counts are only known while unlocked"
                  color: Util.alpha(Color.foreground, 0.35)
                  font.family: metric.font.family
                  font.pixelSize: metric.font.caption
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
                      spacing: metric.spacing.sm
                      Dot { ok: modelData.external === true ? true : null }
                      Text {
                        text: modelData.label
                        color: Color.foreground
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
                        font.bold: true
                        textFormat: Text.PlainText
                        renderType: Text.NativeRendering
                      }
                      Item { Layout.fillWidth: true }
                      Text {
                        text: modelData.external ? "OFFLINE KEY" : "PASSPHRASE"
                        color: modelData.external
                          ? Color.accent : Util.alpha(Color.foreground, 0.55)
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
                        renderType: Text.NativeRendering
                      }
                    }
                    Text {
                      Layout.fillWidth: true
                      Layout.leftMargin: metric.space(13)
                      text: modelData.note
                      color: Util.alpha(Color.foreground, 0.35)
                      font.family: metric.font.family
                      font.pixelSize: metric.font.caption
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
                  font.family: metric.font.family
                  font.pixelSize: metric.font.caption
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
                      spacing: metric.spacing.sm
                      Dot {
                        ok: modelData.ok
                        badTone: root.severityTone(modelData.severity)
                      }
                      Text {
                        text: modelData.label
                        color: Util.alpha(Color.foreground, 0.7)
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
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
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
                        font.bold: modelData.ok === false && modelData.severity === "alert"
                        textFormat: Text.PlainText
                        renderType: Text.NativeRendering
                      }
                    }
                    // The explanation gets its own full-width line rather than
                    // being elided mid-word off the end of the value.
                    Text {
                      Layout.fillWidth: true
                      Layout.leftMargin: metric.space(8) + metric.spacing.sm
                      visible: String(modelData.detail || "").length > 0
                      text: modelData.detail
                      color: Util.alpha(Color.foreground, 0.35)
                      font.family: metric.font.family
                      font.pixelSize: metric.font.caption
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
              spacing: metric.spacing.md
              visible: root.unlocked

              RowLayout {
                Layout.fillWidth: true
                spacing: metric.spacing.md
                InputField {
                  id: searchField
          TapHandler {
            acceptedButtons: Qt.RightButton
            onTapped: {
              searchField.forceActiveFocus()
              fieldMenu.target = searchField
              fieldMenu.popup()
            }
          }
                  font.pixelSize: root.metric.font.body
                  topPadding: root.metric.spacing.inputPaddingY
                  bottomPadding: root.metric.spacing.inputPaddingY
                  leftPadding: root.metric.spacing.controlPaddingX
                  rightPadding: root.metric.spacing.controlPaddingX
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
                    onClicked: {
                      root.filterKind = ""
                      root.selectedIndex = 0
                      keyCatcher.forceActiveFocus()
                    }
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
                radius: metric.cornerRadius
                clip: true

                ListView {
                  id: recordList
                  anchors.fill: parent
                  anchors.margins: metric.spacing.xs
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
                    height: metric.space(42)
                    Accessible.role: Accessible.ListItem
                    Accessible.name: Model.recordLabel(modelData) + ", " + String(modelData.kind)
                                     + (modelData.has_totp ? ", with a 2FA code" : "")
                    Accessible.selected: index === root.selectedIndex
                    color: index === root.selectedIndex
                      ? Util.alpha(Color.accent, 0.12)
                      : (rowMouse.containsMouse
                         ? Util.alpha(Color.foreground, 0.06) : "transparent")
                    radius: metric.cornerRadius

                    Rectangle {
                      visible: index === root.selectedIndex
                      anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
                      width: metric.space(3)
                      color: Color.accent
                      radius: width / 2
                    }

                    RowLayout {
                      anchors.fill: parent
                      anchors.leftMargin: metric.spacing.md
                      anchors.rightMargin: metric.spacing.md
                      spacing: metric.spacing.md

                      Text {
                        text: Model.kindGlyph(modelData.kind)
                        color: index === root.selectedIndex
                          ? Color.accent : Util.alpha(Color.foreground, 0.6)
                        font.family: metric.font.family
                        font.pixelSize: metric.font.body
                        renderType: Text.NativeRendering
                      }

                      ColumnLayout {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignVCenter
                        spacing: metric.space(1)
                        Text {
                          Layout.fillWidth: true
                          text: Model.recordLabel(modelData)
                          color: Color.foreground
                          font.family: metric.font.family
                          font.pixelSize: metric.font.bodySmall
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
                          font.family: metric.font.family
                          font.pixelSize: metric.font.caption
                          elide: Text.ElideRight
                          textFormat: Text.PlainText
                          renderType: Text.NativeRendering
                        }
                      }

                      Text {
                        Layout.preferredWidth: metric.space(14)
                        opacity: modelData.has_totp ? 1 : 0
                        text: "⧗"
                        color: Color.accent
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
                        renderType: Text.NativeRendering
                      }

                      Text {
                        Layout.preferredWidth: metric.space(64)
                        horizontalAlignment: Text.AlignRight
                        text: Model.fmtAgo(modelData.updated_at, root.nowMs)
                        color: Util.alpha(Color.foreground, 0.35)
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
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
                    TapHandler {
                      acceptedButtons: Qt.RightButton
                      onTapped: {
                        // Same housekeeping as a left click: the menu acts on
                        // the selected record, so selection comes first.
                        root.selectedIndex = index
                        root.pendingDeleteId = ""
                        root.clearReveal()
                        keyCatcher.forceActiveFocus()
                        recordMenu.record = modelData
                        recordMenu.popup()
                      }
                    }
                  }
                }

                Text {
                  anchors.centerIn: parent
                  visible: root.visibleRecords.length === 0
                  text: root.listing
                    ? "reading…"
                    : (root.records.length === 0
                       ? "no records in this vault — press n to add one"
                       : "nothing matches this filter")
                  color: Util.alpha(Color.foreground, 0.55)
                  font.family: metric.font.family
                  font.pixelSize: metric.font.caption
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
              width: rightRail.width - metric.spacing.md
              spacing: metric.spacing.md

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
                  font.family: metric.font.family
                  font.pixelSize: metric.font.subtitle
                  font.bold: true
                  wrapMode: Text.WordWrap
                  textFormat: Text.PlainText
                  renderType: Text.NativeRendering
                }

                // Record-level actions, reachable by mouse. Everything here
                // has a key too (e, del) — but a lifecycle you can only drive
                // from the keyboard is half a lifecycle.
                RowLayout {
                  Layout.fillWidth: true
                  visible: root.selectedRecord !== null
                  spacing: metric.spacing.sm
                  ActionButton {
                    label: "EDIT"
                    tone: Util.alpha(Color.foreground, 0.7)
                    onActivated: root.beginEdit()
                  }
                  ActionButton {
                    label: root.deleteArmed ? "SURE? CLICK AGAIN" : "DELETE"
                    tone: Color.urgent
                    onActivated: root.requestDelete()
                  }
                  Item { Layout.fillWidth: true }
                }

                // The armed confirmation, in the open. Both halves of the
                // two-step delete — key and click — arm and confirm the same
                // state, so whichever hand started it, either can finish it.
                Rectangle {
                  Layout.fillWidth: true
                  visible: root.deleteArmed
                  implicitHeight: armCol.implicitHeight + metric.spacing.md
                  color: Util.alpha(Color.urgent, 0.08)
                  border.color: Util.alpha(Color.urgent, 0.5)
                  border.width: 1
                  radius: metric.cornerRadius
                  ColumnLayout {
                    id: armCol
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.margins: metric.spacing.sm
                    spacing: metric.spacing.xxs
                    Text {
                      Layout.fillWidth: true
                      text: "delete \"" + (root.selectedRecord
                              ? String(root.selectedRecord.title) : "") + "\"?"
                      color: Color.urgent
                      font.family: metric.font.family
                      font.pixelSize: metric.font.bodySmall
                      font.bold: true
                      wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                      textFormat: Text.PlainText
                      renderType: Text.NativeRendering
                    }
                    Text {
                      Layout.fillWidth: true
                      text: "no undo and no trash — del or the button confirms · esc backs out"
                      color: Util.alpha(Color.foreground, 0.55)
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
                  visible: root.selectedRecord === null
                  text: "no record selected"
                  color: Util.alpha(Color.foreground, 0.55)
                  font.family: metric.font.family
                  font.pixelSize: metric.font.caption
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
                    spacing: metric.spacing.xs

                    RowLayout {
                      Layout.fillWidth: true
                      spacing: metric.spacing.sm
                      Text {
                        text: "◆ " + modelData.name
                        color: Color.foreground
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
                        font.bold: true
                        renderType: Text.NativeRendering
                      }
                      Item { Layout.fillWidth: true }
                      Text {
                        text: modelData.handle + " · " + Model.fmtBytes(modelData.bytes)
                        color: Util.alpha(Color.foreground, 0.4)
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
                        renderType: Text.NativeRendering
                      }
                    }

                    RowLayout {
                      Layout.fillWidth: true
                      spacing: metric.spacing.sm
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
                      id: revealPanel
                      Layout.fillWidth: true
                      visible: root.revealedValue.length > 0
                               && root.revealedField === modelData.name
                               && root.selectedRecord
                               && root.revealedFor === String(root.selectedRecord.id)
                      // A countdown burning below the fold is a countdown
                      // nobody saw. Bring the panel into view when it appears.
                      onVisibleChanged: if (visible) Qt.callLater(function () {
                        var y = revealPanel.mapToItem(rightCol, 0, 0).y
                        var bottom = y + revealPanel.height
                        if (bottom > rightRail.contentY + rightRail.height)
                          rightRail.contentY = Math.max(0, Math.min(rightRail.contentHeight - rightRail.height,
                                                                   bottom - rightRail.height + metric.spacing.md))
                      })
                      implicitHeight: revealCol.implicitHeight + metric.spacing.md
                      color: Util.alpha(Color.urgent, 0.08)
                      border.color: Util.alpha(Color.urgent, 0.4)
                      border.width: 1
                      radius: metric.cornerRadius

                      ColumnLayout {
                        id: revealCol
                        anchors.fill: parent
                        anchors.margins: metric.spacing.sm
                        spacing: metric.spacing.xs
                        Text {
                          Layout.fillWidth: true
                          text: root.revealedValue
                          color: Color.foreground
                          font.family: metric.font.family
                          font.pixelSize: metric.font.bodySmall
                          wrapMode: Text.WrapAnywhere
                          textFormat: Text.PlainText
                          renderType: Text.NativeRendering
                        }
                        Text {
                          Layout.fillWidth: true
                          text: "on screen for " + root.revealSecondsLeft + "s · Esc hides"
                          color: Util.alpha(Color.urgent, 0.8)
                          font.family: metric.font.family
                          font.pixelSize: metric.font.caption
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
                  implicitHeight: metric.space(64)
                  color: Util.alpha(Color.accent, 0.06)
                  border.color: Util.alpha(Color.accent, 0.3)
                  border.width: 1
                  radius: metric.cornerRadius

                  RowLayout {
                    anchors.fill: parent
                    anchors.margins: metric.spacing.md
                    spacing: metric.spacing.lg

                    Canvas {
                      id: totpArc
                      width: metric.space(40)
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
                        var stroke = Math.max(2, metric.space(3))
                        var r = Math.min(cx, cy) - stroke
                        ctx.lineWidth = stroke
                        ctx.strokeStyle = Util.alpha(Color.foreground, 0.15)
                        ctx.beginPath()
                        ctx.arc(cx, cy, r, 0, Math.PI * 2)
                        ctx.stroke()

                        var left = 1 - progress
                        var secondsLeft = root.liveTotp
                          ? Math.max(0, root.liveTotp.ttl - (root.nowMs - root.liveTotp.at) / 1000) : 0
                        // Red for the last five seconds, whatever the step.
                        ctx.strokeStyle = Model.totpUrgent(secondsLeft) ? Color.urgent : Color.accent
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
                        font.family: metric.font.family
                        font.pixelSize: metric.font.display
                        font.bold: true
                        font.letterSpacing: metric.space(2)
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
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
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

              // Credential hygiene — computed locally. The breach check below
              // is the one act that goes online, and only on request.
              Card {
                visible: root.unlocked
                SectionTitle {
                  text: {
                    if (root.hygieneError.length > 0) return "HYGIENE — UNAVAILABLE"
                    if (!root.hygiene) return hygieneProcess.running ? "HYGIENE — READING" : "HYGIENE"
                    var n = Model.hygieneCount(root.hygiene)
                    return "HYGIENE — " + (n === 0 ? "CLEAN" : n + " ISSUE" + (n === 1 ? "" : "S"))
                  }
                }

                Text {
                  Layout.fillWidth: true
                  visible: root.hygieneError.length > 0
                  text: root.hygieneError
                  color: Color.urgent
                  font.family: metric.font.family
                  font.pixelSize: metric.font.caption
                  wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                  textFormat: Text.PlainText
                  renderType: Text.NativeRendering
                }

                Text {
                  Layout.fillWidth: true
                  visible: root.hygiene !== null && Model.hygieneCount(root.hygiene) === 0
                  text: "every rule passed on " + (root.hygiene ? root.hygiene.scanned : 0)
                      + " record(s)"
                  color: Color.accent
                  font.family: metric.font.family
                  font.pixelSize: metric.font.caption
                  textFormat: Text.PlainText
                  renderType: Text.NativeRendering
                }

                Repeater {
                  model: root.hygiene ? Model.sortHygiene(root.hygiene) : []
                  delegate: ColumnLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    spacing: 0

                    RowLayout {
                      Layout.fillWidth: true
                      spacing: metric.spacing.sm
                      Text {
                        text: Model.kindGlyph(modelData.kind)
                        color: Util.alpha(Color.foreground, 0.5)
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
                        renderType: Text.NativeRendering
                      }
                      Text {
                        Layout.fillWidth: true
                        text: Model.orDash(modelData.title)
                        color: Util.alpha(Color.foreground, 0.8)
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
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
                        Layout.leftMargin: metric.space(14)
                        text: Model.hygieneLine(modelData)
                        color: root.severityTone(Model.hygieneSeverity(modelData))
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
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
                        // A finding for a record the current filter hides
                        // used to be a dead click. Drop the filter, then find it.
                        var wanted = String(modelData.id)
                        var list = root.visibleRecords
                        var found = -1
                        for (var i = 0; i < list.length; i++)
                          if (String(list[i].id) === wanted) { found = i; break }
                        if (found < 0) {
                          root.filterKind = ""
                          searchField.text = ""
                          list = root.visibleRecords
                          for (var j = 0; j < list.length; j++)
                            if (String(list[j].id) === wanted) { found = j; break }
                        }
                        if (found >= 0) {
                          root.selectedIndex = found
                          root.clearReveal()
                          root.totpState = null
                          if (root.selectedRecord && root.selectedRecord.has_totp)
                            root.fetchTotp(root.selectedRecord)
                        }
                        keyCatcher.forceActiveFocus()
                      }
                    }
                  }
                }

                // The breach check. Armed, explained, then run — never on a
                // single press, because it is the one thing here that goes
                // online.
                RowLayout {
                  Layout.fillWidth: true
                  Layout.topMargin: metric.spacing.xs
                  spacing: metric.spacing.sm
                  ActionButton {
                    label: root.breachRunning ? "CHECKING…"
                         : (root.breachArmed ? "SURE? CHECK ONLINE" : "CHECK BREACHES")
                    tone: root.breachArmed ? Color.urgent : Util.alpha(Color.foreground, 0.7)
                    enabledAction: root.unlocked && !root.breachRunning
                    onActivated: root.requestBreachCheck()
                  }
                  Item { Layout.fillWidth: true }
                }
                Text {
                  Layout.fillWidth: true
                  visible: root.breachArmed
                  text: "sends the first 5 characters of each password's SHA-1 to haveibeenpwned.com "
                      + "(k-anonymity: it cannot learn which password you hold) · the full hash never "
                      + "leaves the agent · ^B or the button confirms · esc backs out"
                  color: Util.alpha(Color.urgent, 0.9)
                  font.family: metric.font.family
                  font.pixelSize: metric.font.caption
                  wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                  textFormat: Text.PlainText
                  renderType: Text.NativeRendering
                }
                Text {
                  Layout.fillWidth: true
                  visible: !root.breachArmed
                  text: root.hygiene && Model.exposedCount(root.hygiene) > 0
                    ? Model.exposedCount(root.hygiene) + " password(s) seen in known breaches — change them"
                    : "computed on this machine · only the breach check goes online, and only when you ask"
                  color: root.hygiene && Model.exposedCount(root.hygiene) > 0
                    ? Color.urgent : Util.alpha(Color.foreground, 0.55)
                  font.family: metric.font.family
                  font.pixelSize: metric.font.caption
                  wrapMode: Text.WrapAtWordBoundaryOrAnywhere
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
                Text {
                  Layout.fillWidth: true
                  visible: Model.sortFindings(root.status).length === 0
                  text: root.status ? "nothing to report" : "no status yet"
                  color: Util.alpha(Color.foreground, 0.55)
                  font.family: metric.font.family
                  font.pixelSize: metric.font.caption
                  textFormat: Text.PlainText
                  renderType: Text.NativeRendering
                }
                Repeater {
                  model: Model.sortFindings(root.status)
                  delegate: ColumnLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    spacing: 0
                    RowLayout {
                      Layout.fillWidth: true
                      spacing: metric.spacing.sm
                      Text {
                        text: Model.severityMark(modelData.severity)
                        color: root.severityTone(modelData.severity)
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
                        font.bold: true
                        renderType: Text.NativeRendering
                      }
                      Text {
                        Layout.fillWidth: true
                        text: modelData.title
                        color: root.severityTone(modelData.severity)
                        font.family: metric.font.family
                        font.pixelSize: metric.font.caption
                        font.bold: modelData.severity === "alert"
                        wrapMode: Text.WordWrap
                        textFormat: Text.PlainText
                        renderType: Text.NativeRendering
                      }
                    }
                    Text {
                      Layout.fillWidth: true
                      Layout.leftMargin: metric.space(14)
                      visible: String(modelData.detail).length > 0
                      text: modelData.detail
                      color: Util.alpha(Color.foreground, 0.4)
                      font.family: metric.font.family
                      font.pixelSize: metric.font.caption
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
                Repeater {
                  model: Model.sessionRows(root.status, root.nowMs)
                  delegate: ColumnLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    spacing: 0
                    KV {
                      k: modelData.k
                      v: modelData.v
                      vColor: modelData.ok === false ? Color.urgent
                            : modelData.ok === true ? Color.accent : Color.foreground
                    }
                    Text {
                      Layout.fillWidth: true
                      visible: String(modelData.detail || "").length > 0
                      text: String(modelData.detail || "")
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
                  Layout.topMargin: metric.spacing.xs
                  spacing: metric.spacing.sm
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
          spacing: metric.spacing.lg

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
            font.family: metric.font.family
            font.pixelSize: metric.font.caption
            renderType: Text.NativeRendering
          }

          Text {
            visible: root.actionNote.length > 0 && root.actionError.length === 0
            text: root.actionNote
            color: Color.accent
            font.family: metric.font.family
            font.pixelSize: metric.font.caption
            renderType: Text.NativeRendering
          }

          Text {
            visible: root.actionError.length > 0
            Layout.fillWidth: true
            text: root.actionError
            color: Color.urgent
            font.family: metric.font.family
            font.pixelSize: metric.font.caption
            maximumLineCount: 2
            wrapMode: Text.WrapAtWordBoundaryOrAnywhere
            elide: Text.ElideRight
            renderType: Text.NativeRendering
          }

          Item { Layout.fillWidth: true }

          Text {
            text: root.unlocked
              ? "n new · e edit · del remove · / search · ↑↓ move · ⏎ copy · ⇧⏎ show · ^B breaches · ^L lock · esc close"
              : "⏎ unlock · esc close"
            color: Util.alpha(Color.foreground, 0.55)
            font.family: metric.font.family
            font.pixelSize: metric.font.caption
            renderType: Text.NativeRendering
          }
        }
      }

      // ── record editor ─────────────────────────────────────────────────────
      // Last child, so it paints over the deck and the sealed screen alike.
      Editor {
        id: recordEditor
        motionMs: root.motionMs
        uiScale: root.uiScale
        revealSeconds: root.revealSeconds
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
        // Both terms scale now: the fraction keeps it from spanning a wide
        // display, and the cap grows with the deck's own metric instead of
        // pinning the login screen to a fixed 520px however large the screen.
        readonly property real colW: Math.min(width * 0.5, metric.space(560))
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
          height: Math.max(1, metric.spacing.hairline)
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
            // With motion off the whole rule lights up and holds still; the
            // "deriving key…" line below carries the message.
            width: root.motionEnabled ? parent.width * 0.3 : parent.width
            x: root.motionEnabled ? x : 0
            height: parent.height
            color: Color.accent
            SequentialAnimation on x {
              running: root.unlocking && root.motionEnabled
              loops: Animation.Infinite
              NumberAnimation { from: 0; to: rule.width * 0.7; duration: 900
                                easing.type: Easing.InOutQuad }
              NumberAnimation { from: rule.width * 0.7; to: 0; duration: 900
                                easing.type: Easing.InOutQuad }
            }
          }
        }

        // FIELD — sits directly on the rule.
        InputField {
          id: passField
          TapHandler {
            acceptedButtons: Qt.RightButton
            onTapped: {
              passField.forceActiveFocus()
              fieldMenu.target = passField
              fieldMenu.popup()
            }
          }
          font.pixelSize: root.metric.font.body
          topPadding: root.metric.spacing.inputPaddingY
          bottomPadding: root.metric.spacing.inputPaddingY
          leftPadding: root.metric.spacing.controlPaddingX
          rightPadding: root.metric.spacing.controlPaddingX
          width: sealed.colW
          x: rule.x
          anchors.bottom: rule.top
          anchors.bottomMargin: metric.space(6)
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
          anchors.bottomMargin: metric.space(40)
          text: "B L A C K - B A G"
          color: sealed.alerting ? Color.urgent
               : (sealed.verdict.stale ? root.fg(0.4) : Util.alpha(Color.foreground, 0.85))
          font.family: metric.font.family
          font.pixelSize: metric.font.display
          font.bold: true
          font.letterSpacing: metric.spaceReal(1)
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          Behavior on color { ColorAnimation { duration: root.motionMs } }
        }

        // HAZARD — grows upward from the wordmark. Absent when there is nothing
        // to say, which is the entire source of its authority.
        ColumnLayout {
          width: Math.min(parent.width * 0.7, metric.space(760))
          anchors.horizontalCenter: parent.horizontalCenter
          anchors.bottom: sealedMark.top
          anchors.bottomMargin: metric.space(32)
          spacing: metric.space(6)
          visible: sealed.verdict.headline.length > 0

          Text {
            Layout.fillWidth: true
            text: (sealed.alerting ? "!!  " : "") + sealed.verdict.headline
            color: sealed.hazardTone
            font.family: metric.font.family
            font.pixelSize: metric.font.heading
            font.bold: true
            font.letterSpacing: metric.spaceReal(0.6)
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
            font.family: metric.font.family
            font.pixelSize: metric.font.caption
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
          anchors.topMargin: metric.space(14)
          spacing: metric.space(4)

          RowLayout {
            Layout.fillWidth: true
            spacing: metric.space(12)
            Text {
              text: sealed.verdict.identity
              color: sealed.verdict.hasVault
                ? Util.alpha(Color.foreground, 0.6) : Util.alpha(Color.foreground, 0.25)
              font.family: metric.font.family
              font.pixelSize: metric.font.caption
              font.letterSpacing: metric.spaceReal(0.4)
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
            }
            Text {
              visible: sealed.verdict.witness.length > 0
              text: "·"
              color: Util.alpha(Color.foreground, 0.25)
              font.family: metric.font.family
              font.pixelSize: metric.font.caption
              renderType: Text.NativeRendering
            }
            Text {
              visible: sealed.verdict.witness.length > 0
              text: sealed.verdict.witness
              color: sealed.witnessTone()
              font.family: metric.font.family
              font.pixelSize: metric.font.caption
              font.bold: sealed.verdict.witnessTone === "bad"
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
            }
            Item { Layout.fillWidth: true }
            Text {
              visible: sealed.verdict.stale
              text: "status " + sealed.verdict.staleFor
              color: Util.alpha(Color.foreground, 0.3)
              font.family: metric.font.family
              font.pixelSize: metric.font.caption
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
            }
          }

          // One slot, four states — the idiom Omarchy's own lock screen uses.
          // The note is how "locked before suspend" reaches the sealed screen.
          Text {
            Layout.fillWidth: true
            visible: text.length > 0
            text: root.unlocking ? "deriving key…"
                : (root.actionError.length > 0 ? root.actionError : root.actionNote)
            color: root.unlocking ? Util.alpha(Color.accent, 0.8)
                 : (root.actionError.length > 0 ? Color.urgent : Util.alpha(Color.foreground, 0.6))
            font.family: metric.font.family
            font.pixelSize: metric.font.caption
            wrapMode: Text.WrapAtWordBoundaryOrAnywhere
            textFormat: Text.PlainText
            renderType: Text.NativeRendering
          }

          // The way back in. Shown only when this vault actually has a
          // recipient whose key is held outside it — the deck used to be
          // able to *mint* a recovery key in first run and then had no way
          // to use one, which locked a GUI-only owner out of their own vault
          // while they were holding the thing that opens it.
          Text {
            Layout.fillWidth: true
            Layout.topMargin: metric.space(4)
            visible: sealed.verdict.hasVault && !root.unlocking
                     && Model.canRecover(root.status)
            text: "forgotten it?  unlock with a recovery key  ·  ^K"
            color: Util.alpha(Color.accent, recoverHover.hovered ? 1.0 : 0.55)
            font.family: metric.font.family
            font.pixelSize: metric.font.caption
            textFormat: Text.PlainText
            renderType: Text.NativeRendering
            Accessible.role: Accessible.Button
            Accessible.name: "unlock with a recovery key"
            HoverHandler { id: recoverHover; cursorShape: Qt.PointingHandCursor }
            TapHandler { onTapped: recoverSheet.begin() }
          }
        }

        Text {
          anchors.horizontalCenter: parent.horizontalCenter
          anchors.bottom: parent.bottom
          anchors.bottomMargin: metric.space(28)
          text: {
            if (!root.status || root.status.vault_present !== true)
              return "⏎ create a vault  ·  esc close  ·  ⌘/ctrl +− size"
            if (!sealed.verdict.hasVault) return "esc close"
            if (sealed.blocked) return "detach the debugger to continue  ·  esc close"
            if (Model.canRecover(root.status))
              return "⏎ " + sealed.verdict.verb
                   + "  ·  ^K recovery key  ·  esc close  ·  ⌘/ctrl +− size"
            // Advertised here because this is the screen people meet first,
            // and a surface that is the wrong size is only fixable by someone
            // who knows it can be resized.
            return "⏎ " + sealed.verdict.verb + "  ·  esc close  ·  ⌘/ctrl +− size"
          }
          color: Util.alpha(Color.foreground, 0.35)
          font.family: metric.font.family
          font.pixelSize: metric.font.caption
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
        }
      }

    // ── the way back in ───────────────────────────────────────────────────
    // Offered only when status.json actually lists a recipient whose private
    // key is held outside the vault. A deck that invites you to recover a
    // vault that cannot be recovered is worse than one that stays quiet.
    Recover {
      id: recoverSheet
      motionMs: root.motionMs
      uiScale: root.uiScale
      homeDir: root.homeDir
      recoverableLabels: Model.recoverableLabels(root.status)

      // `recovery use` has just proved this passphrase opens the file, so the
      // deck unlocks with it rather than asking a second time.
      onRecovered: function (passphrase) {
        refreshProcess.running = true
        if (passphrase.length > 0) {
          root.passphrase = passphrase
          root.beginUnlock()
        } else {
          Qt.callLater(function () { root.focusPass() })
        }
      }
      onDismissed: Qt.callLater(function () { root.focusPass() })
    }

    // ── first run ─────────────────────────────────────────────────────────
    Onboard {
      id: onboardSheet
      motionMs: root.motionMs
      uiScale: root.uiScale

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
          Qt.callLater(function () { root.focusPass() })
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
