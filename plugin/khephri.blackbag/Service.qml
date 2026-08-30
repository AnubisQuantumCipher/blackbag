// BLACK-BAG service — keeps status.json fresh and owns the process plumbing
// that both the bar widget and the cockpit read.
//
// The service never holds a secret. It runs `black-bag`, parses the non-secret
// JSON it prints, and hands the result to the surfaces. The one call that can
// return secret bytes (`revealToStdout`) does not pass through here.

import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model

Item {
  id: root

  property var shell: null
  property var manifest: null

  // Last complete status. Kept across a failed parse so the UI never flickers
  // to "unknown" because it caught the writer mid-rename.
  property var status: null
  property bool everLoaded: false
  property string lastError: ""

  // ── settings ───────────────────────────────────────────────────────────────
  //
  // Resolved from `shell.shellConfig`, because the shell injects `settings`
  // into bar widgets only. See Model.resolvePluginSettings for why the cockpit
  // resolves its own rather than reading them off this service.
  property var settings: ({})

  readonly property int pollIntervalSec: setting("pollIntervalSec", 5)
  readonly property int staleAfterSec: setting("staleAfterSec", 120)
  readonly property int clipboardClearSec: setting("clipboardClearSec", 30)
  readonly property int revealSeconds: setting("revealSeconds", 10)
  readonly property bool motionEnabled: setting("motionEnabled", true) === true

  function setting(name, fallback) {
    return Model.settingOf(root.settings, name, fallback)
  }

  function resolveSettings() {
    root.settings = Model.resolvePluginSettings(
      shell ? shell.shellConfig : null, manifest, "khephri.blackbag")
  }

  Component.onCompleted: Qt.callLater(resolveSettings)
  onShellChanged: Qt.callLater(resolveSettings)
  onManifestChanged: Qt.callLater(resolveSettings)
  Connections {
    target: root.shell
    ignoreUnknownSignals: true
    function onShellConfigChanged() { Qt.callLater(root.resolveSettings) }
  }

  readonly property string runtimeDir: Quickshell.env("XDG_RUNTIME_DIR") || ""
  readonly property string statusPath: (runtimeDir.length > 0 ? runtimeDir : "/tmp")
                                       + "/black-bag/status.json"

  signal statusRefreshed()
  signal lockStateChanged(bool unlocked)

  property bool lastUnlocked: false

  function applyStatus(raw) {
    var text = String(raw || "").trim()
    if (text.length === 0) return
    try {
      var parsed = JSON.parse(text)
      if (parsed.schema_version !== 1) return
      if (parsed.published_at === undefined || parsed.host === undefined) return

      root.status = parsed
      root.everLoaded = true
      root.lastError = ""

      var unlocked = !!(parsed.session && parsed.session.unlocked)
      if (unlocked !== root.lastUnlocked) {
        root.lastUnlocked = unlocked
        root.lockStateChanged(unlocked)
      }
      root.statusRefreshed()
    } catch (error) {
      // A partial read during the atomic replace. Keep the previous document.
    }
  }

  // Re-publish status.json. Cheap: this reads the vault header only and never
  // unlocks, so it can run on a timer without prompting for anything.
  function refresh() {
    if (!publishProcess.running) publishProcess.running = true
  }

  FileView {
    id: statusFile
    path: root.statusPath
    watchChanges: true
    atomicWrites: true
    printErrors: false
    onLoaded: root.applyStatus(text())
    onFileChanged: applyTimer.restart()
  }

  Timer {
    id: applyTimer
    interval: 80
    repeat: false
    onTriggered: {
      statusFile.reload()
      root.applyStatus(statusFile.text())
    }
  }

  Timer {
    interval: Math.max(2, root.pollIntervalSec) * 1000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  Process {
    id: publishProcess
    command: ["black-bag", "status", "--publish"]
    running: false
    stdout: StdioCollector { waitForEnd: true }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var text = String(this.text || "").trim()
        // `status --publish` prints the written path to stderr on success.
        if (text.length > 0 && text.indexOf("/") !== 0) root.lastError = text
      }
    }
    onExited: function (code) {
      if (code !== 0 && root.lastError.length === 0)
        root.lastError = "black-bag status exited " + code
      applyTimer.restart()
    }
  }

  // ── notifications ──────────────────────────────────────────────────────────
  // Only two things are worth interrupting the user for: a vault that appears
  // to have been rolled back, and an unlock session about to expire.

  property string notifiedRollbackFor: ""

  onStatusRefreshed: {
    if (!root.status) return
    if (root.status.rollback_suspected === true) {
      var key = String(root.status.vault_id || "") + ":" + String(root.status.epoch || "")
      if (key !== root.notifiedRollbackFor) {
        root.notifiedRollbackFor = key
        notify("BLACK-BAG — possible rollback",
               "Vault epoch " + root.status.epoch + " is behind the "
             + root.status.witness_epoch + " last seen on this machine.")
      }
    }
  }

  function notify(title, body) {
    if (notifyProcess.running) return
    notifyProcess.command = ["notify-send", "--app-name=BLACK-BAG",
                             "--urgency=critical", title, body]
    notifyProcess.running = true
  }

  Process {
    id: notifyProcess
    running: false
  }
}
