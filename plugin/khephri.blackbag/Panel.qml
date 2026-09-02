// BLACK-BAG bar widget — lock state and session countdown.
//
// Reads only $XDG_RUNTIME_DIR/black-bag/status.json, which by construction
// contains no record titles and no secrets. Left click opens the cockpit,
// right click forces a status refresh.

import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

BarWidget {
  id: root
  moduleName: "khephri.blackbag"

  readonly property color fg: bar ? bar.foreground : Color.foreground
  readonly property color urgentColor: bar ? bar.urgent : Color.urgent

  property var status: null
  property real nowMs: Date.now()

  readonly property string runtimeDir: Quickshell.env("XDG_RUNTIME_DIR") || "/tmp"
  readonly property string statusPath: runtimeDir + "/black-bag/status.json"

  readonly property int staleAfterSec: setting("staleAfterSec", 120)
  readonly property bool stale: Model.isStale(root.status, root.nowMs, root.staleAfterSec)
  readonly property string deckState: Model.deckState(root.status, root.nowMs, root.staleAfterSec)

  function setting(name, fallback) {
    var value = settings ? settings[name] : undefined
    return value === undefined || value === null ? fallback : value
  }

  // Stale desaturates rather than colouring: a status we cannot vouch for must
  // not assert "secure" or "breached" in the bar.
  function stateColor() {
    if (root.stale || !root.status) return Util.alpha(root.fg, 0.4)
    if (root.deckState === "ROLLBACK" || root.deckState === "UNREADABLE") return root.urgentColor
    if (Model.countFindings(root.status, "alert") > 0) return root.urgentColor
    if (root.deckState === "UNLOCKED") return Color.accent
    if (Model.countFindings(root.status, "warn") > 0) return Util.alpha(root.urgentColor, 0.75)
    return root.fg
  }

  function applyStatus(text) {
    try {
      var parsed = JSON.parse(String(text || ""))
      if (parsed.schema_version !== 1) return
      root.status = parsed
    } catch (e) {
      // Caught the writer mid-replace; keep the last complete document.
    }
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

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
    interval: 120
    repeat: false
    onTriggered: {
      statusFile.reload()
      root.applyStatus(statusFile.text())
    }
  }

  // 1 Hz so the session countdown actually counts down.
  Timer {
    interval: 1000
    running: true
    repeat: true
    onTriggered: root.nowMs = Date.now()
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: {
      var label = Model.barText(root.status, root.nowMs, root.staleAfterSec)
      var g = root.deckState === "UNLOCKED"
        ? String.fromCodePoint(0xF09C)
        : String.fromCodePoint(0xF023)
      return g + " " + label
    }
    slotSize: Style.bar.statusSlot
    fixedWidth: vertical ? -1
      : Math.max(slotSize, glyphPaintedWidth + Style.spaceReal(8))
    fontSize: Style.font.caption
    foreground: root.stateColor()
    tooltipText: Model.barTooltip(root.status, root.nowMs, root.staleAfterSec)
                 + "\n\nclick: cockpit · right click: refresh"
    onPressed: function (buttonCode) {
      if (buttonCode === Qt.RightButton) {
        refreshProcess.running = true
        statusApply.restart()
        return
      }
      if (root.bar && root.bar.shell)
        root.bar.shell.summon("khephri.blackbag", "{}")
    }
  }

  Process {
    id: refreshProcess
    command: ["black-bag", "status", "--publish"]
    running: false
  }
}
