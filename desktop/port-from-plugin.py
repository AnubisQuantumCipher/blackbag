#!/usr/bin/env python3
"""Regenerate the desktop application's ported QML from the plugin's.

Cockpit.qml, Editor.qml and Model.js are one surface with two hosts. The
plugin wraps them in a Quickshell layer-shell overlay and gets its settings
from the shell's config; the application wraps them in a window and gets its
settings from a file of its own. Nothing else differs, and nothing else is
allowed to: a fix made to one host's copy that never reaches the other is the
failure mode this script exists to make impossible.

The transformations below are the complete list of what a host is permitted to
change. Run with --check to fail when the generated output and the committed
output disagree, which is what CI does; run with no arguments to regenerate.

Source of truth is plugin/khephri.blackbag/. Never edit desktop/qml/Cockpit.qml,
desktop/qml/Editor.qml or desktop/qml/Model.js by hand -- the next run of this
script will discard the edit.
"""

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
PLUGIN = ROOT.parent / "plugin" / "khephri.blackbag"
QML = ROOT / "qml"

# Each entry is (before, after). Every one must match exactly once: a
# transformation that silently stops matching is how the two hosts drift apart
# without anyone noticing, so a miss is a hard error rather than a skip.
COCKPIT_EDITS = [
(
"""// Full-screen cockpit over the live vault. Three rules shape everything here:""",
"""// The deck itself, identical in the standalone application and in the Omarchy
// plugin: the plugin wraps this in a layer-shell overlay, the application
// wraps it in a window, and neither changes what is on screen. Three rules
// shape everything here:"""
),
(
"""import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Ui""",
"""import BlackBag"""
),
(
"""  property var shell: ({})
  property var manifest: ({})
  property bool opened: false""",
"""  // Raised when the operator asks to leave -- the ✕ chip, or Esc with nothing
  // left to back out of. The deck does not close its own window: what a
  // dismissal means belongs to whatever is hosting it.
  signal closeRequested()

  property bool opened: true"""
),
(
"""  readonly property string runtimeDir: Quickshell.env("XDG_RUNTIME_DIR") || "/tmp"
  readonly property string homeDir: Quickshell.env("HOME") || \"\"""",
"""  readonly property string runtimeDir: App.env("XDG_RUNTIME_DIR") || "/tmp"
  readonly property string homeDir: App.env("HOME") || \"\""""
),
(
"""  // The shell does not inject `settings` into overlays, and `serviceFor()` does
  // not reach our own service from here either — the overlay observes
  // `service === null`. `shell.shellConfig` is what is actually reachable, so
  // the manifest schema is resolved off that. See Model.resolvePluginSettings.
  readonly property var settings:
    Model.resolvePluginSettings(shell ? shell.shellConfig : null,
                                manifest, "khephri.blackbag")""",
"""  // In the plugin these come from the shell's config, resolved against the
  // manifest schema. A standalone application owns its own settings file, so
  // they come from ~/.config/black-bag/desktop.json instead, defaulted to the
  // same values the manifest declares — the two surfaces must not disagree
  // about how long a revealed secret stays on screen.
  readonly property var settings: Model.desktopSettings(App.settings)"""
),
(
"""  // Host-initiated end of dismissal. Must not call back into shell.hide().""",
"""  // Host-initiated end of dismissal. Must not raise closeRequested again."""
),
(
"""  // User-initiated. Routes out through the host so its bookkeeping stays right.
  function dismiss() {
    root.clearSecrets()
    if (shell && typeof shell.hide === "function") shell.hide("khephri.blackbag")
    else root.close()
  }""",
"""  // User-initiated. Everything sensitive goes first, then the host is told —
  // in that order, so a host that declines to close still leaves nothing
  // behind.
  function dismiss() {
    root.clearSecrets()
    root.closeRequested()
  }"""
),
(
"""  function persistScale(value) {
    scaleWriter.command = ["omarchy-shell", "shell", "setBarWidget",
                           "khephri.blackbag", "uiScale", String(value), "{}"]
    scaleWriter.running = true
  }

  Process {
    id: scaleWriter
    running: false
    stderr: StdioCollector { waitForEnd: true }
    onExited: function (code) {
      if (code !== 0) root.actionError = "could not save the scale"
    }
  }""",
"""  function persistScale(value) {
    // The application owns its settings file, so this is a direct write; the
    // watcher on that file feeds the new value straight back to Style.
    App.setSetting("uiScale", value)
  }"""
),
(
"""  PanelWindow {
    id: win
    visible: root.opened
    anchors { top: true; bottom: true; left: true; right: true }
    color: Color.background
    exclusionMode: ExclusionMode.Ignore
    WlrLayershell.namespace: "blackbag-cockpit"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive""",
"""  // In the plugin this is a layer-shell overlay that takes exclusive keyboard
  // focus. Here it is simply the window's content: the application already has
  // the keyboard when it is focused, and taking it exclusively from a normal
  // window would be a compositor-level grab no password manager has any
  // business asserting.
  Rectangle {
    id: win
    anchors.fill: parent
    color: Color.background"""
),
]

EDITOR_EDITS = [
(
"""import Quickshell.Io
import qs.Commons
import qs.Ui""",
"""import BlackBag"""
),
]

# The first-run sheet is deliberately host-neutral apart from its imports: it is
# handed $HOME by whichever surface owns it rather than asking the environment
# itself, so this is the whole of its port.
ONBOARD_EDITS = list(EDITOR_EDITS)

# DeckMetrics wraps the host's Style singleton, so only the import differs.
METRICS_EDITS = [
(
"""import qs.Commons""",
"""import BlackBag"""
),
]


def port(text, edits, name, rename_textfield=True):
    for before, after in edits:
        count = text.count(before)
        if count != 1:
            raise SystemExit(
                f"port-from-plugin: {name}: expected exactly one match for\n"
                f"---\n{before}\n---\nfound {count}. "
                f"The plugin changed under this script; update the edit list."
            )
        text = text.replace(before, after, 1)

    # The shell's widget kit supplies TextField; a standalone application has
    # to bring its own, and cannot call it TextField without shadowing the Qt
    # Quick Controls type it is built from.
    if not rename_textfield:
        return text
    text, n = re.subn(r'(\n\s*)TextField \{', r'\1InputField {', text)
    if n == 0:
        raise SystemExit(f"port-from-plugin: {name}: no TextField to rename")
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail if the committed output is out of date")
    args = parser.parse_args()

    generated = {
        "Cockpit.qml": port((PLUGIN / "Cockpit.qml").read_text(),
                            COCKPIT_EDITS, "Cockpit.qml"),
        "Editor.qml": port((PLUGIN / "Editor.qml").read_text(),
                           EDITOR_EDITS, "Editor.qml"),
        "Onboard.qml": port((PLUGIN / "Onboard.qml").read_text(),
                            ONBOARD_EDITS, "Onboard.qml"),
        "DeckMetrics.qml": port((PLUGIN / "DeckMetrics.qml").read_text(),
                                METRICS_EDITS, "DeckMetrics.qml",
                                rename_textfield=False),
        # Model.js is a pure library with no host coupling at all, so it
        # crosses verbatim. That is the point: it is the part both surfaces
        # share, and the plugin's test suite tests it for both.
        "Model.js": (PLUGIN / "Model.js").read_text(),
    }

    stale = []
    for name, text in generated.items():
        target = QML / name
        if target.exists() and target.read_text() == text:
            continue
        stale.append(name)
        if not args.check:
            target.write_text(text)

    if args.check:
        if stale:
            print("port-from-plugin: out of date: " + ", ".join(sorted(stale)),
                  file=sys.stderr)
            print("Run desktop/port-from-plugin.py and commit the result.",
                  file=sys.stderr)
            return 1
        print("port-from-plugin: desktop QML matches the plugin")
        return 0

    print("port-from-plugin: " + (", ".join(sorted(stale)) if stale
                                  else "already current"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
