#!/usr/bin/env python3
"""Invariants about the deck's QML that a reader cannot hold in their head.

These are not style rules. Each one is here because breaking it caused a real
failure that the type checker, the linter and the unit tests all let through.
Run with no arguments; a violation is a non-zero exit and a sentence saying
which rule broke and why the rule exists.
"""

import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
PLUGIN = HERE.parent
FAILURES = []


def fail(rule, detail):
    FAILURES.append((rule, detail))


def strip_comments(text):
    """QML with comments blanked and string literals kept, lengths preserved.

    Written as a scanner rather than a regex because the rules below must not
    fire on a comment that MENTIONS the thing they forbid — every one of these
    rules is explained in a comment right next to the code it governs, so a
    naive search matches its own documentation.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            for _ in range(2):
                if i < n:
                    out[i] = " "
                    i += 1
        elif c in "\"'":
            quote = c
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\":
                    i += 1
                i += 1
            i += 1
        else:
            i += 1
    return "".join(out)


def body_of(source, name):
    """The text of a `function name(...) { ... }`, braces balanced."""
    m = re.search(r"function\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{", source)
    if not m:
        return None
    i = m.end() - 1
    depth = 0
    for j in range(i, len(source)):
        if source[j] == "{":
            depth += 1
        elif source[j] == "}":
            depth -= 1
            if depth == 0:
                return source[i : j + 1]
    return None


# Every rule below reads the stripped text. Each one is explained in a comment
# sitting beside the code it governs, so a rule matching raw source would find
# its own documentation and either fire on it or be satisfied by it.
cockpit = strip_comments((PLUGIN / "Cockpit.qml").read_text())

# 1. One sheet may not tear down another.
#
# A stray `cancelApproval()` lived in this function. The agent republishes
# status on every state change, so any refresh with no passkey ceremony
# waiting — including the deck's own thirty-second safety net — dismissed the
# record approval sheet. It vanished mid-passphrase, the gate below reopened,
# and the rest of a MASTER PASSPHRASE went to the deck as shortcuts: `e` opened
# the record editor and the remaining characters were typed into a record
# field. Nothing about the passkey queue may reach across to that sheet.
sync = body_of(cockpit, "syncConsent")
if sync is None:
    fail("syncConsent exists", "the function was renamed; update this check")
elif "pendingApproval" in sync:
    fail(
        "syncConsent must not touch the approval sheet",
        "the passkey queue cancelled a record approval somebody was typing into",
    )

# 2. A sheet that owns the keyboard owns all of it.
#
# The deck's own map has plain letters in it — `e` edits, `n` adds, Return
# copies. While the approval sheet is up they must be dead, and the gate has to
# come FIRST, before any branch that could act.
keys = re.search(r"Keys\.onPressed:\s*function\s*\([^)]*\)\s*\{", cockpit)
if not keys:
    fail("the deck has a key handler", "Keys.onPressed was not found in Cockpit.qml")
else:
    after = cockpit[keys.end() : keys.end() + 1200]
    gate = after.find("root.pendingApproval !== null")
    if gate < 0:
        fail(
            "the key handler gates on the approval sheet",
            "plain letters would reach the deck while a passphrase is being typed",
        )
    else:
        for earlier in ("Qt.Key_E", "Qt.Key_N", "Qt.Key_T", "Qt.Key_Return"):
            at = after.find(earlier)
            if 0 <= at < gate:
                fail(
                    "the approval gate comes first",
                    f"{earlier} is handled before the sheet is checked",
                )

# 3. A passphrase never crosses in argv.
#
# /proc/<pid>/cmdline is world-readable. Every passphrase in this project goes
# in on stdin, which is why the engine has no --passphrase flag to call.
for qml in sorted(PLUGIN.glob("*.qml")):
    # Comments only: a real flag has to appear in a string to be passed, and
    # blanking comments is what keeps this rule from matching the paragraph
    # written next to the code that obeys it.
    text = strip_comments(qml.read_text())
    for m in re.finditer(r"--pass\w*", text):
        fail(
            "no passphrase in argv",
            f"{qml.name} builds a command with {m.group(0)}; argv is world-readable",
        )

# 4. Approving is proved, not clicked.
#
# A same-uid process can synthesise a click with wtype or hyprctl, so the
# approval sheet must send a passphrase on stdin and the engine must be asked
# with --approve. If either disappears, an approval has stopped costing
# anything.
if "--approve" not in cockpit:
    fail("approvals are proved", "no --approve call remains in the deck")
if "stdinEnabled" not in cockpit:
    fail("approvals are proved", "the approval process no longer writes to stdin")

for rule, detail in FAILURES:
    print(f"FAIL  {rule}\n      {detail}")
print(f"\n{len(FAILURES)} failure(s)" if FAILURES else "\nALL PASS")
sys.exit(1 if FAILURES else 0)
