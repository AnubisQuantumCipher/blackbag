import QtQuick
import QtQuick.Controls

// A single-line text input in the deck's idiom.
//
// This exists because the plugin's fields came from the shell's own widget
// kit, which a standalone application does not have. It is deliberately a
// subclass of Qt Quick Controls' TextField rather than a reimplementation, so
// everything a caller already relies on -- text, placeholderText, accepted,
// selectByMouse, validators -- keeps working untouched, and only the painting
// is ours. It is named InputField rather than TextField because a component
// named TextField would shadow the base type it is built from.
//
// `password` is the one addition. It is a plain alias for the echo mode and
// carries no other behaviour: this control does not clear itself, does not
// time out, and does not decide when a secret has been on screen long enough.
// Those are the deck's decisions, made where the countdown is visible.
TextField {
  id: root

  property color foreground: Color.foreground
  property color accent: Color.accent
  property bool password: false
  property real horizontalPadding: Style.spacing.controlPaddingX
  property real verticalPadding: Style.spacing.inputPaddingY

  readonly property bool focused: activeFocus

  echoMode: password ? TextInput.Password : TextInput.Normal
  font.family: Style.font.family
  font.pixelSize: Style.font.body
  color: foreground
  selectionColor: Util.alpha(accent, 0.35)
  selectedTextColor: foreground
  placeholderTextColor: Util.alpha(foreground, 0.35)
  selectByMouse: true

  leftPadding: horizontalPadding
  rightPadding: horizontalPadding
  topPadding: verticalPadding
  bottomPadding: verticalPadding

  background: Rectangle {
    radius: Style.cornerRadius
    color: root.focused ? Util.alpha(root.accent, 0.10)
         : (root.hovered ? Util.alpha(root.foreground, 0.08)
                         : Util.alpha(root.foreground, 0.05))
    border.width: Math.max(1, Style.spacing.hairline)
    border.color: root.focused ? Util.alpha(root.accent, 0.65)
                               : Util.alpha(root.foreground, 0.15)

    Behavior on color { ColorAnimation { duration: 120 } }
    Behavior on border.color { ColorAnimation { duration: 120 } }
  }
}
