pragma Singleton
import QtQuick
import BlackBag

// The five colours this surface is allowed to use, and nothing else.
//
// They come from the desktop's theme when there is one, so the deck looks like
// the rest of the machine rather than inventing its own palette. A `theme`
// block in ~/.config/black-bag/desktop.json overrides any of them.
//
// The narrowness is the point. `urgent` means a hazard the engine actually
// reported -- a rollback, an unreadable vault, a failed unlock -- and is never
// spent on decoration; `accent` means unlocked and current. A palette with
// more colours in it would make both of those claims cheaper, and this is a
// surface whose whole job is to be believed about which state it is in.
QtObject {
  id: root

  readonly property var values: App.palette

  readonly property color foreground: root.values.foreground
  readonly property color background: root.values.background
  readonly property color accent: root.values.accent
  readonly property color urgent: root.values.urgent
  readonly property color muted: root.values.muted
}
