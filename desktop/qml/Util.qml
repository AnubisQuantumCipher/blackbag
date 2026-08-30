pragma Singleton
import QtQuick

// Colour arithmetic, and only colour arithmetic.
//
// The deck reaches for one operation constantly: take a palette colour and
// state it at a given strength. Every rank on this surface -- a heading against
// a caption, a live value against a dimmed one, a hairline against a border --
// is that operation rather than a second colour, which is what keeps the
// five-colour palette in Color.qml honest. Adding a sixth colour to say
// "slightly less important" would spend a colour on something opacity already
// says.
QtObject {
  function clampAlpha(value) {
    var a = Number(value)
    if (!isFinite(a)) return 1
    return Math.max(0, Math.min(1, a))
  }

  // A string is accepted because bindings routinely produce one, and a bare
  // Qt.rgba on a string silently yields black. Missing input is transparent
  // rather than opaque black for the same reason: an unset colour should
  // disappear, not paint a hole in the surface.
  function alpha(c, opacity) {
    var a = clampAlpha(opacity)
    if (!c) return Qt.rgba(0, 0, 0, a)
    if (typeof c === "string") c = Qt.color(c)
    return Qt.rgba(c.r, c.g, c.b, a)
  }
}
