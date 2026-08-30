pragma Singleton
import QtQuick
import BlackBag

// The metric scale: type sizes, spacing steps, corner radius.
//
// Every gap and every type step on this surface names a token here rather than
// a number picked by eye, so a user who scales `fontBaseSize` or
// `spacingScale` in the settings file scales the whole deck coherently instead
// of unevenly. The token names and their default pixel values match the
// Omarchy shell the plugin runs in, so the deck and the plugin keep the same
// proportions and a screenshot of one is a screenshot of the other.
QtObject {
  id: root

  readonly property var settings: App.settings

  function number(key, fallback) {
    var v = Number(root.settings[key])
    return isFinite(v) ? v : fallback
  }

  // ---------------------------------------------------------------- radius
  readonly property int cornerRadius: Math.max(0, Math.round(number("cornerRadius", 4)))

  // ------------------------------------------------------------- typography
  readonly property string fontFamily: {
    var f = String(root.settings.fontFamily || "")
    return f !== "" ? f : "monospace"
  }
  readonly property int fontBaseSize: Math.max(6, Math.round(number("fontBaseSize", 12)))
  readonly property real fontScale: Math.max(1 / 12, fontBaseSize / 12)

  function fontPx(mult) {
    return Math.max(1, Math.round(fontBaseSize * mult))
  }

  readonly property QtObject font: QtObject {
    readonly property string family: root.fontFamily
    readonly property int baseSize: root.fontBaseSize

    readonly property int caption: root.fontPx(0.833)       // 10
    readonly property int bodySmall: root.fontPx(0.917)     // 11
    readonly property int body: root.fontPx(1.0)            // 12
    readonly property int subtitle: root.fontPx(1.083)      // 13
    readonly property int title: root.fontPx(1.167)         // 14
    readonly property int heading: root.fontPx(1.333)       // 16
    readonly property int display: root.fontPx(2.0)         // 24
    readonly property int displayLarge: root.fontPx(2.333)  // 28
  }

  // ---------------------------------------------------------------- spacing
  //
  // Spacing tracks the font by default, because a surface whose type grew and
  // whose gutters did not is a surface that has quietly got denser.
  readonly property real spacingScale: Math.max(0.25, number("spacingScale", 1.0))
  readonly property bool spacingScaleWithFont: root.settings.spacingScaleWithFont !== false
  readonly property real effectiveSpacingScale:
    spacingScale * (spacingScaleWithFont ? fontScale : 1)

  function spaceReal(px) {
    var n = Number(px)
    if (!isFinite(n) || n <= 0) return 0
    return n * effectiveSpacingScale
  }

  function space(px) {
    var n = spaceReal(px)
    if (n <= 0) return 0
    return Math.max(1, Math.round(n))
  }

  readonly property QtObject spacing: QtObject {
    readonly property real scale: root.effectiveSpacingScale

    readonly property int hairline: root.space(1)
    readonly property int xxs: root.space(2)
    readonly property int xs: root.space(3)
    readonly property int sm: root.space(4)
    readonly property int md: root.space(6)
    readonly property int lg: root.space(8)
    readonly property int xl: root.space(10)
    readonly property int xxl: root.space(12)
    readonly property int xxxl: root.space(14)
    readonly property int huge: root.space(18)

    readonly property int controlGap: root.space(8)
    readonly property int controlPaddingX: root.space(10)
    readonly property int controlPaddingY: root.space(6)
    readonly property int inputPaddingY: root.space(7)
    readonly property int controlHeight: root.space(28)
    readonly property int popupRowHeight: root.space(28)
    readonly property int dropdownWidth: root.space(240)
    readonly property int searchablePopupMinHeight: root.space(220)
    readonly property int rowGap: root.space(8)
    readonly property int rowPaddingX: root.space(12)
    readonly property int labelGap: root.space(4)
    readonly property int panelGap: root.space(14)
    readonly property int panelPadding: root.space(18)
  }

  // The one bar token the deck still reads: the square a status glyph is
  // allotted, which sets the height of the posture strip's rows and keeps them
  // aligned with the bar widget's own.
  readonly property QtObject bar: QtObject {
    readonly property int statusSlot: root.space(21)
  }
}
