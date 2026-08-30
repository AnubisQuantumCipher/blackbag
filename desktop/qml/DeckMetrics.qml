import QtQuick
import BlackBag

// The deck's own type and spacing scale.
//
// Every surface here used to read the shell's Style tokens directly. Those are
// sized for a bar widget — 12px base — which is correct in a 24px-tall bar and
// far too small on a full-screen deck: the login screen ended up as a postage
// stamp in the middle of a 1920×1200 display. A full-screen surface needs its
// own scale, and it must not get one by changing the shell's, because that
// would resize the bar and every other widget along with it.
//
// So this mirrors Style's API exactly — same token names, same shapes — and
// multiplies the type and the spacing by `uiScale`. Call sites read
// `metric.font.caption` where they used to read `Style.font.caption`, and are
// otherwise untouched. Colours are deliberately NOT routed through here: the
// palette is the machine's and has nothing to do with how large the deck is.
QtObject {
  id: m

  // 1.0 means "exactly the shell's own metrics". The deck picks a larger
  // default from the viewport and the operator can override it; see Cockpit.
  property real uiScale: 1.0

  readonly property real safeScale: {
    var s = Number(m.uiScale)
    return isFinite(s) && s > 0 ? Math.max(0.5, Math.min(4.0, s)) : 1.0
  }

  readonly property int cornerRadius:
    Math.max(0, Math.round(Style.cornerRadius * m.safeScale))

  // ------------------------------------------------------------- typography
  readonly property int baseSize:
    Math.max(6, Math.round(Style.fontBaseSize * m.safeScale))

  function fontPx(mult) {
    return Math.max(1, Math.round(m.baseSize * mult))
  }

  // The multipliers are Style's own, so the deck keeps the shell's typographic
  // proportions and only changes their size.
  readonly property QtObject font: QtObject {
    readonly property string family: Style.font.family
    readonly property int baseSize: m.baseSize

    readonly property int caption: m.fontPx(0.833)
    readonly property int bodySmall: m.fontPx(0.917)
    readonly property int body: m.fontPx(1.0)
    readonly property int subtitle: m.fontPx(1.083)
    readonly property int title: m.fontPx(1.167)
    readonly property int heading: m.fontPx(1.333)
    readonly property int display: m.fontPx(2.0)
    readonly property int displayLarge: m.fontPx(2.333)
  }

  // ---------------------------------------------------------------- spacing
  //
  // Scaled with the type rather than independently: a surface whose text grew
  // and whose gutters did not is a surface that has quietly got denser.
  function spaceReal(px) {
    var n = Number(px)
    if (!isFinite(n) || n <= 0) return 0
    return Style.spaceReal(n) * m.safeScale
  }

  function space(px) {
    var n = m.spaceReal(px)
    if (n <= 0) return 0
    return Math.max(1, Math.round(n))
  }

  readonly property QtObject spacing: QtObject {
    readonly property real scale: m.safeScale

    // Hairlines stay hairlines. A 1px rule that becomes 2px at scale 1.5 reads
    // as a border rather than as a separator.
    readonly property int hairline: Math.max(1, Style.spacing.hairline)

    readonly property int xxs: m.space(2)
    readonly property int xs: m.space(3)
    readonly property int sm: m.space(4)
    readonly property int md: m.space(6)
    readonly property int lg: m.space(8)
    readonly property int xl: m.space(10)
    readonly property int xxl: m.space(12)
    readonly property int xxxl: m.space(14)
    readonly property int huge: m.space(18)

    readonly property int controlGap: m.space(8)
    readonly property int controlPaddingX: m.space(10)
    readonly property int controlPaddingY: m.space(6)
    readonly property int inputPaddingY: m.space(7)
    readonly property int controlHeight: m.space(28)
    readonly property int popupRowHeight: m.space(28)
    readonly property int rowGap: m.space(8)
    readonly property int rowPaddingX: m.space(12)
    readonly property int labelGap: m.space(4)
    readonly property int panelGap: m.space(14)
    readonly property int panelPadding: m.space(18)
  }
}
