#!/usr/bin/env bash
# Build and install the standalone BLACK-BAG desktop application.
#
#   * checks that the `black-bag` engine is on PATH, because the application
#     is a renderer and has nothing to render without it
#   * configures and builds with CMake
#   * installs the binary, the desktop entry, the icon and the AppStream
#     metadata under ~/.local (no root, no system directories)
#
# Idempotent: run it again after a pull and it rebuilds in place.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
BUILD="${BUILD_DIR:-$HERE/build}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

echo "BLACK-BAG desktop → $PREFIX"

# 1. The engine must exist before a surface over it is worth installing.
if ! command -v black-bag >/dev/null 2>&1; then
  echo "  ! black-bag is not on PATH."
  echo "    Build and install the engine first:"
  echo "      cd $(dirname "$HERE") && cargo build --release"
  echo "      install -Dm755 target/release/black-bag ~/.local/bin/black-bag"
  exit 1
fi
echo "  engine: $(command -v black-bag) ($(black-bag --version 2>/dev/null | head -1))"

# 2. Toolchain. Only cmake is probed here: the configure step below reports a
#    missing Qt component far more usefully than a probe of our own could, and
#    a probe run from the source directory leaves a CMakeFiles/ behind.
command -v cmake >/dev/null 2>&1 || { echo "  ! cmake is required"; exit 1; }

# 3. The two surfaces share Cockpit.qml, Editor.qml and Model.js. Regenerating
#    is cheap; discovering months later that a fix reached only one of them is
#    not.
if command -v python3 >/dev/null 2>&1; then
  python3 "$HERE/port-from-plugin.py" --check || {
    echo "  ! desktop QML is out of date with the plugin"
    echo "    run: python3 $HERE/port-from-plugin.py"
    exit 1
  }
fi

# 4. Build.
cmake -S "$HERE" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" || exit 1
cmake --build "$BUILD" -j "$JOBS" || exit 1
cmake --install "$BUILD" >/dev/null || exit 1
echo "  installed: $PREFIX/bin/blackbag-desktop"

# 5. Make the launcher and the icon theme aware of it now rather than at the
#    next login.
command -v update-desktop-database >/dev/null 2>&1 \
  && update-desktop-database "$PREFIX/share/applications" >/dev/null 2>&1 \
  && echo "  launcher: desktop database updated"
command -v gtk-update-icon-cache >/dev/null 2>&1 \
  && gtk-update-icon-cache -qtf "$PREFIX/share/icons/hicolor" >/dev/null 2>&1 \
  && echo "  icons: cache updated"

case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) echo "  note: $PREFIX/bin is not on PATH" ;;
esac

echo
echo "BLACK-BAG desktop installed. Launch it from the application menu, or run:"
echo "  blackbag-desktop"
echo
echo "The unlock agent holds the session, so the deck and the CLI share one"
echo "unlocked vault. Start it with:"
echo "  systemctl --user enable --now black-bag-agent"
