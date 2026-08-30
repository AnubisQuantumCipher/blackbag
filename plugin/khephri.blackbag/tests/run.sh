#!/usr/bin/env bash
# Runs the Model.js assertions under node.
#
# Model.js is a `.pragma library` for QML, which node will not accept, so the
# pragma is stripped and assertions.js is appended into a temporary file. This
# is spliced at RUN time on purpose — an earlier version kept a baked-in copy
# of Model.js and silently tested a stale one.
set -euo pipefail
cd "$(dirname "$0")"
command -v node >/dev/null || { echo "node is required"; exit 1; }
out="$(mktemp -t blackbag-model-XXXXXX.js)"
trap 'rm -f "$out"' EXIT
sed 's/^\.pragma library//' ../Model.js > "$out"
cat assertions.js >> "$out"
node "$out"
