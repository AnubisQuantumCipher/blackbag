#!/usr/bin/env bash
# Install Black-Bag's passkey provider into the Chromium-family browsers on this
# machine.
#
# Two pieces have to line up:
#   * the extension, loaded unpacked from this directory;
#   * a native-messaging host manifest naming the extension id and pointing at
#     `black-bag passkey-host`.
#
# The extension id is pinned by the public key in manifest.json rather than
# derived from wherever the directory happens to live, so this manifest stays
# correct if the checkout moves.
set -uo pipefail

EXT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_NAME="com.khephri.blackbag"

echo "BLACK-BAG passkey provider → $EXT_DIR"

if ! command -v black-bag >/dev/null 2>&1; then
  echo "  ! black-bag is not on PATH. Build and install the engine first:"
  echo "      cd ~/Projects/blackbag && cargo build --release"
  echo "      install -Dm755 target/release/black-bag ~/.local/bin/black-bag"
  exit 1
fi
ENGINE="$(command -v black-bag)"
echo "  engine: $ENGINE"

# The id is sha256(DER public key), first 16 bytes, each nibble mapped to a-p.
EXT_ID="$(python3 - "$EXT_DIR/manifest.json" <<'PY'
import base64, hashlib, json, sys
key = json.load(open(sys.argv[1]))["key"]
digest = hashlib.sha256(base64.b64decode(key)).digest()[:16]
print("".join(chr(97 + (b >> 4)) + chr(97 + (b & 15)) for b in digest))
PY
)"
if [[ -z "$EXT_ID" ]]; then
  echo "  ! could not derive the extension id from manifest.json"
  exit 1
fi
echo "  extension id: $EXT_ID"

# Every Chromium-family browser that is actually present here.
INSTALLED=0
for dir in \
  "$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts" \
  "$HOME/.config/chromium/NativeMessagingHosts" \
  "$HOME/.config/google-chrome/NativeMessagingHosts"
do
  parent="$(dirname "$dir")"
  [[ -d "$parent" ]] || continue
  mkdir -p "$dir"
  cat > "$dir/$HOST_NAME.json" <<JSON
{
  "name": "$HOST_NAME",
  "description": "Black-Bag passkey provider",
  "path": "$ENGINE",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXT_ID/"]
}
JSON
  chmod 600 "$dir/$HOST_NAME.json"
  echo "  host manifest: $dir/$HOST_NAME.json"
  INSTALLED=$((INSTALLED + 1))
done

if [[ "$INSTALLED" -eq 0 ]]; then
  echo "  ! no Chromium-family browser profile found; nothing to install into."
  exit 1
fi

# The host is launched by the browser with the browser's environment, and it is
# the browser that decides when. Nothing here starts it.
cat <<EOF

Now load the extension, once, by hand — an unpacked extension cannot be
installed from a script:

  1. Open  brave://extensions  (or chrome://extensions)
  2. Turn on "Developer mode"
  3. "Load unpacked", and choose:
       $EXT_DIR
  4. Confirm the id reads  $EXT_ID

Two things worth knowing before you rely on it:

  * Only ONE extension can be a profile's passkey provider. While Black-Bag is
    attached, another password manager's passkey extension will not receive
    requests, and whichever attaches first wins.
  * While any provider is attached, Chromium disables passkey autofill
    (conditional mediation) for the whole profile. Every sign-in becomes an
    explicit click rather than an offer in the username field. That is
    Chromium's behaviour, measured, and not something Black-Bag can work around.

Approval happens in Black-Bag itself, not in the browser. Nothing is signed
until you say so on Black-Bag's own screen.
EOF
