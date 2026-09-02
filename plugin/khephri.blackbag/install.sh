#!/usr/bin/env bash
# Idempotent installer for the BLACK-BAG Omarchy plugin.
#   * checks that the `black-bag` engine is on PATH
#   * adds the bar widget to ~/.config/omarchy/shell.json (right section)
#   * binds SUPER+SHIFT+K in ~/.config/hypr/bindings.lua (managed block)
#   * installs a user unit for the unlock agent
#   * publishes a first status.json and rescans the shell
set -uo pipefail

PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
SHELL_JSON="$HOME/.config/omarchy/shell.json"
BINDINGS="$HOME/.config/hypr/bindings.lua"
UNIT_DIR="$HOME/.config/systemd/user"
ID="khephri.blackbag"

echo "BLACK-BAG install → $PLUGIN_DIR"

# 1. The engine must exist before the surfaces are worth wiring up.
if ! command -v black-bag >/dev/null 2>&1; then
  echo "  ! black-bag is not on PATH."
  echo "    Build and install it first:"
  echo "      cd ~/Projects/blackbag && cargo build --release"
  echo "      install -Dm755 target/release/black-bag ~/.local/bin/black-bag"
  exit 1
fi
echo "  engine: $(command -v black-bag) ($(black-bag --version 2>/dev/null | head -1))"

# 2. Enable the bar widget (insert after the last khephri.* widget).
if [[ -f "$SHELL_JSON" ]]; then
  python3 - "$SHELL_JSON" "$ID" <<'PY'
import json, sys, os
path, wid = sys.argv[1], sys.argv[2]
with open(path) as f: cfg = json.load(f)
right = cfg.setdefault("bar", {}).setdefault("layout", {}).setdefault("right", [])
if any(isinstance(e, dict) and e.get("id") == wid for e in right):
    print("  shell.json: already enabled"); sys.exit(0)
idx = len(right)
for i, e in enumerate(right):
    if isinstance(e, dict) and str(e.get("id", "")).startswith("khephri."): idx = i + 1
right.insert(idx, {"id": wid})
tmp = path + ".new"
with open(tmp, "w") as f: json.dump(cfg, f, indent=2); f.write("\n")
os.replace(tmp, path)
print("  shell.json: added %s to bar.right" % wid)
PY
else
  echo "  shell.json not found — skipping bar enable"
fi

# 3. Keybind (managed block; idempotent).
if [[ -f "$BINDINGS" ]]; then
  if grep -q "BEGIN BLACK-BAG" "$BINDINGS"; then
    echo "  bindings.lua: BLACK-BAG block already present"
  else
    cat >> "$BINDINGS" <<'LUA'

-- BEGIN BLACK-BAG (managed by khephri.blackbag/install.sh)
-- BLACK-BAG: credential command deck — unlock, browse, copy, TOTP.
o.bind("SUPER + SHIFT + K", "BLACK-BAG: credential deck", "omarchy-shell shell summon khephri.blackbag '{}'")
-- END BLACK-BAG
LUA
    echo "  bindings.lua: bound SUPER+SHIFT+K"
  fi
else
  echo "  bindings.lua not found — skipping keybind"
fi

# 4. The unlock agent as a user unit.
#    Not enabled by default: starting it is the user's decision, because a
#    running agent is what makes an unlocked vault survive between commands.
mkdir -p "$UNIT_DIR"

# The unit's sandbox names these directories in ReadWritePaths, and systemd
# refuses to start a unit whose ReadWritePaths do not exist — with a bare
# `status=226/NAMESPACE` that says nothing about which path is missing. On a
# machine that has not run `black-bag init` yet they legitimately do not exist,
# so create them here and let the engine own their contents.
mkdir -p "$HOME/.local/share/black-bag" "$HOME/.local/state/black-bag"
chmod 700 "$HOME/.local/share/black-bag" "$HOME/.local/state/black-bag"

cat > "$UNIT_DIR/black-bag-agent.service" <<UNIT
[Unit]
Description=Black-Bag unlock agent
Documentation=man:black-bag(1)
After=graphical-session.target

[Service]
Type=simple
ExecStart=%h/.local/bin/black-bag agent serve --idle-secs 900
Restart=on-failure
RestartSec=2

# The agent holds a decryption key in memory for as long as the vault is
# unlocked, so it gets the strictest sandbox that still lets it work.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
# Leading `-` so a directory that has been removed by hand degrades into an
# ordinary engine-level error instead of a namespace failure the operator
# cannot read.
ReadWritePaths=-%h/.local/share/black-bag -%h/.local/state/black-bag -%t/black-bag
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
PrivateDevices=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
UMask=0077
SystemCallArchitectures=native
# The agent speaks to the deck over its socket and to logind over D-Bus, and
# to nothing else. Without AF_INET/AF_INET6 there is no network path, however
# the binary is compromised; the breach check runs in the CLI, not here.
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
# The syscall allow-list a service needs (it includes the memlock group),
# plus memfd_secret for the session key's kernel-invisible page. @resources
# stays allowed: setrlimit(RLIMIT_CORE) is part of the agent's own hardening.
SystemCallFilter=@system-service memfd_secret
SystemCallFilter=~@privileged
SystemCallErrorNumber=EPERM
# Core dumps would defeat the point of locking pages.
LimitCORE=0

[Install]
WantedBy=graphical-session.target
UNIT
systemctl --user daemon-reload >/dev/null 2>&1 || true
echo "  systemd: wrote black-bag-agent.service (start it with: systemctl --user enable --now black-bag-agent)"

# 5. Desktop entry, so the deck is reachable from the launcher too.
APPS="$HOME/.local/share/applications"
mkdir -p "$APPS"
install -m644 "$PLUGIN_DIR/black-bag.desktop" "$APPS/black-bag.desktop"
command -v update-desktop-database >/dev/null 2>&1 \
  && update-desktop-database "$APPS" >/dev/null 2>&1
echo "  launcher: installed black-bag.desktop"

# 6. Seed a first status so the widget has something true to paint.
mkdir -p "$HOME/.local/state/black-bag"
black-bag status --publish >/dev/null 2>&1 \
  && echo "  status: published" \
  || echo "  status: not published yet (run 'black-bag init' to create a vault)"

# 7. Live reload.
if command -v omarchy-shell >/dev/null 2>&1; then
  omarchy-shell shell rescanPlugins >/dev/null 2>&1 && echo "  shell: plugins rescanned" \
    || echo "  shell: rescan failed (reload the shell manually)"
fi
command -v hyprctl >/dev/null 2>&1 && hyprctl reload >/dev/null 2>&1 && echo "  hyprland: reloaded"

echo "BLACK-BAG installed. Press SUPER+SHIFT+K, or click the lock in the bar."
