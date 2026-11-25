#!/bin/sh
set -eu

REPO_RAW="https://raw.githubusercontent.com/omnibuf/omnibuf-wireshark/main"
PLUGIN_DIR="${WIRESHARK_PLUGIN_DIR:-$HOME/.local/lib/wireshark/plugins}"

mkdir -p "$PLUGIN_DIR"

if [ -f "./omnibuf.lua" ] && [ -f "./omnibuf_wire.lua" ]; then
  cp ./omnibuf.lua ./omnibuf_wire.lua "$PLUGIN_DIR/"
else
  curl -fsSL "$REPO_RAW/omnibuf.lua" -o "$PLUGIN_DIR/omnibuf.lua"
  curl -fsSL "$REPO_RAW/omnibuf_wire.lua" -o "$PLUGIN_DIR/omnibuf_wire.lua"
fi

echo "Installed OmniBuf Wireshark dissector into $PLUGIN_DIR"
