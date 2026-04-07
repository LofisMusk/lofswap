#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$ROOT_DIR/wallet-gui/frontend"
APP_BINARY="$ROOT_DIR/target/release/wallet-gui"
APP_DIST_SOURCE="$FRONTEND_DIR/dist"

require_cmd() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "$name is required. Install it first."
    exit 1
  fi
}

if [ "$(uname -s)" != "Linux" ]; then
  echo "This launcher is intended for Linux. Use Start-LofSwap-Wallet.command on macOS."
fi

require_cmd npm
require_cmd cargo

echo "Building frontend..."
(
  cd "$FRONTEND_DIR"
  npm install --no-fund --no-audit
  npm run build
)

echo "Building wallet-gui..."
(
  cd "$ROOT_DIR"
  cargo build --release -p wallet-gui
)

if [ ! -x "$APP_BINARY" ]; then
  echo "wallet-gui binary not found at: $APP_BINARY"
  exit 1
fi

XDG_DATA_HOME_FALLBACK="${XDG_DATA_HOME:-$HOME/.local/share}"
APP_RUNTIME_DATA_DIR="${GUI_APP_DATA_DIR:-$XDG_DATA_HOME_FALLBACK/LofSwap Wallet}"
APP_RUNTIME_DIST_DIR="$APP_RUNTIME_DATA_DIR/frontend-dist"

echo "Preparing runtime assets..."
rm -rf "$APP_RUNTIME_DIST_DIR"
mkdir -p "$APP_RUNTIME_DIST_DIR"
cp -R "$APP_DIST_SOURCE/." "$APP_RUNTIME_DIST_DIR/"

if [ "${NO_LAUNCH:-0}" = "1" ]; then
  echo "Build ready: $APP_BINARY"
  echo "Runtime data dir: $APP_RUNTIME_DATA_DIR"
  echo "Runtime frontend dir: $APP_RUNTIME_DIST_DIR"
  exit 0
fi

echo "Launching wallet-gui..."
unset GUI_APP_DEV_URL
export GUI_APP_DATA_DIR="$APP_RUNTIME_DATA_DIR"
export GUI_APP_DIST_DIR="$APP_RUNTIME_DIST_DIR"
exec "$APP_BINARY"
