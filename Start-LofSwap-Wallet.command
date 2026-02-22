#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
FRONTEND_DIR="$ROOT_DIR/wallet-gui/frontend"
APP_NAME="LofSwap Wallet"
APP_BUNDLE="$ROOT_DIR/target/release/$APP_NAME.app"
APP_EXECUTABLE="$APP_BUNDLE/Contents/MacOS/wallet-gui"
APP_BINARY_SOURCE="$ROOT_DIR/target/release/wallet-gui"
APP_BINARY_WRAPPED="$APP_BUNDLE/Contents/Resources/wallet-gui.bin"
APP_DIST_SOURCE="$ROOT_DIR/wallet-gui/frontend/dist"
APP_DIST_BUNDLE="$APP_BUNDLE/Contents/Resources/frontend-dist"
APP_ICON_PNG="$ROOT_DIR/lofswap-logo.png"

if [ "$(uname -s)" = "Darwin" ]; then
  APP_RUNTIME_DATA_DIR="$HOME/Library/Application Support/LofSwap Wallet"
  APP_RUNTIME_DIST_DIR="$APP_RUNTIME_DATA_DIR/frontend-dist"
else
  APP_RUNTIME_DATA_DIR=""
  APP_RUNTIME_DIST_DIR=""
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required. Install Node.js first."
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required. Install Rust toolchain first."
  exit 1
fi

echo "Building frontend..."
cd "$FRONTEND_DIR"
npm install --no-fund --no-audit
npm run build

echo "Building wallet-gui..."
cd "$ROOT_DIR"
cargo build --release -p wallet-gui

echo "Preparing app bundle..."
rm -rf "$APP_BUNDLE"
if [ -n "$APP_RUNTIME_DIST_DIR" ]; then
  rm -rf "$APP_RUNTIME_DIST_DIR"
  mkdir -p "$APP_RUNTIME_DIST_DIR"
fi
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources" "$APP_DIST_BUNDLE"

cp "$APP_BINARY_SOURCE" "$APP_BINARY_WRAPPED"
chmod +x "$APP_BINARY_WRAPPED"
cp -R "$APP_DIST_SOURCE/." "$APP_DIST_BUNDLE/"
if [ -n "$APP_RUNTIME_DIST_DIR" ]; then
  cp -R "$APP_DIST_SOURCE/." "$APP_RUNTIME_DIST_DIR/"
fi
if [ -f "$APP_ICON_PNG" ]; then
  cp "$APP_ICON_PNG" "$APP_BUNDLE/Contents/Resources/AppIcon.png"
fi

cat > "$APP_EXECUTABLE" <<EOF
#!/bin/bash
set -euo pipefail
APP_CONTENTS_DIR="\$(cd "\$(dirname "\$0")/.." && pwd)"
if [ "\$(uname -s)" = "Darwin" ]; then
  export GUI_APP_DATA_DIR="\$HOME/Library/Application Support/LofSwap Wallet"
  mkdir -p "\$GUI_APP_DATA_DIR"
  export GUI_APP_DIST_DIR="\$GUI_APP_DATA_DIR/frontend-dist"
else
  export GUI_APP_DIST_DIR="\$APP_CONTENTS_DIR/Resources/frontend-dist"
fi
unset GUI_APP_DEV_URL
exec "\$APP_CONTENTS_DIR/Resources/wallet-gui.bin"
EOF
chmod +x "$APP_EXECUTABLE"

cat > "$APP_BUNDLE/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>wallet-gui</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon.png</string>
  <key>CFBundleIdentifier</key>
  <string>com.lofswap.wallet</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>LofSwap Wallet</string>
  <key>CFBundleDisplayName</key>
  <string>LofSwap Wallet</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
EOF

if [ "${NO_LAUNCH:-0}" = "1" ]; then
  echo "Bundle ready: $APP_BUNDLE"
  exit 0
fi

echo "Launching app bundle..."
open "$APP_BUNDLE"
echo "Done: $APP_BUNDLE"
