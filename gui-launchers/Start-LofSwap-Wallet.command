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

generate_bundle_icon_png() {
  local src_png="$1"
  local out_png="$2"

  if [ "$(uname -s)" != "Darwin" ]; then
    cp "$src_png" "$out_png"
    return 0
  fi

  if ! command -v swift >/dev/null 2>&1; then
    cp "$src_png" "$out_png"
    return 0
  fi

  if swift - "$src_png" "$out_png" <<'SWIFT'
import AppKit
import Foundation

let args = CommandLine.arguments
guard args.count >= 3 else {
  fputs("missing icon args\n", stderr)
  exit(2)
}

let srcPath = args[1]
let outPath = args[2]
let iconSize: CGFloat = 1024
let logoScale: CGFloat = 0.94
let inset: CGFloat = iconSize * 0.028
let cornerRadius: CGFloat = iconSize * 0.225

guard let logo = NSImage(contentsOfFile: srcPath) else {
  fputs("failed to load source logo\n", stderr)
  exit(3)
}

guard let bitmap = NSBitmapImageRep(
  bitmapDataPlanes: nil,
  pixelsWide: Int(iconSize),
  pixelsHigh: Int(iconSize),
  bitsPerSample: 8,
  samplesPerPixel: 4,
  hasAlpha: true,
  isPlanar: false,
  colorSpaceName: .deviceRGB,
  bytesPerRow: 0,
  bitsPerPixel: 0
) else {
  fputs("failed to create bitmap canvas\n", stderr)
  exit(4)
}

guard let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
  fputs("failed to create graphics context\n", stderr)
  exit(5)
}

NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = context
context.imageInterpolation = .high
defer { NSGraphicsContext.restoreGraphicsState() }

NSColor.clear.setFill()
NSBezierPath(rect: NSRect(x: 0, y: 0, width: iconSize, height: iconSize)).fill()

let bgRect = NSRect(
  x: inset,
  y: inset,
  width: iconSize - (inset * 2.0),
  height: iconSize - (inset * 2.0)
)
NSColor(calibratedRed: 10.0 / 255.0, green: 10.0 / 255.0, blue: 12.0 / 255.0, alpha: 1.0).setFill()
NSBezierPath(roundedRect: bgRect, xRadius: cornerRadius, yRadius: cornerRadius).fill()

let sourceSize = logo.size
if sourceSize.width > 0 && sourceSize.height > 0 {
  let maxSide = min(bgRect.width, bgRect.height) * logoScale
  let factor = min(maxSide / sourceSize.width, maxSide / sourceSize.height)
  let drawSize = NSSize(width: sourceSize.width * factor, height: sourceSize.height * factor)
  let drawRect = NSRect(
    x: (iconSize - drawSize.width) / 2.0,
    y: (iconSize - drawSize.height) / 2.0,
    width: drawSize.width,
    height: drawSize.height
  )
  logo.draw(in: drawRect, from: .zero, operation: .sourceOver, fraction: 1.0)
}
context.flushGraphics()

guard let pngData = bitmap.representation(using: .png, properties: [:]) else {
  fputs("failed to encode icon png\n", stderr)
  exit(6)
}

do {
  try pngData.write(to: URL(fileURLWithPath: outPath), options: .atomic)
} catch {
  fputs("failed to write icon png: \(error)\n", stderr)
  exit(7)
}
SWIFT
  then
    return 0
  fi

  cp "$src_png" "$out_png"
  return 0
}

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
  generate_bundle_icon_png "$APP_ICON_PNG" "$APP_BUNDLE/Contents/Resources/AppIcon.png"
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
