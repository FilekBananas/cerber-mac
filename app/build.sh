#!/bin/bash
# Builds Cerber.app (SwiftUI GUI for the Cerber antivirus) without an Xcode project.
#   app/build.sh            → <ROOT>/Cerber.app  (ad-hoc signed)
#   CERBER_DEBUG=1 build.sh → unoptimised build (faster to compile)
# Nothing is installed anywhere: the bundle stays next to the project.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$APP_DIR")"
BUNDLE="$ROOT/Cerber.app"
CONTENTS="$BUNDLE/Contents"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/cerber-build.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

SDK="$(xcrun --sdk macosx --show-sdk-path)"
OPT=(-O -whole-module-optimization)
if [[ "${CERBER_DEBUG:-0}" == "1" ]]; then OPT=(-Onone); fi

echo "▸ Kompilacja (swiftc, $(xcrun swiftc --version 2>/dev/null | head -1 | sed 's/.*Apple //'))"
rm -rf "$BUNDLE"
mkdir -p "$CONTENTS/MacOS" "$CONTENTS/Resources/pl.lproj"
xcrun swiftc \
    -sdk "$SDK" \
    -target arm64-apple-macos14.0 \
    -parse-as-library \
    -swift-version 5 \
    "${OPT[@]}" \
    -module-name Cerber \
    -framework SwiftUI -framework AppKit -framework UniformTypeIdentifiers -framework WebKit \
    "$APP_DIR"/Sources/*.swift \
    -o "$CONTENTS/MacOS/Cerber"

echo "▸ Info.plist (CerberRoot = $ROOT)"
cat > "$CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>     <string>pl</string>
    <key>CFBundleLocalizations</key>         <array><string>pl</string></array>
    <key>CFBundleExecutable</key>            <string>Cerber</string>
    <key>CFBundleIdentifier</key>            <string>pl.cerber.app</string>
    <key>CFBundleName</key>                  <string>Cerber</string>
    <key>CFBundleDisplayName</key>           <string>Cerber</string>
    <key>CFBundlePackageType</key>           <string>APPL</string>
    <key>CFBundleShortVersionString</key>    <string>1.0</string>
    <key>CFBundleVersion</key>               <string>1</string>
    <key>CFBundleIconFile</key>              <string>AppIcon</string>
    <key>CFBundleInfoDictionaryVersion</key> <string>6.0</string>
    <key>LSMinimumSystemVersion</key>        <string>14.0</string>
    <key>LSApplicationCategoryType</key>     <string>public.app-category.utilities</string>
    <key>NSHighResolutionCapable</key>       <true/>
    <key>NSPrincipalClass</key>              <string>NSApplication</string>
    <key>NSSupportsAutomaticTermination</key><false/>
    <key>NSHumanReadableCopyright</key>      <string>Cerber – lokalny skaner antywirusowy</string>
    <key>CerberRoot</key>                    <string>$ROOT</string>
</dict>
</plist>
PLIST
printf 'CFBundleName = "Cerber";\nCFBundleDisplayName = "Cerber";\n' > "$CONTENTS/Resources/pl.lproj/InfoPlist.strings"
printf 'APPL????' > "$CONTENTS/PkgInfo"

echo "▸ Ikona (render SwiftUI → iconset → icns)"
"$CONTENTS/MacOS/Cerber" --render-icon "$WORK/icon_1024.png" >/dev/null
ICONSET="$WORK/AppIcon.iconset"
mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
    sips -z "$s" "$s" "$WORK/icon_1024.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
    d=$((s * 2))
    sips -z "$d" "$d" "$WORK/icon_1024.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$CONTENTS/Resources/AppIcon.icns"

echo "▸ Podpis ad-hoc"
codesign --force --deep -s - "$BUNDLE" >/dev/null 2>&1
codesign --verify --deep "$BUNDLE"

echo "✓ Gotowe: $BUNDLE"
echo "  Uruchom:       open \"$BUNDLE\""
echo "  Tryb mock:     \"$CONTENTS/MacOS/Cerber\" --mock   (albo CERBER_MOCK=1)"
echo "  Zrzuty:        \"$CONTENTS/MacOS/Cerber\" --snapshot KATALOG"
echo "  Test parsera:  \"$CONTENTS/MacOS/Cerber\" --selftest-parse"
