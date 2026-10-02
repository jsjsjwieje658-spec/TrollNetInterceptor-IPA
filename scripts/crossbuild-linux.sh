#!/usr/bin/env bash
# =============================================================================
#  AetherNet — Linux Cross-Build Pipeline (clang 19 + ld64.lld + iPhoneOS SDK)
#
#  Produces: build-linux/stage/Payload/AetherNet.app  ->  AetherNet.tipa
#
#  Requirements (Ubuntu 24.04):
#    sudo apt-get install -y clang lld
#    curl -Lo ldid https://github.com/ProcursusTeam/ldid/releases/latest/download/ldid_linux_x86_64 && chmod +x ldid
#    git clone --depth=1 --filter=blob:none --sparse https://github.com/theos/sdks.git
#      cd sdks && git sparse-checkout set iPhoneOS16.5.sdk
#
#  Note: This script uses -fuse-ld=ld64.lld (Mach-O linker). Ensure ld64.lld
#  is available (from lld package). On Ubuntu, ld64.lld may be a separate symlink.
# =============================================================================

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK="${AETHER_SDK:-/home/user/.cache/sdk-repo/iPhoneOS16.5.sdk}"
LDID="${AETHER_LDID:-/home/user/.cache/ldid}"
OUT="$ROOT/build-linux"
STAGE="$OUT/stage"
APP="$STAGE/Payload/AetherNet.app"

# Detect available linker
LNK=""
if command -v ld64.lld >/dev/null 2>&1; then
    LNK="-fuse-ld=ld64.lld"
elif clang++ --version 2>/dev/null | grep -q "lld"; then
    LNK="-fuse-ld=lld"
else
    # Try to find ld64.lld in common locations
    for p in /usr/bin/ld64.lld /usr/local/bin/ld64.lld /opt/llvm/bin/ld64.lld; do
        if [ -x "$p" ]; then
            LNK="-fuse-ld=ld64.lld"
            break
        fi
    done
fi
if [ -z "$LNK" ]; then
    echo "WARNING: ld64.lld not found — falling back to default linker"
    LNK=""
fi
echo "Linker flags: $LNK"

CC=clang
CXX=clang++

TARGET="-target arm64-apple-ios14.0"
MINOS="-mios-version-min=14.0"
COMMON_FLAGS="$TARGET $MINOS -isysroot $SDK -DAETHER_REAL_SDK=1 -I$ROOT/headers \
  -O2 -g0 -fmessage-length=0 -pipe \
  -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-parameter \
  -Werror=format \
  -Wno-unused-function -Wno-objc-designated-initializers -Wno-nullability-completeness"

MMFLAGS="$COMMON_FLAGS -x objective-c++ -std=gnu++17 -fobjc-arc -fobjc-weak"
CFLAGS="$COMMON_FLAGS -x c -std=gnu11"

# Module: libNetHookPayload.dylib (injected L4 hooks)
DYLIB_OBJS=("$OUT/NetHookPayload.o" "$OUT/fishhook.o" "$OUT/AetherSharedMemory_dl.o" "$OUT/compiler_rt_shim_dl.o" "$OUT/AetherLog_dl.o")

mkdir -p "$OUT" "$APP"

echo "── [1/4] Compiling libNetHookPayload.dylib (arm64)…"
$CC $MMFLAGS -c "$ROOT/Payload/NetHookPayload.mm" -o "$OUT/NetHookPayload.o" || exit 1
$CC $CFLAGS   -c "$ROOT/Payload/fishhook.c"       -o "$OUT/fishhook.o"       || exit 1
$CC $MMFLAGS -c "$ROOT/Core/AetherSharedMemory.mm" -o "$OUT/AetherSharedMemory_dl.o" || exit 1
$CC $CFLAGS   -c "$ROOT/Core/compiler_rt_shim.c"  -o "$OUT/compiler_rt_shim_dl.o" || exit 1
$CC $MMFLAGS -DAETHER_LOG_STANDALONE -c "$ROOT/Core/AetherLog.mm" -o "$OUT/AetherLog_dl.o" || exit 1

echo "── Linking dylib…"
$CXX $TARGET $MINOS -isysroot $SDK $LNK \
    -dynamiclib -Wl,-undefined,dynamic_lookup \
    -framework Foundation -framework CoreFoundation -lobjc -lc++ \
    "${DYLIB_OBJS[@]}" -o "$OUT/libNetHookPayload.dylib" || exit 1

echo "── [2/4] Compiling AetherNet executable (arm64)…"

# main.mm uses #import "HUD/HUDMain.mm" and #import "UI/MainApp.mm" — it pulls
# in ALL other .mm/.m source files directly as a single translation unit.
# Compiling those files separately causes duplicate symbol errors, so we
# only compile main.mm (which transitively includes everything).
# Note: NO -dead_strip here — it strips classes only referenced via
# objc_getClass/NSInvocation (e.g. AetherFloatingToggleButton in HUD mode).
$CC $MMFLAGS -c "$ROOT/main.mm" -o "$OUT/main.o" || exit 1

# compiler_rt_shim (for app executable)
$CC $CFLAGS -c "$ROOT/Core/compiler_rt_shim.c" -o "$OUT/compiler_rt_shim_app.o" || exit 1

echo "── Linking executable…"
$CXX $TARGET $MINOS -isysroot $SDK $LNK \
    -Wl,-undefined,dynamic_lookup -ObjC -all_load \
    -framework UIKit -framework Foundation -framework CoreGraphics -framework QuartzCore -framework CoreFoundation \
    -lobjc -lc++ \
    "$OUT/main.o" "$OUT/compiler_rt_shim_app.o" \
    -o "$OUT/AetherNet" || exit 1

echo "── [3/4] Binary build succeeded"
file "$OUT/AetherNet"
file "$OUT/libNetHookPayload.dylib"

echo "── Verifying symbols…"
strings "$OUT/AetherNet" | grep "AetherFloatingToggleButton" | head -1 || echo "WARNING: AetherFloatingToggleButton not found in binary"

echo "── [4/4] Staging .app + fakesigning entitlements…"
STAGE_DIR="$STAGE"
mkdir -p "$APP"

# Copy binary + dylib into .app bundle
cp "$OUT/AetherNet" "$APP/AetherNet"
cp "$OUT/libNetHookPayload.dylib" "$APP/libNetHookPayload.dylib"
chmod 755 "$APP/AetherNet" "$APP/libNetHookPayload.dylib"

# Info.plist for the bundle
python3 - "$APP/Info.plist" <<'PYEOF'
import plistlib, sys
info = {
    "CFBundleDevelopmentRegion": "en",
    "CFBundleDisplayName": "AetherNet",
    "CFBundleExecutable": "AetherNet",
    "CFBundleIcons": {"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}},
    "CFBundleIdentifier": "com.aethernet.interceptor",
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleName": "AetherNet",
    "CFBundlePackageType": "APPL",
    "CFBundleShortVersionString": "3.6.0",
    "CFBundleSupportedPlatforms": ["iPhoneOS"],
    "CFBundleVersion": "360",
    "DTPlatformName": "iphoneos",
    "DTPlatformVersion": "16.5",
    "DTSDKName": "iphoneos16.5",
    "LSRequiresIPhoneOS": True,
    "MinimumOSVersion": "14.0",
    "UILaunchScreen": {},
    "UIRequiredDeviceCapabilities": ["arm64"],
    "UIStatusBarStyle": "UIStatusBarStyleLightContent",
    "UISupportedInterfaceOrientations": [
        "UIInterfaceOrientationPortrait",
        "UIInterfaceOrientationLandscapeLeft",
        "UIInterfaceOrientationLandscapeRight",
    ],
    "UIViewControllerBasedStatusBarAppearance": False,
}
with open(sys.argv[1], "wb") as f:
    plistlib.dump(info, f)
PYEOF

# App icon (generated, resized via Pillow) if available
ICON_SRC="$ROOT/supports/AppIconSource.png"
if [ -f "$ICON_SRC" ]; then
    python3 - "$ICON_SRC" "$APP" <<'PYEOF' || true
import sys
from PIL import Image
img = Image.open(sys.argv[1]).convert("RGBA")
for size, name in ((120, "AppIcon60x60@2x.png"), (180, "AppIcon60x60@3x.png")):
    img.resize((size, size), Image.LANCZOS).save(f"{sys.argv[2]}/{name}")
PYEOF
fi

# Fallback: create placeholder icons if Pillow generation failed
if [ ! -f "$APP/AppIcon60x60@2x.png" ]; then
    python3 -c "
from PIL import Image
img = Image.new('RGBA', (120, 120), (231, 197, 122, 255))
img.save('$APP/AppIcon60x60@2x.png')
img2 = Image.new('RGBA', (180, 180), (231, 197, 122, 255))
img2.save('$APP/AppIcon60x60@3x.png')
" 2>/dev/null || echo "WARNING: Could not generate placeholder icons"
fi

# Verify files in .app bundle
echo "── Files in .app bundle:"
ls -la "$APP/"

# Embed arbitrary TrollStore entitlements into both binaries
"$LDID" -S"$ROOT/supports/entitlements.plist" "$APP/AetherNet"               || exit 1
"$LDID" -S"$ROOT/supports/entitlements.plist" "$APP/libNetHookPayload.dylib" || exit 1

# Verify entitlements embedded
"$LDID" -e "$APP/AetherNet" | head -4 >/dev/null && echo "   entitlements embedded ✔"

# Package TrollStore .tipa
cd "$STAGE_DIR" && rm -f "$ROOT/AetherNet.tipa" && zip -qry "$ROOT/AetherNet.tipa" Payload

echo "── Done: $ROOT/AetherNet.tipa"
