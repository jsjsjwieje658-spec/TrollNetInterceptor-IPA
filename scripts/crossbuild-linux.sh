#!/usr/bin/env bash
# =============================================================================
#  AetherNet — Linux Cross-Build Pipeline (clang 19 + ld64.lld + iPhoneOS SDK)
#
#  Produces: build-linux/stage/Payload/AetherNet.app  →  AetherNet.tipa
#
#  Requirements:
#    sudo apt-get install -y clang lld
#    curl -Lo ldid https://github.com/ProcursusTeam/ldid/releases/latest/download/ldid_linux_x86_64
#    git clone --depth=1 --filter=blob:none --sparse https://github.com/theos/sdks.git
#      && cd sdks && git sparse-checkout set iPhoneOS16.5.sdk
# =============================================================================

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK="${AETHER_SDK:-/home/user/.cache/sdk-repo/iPhoneOS16.5.sdk}"
LDID="${AETHER_LDID:-/home/user/.cache/ldid}"
OUT="$ROOT/build-linux"
STAGE="$OUT/stage"
APP="$STAGE/Payload/AetherNet.app"

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
DYLIB_OBJS=("$OUT/NetHookPayload.o" "$OUT/fishhook.o" "$OUT/AetherLog_dl.o")
# Module: AetherNet executable (main dispatcher → app UI + HUD plugin mode)
APP_OBJS=("$OUT/main.o" "$OUT/AetherSharedMemory.o" "$OUT/ProcessManager.o" \
          "$OUT/MachInjector.o" "$OUT/NECPCapture.o" "$OUT/AppTheme.o" "$OUT/HomeViewController.o" \
          "$OUT/SettingsViewController.o" "$OUT/LogViewController.o" "$OUT/AetherGoldButton.o" "$OUT/AetherLog.o")

mkdir -p "$OUT" "$APP"

echo "── [1/4] Compiling libNetHookPayload.dylib (arm64)…"
$CC $MMFLAGS -c "$ROOT/Payload/NetHookPayload.mm" -o "$OUT/NetHookPayload.o" || exit 1
$CC $CFLAGS   -c "$ROOT/Payload/fishhook.c"       -o "$OUT/fishhook.o"       || exit 1
$CC $MMFLAGS -c "$ROOT/Core/AetherSharedMemory.mm" -o "$OUT/AetherSharedMemory_dl.o" || exit 1
$CC $CFLAGS   -c "$ROOT/Core/compiler_rt_shim.c"  -o "$OUT/compiler_rt_shim_dl.o" || exit 1
DYLIB_OBJS+=("$OUT/AetherSharedMemory_dl.o" "$OUT/compiler_rt_shim_dl.o")
$CC $MMFLAGS -DAETHER_LOG_STANDALONE -c "$ROOT/Core/AetherLog.mm" -o "$OUT/AetherLog_dl.o" || exit 1

echo "── [2/4] Compiling AetherNet executable (arm64)…"
$CC $MMFLAGS -c "$ROOT/main.mm"                       -o "$OUT/main.o"                || exit 1
$CC $MMFLAGS -c "$ROOT/Core/AetherSharedMemory.mm"    -o "$OUT/AetherSharedMemory.o"  || exit 1
$CC $MMFLAGS -c "$ROOT/Core/ProcessManager.mm"        -o "$OUT/ProcessManager.o"      || exit 1
$CC $MMFLAGS -c "$ROOT/Core/MachInjector.mm"          -o "$OUT/MachInjector.o"        || exit 1
$CC $MMFLAGS -c "$ROOT/Core/NECPCapture.mm"           -o "$OUT/NECPCapture.o"         || exit 1
$CC $MMFLAGS -c "$ROOT/HUD/FloatingToggleButton.mm"   -o "$OUT/FloatingToggleButton.o" || exit 1
$CC $MMFLAGS -c "$ROOT/HUD/HUDMainWindow.mm"          -o "$OUT/HUDMainWindow.o"        || exit 1
$CC $MMFLAGS -c "$ROOT/HUD/IOHIDEventKIF.m"           -o "$OUT/IOHIDEventKIF.o"        || exit 1
$CC $MMFLAGS -c "$ROOT/HUD/UITouchKIFAdditions.m"     -o "$OUT/UITouchKIFAdditions.o"  || exit 1
$CC $MMFLAGS -c "$ROOT/HUD/TSEventFetcher.mm"         -o "$OUT/TSEventFetcher.o"       || exit 1
$CC $CFLAGS   -c "$ROOT/Core/compiler_rt_shim.c"  -o "$OUT/compiler_rt_shim_app.o" || exit 1
APP_OBJS+=("$OUT/FloatingToggleButton.o" "$OUT/HUDMainWindow.o" \
          "$OUT/IOHIDEventKIF.o" "$OUT/UITouchKIFAdditions.o" "$OUT/TSEventFetcher.o")
APP_OBJS+=("$OUT/compiler_rt_shim_app.o")
$CC $MMFLAGS -c "$ROOT/UI/AppTheme.mm"                -o "$OUT/AppTheme.o"            || exit 1
$CC $MMFLAGS -c "$ROOT/UI/HomeViewController.mm"      -o "$OUT/HomeViewController.o"  || exit 1
$CC $MMFLAGS -c "$ROOT/UI/LogViewController.mm"      -o "$OUT/LogViewController.o"    || exit 1
$CC $MMFLAGS -c "$ROOT/UI/SettingsViewController.mm"  -o "$OUT/SettingsViewController.o" || exit 1
$CC $MMFLAGS -c "$ROOT/UI/AetherGoldButton.mm"        -o "$OUT/AetherGoldButton.o"     || exit 1
$CC $MMFLAGS -c "$ROOT/Core/AetherLog.mm"             -o "$OUT/AetherLog.o"            || exit 1

echo "── [3/4] Linking (ld64.lld, undefined=dynamic_lookup)…"
# Dylib: public Foundation only; everything else resolves at runtime via dyld
$CXX $TARGET $MINOS -isysroot $SDK -fuse-ld=lld \
    -dynamiclib -Wl,-undefined,dynamic_lookup \
    -framework Foundation -lobjc -lc++ \
    "${DYLIB_OBJS[@]}" -o "$APP/libNetHookPayload.dylib" || exit 1

# Executable: UIKit UI app; private SPI (GSInitialize/BKS*/persona) left for dyld
$CXX $TARGET $MINOS -isysroot $SDK -fuse-ld=lld \
    -Wl,-undefined,dynamic_lookup -Wl,-dead_strip \
    -framework UIKit -framework Foundation -framework CoreGraphics -framework QuartzCore \
    -lobjc -lc++ \
    "${APP_OBJS[@]}" -o "$APP/AetherNet" || exit 1

echo "── [4/4] Staging .app + fakesigning entitlements…"
# Info.plist for the bundle
python3 - "$APP/Info.plist" <<'PYEOF' || exit 1
import plistlib, sys
info = {
    "CFBundleDevelopmentRegion": "en",
    "CFBundleDisplayName": "AetherNet",
    "CFBundleExecutable": "AetherNet",
    "CFBundleIcons": {"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}},
    "CFBundleIdentifier": "com.aethernet.interceptor",
    "UIFileSharingEnabled": True,
    "LSSupportsOpeningDocumentsInPlace": True,
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

chmod 755 "$APP/AetherNet" "$APP/libNetHookPayload.dylib"



# Embed arbitrary TrollStore entitlements into both binaries
"$LDID" -S"$ROOT/supports/entitlements.plist" "$APP/AetherNet"               || exit 1
"$LDID" -S"$ROOT/supports/entitlements.plist" "$APP/libNetHookPayload.dylib" || exit 1

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

# Verify entitlements embedded
"$LDID" -e "$APP/AetherNet" | head -4 >/dev/null && echo "   entitlements embedded ✔"

# Package TrollStore .tipa
cd "$STAGE" && rm -f "$ROOT/AetherNet.tipa" && zip -qry "$ROOT/AetherNet.tipa" Payload

echo "── Done: $ROOT/AetherNet.tipa"
