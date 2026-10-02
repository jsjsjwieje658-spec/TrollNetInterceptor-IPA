#!/usr/bin/env bash
# =============================================================================
#  AetherNet — TrollStore .tipa Build & Entitlement Fakesign Pipeline
#
#  Usage:
#    1. xcodegen generate          (creates AetherNet.xcodeproj from project.yml)
#    2. xcodebuild -project AetherNet.xcodeproj -scheme AetherNet \
#         -configuration Release -sdk iphoneos -derivedDataPath build
#    3. ./scripts/build.sh package (fakesigns + packages Payload/ into .tipa)
#
#  Requirements: xcodegen, xcodebuild (macOS + iOS SDK), ldid, zip
# =============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENTITLEMENTS="${ROOT_DIR}/supports/entitlements.plist"
BUILD_DIR="${ROOT_DIR}/build"
APP_NAME="AetherNet"
BINARY_NAME="AetherNet"

bold()  { printf "\033[1m%s\033[0m\n" "$1"; }
ok()    { printf "  \033[32m✔\033[0m %s\n" "$1"; }
warn()  { printf "  \033[33m⚠\033[0m %s\n" "$1"; }
fail()  { printf "  \033[31m✘\033[0m %s\n" "$1"; exit 1; }

# ----------------------------------------------------------------------------
# Step 1: Generate Xcode project (optional, skips if already generated)
# ----------------------------------------------------------------------------
cmd_generate() {
    bold "[1/3] Generating Xcode project with XcodeGen…"
    if command -v xcodegen >/dev/null 2>&1; then
        (cd "$ROOT_DIR" && xcodegen generate)
        ok "AetherNet.xcodeproj generated"
    else
        warn "xcodegen not found — open project.yml manually or install: brew install xcodegen"
    fi
}

# ----------------------------------------------------------------------------
# Step 2: Build with xcodebuild for arm64 iphoneos
# ----------------------------------------------------------------------------
cmd_build() {
    bold "[2/3] Building arm64 device binary…"
    (cd "$ROOT_DIR" && xcodebuild \
        -project AetherNet.xcodeproj \
        -scheme AetherNet \
        -configuration Release \
        -sdk iphoneos \
        -derivedDataPath build \
        ARCHS=arm64 \
        ONLY_ACTIVE_ARCH=YES \
        CODE_SIGNING_ALLOWED=NO \
        CODE_SIGN_IDENTITY= \
        clean build) || fail "xcodebuild failed"
    ok "Built build/Build/Products/Release-iphoneos/${APP_NAME}.app"
}

# ----------------------------------------------------------------------------
# Step 3: Fake-sign with ldid + TrollStore entitlements, package .tipa
# ----------------------------------------------------------------------------
cmd_package() {
    bold "[3/3] Fakesigning with TrollStore entitlements & packaging .tipa…"

    local APP_PATH
    APP_PATH=$(find "$BUILD_DIR" -type d -name "${APP_NAME}.app" -path "*Release-iphoneos*" | head -n 1)
    [ -n "$APP_PATH" ] || fail "Cannot locate built ${APP_NAME}.app under build/"

    command -v ldid >/dev/null 2>&1 || fail "ldid not found — install: brew install ldid"

    # 3.1 — Embed the arbitrary entitlements (TrollStore preserves these on install)
    ldid -S"$ENTITLEMENTS" "${APP_PATH}/${BINARY_NAME}"
    ok "Entitlements embedded: $(grep -c '<key>' "$ENTITLEMENTS") keys (platform-application, no-sandbox, task_for_pid-allow, hid.client.*, accessibility-window-hosting …)"

    # 3.2 — Fake-sign all nested frameworks / dylibs if present
    find "$APP_PATH" -type f \( -name "*.dylib" -o -path "*Frameworks/*" \) -exec ldid -S {} \; 2>/dev/null || true

    # 3.3 — Package as .tipa (TrollStore IPA convention: Payload/*.app)
    local STAGE="${BUILD_DIR}/tipa-stage"
    rm -rf "$STAGE"
    mkdir -p "${STAGE}/Payload"
    cp -R "$APP_PATH" "${STAGE}/Payload/"

    local TIPA="${ROOT_DIR}/${APP_NAME}.tipa"
    rm -f "$TIPA"
    (cd "$STAGE" && zip -qry "$TIPA" Payload)

    ok "Packaged: ${TIPA}"
    bold "Next: AirDrop / copy ${APP_NAME}.tipa to device → open with TrollStore → Install"
}

case "${1:-all}" in
    generate) cmd_generate ;;
    build)    cmd_build ;;
    package)  cmd_package ;;
    all)      cmd_generate; cmd_build; cmd_package ;;
    *)        echo "Usage: $0 {generate|build|package|all}"; exit 1 ;;
esac
