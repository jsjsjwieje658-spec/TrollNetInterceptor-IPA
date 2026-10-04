#!/usr/bin/env python3
"""Generate Info.plist for AetherNet.app"""
import plistlib
import sys

output_path = sys.argv[1] if len(sys.argv) > 1 else "Info.plist"

info = {
    "CFBundleDevelopmentRegion": "en",
    "CFBundleDisplayName": "AetherNet",
    "CFBundleExecutable": "AetherNet",
    "CFBundleIcons": {"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}},
    "CFBundleIdentifier": "com.aethernet.interceptor",
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleName": "AetherNet",
    "CFBundlePackageType": "APPL",
    "CFBundleShortVersionString": "4.1.5",
    "CFBundleVersion": "415",
    "DTPlatformName": "iphoneos",
    "DTPlatformVersion": "16.5",
    "DTSDKName": "iphoneos16.5",
    "LSRequiresIPhoneOS": True,
    "MinimumOSVersion": "14.0",
    "UIFileSharingEnabled": True,
    "LSSupportsOpeningDocumentsInPlace": True,
    "UIStatusBarStyle": "UIStatusBarStyleLightContent",
    "UISupportedInterfaceOrientations": [
        "UIInterfaceOrientationPortrait",
        "UIInterfaceOrientationLandscapeLeft",
        "UIInterfaceOrientationLandscapeRight",
    ],
    "UIViewControllerBasedStatusBarAppearance": False,
}

with open(output_path, "wb") as f:
    plistlib.dump(info, f)

print(f"Info.plist generated at {output_path}")
