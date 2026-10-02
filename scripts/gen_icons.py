#!/usr/bin/env python3
"""Generate app icons from source PNG using Pillow"""
import sys
import os

app_dir = sys.argv[1] if len(sys.argv) > 1 else "."
src_png = sys.argv[2] if len(sys.argv) > 2 else "supports/AppIconSource.png"

try:
    from PIL import Image
    img = Image.open(src_png).convert("RGBA")
    for size, name in ((120, "AppIcon60x60@2x.png"), (180, "AppIcon60x60@3x.png")):
        out_path = os.path.join(app_dir, name)
        img.resize((size, size), Image.LANCZOS).save(out_path)
    print(f"Icons generated at {app_dir}")
except Exception as e:
    print(f"Icon generation failed: {e}")
    sys.exit(1)
