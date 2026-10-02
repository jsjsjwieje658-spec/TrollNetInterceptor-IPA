#!/usr/bin/env python3
"""Generate placeholder app icons (gold color) if source PNG is unavailable"""
import sys
import os

app_dir = sys.argv[1] if len(sys.argv) > 1 else "."

try:
    from PIL import Image
    # Champagne gold color from AppTheme
    gold = (231, 197, 122, 255)
    for size, name in ((120, "AppIcon60x60@2x.png"), (180, "AppIcon60x60@3x.png")):
        out_path = os.path.join(app_dir, name)
        img = Image.new("RGBA", (size, size), gold)
        img.save(out_path)
    print(f"Placeholder icons generated at {app_dir}")
except Exception as e:
    print(f"Placeholder icon generation failed: {e}")
    sys.exit(1)
