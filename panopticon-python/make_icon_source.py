"""Prepare a square 1024x1024 icon source from a generated logo image."""
import sys
from PIL import Image

SRC = sys.argv[1] if len(sys.argv) > 1 else "logo_flat.png"
OUT = sys.argv[2] if len(sys.argv) > 2 else "icon-source.png"

im = Image.open(SRC).convert("RGB")
gray = im.convert("L")

# Crop strategy: "bbox" removes white side bars, "center" crops full-bleed art
dark = gray.point(lambda p: 255 if p < 128 else 0)
bbox = dark.getbbox()
art = im.crop(bbox)

w, h = art.size
side = max(w, h)
bg = art.getpixel((2, 2))  # sample background color from corner
square = Image.new("RGB", (side, side), bg)
square.paste(art, ((side - w) // 2, (side - h) // 2))

square.resize((1024, 1024), Image.LANCZOS).save(OUT)
print(f"Saved {OUT} (1024x1024)")