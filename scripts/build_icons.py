#!/usr/bin/env python3
"""Build the app's icons and logos.

Writes the SVG sources and a 512px PNG (Splunkbase listing icon) to assets/, and
the Splunk Web images to unifi_security/static/:
  appIcon.png 36x36, appIcon_2x.png 72x72, appIconAlt*.png (same; the tile has
  its own dark background), appLogo.png 160x40, appLogo_2x.png 320x80.

Usage:  pip install resvg-py && python3 scripts/build_icons.py
"""
import math, pathlib
import resvg_py

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = "unifi_security"
LOGO_LINES = [("UniFi Security", 54, "#FFFFFF", 100)]

DEFS = """
<linearGradient id="tile" x1="0" y1="0" x2="1" y2="1">
  <stop offset="0" stop-color="#1D2C47"/><stop offset="1" stop-color="#0A111F"/>
</linearGradient>
<linearGradient id="blue" x1="0" y1="0" x2="1" y2="1">
  <stop offset="0" stop-color="#4AA3FF"/><stop offset="1" stop-color="#0B5BD9"/>
</linearGradient>
<linearGradient id="glyph" gradientUnits="userSpaceOnUse" x1="{gx0}" y1="{gy0}" x2="{gx1}" y2="{gy1}">
  <stop offset="0" stop-color="#FFFFFF"/><stop offset="0.45" stop-color="#DCE8F7"/><stop offset="0.85" stop-color="#2F8BFF"/>
</linearGradient>
<filter id="glow" x="-30%" y="-30%" width="160%" height="160%">
  <feGaussianBlur stdDeviation="10" result="b"/>
  <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
</filter>
"""

def defs(cx, cy, r):
    # The glyph gradient spans the whole Wi-Fi glyph: white upper-left -> blue lower-right.
    return DEFS.format(gx0=cx - r, gy0=cy - r, gx1=cx + r * 0.8, gy1=cy + r * 0.1)

def arc(cx, cy, r, a0, a1):
    """Arc path from angle a0 to a1 (degrees, 0 = east, clockwise)."""
    p = lambda a: (cx + r * math.cos(math.radians(a)), cy + r * math.sin(math.radians(a)))
    (x0, y0), (x1, y1) = p(a0), p(a1)
    large = 1 if (a1 - a0) % 360 > 180 else 0
    return f"M{x0:.1f} {y0:.1f} A{r} {r} 0 {large} 1 {x1:.1f} {y1:.1f}"

def wifi(cx, cy, radii, width, dot):
    arcs = "".join(f'<path d="{arc(cx, cy, r, 225, 315)}"/>' for r in radii)
    return (f'<g fill="none" stroke="url(#glyph)" stroke-width="{width}" stroke-linecap="round">{arcs}</g>'
            f'<circle cx="{cx}" cy="{cy}" r="{dot}" fill="url(#glyph)"/>')

def tile(body, d):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><defs>{d}</defs>'
            f'<rect width="512" height="512" rx="96" fill="url(#tile)"/>{body}</svg>')

SHIELD = "M256 64 L414 118 V246 C414 352 346 422 256 456 C166 422 98 352 98 246 V118 Z"

def icon(small=False):
    """Glowing gradient shield around a Wi-Fi glyph. Reads at every size, so
    the small variant is the same drawing."""
    return tile(
        f'<path d="{SHIELD}" fill="#0A1324" fill-opacity="0.6"/>'
        f'<path d="{SHIELD}" fill="none" stroke="url(#blue)" stroke-width="36" stroke-linejoin="round" filter="url(#glow)"/>'
        + wifi(256, 336, (52, 96, 140), 34, 24), defs(256, 336, 140))

def logo():
    """640x160 (4:1): small icon plus the app name on a navy background, so it reads
    on both the light and dark Splunk app bar."""
    inner = icon(small=True).replace('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">',
                                     '<svg x="0" y="0" width="160" height="160" viewBox="0 0 512 512">', 1)
    text = "".join(f'<text x="184" y="{y}" font-family="Helvetica Neue, Helvetica, Arial, sans-serif" '
                   f'font-size="{size}" font-weight="600" fill="{color}">{label}</text>'
                   for label, size, color, y in LOGO_LINES)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 160">'
            f'<rect width="640" height="160" rx="30" fill="#111C30"/>{inner}{text}</svg>')

def png(svg, width, height):
    return bytes(resvg_py.svg_to_bytes(svg_string=svg, width=width, height=height))

if __name__ == "__main__":
    assets, static = ROOT / "assets", ROOT / APP / "static"
    assets.mkdir(exist_ok=True)
    static.mkdir(exist_ok=True)
    big, small, wide = icon(), icon(small=True), logo()
    for name, svg in (("icon.svg", big), ("icon_small.svg", small), ("logo.svg", wide)):
        (assets / name).write_text(svg + "\n")
    (assets / "icon_512.png").write_bytes(png(big, 512, 512))
    for name, svg, w, h in (("appIcon.png", small, 36, 36), ("appIcon_2x.png", small, 72, 72),
                            ("appIconAlt.png", small, 36, 36), ("appIconAlt_2x.png", small, 72, 72),
                            ("appLogo.png", wide, 160, 40), ("appLogo_2x.png", wide, 320, 80)):
        (static / name).write_bytes(png(svg, w, h))
    print(f"wrote assets/ and {APP}/static/")
