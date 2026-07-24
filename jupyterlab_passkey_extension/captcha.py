"""Render a short code to a distorted PNG a screen scraper cannot read as text.

The code a local client stages for `show` is handed to the browser as an image,
never as DOM text, so it does not ride the notifications extension's broadcast to
every socket, does not sit in the page for a scrape, and is absent from the
accessibility tree. Standard CAPTCHA-style distortion - per-character jitter and
rotation, colour variation, and overlaid line and dot noise - raises the bar
against an OCR pass on a screenshot as well.

The value is drawn to pixels here and dropped; it is never logged. This module is
purely presentational and holds no secret beyond the single render call.
"""

from __future__ import annotations

import io
import random

from PIL import Image, ImageDraw, ImageFilter, ImageFont

_FONT_SIZE = 46
_PAD_X = 22
_PAD_Y = 20
_CHAR_GAP = 5


def _font(size: int):
    """A scalable default font at `size`, without shipping a font file.

    Pillow >= 10.1 returns a TrueType default (DejaVuSans) at the requested size.
    Older Pillow ignores `size` and yields a small bitmap font; the distortion
    still applies, only smaller - the render never fails for want of a font.
    """
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def render_code_png(text: str) -> bytes:
    """Return PNG bytes of `text` drawn as a distorted, scraper-resistant image."""
    font = _font(_FONT_SIZE)

    # Each character is rendered onto its own transparent tile, tinted and rotated
    # independently, then pasted with a small random vertical wobble. Per-glyph
    # handling is what lets each one carry its own rotation.
    tiles = []
    for ch in text:
        left, top, right, bottom = font.getbbox(ch)
        w = max(right - left, 1)
        h = max(bottom - top, 1)
        tile = Image.new("RGBA", (w + 12, h + 12), (0, 0, 0, 0))
        ink = (random.randint(0, 90), random.randint(0, 90), random.randint(0, 90))
        ImageDraw.Draw(tile).text((6 - left, 6 - top), ch, font=font, fill=ink)
        tiles.append(tile.rotate(random.uniform(-22, 22), expand=1, resample=Image.BICUBIC))

    inner_w = sum(t.width for t in tiles) + _CHAR_GAP * max(len(tiles) - 1, 0)
    inner_h = max((t.height for t in tiles), default=_FONT_SIZE)
    width = _PAD_X * 2 + max(inner_w, 1)
    height = _PAD_Y * 2 + inner_h

    canvas = Image.new("RGB", (width, height), (238, 238, 242))
    x = _PAD_X
    for tile in tiles:
        centred = _PAD_Y + (inner_h - tile.height) // 2
        y = centred + random.randint(-6, 6)
        canvas.paste(tile, (x, y), tile)
        x += tile.width + _CHAR_GAP

    draw = ImageDraw.Draw(canvas)
    # A few wandering lines and a light speckle over the top - enough to break the
    # clean glyph edges an OCR pass leans on, not so much a human cannot read it.
    for _ in range(4):
        pts = [(random.randint(0, width), random.randint(0, height)) for _ in range(3)]
        draw.line(pts, fill=(random.randint(130, 200),) * 3, width=1)
    for _ in range(max(width * height // 240, 1)):
        draw.point(
            (random.randint(0, width - 1), random.randint(0, height - 1)),
            fill=(random.randint(130, 200),) * 3,
        )

    buf = io.BytesIO()
    canvas.filter(ImageFilter.SMOOTH).save(buf, format="PNG")
    return buf.getvalue()
