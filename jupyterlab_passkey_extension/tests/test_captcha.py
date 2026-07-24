"""The captcha renderer: a code becomes a PNG, and only pixels - never text."""

import io

import pytest

pytest.importorskip("PIL")
from PIL import Image  # noqa: E402

from jupyterlab_passkey_extension.captcha import render_code_png  # noqa: E402

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def test_render_returns_a_valid_png():
    png = render_code_png("482913")
    assert png.startswith(_PNG_MAGIC)
    img = Image.open(io.BytesIO(png))
    img.load()
    assert img.format == "PNG"
    assert img.width > 0 and img.height > 0


@pytest.mark.parametrize("code", ["1", "ABCDEF-1234", "a1B2c3D4e5", "0000000000000000"])
def test_render_handles_varied_codes(code):
    png = render_code_png(code)
    assert png.startswith(_PNG_MAGIC)
    Image.open(io.BytesIO(png)).load()  # a truncated/corrupt PNG would raise here


def test_the_code_is_not_embedded_as_text_in_the_png():
    # The whole point: the value is drawn to pixels, so it must not appear as literal
    # bytes anywhere in the file. A metadata or tEXt chunk carrying it would hand a
    # scraper the code with no OCR at all, defeating the exercise.
    code = "SCRAPE-ME-IF-YOU-CAN"
    png = render_code_png(code)
    assert code.encode("ascii") not in png


def test_a_longer_code_makes_a_wider_image():
    # Proves the code actually drives the render rather than a fixed blank being
    # returned - the digits are laid out left to right, so more of them is wider.
    short = Image.open(io.BytesIO(render_code_png("1")))
    long = Image.open(io.BytesIO(render_code_png("1234567890")))
    assert long.width > short.width
