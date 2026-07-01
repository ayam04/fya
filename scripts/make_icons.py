from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "assets")
FONT_BOLD = "C:/Windows/Fonts/consolab.ttf"

BG = (13, 16, 23, 255)
BORDER = (35, 42, 54, 255)
INK = (232, 238, 245, 255)
RED = (255, 77, 77, 255)
GREY = (138, 148, 166, 255)

SCALE = 4


def _thick_line(draw, p1, p2, width, color):
    draw.line([p1, p2], fill=color, width=width)
    r = width / 2
    for x, y in (p1, p2):
        draw.ellipse([x - r, y - r, x + r, y + r], fill=color)


def draw_icon(size):
    s = size * SCALE
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    radius = int(0.22 * s)
    border = max(2, int(s / 64))
    draw.rounded_rectangle([0, 0, s - 1, s - 1], radius=radius, fill=BG)
    draw.rounded_rectangle(
        [border, border, s - 1 - border, s - 1 - border],
        radius=radius - border,
        outline=BORDER,
        width=border,
    )
    width = int(0.088 * s)
    ax, top, bot = 0.31 * s, 0.33 * s, 0.67 * s
    bx, ymid = 0.54 * s, 0.5 * s
    _thick_line(draw, (ax, top), (bx, ymid), width, INK)
    _thick_line(draw, (bx, ymid), (ax, bot), width, INK)
    draw.rounded_rectangle(
        [0.60 * s, 0.37 * s, 0.71 * s, 0.65 * s], radius=int(0.02 * s), fill=RED
    )
    return img.resize((size, size), Image.LANCZOS)


def draw_wordmark(width=980, height=440):
    img = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([0, 0, width - 1, height - 1], radius=52, fill=BG)
    draw.rounded_rectangle([3, 3, width - 4, height - 4], radius=49, outline=BORDER, width=3)

    mark = 300
    img.paste(draw_icon(mark), (80, (height - mark) // 2), draw_icon(mark))

    name_font = ImageFont.truetype(FONT_BOLD, 220)
    tag_font = ImageFont.truetype(FONT_BOLD, 44)
    text_x = 430
    name_y = 78
    draw.text((text_x, name_y), "fya", font=name_font, fill=INK)
    box = draw.textbbox((text_x, name_y), "fya", font=name_font)
    cursor_x = box[2] + 26
    draw.rounded_rectangle([cursor_x, box[1] + 20, cursor_x + 46, box[3]], radius=8, fill=RED)
    draw.text((text_x + 6, box[3] + 8), "f*ck your app", font=tag_font, fill=GREY)
    return img


def _preview(sizes):
    pad = 40
    tiles = [draw_icon(s) for s in sizes]
    width = pad + sum(s + pad for s in sizes)
    height = max(sizes) + 2 * pad
    sheet = Image.new("RGBA", (width, height), (8, 10, 14, 255))
    x = pad
    for tile, s in zip(tiles, sizes):
        sheet.paste(tile, (x, (height - s) // 2), tile)
        x += s + pad
    return sheet


def main():
    os.makedirs(OUT, exist_ok=True)
    for size in (512, 256, 128, 64, 48, 32, 16):
        draw_icon(size).save(os.path.join(OUT, f"icon-{size}.png"))
    draw_icon(512).save(os.path.join(OUT, "icon.png"))
    draw_icon(256).save(
        os.path.join(OUT, "favicon.ico"), sizes=[(16, 16), (32, 32), (48, 48)]
    )
    draw_wordmark().save(os.path.join(OUT, "logo.png"))
    _preview([256, 128, 64, 32, 16]).save(os.path.join(OUT, "_preview.png"))
    print("wrote icons to", os.path.relpath(OUT, os.path.join(HERE, "..")))


if __name__ == "__main__":
    main()
