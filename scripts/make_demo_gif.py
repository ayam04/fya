from __future__ import annotations

import os
import sys
import threading
from collections import Counter

from PIL import Image, ImageDraw, ImageFont
from werkzeug.serving import make_server

from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.join(HERE, "..", "docs")
PORT = 5098

MARGIN = 22
RADIUS = 13
TITLE_H = 40
PAD_X = 26
PAD_TOP = 16
PAD_BOTTOM = 16
LH = 27
WIN_W = 900

FONT = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 19)
BOLD = ImageFont.truetype("C:/Windows/Fonts/consolab.ttf", 19)

BACKDROP = (6, 8, 12)
WIN = (13, 16, 23)
BORDER = (32, 38, 48)
TITLEBAR = (18, 22, 30)
DOTS = [(255, 95, 86), (255, 189, 46), (39, 201, 63)]
TITLE_TXT = (120, 130, 148)
GREEN = (63, 185, 80)
GREY = (138, 148, 166)
INK = (201, 209, 217)
CURSOR = (201, 209, 217)
CYAN = (77, 184, 255)
SEV = {"critical": (255, 77, 77), "high": (255, 77, 77), "medium": (245, 179, 1), "low": (77, 184, 255), "info": (138, 148, 166)}

TITLE = f"ayam@fya: fya scan  -  127.0.0.1:{PORT}"


def render(rows, canvas_h):
    W = WIN_W + 2 * MARGIN
    img = Image.new("RGB", (W, canvas_h), BACKDROP)
    draw = ImageDraw.Draw(img)
    wx, wy = MARGIN, MARGIN
    ww, wh = WIN_W, canvas_h - 2 * MARGIN
    draw.rounded_rectangle([wx, wy, wx + ww, wy + wh], radius=RADIUS, fill=WIN, outline=BORDER, width=1)
    draw.rounded_rectangle(
        [wx, wy, wx + ww, wy + TITLE_H], radius=RADIUS, corners=(True, True, False, False), fill=TITLEBAR
    )
    draw.line([wx, wy + TITLE_H, wx + ww, wy + TITLE_H], fill=BORDER, width=1)
    for i, color in enumerate(DOTS):
        cx = wx + 20 + i * 22
        draw.ellipse([cx, wy + 14, cx + 12, wy + 26], fill=color)
    tw = draw.textlength(TITLE, font=FONT)
    draw.text((wx + (ww - tw) / 2, wy + 11), TITLE, font=FONT, fill=TITLE_TXT)

    y = wy + TITLE_H + PAD_TOP
    for row in rows:
        x = wx + PAD_X
        for content, color, bold in row:
            font = BOLD if bold else FONT
            draw.text((x, y), content, font=font, fill=color)
            x += draw.textlength(content, font=font)
        y += LH
    return img


def _bar(done, total, width=20):
    filled = int(round(width * done / total)) if total else 0
    return "█" * filled + "░" * (width - filled)


def _prompt(cmd, cursor):
    segs = [("ayam@fya", GREEN, True), (":~$ ", GREY, False), (cmd, INK, False)]
    if cursor:
        segs.append(("█", CURSOR, False))
    return segs


def build(result):
    cmd = f"fya scan http://127.0.0.1:{PORT} --mode full"
    status = [("authorized ", GREY, False), ("local 127.0.0.1", INK, False), ("   mode ", GREY, False), ("full", INK, True), ("  profile ", GREY, False), ("aggressive", INK, True)]

    totals = Counter(n.split(".")[0] for n in result.checks_run)
    found_by = Counter(f.check.split(".")[0] for f in result.findings)
    cats = [c for c in ("web", "tls", "api", "apk", "integrations") if c in totals]

    data = []
    for i in range(0, len(cmd) + 1, 2):
        data.append(([_prompt(cmd[:i], True)], 45))
    data.append(([_prompt(cmd, False), [], status], 450))

    steps = 14
    for s in range(1, steps + 1):
        rows = [_prompt(cmd, False), [], status, []]
        for cat in cats:
            total = totals[cat]
            done = min(total, int(round(total * s / steps)))
            fnd = int(round(found_by[cat] * done / total)) if total else 0
            label = "tools" if cat == "integrations" else cat
            rows.append([
                (f"  {label:<6}", INK, True),
                (_bar(done, total), CYAN if done < total else GREEN, False),
                (f"  {done}/{total}", GREY, False),
                (f"   {fnd} found", GREY, False),
            ])
        data.append((rows, 110))

    counts = result.counts()
    summary = [("findings  ", GREY, False)]
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts[sev]:
            summary.append((f"{counts[sev]} {sev}  ", SEV[sev], True))
    ordered = result.sorted_findings()[:7]
    header = [_prompt(cmd, False), [], summary, []]
    for n in range(len(ordered) + 1):
        rows = list(header)
        for f in ordered[:n]:
            rows.append([(f"  {f.severity.value:<8}", SEV[f.severity.value], True), (f.title[:56], INK, False)])
        data.append((rows, 190))

    done_rows = list(header)
    for f in ordered:
        done_rows.append([(f"  {f.severity.value:<8}", SEV[f.severity.value], True), (f.title[:56], INK, False)])
    done_rows += [[], [("ayam@fya", GREEN, True), (":~$ ", GREY, False)]]
    blink_on = [r for r in done_rows]
    blink_on[-1] = blink_on[-1] + [("█", CURSOR, False)]
    for _ in range(3):
        data.append((blink_on, 500))
        data.append((done_rows, 500))
    data[-1] = (blink_on, 2600)
    return data


def main():
    sys.path.insert(0, os.path.join(HERE, "..", "examples"))
    from vulnerable_app import create_app

    server = make_server("127.0.0.1", PORT, create_app())
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        result = run_scan(
            detect_target(f"http://127.0.0.1:{PORT}"),
            profile=Profile.AGGRESSIVE,
            detect_external=False,
        )
    finally:
        server.shutdown()

    data = build(result)
    max_rows = max(len(rows) for rows, _ in data)
    canvas_h = 2 * MARGIN + TITLE_H + PAD_TOP + max_rows * LH + PAD_BOTTOM
    frames = [render(rows, canvas_h) for rows, _ in data]
    durations = [d for _, d in data]

    out = os.path.join(DOCS, "demo.gif")
    frames[0].save(out, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)
    print(f"wrote {os.path.relpath(out, os.path.join(HERE, '..'))} ({len(frames)} frames, {canvas_h}px tall, {os.path.getsize(out)//1024} KB)")


if __name__ == "__main__":
    main()
