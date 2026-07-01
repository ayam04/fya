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

W, H = 960, 640
PAD = 28
LH = 30
TITLE_H = 46
FONT = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 20)
BOLD = ImageFont.truetype("C:/Windows/Fonts/consolab.ttf", 20)

BG = (13, 16, 23)
BAR = (22, 27, 36)
DOTS = [(255, 95, 86), (255, 189, 46), (39, 201, 63)]
INK = (201, 209, 217)
GREY = (138, 148, 166)
GREEN = (63, 185, 80)
CYAN = (77, 184, 255)
SEV = {"critical": (255, 77, 77), "high": (255, 77, 77), "medium": (245, 179, 1), "low": (77, 184, 255), "info": (138, 148, 166)}


def _text(draw, x, y, segments):
    for content, color, bold in segments:
        font = BOLD if bold else FONT
        draw.text((x, y), content, font=font, fill=color)
        x += draw.textlength(content, font=font)


def _frame(rows):
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, W, TITLE_H], fill=BAR)
    for i, color in enumerate(DOTS):
        draw.ellipse([PAD + i * 26, 17, PAD + i * 26 + 12, 29], fill=color)
    draw.text((W / 2 - 20, 13), "fya", font=BOLD, fill=GREY)
    y = TITLE_H + 18
    for row in rows:
        _text(draw, PAD, y, row)
        y += LH
    return img


def _bar(done, total, width=20):
    filled = int(round(width * done / total)) if total else 0
    return "█" * filled + "░" * (width - filled)


def build(result):
    frames, durations = [], []
    cmd = f"$ fya scan http://127.0.0.1:{PORT} --mode full"
    status = [
        [("authorized: ", GREY, False), ("local target 127.0.0.1", INK, False), ("   mode ", GREY, False), ("full", INK, True), ("  profile ", GREY, False), ("aggressive", INK, True)],
    ]

    totals = Counter(n.split(".")[0] for n in result.checks_run)
    found_by = Counter(f.check.split(".")[0] for f in result.findings)
    cats = [c for c in ("web", "tls", "api", "apk", "integrations") if c in totals]

    def prompt_row(text, cursor=True):
        segs = [(text, GREEN if text.startswith("$") else INK, True)]
        if cursor:
            segs.append((" █", (255, 77, 77), False))
        return segs

    for i in range(0, len(cmd) + 1, 2):
        frames.append(_frame([prompt_row(cmd[:i])]))
        durations.append(45)
    frames.append(_frame([prompt_row(cmd, cursor=False)] + [[("", INK, False)]] + status))
    durations.append(500)

    steps = 14
    for s in range(1, steps + 1):
        rows = [prompt_row(cmd, cursor=False), [("", INK, False)]] + status + [[("", INK, False)]]
        for cat in cats:
            total = totals[cat]
            done = min(total, int(round(total * s / steps)))
            fnd = int(round(found_by[cat] * done / total)) if total else 0
            label = "tools" if cat == "integrations" else cat
            rows.append([
                (f"{label:<6} ", INK, True),
                (_bar(done, total), CYAN if done < total else GREEN, False),
                (f"  {done}/{total}", GREY, False),
                (f"   {fnd} found", GREY, False),
            ])
        frames.append(_frame(rows))
        durations.append(110)

    counts = result.counts()
    summary = [("findings: ", GREY, False)]
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts[sev]:
            summary.append((f"{counts[sev]} {sev}  ", SEV[sev], True))
    ordered = result.sorted_findings()[:7]
    header = [prompt_row(cmd, cursor=False), [("", INK, False)], summary, [("", INK, False)]]
    for n in range(len(ordered) + 1):
        rows = list(header)
        for f in ordered[:n]:
            rows.append([
                (f"  {f.severity.value:<8}", SEV[f.severity.value], True),
                (f.title[:58], INK, False),
            ])
        frames.append(_frame(rows))
        durations.append(200)

    dur = list(durations)
    dur[-1] = 3200
    return frames, dur


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

    frames, durations = build(result)
    out = os.path.join(DOCS, "demo.gif")
    frames[0].save(
        out,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    total = sum(1 for _ in frames)
    print(f"wrote {os.path.relpath(out, os.path.join(HERE, '..'))} ({total} frames, {os.path.getsize(out)//1024} KB)")


if __name__ == "__main__":
    main()
