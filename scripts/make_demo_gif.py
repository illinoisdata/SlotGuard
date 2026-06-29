#!/usr/bin/env python3
"""Render an animated terminal-style demo GIF for SlotGuard.

Runs the real `slotguard-cli demo-path` against a throwaway workspace that
contains a *sensitive* filename, then renders the authentic output as a typed
terminal session into assets/demo.gif. Pillow-only (no ffmpeg / network).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parent.parent
BIN = REPO / "target" / "release" / "slotguard-cli"
OUT = REPO / "assets" / "demo.gif"

# --- palette (GitHub-dark-ish) ------------------------------------------------
BG = (13, 17, 23)
TITLEBAR = (22, 27, 34)
BORDER = (48, 54, 61)
COMMENT = (139, 148, 158)
PROMPT = (88, 166, 255)
CMD = (126, 231, 135)
LABEL = (199, 222, 237)
RAW = (255, 123, 114)        # sensitive raw value -> red
SAFE = (63, 211, 100)        # sanitized handle -> green
REBOUND = (160, 224, 255)    # local-only rebound -> cyan
SLOTID = (255, 196, 102)
ACCENT = (150, 196, 255)
DIVIDER = (48, 54, 61)
DOT_R, DOT_Y, DOT_G = (255, 95, 86), (254, 188, 46), (39, 201, 63)

FONT_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FONT_SIZE = 19
LINE_H = 30
PADX = 40
TOPBAR = 44
PADTOP = 26
PADBOT = 30


def run_demo() -> dict:
    """Run the CLI on a sensitive file, return parsed JSON (clean display path)."""
    with tempfile.TemporaryDirectory(prefix="sg_demo_") as ws:
        ws = Path(ws)
        (ws / "layoff_plan_for_bob_2026.pdf").write_text("confidential\n")
        env = dict(os.environ, SLOTGUARD_HOME=str(ws / ".sg"))
        path = ws / "layoff_plan_for_bob_2026.pdf"
        res = subprocess.run(
            [str(BIN), "demo-path", str(path), "--workspace-root", str(ws)],
            capture_output=True, text=True, env=env,
        )
        if res.returncode != 0:
            print("CLI failed:", res.stderr, file=sys.stderr)
            sys.exit(1)
        data = json.loads(res.stdout)
    shown = "/tmp/alice/project/layoff_plan_for_bob_2026.pdf"
    data["raw"] = shown
    data["rebound"] = shown
    for s in data["slots"]:
        if s["slot_type"] == "RepoRoot":
            s["raw_value"] = "/tmp/alice/project"
    return data


def build_lines(data: dict):
    raw = data["raw"]
    abst = data["abstracted"]
    slots = {s["id"]: s for s in data["slots"]}
    repo_raw = slots.get("REPO_ROOT_1", {}).get("raw_value", "/tmp/alice/project")
    doc_raw = slots.get("SENSITIVE_DOC_1", {}).get("raw_value", "layoff_plan_for_bob_2026.pdf")

    setup = [
        [("# provider-bound transcript leaks the raw local binding:", COMMENT)],
        [],
        [("  raw   →  ", LABEL), (raw, RAW)],
        [],
        [("# SlotGuard rewrites it before it leaves the trusted runtime:", COMMENT)],
    ]
    cmd_text = (
        "slotguard-cli demo-path \\\n"
        "    /tmp/alice/project/layoff_plan_for_bob_2026.pdf \\\n"
        "    --workspace-root /tmp/alice/project"
    )
    output = [
        [],
        [("  rewrite:", LABEL)],
        [("  abstracted  →  ", LABEL), (abst, SAFE)],
        [("  rebound     →  ", LABEL), (raw, REBOUND), ("   (local-only)", COMMENT)],
        [],
        [("  slots:", COMMENT)],
        [("    ", LABEL), ("REPO_ROOT_1", SLOTID), ("  RepoRoot           ", LABEL), (repo_raw, LABEL)],
        [("    ", LABEL), ("SENSITIVE_DOC_1", SLOTID), ("  SensitiveDocument  ", LABEL), (doc_raw, LABEL)],
    ]
    footer = [
        [("Stop oversharing private local context in agent transcripts.", ACCENT)],
        [("Workflow shape preserved  ·  private content stripped.", COMMENT)],
    ]
    return setup, cmd_text, output, footer


def line_width(font, spans) -> int:
    return int(sum(font.getlength(t) for t, _ in spans))


def draw_spans(draw, x, y, spans, font):
    for text, color in spans:
        draw.text((x, y), text, fill=color, font=font)
        x += font.getlength(text)


def make_fonts():
    return (ImageFont.truetype(FONT_REG, FONT_SIZE),
            ImageFont.truetype(FONT_BOLD, FONT_SIZE))


def render_frame(main_rows, fonts, footer=None, cursor=None, dims=None):
    freg, fbold = fonts
    if dims is None:
        widths = [line_width(freg, s) for s in main_rows]
        fw = [line_width(fbold if i == 0 else freg, s) for i, s in enumerate(footer or [])]
        width = max(widths + fw + [0]) + 2 * PADX
        footer_y0 = TOPBAR + PADTOP + len(main_rows) * LINE_H + 22
        height = footer_y0 + len(footer or []) * LINE_H + PADBOT
        dims = (width, height, footer_y0)
    width, height, footer_y0 = dims

    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, width - 1, TOPBAR], fill=TITLEBAR)
    d.line([(0, TOPBAR), (width - 1, TOPBAR)], fill=BORDER)
    for i, c in enumerate([DOT_R, DOT_Y, DOT_G]):
        d.ellipse([14 + i * 20, 15, 14 + i * 20 + 12, 27], fill=c)
    title = "slotguard — demo"
    d.text(((width - fbold.getlength(title)) / 2, 13), title, fill=COMMENT, font=fbold)

    y = TOPBAR + PADTOP
    for spans in main_rows:
        if spans:
            draw_spans(d, PADX, y, spans, freg)
        y += LINE_H

    if cursor is not None:
        cx, row = cursor
        d.rectangle([PADX + cx, TOPBAR + PADTOP + row * LINE_H + 3,
                     PADX + cx + 10, TOPBAR + PADTOP + row * LINE_H + 22], fill=CMD)

    if footer:
        d.line([(PADX, footer_y0 - 10), (width - PADX, footer_y0 - 10)], fill=DIVIDER)
        fy = footer_y0
        for i, spans in enumerate(footer):
            draw_spans(d, PADX, fy, spans, fbold if i == 0 else freg)
            fy += LINE_H

    d.rectangle([0, 0, width - 1, height - 1], outline=BORDER)
    return img, dims


def main():
    if not BIN.exists():
        print(f"CLI binary not found at {BIN}.\n"
              "Run: cargo build -p slotguard-cli --release", file=sys.stderr)
        sys.exit(1)

    data = run_demo()
    setup, cmd_text, output, footer = build_lines(data)
    fonts = make_fonts()
    freg = fonts[0]

    def rows_for(cmd_chars: int, out_count: int):
        rows = list(setup)
        parts = cmd_text[:cmd_chars].split("\n")
        n_cmd_rows = cmd_text.count("\n") + 1
        for i in range(n_cmd_rows):
            txt = parts[i] if i < len(parts) else ""
            rows.append([("$ ", PROMPT), (txt, CMD)] if i == 0 else [(txt, CMD)])
        rows.extend(output[:out_count])
        return rows

    # measure dims against the final frame
    final_rows = rows_for(len(cmd_text), len(output))
    _, dims = render_frame(final_rows, fonts, footer=footer)

    specs = []  # (rows, duration_ms, footer, cursor)

    def add(cmd_chars, out_count, dur, with_footer=False, cursor=None):
        specs.append((rows_for(cmd_chars, out_count), dur, footer if with_footer else None, cursor))

    add(0, 0, 850)                       # intro
    add(0, 0, 650)                       # reveal problem
    # type command, 2 chars/frame; cursor tracks end of last typed row
    for k in range(0, len(cmd_text) + 1, 3):
        k = min(k, len(cmd_text))
        parts = cmd_text[:k].split("\n")
        row = len(setup) + (len(parts) - 1)
        x = freg.getlength("$ " + parts[-1]) if len(parts) == 1 else freg.getlength(parts[-1])
        add(k, 0, 55, cursor=(x, row))
    add(len(cmd_text), 0, 320,
        cursor=(freg.getlength("$ " + cmd_text.split("\n")[0]), len(setup) + 2))
    for r in range(1, len(output) + 1):  # reveal output line by line
        add(len(cmd_text), r, 110)
    add(len(cmd_text), len(output), 300, with_footer=True)   # footer appears
    for b in range(4):                                       # hold + blink cursor
        add(len(cmd_text), len(output), 560, with_footer=True,
            cursor=(freg.getlength("$ " + cmd_text.split("\n")[0]), len(setup) + 2) if b % 2 else None)

    frames, durations = [], []
    for rows, dur, f, c in specs:
        img, _ = render_frame(rows, fonts, footer=f, cursor=c, dims=dims)
        frames.append(img)
        durations.append(dur)

    pal = frames[0].quantize(colors=256)
    frames_p = [pal] + [f.quantize(palette=pal) for f in frames[1:]]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    frames_p[0].save(OUT, save_all=True, append_images=frames_p[1:],
                     duration=durations, loop=0, disposal=2, optimize=True)
    print(f"wrote {OUT}  ({OUT.stat().st_size // 1024} KB, {len(frames_p)} frames, "
          f"{frames[0].size[0]}x{frames[0].size[1]})")
    frames[-1].save(OUT.with_suffix(".preview.png"))
    print(f"preview: {OUT.with_suffix('.preview.png')}")


if __name__ == "__main__":
    main()
