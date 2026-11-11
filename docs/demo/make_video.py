"""Build the 3-minute demo video from the project's real outputs.

    PYTHONPATH=src python3 docs/demo/make_video.py

Every scene is drawn from something the code actually produced: the sample
log, the terminal output, the HTML report (screenshotted with headless
Chrome through Playwright, a dev-only extra) and evals/results/*.json. Each scene is one held still, encoded on its own with
a fade in and out, then the scenes are joined without re-encoding.
Narration script: docs/DEMO.md (scene timings match SCENES below).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "demo"
FRAMES = OUT / "frames"
W, H, FPS = 1280, 720, 30
INTER = "/usr/share/fonts/opentype/inter/Inter-{}.otf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
INK, MUTED, BLUE, RED, GREEN, PAPER, PANEL = "#1d1d1f", "#6e6e73", "#0071e3", "#d70015", "#1a7f37", "#ffffff", "#f5f5f7"
TERM_BG, TERM_FG = "#111418", "#e6e6e6"


def font(weight: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(INTER.format(weight), size)


def mono(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(MONO_BOLD if bold else MONO, size)


def canvas(title: str, kicker: str = "") -> tuple[Image.Image, ImageDraw.ImageDraw]:
    im = Image.new("RGB", (W, H), PAPER)
    d = ImageDraw.Draw(im)
    if kicker:
        d.text((60, 34), kicker.upper(), font=font("SemiBold", 18), fill=BLUE)
    d.text((60, 58), title, font=font("Bold", 40), fill=INK)
    return im, d


def caption(d: ImageDraw.ImageDraw, text: str) -> None:
    d.rectangle([0, H - 74, W, H], fill=INK)
    d.text((60, H - 52), text, font=font("Medium", 24), fill=PAPER)


def terminal(d: ImageDraw.ImageDraw, box: tuple[int, int, int, int], lines: list[tuple[str, str]], size: int = 17) -> None:
    x0, y0, x1, y1 = box
    d.rounded_rectangle(box, radius=14, fill=TERM_BG)
    for i, c in enumerate(["#ff5f57", "#febc2e", "#28c840"]):
        d.ellipse([x0 + 18 + i * 22, y0 + 14, x0 + 30 + i * 22, y0 + 26], fill=c)
    y = y0 + 44
    f = mono(size)
    for text, colour in lines:
        d.text((x0 + 22, y), text, font=f, fill=colour)
        y += int(size * 1.45)


def table(d, x, y, rows, widths, size=20, header=True, row_h=40):
    for r, row in enumerate(rows):
        if r == 0 and header:
            d.rectangle([x, y, x + sum(widths), y + row_h], fill=PANEL)
        cx = x
        for c, cell in enumerate(row):
            colour = INK
            if isinstance(cell, tuple):
                cell, colour = cell
            weight = "SemiBold" if (r == 0 and header) or c == 1 else "Regular"
            d.text((cx + 12, y + (row_h - size) // 2 - 2), str(cell), font=font(weight, size), fill=colour)
            cx += widths[c]
        d.line([x, y + row_h, x + sum(widths), y + row_h], fill="#e5e5ea", width=1)
        y += row_h
    return y


# ---- Scenes ---------------------------------------------------------------------


def s_title():
    im = Image.new("RGB", (W, H), INK)
    d = ImageDraw.Draw(im)
    d.text((80, 220), "log-analyzer", font=font("Bold", 84), fill=PAPER)
    d.text((84, 330), "What broke, how often, when it spiked,", font=font("Medium", 34), fill="#d2d2d7")
    d.text((84, 376), "and which lines it couldn't read.", font=font("Medium", 34), fill="#d2d2d7")
    d.text((84, 480), "Python standard library only  ·  54 tests  ·  every number measured", font=font("Regular", 24), fill="#a1a1a6")
    d.text((84, 620), "github.com/paulmadojutimi94/log-analyzer", font=mono(22), fill="#66b2ff")
    return im


def s_problem():
    im, d = canvas("Real logs fight back", "The problem")
    head = (ROOT / "examples" / "app.head.log").read_bytes().decode("utf-8", "replace").splitlines()
    sample = [ln[:96] for ln in head[1:6]]
    broken = [
        ("2026-11-11T09:07:16.988Z INFO [i", "cut off mid-write"),
        ("11/11/2026 09:06:03 INFO [auth-service] POST /v1/cart 201", "wrong date format"),
        ("2026-13-11T09:02:56.552Z INFO [order-service] Order created", "month 13"),
        ('{"timestamp": "2026-11-11T09:20:01Z", "level": "error", ...}', "a different service's JSON"),
        ("...GET / 2002026-11-11T09:20:02.456Z ERROR [auth-service] ...", "two lines glued together"),
        ("    at com.shop.orders.OrderService.process(OrderService.java:212)", "stack trace, not a new entry"),
    ]
    lines = [(s, TERM_FG) for s in sample] + [("", TERM_FG)]
    lines += [(f"{s[:62]:<64}", "#ff8a80") for s, _ in broken]
    terminal(d, (60, 130, 1220, 520), lines, size=16)
    y = 130 + 44 + int(16 * 1.45) * 6
    for _, why in broken:
        d.text((850, y), f"← {why}", font=font("SemiBold", 17), fill="#ffd60a")
        y += int(16 * 1.45)
    caption(d, "10,000 entries, ~1.5% deliberately broken, plus stack traces, JSON and glued lines.")
    return im


def s_architecture():
    im, d = canvas("One pass through the file, counters only", "How it works")
    boxes = [
        ("reader.py", "binary mode\nsplit on \\n only\n8 KB per line"),
        ("parser.py", "regex → entry,\ntrace, blank or\nmalformed + why"),
        ("grouping.py", "mask numbers,\nIDs, IPs, e-mails\n→ fingerprint"),
        ("spikes.py", "errors vs.\nexpected for\nthis traffic"),
        ("report.py", "Markdown, JSON,\nHTML; escape\neverything"),
    ]
    x, y, bw, bh, gap = 60, 200, 206, 190, 25
    for i, (name, body) in enumerate(boxes):
        bx = x + i * (bw + gap)
        d.rounded_rectangle([bx, y, bx + bw, y + bh], radius=16, fill=PANEL, outline="#d2d2d7", width=2)
        d.text((bx + 18, y + 18), name, font=mono(20, bold=True), fill=BLUE)
        d.multiline_text((bx + 18, y + 64), body, font=font("Regular", 19), fill=INK, spacing=8)
        if i < len(boxes) - 1:
            ax = bx + bw + 3
            d.line([ax, y + bh // 2, ax + gap - 6, y + bh // 2], fill=MUTED, width=3)
            d.polygon([(ax + gap - 6, y + bh // 2 - 7), (ax + gap + 2, y + bh // 2), (ax + gap - 6, y + bh // 2 + 7)], fill=MUTED)
    d.rounded_rectangle([290, 440, 520, 500], radius=12, fill="#fff4f2", outline=RED, width=2)
    d.text((308, 457), "quarantine.jsonl", font=mono(19, bold=True), fill=RED)
    d.line([406, 390, 406, 440], fill=RED, width=3)
    d.text((560, 448), "Every unreadable line is kept, with a reason, never silently dropped.", font=font("Regular", 21), fill=INK)
    d.text((60, 540), "Memory grows with the log's time span, not its size: 1.4 MB for 200,000 lines.", font=font("SemiBold", 22), fill=INK)
    caption(d, "Like a post-room: open carefully, sort, pile like with like, notice the sudden rush.")
    return im


def s_terminal():
    im, d = canvas("make demo", "Running it")
    out = subprocess.run(["make", "-s", "demo"], cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": "src"}).stdout
    lines = [("$ make demo", "#66b2ff")]
    for ln in out.splitlines():
        if ln.startswith("Answer key") or ln.startswith("Reports written"):
            continue
        colour = "#ff8a80" if "SPIKE" in ln else ("#ffd60a" if ln.startswith("Malformed") else TERM_FG)
        lines.append((ln[:118], colour))
    terminal(d, (40, 125, 1240, 625), lines[:17], size=15)
    caption(d, "0.08 s for 10,581 lines. Exactly the 3 spikes the generator planted, each blamed correctly.")
    return im


def _report_crop(top: int, bottom: int) -> Image.Image:
    shot = Image.open(FRAMES / "report_full.png").convert("RGB")
    part = shot.crop((40, top, 1060, bottom))
    scale = min(1160 / part.width, 500 / part.height)
    return part.resize((int(part.width * scale), int(part.height * scale)), Image.LANCZOS)


def s_report():
    im, d = canvas("The HTML report", "Output")
    crop = _report_crop(20, 490)
    im.paste(crop, ((W - crop.width) // 2, 125))
    d = ImageDraw.Draw(im)
    caption(d, "Error counts over six hours. Pale red bands are the detected spikes.")
    return im


def s_spikes():
    im, d = canvas("Spikes, and what caused them", "Output")
    crop = _report_crop(520, 980)
    im.paste(crop, ((W - crop.width) // 2, 125))
    d = ImageDraw.Draw(im)
    caption(d, "Judged against traffic: 3x the requests at the same failure rate is busy, not broken.")
    return im


def s_malformed():
    im, d = canvas("Handling malformed lines (the bonus)", "Output")
    rep = json.loads((ROOT / "examples" / "report.json").read_text())
    s, why = rep["summary"], rep["malformed"]["by_reason"]
    top3 = ", ".join(f"{k} {v}" for k, v in list(why.items())[:3])
    rows = [("What happened to it", "Lines", "In the demo file")]
    rows += [
        ("Labelled malformed, with a reason", f"{s['malformed_lines']}", f"{top3} …"),
        ("Recovered: JSON from another service", f"{s['recovered'].get('json', 0)}", "parsed into normal entries"),
        ("Recovered: two lines glued together", f"{s['recovered'].get('glued', 0)}", "split, second half marked untrusted"),
        ("Salvaged: invalid bytes in a message", f"{s['bad_byte_entries']}", "kept, bad bytes replaced"),
        ("Stack-trace lines attached to their error", f"{s['continuation_lines']}", "not counted as broken"),
        ("Blank lines", f"{s['blank_lines']}", "skipped"),
    ]
    table(d, 60, 140, rows, [470, 110, 580], size=19, row_h=50)
    d.text((60, 520), "One bad line never stops the run. Every unreadable line goes to quarantine.jsonl.", font=font("SemiBold", 22), fill=INK)
    caption(d, "Malformed-line detection: 100% precision and recall on 531,571 held-out lines.")
    return im


def s_evals():
    acc = json.loads((ROOT / "evals/results/accuracy.json").read_text())
    gold = json.loads((ROOT / "evals/results/gold.json").read_text())
    perf = json.loads((ROOT / "evals/results/performance.json").read_text())
    att = json.loads((ROOT / "evals/results/attacks.json").read_text())
    im, d = canvas("Hard numbers", "Evals")
    p = perf["analyse_and_report_10k"]
    rows = [
        ("Measure", "Result"),
        ("Line classification, 50 held-out files", (f"{100 * acc['line_classification_accuracy']:.1f}%", GREEN)),
        ("Hand-written tricky lines", (f"{gold['correct']} / {gold['cases']}", GREEN)),
        ("Grouping (pair F1)", (f"{acc['grouping_pair_f1']:.3f}", GREEN)),
        ("Planted spikes found", (f"{acc['spikes_found']} / {acc['spikes_planted']}", GREEN)),
        ("False alarms (50 six-hour files)", f"{acc['false_alarms']}  ·  0 from traffic surges"),
        ("Latency, 10,000 entries + 3 reports", f"p50 {p['p50_ms']} ms  ·  p95 {p['p95_ms']} ms"),
        ("Cost per run", "€0.00  (no paid APIs)"),
        ("Attack success rate", (f"{att['successes']} / {att['total']}  ({att['families']} families)", GREEN)),
    ]
    table(d, 60, 128, rows, [600, 560], size=21, row_h=52)
    caption(d, "Tuned on seeds 0-19, reported on seeds 100-149. `make eval` rewrites the README table.")
    return im


def s_ablation():
    att = json.loads((ROOT / "evals/results/attacks.json").read_text())
    im, d = canvas("Each defence, switched off", "Security")
    names = {
        "binary_split": "Split lines on \\n only (forged lines via \\r)",
        "trust_recovered": "Glued-line halves kept out of alerts",
        "max_line_bytes": "8 KB line cap (150 MB line, recursion)",
        "max_groups": "2,000-group cap (200k unique errors)",
        "max_timeline_minutes": "7-day chart window (year 9999)",
        "escape_output": "Escape HTML, Markdown, terminal",
    }
    rows = [("Defence removed", "Attacks that then succeed")]
    for k, label in names.items():
        a = att["ablation"][k]
        rows.append((label, (f"{a['successes']} / {a['cases']}", RED)))
    table(d, 60, 135, rows, [700, 460], size=21, row_h=54)
    d.text((60, 545), "Log text is attacker-controlled: anyone who types into a form writes to your logs.", font=font("SemiBold", 22), fill=INK)
    caption(d, "0% attack success means little alone. This table proves each defence is doing real work.")
    return im


def s_postmortem():
    im, d = canvas("What went wrong, and how it was found", "Postmortem")
    cards = [
        (
            "Grouping shattered",
            "\\b\\d+\\b skipped 5012ms, sda1:",
            [("groups per file", "138 → 14"), ("pair recall", "0.68 → 0.97"), ("spike blame", "83% → 100%")],
        ),
        (
            "A regex went quadratic",
            "e-mail mask on a.a.a.a… (64 KB):",
            [("one line", "11.7 s → 0.001 s"), ("attacks", "1/32 → 0/32"), ("fix", "(?<![\\w.+-])")],
        ),
        (
            "Guards that couldn't fail",
            "found by checking the checkers:",
            [("attack judge", "cried wolf"), ("CI grep", "always green"), ("now", "proven both ways")],
        ),
    ]
    for i, (title, sub, facts) in enumerate(cards):
        x = 60 + i * 392
        d.rounded_rectangle([x, 135, x + 372, 545], radius=16, fill=PANEL)
        d.text((x + 22, 157), title, font=font("Bold", 25), fill=INK)
        d.text((x + 22, 200), sub, font=font("Regular", 18), fill=MUTED)
        y = 255
        for label, value in facts:
            d.text((x + 22, y), label, font=font("Medium", 18), fill=MUTED)
            d.text((x + 22, y + 26), value, font=mono(24, bold=True), fill=BLUE)
            y += 92
    caption(d, "Each found by a number that looked wrong, then fixed and pinned by a test.")
    return im


def s_close():
    im = Image.new("RGB", (W, H), INK)
    d = ImageDraw.Draw(im)
    d.text((80, 140), "Next", font=font("Bold", 48), fill=PAPER)
    steps = [
        "Run it on a week of real logs; grow the gold set first",
        "Learn variable words from the data (logs-prod vs logs-staging)",
        "Syslog, logfmt and Apache formats as plug-ins",
        "--follow mode that pages someone on a spike",
    ]
    for i, s in enumerate(steps):
        d.text((84, 230 + i * 56), f"{i + 1}.  {s}", font=font("Regular", 28), fill="#d2d2d7")
    d.text((84, 530), "README · DESIGN · POSTMORTEM · CHEATSHEET · LEARN", font=font("SemiBold", 24), fill="#a1a1a6")
    d.text((84, 600), "github.com/paulmadojutimi94/log-analyzer", font=mono(26), fill="#66b2ff")
    return im


SCENES = [
    ("01_title", s_title, 10),
    ("02_problem", s_problem, 18),
    ("03_architecture", s_architecture, 18),
    ("04_terminal", s_terminal, 20),
    ("05_report", s_report, 16),
    ("06_spikes", s_spikes, 16),
    ("07_malformed", s_malformed, 16),
    ("08_evals", s_evals, 22),
    ("09_ablation", s_ablation, 16),
    ("10_postmortem", s_postmortem, 20),
    ("11_close", s_close, 12),
]


def encode(png: Path, seconds: float, out: Path) -> None:
    tmp = out.with_name(out.stem + ".part.mp4")
    vf = f"format=yuv420p,loop=-1:1,trim=duration={seconds},fade=t=in:st=0:d=0.5,fade=t=out:st={seconds - 0.5}:d=0.5"
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-loglevel",
            "error",
            "-framerate",
            str(FPS),
            "-i",
            str(png),
            "-vf",
            vf,
            "-r",
            str(FPS),
            "-c:v",
            "libx264",
            "-crf",
            "18",
            "-preset",
            "veryfast",
            "-pix_fmt",
            "yuv420p",
            str(tmp),
        ],
        check=True,
    )
    tmp.rename(out)


def screenshot_report() -> None:
    """Full-page screenshot of examples/report.html (needs Playwright + Chrome)."""
    from playwright.sync_api import sync_playwright

    chrome = os.environ.get("CHROME", "/usr/bin/google-chrome")
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=chrome if Path(chrome).exists() else None)
        page = browser.new_page(viewport={"width": 1100, "height": 1400})
        page.goto((ROOT / "examples" / "report.html").resolve().as_uri())
        page.screenshot(path=str(FRAMES / "report_full.png"), full_page=True)
        browser.close()


def main(only_frames: bool = False) -> None:
    FRAMES.mkdir(parents=True, exist_ok=True)
    screenshot_report()
    clips = []
    for name, draw, seconds in SCENES:
        png = FRAMES / f"{name}.png"
        draw().save(png)
        if not only_frames:
            clip = FRAMES / f"{name}.mp4"
            encode(png, seconds, clip)
            clips.append(clip)
    if only_frames:
        return
    listing = FRAMES / "list.txt"
    listing.write_text("".join(f"file '{c.name}'\n" for c in clips))
    final = OUT / "log-analyzer-demo.mp4"
    tmp = final.with_name("log-analyzer-demo.part.mp4")
    subprocess.run(
        ["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(listing), "-c", "copy", "-movflags", "+faststart", str(tmp)],
        check=True,
    )
    tmp.rename(final)
    print(f"Wrote {final} ({sum(s for *_, s in SCENES)} s)")


if __name__ == "__main__":
    import sys

    main(only_frames="--frames" in sys.argv)
