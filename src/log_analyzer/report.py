"""Reports: Markdown (for GitHub/Slack), JSON (for machines), HTML (for people),
and a short terminal summary.

Log messages are attacker-controlled text: a user can put anything in a
username or a URL, and it ends up in the log. So every message is cleaned
before display:
  * control characters (including ANSI terminal escapes and invisible
    right-to-left overrides) are shown as visible \\xNN codes,
  * Markdown and HTML special characters are escaped for their format.
"""

from __future__ import annotations

import html
import json
import re
from collections import Counter
from datetime import UTC, datetime

from .analyzer import Analysis

# C0/C1 control characters, line/paragraph separators, and bidi overrides.
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
MD_SPECIAL_RE = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~])")
SPARK = "▁▂▃▄▅▆▇█"
MAX_BUCKETS = 72


# ---- Cleaning text ------------------------------------------------------------


def clean(text: str, limit: int = 160, *, safe: bool = True) -> str:
    if safe:
        text = CONTROL_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", text)
        text = text.replace("\n", " ").replace("\t", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def md(text: str, limit: int = 160, *, safe: bool = True) -> str:
    text = clean(text, limit, safe=safe)
    return MD_SPECIAL_RE.sub(r"\\\1", text) if safe else text


def h(text: str, limit: int = 160, *, safe: bool = True) -> str:
    text = clean(text, limit, safe=safe)
    return html.escape(text, quote=True) if safe else text


def minute_iso(minute: int) -> str:
    # A chart window centred near year 9999 can run past the last date Python
    # can represent; show a placeholder instead of crashing the whole report.
    try:
        return datetime.fromtimestamp(minute * 60, UTC).strftime("%Y-%m-%d %H:%M")
    except (ValueError, OverflowError, OSError):
        return "out-of-range"


# ---- Timeline -----------------------------------------------------------------


def timeline(a: Analysis) -> tuple[int, int, list[int], int]:
    """Bucket errors over time: (start_minute, bucket_size, counts, outside).

    One entry stamped year 9999 among entries from 2026 would make the range
    5 billion minutes wide. With the guard on, we chart only the busiest
    window of at most max_timeline_minutes and count the rest as `outside`.
    """
    if not a.totals:
        return 0, 1, [], 0
    lo, hi = min(a.totals), max(a.totals)
    limit = a.options.max_timeline_minutes
    outside = 0
    if limit and hi - lo + 1 > limit:
        minutes = sorted(a.totals.elements())
        centre = minutes[len(minutes) // 2]
        lo, hi = centre - limit // 2, centre + limit // 2
        outside = sum(n for m, n in a.totals.items() if not lo <= m <= hi)
    span = hi - lo + 1
    size = max(1, -(-span // MAX_BUCKETS))  # ceiling division
    series = [a.errors.get(m, 0) for m in range(lo, hi + 1)]
    counts = [sum(series[i : i + size]) for i in range(0, span, size)]
    return lo, size, counts, outside


def sparkline(counts: list[int]) -> str:
    top = max(counts, default=0)
    if top == 0:
        return SPARK[0] * len(counts)
    return "".join(SPARK[min(len(SPARK) - 1, c * (len(SPARK) - 1) // top)] if c else " " for c in counts)


# ---- JSON ---------------------------------------------------------------------


def to_dict(a: Analysis, top: int = 10) -> dict:
    groups = a.grouper.ranked()
    return {
        "source": a.source,
        "summary": {
            "lines_read": a.lines_read,
            "entries": a.entries,
            "errors": a.error_total,
            "error_groups": len(groups),
            "malformed_lines": a.malformed_total,
            "malformed_pct": round(100 * a.malformed_total / a.lines_read, 2) if a.lines_read else 0.0,
            "recovered": dict(a.recovered),
            "bad_byte_entries": a.bad_byte_entries,
            "continuation_lines": a.continuation_lines,
            "blank_lines": a.blank_lines,
            "first_timestamp": a.first_ts.isoformat() if a.first_ts else None,
            "last_timestamp": a.last_ts.isoformat() if a.last_ts else None,
            "seconds": round(a.seconds, 4),
        },
        "levels": dict(a.levels.most_common()),
        "services": dict(a.services.most_common()),
        "top_error_groups": [
            {
                "fingerprint": g.fingerprint,
                "count": g.count,
                "services": dict(g.services.most_common()),
                "levels": dict(g.levels),
                "first_seen": g.first_seen.isoformat() if g.first_seen else None,
                "last_seen": g.last_seen.isoformat() if g.last_seen else None,
                "examples": g.examples,
            }
            for g in groups[:top]
        ],
        "spikes": [
            {
                "start": minute_iso(s.start_minute),
                "end": minute_iso(s.end_minute),
                "minutes": s.end_minute - s.start_minute + 1,
                "peak_errors_per_minute": s.peak_errors,
                "total_errors": s.total_errors,
                "normal_errors_per_minute": s.baseline,
                "top_groups": [{"fingerprint": fp, "count": n} for fp, n in s.top_groups],
            }
            for s in a.spikes
        ],
        "malformed": {
            "by_reason": dict(a.malformed.most_common()),
            "samples": [{"line": m.line_no, "reason": m.reason, "raw": m.raw} for m in a.malformed_samples],
        },
    }


def render_json(a: Analysis, top: int = 10) -> str:
    # json.dumps escapes control characters itself, so JSON needs no extra cleaning.
    return json.dumps(to_dict(a, top), indent=2, ensure_ascii=False)


# ---- Markdown -----------------------------------------------------------------


def render_markdown(a: Analysis, top: int = 10) -> str:
    safe = a.options.escape_output
    d = to_dict(a, top)
    s = d["summary"]
    out: list[str] = []
    w = out.append
    w(f"# Log report: {md(a.source, 120, safe=safe)}\n")
    w(f"{s['entries']:,} entries from {s['lines_read']:,} lines, {s['first_timestamp'] or '?'} to {s['last_timestamp'] or '?'}.\n")

    w("## At a glance\n")
    w("| Metric | Value |\n|---|---|")
    w(f"| Errors (ERROR + CRITICAL + FATAL) | {s['errors']:,} |")
    w(f"| Distinct error groups | {s['error_groups']:,} |")
    w(f"| Error spikes | {len(a.spikes)} |")
    w(f"| Malformed lines | {s['malformed_lines']:,} ({s['malformed_pct']}%) |")
    w(f"| Recovered (JSON lines, glued lines) | {a.recovered['json']:,}, {a.recovered['glued']:,} |")
    w(f"| Entries with unreadable bytes | {s['bad_byte_entries']:,} |")
    w(f"| Stack-trace lines attached | {s['continuation_lines']:,} |")
    w(f"| Analysis time | {s['seconds']:.3f} s |\n")

    w("## Levels\n")
    w("| Level | Count | Share |\n|---|---:|---:|")
    for level, n in a.levels.most_common():
        w(f"| {md(level, safe=safe)} | {n:,} | {100 * n / max(a.entries, 1):.1f}% |")
    w("")

    lo, size, counts, outside = timeline(a)
    if counts:
        w(f"## Errors over time ({size}-minute buckets)\n")
        w("```text")
        w(sparkline(counts))
        w(f"{minute_iso(lo)} UTC{' ' * max(1, len(counts) - 34)}{minute_iso(lo + size * len(counts) - 1)} UTC")
        w("```")
        if outside:
            w(f"\n{outside:,} entries had timestamps far outside this window and are not charted.")
        w("")

    w("## Spikes\n")
    if not a.spikes:
        w("No error spikes detected.\n")
    for i, sp in enumerate(d["spikes"], 1):
        w(f"### Spike {i}: {sp['start']} to {sp['end']} UTC ({sp['minutes']} min)\n")
        w(
            f"Peak **{sp['peak_errors_per_minute']}** errors/min against a normal "
            f"{sp['normal_errors_per_minute']:g}/min; {sp['total_errors']} errors in total. Main causes:\n"
        )
        for g in sp["top_groups"]:
            w(f"- {g['count']} × {md(g['fingerprint'], safe=safe)}")
        w("")

    w(f"## Top {min(top, len(d['top_error_groups']))} error groups\n")
    w("| # | Count | Error (variable parts masked) | Services | First seen | Last seen |")
    w("|---:|---:|---|---|---|---|")
    for i, g in enumerate(d["top_error_groups"], 1):
        services = ", ".join(md(x, 40, safe=safe) for x in g["services"])
        w(
            f"| {i} | {g['count']:,} | {md(g['fingerprint'], safe=safe)} | {services} | "
            f"{(g['first_seen'] or '')[11:19]} | {(g['last_seen'] or '')[11:19]} |"
        )
    w("")

    w("## Malformed lines\n")
    if not a.malformed:
        w("None.\n")
    else:
        w("| Reason | Lines |\n|---|---:|")
        for reason, n in a.malformed.most_common():
            w(f"| {md(reason, safe=safe)} | {n:,} |")
        w("\nFirst examples (control characters shown as \\xNN):\n")
        w("| Line | Reason | Raw text |\n|---:|---|---|")
        for m in a.malformed_samples[:10]:
            w(f"| {m.line_no} | {md(m.reason, safe=safe)} | {md(m.raw, 100, safe=safe)} |")
        w("")
    return "\n".join(out) + "\n"


# ---- HTML ---------------------------------------------------------------------

HTML_STYLE = """
body{font:15px/1.5 system-ui,-apple-system,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#1d1d1f}
h1{font-size:1.5rem}h2{font-size:1.15rem;margin-top:2rem;border-bottom:1px solid #ddd;padding-bottom:.3rem}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid #eee;padding:.35rem .5rem;text-align:left;vertical-align:top}
th{background:#f6f6f8}td.n{text-align:right;font-variant-numeric:tabular-nums}code{font-size:12px;word-break:break-all}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.6rem}
.card{background:#f6f6f8;border-radius:10px;padding:.7rem .9rem}.card b{display:block;font-size:1.4rem}
.spike{background:#fff4f2;border-left:4px solid #d70015;padding:.6rem .9rem;margin:.6rem 0;border-radius:6px}
svg{width:100%;height:auto}
"""


def _svg_chart(a: Analysis) -> str:
    lo, size, counts, outside = timeline(a)
    if not counts:
        return ""
    width, height, top = 900, 160, max(counts) or 1
    bar = width / len(counts)
    parts = [f'<svg viewBox="0 0 {width} {height + 20}" role="img" aria-label="Errors over time">']
    for sp in a.spikes:  # shade spike windows behind the bars
        x0 = (sp.start_minute - lo) / size * bar
        x1 = (sp.end_minute - lo + 1) / size * bar
        parts.append(f'<rect x="{x0:.1f}" y="0" width="{max(x1 - x0, 2):.1f}" height="{height}" fill="#ffd9d4"/>')
    for i, c in enumerate(counts):
        bh = c / top * (height - 4)
        parts.append(
            f'<rect x="{i * bar + 1:.1f}" y="{height - bh:.1f}" width="{max(bar - 2, 1):.1f}" '
            f'height="{bh:.1f}" fill="#0071e3"><title>{c} errors</title></rect>'
        )
    parts.append(f'<text x="0" y="{height + 16}" font-size="11">{minute_iso(lo)} UTC</text>')
    parts.append(f'<text x="{width}" y="{height + 16}" font-size="11" text-anchor="end">{minute_iso(lo + size * len(counts) - 1)} UTC</text></svg>')
    if outside:
        parts.append(f"<p>{outside:,} entries had timestamps far outside this window and are not charted.</p>")
    return "".join(parts)


def render_html(a: Analysis, top: int = 10) -> str:
    safe = a.options.escape_output
    d = to_dict(a, top)
    s = d["summary"]
    o: list[str] = []
    w = o.append
    w(
        f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' "
        f"content='width=device-width,initial-scale=1'><title>Log report</title><style>{HTML_STYLE}</style></head><body>"
    )
    w(f"<h1>Log report: <code>{h(a.source, 120, safe=safe)}</code></h1>")
    w(f"<p>{s['entries']:,} entries from {s['lines_read']:,} lines, {s['first_timestamp']} to {s['last_timestamp']}.</p>")
    w("<div class='cards'>")
    for label, value in [
        ("Errors", f"{s['errors']:,}"),
        ("Error groups", f"{s['error_groups']:,}"),
        ("Spikes", str(len(a.spikes))),
        ("Malformed lines", f"{s['malformed_lines']:,}"),
        ("Recovered", f"{sum(a.recovered.values()):,}"),
        ("Time", f"{s['seconds']:.2f} s"),
    ]:
        w(f"<div class='card'>{label}<b>{value}</b></div>")
    w("</div><h2>Errors over time</h2>")
    w(_svg_chart(a))
    w("<h2>Spikes</h2>")
    if not a.spikes:
        w("<p>No error spikes detected.</p>")
    for sp in d["spikes"]:
        causes = "".join(f"<li>{g['count']} × <code>{h(g['fingerprint'], safe=safe)}</code></li>" for g in sp["top_groups"])
        w(
            f"<div class='spike'><b>{sp['start']} to {sp['end']} UTC</b>: peak {sp['peak_errors_per_minute']} errors/min "
            f"against a normal {sp['normal_errors_per_minute']:g}/min.<ul>{causes}</ul></div>"
        )
    w("<h2>Top error groups</h2><table><tr><th>#</th><th>Count</th><th>Error</th><th>Services</th></tr>")
    for i, g in enumerate(d["top_error_groups"], 1):
        services = ", ".join(h(x, 40, safe=safe) for x in g["services"])
        w(
            f"<tr><td class='n'>{i}</td><td class='n'>{g['count']:,}</td><td><code>{h(g['fingerprint'], safe=safe)}</code>"
            f"</td><td>{services}</td></tr>"
        )
    w("</table><h2>Levels</h2><table><tr><th>Level</th><th>Count</th></tr>")
    for level, n in a.levels.most_common():
        w(f"<tr><td>{h(level, safe=safe)}</td><td class='n'>{n:,}</td></tr>")
    w("</table><h2>Malformed lines</h2>")
    if a.malformed:
        w("<table><tr><th>Reason</th><th>Lines</th></tr>")
        for reason, n in a.malformed.most_common():
            w(f"<tr><td>{h(reason, safe=safe)}</td><td class='n'>{n:,}</td></tr>")
        w("</table><h3>First examples</h3><table><tr><th>Line</th><th>Reason</th><th>Raw text</th></tr>")
        for m in a.malformed_samples[:10]:
            w(f"<tr><td class='n'>{m.line_no}</td><td>{h(m.reason, safe=safe)}</td><td><code>{h(m.raw, 100, safe=safe)}</code></td></tr>")
        w("</table>")
    else:
        w("<p>None.</p>")
    w("</body></html>")
    return "\n".join(o)


# ---- Terminal -----------------------------------------------------------------


def render_terminal(a: Analysis, top: int = 5) -> str:
    safe = a.options.escape_output
    lines = [
        f"Analysed {a.lines_read:,} lines in {a.seconds:.2f}s: {a.entries:,} entries, "
        f"{a.error_total:,} errors in {len(a.grouper.groups):,} groups, "
        f"{a.malformed_total:,} malformed lines, {len(a.spikes)} spike(s).",
    ]
    for sp in a.spikes:
        cause = clean(sp.top_groups[0][0], 70, safe=safe) if sp.top_groups else "?"
        lines.append(
            f"  SPIKE {minute_iso(sp.start_minute)}-{minute_iso(sp.end_minute)[11:]} UTC  peak {sp.peak_errors}/min (normal {sp.baseline:g})  {cause}"
        )
    lines.append("Top error groups:")
    for g in a.grouper.ranked()[:top]:
        lines.append(f"  {g.count:>6,}  {clean(g.fingerprint, 90, safe=safe)}")
    if a.malformed:
        reasons = ", ".join(f"{r}={n}" for r, n in Counter(a.malformed).most_common())
        lines.append(f"Malformed: {reasons}")
    return "\n".join(lines)
