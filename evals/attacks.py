"""Attack eval: can hostile log content break, slow down, or fool the analyzer?

Who is the attacker? Anyone who can get text into a log: a username, a URL,
a User-Agent header. They don't need access to the server.

Each case runs in its own child process with a 10-second time limit and a
1.5 GB memory limit, so an attack that works (hang, crash, memory blow-up)
is recorded instead of taking the eval down with it.

Ablation: every defence is then switched off on its own and the cases it is
meant to stop are run again. If an attack still fails with its defence off,
either the attack is weak or the defence is not what is stopping it, and
both are worth knowing.
"""

from __future__ import annotations

import json
import re
import resource
import subprocess
import sys
import tempfile
from dataclasses import asdict, replace
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.analyzer import Options  # noqa: E402

TIMEOUT_S = 10
MEMORY_LIMIT = 1536 * 1024 * 1024
RSS_LIMIT_MB = 300
HEAD = "2026-11-11T09:{m:02d}:{s:02d}.000Z"
FORGED = "Admin password changed"


def normal_lines(n: int = 600) -> list[str]:
    """Background traffic: n INFO lines over 30 minutes."""
    return [f"{HEAD.format(m=i * 30 // n, s=i % 60)} INFO [api-gateway] GET /v1/products/{i} 200 12ms" for i in range(n)]


def at(minute: int, sec: int = 0) -> str:
    return HEAD.format(m=minute, s=sec)


# ---- Building the attack files -------------------------------------------------
# Each builder writes a file and returns nothing; `check` judges the outcome.


def _write(path: Path, lines: list[str] | None = None, raw: bytes = b"") -> None:
    with path.open("wb") as f:
        for line in lines or []:
            f.write(line.encode("utf-8", "surrogatepass") + b"\n")
        f.write(raw)


def forge_cr(path: Path, burst: int = 1, sep: str = "\r") -> None:
    forged = [
        f"{at(20, 0)} WARN [auth-service] login failed for user bob{sep}{at(20, s % 60)} CRITICAL [auth-service] {FORGED}" for s in range(burst)
    ]
    _write(path, normal_lines() + forged)


def forge_embedded(path: Path, burst: int = 1, gap: str = " ") -> None:
    forged = [
        f"{at(20, 0)} WARN [auth-service] login failed for user=bob{gap}{at(20, s % 60)}{gap}CRITICAL{gap}[auth-service] {FORGED}"
        for s in range(burst)
    ]
    _write(path, normal_lines() + forged)


def huge_line(path: Path, mb: int) -> None:
    with path.open("wb") as f:
        f.write(f"{at(1)} ERROR [api-gateway] ".encode())
        chunk = b"A" * (1024 * 1024)
        for _ in range(mb):
            f.write(chunk)
        f.write(b"\n")


def many_long_lines(path: Path, n: int, kb: int) -> None:
    body = "B" * (kb * 1024)
    _write(path, [f"{at(i % 60)} ERROR [api-gateway] {body}" for i in range(n)])


def slow_regex(path: Path, n: int, length: int) -> None:
    # "a.a.a.a..." with no "@". There is a word boundary before every "a", so
    # an e-mail pattern starting with \b can begin at every one of them and
    # scan to the end of the line each time: quadratic work. (A plain "aaaa"
    # run has only one word boundary, which is why the first version of this
    # attack was too weak to find anything; see docs/POSTMORTEM.md.)
    _write(path, normal_lines(100) + [f"{at(5, i % 60)} ERROR [api-gateway] {'a.' * (length // 2)}" for i in range(n)])


def glued_chain(path: Path, n: int) -> None:
    piece = f"{at(5)} ERROR [api-gateway] x"
    _write(path, [piece * n])


def group_explosion(path: Path, n: int) -> None:
    import random

    r = random.Random(1)
    words = ["".join(r.choice("qwrtypsdfghjklzxcvbnm") for _ in range(10)) for _ in range(n)]
    _write(path, [f"{at(i * 30 // n, i % 60)} ERROR [api-gateway] tenant {w} failed" for i, w in enumerate(words)])


def clock_skew(path: Path, stamp: str) -> None:
    _write(path, normal_lines() + [f"{stamp} ERROR [api-gateway] clock is wrong"])


def nested_json(path: Path, depth: int) -> None:
    _write(path, normal_lines(50) + ['{"a":' * depth + "1" + "}" * depth])


def message_payload(path: Path, payload: str, as_malformed: bool = False) -> None:
    line = payload if as_malformed else f"{at(10)} ERROR [api-gateway] {payload}"
    _write(path, normal_lines(50) + [line] * 3)


# ---- Judging the outcome -------------------------------------------------------


class _TagScan(HTMLParser):
    BAD_TAGS = {"script", "img", "iframe", "a", "object", "embed", "link", "meta", "form", "base"}

    def __init__(self) -> None:
        super().__init__()
        self.bad: list[str] = []
        self.in_body = False  # log text only ever lands in <body>; <head> is ours

    def handle_starttag(self, tag, attrs):
        if tag == "body":
            self.in_body = True
            return
        if not self.in_body:
            return
        if tag in self.BAD_TAGS:
            self.bad.append(tag)
        for name, value in attrs:
            if name.startswith("on") or (value and value.strip().lower().startswith("javascript:")):
                self.bad.append(f"{tag}[{name}]")


def html_injected(html: str) -> bool:
    scan = _TagScan()
    scan.feed(html)
    return bool(scan.bad)


UNESCAPED_LINK = re.compile(r"(?<!\\)\]\((?!\s)")
UNESCAPED_TAG = re.compile(r"(?<!\\)<[a-zA-Z!/]")
UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")


def markdown_injected(md: str) -> bool:
    if UNESCAPED_LINK.search(md) or UNESCAPED_TAG.search(md):
        return True
    # Every row of a table must keep its column count.
    for block in md.split("\n\n"):
        rows = [r for r in block.splitlines() if r.startswith("|")]
        if rows and len({len(UNESCAPED_PIPE.findall(r)) for r in rows}) > 1:
            return True
    return False


def forged_trusted(result: dict) -> bool:
    return any(FORGED in fp for fp in result["groups"]) or result["spikes"] > 0


CASES = [
    # family, id, builder, judge, the defence that should stop it
    ("log forging (\\r)", "cr_single", lambda p: forge_cr(p), forged_trusted, "binary_split"),
    ("log forging (\\r)", "cr_burst_fake_spike", lambda p: forge_cr(p, 40), forged_trusted, "binary_split"),
    ("log forging (\\r)", "cr_crlf", lambda p: forge_cr(p, 1, "\r\r"), forged_trusted, "binary_split"),
    ("log forging (embedded line)", "embedded_single", lambda p: forge_embedded(p), forged_trusted, "trust_recovered"),
    ("log forging (embedded line)", "embedded_burst_fake_spike", lambda p: forge_embedded(p, 40), forged_trusted, "trust_recovered"),
    ("log forging (embedded line)", "embedded_tabs", lambda p: forge_embedded(p, 1, "\t"), forged_trusted, "trust_recovered"),
    ("oversized lines", "one_line_150mb", lambda p: huge_line(p, 150), "resource", "max_line_bytes"),
    ("oversized lines", "400_lines_of_1mb", lambda p: many_long_lines(p, 400, 1024), "resource", "max_line_bytes"),
    ("slow regex", "email_mask_quadratic_200x8kb", lambda p: slow_regex(p, 200, 8100), "resource", "max_line_bytes"),
    ("slow regex", "email_mask_quadratic_20x200kb", lambda p: slow_regex(p, 20, 200_000), "resource", "max_line_bytes"),
    ("slow regex", "glued_recursion_5000", lambda p: glued_chain(p, 5000), "resource", "max_line_bytes"),
    ("group explosion", "200k_unique_errors", lambda p: group_explosion(p, 200_000), "groups", "max_groups"),
    ("clock skew", "year_9999", lambda p: clock_skew(p, "9999-12-31T23:59:59.000Z"), "resource", "max_timeline_minutes"),
    ("clock skew", "year_0001", lambda p: clock_skew(p, "0001-01-01T00:00:00.000Z"), "resource", "max_timeline_minutes"),
    ("parser crash", "nested_json_1600", lambda p: nested_json(p, 1600), "resource", None),
    ("parser crash", "nested_json_100k", lambda p: nested_json(p, 100_000), "resource", None),
]

HTML_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '"><script>alert(1)</script>',
    '<a href="javascript:alert(1)">x</a>',
    "<iframe src=//evil.example>",
]
for i, payload in enumerate(HTML_PAYLOADS):
    CASES.append(("HTML report injection", f"html_{i}", lambda p, x=payload: message_payload(p, x), "html", "escape_output"))
CASES.append(
    ("HTML report injection", "html_malformed_line", lambda p: message_payload(p, "<script>alert(2)</script>", True), "html", "escape_output")
)

MD_PAYLOADS = [
    "[click me](javascript:alert(1))",
    "![x](https://evil.example/track.png)",
    "<script>alert(1)</script>",
    "a | fake | column",
    "<details open>hidden</details>",
]
for i, payload in enumerate(MD_PAYLOADS):
    CASES.append(("Markdown report injection", f"md_{i}", lambda p, x=payload: message_payload(p, x), "markdown", "escape_output"))

TERM_PAYLOADS = ["\x1b]0;pwned\x07", "\x1b[2J\x1b[H all clear", "\x1b[8m hidden", "invoice‮gnp.exe"]
for i, payload in enumerate(TERM_PAYLOADS):
    CASES.append(("terminal escape injection", f"term_{i}", lambda p, x=payload: message_payload(p, x), "terminal", "escape_output"))


# ---- Child process -------------------------------------------------------------


def _worker(path: str, options_json: str) -> None:
    from log_analyzer.analyzer import analyze
    from log_analyzer.report import render_html, render_markdown, render_terminal
    from log_analyzer.spikes import SpikeConfig

    raw = json.loads(options_json)
    raw["spikes"] = SpikeConfig(**raw["spikes"])
    a = analyze(path, Options(**raw))
    html, md, term = render_html(a), render_markdown(a), render_terminal(a)
    rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    print(
        json.dumps(
            {
                "groups": list(a.grouper.groups),
                "group_count": len(a.grouper.groups),
                "spikes": len(a.spikes),
                "html": html_injected(html),
                "markdown": markdown_injected(md),
                "terminal": "\x1b" in term or "‮" in term,
                "rss_mb": round(rss_mb, 1),
            }
        )
    )


def _limit_memory() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT, MEMORY_LIMIT))


def run_case(path: Path, judge, options: Options) -> tuple[bool, str]:
    cmd = [sys.executable, __file__, "--worker", str(path), json.dumps(asdict(options))]
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_S, preexec_fn=_limit_memory)
    except subprocess.TimeoutExpired:
        return True, f"hung > {TIMEOUT_S}s"
    if done.returncode != 0:
        last = (done.stderr.strip().splitlines() or ["?"])[-1]
        return True, f"crashed: {last[:120]}"
    result = json.loads(done.stdout)
    if callable(judge):
        return judge(result), f"groups={result['group_count']} spikes={result['spikes']}"
    if judge == "resource":
        return result["rss_mb"] > RSS_LIMIT_MB, f"peak memory {result['rss_mb']} MB"
    if judge == "groups":
        bad = result["group_count"] > 10_000 or result["rss_mb"] > RSS_LIMIT_MB
        return bad, f"{result['group_count']} groups, {result['rss_mb']} MB"
    return result[judge], judge


def run(verbose: bool = False) -> dict:
    safe = Options()
    out = {"cases": [], "ablation": {}}
    with tempfile.TemporaryDirectory() as tmp:
        files = {}
        for family, cid, build, judge, defence in CASES:
            path = Path(tmp) / f"{cid}.log"
            build(path)
            files[cid] = path
            ok, detail = run_case(path, judge, safe)
            out["cases"].append({"family": family, "id": cid, "success": ok, "detail": detail, "defence": defence})
            if verbose:
                print(f"{'BREACH' if ok else 'held  '} {family:30} {cid:32} {detail}", file=sys.stderr)

        off = {
            "binary_split": {"binary_split": False},
            "trust_recovered": {"trust_recovered": True},
            "max_line_bytes": {"max_line_bytes": None},
            "max_groups": {"max_groups": None},
            "max_timeline_minutes": {"max_timeline_minutes": None},
            "escape_output": {"escape_output": False},
        }
        for defence, change in off.items():
            relevant = [c for c in CASES if c[4] == defence]
            wins = []
            for _family, cid, _, judge, _ in relevant:
                ok, detail = run_case(files[cid], judge, replace(safe, **change))
                wins.append({"id": cid, "success": ok, "detail": detail})
                if verbose:
                    print(f"[{defence} OFF] {'BREACH' if ok else 'held  '} {cid:32} {detail}", file=sys.stderr)
            out["ablation"][defence] = {"successes": sum(w["success"] for w in wins), "cases": len(wins), "detail": wins}

    out["total"] = len(out["cases"])
    out["successes"] = sum(c["success"] for c in out["cases"])
    out["families"] = len({c["family"] for c in out["cases"]})
    return out


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        _worker(sys.argv[2], sys.argv[3])
    else:
        result = run(verbose=True)
        print(json.dumps({k: v for k, v in result.items() if k != "cases"}, indent=2, default=str))
        print(f"\nAttack success rate: {result['successes']}/{result['total']}")
