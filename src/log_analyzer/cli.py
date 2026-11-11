"""Command line: `log-analyzer generate` and `log-analyzer analyze`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyzer import Options, analyze
from .generator import write
from .report import render_html, render_json, render_markdown, render_terminal

FORMATS = {"md": ("report.md", render_markdown), "json": ("report.json", render_json), "html": ("report.html", render_html)}


def _cmd_generate(args: argparse.Namespace) -> int:
    truth = write(args.output, n=args.n, seed=args.seed, with_truth=not args.no_truth)
    print(f"Wrote {args.n:,} log events ({len(truth['lines']):,} lines) to {args.output}")
    if not args.no_truth:
        print(f"Answer key: {Path(args.output).with_suffix('.truth.json')}")
    return 0


def _cmd_analyze(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    quarantine = None if args.no_quarantine else out / "quarantine.jsonl"
    try:
        a = analyze(args.path, Options(), quarantine=quarantine)
    except FileNotFoundError:
        print(f"error: no such file: {args.path}", file=sys.stderr)
        return 2
    for fmt in args.format.split(","):
        name, render = FORMATS[fmt.strip()]
        (out / name).write_text(render(a, args.top), encoding="utf-8")
    print(render_terminal(a))
    print(f"Reports written to {out}/")
    if args.fail_on_spike and a.spikes:
        return 1  # lets a CI job or cron fail loudly when there's a spike
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="log-analyzer", description="Parse logs, group errors, detect spikes, write reports.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="write a realistic, messy sample log")
    g.add_argument("-n", type=int, default=10_000, help="number of log events (default 10,000)")
    g.add_argument("--seed", type=int, default=42, help="same seed, same file")
    g.add_argument("-o", "--output", default="data/app.log")
    g.add_argument("--no-truth", action="store_true", help="skip the answer-key file")
    g.set_defaults(func=_cmd_generate)

    a = sub.add_parser("analyze", help="analyse a log file ('-' for stdin; .gz auto-detected)")
    a.add_argument("path")
    a.add_argument("-o", "--out", default="reports")
    a.add_argument("--format", default="md,json,html", help="comma-separated: md,json,html")
    a.add_argument("--top", type=int, default=10, help="error groups to list")
    a.add_argument("--no-quarantine", action="store_true", help="don't write malformed lines to quarantine.jsonl")
    a.add_argument("--fail-on-spike", action="store_true", help="exit 1 if any spike is found")
    a.set_defaults(func=_cmd_analyze)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
