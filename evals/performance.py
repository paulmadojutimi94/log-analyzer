"""Latency, throughput, memory and cost.

p50 / p95: half of the runs were faster than p50, 95 in 100 faster than p95.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from statistics import quantiles

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer.analyzer import analyze  # noqa: E402
from log_analyzer.generator import generate  # noqa: E402
from log_analyzer.parser import parse_lines  # noqa: E402
from log_analyzer.reader import iter_lines, open_log  # noqa: E402
from log_analyzer.report import render_html, render_json, render_markdown  # noqa: E402


def pcts(samples: list[float]) -> dict:
    cuts = quantiles(samples, n=100, method="inclusive")
    return {"p50_ms": round(cuts[49] * 1000, 1), "p95_ms": round(cuts[94] * 1000, 1), "runs": len(samples)}


def timed(fn, runs: int) -> list[float]:
    fn()  # warm-up run, not counted
    out = []
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t)
    return out


def peak_memory_mb(fn) -> float:
    tracemalloc.start()
    fn()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return round(peak / 1e6, 2)


def run() -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        small = Path(tmp) / "app.log"
        small.write_bytes(generate(n=10_000, seed=7)[0])
        big = Path(tmp) / "big.log"
        big.write_bytes(generate(n=200_000, seed=7, minutes=360 * 20)[0])

        def parse_only(path=small):
            with open_log(path) as fh:
                for _ in parse_lines(iter_lines(fh)):
                    pass

        def full(path=small):
            a = analyze(path)
            render_markdown(a), render_json(a), render_html(a)

        cli_env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        out_dir = Path(tmp) / "reports"

        def cli():
            subprocess.run(
                [sys.executable, "-m", "log_analyzer", "analyze", str(small), "-o", str(out_dir)], check=True, capture_output=True, env=cli_env
            )

        big_runs = timed(lambda: full(big), 5)
        big_lines = sum(1 for _ in big.open("rb"))
        return {
            "machine": f"{platform.system()} {platform.machine()}, {os.cpu_count()} CPUs, Python {platform.python_version()}",
            "parse_only_10k": pcts(timed(parse_only, 50)),
            "analyse_and_report_10k": pcts(timed(full, 50)),
            "cli_end_to_end_10k": pcts(timed(cli, 20)),
            "throughput_lines_per_s": round(big_lines / min(big_runs)),
            "big_file_lines": big_lines,
            "peak_memory_mb_10k": peak_memory_mb(lambda: analyze(small)),
            "peak_memory_mb_200k": peak_memory_mb(lambda: analyze(big)),
            "cost_per_run_eur": 0.0,
            "paid_api_calls": 0,
        }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
