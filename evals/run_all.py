"""Run every eval, save results to evals/results/, and rewrite the README table.

python evals/run_all.py            # run everything (about a minute)
python evals/run_all.py --check    # CI: fail if README doesn't match results/
python evals/run_all.py --fast     # CI: re-measure gold + accuracy + attacks only
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RESULTS = HERE / "results"
README = ROOT / "README.md"
START, END = "<!-- results:start -->", "<!-- results:end -->"
sys.path.insert(0, str(HERE))


def load(name: str) -> dict:
    return json.loads((RESULTS / f"{name}.json").read_text())


def save(name: str, data: dict) -> None:
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / f"{name}.json").write_text(json.dumps(data, indent=2, default=str) + "\n")


def pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def render() -> str:
    acc, gold, att, perf, sens = (load(n) for n in ("accuracy", "gold", "attacks", "performance", "sensitivity"))
    curve = sens["detection_rate_by_extra_errors_per_minute"]
    rows = [
        "| What | Result | How it was measured |",
        "|---|---|---|",
        f"| **Parsing:** line classification | **{pct(acc['line_classification_accuracy'])}** of {acc['lines']:,} lines | "
        f"{acc['files']} held-out generated files (seeds 100-149), every line labelled by the generator |",
        f"| **Parsing:** hand-written tricky lines | **{gold['correct']} / {gold['cases']}** | "
        f"Written and frozen before being run; formats the generator never makes |",
        f"| **Malformed lines** caught | precision {pct(acc['malformed_precision'])}, recall {pct(acc['malformed_recall'])} | "
        f"Same {acc['files']} files |",
        f"| **Recovered** instead of dropped | JSON {acc['recovered']['json_line']}, glued {acc['recovered']['glued']}, "
        f"bad bytes {acc['recovered']['bad_byte_in_message']}, CRLF {acc['recovered']['crlf']} | Same files |",
        f"| **Grouping** (pair F1) | **{acc['grouping_pair_f1']:.3f}** (precision {acc['grouping_pair_precision']:.3f}, "
        f"recall {acc['grouping_pair_recall']:.3f}) | {acc['groups_found_per_file']} groups found per file for "
        f"{acc['true_templates_per_file']:g} real error types |",
        f"| **Spikes** found | **{acc['spikes_found']} / {acc['spikes_planted']}** (recall {pct(acc['spike_recall'])}) | "
        f"3 planted per file, 8-20 extra errors/min |",
        f"| Spike false alarms | {acc['false_alarms']} in {acc['files']} files (precision {pct(acc['spike_precision'])}); "
        f"{acc['surge_false_alarms']} from traffic surges | Each file is 6 hours with a planted 3x traffic surge |",
        f"| Spike blamed on the right error | **{pct(acc['spike_attribution_accuracy'])}** | Top group in each caught spike |",
        f"| Spike sensitivity | caught {pct(curve['6'])} at +6/min, {pct(curve['8'])} at +8, {pct(curve['10'])} at +10 | "
        f"{sens['trials_per_size']} synthetic trials per size; ~1.1 errors/min normally |",
        f"| False alarms on a quiet log | {sens['false_alarms_per_24h']} per 24 h | Same synthetic traffic, no spikes |",
        f"| **Latency:** analyse 10,000 entries + 3 reports | **p50 {perf['analyse_and_report_10k']['p50_ms']} ms, "
        f"p95 {perf['analyse_and_report_10k']['p95_ms']} ms** | {perf['analyse_and_report_10k']['runs']} runs, warm |",
        f"| Latency: whole CLI, cold start | p50 {perf['cli_end_to_end_10k']['p50_ms']} ms, "
        f"p95 {perf['cli_end_to_end_10k']['p95_ms']} ms | {perf['cli_end_to_end_10k']['runs']} runs, includes Python start-up |",
        f"| Throughput | {perf['throughput_lines_per_s']:,} lines/s | {perf['big_file_lines']:,}-line file |",
        f"| Peak memory (Python heap) | {perf['peak_memory_mb_10k']} MB at 10k lines, {perf['peak_memory_mb_200k']} MB at "
        f"{perf['big_file_lines'] // 1000}k | Streaming: grows with the time span, not file size |",
        f"| **Cost per task** | **€{perf['cost_per_run_eur']:.2f}** | {perf['paid_api_calls']} paid API calls; runs locally |",
        f"| **Attack success rate**, all defences on | **{att['successes']} / {att['total']} "
        f"({pct(att['successes'] / att['total'])})** | {att['families']} families of attack, each in a sandboxed process |",
        "",
        "| Defence switched off | Attacks that then get through |",
        "|---|---|",
    ]
    names = {
        "binary_split": "Binary line splitting (only `\\n` ends a line)",
        "trust_recovered": "Recovered glued lines kept out of alerts",
        "max_line_bytes": "8 KB line cap with bounded reads",
        "max_groups": "Cap of 2,000 error groups",
        "max_timeline_minutes": "7-day chart window",
        "escape_output": "Escaping in HTML, Markdown and terminal output",
    }
    for key, label in names.items():
        a = att["ablation"][key]
        rows.append(f"| {label} | {a['successes']} / {a['cases']} |")
    rows.append("")
    rows.append(f"Measured on {perf['machine']}.")
    return "\n".join(rows)


def write_readme() -> bool:
    text = README.read_text()
    before, rest = text.split(START, 1)
    _, after = rest.split(END, 1)
    new = f"{before}{START}\n{render()}\n{END}{after}"
    changed = new != text
    README.write_text(new)
    return changed


def check() -> int:
    text = README.read_text()
    current = text.split(START, 1)[1].split(END, 1)[0].strip()
    if current != render().strip():
        print("README results table is out of date: run `make eval`.", file=sys.stderr)
        return 1
    print("README matches evals/results/.")
    return 0


def main() -> int:
    if "--check" in sys.argv:
        return check()
    import accuracy
    import attacks
    import gold

    save("gold", gold.run())
    print("gold done")
    save("accuracy", accuracy.run())
    print("accuracy done")
    save("attacks", attacks.run())
    print("attacks done")
    if "--fast" not in sys.argv:
        import performance
        import sensitivity

        save("sensitivity", sensitivity.run())
        print("sensitivity done")
        save("performance", performance.run())
        print("performance done")
    write_readme()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
