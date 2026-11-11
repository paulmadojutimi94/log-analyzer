"""Accuracy eval: score the analyzer against the generator's answer key.

Seeds are split like a machine-learning dataset:
  * DEV seeds (0-19) are the ones we looked at while tuning thresholds.
  * TEST seeds (100-149) were only run to produce the published numbers.
Tuning on the same files you report on flatters the result.
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime
from math import comb
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from log_analyzer.analyzer import Options, analyze  # noqa: E402
from log_analyzer.generator import generate  # noqa: E402
from log_analyzer.grouping import epoch_minute, fingerprint  # noqa: E402
from log_analyzer.models import Blank, Continuation, Entry, Malformed  # noqa: E402
from log_analyzer.parser import parse_lines  # noqa: E402
from log_analyzer.reader import iter_lines, open_log  # noqa: E402

DEV_SEEDS = range(0, 20)
TEST_SEEDS = range(100, 150)


def _kind(item) -> str:
    return {Entry: "entry", Continuation: "continuation", Blank: "blank", Malformed: "malformed"}[type(item)]


def _fields_match(pred: Entry, truth: dict, suffix_replaced: bool) -> bool:
    msg_ok = pred.message.startswith(truth["message"]) if suffix_replaced else pred.message == truth["message"]
    return (
        msg_ok
        and pred.level == truth["level"]
        and pred.service == truth["service"]
        and pred.timestamp.isoformat(timespec="milliseconds") == truth["ts"]
    )


def score_seed(seed: int, options: Options = Options()) -> dict:
    data, truth = generate(seed=seed)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "app.log"
        path.write_bytes(data)
        by_line: dict[int, list] = defaultdict(list)
        with open_log(path) as fh:
            for item in parse_lines(iter_lines(fh, options.max_line_bytes)):
                by_line[item.line_no].append(item)
        analysis = analyze(path, options)

    s = Counter()
    pairs: list[tuple[str, str]] = []  # (predicted fingerprint, true template)
    for line_no, label in enumerate(truth["lines"], start=1):
        preds = by_line.get(line_no, [])
        pred_kind = _kind(preds[0]) if preds else "missing"
        s["lines"] += 1
        s["lines_correct"] += pred_kind == label["kind"]
        is_bad, said_bad = label["kind"] == "malformed", pred_kind == "malformed"
        s["tp_malformed"] += is_bad and said_bad
        s["fp_malformed"] += said_bad and not is_bad
        s["fn_malformed"] += is_bad and not said_bad
        if label["kind"] != "entry":
            continue
        corruption = label.get("corruption")
        if corruption in ("json_line", "glued", "bad_byte_in_message", "crlf"):
            s[f"recoverable_{corruption}"] += 1
        entries = [p for p in preds if isinstance(p, Entry)]
        ok = len(entries) == len(label["entries"]) and all(
            _fields_match(p, t, label.get("message_suffix_replaced", False)) for p, t in zip(entries, label["entries"], strict=False)
        )
        s["entries"] += len(label["entries"])
        s["entries_correct"] += len(label["entries"]) if ok else 0
        if corruption in ("json_line", "glued", "bad_byte_in_message", "crlf") and ok:
            s[f"recovered_{corruption}"] += 1
        if ok:
            for p, t in zip(entries, label["entries"], strict=True):
                if t["template"] and p.trusted:
                    pairs.append((fingerprint(p.message), t["template"]))

    # Grouping, pair-counting: for every pair of errors, did we put them in
    # the same group exactly when they truly belong together?
    cells = Counter(pairs)
    pred_sizes = Counter(fp for fp, _ in pairs)
    true_sizes = Counter(t for _, t in pairs)
    same_both = sum(comb(n, 2) for n in cells.values())
    s["pair_tp"] = same_both
    s["pair_pred"] = sum(comb(n, 2) for n in pred_sizes.values())
    s["pair_true"] = sum(comb(n, 2) for n in true_sizes.values())
    s["groups_found"] = len(pred_sizes)
    s["templates"] = len(true_sizes)
    majority = {}  # fingerprint -> the template most of its members came from
    for (fp, t), _n in cells.most_common():
        majority.setdefault(fp, t)

    # Spikes: a detection counts if it overlaps a planted spike.
    planted = [
        (epoch_minute(datetime.fromisoformat(sp["start"])), epoch_minute(datetime.fromisoformat(sp["end"])), sp["template"]) for sp in truth["spikes"]
    ]
    surge = truth["traffic_surge"]
    surge_lo = epoch_minute(datetime.fromisoformat(surge["start"]))
    surge_hi = epoch_minute(datetime.fromisoformat(surge["end"]))
    hit = set()
    for sp in analysis.spikes:
        overlaps = [i for i, (lo, hi, _) in enumerate(planted) if sp.start_minute <= hi and sp.end_minute >= lo]
        if overlaps:
            s["spike_tp"] += 1
            i = overlaps[0]
            if i not in hit:
                hit.add(i)
                s["delay_minutes"] += max(0, sp.start_minute - planted[i][0])
                top = sp.top_groups[0][0] if sp.top_groups else None
                s["attribution_correct"] += majority.get(top) == planted[i][2]
        else:
            s["spike_fp"] += 1
            s["surge_false_alarms"] += sp.start_minute <= surge_hi and sp.end_minute >= surge_lo
    s["spikes_planted"] += len(planted)
    s["spikes_found"] += len(hit)
    return dict(s)


def summarise(seed_scores: list[dict]) -> dict:
    t = Counter()
    for sc in seed_scores:
        t.update(sc)

    def ratio(a: str, b: str) -> float:
        return round(t[a] / t[b], 4) if t[b] else 0.0

    p = t["tp_malformed"] / (t["tp_malformed"] + t["fp_malformed"]) if t["tp_malformed"] + t["fp_malformed"] else 0
    r = t["tp_malformed"] / (t["tp_malformed"] + t["fn_malformed"]) if t["tp_malformed"] + t["fn_malformed"] else 0
    gp = t["pair_tp"] / t["pair_pred"] if t["pair_pred"] else 0
    gr = t["pair_tp"] / t["pair_true"] if t["pair_true"] else 0
    sp_p = t["spike_tp"] / (t["spike_tp"] + t["spike_fp"]) if t["spike_tp"] + t["spike_fp"] else 0
    sp_r = t["spikes_found"] / t["spikes_planted"] if t["spikes_planted"] else 0
    recov = {k: f"{t['recovered_' + k]}/{t['recoverable_' + k]}" for k in ("json_line", "glued", "bad_byte_in_message", "crlf")}
    return {
        "files": len(seed_scores),
        "lines": t["lines"],
        "line_classification_accuracy": ratio("lines_correct", "lines"),
        "entry_field_accuracy": ratio("entries_correct", "entries"),
        "malformed_precision": round(p, 4),
        "malformed_recall": round(r, 4),
        "recovered": recov,
        "grouping_pair_precision": round(gp, 4),
        "grouping_pair_recall": round(gr, 4),
        "grouping_pair_f1": round(2 * gp * gr / (gp + gr), 4) if gp + gr else 0.0,
        "groups_found_per_file": round(t["groups_found"] / len(seed_scores), 1),
        "true_templates_per_file": round(t["templates"] / len(seed_scores), 1),
        "spikes_planted": t["spikes_planted"],
        "spikes_found": t["spikes_found"],
        "spike_recall": round(sp_r, 4),
        "spike_precision": round(sp_p, 4),
        "false_alarms": t["spike_fp"],
        "surge_false_alarms": t["surge_false_alarms"],
        "mean_detection_delay_minutes": round(t["delay_minutes"] / t["spikes_found"], 2) if t["spikes_found"] else None,
        "spike_attribution_accuracy": ratio("attribution_correct", "spikes_found"),
    }


def run(seeds=TEST_SEEDS, options: Options = Options()) -> dict:
    return summarise([score_seed(seed, options) for seed in seeds])


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "dev"
    seeds = DEV_SEEDS if which == "dev" else TEST_SEEDS
    print(json.dumps(run(seeds), indent=2))
