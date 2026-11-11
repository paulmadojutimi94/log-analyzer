"""How big must a spike be before we catch it, and how often do we cry wolf?

Synthetic minutes: about 28 log entries a minute, each an error with 4%
probability (about 1.1 errors a minute, like the generated logs). Into minute
45 we add `extra` errors and see whether the detector flags it. 500 trials
per size, fixed seed.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from random import Random

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from log_analyzer.spikes import detect_spikes  # noqa: E402

TRIALS = 500
EXTRAS = [2, 4, 6, 8, 10, 12, 16]


def _minutes(r: Random, n: int = 60) -> tuple[Counter, Counter]:
    totals, errors = Counter(), Counter()
    for m in range(n):
        totals[m] = r.randint(20, 36)
        errors[m] = r.binomialvariate(totals[m], 0.04)
    return totals, errors


def run() -> dict:
    r = Random(2026)
    curve = {}
    for extra in EXTRAS:
        hits = 0
        for _ in range(TRIALS):
            totals, errors = _minutes(r)
            totals[45] += extra
            errors[45] += extra
            hits += any(s.start_minute <= 45 <= s.end_minute for s in detect_spikes(totals, errors))
        curve[str(extra)] = round(hits / TRIALS, 3)
    alarms = clean_minutes = 0
    for _ in range(TRIALS):
        totals, errors = _minutes(r, 360)
        alarms += len(detect_spikes(totals, errors))
        clean_minutes += 360 - 10  # the first 10 minutes are warm-up and never judged
    return {
        "detection_rate_by_extra_errors_per_minute": curve,
        "false_alarms_per_24h": round(alarms / clean_minutes * 1440, 3),
        "trials_per_size": TRIALS,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
