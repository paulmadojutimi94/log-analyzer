"""Spike detection: which minutes had far more errors than this much traffic explains?

Errors go up for two very different reasons:
  * something broke (the error *rate* jumps), or
  * it's just busy (3x the requests gives 3x the errors at the same rate).
Only the first is an incident. So for every minute we ask: "given how many
log entries arrived this minute, how many errors would a normal minute have
had?"

    base_rate = errors / entries over the previous `window` minutes
                (minutes already flagged as spikes are left out, so one
                outage doesn't make the next one look normal)
    expected  = base_rate * entries this minute
    spike if  errors >= expected + k * sqrt(expected)   and   errors >= min_errors

sqrt(expected) is how much a count of rare, independent events (a Poisson
process) naturally wobbles, so k is "how many wobbles above normal".
k was tuned on DEV seeds only; docs/DESIGN.md shows the earlier designs and
why they lost.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SpikeConfig:
    window: int = 30  # minutes of history that define "normal"
    min_history: int = 10  # minutes of history needed before we judge at all
    k: float = 5.0  # wobbles above normal
    min_errors: int = 5  # 3 errors in a minute is never an incident
    merge_gap: int = 1  # spike minutes this close together are one spike


@dataclass
class Spike:
    start_minute: int
    end_minute: int
    peak_errors: int
    total_errors: int
    baseline: float  # errors expected in the peak minute
    top_groups: list[tuple[str, int]] = field(default_factory=list)


def expected_errors(minute: int, first_minute: int, totals: Counter[int], errors: Counter[int], flagged: set[int], cfg: SpikeConfig) -> float | None:
    """Errors a normal minute with this traffic would have; None if too little history."""
    history = [m for m in range(max(first_minute, minute - cfg.window), minute) if m not in flagged]
    if len(history) < cfg.min_history:
        return None
    history_total = sum(totals.get(m, 0) for m in history)
    if history_total == 0:
        return None
    base_rate = sum(errors.get(m, 0) for m in history) / history_total
    return base_rate * totals[minute]


def detect_spikes(totals: Counter[int], errors: Counter[int], cfg: SpikeConfig = SpikeConfig()) -> list[Spike]:
    """totals and errors map epoch-minute -> count. Only minutes with errors are scanned."""
    if not totals:
        return []
    first_minute = min(totals)
    flagged: set[int] = set()
    expected_at: dict[int, float] = {}
    for minute in sorted(errors):  # time order matters: flagged minutes leave the baseline
        expected = expected_errors(minute, first_minute, totals, errors, flagged, cfg)
        if expected is None:
            continue
        threshold = expected + cfg.k * math.sqrt(max(expected, 1.0))
        if errors[minute] >= max(cfg.min_errors, threshold):
            flagged.add(minute)
            expected_at[minute] = expected

    spikes: list[Spike] = []
    for minute in sorted(flagged):
        n = errors[minute]
        if spikes and minute - spikes[-1].end_minute <= cfg.merge_gap + 1:
            spike = spikes[-1]
            spike.end_minute = minute
            if n > spike.peak_errors:
                spike.peak_errors, spike.baseline = n, round(expected_at[minute], 2)
        else:
            spikes.append(Spike(minute, minute, n, 0, round(expected_at[minute], 2)))
    for spike in spikes:
        spike.total_errors = sum(errors.get(m, 0) for m in range(spike.start_minute, spike.end_minute + 1))
    return spikes


def attribute(spike: Spike, per_group_minutes: dict[str, Counter[int]], top: int = 3) -> None:
    """Fill spike.top_groups: which error groups made up this spike."""
    window = range(spike.start_minute, spike.end_minute + 1)
    scores = Counter({fp: sum(c.get(m, 0) for m in window) for fp, c in per_group_minutes.items()})
    spike.top_groups = [(fp, n) for fp, n in scores.most_common(top) if n > 0]
