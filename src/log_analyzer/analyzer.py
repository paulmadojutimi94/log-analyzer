"""The pipeline: read -> parse -> aggregate -> detect spikes, in one pass.

We never keep all entries in memory. Each entry updates a few counters and is
then dropped, so a 10 GB log needs about as much memory as a 10 MB one.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .grouping import Grouper, epoch_minute
from .models import Blank, Continuation, Entry, Malformed
from .parser import parse_lines
from .reader import iter_lines, iter_lines_text_mode, open_log
from .spikes import Spike, SpikeConfig, attribute, detect_spikes


@dataclass(frozen=True)
class Options:
    """Limits and defences. The defaults are the safe ones.

    The attack eval switches each defence off in turn to prove it matters;
    nothing in normal use should change them.
    """

    max_line_bytes: int | None = 8192
    max_groups: int | None = 2000
    binary_split: bool = True  # split lines on b"\n" only
    trust_recovered: bool = False  # let glued-line halves drive groups/spikes
    max_timeline_minutes: int | None = 7 * 24 * 60
    escape_output: bool = True
    spikes: SpikeConfig = SpikeConfig()
    malformed_samples: int = 20


@dataclass
class Analysis:
    source: str
    options: Options
    lines_read: int = 0
    entries: int = 0
    recovered: Counter[str] = field(default_factory=Counter)  # json / glued
    blank_lines: int = 0
    continuation_lines: int = 0
    bad_byte_entries: int = 0
    malformed: Counter[str] = field(default_factory=Counter)
    malformed_samples: list[Malformed] = field(default_factory=list)
    levels: Counter[str] = field(default_factory=Counter)
    services: Counter[str] = field(default_factory=Counter)
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    totals: Counter[int] = field(default_factory=Counter)  # minute -> entries
    errors: Counter[int] = field(default_factory=Counter)  # minute -> errors
    grouper: Grouper = field(default_factory=Grouper)
    spikes: list[Spike] = field(default_factory=list)
    seconds: float = 0.0

    @property
    def malformed_total(self) -> int:
        return sum(self.malformed.values())

    @property
    def error_total(self) -> int:
        return sum(self.levels[lvl] for lvl in ("ERROR", "CRITICAL", "FATAL"))


def _record_entry(a: Analysis, entry: Entry) -> None:
    a.entries += 1
    if entry.source != "text":
        a.recovered[entry.source] += 1
    if entry.had_bad_bytes:
        a.bad_byte_entries += 1
    a.levels[entry.level] += 1
    a.services[entry.service] += 1
    if a.first_ts is None or entry.timestamp < a.first_ts:
        a.first_ts = entry.timestamp
    if a.last_ts is None or entry.timestamp > a.last_ts:
        a.last_ts = entry.timestamp
    if not entry.trusted and not a.options.trust_recovered:
        return  # counted above, but kept out of groups and spike maths
    minute = epoch_minute(entry.timestamp)
    a.totals[minute] += 1
    if entry.is_error:
        a.errors[minute] += 1
        a.grouper.add(entry)


def analyze(path: str | Path, options: Options = Options(), quarantine: str | Path | None = None) -> Analysis:
    """Analyse one log file. Optionally write malformed lines to a quarantine file."""
    started = time.perf_counter()
    a = Analysis(source=str(path), options=options, grouper=Grouper(options.max_groups))
    # ExitStack closes every file we open, even if the quarantine file is
    # optional or an exception happens half-way through.
    with ExitStack() as stack:
        fh = stack.enter_context(open_log(path))
        q = stack.enter_context(open(quarantine, "w", encoding="utf-8")) if quarantine else None
        raw = iter_lines(fh, options.max_line_bytes) if options.binary_split else iter_lines_text_mode(fh)
        for item in parse_lines(raw):
            if isinstance(item, Entry):
                _record_entry(a, item)
            elif isinstance(item, Continuation):
                a.continuation_lines += 1
            elif isinstance(item, Blank):
                a.blank_lines += 1
            else:
                a.malformed[item.reason] += 1
                if len(a.malformed_samples) < options.malformed_samples:
                    a.malformed_samples.append(item)
                if q:
                    # One JSON object per line ("JSON Lines"): easy to grep and replay.
                    q.write(json.dumps({"line": item.line_no, "reason": item.reason, "raw": item.raw}) + "\n")
            a.lines_read = item.line_no

    a.spikes = detect_spikes(a.totals, a.errors, options.spikes)
    per_group = {g.fingerprint: g.per_minute for g in a.grouper.groups.values()}
    for spike in a.spikes:
        attribute(spike, per_group)
    a.seconds = time.perf_counter() - started
    return a
