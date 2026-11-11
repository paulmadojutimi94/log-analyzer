"""Group errors that are "the same problem" even though their text differs.

    Database connection timeout after 5012ms (host=db-3.internal)
    Database connection timeout after 30000ms (host=db-1.internal)

are one problem. We replace the parts that vary (numbers, IDs, IPs...) with
placeholders, and the text that is left is the group's *fingerprint*:

    Database connection timeout after <NUM>ms (host=db-<NUM>.internal)

Order matters: a UUID contains digits, so it must be masked before the
generic number rule chews it into pieces.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from .models import Entry

MASKS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<UUID>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),
    # (?<![\w.+-]) means "only start where a run of address characters
    # starts". Without it, "a.a.a.a..." has a word boundary before every "a",
    # the pattern restarts at each one and scans to the end: quadratic time,
    # 12 seconds for one 64 KB line (see docs/POSTMORTEM.md).
    (re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "<EMAIL>"),
    (re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{16,}\b", re.I), "<HEX>"),
    # No \b here on purpose: "5012ms", "rss=8052MB" and "sda1" have a letter
    # touching the digits, so there is no word boundary and \b\d+\b skipped
    # them, giving one group per distinct value (see docs/POSTMORTEM.md).
    (re.compile(r"\d+(?:\.\d+)?"), "<NUM>"),
]
WHITESPACE_RE = re.compile(r"\s+")
MAX_FINGERPRINT = 300
MAX_MASK_INPUT = 1000  # defence in depth: never run the masks over more than this
OVERFLOW = "<too many distinct error groups: the rest are counted here>"


def fingerprint(message: str) -> str:
    text = message[:MAX_MASK_INPUT]
    for pattern, placeholder in MASKS:
        text = pattern.sub(placeholder, text)
    return WHITESPACE_RE.sub(" ", text).strip()[:MAX_FINGERPRINT]


def epoch_minute(ts: datetime) -> int:
    return int(ts.timestamp()) // 60


@dataclass
class ErrorGroup:
    fingerprint: str
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    services: Counter[str] = field(default_factory=Counter)
    levels: Counter[str] = field(default_factory=Counter)
    examples: list[str] = field(default_factory=list)
    per_minute: Counter[int] = field(default_factory=Counter)

    def add(self, entry: Entry) -> None:
        self.count += 1
        if self.first_seen is None or entry.timestamp < self.first_seen:
            self.first_seen = entry.timestamp
        if self.last_seen is None or entry.timestamp > self.last_seen:
            self.last_seen = entry.timestamp
        self.services[entry.service] += 1
        self.levels[entry.level] += 1
        if len(self.examples) < 3:
            self.examples.append(entry.message)
        self.per_minute[epoch_minute(entry.timestamp)] += 1


class Grouper:
    """Holds one ErrorGroup per fingerprint, with a hard cap on how many."""

    def __init__(self, max_groups: int | None = 2000) -> None:
        self.max_groups = max_groups
        self.groups: dict[str, ErrorGroup] = {}

    def add(self, entry: Entry) -> str:
        key = fingerprint(entry.message)
        group = self.groups.get(key)
        if group is None:
            if self.max_groups and len(self.groups) >= self.max_groups:
                key = OVERFLOW  # cap reached: don't let memory grow without limit
                group = self.groups.get(key)
            if group is None:
                group = self.groups[key] = ErrorGroup(key)
        group.add(entry)
        return key

    def ranked(self) -> list[ErrorGroup]:
        return sorted(self.groups.values(), key=lambda g: (-g.count, g.fingerprint))
