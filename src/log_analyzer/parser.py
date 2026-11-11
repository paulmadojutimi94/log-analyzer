"""Regex parsing: turn raw lines into Entry / Continuation / Blank / Malformed.

The expected line format is:

    2026-11-11T09:15:02.123Z ERROR [payment-service] Payment declined for user 48213

    <timestamp>              <level> [<service>]      <message>

Everything here is built so that one bad line can never stop the run: it is
labelled with a reason and the parser moves on to the next one.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime

from .models import KNOWN_LEVELS, Blank, Continuation, Entry, Malformed, Parsed
from .reader import RawLine

# ---- The regular expressions -------------------------------------------------

# ISO-8601: date, "T" or a space, time, optional fraction of a second ("."
# or "," as Python's logging module writes), then optional zone: "Z" or +01:00.
TS = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?"
GAP = r"[ \t]+"  # fields are separated by spaces or tabs
SERVICE = r"[A-Za-z0-9_.\-]{1,64}"

# The whole line. Named groups (?P<name>...) let us pull fields out by name.
# Each piece is a simple character class with no nested repetition, so the
# regex runs in time proportional to the line length (no catastrophic
# backtracking).
LINE_RE = re.compile(
    rf"(?P<ts>{TS}){GAP}(?P<level>[A-Za-z]+){GAP}\[(?P<service>{SERVICE})\](?:[ \t](?P<message>.*))?",
    re.DOTALL,
)

# A complete header appearing *inside* a message means two lines got glued.
EMBEDDED_HEADER_RE = re.compile(rf"{TS}{GAP}(?P<level>[A-Za-z]+){GAP}\[{SERVICE}\]")

# Pieces used only to explain *why* a line failed.
TS_PREFIX_RE = re.compile(TS)
LEVEL_AFTER_TS_RE = re.compile(rf"{TS}{GAP}(?P<level>\S+)")

# Lines that continue the previous event: indented lines ("    at Foo.bar"),
# Python's traceback header, and Java's "Caused by:".
CONTINUATION_RE = re.compile(r"[ \t]+\S|Traceback \(most recent call last\):|Caused by: ")
# The last line of a Python traceback is not indented: "KeyError: 'sku'".
EXCEPTION_TAIL_RE = re.compile(r"[A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt)\b")

LEVEL_ALIASES = {"WARNING": "WARN"}
GARBAGE_RATIO = 0.30  # more than 30% unreadable characters = binary junk
PREVIEW_CHARS = 200

# ---- Helpers -----------------------------------------------------------------


def _parse_ts(text: str) -> datetime | None:
    """Return a UTC datetime, or None if the date is impossible (e.g. month 13).

    Every timestamp is converted to UTC. One naive and one zone-aware
    datetime can't even be compared in Python, so mixing them would crash
    the min/max tracking later. A timestamp with no zone is assumed to be UTC.
    """
    try:
        ts = datetime.fromisoformat(text.replace(",", "."))
    except ValueError:
        return None
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)


def _is_garbage(text: str) -> bool:
    if not text:
        return False
    bad = sum(1 for ch in text if ch == "\ufffd" or (ord(ch) < 32 and ch != "\t"))
    return bad / len(text) > GARBAGE_RATIO


def _diagnose(text: str) -> str:
    """Explain why LINE_RE did not match, for the malformed-lines report."""
    if not TS_PREFIX_RE.match(text):
        return "no_timestamp"
    level = LEVEL_AFTER_TS_RE.match(text)
    if not level:
        return "missing_level"
    if level.group("level").upper() not in KNOWN_LEVELS:
        return "unknown_level"
    return "missing_service"


def _first(obj: dict, *keys: str):
    for key in keys:
        value = obj.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _try_json(text: str, line_no: int) -> Entry | None:
    """Recover a JSON log line from another emitter, if it has what we need."""
    try:
        obj = json.loads(text)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    ts_text = _first(obj, "timestamp", "ts", "time", "@timestamp")
    level = _first(obj, "level", "lvl", "severity")
    service = _first(obj, "service", "svc", "app")
    message = _first(obj, "message", "msg")
    if not (ts_text and level and service and message is not None):
        return None
    if not TS_PREFIX_RE.fullmatch(ts_text):
        return None
    level = LEVEL_ALIASES.get(level.upper(), level.upper())
    timestamp = _parse_ts(ts_text)
    if timestamp is None or level not in KNOWN_LEVELS:
        return None
    return Entry(line_no, timestamp, level, service, message, source="json")


# ---- Parsing one line ----------------------------------------------------------


def parse_text(text: str, line_no: int, source: str = "text") -> list[Entry] | Malformed:
    """Parse one decoded line. Returns entries (2+ if lines were glued) or Malformed."""
    match = LINE_RE.fullmatch(text)
    if not match:
        return Malformed(line_no, _diagnose(text), text[:PREVIEW_CHARS])

    level = match.group("level").upper()
    if level not in KNOWN_LEVELS:
        return Malformed(line_no, "unknown_level", text[:PREVIEW_CHARS])
    level = LEVEL_ALIASES.get(level, level)

    timestamp = _parse_ts(match.group("ts"))
    if timestamp is None:
        return Malformed(line_no, "invalid_timestamp", text[:PREVIEW_CHARS])

    message = match.group("message") or ""
    entries = [Entry(line_no, timestamp, level, match.group("service"), message, source=source)]

    # Two lines stuck together? Look for a second, complete header in the message.
    glued = EMBEDDED_HEADER_RE.search(message)
    if glued and glued.group("level").upper() in KNOWN_LEVELS:
        rest = parse_text(message[glued.start() :], line_no, source="glued")
        if isinstance(rest, list):
            entries[0].message = message[: glued.start()].rstrip()
            entries.extend(rest)
    return entries


def parse_lines(lines: Iterable[RawLine]) -> Iterator[Parsed]:
    """Classify every raw line. Continuation lines are attached to their entry."""
    last_entry: Entry | None = None
    in_trace = False  # are we inside a multi-line stack trace?

    for raw in lines:
        if raw.too_long:
            yield Malformed(raw.line_no, "line_too_long", raw.data[:PREVIEW_CHARS].decode("utf-8", "replace"))
            in_trace = False
            continue

        text = raw.data.decode("utf-8", errors="replace")
        if raw.line_no == 1:
            text = text.removeprefix("\ufeff")  # byte-order mark some editors add

        if not text.strip():
            yield Blank(raw.line_no)
            continue

        if CONTINUATION_RE.match(text) or (in_trace and EXCEPTION_TAIL_RE.match(text)):
            if last_entry is None:
                yield Malformed(raw.line_no, "orphan_continuation", text[:PREVIEW_CHARS])
            else:
                last_entry.continuation.append(text)
                in_trace = True
                yield Continuation(raw.line_no, text)
            continue
        in_trace = False

        if _is_garbage(text):
            yield Malformed(raw.line_no, "binary_garbage", text[:PREVIEW_CHARS])
            continue

        result = parse_text(text, raw.line_no)
        if isinstance(result, Malformed) and text.lstrip().startswith("{"):
            recovered = _try_json(text, raw.line_no)
            result = [recovered] if recovered else Malformed(raw.line_no, "unrecognised_json", text[:PREVIEW_CHARS])

        if isinstance(result, Malformed):
            yield result
            continue

        bad_bytes = "\ufffd" in text
        for entry in result:
            entry.had_bad_bytes = bad_bytes
            last_entry = entry
            yield entry
