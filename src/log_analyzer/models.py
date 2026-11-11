"""The small data types every other module passes around.

The parser turns each physical line of a log file into exactly one of four
things: an Entry (a real log event), a Continuation (an extra line belonging
to the previous event, like a stack trace), a Blank line, or a Malformed line
it could not understand. Keeping these as plain dataclasses means each stage
of the pipeline is easy to test on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# Levels we treat as "something broke". FATAL is a synonym some loggers use.
ERROR_LEVELS = frozenset({"ERROR", "CRITICAL", "FATAL"})

# Every level we accept. Anything else (a typo like "EROR") is malformed.
KNOWN_LEVELS = frozenset({"TRACE", "DEBUG", "INFO", "WARN", "WARNING", *ERROR_LEVELS})


@dataclass(slots=True)
class Entry:
    """One log event, parsed."""

    line_no: int
    timestamp: datetime
    level: str
    service: str
    message: str
    # "text" = a normal line; "json" = a JSON line we recovered;
    # "glued" = the second half of two lines that were stuck together.
    source: str = "text"
    had_bad_bytes: bool = False
    continuation: list[str] = field(default_factory=list)

    @property
    def is_error(self) -> bool:
        return self.level in ERROR_LEVELS

    @property
    def trusted(self) -> bool:
        # A "glued" entry was found *inside* another line's message. Real
        # glued lines happen, but so does an attacker typing a fake log line
        # into a form field. We count these but never let them drive alerts.
        return self.source != "glued"


@dataclass(slots=True)
class Continuation:
    line_no: int
    text: str


@dataclass(slots=True)
class Blank:
    line_no: int


@dataclass(slots=True)
class Malformed:
    line_no: int
    reason: str
    raw: str  # decoded, possibly cut short; never trusted for display


Parsed = Entry | Continuation | Blank | Malformed
