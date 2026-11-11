"""Gold-set eval: hand-written tricky lines, labelled by what a human wants.

The generator and the parser were written by the same author, so a 100%
score on generated logs proves less than it seems: both share the same
assumptions. These lines were written and frozen *before* being run against
the parser, and include formats real services emit that our generator
never does. Misses here are published, not hidden.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from log_analyzer.models import Blank, Entry, Malformed  # noqa: E402
from log_analyzer.parser import parse_lines  # noqa: E402
from log_analyzer.reader import RawLine  # noqa: E402

GOLD = Path(__file__).with_name("gold_lines.jsonl")
MAX = 8192


def _line_bytes(case: dict) -> bytes:
    if "line_hex" in case:
        return bytes.fromhex(case["line_hex"])
    if "line_repeat" in case:
        head, unit, n = case["line_repeat"]
        return (head + unit * n).encode()
    return case["line"].encode()


def _check(case: dict) -> tuple[bool, str]:
    data = _line_bytes(case)
    raw = RawLine(1, data[:MAX], too_long=len(data) > MAX, original_length=len(data))
    items = list(parse_lines([raw]))
    first = items[0]
    got = {Entry: "entry", Malformed: "malformed", Blank: "blank"}.get(type(first), "continuation")
    detail = got if not isinstance(first, Malformed) else f"malformed:{first.reason}"
    if got != case["want"]:
        return False, detail
    entries = [i for i in items if isinstance(i, Entry)]
    if "entries" in case and len(entries) != case["entries"]:
        return False, f"{len(entries)} entries"
    for field in ("level", "service", "message"):
        if field in case and getattr(entries[0], field) != case[field]:
            return False, f"{field}={getattr(entries[0], field)!r}"
    return True, detail


def run() -> dict:
    cases = [json.loads(line) for line in GOLD.read_text(encoding="utf-8").splitlines() if line.strip()]
    misses = []
    for case in cases:
        ok, detail = _check(case)
        if not ok:
            misses.append({"id": case["id"], "wanted": case["want"], "got": detail})
    return {"cases": len(cases), "correct": len(cases) - len(misses), "misses": misses}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
