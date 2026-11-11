"""File handling: get raw lines out of a file safely.

Three ideas worth learning here:

1. Read in *binary* mode and split only on b"\\n". Text mode in Python uses
   "universal newlines", which also splits on a lone "\\r". If an attacker can
   put "\\r" in a log message, text mode lets them start a fake new line.
2. Read with a *size limit* per line (readline(limit)). A 2 GB file with no
   newline would otherwise be loaded into memory as one giant string.
3. Detect gzip by its magic bytes (1f 8b), not by the file name, so rotated
   logs like app.log.1 that happen to be compressed still work.
"""

from __future__ import annotations

import gzip
import io
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

GZIP_MAGIC = b"\x1f\x8b"
DRAIN_CHUNK = 64 * 1024


@dataclass(slots=True)
class RawLine:
    line_no: int
    data: bytes  # the line without its newline, at most max_line_bytes long
    too_long: bool = False
    original_length: int = 0


@contextmanager
def open_log(path: str | Path) -> Iterator[BinaryIO]:
    """Open a log for binary reading. "-" means stdin; gzip is auto-detected."""
    if str(path) == "-":
        yield sys.stdin.buffer
        return
    p = Path(path)
    with p.open("rb") as probe:
        magic = probe.read(2)
    opener = gzip.open if magic == GZIP_MAGIC else open
    with opener(p, "rb") as fh:
        yield fh


def _strip_newline(chunk: bytes) -> bytes:
    if chunk.endswith(b"\n"):
        chunk = chunk[:-1]
    if chunk.endswith(b"\r"):  # Windows line ending "\r\n"
        chunk = chunk[:-1]
    return chunk


def iter_lines(fh: BinaryIO, max_line_bytes: int | None = 8192) -> Iterator[RawLine]:
    """Yield every line, never holding more than max_line_bytes of one line."""
    line_no = 0
    while True:
        chunk = fh.readline(max_line_bytes + 1) if max_line_bytes else fh.readline()
        if not chunk:
            return  # end of file
        line_no += 1
        if max_line_bytes and len(chunk) > max_line_bytes and not chunk.endswith(b"\n"):
            # Too long. Keep the first max_line_bytes for the error report and
            # throw the rest away in small pieces until the newline.
            total = len(chunk)
            while True:
                more = fh.readline(DRAIN_CHUNK)
                total += len(more)
                if not more or more.endswith(b"\n"):
                    break
            yield RawLine(line_no, chunk[:max_line_bytes], too_long=True, original_length=total)
            continue
        yield RawLine(line_no, _strip_newline(chunk), original_length=len(chunk))


def iter_lines_text_mode(fh: BinaryIO) -> Iterator[RawLine]:
    """The naive way: text mode, universal newlines, no size limit.

    Kept only so the attack eval can show what the two defences above buy us.
    """
    text = io.TextIOWrapper(fh, encoding="utf-8", errors="replace", newline=None)
    for line_no, line in enumerate(text, start=1):
        data = line.rstrip("\n").encode("utf-8")
        yield RawLine(line_no, data, original_length=len(data))
