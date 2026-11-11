"""Fail if code or docs contain invisible or direction-changing characters.

Byte-order marks, replacement characters, line separators, bidi overrides
(the "Trojan Source" trick) and raw escape bytes must be written as escape
sequences, never as the literal character. See docs/POSTMORTEM.md.
"""

import re
import sys
from pathlib import Path

# Built from plain numbers so this file can never contain the characters itself.
CODEPOINTS = [0xFEFF, 0xFFFD, 0x2028, 0x2029, *range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x1B, 0x07]
BAD = re.compile("[" + "".join(re.escape(chr(c)) for c in CODEPOINTS) + "]")
PATHS = ["src", "tests", "evals", "docs", "scripts", "README.md", "CLAUDE.md"]
SUFFIXES = {".py", ".md", ".jsonl", ".toml", ".yml"}


def main(root: Path = Path(".")) -> int:
    found = 0
    for name in PATHS:
        base = root / name
        files = [base] if base.is_file() else sorted(p for p in base.rglob("*") if p.suffix in SUFFIXES)
        for path in files:
            # split on "\n" only: str.splitlines() would also split on U+2028 and hide it
            for no, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
                for m in BAD.finditer(line):
                    print(f"{path}:{no}: U+{ord(m.group()):04X}")
                    found += 1
    print(f"{found} invisible character(s) found")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
