# CLAUDE.md: guide for AI agents working in this repo

## What this is
A stdlib-only Python log analyzer: parse → group errors → detect spikes → report. Every claim in the README is produced by `evals/`, never typed by hand.

## Module map (one job each)
| File | Job | Don't put here |
|---|---|---|
| `src/log_analyzer/reader.py` | Open files (gzip, stdin), yield bounded raw byte lines | Any parsing |
| `src/log_analyzer/parser.py` | Regex: bytes → Entry / Continuation / Blank / Malformed(reason) | Counting, output |
| `src/log_analyzer/grouping.py` | Fingerprint masks, `Grouper` with a cap | Spike logic |
| `src/log_analyzer/spikes.py` | Traffic-aware spike detection + attribution | File I/O |
| `src/log_analyzer/analyzer.py` | One streaming pass; `Options` holds every limit/defence | Rendering |
| `src/log_analyzer/report.py` | Markdown / JSON / HTML / terminal; all escaping | Analysis |
| `src/log_analyzer/generator.py` | Seeded messy log + answer key | Anything the analyzer imports |
| `src/log_analyzer/cli.py` | argparse wiring only | Logic |

## Commands
```bash
make demo        # generate 10k entries + analyse
make test        # pytest (54 tests, < 1 s)
make lint        # ruff check + format check
make eval        # all evals (~90 s); rewrites the README results table
make eval-check  # fail if README table != evals/results/
```

## Rules
1. **Never edit numbers in the README results block by hand.** Run `make eval`. CI fails on drift.
2. **Changing a regex or a threshold?** Run `python evals/accuracy.py dev` *and* `python evals/gold.py` before and after; paste both into the PR. Tune only on DEV seeds (0-19); TEST seeds (100-149) are for reporting.
3. **Log text is attacker-controlled.** Anything that reaches output must go through `report.clean` / `md` / `h`. New output format → add cases to `evals/attacks.py`.
4. **New defence → new `Options` field** (safe default) **+ an ablation entry** in `evals/attacks.py` proving an attack succeeds without it.
5. **No new dependencies** in `src/`. pytest and ruff are dev-only.
6. **The gold set is append-only.** Add lines a real log broke on; never edit an existing expectation to make a test pass.
7. Keep `docs/CHEATSHEET.md` in step with the code: it explains every line.
8. **Never paste literal invisible characters** (BOM, U+FFFD, bidi overrides, ESC). Write `"\u202e"`-style escapes or `chr(0x202E)`; `python scripts/check_invisible_chars.py` must pass.
9. **A new guard must be seen failing once** (plant the problem, watch it go red) before it's trusted.
10. Changed the report or results? Rebuild the demo: `PYTHONPATH=src python3 docs/demo/make_video.py` (needs Playwright + Chrome).
