# Learn: file handling, regex and data processing, through this project

Three skills, taught from first principles with the code in this repo. Each part ends with exercises you can do in 15-30 minutes; answers are hinted at the bottom. Run things as you go:

```bash
make demo                       # creates data/app.log and reports/
PYTHONPATH=src python3          # then: from log_analyzer.parser import *
```

---

## Part 1: File handling

### 1.1 A file is bytes, not text

A file on disk is a row of numbers from 0 to 255 (bytes). "Text" is an *interpretation*: UTF-8 says the bytes `43 61 66 C3 A9` mean `Café`. Most bytes sequences are valid UTF-8, but not all: `FF FE` isn't.

**Analogy:** bytes are the marks on a page; an encoding is the language you read them in. Open a Polish letter as if it were English and some words won't make sense. You want to notice that, not throw the letter away.

```python
open("app.log")  # text mode: Python decodes for you, and RAISES on bad bytes
open("app.log", "rb")  # binary mode: you get raw bytes and decide what to do
```

This project reads in **binary** and decodes each line itself with `errors="replace"`, so one bad byte becomes U+FFFD (the replacement character, usually drawn as a question mark in a diamond) in that line instead of crashing the run (`parser.py`, `parse_lines`).

### 1.2 Where does a line end?

In binary mode, `readline()` ends a line at `\n`. In text mode, Python also treats a lone `\r` as a line end ("universal newlines", a convenience for old Mac files). That convenience is a **security hole** for logs. If a user signs up with the name `bob\r2026-11-11T09:00:00Z CRITICAL [auth] Admin password changed`, text mode sees two lines, and the second is a forged CRITICAL. The attack eval shows it working 3/3 times in text mode and 0/3 in binary mode (`reader.py`, `iter_lines` vs `iter_lines_text_mode`).

### 1.3 Never trust a file's size

`f.read()` loads the whole file. `for line in f` loads one line at a time, but a line can be 2 GB if nobody wrote a newline. The fix is `readline(limit)`, which stops after `limit` bytes even without a newline. Then you **drain** the rest of that line in small pieces without keeping it (`iter_lines`). Measured: a 150 MB line costs 19 MB instead of 624 MB.

**Analogy:** a post-room that opens every parcel fully before checking its size will one day be buried by a single crate. Check the size on the label first.

### 1.4 Always close what you open

```python
with open(path, "rb") as fh:  # closed automatically, even if an error happens inside
    ...
```

When you have a *variable* number of files (the log always, the quarantine file only sometimes), use `contextlib.ExitStack` (`analyzer.py`, `analyze`). To make your own `with`-able thing, write a generator and decorate it with `@contextmanager` (`reader.py`, `open_log`).

### 1.5 Recognise files by content, not by name

Every gzip file starts with the bytes `1f 8b`. Checking those two "magic bytes" means `app.log.1` that happens to be compressed still works (`open_log`). And `"-"` meaning "standard input" lets you pipe: `kubectl logs api | log-analyzer analyze -`.

### 1.6 Writing files

- Text: always say `encoding="utf-8"`; the default differs between Windows and Linux.
- Data you can't express as valid text (the generator's deliberately broken lines): `path.write_bytes(data)`.
- Records for machines: **JSON Lines**, one JSON object per line (`quarantine.jsonl`). You can append to it, `grep` it, and read it back line by line.

### Exercises

1. Run `python3 -c "print(open('data/app.log').read()[:10])"` and then the same with `"rb"`. Why does the binary version start with `b'\xef\xbb\xbf'`? (Hint: `parse_lines`, line 1.)
2. Add a `--encoding` flag that lets `analyze` read Latin-1 logs. Where is the one place that needs to change?
3. Make `open_log` also detect bzip2 files (they start with `BZh`). Write the test first, like `test_gzip_is_detected_by_magic_bytes`.

---

## Part 2: Regular expressions

### 2.1 What a regex is

A regex is a tiny pattern language for "text shaped like this". The building blocks:

| Piece | Means | Example |
|---|---|---|
| `\d` | one digit | `\d\d` matches `42` |
| `{4}` / `{1,6}` | exactly 4 / between 1 and 6 of the thing before | `\d{4}` matches `2026` |
| `+` / `*` / `?` | one or more / zero or more / optional | `[ \t]+` = at least one space or tab |
| `[abc]` / `[^abc]` | one of these / anything but these | `[T ]` = a T or a space |
| `(?P<name>...)` | capture this part and call it *name* | `(?P<level>[A-Za-z]+)` |
| `(?:...)` | group without capturing | `(?:Z|[+-]\d{2}:\d{2})?` |
| `\b` | word boundary: edge between a word character and anything else | `\bcat\b` matches `cat` but not `cats` |
| `(?<!x)` | negative lookbehind: "not preceded by x" | see 2.4 |

### 2.2 Build big patterns from named small ones

Look at the top of `parser.py`: `TS`, `GAP` and `SERVICE` are small patterns pasted into `LINE_RE` with an f-string. Each piece can be read and tested alone. A 200-character regex written in one go can't.

```python
>>> from log_analyzer.parser import LINE_RE
>>> m = LINE_RE.fullmatch("2026-11-11T09:15:02.123Z ERROR [payment-service] Card declined")
>>> m.group("level"), m.group("service"), m.group("message")
('ERROR', 'payment-service', 'Card declined')
```

`match` checks from the start, `fullmatch` requires the *whole* string to match, and `search` finds the pattern anywhere. Use the strictest one that fits.

### 2.3 A regex checks shape, not meaning

`\d{4}-\d{2}-\d{2}` happily matches `2026-02-30`. Shape is the regex's job; meaning is `datetime.fromisoformat`'s (`_parse_ts`). Split them, and you can report *which* one failed (`invalid_timestamp` vs `no_timestamp`).

### 2.4 Two real bugs from this project

**Bug 1: the boundary that wasn't there.** `\b\d+\b` is meant to mean "a number". But in `5012ms` the digits touch the letters `ms`, and digits and letters are both "word characters", so there's no boundary after the `2`. The pattern skipped it, and one error type became 44 groups. Fix: `\d+(?:\.\d+)?`. (Postmortem, Incident 1.)

**Bug 2: the pattern that started everywhere.** The e-mail mask began with `\b[\w.+-]+@`. In `a.a.a.a…` there's a word boundary before *every* `a`. So the engine tried to start a match at each one, scanned to the end looking for `@`, failed, and moved one step on. 32,000 starts × 64,000 characters ≈ 2 billion steps: 11.7 seconds for one line. Fix: `(?<![\w.+-])`, "only start where a run of address characters starts", which leaves one start per run. 0.001 seconds. (Postmortem, Incident 2.)

**Rule of thumb:** for each pattern, ask "how many places could this *start*, and how far could it scan from each?" If both are "about n", you have n².

### 2.5 Order matters when you replace

`grouping.py` masks UUIDs before numbers. Reverse the order and `3f2b8c1e-9a4d-…` becomes `<NUM>f<NUM>b<NUM>c<NUM>e-…` before the UUID rule ever sees it.

### Exercises

1. Write a regex for this project's level that also accepts `Warn` and `err`, mapped to `WARN` and `ERROR`. Add both to `evals/gold_lines.jsonl` *first*, run `python evals/gold.py`, watch it fail, then fix.
2. Add a `<PATH>` mask for file paths like `/var/lib/app/cache/123.tmp`. Where in the `MASKS` order must it go, and why?
3. Time `re.search(r"(a+)+$", "a" * 25 + "b")`, then 26, then 27. What happens each time you add one `a`? This is classic catastrophic backtracking. Why is `LINE_RE` safe from it?

---

## Part 3: Data processing

### 3.1 Stream, don't load

The analyzer never holds the log in memory. Three generators are chained: `iter_lines` yields raw lines → `parse_lines` yields parsed items → the loop in `analyze` updates counters. Each line flows through all three before the next one is read, like a sushi conveyor belt: you take one plate at a time, so the kitchen never needs a table big enough for all of them. That's why memory is 1.4 MB for 200,000 lines.

### 3.2 Aggregate with counters

`collections.Counter` is a dict that starts every key at 0:

```python
from collections import Counter

levels = Counter()
levels["ERROR"] += 1  # no KeyError, no "if key in dict" first
levels.most_common(3)  # [('INFO', 6194), ('WARN', 1646), ...]
```

Counters also add up (`c1 + c2`). That's how you'd scale this to 100 files in parallel: each worker returns counters, and you sum them.

### 3.3 Group by a key you compute

Grouping is "compute a key for each item, put items with the same key in one pile". Here the key is the **fingerprint**: the message with its variables masked. Choosing the key *is* the design decision: include the service and the same DB timeout in three services becomes three groups; leave it out and it's one problem with three victims (`DESIGN.md`).

### 3.4 Bucket time

Minute buckets: `int(ts.timestamp()) // 60`. A plain integer is easy to subtract ("30 minutes before" is `m - 30`) and makes a good dict key. **Use a dict, not a list from first to last minute.** One entry dated year 9999 would make that list billions long (`MemoryError` in the attack eval).

### 3.5 Normal vs unusual

To call something a spike you need a model of normal. The project tried three:

| Model | Problem |
|---|---|
| Mean + 3 standard deviations | One outage raises the mean and hides the next |
| Median + MAD of counts | With ~1 error a minute the MAD is usually 0, so noise looks extreme (14 false alarms) |
| **Expected errors for this traffic, + 5√expected** | Shipped: 0 false alarms from traffic surges |

The square root comes from the Poisson distribution: when events are rare and independent, their count wobbles by about √(average). It's the same maths as "a shop expecting 100 customers an hour won't be surprised by 90 or 110, but 150 means something's up".

### 3.6 Measure against an answer key, and keep the exam separate

The generator writes the right answer for every line. That turns "looks right to me" into a number. Two habits from machine learning keep the number honest:

- **Tune on one set, report on another.** Thresholds were chosen on seeds 0-19 and the published numbers come from seeds 100-149.
- **Get an independent check.** The gold set was written by hand and frozen before being run, because a generator and parser by the same author share blind spots. Its first score was 35/40.

### Exercises

1. Add "errors per service per hour" to `report.json`. Which counter do you need in `Analysis`, and where do you update it?
2. Change `SpikeConfig.k` to 3 and run `python evals/accuracy.py dev`. What happens to recall and false alarms? Now try 7. Plot both against k.
3. Write `merge(a: Analysis, b: Analysis) -> Analysis` that combines two analyses using Counter addition. Which fields *can't* simply be added? (Hint: first/last seen, spikes.)

---

## Exercise hints

- **1.1:** that's the byte-order mark the generator writes; `parse_lines` strips it from line 1.
- **1.2:** only the `decode(...)` call in `parse_lines`, but the encoding has to travel there through `Options`.
- **2.2:** before `<NUM>`, otherwise `/123.tmp` loses its digits first and the path no longer looks whole.
- **2.3:** time roughly doubles per `a`. `LINE_RE` has no nested quantifiers, and its adjacent pieces can't match the same characters ambiguously.
- **3.2:** lower k catches more but raises false alarms (k = 3 on dev: 19). k = 7 starts missing the first minute of spikes.
- **3.3:** min/max for first/last seen; spikes must be re-detected on the merged minute counters, not added.
