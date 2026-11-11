# Postmortem

Blameless format: what happened, how it was found, why, what it cost, and what now stops it happening again. All numbers are from the eval runs at the time.

---

## Incident 1: one error type became dozens of groups (the headline)

**What happened.** The first accuracy run on the 20 dev files scored grouping pair-recall at **0.679**: 12 real error types had been split into **137.7 groups per file**. On the demo file, a database-timeout spike was blamed on "Upstream inventory-service returned HTTP…" instead. Spike blame was right only **83%** of the time.

**How it was found.** The eval said *something* was wrong with grouping, but not what. Listing the distinct fingerprints for each true error type made it obvious:

```text
44 db_timeout   'Database connection timeout after 21367ms (host=db-<NUM>.internal, …)'
                'Database connection timeout after 26325ms (host=db-<NUM>.internal, …)'
25 order_stuck  'Order <UUID> stuck in state PENDING for 1576s'
15 oom          'Worker <NUM> killed: out of memory (rss=8052MB)'
 3 disk_full    'Disk usage at <NUM>% on /dev/sda1'
```

`db-<NUM>` was masked but `21367ms` wasn't. Same regex, different result: the difference was what touched the digits.

**Root cause.** The number mask was `\b\d+(?:\.\d+)?\b`. `\b` is a *word boundary*, the edge between a word character (letter, digit, underscore) and anything else. In `db-3`, a `-` sits before the 3 and the line ends after, so both boundaries exist. In `21367ms`, the digits run straight into the letters `ms`: no boundary after them, so no match. The same went for `1576s`, `8052MB` and `sda1`. Units glued to numbers are everywhere in real logs.

**Impact.** No crash and no wrong count, which made it dangerous. The report *looked* fine but was quietly misleading. The biggest problem in the log was spread across dozens of small piles and fell down the "top errors" ranking, and spike blame went to whichever unbroken group happened to be largest.

**Fix.** Drop the boundaries: `\d+(?:\.\d+)?`. Pair-recall **0.679 → 0.968**, groups **137.7 → 14.2** per file, spike blame **83% → 100%** (dev seeds). Masking digits inside words also turns `v1` into `v<NUM>` and `S3` into `S<NUM>`. That's harmless, because those parts never vary, and the fingerprint stays readable.

**Guard.** `tests/test_grouping_and_spikes.py` pins `5012ms`, `sda1` and the other cases. The README publishes groups-per-file next to the true count, so a regression shows up as a number, not a vibe.

**Lesson.** A metric with no diagnostic is an alarm with no location. The useful step was the one-line breakdown *per true category*, which every eval should make easy.

---

## Incident 2: 200 hostile lines hung the tool, with every defence on

**What happened.** The first attack eval reported 0 successes in the "slow regex" family, even with the 8 KB line cap switched off. That should have been suspicious, and it was.

**How it was found.** The attack was a long run of `aaaa…` with no `@`, aimed at the e-mail mask `\b[\w.+-]+@…`. Timing it directly showed 0.0 s. The reason: inside `aaaa…` there is a word boundary only at the start, so the pattern only tries once. That makes it linear, so the *attack* was weak, not the code strong. Changing it to `a.a.a.a…` puts a boundary before every `a`. The pattern then starts at each one and scans to the end of the line, which is quadratic:

| Input | Time for one line |
|---|---|
| `a.a.…` 8 KB | 0.176 s |
| `a.a.…` 64 KB | 11.7 s |

With the stronger attack, 200 such 8 KB lines hung the analyzer past the 10-second limit **with every defence on** (attack success 1/32). The line cap didn't save it: 8 KB is small enough to get through and big enough to hurt.

**Root cause.** A regex that can start at many positions and scan far from each one. No nested quantifiers were needed for it to be quadratic.

**Fix.** Two layers. (1) `(?<![\w.+-])` at the front: the pattern may only *start* where a run of address characters starts, so a run is scanned once. 64 KB now takes **0.0011 s**, about 10,000× faster. (2) Masks only ever see the first 1,000 characters of a message; the fingerprint keeps just 300 anyway.

**Guard.** The strong attack stays in the eval, and a unit test fails if fingerprinting 64 KB of `a.a.…` takes over 50 ms.

**Lesson.** An attack that "fails" with its defence switched off is telling you about the attack. The ablation table exists to catch exactly this.

---

## Incident 3: the attack eval cried wolf

The first run marked all 7 HTML-injection attacks as successful while Markdown and terminal injection, escaped by the same helper, all held. The report wasn't vulnerable. The *judge* flagged `<meta>` tags as injected, and the report's own `<head>` has `<meta charset="utf-8">`. The fix: only look inside `<body>`, where log text can land. **Lesson:** when one family fails and its siblings pass through the same code, suspect the measuring stick first.

## Incident 4: the gold set's first run scored 35/40

The generator and the parser shared their author's assumptions, so generated-log accuracy was 100% from day one. The 40 hand-written lines, frozen before being run, failed on formats real services emit and the generator never did: `+01:00` offsets, a space instead of `T`, Python's comma milliseconds (`09:15:02,123`), and tab separators. The parser now accepts all four and converts every timestamp to UTC; naive ones are assumed to be UTC. **39/40.** The remaining miss, a log line quoted inside a message, is a deliberate trade-off (see Known failures). **Risk noted:** having fixed the parser against these 40 lines, they're now partly a training set. Fresh lines from real logs are the top next step.

## Incident 5: a unit test found a crash the attack eval missed

`test_clock_skew_does_not_explode_the_timeline` wrote a 2-line file, one entry in 2026 and one in 9999, and the report crashed with `ValueError: year 10000 is out of range`. The chart window is centred on the median entry. In the attack files, 600 normal lines kept the median in 2026; here the median *was* year 9999, so the window ran past the last date Python can represent. **Fix:** date formatting returns `out-of-range` instead of raising. **Lesson:** attack files that are 99% normal only test the 1% case; edge cases also need tiny, lopsided inputs.

## Incident 6: invisible characters in our own source code

**What happened.** While writing the cheatsheet, a check that every quoted line exists in the code flagged lines that looked identical. `parser.py` held a *literal* U+FEFF (byte-order mark) and U+FFFD (replacement character) where the escapes `"\ufeff"` and `"\ufffd"` were intended. The test and attack files held literal U+202E right-to-left overrides, the "Trojan Source" trick that makes code display differently from how it runs. Everything still behaved correctly, but a reviewer would have seen `text.removeprefix("")` and "fixed" it into a bug.

**Root cause.** Not a typo: the editing tool turned every escape written as text into the literal character. The cheatsheet's own code quotes then picked them up the same way, which is how we knew it was the tooling.

**The fix had its own bug.** The first CI guard was `! grep -P '[...]'`. On this machine `grep` refused the pattern (a locale problem) and exited with an error, and the `!` turned that error into a green tick: a check that could never fail. The replacement, `scripts/check_invisible_chars.py`, builds its character list from plain numbers (`chr(0x202E)`) so it can't contain the characters itself, splits only on `\n` (Python's `splitlines()` would also split on U+2028 and hide it), and was proven both ways: 0 found on the clean repo, exit 1 with a planted U+202E.

**Lessons.** (1) A defence you build for your users' text applies to your own source too. (2) **A guard you haven't seen fail isn't a guard.** Every check added here was run once against a planted problem before being trusted.

## Near miss: a prediction that was wrong

I expected deeply nested JSON (`{"a":{"a":…`) to crash `json.loads` with `RecursionError`, which the parser didn't catch. It didn't crash at 1,600 levels or at 8,000: the C JSON decoder in Python 3.13 copes. The attack stays in the eval (`nested_json_*`) because a future Python, or a switch to a pure-Python parser, could change that.

## Spike detector redesign (not an incident, but it was wrong first)

v1 compared each minute's error *count* with the median and MAD of the previous 30 minutes, plus an error-rate guard. On dev files it caught every spike but raised **14 false alarms in 20 files, 9 of them during the planted 3× traffic surge**. With ~1 error a minute, the MAD is usually 0, so ordinary noise looked extreme; at counts that small the rate guard was itself too noisy to help. v2 asks how many errors a normal minute *with this much traffic* would have, using √expected as the natural wobble of rare events. **2 false alarms, 0 from surges, 100% recall** on the same dev files; 5 false alarms in 50 files on the held-out test seeds.
