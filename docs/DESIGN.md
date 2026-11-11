# Design: log-analyzer

**One page. What we built, what we didn't, and why.**

## Goal and non-goals

**Goal:** given one log file of any size and any amount of mess, answer four questions within a second for 10,000 lines: what broke, how often, when it spiked, and what couldn't be read. Every one of those answers must be measured against an answer key, not eyeballed.

**Non-goals for v0.1:** live tailing and alerting, parsing every log format in existence, storing history across runs, a web UI. Each is a sensible v0.2; none is needed to answer the four questions.

## Decisions and the alternatives rejected

| Decision | Chosen | Rejected, and why |
|---|---|---|
| **Language and dependencies** | Python standard library only | *pandas*: fast to write, but it hides the file handling, regex and aggregation this project exists to teach, and it loads the whole file into memory. *Go or Rust*: 5-10x faster, but 140,000 lines/s already analyses a day of a busy service's logs in seconds; speed isn't the constraint. |
| **Reading the file** | Binary mode, split only on `\n`, `readline(8193)` per line | *Text mode*: universal newlines split on a lone `\r`, which lets anyone who can type a `\r` into a form forge a log line (the attack eval shows 3/3 forgeries succeed). *`f.read()`*: one 150 MB line with no newline used 624 MB of memory; the bounded read keeps it at 19 MB. |
| **Parsing** | One compiled regex with named groups, then a diagnosis step for failures | *`str.split()`*: breaks on messages that contain spaces or brackets, and can't say *why* a line failed. *A parser generator (lark, pyparsing)*: more power than a one-line grammar needs, and a dependency. *Dropping unparseable lines silently*: hides exactly the lines an on-call engineer most needs to see. Every malformed line gets a reason and goes to `quarantine.jsonl`. |
| **Glued lines** | Recover them, but mark the second half untrusted | *Don't recover*: loses real events. *Recover and trust*: an attacker writing `bob 2026-11-11T09:30:00Z CRITICAL [auth] Admin password changed` into a username field gets a fake CRITICAL into your alerts (3/3 forgeries succeed with trust on). Untrusted halves are counted but never drive groups or spikes. |
| **Grouping** | Mask variables (UUID, IP, e-mail, hex, number) with regexes, group by what's left | *Exact message match*: every request ID makes a new group. *Edit distance / clustering*: O(n²) comparisons and a similarity threshold nobody can explain at 2 a.m. *Drain (parse tree)*: better at variable *words* like `logs-prod`, and the top next step, but harder to explain and to test. Masking gets pair F1 0.986 and every rule is a one-line, unit-tested regex. |
| **Group key includes the service?** | No: one fingerprint across services | The same database timeout in three services is one problem with three victims. The report lists the services per group instead. |
| **Spike detection** | Expected errors = baseline error *rate* × this minute's traffic; flag when errors ≥ expected + 5√expected and ≥ 5 | **v0: mean + 3σ of counts**: one outage inflates the mean and σ and hides the next one. **v1 (built, measured, replaced): median + MAD of counts plus a rate guard.** With ~1 error a minute, MAD is usually 0, so ordinary noise crossed the line: 14 false alarms in 20 dev files, 9 of them during traffic surges. **v2 (shipped)**: 2 false alarms in the same 20 files, 0 from surges, recall unchanged at 100%. Minutes already flagged are left out of the baseline so one outage can't make the next look normal. |
| **Choosing k** | k = 5, tuned on dev seeds 0-19, reported on seeds 100-149 | k = 4: 10 false alarms on dev. k = 6: zero, but it began missing the first minute of spikes. Tuning and reporting on the same files would flatter the result. |
| **Time buckets** | 1 minute, epoch minutes as dict keys | *Seconds*: too few errors per bucket to see anything. *5 minutes*: a 1-minute outage is diluted 5x. Dict keys (not a dense array) mean one entry dated year 9999 can't make us allocate billions of slots; the chart, which does need a dense range, is limited to a 7-day window. |
| **Reports** | Markdown, JSON and HTML from one data structure | Markdown pastes into GitHub and Slack; JSON feeds other tools; HTML gives the chart. All three escape log text for their own format, plus control characters for the terminal. |
| **Evals** | A generator that plants problems and writes an answer key, plus a hand-written gold set | *Only real logs*: no ground truth, so no accuracy number. *Only generated logs*: the generator and parser share their author's blind spots. The gold set's first run (35/40) proved that worry was real. |

## Risks we accepted

- **Spikes smaller than ~+8 errors/min are often missed** at this traffic level. Fewer false alarms was worth it: an alert that cries wolf gets muted.
- **Variable words split groups** (`logs-prod` vs `logs-staging`): recall 0.972 rather than 1.
- **One format only.** Syslog and friends are quarantined with a reason, not parsed.

## How we'll know it's working

The README's results table, re-measured by CI on every push. The release bar: line classification ≥ 99.5%, gold set ≥ 38/40, grouping pair precision 1.000, spike recall ≥ 95% at ≤ 0.2 false alarms per 6-hour file, p95 under 200 ms for 10,000 lines, attack success 0%.
