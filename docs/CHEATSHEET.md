# Cheatsheet: every line, explained

For technical interviews. Read it in pipeline order: **reader → parser → grouping → spikes → analyzer → report → generator → CLI → evals**. Each section quotes the code, then explains it line by line. Repetitive lines (the dozens of `w(...)` calls that print report rows) are explained once as a pattern. To keep the quotes readable, some function signatures drop their type hints and trailing comments are left off; everything else is verbatim.

**The 30-second pitch:** *"It streams a log file once, in binary, with a per-line size cap. Each line is classified by regex into entry, stack-trace continuation, blank, or malformed-with-a-reason. Errors are grouped by masking variable parts into a fingerprint. Spikes are minutes whose errors exceed what this minute's traffic predicts, by five Poisson standard deviations. Every number in the README comes from evals against a generated answer key, a hand-written gold set and 32 attacks, with each defence ablated."*

---

## 1. `models.py`: the four things a line can become

```python
ERROR_LEVELS = frozenset({"ERROR", "CRITICAL", "FATAL"})
KNOWN_LEVELS = frozenset({"TRACE", "DEBUG", "INFO", "WARN", "WARNING", *ERROR_LEVELS})
```
- `frozenset`: an immutable set. Membership checks (`x in s`) are O(1), and nobody can accidentally `add()` to a module-level constant.
- `*ERROR_LEVELS` unpacks the first set into the second, so the error levels are defined once.

```python
@dataclass(slots=True)
class Entry:
    line_no: int
    timestamp: datetime
    level: str
    service: str
    message: str
    source: str = "text"
    had_bad_bytes: bool = False
    continuation: list[str] = field(default_factory=list)
```
- `@dataclass` writes `__init__`, `__repr__` and `__eq__` for us from the annotated fields.
- `slots=True` stores fields in fixed slots instead of a per-object dict: less memory and faster attribute access. That matters when there are millions of entries.
- `source`: `"text"` (normal), `"json"` (recovered JSON line) or `"glued"` (second half of two stuck-together lines).
- `field(default_factory=list)`: every Entry gets its *own* new list. Writing `= []` would share one list between all instances, a classic Python bug, which is why dataclasses forbid it.

```python
# inside class Entry
@property
def is_error(self) -> bool:
    return self.level in ERROR_LEVELS


@property
def trusted(self) -> bool:
    return self.source != "glued"
```
- `@property` makes a method read like an attribute: `entry.is_error`, no brackets.
- `trusted` is a security decision: text found *inside* another line's message could be a real glued line or an attacker's fake one, so it never drives alerts.

```python
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
```
- Three more tiny result types. `Malformed.reason` is what makes the "malformed lines" report useful: *why*, not just *how many*.
- `Parsed` is a **type alias** for "any of the four" (the `|` union syntax is Python 3.10+).

---

## 2. `reader.py`: file handling

```python
GZIP_MAGIC = b"\x1f\x8b"
DRAIN_CHUNK = 64 * 1024
```
- Every gzip file starts with the bytes `1f 8b` (its "magic number"). We check content, not the file name, so a rotated `app.log.1` that's compressed still works.
- `DRAIN_CHUNK`: how much of an over-long line we read at a time while throwing it away (64 KB).

```python
@dataclass(slots=True)
class RawLine:
    line_no: int
    data: bytes
    too_long: bool = False
    original_length: int = 0
```
- `data` is **bytes**, not str: we haven't decoded it yet. Decoding is the parser's job, so it can decide how to handle invalid UTF-8.

```python
@contextmanager
def open_log(path: str | Path) -> Iterator[BinaryIO]:
    if str(path) == "-":
        yield sys.stdin.buffer
        return
    p = Path(path)
    with p.open("rb") as probe:
        magic = probe.read(2)
    opener = gzip.open if magic == GZIP_MAGIC else open
    with opener(p, "rb") as fh:
        yield fh
```
- `@contextmanager` turns a generator into something usable with `with`: code before `yield` is setup, code after is cleanup.
- `"-"` is the Unix convention for "read standard input". `sys.stdin.buffer` is the *binary* stdin (plain `sys.stdin` is text).
- We open the file once just to read 2 bytes (`probe`), then close it. `with` guarantees the close.
- `opener = gzip.open if ... else open`: functions are values in Python, so we pick one and call it.
- `"rb"` = read, binary. The `with ... yield fh` keeps the file open while the caller uses it and closes it when their `with` block ends, even on an exception.

```python
def _strip_newline(chunk: bytes) -> bytes:
    if chunk.endswith(b"\n"):
        chunk = chunk[:-1]
    if chunk.endswith(b"\r"):
        chunk = chunk[:-1]
    return chunk
```
- Removes `\n`, then a `\r` before it (Windows lines end `\r\n`). A `\r` in the *middle* of a line is left alone, deliberately (see below).

```python
def iter_lines(fh: BinaryIO, max_line_bytes: int | None = 8192) -> Iterator[RawLine]:
    line_no = 0
    while True:
        chunk = fh.readline(max_line_bytes + 1) if max_line_bytes else fh.readline()
        if not chunk:
            return
        line_no += 1
```
- A **generator** (it `yield`s): it produces one line at a time, so the file is never loaded whole. That's why memory stays flat.
- `fh.readline(limit)` reads up to the next `\n` **or** `limit` bytes, whichever comes first. Asking for one byte more than the cap is how we can tell "exactly 8,192 bytes" from "longer than 8,192".
- In binary mode `readline` splits only on `b"\n"`. **Text mode would also split on a lone `\r`** ("universal newlines"), which lets someone who types `\r` into a username start a fake log line. The attack eval proves it: 3/3 forgeries succeed in text mode.
- An empty `chunk` (`b""`) means end of file; `return` ends the generator.

```python
        if max_line_bytes and len(chunk) > max_line_bytes and not chunk.endswith(b"\n"):
            total = len(chunk)
            while True:
                more = fh.readline(DRAIN_CHUNK)
                total += len(more)
                if not more or more.endswith(b"\n"):
                    break
            yield RawLine(line_no, chunk[:max_line_bytes], too_long=True, original_length=total)
            continue
        yield RawLine(line_no, _strip_newline(chunk), original_length=len(chunk))
```
- Too long: keep the first 8 KB for the error report, then **drain** the rest in 64 KB bites, keeping only a byte count, until the newline. A 150 MB line therefore costs 19 MB of memory instead of 624 MB (measured).
- `continue` jumps to the next loop iteration, so the normal `yield` below is skipped.

```python
def iter_lines_text_mode(fh: BinaryIO) -> Iterator[RawLine]:
    text = io.TextIOWrapper(fh, encoding="utf-8", errors="replace", newline=None)
    for line_no, line in enumerate(text, start=1):
        data = line.rstrip("\n").encode("utf-8")
        yield RawLine(line_no, data, original_length=len(data))
```
- The naive version, kept **only** for the ablation eval. `newline=None` turns on universal newlines (the `\r` problem), and there's no size limit. `enumerate(..., start=1)` numbers lines from 1.

---

## 3. `parser.py`: regular expressions

```python
TS = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?"
GAP = r"[ \t]+"
SERVICE = r"[A-Za-z0-9_.\-]{1,64}"
```
- `r"..."` is a **raw string**: backslashes are kept as-is, so `\d` reaches the regex engine instead of being treated as a Python escape.
- `\d{4}`: exactly four digits. `[T ]`: a `T` or a space (both are valid ISO-8601).
- `(?:...)` is a **non-capturing group**: it groups for `?` without creating a numbered capture.
- `(?:[.,]\d{1,6})?`: optional fraction of a second, with `.` or `,` (Python's `logging` writes a comma), 1 to 6 digits.
- `(?:Z|[+-]\d{2}:?\d{2})?`: optional time zone, `Z` or `+01:00` / `-0500`.
- `GAP`: one or more spaces or tabs. `SERVICE`: 1 to 64 safe characters. Capping the length bounds the work and stops absurd service names.

```python
LINE_RE = re.compile(
    rf"(?P<ts>{TS}){GAP}(?P<level>[A-Za-z]+){GAP}\[(?P<service>{SERVICE})\](?:[ \t](?P<message>.*))?",
    re.DOTALL,
)
```
- `rf"..."` is raw **and** an f-string: `{TS}` is pasted in, so the pattern is built from named, readable parts.
- `(?P<name>...)`: a **named group**, so later we write `match.group("level")` instead of remembering "group 2".
- `\[` and `\]`: literal brackets (unescaped, `[` starts a character class).
- `(?:[ \t](?P<message>.*))?`: the message is optional (`[svc]` with nothing after is valid).
- `re.DOTALL` lets `.` match any character, including a stray `\r` inside the message.
- `re.compile` once at import time; reusing the compiled object is faster than recompiling per line.
- **Why it's safe from catastrophic backtracking:** no nested quantifiers like `(a+)+`, and the adjacent pieces can't match the same characters ambiguously, so the time is linear in the line length.

```python
EMBEDDED_HEADER_RE = re.compile(rf"{TS}{GAP}(?P<level>[A-Za-z]+){GAP}\[{SERVICE}\]")
TS_PREFIX_RE = re.compile(TS)
LEVEL_AFTER_TS_RE = re.compile(rf"{TS}{GAP}(?P<level>\S+)")
CONTINUATION_RE = re.compile(r"[ \t]+\S|Traceback \(most recent call last\):|Caused by: ")
EXCEPTION_TAIL_RE = re.compile(r"[A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt)\b")
```
- `EMBEDDED_HEADER_RE`: a complete header *inside* a message, the sign of two glued lines. We use `.search()` (anywhere), not `.match()` (start only).
- `TS_PREFIX_RE` and `LEVEL_AFTER_TS_RE` exist only to **diagnose** failures (below). `\S+` = one or more non-space characters.
- `CONTINUATION_RE`: `|` means "or". It matches indented lines (`    at Foo.bar`), Python's traceback header (the `\(` escapes a literal bracket), or Java's `Caused by: `.
- `EXCEPTION_TAIL_RE`: the last line of a Python traceback (`KeyError: 'sku'`) isn't indented. `[\w.]*` allows dotted names like `json.decoder.JSONDecodeError`; `\b` stops `Errorful` from matching.

```python
LEVEL_ALIASES = {"WARNING": "WARN"}
GARBAGE_RATIO = 0.30
PREVIEW_CHARS = 200
```
- Normalise `WARNING` to `WARN` so counts aren't split. 30% unreadable characters = binary junk. Malformed previews are cut to 200 characters.

```python
def _parse_ts(text: str) -> datetime | None:
    try:
        ts = datetime.fromisoformat(text.replace(",", "."))
    except ValueError:
        return None
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)
```
- The regex checked the *shape*; `fromisoformat` checks the *meaning*. `2026-02-30` has the right shape but isn't a real date, so it raises `ValueError` and we return `None` (the caller reports `invalid_timestamp`).
- `replace(",", ".")` normalises comma milliseconds first.
- Everything becomes UTC. A naive datetime (no zone) and an aware one **can't be compared** in Python (`TypeError`), and we compare timestamps for first/last seen, so mixing them would crash. Naive is assumed to be UTC (a documented known failure).

```python
def _is_garbage(text: str) -> bool:
    if not text:
        return False
    bad = sum(1 for ch in text if ch == "\ufffd" or (ord(ch) < 32 and ch != "\t"))
    return bad / len(text) > GARBAGE_RATIO
```
- `\ufffd` is the replacement character, what `decode(errors="replace")` puts in place of invalid bytes. `ord(ch) < 32` are control characters (tab excepted).
- `sum(1 for ... if ...)` counts matches with a generator: no list is built.
- The `if not text` guard avoids dividing by zero.

```python
def _diagnose(text: str) -> str:
    if not TS_PREFIX_RE.match(text):
        return "no_timestamp"
    level = LEVEL_AFTER_TS_RE.match(text)
    if not level:
        return "missing_level"
    if level.group("level").upper() not in KNOWN_LEVELS:
        return "unknown_level"
    return "missing_service"
```
- Runs only when `LINE_RE` failed. It peels the line from the left, one field at a time, and reports the first field that's wrong. Cheap, because it only runs on the 1-2% of lines that failed.

```python
def _first(obj: dict, *keys: str):
    for key in keys:
        value = obj.get(key)
        if isinstance(value, str) and value:
            return value
    return None
```
- `*keys` collects any number of arguments into a tuple. Returns the first key that holds a non-empty string. Different loggers call the same field `msg`, `message`, `ts` or `@timestamp`.
- `isinstance(value, str)` rejects `"level": 50` (a number), which the gold set tests.

```python
def _try_json(text: str, line_no: int) -> Entry | None:
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
```
- **Recovery, the "handle malformed" bonus.** A JSON line from another service isn't garbage; it just isn't our format.
- `json.JSONDecodeError` is a subclass of `ValueError`, so `except ValueError` catches bad JSON.
- `[1, 2, 3]` is valid JSON but not an object, hence `isinstance(obj, dict)`.
- `fullmatch` (whole string) rather than `match` (start only): `"2026-11-11T09:00:00Z junk"` must not pass.
- `dict.get(key, default)`: `LEVEL_ALIASES.get(x, x)` means "the alias if there is one, otherwise x unchanged".

```python
def parse_text(text: str, line_no: int, source: str = "text") -> list[Entry] | Malformed:
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
```
- Returns a **list** because one physical line can hold two entries (glued).
- `[A-Za-z]+` in the regex accepted `EROR`; the set check rejects it. Splitting it this way gives a precise reason.
- `.upper()` makes `error` and `ERROR` the same (case-insensitive levels).
- `match.group("message") or ""`: an absent optional group returns `None`; `or ""` turns that into an empty string.

```python
    glued = EMBEDDED_HEADER_RE.search(message)
    if glued and glued.group("level").upper() in KNOWN_LEVELS:
        rest = parse_text(message[glued.start() :], line_no, source="glued")
        if isinstance(rest, list):
            entries[0].message = message[: glued.start()].rstrip()
            entries.extend(rest)
    return entries
```
- If a full header appears inside the message, cut there. `glued.start()` is the index where the match begins; `message[i:]` is a slice from i to the end.
- **Recursion:** the second half is parsed by the same function, so three glued lines work too. Each level is marked `source="glued"` (untrusted). Recursion depth is bounded by the 8 KB line cap; without the cap, 5,000 glued headers crash with `RecursionError` (the ablation shows it).
- Only if the second half parses do we trim the first message, so a failed split changes nothing.

```python
def parse_lines(lines: Iterable[RawLine]) -> Iterator[Parsed]:
    last_entry: Entry | None = None
    in_trace = False
    for raw in lines:
        if raw.too_long:
            yield Malformed(raw.line_no, "line_too_long", raw.data[:PREVIEW_CHARS].decode("utf-8", "replace"))
            in_trace = False
            continue
```
- The parser's main loop, also a generator: it takes a stream of RawLines and yields a stream of results. Two pieces of state: the last good entry (stack traces attach to it) and whether we're inside a trace.

```python
        text = raw.data.decode("utf-8", errors="replace")
        if raw.line_no == 1:
            text = text.removeprefix("\ufeff")
        if not text.strip():
            yield Blank(raw.line_no)
            continue
```
- **Decoding:** bytes → str. `errors="replace"` swaps each invalid byte for `\ufffd` instead of raising `UnicodeDecodeError`. One bad byte shouldn't lose a whole line.
- `\ufeff` is the byte-order mark some Windows editors put at the very start of a file; invisible but it would break the timestamp match on line 1.
- `text.strip()` removes surrounding whitespace; if nothing is left, the line is blank.

```python
        if CONTINUATION_RE.match(text) or (in_trace and EXCEPTION_TAIL_RE.match(text)):
            if last_entry is None:
                yield Malformed(raw.line_no, "orphan_continuation", text[:PREVIEW_CHARS])
            else:
                last_entry.continuation.append(text)
                in_trace = True
                yield Continuation(raw.line_no, text)
            continue
        in_trace = False
```
- Stack-trace lines are attached to the entry they belong to, not reported as malformed (580 of them in the demo file).
- `EXCEPTION_TAIL_RE` only counts *inside* a trace, otherwise any line starting `ValueError:` would be swallowed.
- A trace line with nothing before it is an **orphan**: reported, not silently dropped.

```python
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
```
- Order matters: garbage check → normal parse → JSON fallback (only if the line looks like JSON, so we don't waste `json.loads` on every failure).
- `isinstance` checks which of the two return types we got.
- `had_bad_bytes`: the entry was salvaged but had invalid bytes, counted separately in the report.

---

## 4. `grouping.py`: turning messages into fingerprints

```python
MASKS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<UUID>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),
    (re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "<EMAIL>"),
    (re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{16,}\b", re.I), "<HEX>"),
    (re.compile(r"\d+(?:\.\d+)?"), "<NUM>"),
]
```
- A list of (pattern, placeholder) pairs, applied **in order**. Order matters: a UUID is full of digits, so if `<NUM>` ran first it would shred the UUID into `<NUM>a<NUM>-...` and the UUID pattern would never match.
- `re.I` = ignore case (hex can be `A-F` or `a-f`).
- UUID: 8-4-4-4-12 hex digits. `\b` = word boundary, the edge between a word character and anything else.
- IP: 1-3 digits, then `.digits` exactly three more times (`{3}`).
- E-mail: `(?<![\w.+-])` is a **negative lookbehind**, "the character before here is not an address character". It forces the match to start at the beginning of a run. Without it, `a.a.a.a…` (64 KB) took 11.7 s; with it, 0.001 s. That's **Incident 2** in the postmortem.
- Hex: `0x1f`-style, or 16+ hex characters (session tokens). 16 rather than 8 so ordinary words like `deadbeef` stay.
- Number: **no `\b`**, on purpose. `\b\d+\b` missed `5012ms` (no boundary between `2` and `m`) and split one error type into dozens of groups. That's **Incident 1**, the headline.

```python
WHITESPACE_RE = re.compile(r"\s+")
MAX_FINGERPRINT = 300
MAX_MASK_INPUT = 1000
OVERFLOW = "<too many distinct error groups: the rest are counted here>"


def fingerprint(message: str) -> str:
    text = message[:MAX_MASK_INPUT]
    for pattern, placeholder in MASKS:
        text = pattern.sub(placeholder, text)
    return WHITESPACE_RE.sub(" ", text).strip()[:MAX_FINGERPRINT]
```
- `pattern.sub(replacement, text)` replaces every match.
- Only the first 1,000 characters are masked (defence in depth against slow regexes), whitespace runs collapse to one space, and the result is capped at 300 characters.
- **Interview line:** "Fingerprinting is a lossy hash designed so that messages differing only in their variables collide."

```python
def epoch_minute(ts: datetime) -> int:
    return int(ts.timestamp()) // 60
```
- `timestamp()` = seconds since 1 Jan 1970 UTC; `// 60` is integer division, giving whole minutes. A plain integer makes a perfect dict key and is easy to subtract ("30 minutes earlier" = `m - 30`).

```python
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
```
- `Counter` is a dict that defaults missing keys to 0, so `c[k] += 1` works without checking first. It also has `.most_common(n)`.
- First/last seen use comparisons, not "first line read", because lines can arrive out of order.
- Only 3 example messages are kept (bounded memory). `per_minute` records *when* this group's errors happened; spike attribution uses it.

```python
class Grouper:
    def __init__(self, max_groups: int | None = 2000) -> None:
        self.max_groups = max_groups
        self.groups: dict[str, ErrorGroup] = {}

    def add(self, entry: Entry) -> str:
        key = fingerprint(entry.message)
        group = self.groups.get(key)
        if group is None:
            if self.max_groups and len(self.groups) >= self.max_groups:
                key = OVERFLOW
                group = self.groups.get(key)
            if group is None:
                group = self.groups[key] = ErrorGroup(key)
        group.add(entry)
        return key

    def ranked(self) -> list[ErrorGroup]:
        return sorted(self.groups.values(), key=lambda g: (-g.count, g.fingerprint))
```
- One group per fingerprint, in a dict (O(1) lookup).
- **The cap:** once 2,000 groups exist, new fingerprints go to a single overflow group. Without it, 200,000 unique error messages built 200,000 groups and 292 MB (the ablation shows it).
- `group = self.groups[key] = ErrorGroup(key)`: chained assignment, store and keep a reference in one line.
- `sorted(..., key=lambda g: (-g.count, g.fingerprint))`: sort by count descending (the minus sign), then alphabetically to break ties, so the output is deterministic.

---

## 5. `spikes.py`: the statistics

```python
@dataclass(frozen=True)
class SpikeConfig:
    window: int = 30
    min_history: int = 10
    k: float = 5.0
    min_errors: int = 5
    merge_gap: int = 1
```
- `frozen=True` makes it immutable, so it's safe as a default argument and can't be changed mid-run. Every knob has a name and a comment instead of a magic number in the code.

```python
@dataclass
class Spike:
    start_minute: int
    end_minute: int
    peak_errors: int
    total_errors: int
    baseline: float
    top_groups: list[tuple[str, int]] = field(default_factory=list)
```
- One detected spike: its window, its worst minute, its total, what was expected in the worst minute, and its top causes.

```python
def expected_errors(minute, first_minute, totals, errors, flagged, cfg) -> float | None:
    history = [m for m in range(max(first_minute, minute - cfg.window), minute) if m not in flagged]
    if len(history) < cfg.min_history:
        return None
    history_total = sum(totals.get(m, 0) for m in history)
    if history_total == 0:
        return None
    base_rate = sum(errors.get(m, 0) for m in history) / history_total
    return base_rate * totals[minute]
```
- `history`: the previous 30 minutes (not before the log starts), **minus minutes already flagged as spikes**, so one outage can't make the next one look normal.
- Fewer than 10 minutes of history → `None`, meaning "don't judge yet" (warm-up).
- `base_rate` = errors per log entry recently, say 4%. `expected` = that rate × entries this minute. A minute with 3× the traffic *expects* 3× the errors. **This is what makes traffic surges not alarm** (0 surge false alarms in 50 test files).
- `.get(m, 0)`: minutes with no entries simply aren't in the Counter.

```python
def detect_spikes(totals, errors, cfg=SpikeConfig()) -> list[Spike]:
    if not totals:
        return []
    first_minute = min(totals)
    flagged: set[int] = set()
    expected_at: dict[int, float] = {}
    for minute in sorted(errors):
        expected = expected_errors(minute, first_minute, totals, errors, flagged, cfg)
        if expected is None:
            continue
        threshold = expected + cfg.k * math.sqrt(max(expected, 1.0))
        if errors[minute] >= max(cfg.min_errors, threshold):
            flagged.add(minute)
            expected_at[minute] = expected
```
- We only scan minutes **that had errors** (`sorted(errors)`): a minute with zero errors can't be a spike, and iterating a dict's keys (never a dense range) means one entry dated year 9999 can't make us loop over billions of empty minutes.
- `sorted` = time order, needed because flagged minutes leave later baselines.
- **The threshold:** errors from rare, independent events (a Poisson process) naturally wobble by about √expected. So `expected + 5·√expected` means "five wobbles above normal". `max(expected, 1.0)` stops the threshold collapsing when expected is near 0.
- Also require at least 5 errors: 3 errors in a quiet minute is never an incident.
- k = 5 was chosen on **dev** seeds only (k = 4: 10 false alarms; k = 6: started missing spike starts).

```python
    spikes: list[Spike] = []
    for minute in sorted(flagged):
        n = errors[minute]
        if spikes and minute - spikes[-1].end_minute <= cfg.merge_gap + 1:
            spike = spikes[-1]
            spike.end_minute = minute
            if n > spike.peak_errors:
                spike.peak_errors, spike.baseline = n, round(expected_at[minute], 2)
        else:
            spikes.append(Spike(minute, minute, n, 0, round(expected_at[minute], 2)))
    for spike in spikes:
        spike.total_errors = sum(errors.get(m, 0) for m in range(spike.start_minute, spike.end_minute + 1))
    return spikes
```
- **Merging:** flagged minutes next to each other (or with one quiet minute between) become one spike, so a 5-minute outage is one alert, not five.
- `spikes[-1]` = the last item. `a, b = x, y` assigns two values at once.
- `range(start, end + 1)`: `range` excludes its end, hence `+ 1`.

```python
def attribute(spike, per_group_minutes, top=3) -> None:
    window = range(spike.start_minute, spike.end_minute + 1)
    scores = Counter({fp: sum(c.get(m, 0) for m in window) for fp, c in per_group_minutes.items()})
    spike.top_groups = [(fp, n) for fp, n in scores.most_common(top) if n > 0]
```
- For each error group, count its errors inside the spike's window; the top 3 are "the main causes". A **dict comprehension** builds the scores, `most_common(3)` ranks them, and the `if n > 0` filter drops groups that weren't involved. 100% of caught spikes are blamed on the right error in the eval.

---

## 6. `analyzer.py`: the one-pass pipeline

```python
@dataclass(frozen=True)
class Options:
    max_line_bytes: int | None = 8192
    max_groups: int | None = 2000
    binary_split: bool = True
    trust_recovered: bool = False
    max_timeline_minutes: int | None = 7 * 24 * 60
    escape_output: bool = True
    spikes: SpikeConfig = SpikeConfig()
    malformed_samples: int = 20
```
- **Every limit and defence lives here, with safe defaults.** The attack eval flips one at a time (`dataclasses.replace(safe, binary_split=False)`) to prove each matters. `None` means "no limit", only ever used by the eval.

```python
@dataclass
class Analysis:
    source: str
    options: Options
    lines_read: int = 0
    entries: int = 0
    recovered: Counter[str] = field(default_factory=Counter)
    blank_lines: int = 0
    continuation_lines: int = 0
    bad_byte_entries: int = 0
    malformed: Counter[str] = field(default_factory=Counter)
    malformed_samples: list[Malformed] = field(default_factory=list)
    levels: Counter[str] = field(default_factory=Counter)
    services: Counter[str] = field(default_factory=Counter)
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    totals: Counter[int] = field(default_factory=Counter)
    errors: Counter[int] = field(default_factory=Counter)
    grouper: Grouper = field(default_factory=Grouper)
    spikes: list[Spike] = field(default_factory=list)
    seconds: float = 0.0
```
- The whole result is **counters, not entries**: that's why memory doesn't grow with file size. `totals` and `errors` map epoch-minute → count; they feed the spike detector.

```python
# inside class Analysis
@property
def malformed_total(self) -> int:
    return sum(self.malformed.values())


@property
def error_total(self) -> int:
    return sum(self.levels[lvl] for lvl in ("ERROR", "CRITICAL", "FATAL"))
```
- Derived numbers are computed on demand rather than stored, so they can never disagree with the counters.

```python
def _record_entry(a: Analysis, entry: Entry) -> None:
    a.entries += 1
    if entry.source != "text":
        a.recovered[entry.source] += 1
    if entry.had_bad_bytes:
        a.bad_byte_entries += 1
    a.levels[entry.level] += 1
    a.services[entry.service] += 1
    if a.first_ts is None or entry.timestamp < a.first_ts:
        a.first_ts = entry.timestamp
    if a.last_ts is None or entry.timestamp > a.last_ts:
        a.last_ts = entry.timestamp
    if not entry.trusted and not a.options.trust_recovered:
        return
    minute = epoch_minute(entry.timestamp)
    a.totals[minute] += 1
    if entry.is_error:
        a.errors[minute] += 1
        a.grouper.add(entry)
```
- Updates every counter for one entry. **The security line** is the early `return`: untrusted (glued) entries are counted, but never reach the spike maths or the groups. With it off, 40 forged CRITICAL lines create a fake spike (ablation: 3/3 succeed).

```python
def analyze(path, options=Options(), quarantine=None) -> Analysis:
    started = time.perf_counter()
    a = Analysis(source=str(path), options=options, grouper=Grouper(options.max_groups))
    with ExitStack() as stack:
        fh = stack.enter_context(open_log(path))
        q = stack.enter_context(open(quarantine, "w", encoding="utf-8")) if quarantine else None
        raw = iter_lines(fh, options.max_line_bytes) if options.binary_split else iter_lines_text_mode(fh)
```
- `time.perf_counter()`: the high-resolution clock for measuring durations (not wall-clock time).
- **`ExitStack`** handles a *variable* number of `with` contexts: the log file always, the quarantine file only sometimes. Both are closed when the block ends, even on an exception. The alternative is nested `with` statements or a fragile `try/finally`.
- `encoding="utf-8"` explicitly: never rely on the platform default (Windows' default isn't UTF-8).

```python
        for item in parse_lines(raw):
            if isinstance(item, Entry):
                _record_entry(a, item)
            elif isinstance(item, Continuation):
                a.continuation_lines += 1
            elif isinstance(item, Blank):
                a.blank_lines += 1
            else:
                a.malformed[item.reason] += 1
                if len(a.malformed_samples) < options.malformed_samples:
                    a.malformed_samples.append(item)
                if q:
                    q.write(json.dumps({"line": item.line_no, "reason": item.reason, "raw": item.raw}) + "\n")
            a.lines_read = item.line_no
```
- Generators chained: `iter_lines` → `parse_lines` → this loop. Each line flows through all three before the next is read. This is the "streaming" in the README.
- Malformed lines go to `quarantine.jsonl`: **JSON Lines**, one JSON object per line. `json.dumps` escapes control characters, so a hostile line can't break the file. The quarantine is the "dead-letter queue" pattern: keep what you couldn't process, so it can be inspected and replayed.

```python
    a.spikes = detect_spikes(a.totals, a.errors, options.spikes)
    per_group = {g.fingerprint: g.per_minute for g in a.grouper.groups.values()}
    for spike in a.spikes:
        attribute(spike, per_group)
    a.seconds = time.perf_counter() - started
    return a
```
- Spike detection needs the whole timeline, so it runs **after** the pass, on the small counters, not the file.

---

## 7. `report.py`: output, and treating log text as hostile

```python
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
MD_SPECIAL_RE = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~])")
SPARK = "▁▂▃▄▅▆▇█"
MAX_BUCKETS = 72
```
- `CONTROL_RE`: control characters (including `\x1b`, the start of every ANSI terminal escape, which can change your terminal title or clear the screen), Unicode line separators, and **bidirectional overrides** (`\u202e` makes `invoice\u202egnp.exe` display as `invoiceexe.png`). Tab (`\x09`) and newline (`\x0a`) are left out of the range and handled separately.
- `MD_SPECIAL_RE`: every character with meaning in Markdown, in a capture group `(...)` so the replacement can put it back with a backslash in front.
- `SPARK`: eight block characters for the text sparkline.

```python
def clean(text, limit=160, *, safe=True) -> str:
    if safe:
        text = CONTROL_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", text)
        text = text.replace("\n", " ").replace("\t", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"
```
- The `*` in the signature makes `safe` **keyword-only**: you must write `safe=False`, so turning the defence off is never an accident.
- `.sub` with a **function** as the replacement: each control character becomes visible text like `\x1b` (`:02x` = two-digit hex).

```python
def md(text, limit=160, *, safe=True) -> str:
    text = clean(text, limit, safe=safe)
    return MD_SPECIAL_RE.sub(r"\\\1", text) if safe else text


def h(text, limit=160, *, safe=True) -> str:
    text = clean(text, limit, safe=safe)
    return html.escape(text, quote=True) if safe else text
```
- `r"\\\1"` = a literal backslash followed by group 1. So `|` becomes `\|` and can no longer break a table, and `](` can't make a link.
- `html.escape(..., quote=True)` turns `< > & " '` into entities like `&lt;`. `quote=True` matters for text inside attributes.
- **Escape at output, for the output's format** (HTML-escape for HTML, Markdown-escape for Markdown), not once at input: the same text needs different escaping in different places.

```python
def minute_iso(minute: int) -> str:
    try:
        return datetime.fromtimestamp(minute * 60, UTC).strftime("%Y-%m-%d %H:%M")
    except (ValueError, OverflowError, OSError):
        return "out-of-range"
```
- Epoch minutes back to readable text. The `try` exists because of **Incident 5**: a chart window near year 9999 crashed the whole report.

```python
def timeline(a: Analysis) -> tuple[int, int, list[int], int]:
    if not a.totals:
        return 0, 1, [], 0
    lo, hi = min(a.totals), max(a.totals)
    limit = a.options.max_timeline_minutes
    outside = 0
    if limit and hi - lo + 1 > limit:
        minutes = sorted(a.totals.elements())
        centre = minutes[len(minutes) // 2]
        lo, hi = centre - limit // 2, centre + limit // 2
        outside = sum(n for m, n in a.totals.items() if not lo <= m <= hi)
    span = hi - lo + 1
    size = max(1, -(-span // MAX_BUCKETS))
    series = [a.errors.get(m, 0) for m in range(lo, hi + 1)]
    counts = [sum(series[i : i + size]) for i in range(0, span, size)]
    return lo, size, counts, outside
```
- The chart *does* need a dense list of minutes, so this is where clock skew bites: one entry in year 9999 makes `range(lo, hi + 1)` billions long (`MemoryError` in the ablation).
- **The guard:** if the span is over 7 days, centre a 7-day window on the **median** entry and count the rest as `outside`. `Counter.elements()` repeats each minute by its count, so the median is weighted by entries. `lo <= m <= hi` is a chained comparison.
- `-(-span // MAX_BUCKETS)` is **ceiling division** (integer division rounds down; negating twice rounds up). It picks a bucket size so there are at most 72 buckets.
- The last line sums each slice of `size` minutes into one bucket.

```python
def sparkline(counts):
    top = max(counts, default=0)
    if top == 0:
        return SPARK[0] * len(counts)
    return "".join(SPARK[min(len(SPARK) - 1, c * (len(SPARK) - 1) // top)] if c else " " for c in counts)
```
- Scales each bucket to one of 8 block heights. `max(..., default=0)` avoids an error on an empty list. Empty buckets become a space.

**`to_dict(a, top)`** builds one plain dictionary of everything: summary numbers, levels, services, the top N groups, spikes and malformed samples. Datetimes become strings with `.isoformat()`. **All three renderers read from it**, so Markdown, JSON and HTML can never disagree. `round(100 * x / y, 2) if y else 0.0` avoids dividing by zero on an empty file.

**`render_json`** is `json.dumps(to_dict(...), indent=2, ensure_ascii=False)`. JSON needs no extra escaping, because `json.dumps` escapes control characters and quotes itself. `ensure_ascii=False` keeps `Zoë` readable instead of `Zo\u00eb`.

**`render_markdown` and `render_html`** follow one pattern:
```python
out: list[str] = []
w = out.append  # w("line") adds a line
...
return "\n".join(out) + "\n"
```
- Building a list and joining once is O(n). Repeated `s += line` can copy the whole string every time.
- `safe = a.options.escape_output` is read once and passed to every `md(...)` / `h(...)` call, which is how the ablation switches escaping off everywhere at once.
- Every value that came from a log (fingerprints, service names, levels, malformed raw text, the file name) goes through `md()` or `h()`. Numbers we computed ourselves (`f"{n:,}"`, thousands separators) don't need it.
- Tables are rows of `| a | b |`, with `---:` right-aligning numeric columns. `(g["first_seen"] or "")[11:19]` slices `HH:MM:SS` out of an ISO timestamp.

**`_svg_chart`** draws the HTML chart as inline SVG, so there's no JavaScript and no library. Spike windows are drawn first as pale red rectangles *behind* the bars. Each bar's height is `count / max × chart height`; SVG's y-axis points down, hence `y = height - bar_height`. `<title>` inside a bar gives a hover tooltip for free.

**`render_terminal`** is the short CLI summary. It uses `clean()` (control characters made visible) because a terminal interprets escape codes: `\x1b]0;pwned\x07` would rename your terminal window, and `\x1b[2J` would clear it.

---

## 8. `generator.py`: the measuring stick

- `Random(seed)`: its own random generator, never the global one, so the same seed gives **byte-identical** files (a test checks this). That's what makes every eval reproducible.
- `_uuid(r)` builds a UUID from the seeded generator (`uuid.uuid4()` would use the OS's randomness and break reproducibility). `_ip(r)` makes four random octets.
- `ERROR_TEMPLATES`: 12 error types, each `(level, services it can come from, lambda r: message)`. A **lambda** is a small anonymous function; each call makes a fresh message with new variable values. Some templates deliberately contain the traps the analyzer must survive: units glued to numbers (`5012ms`), e-mails, UUIDs, word variables (`logs-prod`).
- `ERROR_WEIGHTS` and `LEVEL_WEIGHTS` feed `r.choices(population, weights)`, a weighted random pick (65% INFO, 4% ERROR, …).
- `JAVA_TRACE` / `PY_TRACE`: realistic stack traces; 30% of errors get one.
- `Event.header()`: `strftime` formats the time; `microsecond // 1000` gives milliseconds, zero-padded with `:03d`. `Event.truth()` is this event's line in the answer key.
- `_plan(r, minutes)`: picks a traffic surge and 3 spikes, keeping 30 minutes between any two, so each spike has a clean baseline. Spikes start after minute 40 (warm-up is a known limitation, not something to hide).
- `make_events`: spike events first, then fill the rest so there are **exactly n events**. `r.choices(range(minutes), weights, k=...)` places background events, with 3× weight in surge minutes. Then sort by time, and shift 1% of events up to 4 s earlier ("late writes" happen in multi-threaded services).
- `_corrupt(r, kind, e)`: the 10 corruption types. Each returns the broken bytes **and** the truth label (malformed, or entry if it should be recoverable). `truncated` cuts *inside the header* so the right answer is unambiguous. `garbage_bytes` uses bytes 128-255, which are never valid UTF-8 on their own. `bad_byte_in_message` appends `\xff\xfe`. `crlf` adds a `\r` before the newline.
- `generate()`: starts the file with a byte-order mark, then for each event maybe inserts a blank line, maybe corrupts it (2.5%), maybe glues it to the next event, and appends its stack trace. `emit()` appends bytes and a label together, so the answer key can't get out of step with the file.
- `write()`: `path.write_bytes(data)`. It must be **bytes**, because the file deliberately contains invalid UTF-8 that `write_text` would refuse. `mkdir(parents=True, exist_ok=True)` creates `data/` if needed and doesn't complain if it exists.

---

## 9. `cli.py`, `__main__.py`, `__init__.py`

- `argparse` with **subcommands** (`generate`, `analyze`), each with its own flags and `set_defaults(func=...)` pointing at the function that runs it. `main()` parses and calls `args.func(args)`.
- `_cmd_analyze` writes each requested format through a `FORMATS` dict mapping name → (file name, render function). Adding a format means one dict entry.
- **Exit codes** are the CLI's API: 0 = fine, 1 = spike found with `--fail-on-spike` (so a cron job or CI step can fail loudly), 2 = file not found. Errors go to `sys.stderr` so they don't pollute output piped elsewhere.
- `raise SystemExit(main())` turns `main`'s return value into the process exit code.
- `__main__.py` makes `python -m log_analyzer` work. `__init__.py` holds `__version__`, which `--version` prints.

---

## 10. The evals, in one breath each

- **`accuracy.py`**: generates each seed's file, parses it, and compares **every line** with the answer key (classification, malformed precision/recall, field-by-field entries, recoveries). Grouping uses **pair counting**: for every pair of errors, "same group" should equal "same true type". `math.comb(n, 2)` = number of pairs in a group of n. Spikes: a detection counts if it overlaps a planted window; delay and attribution are measured too. DEV seeds (0-19) are for tuning, TEST seeds (100-149) for reporting.
- **`gold.py`**: 40 hand-written lines with the answer a human wants, frozen before the first run. Catches the blind spots the generator shares with the parser.
- **`sensitivity.py`**: synthetic minutes (`r.binomialvariate(total, 0.04)` = how many of `total` entries are errors at 4%), with `extra` errors added at minute 45. It plots detection rate against spike size and measures false alarms on quiet data.
- **`performance.py`**: `timed()` runs a function after a warm-up and records durations; `statistics.quantiles(n=100)` gives the 50th and 95th percentiles. `tracemalloc` measures the peak Python heap. The CLI is timed as a real subprocess, so Python's start-up is included.
- **`attacks.py`**: each attack file is analysed in a **child process** (`subprocess.run(..., timeout=10, preexec_fn=_limit_memory)`, with `resource.setrlimit(RLIMIT_AS)` capping memory at 1.5 GB), so a successful hang or crash is recorded instead of killing the eval. Judges: `html.parser.HTMLParser` scans `<body>` for dangerous tags and `on*` attributes; regexes with **negative lookbehind** `(?<!\\)` find *unescaped* Markdown links, tags and pipes; the terminal check looks for `\x1b` / `\u202e`. Then each defence is switched off with `dataclasses.replace` to show its attacks succeed.
- **`run_all.py`**: runs everything, saves JSON to `evals/results/`, and rewrites the README between `<!-- results:start -->` and `<!-- results:end -->`. CI runs the fast evals and `git diff --exit-code README.md`, so a regression fails the build.

---

## Questions you'll get, and crisp answers

**"Why not pandas?"** It would load the file into memory and hide the parts I wanted to own: binary reading, size limits, failure reasons. Streaming with counters handles a file of any size in constant memory, and 140k lines/s is plenty.

**"How do you know your parser is right?"** Two independent checks. A generator plants 10 kinds of corruption and writes an answer key for every line (100% on 531k held-out lines). Because that shares my assumptions, there's also a hand-written gold set frozen before it was run; its first score was 35/40, which found four real format gaps.

**"Explain catastrophic backtracking."** A regex is slow when it can match the same text many different ways and must try them all on failure, like `(a+)+$` on `aaaa…b`. Mine had a milder cousin: a pattern that could *start* at thousands of positions and scan to the end from each, which is quadratic. A lookbehind that only allows starting at the beginning of a run made it linear: 11.7 s → 0.001 s.

**"Why median/MAD, then why not?"** Median and MAD resist outliers better than mean and standard deviation, which is why v1 used them. But with about 1 error a minute the MAD is usually 0, so noise looked extreme: 14 false alarms in 20 files. v2 models expected errors from traffic, and its √expected scale is the natural Poisson noise.

**"What's your false-alarm rate?"** About 0.2 per 24 hours on quiet synthetic data; 5 in 50 six-hour test files. It's tunable: k = 6 gives fewer false alarms but misses weaker spikes. The sensitivity curve shows the trade-off.

**"How would you scale it?"** Logs are append-only and the state is counters, so it shards naturally: per-file or per-hour workers produce counters, and you merge them (Counters add). Spike detection runs on the merged minute series. For live use, keep the last 30 minutes of counters in memory and evaluate each minute as it closes.

**"What would you do differently?"** Learn variable words from the data (Drain), test on a week of real logs before tuning anything further, and put the invisible-character check in CI from day one instead of after finding them in my own source.
