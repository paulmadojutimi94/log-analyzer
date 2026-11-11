"""Generate a realistic, deliberately messy log file, plus the answer key.

The answer key ("truth" file) records, for every physical line, what it
really is: a good entry, a stack-trace line, a blank line or a broken line,
and which error template made it. It also lists the spikes we planted. The
evals score the analyzer against this key, so the generator is the
measuring stick and must be deterministic: same seed, same bytes.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from random import Random

SERVICES = ["api-gateway", "auth-service", "payment-service", "order-service", "inventory-service", "notification-service"]
START = datetime(2026, 11, 11, 9, 0, tzinfo=UTC)


def _uuid(r: Random) -> str:
    return str(uuid.UUID(int=r.getrandbits(128), version=4))


def _ip(r: Random) -> str:
    return ".".join(str(r.randint(1, 254)) for _ in range(4))


# ---- Message templates -------------------------------------------------------
# Each error template: (level, services it can come from, message maker).

ERROR_TEMPLATES = {
    "db_timeout": (
        "ERROR",
        ["order-service", "payment-service", "inventory-service"],
        lambda r: f"Database connection timeout after {r.randint(3000, 30000)}ms (host=db-{r.randint(1, 4)}.internal, pool=primary)",
    ),
    "payment_declined": (
        "ERROR",
        ["payment-service"],
        lambda r: f"Payment declined for user {r.randint(10000, 99999)}: card expired (amount={r.randint(5, 500)}.{r.randint(0, 99):02d} EUR)",
    ),
    "upstream_5xx": (
        "ERROR",
        ["api-gateway", "order-service"],
        lambda r: f"Upstream inventory-service returned HTTP {r.choice([500, 502, 503, 504])} for GET /v1/stock/{r.randint(100000, 999999)}",
    ),
    "null_pointer": ("ERROR", ["order-service"], lambda r: f"NullPointerException in OrderService.process(order_id={_uuid(r)})"),
    "disk_full": ("CRITICAL", ["notification-service", "api-gateway"], lambda r: f"Disk usage at {r.randint(90, 99)}% on /dev/sda{r.randint(1, 3)}"),
    "rate_limited": ("ERROR", ["api-gateway"], lambda r: f"Rate limit exceeded for client {_ip(r)} ({r.randint(101, 400)} req/min)"),
    "jwt_invalid": ("ERROR", ["auth-service"], lambda r: f"Invalid JWT for session {r.getrandbits(128):032x}: signature mismatch"),
    "s3_denied": ("ERROR", ["notification-service"], lambda r: f"S3 PutObject failed for bucket logs-{r.choice(['prod', 'staging'])}: AccessDenied"),
    "oom": (
        "CRITICAL",
        ["inventory-service", "order-service"],
        lambda r: f"Worker {r.randint(1, 16)} killed: out of memory (rss={r.randint(2048, 8192)}MB)",
    ),
    "email_bounce": (
        "ERROR",
        ["notification-service"],
        lambda r: (
            f"Email to {r.choice(['ana', 'li.wei', 'sam+shop', 'o.brien'])}"
            f"{r.randint(1, 999)}@{r.choice(['gmail.com', 'example.ie', 'mail.co.uk'])} "
            f"bounced: mailbox full"
        ),
    ),
    "order_stuck": ("ERROR", ["order-service"], lambda r: f"Order {_uuid(r)} stuck in state PENDING for {r.randint(300, 3600)}s"),
    "kafka_lag": (
        "ERROR",
        ["inventory-service"],
        lambda r: f"Consumer group billing lagging by {r.randint(10000, 900000)} messages on topic orders.v2 partition {r.randint(0, 11)}",
    ),
}
ERROR_WEIGHTS = {
    "db_timeout": 14,
    "payment_declined": 12,
    "upstream_5xx": 12,
    "null_pointer": 8,
    "disk_full": 3,
    "rate_limited": 12,
    "jwt_invalid": 10,
    "s3_denied": 5,
    "oom": 3,
    "email_bounce": 8,
    "order_stuck": 7,
    "kafka_lag": 6,
}

OTHER_TEMPLATES = {
    "DEBUG": [
        lambda r: f"Query took {r.randint(1, 40)}ms: SELECT * FROM products WHERE id = {r.randint(1, 99999)}",
        lambda r: f"Cache lookup key=user:{r.randint(10000, 99999)}:profile hit={r.choice(['true', 'false'])}",
    ],
    "INFO": [
        lambda r: f"GET /v1/products/{r.randint(1, 99999)} 200 {r.randint(3, 250)}ms",
        lambda r: f"User {r.randint(10000, 99999)} logged in from {_ip(r)}",
        lambda r: f"Order {_uuid(r)} created (items={r.randint(1, 9)}, total={r.randint(5, 900)}.00 EUR)",
        lambda r: f"POST /v1/cart 201 {r.randint(5, 300)}ms",
        lambda r: "Health check OK",
    ],
    "WARN": [
        lambda r: f"Slow query {r.randint(500, 4000)}ms on table orders",
        lambda r: f"Retrying request to payment-provider (attempt {r.randint(1, 3)}/3)",
        lambda r: f"Deprecated API /v1/legacy called by client {_ip(r)}",
    ],
}
LEVEL_WEIGHTS = {"DEBUG": 15, "INFO": 65, "WARN": 16, "ERROR": 4}

JAVA_TRACE = [
    "    at com.shop.orders.OrderService.process(OrderService.java:{n})",
    "    at com.shop.orders.OrderController.create(OrderController.java:{n})",
    "Caused by: java.net.SocketTimeoutException: Read timed out",
    "    at java.base/java.net.SocketInputStream.read(SocketInputStream.java:{n})",
]
PY_TRACE = [
    "Traceback (most recent call last):",
    '  File "/app/inventory/worker.py", line {n}, in handle',
    "    stock = self.cache[sku]",
    "KeyError: 'sku-{n}'",
]

CORRUPTIONS = [
    "truncated",
    "bad_level",
    "us_date",
    "impossible_date",
    "missing_service",
    "garbage_bytes",
    "json_line",
    "glued",
    "bad_byte_in_message",
    "crlf",
]


@dataclass
class Event:
    ts: datetime
    level: str
    service: str
    message: str
    template: str | None = None  # error template id, None for non-errors
    trace: list[str] = field(default_factory=list)

    def header(self) -> str:
        return f"{self.ts.strftime('%Y-%m-%dT%H:%M:%S')}.{self.ts.microsecond // 1000:03d}Z {self.level} [{self.service}]"

    def line(self) -> str:
        return f"{self.header()} {self.message}"

    def truth(self) -> dict:
        return {
            "ts": self.ts.isoformat(timespec="milliseconds"),
            "level": self.level,
            "service": self.service,
            "message": self.message,
            "template": self.template,
        }


@dataclass
class PlantedSpike:
    start: int  # minute offset from START
    end: int
    template: str
    per_minute: int


def _error_event(r: Random, ts: datetime, template: str) -> Event:
    level, services, make = ERROR_TEMPLATES[template]
    event = Event(ts, level, r.choice(services), make(r), template)
    if r.random() < 0.3:  # some errors come with a stack trace
        lines = JAVA_TRACE if r.random() < 0.5 else PY_TRACE
        event.trace = [t.format(n=r.randint(10, 400)) for t in lines]
    return event


def _random_event(r: Random, ts: datetime) -> Event:
    level = r.choices(list(LEVEL_WEIGHTS), list(LEVEL_WEIGHTS.values()))[0]
    if level == "ERROR":
        template = r.choices(list(ERROR_WEIGHTS), list(ERROR_WEIGHTS.values()))[0]
        return _error_event(r, ts, template)
    return Event(ts, level, r.choice(SERVICES), r.choice(OTHER_TEMPLATES[level])(r))


def _plan(r: Random, minutes: int) -> tuple[list[PlantedSpike], tuple[int, int]]:
    """Pick 3 spikes and 1 traffic surge that don't overlap (30-minute gaps)."""
    while True:
        surge_start = r.randint(40, minutes - 40)
        surge = (surge_start, surge_start + r.randint(10, 25))
        spikes: list[PlantedSpike] = []
        busy = [(surge[0] - 30, surge[1] + 30)]
        for _ in range(200):
            if len(spikes) == 3:
                break
            start = r.randint(40, minutes - 10)
            end = start + r.randint(0, 4)
            if all(end + 30 < a or start - 30 > b for a, b in busy):
                template = r.choice(list(ERROR_TEMPLATES))
                spikes.append(PlantedSpike(start, end, template, r.randint(8, 20)))
                busy.append((start, end))
        if len(spikes) == 3:
            return sorted(spikes, key=lambda s: s.start), surge


def make_events(n: int, seed: int, minutes: int = 360) -> tuple[list[Event], list[PlantedSpike], tuple[int, int]]:
    r = Random(seed)
    spikes, surge = _plan(r, minutes)
    events: list[Event] = []
    for sp in spikes:
        for m in range(sp.start, sp.end + 1):
            for _ in range(sp.per_minute):
                events.append(_error_event(r, START + timedelta(minutes=m, seconds=r.uniform(0, 59.999)), sp.template))
    weights = [3 if surge[0] <= m <= surge[1] else 1 for m in range(minutes)]
    for m in r.choices(range(minutes), weights, k=n - len(events)):
        events.append(_random_event(r, START + timedelta(minutes=m, seconds=r.uniform(0, 59.999))))
    events.sort(key=lambda e: e.ts)
    # A few late writes: real multi-threaded services log slightly out of order.
    for e in events:
        if r.random() < 0.01:
            e.ts -= timedelta(seconds=r.uniform(0.5, 4))
    return events, spikes, surge


def _corrupt(r: Random, kind: str, e: Event) -> tuple[bytes, dict]:
    """Return the broken line's bytes and its truth label."""
    line = e.line()
    if kind == "truncated":
        cut = r.randint(5, len(e.header()) - 1)
        return line[:cut].encode(), {"kind": "malformed", "corruption": kind}
    if kind == "bad_level":
        typo = {"ERROR": "EROR", "CRITICAL": "CRIT1CAL", "INFO": "INF0", "WARN": "WARNN", "DEBUG": "DEBU"}[e.level]
        return line.replace(f" {e.level} ", f" {typo} ", 1).encode(), {"kind": "malformed", "corruption": kind}
    if kind == "us_date":
        us = e.ts.strftime("%m/%d/%Y %H:%M:%S")
        return f"{us} {e.level} [{e.service}] {e.message}".encode(), {"kind": "malformed", "corruption": kind}
    if kind == "impossible_date":
        broken = line.replace(e.ts.strftime("%Y-%m-"), e.ts.strftime("%Y-13-"), 1)
        return broken.encode(), {"kind": "malformed", "corruption": kind}
    if kind == "missing_service":
        return line.replace(f"[{e.service}]", e.service, 1).encode(), {"kind": "malformed", "corruption": kind}
    if kind == "garbage_bytes":
        return bytes(r.randint(128, 255) for _ in range(r.randint(20, 80))), {"kind": "malformed", "corruption": kind}
    if kind == "json_line":
        obj = {"timestamp": e.header().split(" ")[0], "level": e.level.lower(), "service": e.service, "msg": e.message}
        return json.dumps(obj).encode(), {"kind": "entry", "entries": [e.truth()], "corruption": kind}
    if kind == "bad_byte_in_message":
        return line.encode() + b" \xff\xfe", {"kind": "entry", "entries": [e.truth()], "corruption": kind, "message_suffix_replaced": True}
    if kind == "crlf":
        return line.encode() + b"\r", {"kind": "entry", "entries": [e.truth()], "corruption": kind}
    raise ValueError(kind)


def generate(n: int = 10_000, seed: int = 42, corruption_rate: float = 0.025, blank_rate: float = 0.004, minutes: int = 360) -> tuple[bytes, dict]:
    """Return (log file bytes, truth dict). n = number of log events."""
    events, spikes, surge = make_events(n, seed, minutes)
    r = Random(seed + 1)
    out: list[bytes] = [b"\xef\xbb\xbf"]  # a byte-order mark, as some editors write
    labels: list[dict] = []

    def emit(data: bytes, label: dict) -> None:
        out.append(data + b"\n")
        labels.append(label)

    i = 0
    while i < len(events):
        e = events[i]
        if r.random() < blank_rate:
            emit(b"", {"kind": "blank"})
        kind = r.choice(CORRUPTIONS) if r.random() < corruption_rate else None
        if kind == "glued" and i + 1 < len(events) and not e.trace and not events[i + 1].trace:
            nxt = events[i + 1]
            emit((e.line() + nxt.line()).encode(), {"kind": "entry", "entries": [e.truth(), nxt.truth()], "corruption": kind})
            i += 2
            continue
        if kind and kind != "glued":
            data, label = _corrupt(r, kind, e)
            emit(data, label)
        else:
            emit(e.line().encode(), {"kind": "entry", "entries": [e.truth()], "corruption": None})
        for t in e.trace:
            emit(t.encode(), {"kind": "continuation"})
        i += 1

    truth = {
        "seed": seed,
        "events": n,
        "start": START.isoformat(),
        "spikes": [
            {
                "start": (START + timedelta(minutes=s.start)).isoformat(),
                "end": (START + timedelta(minutes=s.end)).isoformat(),
                "template": s.template,
                "per_minute": s.per_minute,
            }
            for s in spikes
        ],
        "traffic_surge": {"start": (START + timedelta(minutes=surge[0])).isoformat(), "end": (START + timedelta(minutes=surge[1])).isoformat()},
        "lines": labels,
    }
    return b"".join(out), truth


def write(path: str | Path, n: int = 10_000, seed: int = 42, with_truth: bool = True) -> dict:
    """Write the log file (and path.truth.json beside it). Returns the truth dict."""
    data, truth = generate(n, seed)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)  # bytes, not text: the file contains deliberately invalid UTF-8
    if with_truth:
        path.with_suffix(".truth.json").write_text(json.dumps(truth), encoding="utf-8")
    return truth
