from datetime import UTC, datetime

import pytest

from log_analyzer.models import Blank, Continuation, Entry, Malformed
from log_analyzer.parser import parse_lines, parse_text
from log_analyzer.reader import RawLine


def parse(*lines: str | bytes):
    raws = [RawLine(i, x if isinstance(x, bytes) else x.encode()) for i, x in enumerate(lines, 1)]
    return list(parse_lines(raws))


def test_parses_a_normal_line():
    [e] = parse("2026-11-11T09:15:02.123Z ERROR [payment-service] Payment declined for user 48213")
    assert isinstance(e, Entry)
    assert e.timestamp == datetime(2026, 11, 11, 9, 15, 2, 123000, tzinfo=UTC)
    assert (e.level, e.service, e.message) == ("ERROR", "payment-service", "Payment declined for user 48213")
    assert e.is_error and e.trusted


@pytest.mark.parametrize(
    "line, reason",
    [
        ("2026-11-11T09:1", "no_timestamp"),
        ("11/11/2026 09:15:02 ERROR [api] x", "no_timestamp"),
        ("2026-11-11T09:15:02.123Z", "missing_level"),
        ("2026-11-11T09:15:02.123Z EROR [api] x", "unknown_level"),
        ("2026-11-11T09:15:02.123Z INF0 [api] x", "unknown_level"),
        ("2026-11-11T09:15:02.123Z ERROR api x", "missing_service"),
        ("2026-13-11T09:15:02.123Z ERROR [api] x", "invalid_timestamp"),
        ("2026-02-30T09:15:02.123Z ERROR [api] x", "invalid_timestamp"),
    ],
)
def test_malformed_lines_get_a_reason(line, reason):
    [m] = parse(line)
    assert isinstance(m, Malformed) and m.reason == reason


def test_one_bad_line_does_not_stop_the_run():
    items = parse("2026-11-11T09:00:00Z INFO [a] one", "garbage!!", "2026-11-11T09:00:01Z INFO [a] two")
    assert [type(i) for i in items] == [Entry, Malformed, Entry]


def test_level_aliases_and_case():
    [a, b] = parse("2026-11-11T09:00:00Z warning [a] x", "2026-11-11T09:00:00Z error [a] x")
    assert a.level == "WARN" and b.level == "ERROR"


def test_offsets_are_converted_to_utc_and_naive_assumed_utc():
    [a, b] = parse("2026-11-11T10:00:00+01:00 INFO [a] x", "2026-11-11 09:00:00,500 INFO [a] y")
    assert a.timestamp == datetime(2026, 11, 11, 9, tzinfo=UTC)
    assert b.timestamp == datetime(2026, 11, 11, 9, 0, 0, 500000, tzinfo=UTC)


def test_stack_traces_attach_to_their_entry():
    items = parse(
        "2026-11-11T09:00:00Z ERROR [inv] boom",
        "Traceback (most recent call last):",
        '  File "w.py", line 3, in f',
        "KeyError: 'sku-1'",
        "2026-11-11T09:00:01Z INFO [inv] fine",
    )
    assert [type(i) for i in items] == [Entry, Continuation, Continuation, Continuation, Entry]
    assert len(items[0].continuation) == 3


def test_exception_tail_only_counts_inside_a_trace():
    [m] = parse("KeyError: 'sku-1'")
    assert isinstance(m, Malformed)


def test_continuation_with_no_entry_is_an_orphan():
    [m] = parse("    at com.shop.Foo.bar(Foo.java:10)")
    assert isinstance(m, Malformed) and m.reason == "orphan_continuation"


def test_blank_lines():
    assert isinstance(parse("   \t ")[0], Blank)


def test_glued_lines_are_split_and_second_half_untrusted():
    items = parse("2026-11-11T09:00:00Z INFO [a] GET / 2002026-11-11T09:00:01Z ERROR [b] boom")
    assert [e.message for e in items] == ["GET / 200", "boom"]
    assert items[0].trusted and not items[1].trusted and items[1].source == "glued"


def test_json_lines_are_recovered():
    [e] = parse('{"timestamp": "2026-11-11T09:00:00.000Z", "level": "error", "service": "auth", "msg": "bad token"}')
    assert isinstance(e, Entry) and e.source == "json" and e.level == "ERROR" and e.trusted


@pytest.mark.parametrize("line", ['{"level": "error", "msg": "x"}', "[1,2]", '{"timestamp": "now", "level": "error", "service": "a", "msg": "x"}'])
def test_json_without_what_we_need_is_malformed(line):
    [m] = parse(line)
    assert isinstance(m, Malformed)


def test_binary_garbage_and_salvageable_bad_bytes():
    garbage, salvage = parse(bytes(range(128, 200)), b"2026-11-11T09:00:00Z INFO [a] hello \xff")
    assert isinstance(garbage, Malformed) and garbage.reason == "binary_garbage"
    assert isinstance(salvage, Entry) and salvage.had_bad_bytes


def test_byte_order_mark_on_first_line_is_ignored():
    [e] = parse(b"\xef\xbb\xbf2026-11-11T09:00:00Z INFO [a] x")
    assert isinstance(e, Entry)


def test_too_long_lines_are_malformed():
    items = list(parse_lines([RawLine(1, b"2026-11-11T09:00:00Z INFO [a] " + b"x" * 100, too_long=True)]))
    assert items[0].reason == "line_too_long"


def test_parse_text_returns_list_or_malformed():
    assert isinstance(parse_text("nope", 1), Malformed)
    assert len(parse_text("2026-11-11T09:00:00Z INFO [a] x", 1)) == 1
