from collections import Counter
from datetime import UTC, datetime

import pytest

from log_analyzer.grouping import OVERFLOW, Grouper, fingerprint
from log_analyzer.models import Entry
from log_analyzer.spikes import detect_spikes


@pytest.mark.parametrize(
    "message, expected",
    [
        ("Database connection timeout after 5012ms (host=db-3.internal)", "Database connection timeout after <NUM>ms (host=db-<NUM>.internal)"),
        ("Disk usage at 93% on /dev/sda1", "Disk usage at <NUM>% on /dev/sda<NUM>"),
        ("Order 3f2b8c1e-9a4d-4b7e-8f00-1234567890ab stuck", "Order <UUID> stuck"),
        ("Rate limit for client 10.0.4.17", "Rate limit for client <IP>"),
        ("Email to li.wei42@example.ie bounced", "Email to <EMAIL> bounced"),
        ("session 9f86d081884c7d659a2feaa0c55ad015 bad", "session <HEX> bad"),
        ("too   much\tspace", "too much space"),
    ],
)
def test_fingerprint_masks_variable_parts(message, expected):
    assert fingerprint(message) == expected


def test_same_problem_same_fingerprint():
    assert fingerprint("timeout after 5012ms") == fingerprint("timeout after 30000ms")


def test_fingerprint_is_fast_on_hostile_input():
    import time

    t = time.perf_counter()
    fingerprint("a." * 32_000)
    assert time.perf_counter() - t < 0.05


def entry(msg: str, minute: int = 0, service="api") -> Entry:
    return Entry(1, datetime(2026, 11, 11, 9, minute, tzinfo=UTC), "ERROR", service, msg)


def test_grouper_counts_and_caps():
    g = Grouper(max_groups=2)
    for msg in ["a 1", "a 2", "b 1", "c 1", "d 1"]:
        g.add(entry(msg))
    counts = {k: v.count for k, v in g.groups.items()}
    assert counts == {"a <NUM>": 2, "b <NUM>": 1, OVERFLOW: 2}


def test_grouper_tracks_services_and_times():
    g = Grouper()
    g.add(entry("x 1", 5, "api"))
    g.add(entry("x 2", 1, "db"))
    [grp] = g.groups.values()
    assert grp.services == Counter({"api": 1, "db": 1})
    assert grp.first_seen.minute == 1 and grp.last_seen.minute == 5


def steady(minutes=60, total=28, errors=1):
    return Counter({m: total for m in range(minutes)}), Counter({m: errors for m in range(minutes)})


def test_detects_a_clear_spike():
    totals, errors = steady()
    errors[40] = 15
    [s] = detect_spikes(totals, errors)
    assert (s.start_minute, s.end_minute, s.peak_errors) == (40, 40, 15)


def test_quiet_log_has_no_spikes():
    assert detect_spikes(*steady()) == []


def test_traffic_surge_at_same_error_rate_is_not_a_spike():
    totals, errors = steady(errors=1)
    for m in range(30, 45):
        totals[m], errors[m] = 28 * 4, 4  # 4x busier, same 3.6% error rate
    assert detect_spikes(totals, errors) == []


def test_spike_minutes_merge_and_do_not_poison_the_baseline():
    totals, errors = steady()
    for m in (20, 21, 23):  # gap of one minute still merges
        errors[m] = 14
    errors[40] = 14  # a second spike shortly after is still caught
    spikes = detect_spikes(totals, errors)
    assert [(s.start_minute, s.end_minute) for s in spikes] == [(20, 23), (40, 40)]


def test_no_judgement_during_warm_up():
    totals, errors = steady()
    errors[3] = 50
    assert detect_spikes(totals, errors) == []
