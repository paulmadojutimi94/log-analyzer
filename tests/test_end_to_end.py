import json

from log_analyzer.analyzer import Options, analyze
from log_analyzer.cli import main
from log_analyzer.generator import generate
from log_analyzer.report import clean, md, render_html, render_markdown, render_terminal


def test_generator_is_deterministic_and_makes_10k_events():
    data_a, truth_a = generate(seed=5)
    data_b, _ = generate(seed=5)
    assert data_a == data_b
    events = sum(len(label.get("entries", [1])) for label in truth_a["lines"] if label["kind"] in ("entry", "malformed"))
    assert events == 10_000
    assert len(truth_a["spikes"]) == 3


def test_cli_generate_then_analyze(tmp_path, capsys):
    log = tmp_path / "app.log"
    assert main(["generate", "-o", str(log), "--seed", "3"]) == 0
    out = tmp_path / "reports"
    assert main(["analyze", str(log), "-o", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "SPIKE" in printed and "Malformed:" in printed
    report = json.loads((out / "report.json").read_text())
    assert report["summary"]["entries"] > 9_500
    assert len(report["spikes"]) >= 3
    assert (out / "report.md").read_text().startswith("# Log report")
    assert "<svg" in (out / "report.html").read_text()
    quarantined = (out / "quarantine.jsonl").read_text().splitlines()
    assert len(quarantined) == report["summary"]["malformed_lines"]


def test_cli_missing_file_and_fail_on_spike(tmp_path):
    assert main(["analyze", str(tmp_path / "nope.log"), "-o", str(tmp_path)]) == 2
    log = tmp_path / "app.log"
    main(["generate", "-o", str(log)])
    assert main(["analyze", str(log), "-o", str(tmp_path / "r"), "--fail-on-spike"]) == 1


def test_hostile_messages_are_neutralised(tmp_path):
    log = tmp_path / "evil.log"
    evil = ["<script>alert(1)</script>", "[x](javascript:alert(1))", "\x1b]0;pwned\x07", "a | b", "rtl‮txt"]
    log.write_text("\n".join(f"2026-11-11T09:00:0{i}Z ERROR [api] {m}" for i, m in enumerate(evil)) + "\n")
    a = analyze(log)
    html, markdown, term = render_html(a), render_markdown(a), render_terminal(a)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "](javascript" not in markdown and "\\|" in markdown
    assert "\x1b" not in term and "‮" not in term


def test_clean_and_md_helpers():
    assert clean("a\x1bb") == "a\\x1bb"
    assert clean("x" * 10, limit=5) == "xxxx…"
    assert md("a|b*c") == "a\\|b\\*c"


def test_clock_skew_does_not_explode_the_timeline(tmp_path):
    log = tmp_path / "skew.log"
    log.write_text("2026-11-11T09:00:00Z ERROR [a] x\n9999-12-31T23:59:59Z ERROR [a] y\n")
    a = analyze(log)
    assert "outside this window" in render_markdown(a)
    assert a.options == Options()


def test_stdin_and_gzip(tmp_path, monkeypatch):
    import gzip
    import io
    import sys

    data = b"2026-11-11T09:00:00Z ERROR [a] boom\n"
    gz = tmp_path / "app.log.gz"
    gz.write_bytes(gzip.compress(data))
    assert analyze(gz).entries == 1
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))
    assert analyze("-").entries == 1
