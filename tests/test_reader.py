import gzip
import io

from log_analyzer.reader import iter_lines, iter_lines_text_mode, open_log


def lines(data: bytes, limit=8192):
    return list(iter_lines(io.BytesIO(data), limit))


def test_splits_on_newline_and_strips_crlf():
    got = lines(b"a\r\nb\nc")
    assert [r.data for r in got] == [b"a", b"b", b"c"]
    assert [r.line_no for r in got] == [1, 2, 3]


def test_lone_carriage_return_does_not_start_a_new_line():
    # The log-forging defence: "\r" stays inside the line in binary mode...
    assert [r.data for r in lines(b"user bob\rFAKE LINE\n")] == [b"user bob\rFAKE LINE"]
    # ...while text mode (universal newlines) would split it into two lines.
    assert len(list(iter_lines_text_mode(io.BytesIO(b"user bob\rFAKE LINE\n")))) == 2


def test_long_lines_are_cut_and_drained_without_losing_the_next_line():
    data = b"x" * 50_000 + b"\nnext\n"
    first, second = lines(data, limit=100)
    assert first.too_long and len(first.data) == 100 and first.original_length == 50_001
    assert second.data == b"next" and second.line_no == 2


def test_line_exactly_at_the_limit_is_fine():
    [r] = lines(b"x" * 100 + b"\n", limit=100)
    assert not r.too_long and r.data == b"x" * 100


def test_gzip_is_detected_by_magic_bytes(tmp_path):
    path = tmp_path / "rotated.log.1"  # no .gz in the name on purpose
    path.write_bytes(gzip.compress(b"one\ntwo\n"))
    with open_log(path) as fh:
        assert [r.data for r in iter_lines(fh)] == [b"one", b"two"]


def test_empty_file(tmp_path):
    path = tmp_path / "empty.log"
    path.write_bytes(b"")
    with open_log(path) as fh:
        assert list(iter_lines(fh)) == []
