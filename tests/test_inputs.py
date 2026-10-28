"""
Input handling: finding files, multi-file parsing + de-duplication, the
Event-ID prefilter, EventRecordID gap detection, backend selection, and
recovery from corrupted records.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from adforensictool.parser import evtx_parser
from adforensictool.parser.evtx_parser import ParseStats, find_evtx_files, parse_evtx, parse_evtx_files, resolve_backend
from tests.fixtures.sample_events import failed_logon_xml, kerberoasting_xml, successful_logon_xml

FIXTURES = Path(__file__).parent / "fixtures"


def _with_record_id(xml: str, record_id: int, computer: str = "DC01.contoso.local") -> str:
    xml = xml.replace("<EventRecordID>1</EventRecordID>", f"<EventRecordID>{record_id}</EventRecordID>")
    return xml.replace("<Computer>DC01.contoso.local</Computer>", f"<Computer>{computer}</Computer>")


@pytest.fixture
def fake_files(monkeypatch):
    """Map file paths to lists of record XML (or ints = lost records)."""
    contents: dict[str, list] = {}
    monkeypatch.setattr(evtx_parser, "_iter_record_xml", lambda path, backend="python": iter(contents[path]))
    return contents


# -- finding files -------------------------------------------------------------------


def test_find_evtx_files_mixes_files_and_recursive_dirs(tmp_path):
    (tmp_path / "dc1").mkdir()
    (tmp_path / "dc1" / "nested").mkdir()
    a = tmp_path / "dc1" / "Security.evtx"
    b = tmp_path / "dc1" / "nested" / "System.EVTX"  # suffix match is case-insensitive
    c = tmp_path / "loose.evtx"
    for p in (a, b, c):
        p.write_bytes(b"")
    (tmp_path / "dc1" / "notes.txt").write_text("x")

    found = find_evtx_files([str(tmp_path / "dc1"), str(c), str(a)])  # `a` given twice
    assert found == [b, a, c]  # "dc1/nested/..." < "dc1/security.evtx" (casefolded), then explicit files


def test_find_evtx_files_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError, match="input not found"):
        find_evtx_files([str(tmp_path / "nope.evtx")])


# -- multi-file parsing ----------------------------------------------------------------


def test_overlapping_exports_are_deduplicated(fake_files):
    shared = [_with_record_id(failed_logon_xml(f"2026-06-08T02:1{i}:00Z"), 100 + i) for i in range(3)]
    fake_files["a.evtx"] = shared + [_with_record_id(failed_logon_xml("2026-06-08T02:20:00Z"), 103)]
    fake_files["b.evtx"] = shared + [_with_record_id(failed_logon_xml("2026-06-08T02:21:00Z"), 104)]
    # same record number on ANOTHER DC is a different record
    fake_files["c.evtx"] = [_with_record_id(failed_logon_xml("2026-06-08T02:22:00Z"), 100, computer="DC02.contoso.local")]

    stats = ParseStats()
    df = parse_evtx_files([Path("a.evtx"), Path("b.evtx"), Path("c.evtx")], stats=stats)

    assert len(df) == 6
    assert stats.records_duplicate == 3
    assert stats.files == 3
    assert list(df["source_file"]) == ["a.evtx", "a.evtx", "a.evtx", "a.evtx", "b.evtx", "c.evtx"]
    assert df["timestamp"].is_monotonic_increasing


def test_multi_file_with_no_events(fake_files):
    fake_files["a.evtx"] = []
    df = parse_evtx_files([Path("a.evtx")])
    assert df.empty
    assert "source_file" in df.columns


# -- prefilter -----------------------------------------------------------------------------


def test_prefilter_skips_irrelevant_event_ids_but_tracks_their_record_ids(fake_files):
    fake_files["a.evtx"] = [
        _with_record_id(failed_logon_xml("2026-06-08T02:10:00Z"), 1),
        _with_record_id(successful_logon_xml("2026-06-08T02:11:00Z"), 2),
        _with_record_id(kerberoasting_xml("2026-06-08T02:12:00Z"), 3),
    ]
    stats = ParseStats()
    df = parse_evtx("a.evtx", stats=stats, event_ids={4625})
    assert list(df["event_id"]) == [4625]
    assert stats.records_filtered == 2
    assert stats.records_read == 3
    assert stats.record_id_gaps() == []  # filtered records are not "missing"


# -- EventRecordID gaps ------------------------------------------------------------------------


def test_record_id_gaps_are_reported_per_log(fake_files):
    fake_files["a.evtx"] = [_with_record_id(failed_logon_xml(f"2026-06-08T02:1{i}:00Z"), rid) for i, rid in enumerate([10, 11, 12, 15, 16])]
    stats = ParseStats()
    parse_evtx("a.evtx", stats=stats)
    assert stats.record_id_gaps() == [("a.evtx", "Security", "DC01.contoso.local", 10, 16, 2)]


# -- member display names ---------------------------------------------------------------------


def test_group_change_member_display_name_resolved_via_sid(fake_files):
    """Regression test from a real lab DC: group changes name the member by
    DN ("CN=John Smith,..."), so the report said "John Smith added to Domain
    Admins" while every other event said "jsmith"."""
    from tests.fixtures.sample_events import account_created_xml, make_event_xml, sid_for

    fake_files["a.evtx"] = [
        account_created_xml("2026-06-08T02:00:00Z", new_account="jsmith", performed_by="Administrator"),
        make_event_xml(
            4728,
            "2026-06-08T02:05:00Z",
            data={"MemberName": "CN=John Smith,CN=Users,DC=contoso,DC=local", "MemberSid": sid_for("jsmith"),
                  "TargetUserName": "Domain Admins", "SubjectUserName": "Administrator"},
        ),  # fmt: skip
        make_event_xml(
            4728,
            "2026-06-08T02:06:00Z",
            data={"MemberName": "CN=Unknown Person,DC=contoso,DC=local", "MemberSid": "S-1-5-21-9-9-9-9999",
                  "TargetUserName": "Domain Admins"},
        ),  # fmt: skip
    ]
    df = parse_evtx_files([Path("a.evtx")])
    changes = df[df["event_id"] == 4728]
    assert list(changes["user"]) == ["jsmith", "Unknown Person"]  # unresolvable SID keeps the CN
    assert "John Smith" in changes.iloc[0]["event_data"]["MemberName"]


# -- lost / corrupt records -------------------------------------------------------------------


def test_lost_records_from_the_reader_count_as_skipped(fake_files):
    fake_files["a.evtx"] = [failed_logon_xml("2026-06-08T02:10:00Z"), 5, "<Event><broken", failed_logon_xml("2026-06-08T02:11:00Z")]
    stats = ParseStats()
    df = parse_evtx("a.evtx", stats=stats)
    assert len(df) == 2
    assert stats.records_skipped == 6
    assert stats.records_read == 8


class _FakeRecord:
    def __init__(self, xml):
        self._xml = xml

    def xml(self):
        if isinstance(self._xml, Exception):
            raise self._xml
        return self._xml


class _FakeChunk:
    def __init__(self, first, last, items):
        self._first, self._last, self._items = first, last, items

    def log_first_record_number(self):
        return self._first

    def log_last_record_number(self):
        return self._last

    def records(self):
        for item in self._items:
            if item == "BREAK":
                raise ValueError("record chain broken")
            yield _FakeRecord(item)


def test_python_backend_survives_corruption_and_counts_exact_losses(monkeypatch):
    """Regression test: a corrupt record used to raise out of python-evtx's
    generator and abort the whole parse (every valid event lost). Now: bad
    record skipped, broken chunk abandoned after its readable records, later
    chunks still read, losses counted exactly from the chunk headers."""
    import Evtx.Evtx

    good = failed_logon_xml("2026-06-08T02:10:00Z")
    chunks = [
        _FakeChunk(1, 3, [good, RuntimeError("bad template"), good]),  # 1 bad record
        _FakeChunk(4, 8, [good, "BREAK"]),  # 1 read, 4 unreachable
        _FakeChunk(9, 10, [good, good]),  # still read
        _FakeChunk(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, []),  # empty chunk: nothing lost
    ]

    class FakeEvtx:
        def __init__(self, path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def chunks(self):
            yield from chunks

    monkeypatch.setattr(Evtx.Evtx, "Evtx", FakeEvtx)
    stats = ParseStats()
    df = parse_evtx("whatever.evtx", stats=stats, backend="python")
    assert len(df) == 5
    assert stats.records_skipped == 5
    assert stats.records_read == 10


def test_real_empty_evtx_binary():
    """A genuine .evtx (an export that matched no events), read through
    python-evtx end to end: header + one empty chunk, no records lost."""
    stats = ParseStats()
    df = parse_evtx(str(FIXTURES / "empty.evtx"), stats=stats, backend="python")
    assert df.empty
    assert stats.records_read == 0
    assert stats.records_skipped == 0


# -- backend selection -----------------------------------------------------------------------------


def test_resolve_backend(monkeypatch):
    monkeypatch.setattr(evtx_parser, "rust_backend_available", lambda: False)
    assert resolve_backend("auto") == "python"
    assert resolve_backend("python") == "python"
    with pytest.raises(ValueError, match="pyevtx-rs"):
        resolve_backend("rust")
    with pytest.raises(ValueError, match="unknown backend"):
        resolve_backend("java")
    monkeypatch.setattr(evtx_parser, "rust_backend_available", lambda: True)
    assert resolve_backend("auto") == "rust"
