from __future__ import annotations

import csv
import json
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd
import pytest

from adforensictool.correlator.chain_builder import build_chains
from adforensictool.exporters import csv_safe, infer_formats, output_paths, write_csv, write_json, write_timeline
from adforensictool.parser.evtx_parser import ParseStats, normalize_record
from adforensictool.rules.engine import DEFAULT_RULES_PATH, apply_rules, load_rules
from tests.fixtures.sample_events import failed_logon_xml, group_membership_change_xml, successful_logon_xml

HOSTILE = '=HYPERLINK("http://203.0.113.9/x","click")'


@pytest.fixture(scope="module")
def results():
    rules = load_rules(DEFAULT_RULES_PATH)
    xml = [failed_logon_xml(f"2026-06-08T02:{10 + i}:00Z", user="jsmith") for i in range(5)]
    xml.append(successful_logon_xml("2026-06-08T02:20:00Z", user="jsmith"))
    xml.append(group_membership_change_xml("2026-06-08T02:25:00Z", member="jsmith", group="Domain Admins"))
    xml += [failed_logon_xml(f"2026-06-08T04:{10 + i}:00Z", user=HOSTILE) for i in range(5)]
    flagged = apply_rules(pd.DataFrame([normalize_record(x) for x in xml]), rules)
    return flagged, build_chains(flagged)


@pytest.mark.parametrize(
    "output, formats, expected",
    [
        ("out/report.xlsx", ["xlsx"], {"xlsx": "out/report.xlsx"}),
        ("out/report.xlsx", ["xlsx", "json"], {"xlsx": "out/report.xlsx", "json": "out/report.json"}),
        ("report", ["csv", "timeline"], {"csv": "report.csv", "timeline": "report.timeline.csv"}),
        ("r.timeline.csv", ["json", "timeline"], {"json": "r.json", "timeline": "r.timeline.csv"}),
        ("case.v2.xlsx", ["json"], {"json": "case.v2.json"}),
    ],
)
def test_output_paths(output, formats, expected):
    assert output_paths(output, formats) == {k: Path(v) for k, v in expected.items()}


@pytest.mark.parametrize(
    "name, expected",
    [("a.xlsx", ["xlsx"]), ("a.JSON", ["json"]), ("a.csv", ["csv"]), ("a.timeline.csv", ["timeline"]), ("a.out", ["xlsx"])],
)
def test_infer_formats(name, expected):
    assert infer_formats(name) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("=1+1", "'=1+1"),
        ("+cmd", "'+cmd"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("\tx", "'\tx"),
        ("-2+3", "'-2+3"),
        ("-cmd|' /c calc'!A1", "'-cmd|' /c calc'!A1"),
        ("-", "-"),  # Windows' empty-field placeholder stays readable
        ("-12", "-12"),  # plain negative number
        ("-1.5", "-1.5"),
        ("jsmith", "jsmith"),
        (42, 42),
        ("", ""),
    ],
)
def test_csv_safe(value, expected):
    assert csv_safe(value) == expected


def test_json_contains_chains_findings_and_stats(tmp_path, results):
    flagged, chains = results
    stats = ParseStats(records_read=12, records_skipped=1)
    stats.note_record_id("a.evtx", "Security", "DC01", 10)
    stats.note_record_id("a.evtx", "Security", "DC01", 13)
    path = tmp_path / "r.json"
    write_json(path, flagged, chains, sources=["a.evtx"], parse_stats=stats, suppressed={"scanner": 3}, tz=ZoneInfo("Europe/Sofia"))

    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["timezone"] == "Europe/Sofia"
    assert doc["parse_stats"]["records_skipped"] == 1
    assert doc["parse_stats"]["record_id_gaps"] == [
        {"file": "a.evtx", "channel": "Security", "computer": "DC01", "first_record_id": 10, "last_record_id": 13, "missing": 2}
    ]
    assert doc["suppressed_by_allowlist"] == {"scanner": 3}
    (chain,) = doc["chains"]
    assert chain["start"] == "2026-06-08T05:10:00+03:00"
    assert chain["narrative"].startswith("2026-06-08 05:10-05:25 EEST:")
    assert [s["rule_id"] for s in chain["stages"]] == ["brute_force", "logon_after_brute_force", "privilege_escalation"]
    assert len(doc["findings"]) == len(flagged)
    first = doc["findings"][0]
    assert first["timestamp"] == "2026-06-08T05:10:00+03:00"
    assert first["chain_id"] == "chain-1"
    assert first["event_data"]["TargetUserName"] == "jsmith"
    hostile = [f for f in doc["findings"] if f["user"] == HOSTILE]
    assert len(hostile) == 5  # JSON keeps exact values; it is not a spreadsheet


def test_csv_escapes_hostile_values_and_uses_display_timezone(tmp_path, results):
    flagged, chains = results
    path = tmp_path / "r.csv"
    write_csv(path, flagged, chains, ZoneInfo("Europe/Sofia"))
    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # BOM so Excel reads UTF-8
    with path.open(encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == len(flagged)
    assert rows[0]["timestamp (Europe/Sofia)"] == "2026-06-08T05:10:00+03:00"
    assert rows[0]["chain_id"] == "chain-1"
    assert {r["user"] for r in rows} == {"jsmith", "'" + HOSTILE}
    assert not any(v.startswith("=") for r in rows for v in r.values())


def test_timeline_is_timesketch_shaped_and_utc(tmp_path, results):
    flagged, chains = results
    path = tmp_path / "r.timeline.csv"
    write_timeline(path, flagged, chains)
    with path.open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert list(rows[0])[:3] == ["message", "datetime", "timestamp_desc"]
    assert rows[0]["datetime"] == "2026-06-08T02:10:00+00:00"
    assert rows[0]["message"] == "[HIGH] Brute Force Login Attempts (event 4625) -- jsmith from 203.0.113.44"
    assert rows[0]["chain_id"] == "chain-1"
    assert not any(v.startswith("=") for r in rows for v in r.values())


def test_exports_with_no_findings(tmp_path):
    rules = load_rules(DEFAULT_RULES_PATH)
    flagged = apply_rules(pd.DataFrame([normalize_record(failed_logon_xml("2026-06-08T02:10:00Z"))]), rules)
    write_json(tmp_path / "e.json", flagged, [], sources=[], parse_stats=None, suppressed=None, tz=None)
    write_csv(tmp_path / "e.csv", flagged, [], None)
    write_timeline(tmp_path / "e.timeline.csv", flagged, [])
    assert json.loads((tmp_path / "e.json").read_text(encoding="utf-8"))["findings"] == []
    assert len((tmp_path / "e.csv").read_text(encoding="utf-8-sig").splitlines()) == 1  # header only
