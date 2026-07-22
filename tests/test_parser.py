"""
Unit tests for parser.evtx_parser.

normalize_record is tested directly against synthetic XML strings (see
tests/fixtures/sample_events.py) -- no real .evtx file or python-evtx
dependency needed for these.

parse_evtx is tested by monkeypatching its internal XML-record generator,
so the full parse -> normalize -> sort pipeline is covered without needing
a real .evtx binary either.
"""
from __future__ import annotations

import pandas as pd
import pytest

from parser import evtx_parser
from parser.evtx_parser import normalize_record
from tests.fixtures.sample_events import (
    audit_log_cleared_xml,
    failed_logon_xml,
    group_membership_change_xml,
    kerberoasting_xml,
    successful_logon_xml,
)


def test_normalize_failed_logon():
    xml = failed_logon_xml("2026-06-08T02:14:00.000000Z", user="jsmith", ip="203.0.113.44")
    record = normalize_record(xml)

    assert record["event_id"] == 4625
    assert record["user"] == "jsmith"
    assert record["source_ip"] == "203.0.113.44"
    assert record["target_host"] == "DC01.contoso.local"
    assert record["logon_type"] == "3"
    assert record["process_name"] == "-"
    assert "TargetUserName=jsmith" in record["raw_message"]
    assert record["event_data"]["Status"] == "0xc000006d"
    assert record["timestamp"] == pd.Timestamp("2026-06-08T02:14:00.000000Z")


def test_normalize_successful_logon():
    xml = successful_logon_xml("2026-06-08T02:52:00.000000Z", user="jsmith")
    record = normalize_record(xml)

    assert record["event_id"] == 4624
    assert record["user"] == "jsmith"


def test_normalize_group_membership_change_exposes_extra_fields():
    xml = group_membership_change_xml(
        "2026-06-08T02:53:00.000000Z", member="jsmith", group="Domain Admins", performed_by="administrator"
    )
    record = normalize_record(xml)

    assert record["event_id"] == 4728
    # TargetUserName on 4728 is the group name, not a logon target -- still
    # lands in `user` via the generic alias map. Group/member detail lives
    # in event_data for rule-specific logic to pick up.
    assert record["user"] == "Domain Admins"
    assert record["event_data"]["SubjectUserName"] == "administrator"
    assert "jsmith" in record["event_data"]["MemberName"]


def test_normalize_audit_log_cleared_has_minimal_fields():
    xml = audit_log_cleared_xml("2026-06-08T03:00:00.000000Z", performed_by="administrator")
    record = normalize_record(xml)

    assert record["event_id"] == 1102
    assert record["source_ip"] is None
    assert record["logon_type"] is None
    assert record["event_data"]["SubjectUserName"] == "administrator"


def test_normalize_kerberoasting_ticket_encryption_type():
    xml = kerberoasting_xml("2026-06-08T04:00:00.000000Z", user="svc_sql")
    record = normalize_record(xml)

    assert record["event_id"] == 4769
    assert record["event_data"]["TicketEncryptionType"] == "0x17"


def test_normalize_record_raises_on_malformed_xml():
    with pytest.raises(Exception):
        normalize_record("<Event><System>")


def test_parse_evtx_sorts_by_timestamp_and_skips_bad_records(monkeypatch):
    xml_records = [
        failed_logon_xml("2026-06-08T02:20:00.000000Z"),
        "<not-valid-xml",
        failed_logon_xml("2026-06-08T02:14:00.000000Z"),
    ]
    monkeypatch.setattr(evtx_parser, "_iter_record_xml", lambda path: iter(xml_records))

    df = evtx_parser.parse_evtx("unused-path.evtx")

    assert len(df) == 2
    assert list(df["timestamp"]) == sorted(df["timestamp"])
    assert df.iloc[0]["timestamp"] < df.iloc[1]["timestamp"]


def test_parse_evtx_empty_returns_empty_dataframe_with_expected_columns(monkeypatch):
    monkeypatch.setattr(evtx_parser, "_iter_record_xml", lambda path: iter([]))

    df = evtx_parser.parse_evtx("unused-path.evtx")

    assert df.empty
    for col in evtx_parser.REQUIRED_COLUMNS:
        assert col in df.columns
