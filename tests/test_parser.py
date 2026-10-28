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

import xml.etree.ElementTree as ET

import pandas as pd
import pytest

from adforensictool.parser import evtx_parser
from adforensictool.parser.evtx_parser import normalize_record
from tests.fixtures.sample_events import (
    audit_log_cleared_xml,
    failed_logon_xml,
    group_membership_change_xml,
    kerberoasting_xml,
    make_event_xml,
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
    # "-" is Windows' placeholder for "no value", not a real process name
    assert record["process_name"] is None
    assert record["subject_user"] is None  # SubjectUserName "-" on a 4625
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
    # Regression test: TargetUserName on 4728 is the GROUP, not a user. The
    # generic "TargetUserName first" alias used to put "Domain Admins" in
    # `user`, which made the account that was actually escalated invisible
    # (and impossible to correlate with e.g. a brute force against it).
    assert record["user"] == "jsmith"
    assert record["user_sid"] == "S-1-5-21-1-2-3-1234"
    assert record["target_group"] == "Domain Admins"
    assert record["subject_user"] == "administrator"


@pytest.mark.parametrize("event_id", [4728, 4732, 4756])
def test_member_name_dn_with_escaped_comma(event_id):
    xml = make_event_xml(
        event_id,
        "2026-06-08T02:53:00.000000Z",
        data={
            "MemberName": r"CN=Smith\, John,OU=Staff,DC=contoso,DC=local",
            "MemberSid": "S-1-5-21-1-2-3-1500",
            "TargetUserName": "Administrators",
            "SubjectUserName": "administrator",
        },
    )
    record = normalize_record(xml)
    assert record["user"] == "Smith, John"
    assert record["target_group"] == "Administrators"


def test_member_name_placeholder_falls_back_to_none_user_but_keeps_sid():
    xml = make_event_xml(
        4732,
        "2026-06-08T02:53:00.000000Z",
        data={"MemberName": "-", "MemberSid": "S-1-5-21-1-2-3-1501", "TargetUserName": "Administrators"},
    )
    record = normalize_record(xml)
    assert record["user"] is None
    assert record["user_sid"] == "S-1-5-21-1-2-3-1501"


def test_normalize_audit_log_cleared_has_minimal_fields():
    xml = audit_log_cleared_xml("2026-06-08T03:00:00.000000Z", performed_by="administrator")
    record = normalize_record(xml)

    assert record["event_id"] == 1102
    assert record["source_ip"] is None
    assert record["logon_type"] is None
    # Regression test: real 1102s carry their fields under
    # <UserData><LogFileCleared>, not <EventData>; reading only EventData
    # meant who cleared the log was silently lost.
    assert record["event_data"]["SubjectUserName"] == "administrator"
    assert record["user"] == "administrator"
    assert record["subject_user"] == "administrator"


def test_normalize_kerberoasting_ticket_encryption_type():
    xml = kerberoasting_xml("2026-06-08T04:00:00.000000Z", user="svc_sql")
    record = normalize_record(xml)

    assert record["event_id"] == 4769
    assert record["event_data"]["TicketEncryptionType"] == "0x17"


def test_normalize_record_raises_on_malformed_xml():
    with pytest.raises(ET.ParseError):
        normalize_record("<Event><System>")


def test_parse_evtx_sorts_by_timestamp_and_skips_bad_records(monkeypatch):
    xml_records = [
        failed_logon_xml("2026-06-08T02:20:00.000000Z"),
        "<not-valid-xml",
        failed_logon_xml("2026-06-08T02:14:00.000000Z"),
    ]
    monkeypatch.setattr(evtx_parser, "_iter_record_xml", lambda path: iter(xml_records))

    stats = evtx_parser.ParseStats()
    df = evtx_parser.parse_evtx("unused-path.evtx", stats=stats)

    assert len(df) == 2
    assert stats.records_read == 3
    assert stats.records_skipped == 1
    assert list(df["timestamp"]) == sorted(df["timestamp"])
    assert df.iloc[0]["timestamp"] < df.iloc[1]["timestamp"]


def test_parse_evtx_empty_returns_empty_dataframe_with_expected_columns(monkeypatch):
    monkeypatch.setattr(evtx_parser, "_iter_record_xml", lambda path: iter([]))

    df = evtx_parser.parse_evtx("unused-path.evtx")

    assert df.empty
    for col in evtx_parser.REQUIRED_COLUMNS:
        assert col in df.columns
