"""
End-to-end-ish tests for the rules engine: build a normalized DataFrame
straight from synthetic event XML (bypassing parse_evtx/python-evtx
entirely) and confirm each of the 3 fully-implemented default rules fires
as expected.
"""
from __future__ import annotations

import pandas as pd
import pytest

from parser.evtx_parser import normalize_record
from rules.engine import apply_rules, load_rules
from tests.fixtures.sample_events import (
    audit_log_cleared_xml,
    failed_logon_xml,
    group_membership_change_xml,
    kerberos_preauth_failed_xml,
    kerberoasting_xml,
    make_event_xml,
)

RULES_PATH = "rules/default_rules.yaml"


def _df_from_xml(xml_strings: list[str]) -> pd.DataFrame:
    return pd.DataFrame([normalize_record(x) for x in xml_strings])


@pytest.fixture
def rules():
    return load_rules(RULES_PATH)


def test_brute_force_fires_on_five_failed_logons_in_window(rules):
    xml = [failed_logon_xml(f"2026-06-08T02:{10 + i}:00.000000Z", user="jsmith") for i in range(5)]
    df = _df_from_xml(xml)

    flagged = apply_rules(df, rules)

    brute_force_hits = flagged[flagged["rule_id"] == "brute_force"]
    assert len(brute_force_hits) == 5
    assert (brute_force_hits["severity"] == "high").all()


def test_brute_force_does_not_fire_below_threshold(rules):
    xml = [failed_logon_xml(f"2026-06-08T02:1{i}:00.000000Z", user="jsmith") for i in range(3)]
    df = _df_from_xml(xml)

    flagged = apply_rules(df, rules)

    assert flagged[flagged["rule_id"] == "brute_force"].empty


def test_brute_force_fires_on_kerberos_preauth_failures_alone(rules):
    """Regression test: Kerberos-based brute force (domain logon attempted
    against a hostname, not a bare IP) never generates 4625 at all -- it
    fails at Kerberos pre-authentication and only produces 4771. Confirmed
    against a real AD lab: hostname-targeted failed logons produced zero
    4625s until the attempts were retargeted at the DC's bare IP to force
    NTLM. Without 4771 in brute_force's event_ids, this whole attack path
    would be invisible to the tool.
    """
    xml = [kerberos_preauth_failed_xml(f"2026-06-08T02:{10 + i}:00.000000Z", user="jsmith") for i in range(5)]
    df = _df_from_xml(xml)

    flagged = apply_rules(df, rules)

    hits = flagged[flagged["rule_id"] == "brute_force"]
    assert len(hits) == 5
    assert (hits["severity"] == "high").all()


def test_brute_force_fires_on_mixed_ntlm_and_kerberos_failures(rules):
    """A real attacker's tooling can trip a mix of 4625 and 4771 depending
    on how each attempt was routed -- the threshold should count both
    event IDs toward the same per-user cluster rather than requiring 5+ of
    one specific type.
    """
    xml = [failed_logon_xml(f"2026-06-08T02:{10 + i}:00.000000Z", user="jsmith") for i in range(3)]
    xml += [kerberos_preauth_failed_xml(f"2026-06-08T02:{13 + i}:00.000000Z", user="jsmith") for i in range(2)]
    df = _df_from_xml(xml)

    flagged = apply_rules(df, rules)

    hits = flagged[flagged["rule_id"] == "brute_force"]
    assert len(hits) == 5
    assert set(hits["event_id"]) == {4625, 4771}


def test_privilege_escalation_always_flags(rules):
    xml = [group_membership_change_xml("2026-06-08T02:53:00.000000Z", member="jsmith", group="Domain Admins")]
    df = _df_from_xml(xml)

    flagged = apply_rules(df, rules)

    hits = flagged[flagged["rule_id"] == "privilege_escalation"]
    assert len(hits) == 1
    assert hits.iloc[0]["severity"] == "critical"
    assert hits.iloc[0]["mitre_technique"] == "T1098"


def test_audit_log_cleared_always_flags(rules):
    xml = [audit_log_cleared_xml("2026-06-08T03:00:00.000000Z")]
    df = _df_from_xml(xml)

    flagged = apply_rules(df, rules)

    hits = flagged[flagged["rule_id"] == "audit_log_cleared"]
    assert len(hits) == 1
    assert hits.iloc[0]["severity"] == "critical"


def test_kerberoasting_field_match(rules):
    xml = [kerberoasting_xml("2026-06-08T04:00:00.000000Z", user="svc_sql")]
    df = _df_from_xml(xml)

    flagged = apply_rules(df, rules)

    hits = flagged[flagged["rule_id"] == "kerberoasting"]
    assert len(hits) == 1


def test_kerberoasting_matches_zero_padded_hex_from_real_evtx(rules):
    """Regression test: real Security.evtx XML renders TicketEncryptionType
    as an 8-digit zero-padded hex string ("0x00000017"), not the short form
    ("0x17") used in rules/default_rules.yaml and Microsoft's own docs. This
    was caught by running the tool against a real AD lab capture -- the rule
    silently matched zero events until the engine started normalizing hex
    values instead of comparing raw strings.
    """
    xml = [
        make_event_xml(
            4769,
            "2026-06-08T04:00:00.000000Z",
            data={"TargetUserName": "svc_sql", "TicketEncryptionType": "0x00000017"},
        )
    ]
    df = _df_from_xml(xml)

    flagged = apply_rules(df, rules)

    assert len(flagged[flagged["rule_id"] == "kerberoasting"]) == 1


def test_no_rules_fire_on_benign_events(rules):
    xml = [failed_logon_xml("2026-06-08T02:10:00.000000Z", user="jsmith")]  # just 1, below threshold
    df = _df_from_xml(xml)

    flagged = apply_rules(df, rules)

    assert flagged.empty
