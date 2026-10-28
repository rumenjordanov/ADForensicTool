"""
Tests for the generic rule-engine features: validation, match/exclude
conditions, distinct-count thresholds, followed_by rules and output order.
Rules are built inline from dicts so each test shows exactly what it uses.
"""
from __future__ import annotations

import pandas as pd
import pytest

from adforensictool.parser.evtx_parser import normalize_record
from adforensictool.rules.engine import RuleError, actor_key, apply_rules, parse_rules
from tests.fixtures.sample_events import (
    failed_logon_xml,
    kerberoasting_xml,
    make_event_xml,
    successful_logon_xml,
)


def _df(xml_strings: list[str]) -> pd.DataFrame:
    return pd.DataFrame([normalize_record(x) for x in xml_strings])


def _rule(**overrides) -> dict:
    base = {"id": "r", "name": "R", "severity": "high", "mitre_technique": "T0000", "type": "always_flag", "event_ids": [4625]}
    base.update(overrides)
    return base


# -- validation -------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, message",
    [
        (_rule(severity="severe"), "severity must be one of"),
        (_rule(type="nope"), "unknown type"),
        (_rule(evnt_ids=[1]), "unknown key(s): evnt_ids"),
        ({"id": "x", "name": "X"}, "missing required key(s)"),
        (_rule(event_ids=[]), "event_ids"),
        (_rule(type="threshold", group_by="user"), "threshold rules require"),
        (_rule(type="threshold", group_by="user", window_minutes=5, min_count=2, distinct_field="user"), "must be given together"),
        (_rule(type="field_match"), "field_match rules require"),
        (_rule(match=[{"field": "user"}]), "exactly one of"),
        (_rule(match=[{"field": "user", "equals": "a", "contains": "b"}]), "exactly one of"),
        (_rule(match=[{"field": "user", "regex": "("}]), "invalid regex"),
        (_rule(type="followed_by", after="r2"), "followed_by rules require"),
        (_rule(type="followed_by", after="missing", within_minutes=5), "unknown rule 'missing'"),
        (_rule(channels=[]), "channels must be"),
    ],
)
def test_invalid_rules_raise_clear_errors(raw, message):
    with pytest.raises(RuleError, match=None) as exc_info:
        parse_rules({"rules": [raw]})
    assert message in str(exc_info.value)
    assert "'" in str(exc_info.value)  # names the offending rule/key


def test_duplicate_rule_ids_rejected():
    with pytest.raises(RuleError, match="Duplicate rule id 'r'"):
        parse_rules({"rules": [_rule(), _rule()]})


def test_circular_followed_by_rejected():
    a = _rule(id="a", type="followed_by", after="b", within_minutes=5)
    b = _rule(id="b", type="followed_by", after="a", within_minutes=5)
    with pytest.raises(RuleError, match="Circular"):
        parse_rules({"rules": [a, b]})


def test_followed_by_runs_after_its_dependency_regardless_of_file_order():
    later = _rule(id="later", type="followed_by", after="base", within_minutes=5, event_ids=[4624])
    base = _rule(id="base")
    ordered = parse_rules({"rules": [later, base]})
    assert [r.id for r in ordered] == ["base", "later"]


def test_empty_or_rule_less_file_is_fine():
    assert parse_rules(None) == []
    assert parse_rules({"rules": []}) == []


def test_severity_case_insensitive_and_scalar_event_id():
    (rule,) = parse_rules({"rules": [_rule(severity="HIGH", event_ids=4625)]})
    assert rule.severity == "high"
    assert rule.event_ids == [4625]


# -- conditions -------------------------------------------------------------


@pytest.mark.parametrize(
    "condition, should_fire",
    [
        ({"field": "user", "equals": "JSMITH"}, True),  # case-insensitive
        ({"field": "user", "equals": ["nobody", "jsmith"]}, True),  # any-of
        ({"field": "user", "contains": "smi"}, True),
        ({"field": "user", "startswith": "js"}, True),
        ({"field": "user", "endswith": "ith"}, True),
        ({"field": "user", "regex": "^j.+h$"}, True),
        ({"field": "Status", "equals": "0xC000006D"}, True),  # raw event_data field
        ({"field": "Status", "equals": "0xc000006a"}, False),
        ({"field": "NoSuchField", "equals": "x"}, False),  # missing field never matches
    ],
)
def test_match_conditions(condition, should_fire):
    rules = parse_rules({"rules": [_rule(match=[condition])]})
    flagged = apply_rules(_df([failed_logon_xml("2026-06-08T02:10:00Z", user="jsmith")]), rules)
    assert (len(flagged) == 1) is should_fire


def test_exclude_single_and_all_groups():
    xml = [
        failed_logon_xml("2026-06-08T02:10:00Z", user="jsmith", ip="10.0.0.1"),
        failed_logon_xml("2026-06-08T02:11:00Z", user="scanner", ip="10.0.0.2"),
        failed_logon_xml("2026-06-08T02:12:00Z", user="jdoe", ip="10.0.0.3"),
        failed_logon_xml("2026-06-08T02:13:00Z", user="jdoe", ip="10.0.0.4"),
    ]
    rules = parse_rules(
        {
            "rules": [
                _rule(
                    exclude=[
                        {"field": "user", "equals": "scanner"},
                        {"all": [{"field": "user", "equals": "jdoe"}, {"field": "source_ip", "equals": "10.0.0.3"}]},
                    ]
                )
            ]
        }
    )
    flagged = apply_rules(_df(xml), rules)
    assert sorted(flagged["source_ip"]) == ["10.0.0.1", "10.0.0.4"]


# -- kerberoasting noise (default rules) -------------------------------------


def test_kerberoasting_ignores_krbtgt_machine_accounts_and_failures():
    from adforensictool.rules.engine import DEFAULT_RULES_PATH, load_rules

    rules = load_rules(DEFAULT_RULES_PATH)
    xml = [
        kerberoasting_xml("2026-06-08T04:00:00Z", user="jsmith@CONTOSO.LOCAL", service="MSSQLSvc/db01"),
        kerberoasting_xml("2026-06-08T04:01:00Z", user="jsmith@CONTOSO.LOCAL", service="krbtgt"),
        kerberoasting_xml("2026-06-08T04:02:00Z", user="jsmith@CONTOSO.LOCAL", service="FILE01$"),
        kerberoasting_xml("2026-06-08T04:03:00Z", user="WKS01$@CONTOSO.LOCAL", service="MSSQLSvc/db01"),
        make_event_xml(
            4769,
            "2026-06-08T04:04:00Z",
            data={"TargetUserName": "jsmith", "ServiceName": "HTTP/web", "TicketEncryptionType": "0x17", "Status": "0x20"},
        ),
    ]
    flagged = apply_rules(_df(xml), rules)
    hits = flagged[flagged["rule_id"] == "kerberoasting"]
    assert list(hits["event_data"].map(lambda d: d["ServiceName"])) == ["MSSQLSvc/db01"]


# -- thresholds ---------------------------------------------------------------


def test_threshold_groups_account_name_variants_together():
    names = ["jsmith", "JSmith", "CONTOSO\\jsmith", "jsmith@contoso.local", "JSMITH"]
    xml = [failed_logon_xml(f"2026-06-08T02:1{i}:00Z", user=n) for i, n in enumerate(names)]
    rules = parse_rules({"rules": [_rule(type="threshold", group_by="user", window_minutes=10, min_count=5)]})
    assert len(apply_rules(_df(xml), rules)) == 5


def _spray_rule(**overrides):
    return _rule(
        id="spray",
        type="threshold",
        group_by="source_ip",
        window_minutes=30,
        distinct_field="user",
        min_distinct=5,
        **overrides,
    )


def test_distinct_threshold_detects_password_spraying():
    xml = [failed_logon_xml(f"2026-06-08T02:{10 + i}:00Z", user=f"user{i}", ip="198.51.100.7") for i in range(6)]
    flagged = apply_rules(_df(xml), parse_rules({"rules": [_spray_rule()]}))
    assert len(flagged) == 6
    assert flagged["cluster_id"].nunique() == 1


def test_distinct_threshold_ignores_many_attempts_on_one_user():
    xml = [failed_logon_xml(f"2026-06-08T02:{10 + i}:00Z", user="jsmith", ip="198.51.100.7") for i in range(10)]
    assert apply_rules(_df(xml), parse_rules({"rules": [_spray_rule()]})).empty


def test_distinct_threshold_respects_window():
    # 5 distinct users but spread over 2 hours: no single 30-minute window qualifies
    xml = [failed_logon_xml(f"2026-06-08T{10 + i // 2:02d}:{(i % 2) * 30:02d}:00Z", user=f"u{i}", ip="198.51.100.7") for i in range(5)]
    assert apply_rules(_df(xml), parse_rules({"rules": [_spray_rule()]})).empty


def test_distinct_threshold_can_combine_with_min_count():
    xml = [failed_logon_xml(f"2026-06-08T02:{10 + i}:00Z", user=f"user{i}", ip="198.51.100.7") for i in range(5)]
    rules = parse_rules({"rules": [_spray_rule(min_count=6)]})
    assert apply_rules(_df(xml), rules).empty  # 5 distinct, but only 5 events < min_count 6


# -- followed_by ---------------------------------------------------------------


def _brute_then_logon_rules(within=60):
    return parse_rules(
        {
            "rules": [
                _rule(id="bf", type="threshold", group_by="user", window_minutes=10, min_count=5),
                _rule(id="after_bf", type="followed_by", event_ids=[4624], after="bf", within_minutes=within),
            ]
        }
    )


def _brute_force(user="jsmith", minute=10):
    return [failed_logon_xml(f"2026-06-08T02:{minute + i:02d}:00Z", user=user) for i in range(5)]


def test_followed_by_flags_logon_after_brute_force():
    xml = _brute_force() + [successful_logon_xml("2026-06-08T02:30:00Z", user="JSMITH")]
    flagged = apply_rules(_df(xml), _brute_then_logon_rules())
    assert list(flagged[flagged["rule_id"] == "after_bf"]["event_id"]) == [4624]


@pytest.mark.parametrize(
    "logon_xml",
    [
        successful_logon_xml("2026-06-08T02:05:00Z", user="jsmith"),  # before the brute force
        successful_logon_xml("2026-06-08T04:00:00Z", user="jsmith"),  # outside the window
        successful_logon_xml("2026-06-08T02:30:00Z", user="someone_else"),  # different actor
    ],
)
def test_followed_by_does_not_flag_unrelated_logons(logon_xml):
    flagged = apply_rules(_df(_brute_force() + [logon_xml]), _brute_then_logon_rules())
    assert flagged[flagged["rule_id"] == "after_bf"].empty


def test_followed_by_without_prior_hits_flags_nothing():
    flagged = apply_rules(_df([successful_logon_xml("2026-06-08T02:30:00Z")]), _brute_then_logon_rules())
    assert flagged.empty


# -- misc -------------------------------------------------------------------------


def test_flagged_events_are_in_timestamp_order_across_rules():
    """Regression test: output used to be grouped by rule, not chronological."""
    xml = [
        failed_logon_xml("2026-06-08T03:00:00Z", user="b"),
        make_event_xml(4728, "2026-06-08T02:00:00Z", data={"MemberName": "CN=a", "TargetUserName": "Domain Admins"}),
    ]
    rules = parse_rules({"rules": [_rule(id="late"), _rule(id="early", event_ids=[4728])]})
    flagged = apply_rules(_df(xml), rules)
    assert list(flagged["rule_id"]) == ["early", "late"]


def test_apply_rules_on_empty_frame():
    from adforensictool.parser.evtx_parser import empty_events_frame

    flagged = apply_rules(empty_events_frame(), parse_rules({"rules": [_rule()]}))
    assert flagged.empty
    assert "rule_id" in flagged.columns


@pytest.mark.parametrize(
    "raw, expected",
    [("jsmith", "jsmith"), ("CONTOSO\\JSmith", "jsmith"), ("jsmith@CONTOSO.LOCAL", "jsmith"), ("", None), (None, None), ("  ", None)],
)
def test_actor_key(raw, expected):
    assert actor_key(raw) == expected


def test_events_without_timestamp_never_join_a_threshold_cluster():
    """Regression test: NaT comparisons are always False, so a timestamp-less
    event sorted to the end of a group was swept into the open cluster."""
    xml = _brute_force()
    xml.append(make_event_xml(4625, "", data={"TargetUserName": "jsmith"}).replace(' SystemTime=""', ""))
    df = _df(xml)
    assert df["timestamp"].isna().sum() == 1
    rules = parse_rules({"rules": [_rule(type="threshold", group_by="user", window_minutes=10, min_count=5)]})
    flagged = apply_rules(df, rules)
    assert len(flagged) == 5
    assert flagged["timestamp"].notna().all()
