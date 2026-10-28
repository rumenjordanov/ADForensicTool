from __future__ import annotations

from zoneinfo import ZoneInfo

import pandas as pd
import pytest

from adforensictool.correlator.chain_builder import build_chains
from adforensictool.narrator.narrate import PHRASES, chain_headline, narrate_chain, narrate_stages
from adforensictool.parser.evtx_parser import normalize_record
from adforensictool.rules.engine import DEFAULT_RULES_PATH, apply_rules, load_rules, parse_rules
from tests.fixtures.sample_events import (
    account_created_xml,
    audit_log_cleared_xml,
    failed_logon_xml,
    group_membership_change_xml,
    kerberoasting_xml,
    service_installed_xml,
    successful_logon_xml,
)


@pytest.fixture(scope="module")
def rules():
    return load_rules(DEFAULT_RULES_PATH)


def _ts(minute: int, hour: int = 2, day: int = 8) -> str:
    return f"2026-06-{day:02d}T{hour + minute // 60:02d}:{minute % 60:02d}:00Z"


def _only_chain(rules, xml):
    df = pd.DataFrame([normalize_record(x) for x in xml])
    (chain,) = build_chains(apply_rules(df, rules))
    return chain


def _intrusion(spacing: int = 2):
    """Brute force from 02:14, logon at 02:52, Domain Admins at 02:53. The
    default brute_force window is 10 min, so the default spacing keeps the
    5 failures inside it; the spec-example test widens both."""
    xml = [failed_logon_xml(_ts(14 + i * spacing), user="jsmith") for i in range(5)]
    if spacing * 4 < 10:
        xml = [failed_logon_xml(_ts(42 + i * spacing), user="jsmith") for i in range(5)]  # 02:42 .. 02:50
    xml.append(successful_logon_xml(_ts(52), user="jsmith"))
    xml.append(group_membership_change_xml(_ts(53), member="jsmith", group="Domain Admins", performed_by="administrator"))
    return xml


def test_spec_example_sentence():
    """The target sentence from the project spec, with brute force over a
    longer window so the 5 attempts spread across 02:14-02:50."""
    rules = parse_rules(
        {
            "rules": [
                {"id": "brute_force", "name": "BF", "severity": "high", "mitre_technique": "T1110", "type": "threshold",
                 "event_ids": [4625], "group_by": "user", "window_minutes": 60, "min_count": 5},
                {"id": "logon_after_brute_force", "name": "L", "severity": "critical", "mitre_technique": "T1078",
                 "type": "followed_by", "event_ids": [4624], "after": "brute_force", "within_minutes": 60},
                {"id": "privilege_escalation", "name": "PE", "severity": "critical", "mitre_technique": "T1098",
                 "type": "always_flag", "event_ids": [4728]},
            ]
        }
    )  # fmt: skip
    chain = _only_chain(rules, _intrusion(spacing=9))  # 02:14 .. 02:50
    assert narrate_chain(chain) == (
        "2026-06-08 02:14-02:53 UTC: 5 failed logons against jsmith from 203.0.113.44 (02:14-02:50), "
        "followed by a successful logon as jsmith from 203.0.113.44 at 02:52 and "
        "jsmith added to Domain Admins by administrator at 02:53."
    )


def test_persistence_event_described_once_under_its_most_specific_rule(rules):
    xml = [failed_logon_xml(_ts(i), user="jsmith") for i in range(5)]
    xml.append(successful_logon_xml(_ts(10), user="jsmith"))
    xml.append(service_installed_xml(_ts(20), performed_by="jsmith", service="PSEXESVC"))
    chain = _only_chain(rules, xml)
    assert {"service_installed", "persistence_after_suspicious_logon"} <= {s.rule_id for s in chain.stages}
    phrases = narrate_stages(chain)
    assert sum("PSEXESVC" in p for p in phrases) == 1
    assert len(phrases) == 3


def test_event_flagged_by_two_equal_rules_is_narrated_once(rules):
    """Regression test: with an imported Sigma rule flagging the same ticket
    request as the built-in kerberoasting rule (same severity), the
    narrative described the one request twice."""
    sigma_like = parse_rules(
        {"rules": [{"id": "sigma_rc4", "name": "RC4 Ticket (Sigma)", "severity": "high", "mitre_technique": "T1558.003",
                    "type": "always_flag", "event_ids": [4769]}]}
    )[0]  # fmt: skip
    xml = [kerberoasting_xml(_ts(0), user="jsmith"), group_membership_change_xml(_ts(5), member="jsmith")]
    df = pd.DataFrame([normalize_record(x) for x in xml])
    for ordered in ([*rules, sigma_like], [sigma_like, *rules]):  # independent of rule order
        (chain,) = build_chains(apply_rules(df, ordered))
        phrases = narrate_stages(chain)
        assert len(phrases) == 2
        assert "(Kerberoasting)" in phrases[0]  # the built-in rule's dedicated phrase wins


def test_repeated_stages_of_one_rule_merge_into_one_phrase(rules):
    xml = [kerberoasting_xml(_ts(i), user="jsmith", service=f"MSSQLSvc/db0{i}") for i in range(3)]
    xml.append(group_membership_change_xml(_ts(10), member="jsmith"))
    chain = _only_chain(rules, xml)
    phrases = narrate_stages(chain)
    assert phrases[0] == (
        "3 RC4 service tickets for MSSQLSvc/db00, MSSQLSvc/db01 and MSSQLSvc/db02 requested by jsmith (Kerberoasting) (02:00-02:02)"
    )
    assert len(phrases) == 2


def test_new_account_and_log_cleared_phrases(rules):
    xml = [
        account_created_xml(_ts(0), new_account="backdoor", performed_by="jsmith"),
        group_membership_change_xml(_ts(1), member="backdoor", group="Domain Admins", performed_by="jsmith"),
        audit_log_cleared_xml(_ts(5), performed_by="jsmith"),
    ]
    text = narrate_chain(_only_chain(rules, xml))
    assert ": New account backdoor created by jsmith at 02:00," in text  # sentence start is capitalized
    assert "backdoor added to Domain Admins by jsmith at 02:01" in text
    assert "the Security event log cleared by jsmith at 02:05" in text


def test_unknown_rule_gets_generic_phrase():
    rules = parse_rules(
        {
            "rules": [
                {"id": "custom_a", "name": "Custom Thing", "severity": "low", "mitre_technique": "T0", "type": "always_flag", "event_ids": [4625]},
                {"id": "custom_b", "name": "Other Thing", "severity": "low", "mitre_technique": "T0", "type": "always_flag", "event_ids": [4624]},
            ]
        }
    )  # fmt: skip
    xml = [failed_logon_xml(_ts(0), user="jsmith"), successful_logon_xml(_ts(1), user="jsmith")]
    phrases = narrate_stages(_only_chain(rules, xml))
    assert phrases == ["Custom Thing (1 event) involving jsmith at 02:00", "Other Thing (1 event) involving jsmith at 02:01"]


def test_timezone_conversion(rules):
    chain = _only_chain(rules, _intrusion())
    text = narrate_chain(chain, tz=ZoneInfo("Europe/Sofia"))  # UTC+3 in June
    assert text.startswith("2026-06-08 05:42-05:53 EEST:")
    assert "at 05:53" in text


def test_multi_day_chain_shows_dates(rules):
    xml = [kerberoasting_xml(_ts(50, hour=23, day=8), user="jsmith"), group_membership_change_xml(_ts(20, hour=0, day=9), member="jsmith")]
    text = narrate_chain(_only_chain(rules, xml))
    assert text.startswith("2026-06-08 23:50 to 2026-06-09 00:20 UTC:")
    assert "at 06-09 00:20" in text


def test_many_names_are_summarized(rules):
    xml = [failed_logon_xml(_ts(i), user=f"user{i}", ip="198.51.100.7") for i in range(10)]
    xml.append(successful_logon_xml(_ts(20), user="user3"))
    phrases = narrate_stages(_only_chain(rules, xml))
    assert phrases[0].startswith("password spraying from 198.51.100.7: 10 failed logons against 10 different accounts")


def test_headline(rules):
    chain = _only_chain(rules, _intrusion())
    assert chain_headline(chain) == "Credential Access → Initial Access → Privilege Escalation (jsmith)"


def test_every_default_rule_has_a_phrase(rules):
    assert {r.id for r in rules} <= set(PHRASES)
