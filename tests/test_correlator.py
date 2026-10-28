from __future__ import annotations

import pandas as pd
import pytest

from adforensictool.correlator.chain_builder import build_chains, tactic_for
from adforensictool.parser.evtx_parser import normalize_record
from adforensictool.rules.engine import DEFAULT_RULES_PATH, apply_rules, load_rules
from tests.fixtures.sample_events import (
    account_created_xml,
    account_lockout_xml,
    asrep_tgt_xml,
    audit_log_cleared_xml,
    failed_logon_xml,
    group_membership_change_xml,
    kerberoasting_xml,
    make_event_xml,
    scheduled_task_xml,
    service_installed_xml,
    successful_logon_xml,
)


@pytest.fixture(scope="module")
def rules():
    return load_rules(DEFAULT_RULES_PATH)


def _chains(rules, xml, **kwargs):
    df = pd.DataFrame([normalize_record(x) for x in xml])
    return build_chains(apply_rules(df, rules), **kwargs)


def _ts(minute: int, hour: int = 2) -> str:
    return f"2026-06-08T{hour + minute // 60:02d}:{minute % 60:02d}:00Z"


def _brute_force(user="jsmith", start=0, ip="203.0.113.44"):
    return [failed_logon_xml(_ts(start + i), user=user, ip=ip) for i in range(5)]


def test_classic_intrusion_is_one_chain_in_order(rules):
    xml = _brute_force()
    xml.append(successful_logon_xml(_ts(10), user="JSMITH"))
    xml.append(group_membership_change_xml(_ts(12), member="jsmith", group="Domain Admins", performed_by="jsmith"))
    xml.append(audit_log_cleared_xml(_ts(20), performed_by="CONTOSO\\jsmith"))

    (chain,) = _chains(rules, xml)
    assert [s.rule_id for s in chain.stages] == [
        "brute_force",
        "logon_after_brute_force",
        "privilege_escalation",
        "audit_log_cleared",
    ]
    assert chain.stages[0].event_count == 5  # the burst is ONE stage
    assert chain.severity == "critical"
    assert chain.tactics == ["Credential Access", "Initial Access", "Privilege Escalation", "Defense Evasion"]
    assert chain.start_time == pd.Timestamp(_ts(0))
    assert chain.end_time == pd.Timestamp(_ts(20))
    assert chain.event_count == 8
    assert chain.id == "chain-1"


def test_single_rule_activity_is_not_a_chain(rules):
    xml = _brute_force() + _brute_force(start=30)
    assert _chains(rules, xml) == []


def test_unrelated_accounts_stay_separate(rules):
    xml = _brute_force(user="jsmith") + [successful_logon_xml(_ts(10), user="jsmith")]
    xml += _brute_force(user="jdoe", start=100, ip="198.51.100.9") + [successful_logon_xml(_ts(110), user="jdoe", ip="198.51.100.9")]
    chains = _chains(rules, xml)
    assert len(chains) == 2
    assert {tuple(c.users) for c in chains} == {("jsmith",), ("jdoe",)}


def test_stages_too_far_apart_are_not_linked(rules):
    xml = [kerberoasting_xml(_ts(0), user="jsmith"), group_membership_change_xml(_ts(0, hour=6), member="jsmith")]
    assert _chains(rules, xml) == []
    assert len(_chains(rules, xml, window_minutes=300)) == 1


def test_links_are_transitive_beyond_the_window(rules):
    # each step 50 min after the previous: total span 100 min > 60 min window
    xml = [
        kerberoasting_xml(_ts(0), user="jsmith"),
        group_membership_change_xml(_ts(50), member="jsmith"),
        audit_log_cleared_xml(_ts(100), performed_by="jsmith"),
    ]
    (chain,) = _chains(rules, xml)
    assert len(chain.stages) == 3


def test_password_spray_links_to_the_account_that_then_logged_on(rules):
    xml = [failed_logon_xml(_ts(i), user=f"user{i}", ip="198.51.100.7") for i in range(8)]
    xml.append(successful_logon_xml(_ts(20), user="user3", ip="10.9.9.9"))
    (chain,) = _chains(rules, xml)
    assert [s.rule_id for s in chain.stages] == ["password_spray", "logon_after_brute_force"]


def test_key_accounts_put_the_compromised_account_ahead_of_sprayed_ones(rules):
    """Regression test: the spray chain's headline listed 'abaker, bcole,
    cdiaz and 8 more' instead of the account that was actually taken over."""
    xml = [failed_logon_xml(_ts(i), user=f"user{i}", ip="198.51.100.7") for i in range(8)]
    xml.append(successful_logon_xml(_ts(20), user="user3"))
    xml.append(account_created_xml(_ts(25), new_account="backdoor", performed_by="user3"))
    xml.append(group_membership_change_xml(_ts(26), member="backdoor", performed_by="user3"))
    (chain,) = _chains(rules, xml)
    assert chain.key_accounts == ["user3", "backdoor"]
    assert len(chain.users) == 9  # the full list is still available


def test_shared_source_ip_alone_does_not_link_different_accounts(rules):
    """Two unrelated single-account detections from the same address (a
    jump host, NAT) must not be glued together."""
    xml = [
        kerberoasting_xml(_ts(0), user="jsmith"),  # IpAddress 10.0.0.5
        asrep_tgt_xml(_ts(5), user="jdoe", ip="::ffff:10.0.0.5"),
    ]
    assert _chains(rules, xml) == []


def test_new_account_created_by_attacker_links_both_ways(rules):
    """jsmith logs on after a brute force, creates 'backdoor' and adds it
    to Domain Admins: subject_user links jsmith to the 4720, and the
    created account's name links the 4720 to the group change."""
    xml = _brute_force()
    xml.append(successful_logon_xml(_ts(10), user="jsmith"))
    xml.append(account_created_xml(_ts(15), new_account="backdoor", performed_by="jsmith"))
    xml.append(group_membership_change_xml(_ts(16), member="backdoor", group="Domain Admins", performed_by="jsmith"))
    (chain,) = _chains(rules, xml)
    assert {"brute_force", "logon_after_brute_force", "account_created", "privilege_escalation"} <= {s.rule_id for s in chain.stages}
    assert "backdoor" in chain.users


def test_machine_account_subject_does_not_link(rules):
    xml = [
        account_lockout_xml(_ts(0), user="jsmith"),  # SubjectUserName DC01$
        account_lockout_xml(_ts(1), user="jdoe"),
        scheduled_task_xml(_ts(2), performed_by="DC01$"),
    ]
    assert _chains(rules, xml) == []


def test_machine_account_as_the_events_account_does_not_link(rules):
    """Regression test: 4697/4698 take `user` from SubjectUserName, which is
    very often the DC's own machine account. Those routine events must not
    be chained together just because DC01$ did both."""
    xml = [
        scheduled_task_xml(_ts(0), performed_by="DC01$"),
        service_installed_xml(_ts(1), performed_by="DC01$"),
    ]
    assert _chains(rules, xml) == []


def test_chains_ordered_by_severity_then_time(rules):
    # medium-only chain first in time, critical chain later
    xml = [
        account_created_xml(_ts(0), new_account="tmp1", performed_by="alice"),
        scheduled_task_xml(_ts(1), performed_by="alice"),
    ]
    xml += _brute_force(user="jsmith", start=30) + [successful_logon_xml(_ts(40), user="jsmith")]
    chains = _chains(rules, xml)
    assert [c.severity for c in chains] == ["critical", "medium"]
    assert [c.id for c in chains] == ["chain-1", "chain-2"]


def test_events_without_timestamp_are_ignored(rules):
    xml = [
        kerberoasting_xml(_ts(0), user="jsmith"),
        make_event_xml(4728, "", data={"MemberName": "CN=jsmith", "TargetUserName": "Domain Admins"}).replace(' SystemTime=""', ""),
    ]
    assert _chains(rules, xml) == []


def test_empty_input():
    assert build_chains(pd.DataFrame()) == []


def test_chain_lists_each_account_once_preferring_plain_name(rules):
    """Regression test: the headline read 'jsmith and jsmith@CONTOSO.LOCAL'."""
    xml = [
        kerberoasting_xml(_ts(0), user="jsmith@CONTOSO.LOCAL"),
        group_membership_change_xml(_ts(5), member="jsmith"),
        audit_log_cleared_xml(_ts(6), performed_by="CONTOSO\\JSmith"),
    ]
    (chain,) = _chains(rules, xml)
    assert chain.users == ["jsmith"]


@pytest.mark.parametrize(
    "rule_id, technique, expected",
    [("brute_force", "T1110", "Credential Access"), ("custom", "T1543.003", "Persistence"), ("custom", "T9999", "Other")],
)
def test_tactic_for(rule_id, technique, expected):
    assert tactic_for(rule_id, technique) == expected
