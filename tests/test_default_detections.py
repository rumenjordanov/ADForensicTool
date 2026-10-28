"""
One positive and at least one negative case for each detection in
rules/default_rules.yaml added beyond the original four (those live in
test_rules_engine.py).
"""
from __future__ import annotations

import pandas as pd
import pytest

from adforensictool.parser.evtx_parser import normalize_record
from adforensictool.rules.engine import DEFAULT_RULES_PATH, apply_rules, load_rules
from tests.fixtures.sample_events import (
    account_created_xml,
    account_lockout_xml,
    asrep_tgt_xml,
    audit_policy_changed_xml,
    directory_access_xml,
    dsrm_password_set_xml,
    failed_logon_xml,
    kerberos_preauth_failed_xml,
    make_event_xml,
    new_credentials_logon_xml,
    scheduled_task_xml,
    service_installed_xml,
    successful_logon_xml,
    system_service_installed_xml,
)


@pytest.fixture(scope="module")
def rules():
    return load_rules(DEFAULT_RULES_PATH)


def _hits(rules, xml_strings, rule_id):
    df = pd.DataFrame([normalize_record(x) for x in xml_strings])
    flagged = apply_rules(df, rules)
    return flagged[flagged["rule_id"] == rule_id]


def _ts(minute: int, hour: int = 2) -> str:
    return f"2026-06-08T{hour:02d}:{minute:02d}:00Z"


# -- password spraying ----------------------------------------------------------


def test_password_spray_mixed_ntlm_and_kerberos_from_one_ip(rules):
    """4771 logs the client as ::ffff:a.b.c.d and 4625 as a.b.c.d; both must
    count toward the same source address."""
    xml = [failed_logon_xml(_ts(i), user=f"user{i}", ip="198.51.100.7") for i in range(4)]
    xml += [kerberos_preauth_failed_xml(_ts(4 + i), user=f"user{4 + i}", ip="::ffff:198.51.100.7") for i in range(4)]
    hits = _hits(rules, xml, "password_spray")
    assert len(hits) == 8
    assert set(hits["source_ip"]) == {"198.51.100.7"}


def test_password_spray_below_distinct_threshold(rules):
    xml = [failed_logon_xml(_ts(i), user=f"user{i}", ip="198.51.100.7") for i in range(7)]
    assert _hits(rules, xml, "password_spray").empty


# -- logon after brute force / spray ---------------------------------------------


def test_logon_after_brute_force(rules):
    xml = [failed_logon_xml(_ts(i), user="jsmith") for i in range(5)]
    xml.append(successful_logon_xml(_ts(20), user="jsmith"))
    hits = _hits(rules, xml, "logon_after_brute_force")
    assert list(hits["user"]) == ["jsmith"]
    assert hits.iloc[0]["severity"] == "critical"


def test_logon_after_password_spray_for_one_sprayed_account(rules):
    xml = [failed_logon_xml(_ts(i), user=f"user{i}", ip="198.51.100.7") for i in range(8)]
    xml.append(successful_logon_xml(_ts(30), user="user3", ip="198.51.100.7"))
    assert list(_hits(rules, xml, "logon_after_brute_force")["user"]) == ["user3"]


def test_logon_after_brute_force_ignores_other_accounts_and_machine_accounts(rules):
    xml = [failed_logon_xml(_ts(i), user="jsmith") for i in range(5)]
    xml.append(successful_logon_xml(_ts(20), user="jdoe"))
    assert _hits(rules, xml, "logon_after_brute_force").empty


# -- pass the hash -----------------------------------------------------------------


def test_pass_the_hash_seclogo_logon(rules):
    assert len(_hits(rules, [new_credentials_logon_xml(_ts(0))], "pass_the_hash")) == 1


def test_pass_the_hash_ignores_normal_network_logon(rules):
    assert _hits(rules, [successful_logon_xml(_ts(0))], "pass_the_hash").empty


# -- AS-REP roasting -----------------------------------------------------------------


def test_asrep_roasting(rules):
    hits = _hits(rules, [asrep_tgt_xml(_ts(0))], "asrep_roasting")
    assert len(hits) == 1
    assert hits.iloc[0]["source_ip"] == "203.0.113.44"  # ::ffff: prefix normalized


def test_asrep_roasting_ignores_normal_preauth(rules):
    assert _hits(rules, [asrep_tgt_xml(_ts(0), preauth="2")], "asrep_roasting").empty


# -- DCSync --------------------------------------------------------------------------


def test_dcsync_by_user_account(rules):
    hits = _hits(rules, [directory_access_xml(_ts(0), performed_by="jsmith")], "dcsync")
    assert list(hits["user"]) == ["jsmith"]


def test_dcsync_ignores_domain_controller_and_unrelated_rights(rules):
    xml = [
        directory_access_xml(_ts(0), performed_by="DC02$"),
        directory_access_xml(_ts(1), performed_by="jsmith", guid="bf967a86-0de6-11d0-a285-00aa003049e2"),
    ]
    assert _hits(rules, xml, "dcsync").empty


# -- persistence ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "xml, rule_id",
    [
        (account_created_xml(_ts(0)), "account_created"),
        (scheduled_task_xml(_ts(0)), "scheduled_task_created"),
        (service_installed_xml(_ts(0)), "service_installed"),
        (system_service_installed_xml(_ts(0)), "service_installed"),
        (dsrm_password_set_xml(_ts(0)), "dsrm_password_set"),
        (account_lockout_xml(_ts(0)), "account_lockout"),
    ],
)
def test_always_flag_detections(rules, xml, rule_id):
    assert len(_hits(rules, [xml], rule_id)) == 1


@pytest.mark.parametrize(
    "persistence_xml",
    [
        service_installed_xml(_ts(40), performed_by="jsmith"),
        scheduled_task_xml(_ts(40), performed_by="jsmith"),
        account_created_xml(_ts(40), new_account="backdoor", performed_by="jsmith"),
    ],
)
def test_persistence_after_suspicious_logon(rules, persistence_xml):
    xml = [failed_logon_xml(_ts(i), user="jsmith") for i in range(5)]
    xml.append(successful_logon_xml(_ts(20), user="jsmith"))
    xml.append(persistence_xml)
    hits = _hits(rules, xml, "persistence_after_suspicious_logon")
    assert len(hits) == 1
    assert hits.iloc[0]["subject_user"] == "jsmith"


def test_persistence_after_pass_the_hash(rules):
    xml = [new_credentials_logon_xml(_ts(0)), scheduled_task_xml(_ts(5))]
    assert len(_hits(rules, xml, "persistence_after_suspicious_logon")) == 1


def test_persistence_by_someone_else_is_not_linked(rules):
    xml = [failed_logon_xml(_ts(i), user="jsmith") for i in range(5)]
    xml.append(successful_logon_xml(_ts(20), user="jsmith"))
    xml.append(service_installed_xml(_ts(40), performed_by="admin2"))
    assert _hits(rules, xml, "persistence_after_suspicious_logon").empty


# -- audit policy -------------------------------------------------------------------------


@pytest.mark.parametrize("changes", ["%%8448", "%%8450", "%%8448, %%8450"])
def test_audit_policy_weakened(rules, changes):
    assert len(_hits(rules, [audit_policy_changed_xml(_ts(0), changes=changes)], "audit_policy_changed")) == 1


@pytest.mark.parametrize("changes", ["%%8449", "%%8451"])  # success / failure ADDED: routine GPO refresh
def test_audit_policy_additions_ignored(rules, changes):
    assert _hits(rules, [audit_policy_changed_xml(_ts(0), changes=changes)], "audit_policy_changed").empty


def test_same_event_ids_from_other_logs_do_not_fire(rules):
    """Regression test: Event IDs are only unique per provider. A real
    Application.evtx from a test machine contained Microsoft-Windows-
    EventSystem events with ID 4625; given directory input, any app's event
    1102 would have been reported as "Security audit log cleared"."""
    app = {"channel": "Application", "provider": "Microsoft-Windows-EventSystem"}
    xml = [make_event_xml(4625, _ts(i), data={"TargetUserName": "jsmith"}, **app) for i in range(6)]
    xml.append(make_event_xml(1102, _ts(10), data={"SubjectUserName": "x"}, **app))
    xml.append(make_event_xml(7045, _ts(11), data={"ServiceName": "x"}, **app))  # 7045 only counts from System
    df = pd.DataFrame([normalize_record(x) for x in xml])
    assert apply_rules(df, rules).empty


def test_every_default_rule_mitre_technique_has_a_name(rules):
    from adforensictool.excel_export.report import MITRE_NAMES

    assert {r.mitre_technique for r in rules} <= set(MITRE_NAMES)
