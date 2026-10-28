#!/usr/bin/env python3
"""
Generates examples/sample_report.xlsx (and sample_report.json) from fully
synthetic Security event data -- no real .evtx file, no real
infrastructure. Every user, hostname, domain, and IP here is a standard
fictional placeholder (contoso.local, RFC 5737 documentation-range IPs) so
the finished report can be committed to the repo and previewed on GitHub
without shipping any real forensic evidence from anyone's actual
environment.

The scenario is a small fictional intrusion that exercises the detections
and the correlation/narration pipeline:

  1. Brute force (NTLM + Kerberos) against jsmith -> successful logon ->
     jsmith added to Domain Admins -> Kerberoasting -> scheduled task ->
     Security log cleared
  2. Password spray from one address -> successful logon as mbrown ->
     mbrown creates svc_backup2 and adds it to Domain Admins -> DCSync ->
     audit policy weakened
  3. Pass-the-hash style logon by tlee -> PsExec service installed
  plus a few unrelated single findings and benign background noise.

Run: python examples/generate_sample_report.py
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

import pandas as pd

from adforensictool.correlator.chain_builder import build_chains
from adforensictool.excel_export.report import build_report
from adforensictool.exporters import write_json
from adforensictool.parser.evtx_parser import ParseStats, normalize_record
from adforensictool.rules.engine import DEFAULT_RULES_PATH, apply_rules, load_rules
from tests.fixtures.sample_events import (
    account_created_xml,
    account_lockout_xml,
    asrep_tgt_xml,
    audit_log_cleared_xml,
    audit_policy_changed_xml,
    directory_access_xml,
    dsrm_password_set_xml,
    failed_logon_xml,
    group_membership_change_xml,
    kerberoasting_xml,
    kerberos_preauth_failed_xml,
    new_credentials_logon_xml,
    scheduled_task_xml,
    service_installed_xml,
    successful_logon_xml,
)

OUTPUT_PATH = Path(__file__).parent / "sample_report.xlsx"
JSON_PATH = Path(__file__).parent / "sample_report.json"
RULES_PATH = DEFAULT_RULES_PATH
ATTACKER_IP = "203.0.113.44"
SPRAY_IP = "198.51.100.23"


def t(hhmm: str, second: int = 0) -> str:
    return f"2026-03-14T{hhmm}:{second:02d}.000000Z"


def build_sample_events() -> list[str]:
    events = []

    # -- Chain 1: jsmith ---------------------------------------------------------
    events += [failed_logon_xml(t(f"02:{10 + i:02d}"), user="jsmith", ip=ATTACKER_IP) for i in range(4)]
    events += [kerberos_preauth_failed_xml(t(f"02:{14 + i:02d}"), user="jsmith", ip=f"::ffff:{ATTACKER_IP}") for i in range(3)]
    events.append(successful_logon_xml(t("02:17"), user="jsmith", ip=ATTACKER_IP))
    events.append(group_membership_change_xml(t("02:18"), member="jsmith", group="Domain Admins", performed_by="jsmith"))
    events.append(kerberoasting_xml(t("02:20"), user="jsmith@CONTOSO.LOCAL", service="MSSQLSvc/db01.contoso.local"))
    events.append(kerberoasting_xml(t("02:21"), user="jsmith@CONTOSO.LOCAL", service="HTTP/webapp01.contoso.local"))
    events.append(scheduled_task_xml(t("02:25"), performed_by="jsmith", task="\\Microsoft\\Windows\\UpdateCheck"))
    events.append(audit_log_cleared_xml(t("02:40"), performed_by="jsmith"))

    # -- Chain 2: password spray -> mbrown -----------------------------------------
    sprayed = ["abaker", "bcole", "cdiaz", "devans", "efox", "fgray", "mbrown", "hhill", "iivers", "jjones"]
    events += [failed_logon_xml(t(f"03:{i:02d}"), user=u, ip=SPRAY_IP) for i, u in enumerate(sprayed)]
    events.append(account_lockout_xml(t("03:05"), user="efox"))
    events.append(successful_logon_xml(t("03:20"), user="mbrown", ip=SPRAY_IP))
    events.append(account_created_xml(t("03:25"), new_account="svc_backup2", performed_by="mbrown"))
    events.append(group_membership_change_xml(t("03:26"), member="svc_backup2", group="Domain Admins", performed_by="mbrown"))
    events.append(directory_access_xml(t("03:30"), performed_by="mbrown"))
    events.append(audit_policy_changed_xml(t("03:35"), changes="%%8448", performed_by="mbrown"))

    # -- Chain 3: tlee pass-the-hash -> PsExec service ------------------------------
    events.append(new_credentials_logon_xml(t("04:30"), user="tlee"))
    events.append(service_installed_xml(t("04:32"), performed_by="tlee", service="PSEXESVC"))

    # -- Unrelated single findings --------------------------------------------------
    events.append(asrep_tgt_xml(t("04:00"), user="svc_legacy", ip="::ffff:10.0.4.17"))
    events.append(dsrm_password_set_xml(t("05:00"), performed_by="administrator"))

    # -- Benign background noise (should not be flagged) ----------------------------
    for i, user in enumerate(["alice", "bob", "carol", "dave"]):
        events.append(successful_logon_xml(t(f"01:{10 + i:02d}"), user=user, ip=f"10.0.1.{20 + i}"))
    events.append(failed_logon_xml(t("01:30"), user="carol", ip="10.0.1.22"))  # one typo'd password
    events.append(kerberoasting_xml(t("01:40"), user="FILESRV01$@CONTOSO.LOCAL", service="krbtgt"))  # routine RC4 noise
    return events


def main() -> None:
    xml_events = build_sample_events()
    df = pd.DataFrame([normalize_record(x) for x in xml_events])
    df.sort_values("timestamp", inplace=True, ignore_index=True)

    rules = load_rules(RULES_PATH)
    flagged = apply_rules(df, rules)
    chains = build_chains(flagged)
    stats = ParseStats(records_read=len(xml_events), files=1)
    source = "security.evtx (synthetic sample data, see examples/generate_sample_report.py)"
    generated_at = datetime(2026, 3, 14, 6, 0, tzinfo=UTC)

    build_report(df, flagged, rules, str(OUTPUT_PATH), source_file=source, generated_at=generated_at, parse_stats=stats, chains=chains)
    write_json(JSON_PATH, flagged, chains, sources=[source], parse_stats=stats, suppressed=None, tz=None, generated_at=generated_at)
    print(f"Wrote {OUTPUT_PATH} and {JSON_PATH.name}: {len(flagged)} findings, {len(chains)} chain(s) from {len(df)} synthetic events")


if __name__ == "__main__":
    main()
