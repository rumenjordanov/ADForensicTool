#!/usr/bin/env python3
"""
Generates examples/sample_report.xlsx from fully synthetic Security event
data -- no real .evtx file, no real infrastructure. Every user, hostname,
domain, and IP here is a standard fictional placeholder (contoso.local,
RFC 5737 documentation-range IPs) so the finished report can be committed
to the repo and previewed on GitHub without shipping any real forensic
evidence from anyone's actual environment.

Covers all 4 currently-implemented detections, including all 3 event IDs
the privilege_escalation rule watches (4728/4732/4756), so the sample
report shows the full breadth of what the tool currently detects.

Run: python examples/generate_sample_report.py
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

import pandas as pd

from adforensictool.excel_export.report import build_report
from adforensictool.parser.evtx_parser import normalize_record
from adforensictool.rules.engine import DEFAULT_RULES_PATH, apply_rules, load_rules
from tests.fixtures.sample_events import (
    audit_log_cleared_xml,
    failed_logon_xml,
    group_membership_change_xml,
    kerberoasting_xml,
    successful_logon_xml,
)

OUTPUT_PATH = Path(__file__).parent / "sample_report.xlsx"
RULES_PATH = DEFAULT_RULES_PATH


def build_sample_events() -> list[str]:
    events = []

    # Brute force + successful logon: jsmith
    events += [failed_logon_xml(f"2026-03-14T02:{10 + i}:00.000000Z", user="jsmith") for i in range(6)]
    events.append(successful_logon_xml("2026-03-14T02:17:00.000000Z", user="jsmith"))

    # Brute force + successful logon: jdoe (different burst size, different source IP)
    events += [
        failed_logon_xml(f"2026-03-14T03:{40 + i}:00.000000Z", user="jdoe", ip="203.0.113.77") for i in range(7)
    ]
    events.append(successful_logon_xml("2026-03-14T03:48:00.000000Z", user="jdoe", ip="203.0.113.77"))

    # Privilege escalation across all 3 event IDs the rule watches
    events.append(
        group_membership_change_xml(
            "2026-03-14T02:18:00.000000Z", member="jsmith", group="Domain Admins", event_id=4728
        )
    )
    events.append(
        group_membership_change_xml(
            "2026-03-14T03:49:00.000000Z", member="jdoe", group="Administrators", event_id=4732
        )
    )
    events.append(
        group_membership_change_xml(
            "2026-03-14T04:05:00.000000Z", member="asmith", group="Enterprise Admins", event_id=4756
        )
    )

    # Kerberoasting: two different service accounts
    events.append(kerberoasting_xml("2026-03-14T04:10:00.000000Z", user="svc_sql", service="MSSQLSvc/db01.contoso.local"))
    events.append(kerberoasting_xml("2026-03-14T04:11:00.000000Z", user="svc_web", service="HTTP/webapp01.contoso.local"))

    # Audit log cleared -- last, same order an attacker covering their
    # tracks would produce it in a real incident
    events.append(audit_log_cleared_xml("2026-03-14T05:00:00.000000Z"))

    return events


def main() -> None:
    xml_events = build_sample_events()
    df = pd.DataFrame([normalize_record(x) for x in xml_events])
    df.sort_values("timestamp", inplace=True, ignore_index=True)

    rules = load_rules(RULES_PATH)
    flagged = apply_rules(df, rules)

    build_report(
        df,
        flagged,
        rules,
        str(OUTPUT_PATH),
        source_file="security.evtx (synthetic sample data, see examples/generate_sample_report.py)",
        generated_at=datetime(2026, 3, 14, 5, 5, tzinfo=UTC),
    )
    print(f"Wrote {OUTPUT_PATH} ({len(flagged)} findings from {len(df)} synthetic events)")


if __name__ == "__main__":
    main()
