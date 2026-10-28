"""
Smoke test for excel_export.report.build_report: confirms it runs end to
end (on both an empty and a populated flagged-events DataFrame), produces a
workbook with all 5 expected tabs, and that the branded-dashboard elements
(banner, charts, autofilter) that make it look like a polished product
actually show up rather than just checking sheet names. Does not assert on
exact colors/fonts -- that's better verified by opening the file manually.
"""
from __future__ import annotations

import zipfile
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pandas as pd
from openpyxl import load_workbook

from adforensictool.correlator.chain_builder import build_chains
from adforensictool.excel_export.report import DISPLAY_COLUMNS, build_report
from adforensictool.parser.evtx_parser import normalize_record
from adforensictool.rules.engine import DEFAULT_RULES_PATH, apply_rules, load_rules
from tests.fixtures.sample_events import (
    failed_logon_xml,
    group_membership_change_xml,
    kerberoasting_xml,
    successful_logon_xml,
)

EXPECTED_SHEETS = {
    "Executive Summary",
    "Attack Chains",
    "Detections by Rule",
    "Raw Flagged Events",
    "Account-Group Changes",
    "MITRE ATT&CK Coverage",
}


def test_build_report_with_findings(tmp_path):
    rules = load_rules(DEFAULT_RULES_PATH)
    xml = [failed_logon_xml(f"2026-06-08T02:{10 + i}:00.000000Z", user="jsmith") for i in range(5)]
    xml.append(group_membership_change_xml("2026-06-08T02:53:00.000000Z", member="jsmith", group="Domain Admins"))
    df = pd.DataFrame([normalize_record(x) for x in xml])
    flagged = apply_rules(df, rules)

    output_path = tmp_path / "report.xlsx"
    generated_at = datetime(2026, 6, 8, 12, 0, tzinfo=UTC)
    build_report(df, flagged, rules, str(output_path), source_file="security.evtx", generated_at=generated_at)

    assert output_path.exists()
    wb = load_workbook(output_path)
    assert set(wb.sheetnames) == EXPECTED_SHEETS

    summary = wb["Executive Summary"]
    assert summary["A1"].value == "ADForensicTool"
    assert "security.evtx" in summary["G2"].value
    assert "2026-06-08" in summary["G1"].value
    # Two native bar charts: Findings by Severity + Findings by Rule
    assert len(summary._charts) == 2
    for chart in summary._charts:
        # Regression guard: these charts' source data lives in columns
        # N:O/Q:R, which are hidden. Charts default to plotting only
        # visible cells, so without visible_cells_only=False they render
        # as blank boxes in Excel despite having valid data underneath.
        assert chart.visible_cells_only is False

    mitre = wb["MITRE ATT&CK Coverage"]
    assert len(mitre._charts) == 1

    # Regression guard: openpyxl 3.1 writes axes as deleted by default, so
    # Excel rendered the bars with no rule names / technique IDs / scale.
    with zipfile.ZipFile(output_path) as zf:
        chart_xml = [zf.read(n).decode() for n in zf.namelist() if n.startswith("xl/charts/chart")]
    assert len(chart_xml) == 3
    for xml in chart_xml:
        assert xml.count('<delete val="0"') == 2  # category + value axis both explicitly shown

    raw_events = wb["Raw Flagged Events"]
    assert raw_events.auto_filter.ref is not None

    chains = wb["Attack Chains"]
    assert chains.auto_filter.ref is not None


def test_report_renders_chains_narrative_and_local_times(tmp_path):
    rules = load_rules(DEFAULT_RULES_PATH)
    xml = [failed_logon_xml(f"2026-06-08T02:{10 + i}:00.000000Z", user="jsmith") for i in range(5)]
    xml.append(successful_logon_xml("2026-06-08T02:20:00.000000Z", user="jsmith"))
    xml.append(group_membership_change_xml("2026-06-08T02:25:00.000000Z", member="jsmith", group="Domain Admins"))
    xml.append(failed_logon_xml("2026-06-08T05:00:00.000000Z", user="unrelated"))
    xml += [kerberoasting_xml(f"2026-06-08T09:0{i}:00.000000Z", user="nobody_else") for i in range(2)]
    df = pd.DataFrame([normalize_record(x) for x in xml])
    flagged = apply_rules(df, rules)
    chains = build_chains(flagged)
    assert len(chains) == 1

    output_path = tmp_path / "report.xlsx"
    build_report(df, flagged, rules, str(output_path), chains=chains, tz=ZoneInfo("Europe/Sofia"))
    wb = load_workbook(output_path)

    summary_text = "\n".join(str(c.value) for row in wb["Executive Summary"].iter_rows() for c in row if c.value)
    assert "ATTACK NARRATIVE" in summary_text
    assert "chain-1: Credential Access → Initial Access → Privilege Escalation (jsmith)" in summary_text
    assert "2026-06-08 05:10-05:25 EEST: 5 failed logons against jsmith" in summary_text  # UTC+3
    assert "shown in Europe/Sofia" in summary_text

    chains_ws = wb["Attack Chains"]
    header = [c.value for c in chains_ws[1]]
    assert header[:4] == ["chain_id", "severity", "start (Europe/Sofia)", "end (Europe/Sofia)"]
    assert chains_ws["A2"].value == "chain-1"
    assert chains_ws["C2"].value == datetime(2026, 6, 8, 5, 10)  # real datetime, local time
    assert chains_ws["C2"].number_format == "yyyy-mm-dd hh:mm:ss"
    stage_rules = [row[4] for row in chains_ws.iter_rows(min_row=6, values_only=True) if row[0] == "chain-1"]
    assert stage_rules == ["Brute Force Login Attempts", "Successful Logon After Brute Force", "Privileged Group Membership Change"]

    raw = wb["Raw Flagged Events"]
    raw_header = [c.value for c in raw[1]]
    assert raw_header[0] == "timestamp (Europe/Sofia)"
    chain_col = raw_header.index("chain_id")
    rule_col = raw_header.index("rule_name")
    by_rule = {row[rule_col]: row[chain_col] for row in raw.iter_rows(min_row=2, values_only=True)}
    assert by_rule["Brute Force Login Attempts"] == "chain-1"
    assert by_rule["Kerberoasting (RC4 Service Ticket Request)"] in (None, "")


def test_report_without_chains_says_so(tmp_path):
    rules = load_rules(DEFAULT_RULES_PATH)
    df = pd.DataFrame([normalize_record(kerberoasting_xml("2026-06-08T04:00:00Z"))])
    output_path = tmp_path / "report.xlsx"
    build_report(df, apply_rules(df, rules), rules, str(output_path))
    ws = load_workbook(output_path)["Attack Chains"]
    assert "No multi-stage attack chains" in ws["A2"].value


def test_build_report_with_no_findings(tmp_path):
    rules = load_rules(DEFAULT_RULES_PATH)
    df = pd.DataFrame([normalize_record(failed_logon_xml("2026-06-08T02:10:00.000000Z"))])
    flagged = apply_rules(df, rules)  # single event, below every threshold -- empty

    output_path = tmp_path / "report_empty.xlsx"
    build_report(df, flagged, rules, str(output_path))

    assert output_path.exists()
    wb = load_workbook(output_path)
    assert set(wb.sheetnames) == EXPECTED_SHEETS

    summary = wb["Executive Summary"]
    assert summary["A1"].value == "ADForensicTool"
    assert "unknown" in summary["G2"].value  # source_file defaults when not given
    # No findings -- no charts should have been built
    assert len(summary._charts) == 0


def test_attacker_controlled_text_is_never_written_as_a_formula(tmp_path):
    """Regression test: usernames are attacker-controlled (anyone can fail a
    logon as any name), and openpyxl stores strings starting with "=" as
    live formulas. A hostile account name must land in the report as inert
    text, unchanged, not as an executable HYPERLINK/DDE formula.
    """
    hostile = '=HYPERLINK("http://203.0.113.9/x","click")'
    rules = load_rules(DEFAULT_RULES_PATH)
    xml = [failed_logon_xml(f"2026-06-08T02:{10 + i}:00.000000Z", user=hostile) for i in range(5)]
    df = pd.DataFrame([normalize_record(x) for x in xml])
    flagged = apply_rules(df, rules)
    assert len(flagged) == 5

    output_path = tmp_path / "report.xlsx"
    build_report(df, flagged, rules, str(output_path), source_file="=cmd|'/c calc'!A1.evtx")

    with zipfile.ZipFile(output_path) as zf:
        sheet_xml = "".join(zf.read(n).decode("utf-8") for n in zf.namelist() if n.startswith("xl/worksheets/"))
    assert "<f>" not in sheet_xml

    wb = load_workbook(output_path)
    user_col = DISPLAY_COLUMNS.index("user") + 1
    cell = wb["Raw Flagged Events"].cell(row=2, column=user_col)
    assert cell.value == hostile
    assert cell.data_type == "s"
