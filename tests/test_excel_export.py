"""
Smoke test for excel_export.report.build_report: confirms it runs end to
end (on both an empty and a populated flagged-events DataFrame), produces a
workbook with all 5 expected tabs, and that the branded-dashboard elements
(banner, charts, autofilter) that make it look like a polished product
actually show up rather than just checking sheet names. Does not assert on
exact colors/fonts -- that's better verified by opening the file manually.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd
from openpyxl import load_workbook

from excel_export.report import build_report
from parser.evtx_parser import normalize_record
from rules.engine import apply_rules, load_rules
from tests.fixtures.sample_events import failed_logon_xml, group_membership_change_xml

EXPECTED_SHEETS = {
    "Executive Summary",
    "Attack Chains",
    "Raw Flagged Events",
    "Account-Group Changes",
    "MITRE ATT&CK Coverage",
}


def test_build_report_with_findings(tmp_path):
    rules = load_rules("rules/default_rules.yaml")
    xml = [failed_logon_xml(f"2026-06-08T02:{10 + i}:00.000000Z", user="jsmith") for i in range(5)]
    xml.append(group_membership_change_xml("2026-06-08T02:53:00.000000Z", member="jsmith", group="Domain Admins"))
    df = pd.DataFrame([normalize_record(x) for x in xml])
    flagged = apply_rules(df, rules)

    output_path = tmp_path / "report.xlsx"
    generated_at = datetime(2026, 6, 8, 12, 0, tzinfo=timezone.utc)
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

    raw_events = wb["Raw Flagged Events"]
    assert raw_events.auto_filter.ref is not None

    chains = wb["Attack Chains"]
    assert chains.auto_filter.ref is not None


def test_build_report_with_no_findings(tmp_path):
    rules = load_rules("rules/default_rules.yaml")
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
