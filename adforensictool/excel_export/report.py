"""
Builds the analyst-facing .xlsx report from flagged events.

Tabs (per the project spec):
  - Executive Summary       branded dashboard: risk score, KPI tiles, charts, key findings
  - Attack Chains           one row per chain, color-coded by severity
  - Raw Flagged Events      full detail table, color-coded by severity, filterable
  - Account/Group Changes   dedicated view of privilege-escalation events
  - MITRE ATT&CK Coverage   technique -> observed count heatmap + chart

"Attack Chains" currently groups flagged events by rule_id as a stand-in for
real multi-stage chains, since correlator/chain_builder.py (which produces
actual cross-rule chains) is still a stub. Once that module is implemented,
this tab should be fed real Chain objects instead -- see the TODO on
build_report's `chains` parameter.

Visual design (colors, fonts, KPI tile styling) lives in excel_export/theme.py
so every tab shares one look rather than five independently-styled sheets.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pandas as pd
from openpyxl import Workbook
from openpyxl.cell.rich_text import CellRichText, TextBlock
from openpyxl.cell.text import InlineFont
from openpyxl.chart import BarChart, Reference
from openpyxl.chart.marker import DataPoint
from openpyxl.chart.shapes import GraphicalProperties
from openpyxl.formatting.rule import ColorScaleRule
from openpyxl.styles import Alignment, Font
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from adforensictool.excel_export import theme
from adforensictool.rules.engine import Rule

SEVERITY_SCORE = {"critical": 40, "high": 20, "medium": 10, "low": 5}

# Human-readable names for the MITRE technique IDs this tool's default rules
# reference. Extend when you add rules that cite new technique IDs.
MITRE_NAMES = {
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1098": "Account Manipulation",
    "T1070.001": "Clear Windows Event Logs",
    "T1558.003": "Steal or Forge Kerberos Tickets: Kerberoasting",
    "T1543": "Create or Modify System Process",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
}

DISPLAY_COLUMNS = [
    "timestamp",
    "event_id",
    "rule_name",
    "severity",
    "mitre_technique",
    "user",
    "source_ip",
    "target_host",
    "logon_type",
    "process_name",
    "raw_message",
    "cluster_id",
]

DASHBOARD_LAST_COL = 12  # column L -- width of the banner/KPI/bullet area


# --------------------------------------------------------------------------
# Generic table helpers, shared by the four data tabs
# --------------------------------------------------------------------------


def _write_header(ws: Worksheet, columns: list[str], row: int = 1) -> None:
    for col_idx, col_name in enumerate(columns, start=1):
        cell = ws.cell(row=row, column=col_idx, value=col_name)
        cell.fill = theme.TABLE_HEADER_FILL
        cell.font = theme.TABLE_HEADER_FONT
        cell.alignment = theme.TABLE_HEADER_ALIGN
        cell.border = theme.THIN_BORDER
    ws.row_dimensions[row].height = 20


def _autosize_columns(ws: Worksheet, columns: list[str], rows: list[list[Any]]) -> None:
    for col_idx, col_name in enumerate(columns, start=1):
        max_len = len(str(col_name))
        for row in rows:
            val = row[col_idx - 1] if col_idx - 1 < len(row) else ""
            max_len = max(max_len, len(str(val)))
        ws.column_dimensions[get_column_letter(col_idx)].width = min(max_len + 2, 60)


def _write_table(ws: Worksheet, df: pd.DataFrame, columns: list[str], color_by_severity: bool = True) -> None:
    _write_header(ws, columns)
    rows = df[columns].astype(object).where(pd.notnull(df[columns]), "").values.tolist()
    severity_idx = columns.index("severity") if "severity" in columns else None

    for row_idx, row in enumerate(rows, start=2):
        for col_idx, value in enumerate(row, start=1):
            if hasattr(value, "isoformat"):
                value = value.isoformat(sep=" ", timespec="seconds")
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.border = theme.THIN_BORDER

        severity = str(row[severity_idx]).lower() if severity_idx is not None else None
        row_fill = theme.SEVERITY_ROW_FILLS.get(severity) if severity else None
        text_color = theme.SEVERITY_TEXT_COLORS.get(severity) if severity else None
        if row_fill is None and color_by_severity:
            # No severity color applies (or this table doesn't carry one) --
            # fall back to plain zebra striping so the table still reads
            # cleanly at a glance instead of a flat wall of white rows.
            row_fill = theme.ZEBRA_FILL if row_idx % 2 == 0 else None

        for col_idx in range(1, len(columns) + 1):
            cell = ws.cell(row=row_idx, column=col_idx)
            if row_fill:
                cell.fill = row_fill
            if severity_idx == col_idx - 1 and text_color:
                cell.font = Font(color=text_color, bold=True)

    _autosize_columns(ws, columns, rows)
    if rows:
        last_col_letter = get_column_letter(len(columns))
        ws.auto_filter.ref = f"A1:{last_col_letter}{len(rows) + 1}"
    ws.freeze_panes = "A2"


# --------------------------------------------------------------------------
# Executive Summary: branded dashboard
# --------------------------------------------------------------------------


def _fill_range(ws: Worksheet, cell_range: str, fill) -> None:
    for row in ws[cell_range]:
        for cell in row:
            cell.fill = fill


def _build_banner(ws: Worksheet, source_file: str | None, generated_at: datetime) -> None:
    last_col_letter = get_column_letter(DASHBOARD_LAST_COL)

    _fill_range(ws, f"A1:{last_col_letter}3", theme.BANNER_FILL)

    ws.merge_cells("A1:F2")
    title_cell = ws["A1"]
    title_cell.value = theme.TOOL_NAME
    title_cell.font = theme.BANNER_TITLE_FONT
    title_cell.alignment = Alignment(horizontal="left", vertical="center", indent=1)

    ws.merge_cells(f"G1:{last_col_letter}1")
    gen_cell = ws["G1"]
    gen_cell.value = f"Generated: {generated_at.strftime('%Y-%m-%d %H:%M UTC')}"
    gen_cell.font = theme.BANNER_SUBTITLE_FONT
    gen_cell.alignment = Alignment(horizontal="right", vertical="center")

    ws.merge_cells(f"G2:{last_col_letter}2")
    src_cell = ws["G2"]
    src_cell.value = f"Source: {source_file or 'unknown'}"
    src_cell.font = theme.BANNER_SUBTITLE_FONT
    src_cell.alignment = Alignment(horizontal="right", vertical="center")

    ws.merge_cells(f"A3:{last_col_letter}3")
    subtitle_cell = ws["A3"]
    # Two-tone rich text: gray subtitle, amber version tag -- the signature
    # accent color, not just another wash of the banner's charcoal.
    subtitle_cell.value = CellRichText(
        TextBlock(InlineFont(color="B8B8B8", sz=10), "Active Directory Security Incident Report   "),
        TextBlock(InlineFont(color=theme.ACCENT_AMBER, sz=10, b=True), f"v{theme.TOOL_VERSION}"),
    )
    subtitle_cell.alignment = Alignment(horizontal="left", vertical="center", indent=1)

    # Amber divider strip under the charcoal banner -- the recurring accent
    # motif, rather than yet more blue.
    _fill_range(ws, f"A4:{last_col_letter}4", theme.BANNER_ACCENT_FILL)

    ws.row_dimensions[1].height = 24
    ws.row_dimensions[2].height = 24
    ws.row_dimensions[3].height = 18
    ws.row_dimensions[4].height = 5


def _write_kpi_tile(ws: Worksheet, start_col: int, label: str, value: str, value_color: str) -> None:
    end_col = start_col + 1
    start_letter = get_column_letter(start_col)
    end_letter = get_column_letter(end_col)

    ws.merge_cells(f"{start_letter}6:{end_letter}6")
    label_cell = ws[f"{start_letter}6"]
    label_cell.value = label
    label_cell.font = theme.KPI_LABEL_FONT
    label_cell.alignment = Alignment(horizontal="center", vertical="bottom")

    ws.merge_cells(f"{start_letter}7:{end_letter}8")
    value_cell = ws[f"{start_letter}7"]
    value_cell.value = value
    value_cell.font = Font(color=value_color, bold=True, size=22, name="Calibri")
    value_cell.alignment = Alignment(horizontal="center", vertical="center")

    for row in ws[f"{start_letter}6:{end_letter}8"]:
        for cell in row:
            cell.fill = theme.KPI_FILL
            cell.border = theme.KPI_BORDER


def _build_kpi_row(ws: Worksheet, df: pd.DataFrame, flagged: pd.DataFrame, risk_score: int, severity_counts: dict) -> None:
    risk_label, risk_color = theme.risk_band(risk_score)
    _write_kpi_tile(ws, 2, f"OVERALL RISK ({risk_label})", f"{risk_score}/100", risk_color)
    _write_kpi_tile(ws, 4, "EVENTS PARSED", str(len(df)), theme.BRAND_DARK)
    _write_kpi_tile(ws, 6, "EVENTS FLAGGED", str(len(flagged)), theme.BRAND_DARK)
    _write_kpi_tile(ws, 8, "CRITICAL FINDINGS", str(severity_counts.get("critical", 0)), theme.SEVERITY_TEXT_COLORS["critical"])
    _write_kpi_tile(ws, 10, "HIGH FINDINGS", str(severity_counts.get("high", 0)), theme.SEVERITY_TEXT_COLORS["high"])


def _colored_data_points(hex_colors: list[str]) -> list[DataPoint]:
    """Explicit per-bar fill colors for a single-series bar chart.

    Without this, Excel falls back to its default theme accent palette
    (blue, then orange, then grey, ...) assigned by category *position*,
    which is meaningless here -- "Critical" would render blue just because
    it happened to be the first bar. This pins each bar to the same
    severity color used everywhere else in the report (theme.SEVERITY_HEX).
    """
    return [DataPoint(idx=i, spPr=GraphicalProperties(solidFill=color)) for i, color in enumerate(hex_colors)]


def _build_charts(ws: Worksheet, flagged: pd.DataFrame) -> int:
    """Writes hidden chart-data staging tables off to the side, builds two
    native bar charts from them, and returns the row number where content
    below the charts should resume.
    """
    if flagged.empty:
        return 11

    # -- Severity breakdown staging table (columns N:O), hidden from view --
    severity_counts = flagged["severity"].str.lower().value_counts()
    sev_rows = [
        (sev, sev.title(), int(severity_counts.get(sev, 0)))
        for sev in theme.SEVERITY_ORDER
        if severity_counts.get(sev, 0)
    ]

    ws["N1"] = "Severity"
    ws["O1"] = "Count"
    for i, (_, sev_label, count) in enumerate(sev_rows, start=2):
        ws.cell(row=i, column=14, value=sev_label)
        ws.cell(row=i, column=15, value=count)

    severity_chart = BarChart()
    severity_chart.type = "col"
    severity_chart.title = "Findings by Severity"
    severity_chart.y_axis.title = "Events"
    severity_chart.x_axis.title = "Severity"
    severity_chart.height = 8
    severity_chart.width = 14
    data = Reference(ws, min_col=15, min_row=1, max_row=1 + len(sev_rows))
    cats = Reference(ws, min_col=14, min_row=2, max_row=1 + len(sev_rows))
    severity_chart.add_data(data, titles_from_data=True)
    severity_chart.set_categories(cats)
    severity_chart.legend = None
    severity_chart.varyColors = True
    severity_chart.series[0].data_points = _colored_data_points([theme.SEVERITY_HEX[sev] for sev, _, _ in sev_rows])
    # Source data lives in columns N:O, which are hidden below -- charts
    # default to plotting only visible cells, so without this the chart
    # renders as a blank box once its data columns are hidden.
    severity_chart.visible_cells_only = False
    ws.add_chart(severity_chart, "B11")

    # -- Findings-by-rule staging table (columns Q:R), hidden from view --
    # Keep each rule's severity alongside its name/count so its bar can be
    # colored the same way (one rule always has exactly one severity).
    by_rule = (
        flagged.groupby(["rule_name", "severity"]).size().reset_index(name="count").sort_values("count", ascending=False)
    )

    ws["Q1"] = "Rule"
    ws["R1"] = "Count"
    for i, row in enumerate(by_rule.itertuples(index=False), start=2):
        ws.cell(row=i, column=17, value=row.rule_name)
        ws.cell(row=i, column=18, value=int(row.count))

    rule_chart = BarChart()
    rule_chart.type = "bar"  # horizontal bars read better with long rule names
    rule_chart.title = "Findings by Rule"
    rule_chart.x_axis.title = "Events"
    rule_chart.height = 8
    rule_chart.width = 14
    data = Reference(ws, min_col=18, min_row=1, max_row=1 + len(by_rule))
    cats = Reference(ws, min_col=17, min_row=2, max_row=1 + len(by_rule))
    rule_chart.add_data(data, titles_from_data=True)
    rule_chart.set_categories(cats)
    rule_chart.legend = None
    rule_chart.varyColors = True
    rule_chart.series[0].data_points = _colored_data_points(
        [theme.SEVERITY_HEX[str(sev).lower()] for sev in by_rule["severity"]]
    )
    rule_chart.visible_cells_only = False  # same hidden-source-columns issue as above
    ws.add_chart(rule_chart, "H11")

    for col in ("N", "O", "Q", "R"):
        ws.column_dimensions[col].hidden = True

    return 28  # generous clearance below ~8cm-tall charts anchored at row 11


def _build_section_header(ws: Worksheet, row: int, text: str) -> None:
    last_col_letter = get_column_letter(DASHBOARD_LAST_COL)
    ws.merge_cells(f"A{row}:{last_col_letter}{row}")
    cell = ws[f"A{row}"]
    cell.value = text
    cell.font = theme.SECTION_HEADER_FONT
    for c in ws[f"A{row}:{last_col_letter}{row}"][0]:
        c.border = theme.SECTION_HEADER_BORDER


def _write_wide_row(ws: Worksheet, row: int, text: str, font: Font | None = None) -> None:
    last_col_letter = get_column_letter(DASHBOARD_LAST_COL)
    ws.merge_cells(f"A{row}:{last_col_letter}{row}")
    cell = ws[f"A{row}"]
    cell.value = text
    cell.alignment = Alignment(wrap_text=True, vertical="center")
    if font:
        cell.font = font
    ws.row_dimensions[row].height = 18


def _build_executive_summary(ws: Worksheet, df: pd.DataFrame, flagged: pd.DataFrame, source_file: str | None, generated_at: datetime) -> None:
    for col in range(1, DASHBOARD_LAST_COL + 1):
        ws.column_dimensions[get_column_letter(col)].width = 11

    severity_counts = flagged["severity"].str.lower().value_counts().to_dict() if not flagged.empty else {}
    risk_score = min(100, sum(SEVERITY_SCORE.get(sev, 0) * count for sev, count in severity_counts.items()))

    _build_banner(ws, source_file, generated_at)
    _build_kpi_row(ws, df, flagged, risk_score, severity_counts)
    r = _build_charts(ws, flagged)

    _build_section_header(ws, r, "KEY FINDINGS")
    r += 2

    if flagged.empty:
        _write_wide_row(ws, r, "No detections fired against the supplied log.")
        r += 1
    else:
        by_rule = flagged.groupby(["rule_id", "rule_name", "severity"]).agg(
            count=("event_id", "size"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
        ).reset_index()
        by_rule.sort_values("first_seen", inplace=True)
        for _, row in by_rule.iterrows():
            first_seen = row["first_seen"]
            last_seen = row["last_seen"]
            first_str = first_seen.isoformat(sep=" ", timespec="seconds") if pd.notnull(first_seen) else "?"
            last_str = last_seen.isoformat(sep=" ", timespec="seconds") if pd.notnull(last_seen) else "?"
            severity = str(row["severity"]).lower()
            bullet = (
                f"  ●  [{row['severity'].upper()}] {row['rule_name']}: "
                f"{row['count']} event(s) between {first_str} and {last_str}"
            )
            font = Font(color=theme.SEVERITY_TEXT_COLORS.get(severity, theme.BRAND_DARK), bold=True)
            _write_wide_row(ws, r, bullet, font)
            r += 1

    r += 1
    _write_wide_row(
        ws,
        r,
        (
            "Note: full attack-chain narratives (plain-English, timestamp-anchored) require the "
            "correlator/narrator modules, currently stubbed. See the Attack Chains tab for a "
            "per-rule grouping in the meantime."
        ),
        Font(italic=True, color=theme.SLATE),
    )


# --------------------------------------------------------------------------
# Attack Chains / Account-Group Changes / MITRE Coverage tabs
# --------------------------------------------------------------------------


def _build_attack_chains(ws: Worksheet, flagged: pd.DataFrame) -> None:
    columns = ["rule_id", "rule_name", "severity", "mitre_technique", "cluster_id", "event_count", "first_seen", "last_seen"]
    _write_header(ws, columns)

    if flagged.empty:
        _autosize_columns(ws, columns, [])
        return

    group_cols = ["rule_id", "rule_name", "severity", "mitre_technique", "cluster_id"]
    grouped = flagged.groupby(group_cols, dropna=False).agg(
        event_count=("event_id", "size"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
    ).reset_index()
    grouped.sort_values("first_seen", inplace=True)

    rows = grouped[columns].astype(object).values.tolist()
    for row_idx, row in enumerate(rows, start=2):
        for col_idx, value in enumerate(row, start=1):
            if hasattr(value, "isoformat"):
                value = value.isoformat(sep=" ", timespec="seconds")
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.border = theme.THIN_BORDER
        severity = str(row[columns.index("severity")]).lower()
        row_fill = theme.SEVERITY_ROW_FILLS.get(severity)
        text_color = theme.SEVERITY_TEXT_COLORS.get(severity)
        for col_idx in range(1, len(columns) + 1):
            cell = ws.cell(row=row_idx, column=col_idx)
            if row_fill:
                cell.fill = row_fill
            if col_idx - 1 == columns.index("severity") and text_color:
                cell.font = Font(color=text_color, bold=True)

    _autosize_columns(ws, columns, rows)
    ws.auto_filter.ref = f"A1:{get_column_letter(len(columns))}{len(rows) + 1}"
    ws.freeze_panes = "A2"


def _build_account_changes(ws: Worksheet, flagged: pd.DataFrame) -> None:
    columns = ["timestamp", "target_host", "event_id", "user", "raw_message", "severity"]
    changes = flagged[flagged["rule_id"] == "privilege_escalation"] if not flagged.empty else flagged
    if changes.empty:
        _write_header(ws, columns)
        _autosize_columns(ws, columns, [])
    else:
        _write_table(ws, changes, columns)


def _build_mitre_coverage(ws: Worksheet, flagged: pd.DataFrame, rules: list[Rule]) -> None:
    columns = ["mitre_technique", "technique_name", "observed_count"]
    _write_header(ws, columns)

    watched_techniques = sorted({r.mitre_technique for r in rules})
    counts = flagged.groupby("mitre_technique").size().to_dict() if not flagged.empty else {}

    rows = []
    for technique in watched_techniques:
        rows.append([technique, MITRE_NAMES.get(technique, "Unknown"), counts.get(technique, 0)])

    for row_idx, row in enumerate(rows, start=2):
        for col_idx, value in enumerate(row, start=1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.border = theme.THIN_BORDER
            if row_idx % 2 == 0:
                cell.fill = theme.ZEBRA_FILL

    _autosize_columns(ws, columns, rows)

    if rows:
        last_row = len(rows) + 1
        count_col_letter = get_column_letter(columns.index("observed_count") + 1)
        color_scale = ColorScaleRule(start_type="min", start_color="FFFFFF", end_type="max", end_color="C00000")
        ws.conditional_formatting.add(f"{count_col_letter}2:{count_col_letter}{last_row}", color_scale)

        chart_col_start = len(columns) + 3  # a couple columns of gutter to the right of the table
        chart = BarChart()
        chart.type = "bar"
        chart.style = 10
        chart.title = "MITRE ATT&CK Technique Coverage"
        chart.x_axis.title = "Events Observed"
        chart.height = max(6, len(rows) * 1.1)
        chart.width = 16
        data = Reference(ws, min_col=3, min_row=1, max_row=last_row)
        cats = Reference(ws, min_col=1, min_row=2, max_row=last_row)
        chart.add_data(data, titles_from_data=True)
        chart.set_categories(cats)
        chart.legend = None
        ws.add_chart(chart, f"{get_column_letter(chart_col_start)}1")

    ws.freeze_panes = "A2"


def build_report(
    df: pd.DataFrame,
    flagged: pd.DataFrame,
    rules: list[Rule],
    output_path: str,
    source_file: str | None = None,
    generated_at: datetime | None = None,
) -> None:
    """Build the .xlsx report and write it to output_path.

    df:            full normalized event DataFrame (not currently rendered
                   on its own tab, kept for future tabs / chain construction).
    flagged:       output of rules.engine.apply_rules -- one row per flagged event.
    rules:         the loaded rule definitions, used to enumerate MITRE
                   techniques this run *watched for* (not just ones that fired).
    source_file:   input .evtx path, shown in the Executive Summary banner
                   for provenance. Optional -- falls back to "unknown".
    generated_at:  report generation timestamp shown in the banner. Defaults
                   to now (UTC) if not supplied.

    TODO: once correlator/chain_builder.py exists, pass its Chain objects in
    here (a `chains` parameter) and have _build_attack_chains render those
    instead of the per-rule grouping it falls back to today.
    """
    generated_at = generated_at or datetime.now(UTC)
    wb = Workbook()

    ws_summary = wb.active
    ws_summary.title = "Executive Summary"
    _build_executive_summary(ws_summary, df, flagged, source_file, generated_at)

    ws_chains = wb.create_sheet("Attack Chains")
    _build_attack_chains(ws_chains, flagged)

    ws_raw = wb.create_sheet("Raw Flagged Events")
    if flagged.empty:
        _write_header(ws_raw, DISPLAY_COLUMNS)
        _autosize_columns(ws_raw, DISPLAY_COLUMNS, [])
    else:
        _write_table(ws_raw, flagged, DISPLAY_COLUMNS)

    ws_accounts = wb.create_sheet("Account-Group Changes")
    _build_account_changes(ws_accounts, flagged)

    ws_mitre = wb.create_sheet("MITRE ATT&CK Coverage")
    _build_mitre_coverage(ws_mitre, flagged, rules)

    wb.save(output_path)
