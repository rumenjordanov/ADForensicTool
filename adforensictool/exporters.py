"""
Machine-readable outputs alongside the Excel report:

  - json:      everything -- run metadata, parse stats, chains (with
               narrative and stages) and every flagged event
  - csv:       the flagged-events table, one row per flagged event
  - timeline:  a Timesketch-importable CSV (message / datetime /
               timestamp_desc + extra fields), for super-timelining with
               other evidence

Event times are written as ISO 8601 with an explicit UTC offset, in the
display timezone (Timesketch always gets UTC, which is what it expects).
"""
from __future__ import annotations

import csv
import json
import re
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import Any

import pandas as pd

from adforensictool.correlator.chain_builder import Chain
from adforensictool.excel_export.report import DISPLAY_COLUMNS, OPTIONAL_DISPLAY_COLUMNS, chain_ids_by_row, zone_label
from adforensictool.narrator.narrate import chain_headline, narrate_chain, narrate_stages
from adforensictool.parser.evtx_parser import ParseStats
from adforensictool.version import __version__

FORMATS = ("xlsx", "json", "csv", "timeline")
EXTENSIONS = {"xlsx": ".xlsx", "json": ".json", "csv": ".csv", "timeline": ".timeline.csv"}

_PLAIN_NUMBER = re.compile(r"^-\d+(\.\d+)?$")


def output_paths(output: str, formats: list[str]) -> dict[str, Path]:
    """--output plus formats -> one path per format.

    A single format whose extension already matches is written exactly to
    --output; otherwise each format gets --output's stem + its extension.
    """
    out = Path(output)
    if len(formats) == 1 and out.name.lower().endswith(EXTENSIONS[formats[0]]):
        return {formats[0]: out}
    stem = out.name
    for ext in sorted(EXTENSIONS.values(), key=len, reverse=True):
        if stem.lower().endswith(ext):
            stem = stem[: -len(ext)]
            break
    return {fmt: out.with_name(stem + EXTENSIONS[fmt]) for fmt in formats}


def infer_formats(output: str) -> list[str]:
    name = output.lower()
    for fmt in ("timeline", "json", "csv", "xlsx"):  # ".timeline.csv" before ".csv"
        if name.endswith(EXTENSIONS[fmt]):
            return [fmt]
    return ["xlsx"]


def csv_safe(value: Any) -> Any:
    """Neutralize spreadsheet formula injection in CSV cells.

    Unlike .xlsx (where report.py stores such text as typed strings), a CSV
    has no types: Excel re-interprets any cell starting with = + @ (or a
    "-" that isn't just a negative number) as a formula when the file is
    opened. Account names and other fields are attacker-controlled, so such
    values get a leading apostrophe -- OWASP's recommended mitigation.
    """
    if not isinstance(value, str) or not value:
        return value
    if value[0] in "=+@\t\r" or (value[0] == "-" and len(value) > 1 and not _PLAIN_NUMBER.match(value)):
        return "'" + value
    return value


def _iso(value: Any, tz: tzinfo | None) -> str | None:
    if value is None or (not isinstance(value, str) and pd.isna(value)):
        return None
    ts = pd.Timestamp(value)
    if ts.tzinfo is not None:
        ts = ts.tz_convert(tz or UTC)
    return ts.isoformat()


def _plain(value: Any) -> Any:
    """JSON-friendly scalar: NaN/NaT -> None, numpy ints -> int."""
    if isinstance(value, dict):
        return value
    if value is None or (not isinstance(value, str) and pd.isna(value)):
        return None
    if hasattr(value, "item"):
        return value.item()
    return value


def _findings_frame(flagged: pd.DataFrame, chains: list[Chain]) -> pd.DataFrame:
    frame = flagged.copy()
    frame["chain_id"] = chain_ids_by_row(frame, chains) if not frame.empty else pd.Series(dtype=object)
    return frame


def write_json(
    path: Path,
    flagged: pd.DataFrame,
    chains: list[Chain],
    *,
    sources: list[str],
    parse_stats: ParseStats | None,
    suppressed: dict[str, int] | None,
    tz: tzinfo | None,
    generated_at: datetime | None = None,
) -> None:
    findings = _findings_frame(flagged, chains)
    columns = [c for c in DISPLAY_COLUMNS + OPTIONAL_DISPLAY_COLUMNS + ["rule_id", "event_data"] if c in findings.columns]
    doc = {
        "tool": "ADForensicTool",
        "version": __version__,
        "generated_at": (generated_at or datetime.now(UTC)).isoformat(),
        "timezone": zone_label(tz),
        "sources": sources,
        "parse_stats": None
        if parse_stats is None
        else {
            "records_read": parse_stats.records_read,
            "records_skipped": parse_stats.records_skipped,
            "records_filtered": parse_stats.records_filtered,
            "records_duplicate": parse_stats.records_duplicate,
            "files": parse_stats.files,
            "record_id_gaps": [
                {"file": f, "channel": ch, "computer": comp, "first_record_id": lo, "last_record_id": hi, "missing": n}
                for f, ch, comp, lo, hi, n in parse_stats.record_id_gaps()
            ],
        },
        "suppressed_by_allowlist": suppressed or {},
        "chains": [
            {
                "id": c.id,
                "severity": c.severity,
                "start": _iso(c.start_time, tz),
                "end": _iso(c.end_time, tz),
                "accounts": c.users,
                "source_ips": c.source_ips,
                "tactics": c.tactics,
                "headline": chain_headline(c),
                "narrative": narrate_chain(c, tz),
                "narrative_steps": narrate_stages(c, tz),
                "stages": [
                    {
                        "rule_id": s.rule_id,
                        "rule_name": s.rule_name,
                        "severity": s.severity,
                        "tactic": s.tactic,
                        "mitre_technique": s.mitre_technique,
                        "start": _iso(s.start_time, tz),
                        "end": _iso(s.end_time, tz),
                        "event_count": s.event_count,
                        "users": s.users,
                        "source_ips": s.source_ips,
                    }
                    for s in c.stages
                ],
            }
            for c in chains
        ],
        "findings": [
            {col: (_iso(row[col], tz) if col == "timestamp" else _plain(row[col])) for col in columns}
            for row in findings.to_dict("records")
        ],
    }
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def write_csv(path: Path, flagged: pd.DataFrame, chains: list[Chain], tz: tzinfo | None) -> None:
    findings = _findings_frame(flagged, chains)
    columns = DISPLAY_COLUMNS + [c for c in OPTIONAL_DISPLAY_COLUMNS if c in findings.columns]
    # utf-8-sig: Excel only detects UTF-8 in a CSV when it has a BOM
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow([f"timestamp ({zone_label(tz)})" if c == "timestamp" else c for c in columns])
        for row in findings.reindex(columns=columns).to_dict("records"):
            writer.writerow(
                [_iso(row[c], tz) if c == "timestamp" else csv_safe("" if _plain(row[c]) is None else row[c]) for c in columns]
            )


def write_timeline(path: Path, flagged: pd.DataFrame, chains: list[Chain]) -> None:
    """Timesketch CSV: required message/datetime/timestamp_desc, then extra
    attributes. One row per flagged event, always in UTC."""
    findings = _findings_frame(flagged, chains)
    extra = ["event_id", "record_id", "rule_id", "rule_name", "severity", "mitre_technique", "chain_id", "user",
             "subject_user", "target_group", "source_ip", "target_host"]  # fmt: skip
    extra += [c for c in OPTIONAL_DISPLAY_COLUMNS if c in findings.columns]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["message", "datetime", "timestamp_desc", *extra])
        for row in findings.to_dict("records"):
            if _iso(row["timestamp"], UTC) is None:
                continue
            who = row.get("user")
            who = "" if _plain(who) is None else f" -- {who}"
            origin = row.get("source_ip")
            origin = "" if _plain(origin) is None else f" from {origin}"
            message = f"[{str(row['severity']).upper()}] {row['rule_name']} (event {row['event_id']}){who}{origin}"
            writer.writerow(
                [csv_safe(message), _iso(row["timestamp"], UTC), "Event Logged"]
                + [csv_safe("" if _plain(row.get(c)) is None else row.get(c)) for c in extra]
            )
