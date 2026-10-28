"""
Generic detection rule engine.

Loads rule definitions from a YAML file (see rules/default_rules.yaml for the
schema and comments) and applies them to a normalized event DataFrame
(the output of parser.evtx_parser.parse_evtx).

Three rule types are supported, each covering a class of single-event-ID
detections that need no cross-event-ID correlation:

  - threshold:    N+ matching events for the same actor within a time window
                  (e.g. brute force: 5+ 4625s for one user in 10 minutes)
  - always_flag:  every matching event is inherently suspicious
                  (e.g. audit log cleared, privileged group membership change)
  - field_match:  a raw EventData field equals one of a set of values
                  (e.g. kerberoasting: TicketEncryptionType == RC4)

Rules that need to stitch together events from *different* Event IDs across
a single actor (e.g. "successful logon after a flagged brute-force cluster")
are out of scope here by design -- that's cross-rule correlation, which is
correlator/chain_builder.py's job.
"""
from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import timedelta
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

DEFAULT_RULES_PATH = Path(__file__).parent / "default_rules.yaml"

VALID_TYPES = {"threshold", "always_flag", "field_match"}


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    mitre_technique: str
    type: str
    event_ids: list[int]
    group_by: str | None = None
    window_minutes: float | None = None
    min_count: int | None = None
    field: str | None = None
    equals: list[str] = dc_field(default_factory=list)

    def __post_init__(self) -> None:
        if self.type not in VALID_TYPES:
            raise ValueError(f"Rule '{self.id}': unknown type '{self.type}'")
        if self.type == "threshold" and not (self.group_by and self.window_minutes and self.min_count):
            raise ValueError(f"Rule '{self.id}': threshold rules require group_by, window_minutes, min_count")
        if self.type == "field_match" and not (self.field and self.equals):
            raise ValueError(f"Rule '{self.id}': field_match rules require field and equals")


def load_rules(yaml_path: str | Path) -> list[Rule]:
    with open(yaml_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return [Rule(**raw) for raw in data.get("rules", [])]


def _apply_threshold(df: pd.DataFrame, rule: Rule) -> pd.DataFrame:
    """Flag events forming a cluster of >= min_count within window_minutes.

    Clusters are computed per group_by value (e.g. per user) using a
    sliding window over sorted timestamps, then adjacent qualifying windows
    are merged so each contiguous burst gets a single cluster_id rather than
    many overlapping ones.
    """
    subset = df[df["event_id"].isin(rule.event_ids)].copy()
    if subset.empty or rule.group_by not in subset.columns:
        return subset.iloc[0:0]

    window = timedelta(minutes=rule.window_minutes)
    flagged_frames = []
    cluster_counter = 0

    for _, group in subset.groupby(rule.group_by, dropna=True):
        group = group.sort_values("timestamp").reset_index(drop=True)
        timestamps = group["timestamp"]
        n = len(group)
        left = 0
        cluster_ranges: list[list[int]] = []

        for right in range(n):
            while timestamps[right] - timestamps[left] > window:
                left += 1
            if right - left + 1 >= rule.min_count:
                if cluster_ranges and cluster_ranges[-1][1] >= left:
                    cluster_ranges[-1][1] = max(cluster_ranges[-1][1], right)
                else:
                    cluster_ranges.append([left, right])

        for start_idx, end_idx in cluster_ranges:
            chunk = group.iloc[start_idx : end_idx + 1].copy()
            chunk["cluster_id"] = f"{rule.id}-{cluster_counter}"
            cluster_counter += 1
            flagged_frames.append(chunk)

    if not flagged_frames:
        return subset.iloc[0:0]
    return pd.concat(flagged_frames, ignore_index=True)


def _apply_always_flag(df: pd.DataFrame, rule: Rule) -> pd.DataFrame:
    return df[df["event_id"].isin(rule.event_ids)].copy()


def _normalize_hex(value: Any) -> Any:
    """Normalize a Windows event field value for comparison.

    Windows event templates render DWORD fields as zero-padded 8-digit hex
    strings (e.g. TicketEncryptionType "0x00000017"), but rule authors
    naturally write the short form used in Microsoft's own docs and most
    security literature (e.g. "0x17"). Comparing as ints instead of raw
    strings means both forms match, so rules don't silently never fire
    over a padding difference.
    """
    if isinstance(value, str):
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value)
        except ValueError:
            return value
    return value


def _apply_field_match(df: pd.DataFrame, rule: Rule) -> pd.DataFrame:
    subset = df[df["event_id"].isin(rule.event_ids)].copy()
    if subset.empty:
        return subset

    normalized_targets = {_normalize_hex(v) for v in rule.equals}

    def matches(event_data: dict[str, Any]) -> bool:
        value = event_data.get(rule.field)
        if value is None:
            return False
        return _normalize_hex(value) in normalized_targets

    mask = subset["event_data"].apply(matches)
    return subset[mask]


_DISPATCH = {
    "threshold": _apply_threshold,
    "always_flag": _apply_always_flag,
    "field_match": _apply_field_match,
}


def apply_rules(df: pd.DataFrame, rules: list[Rule]) -> pd.DataFrame:
    """Run every rule against df, returning one combined DataFrame of flagged
    events tagged with which rule(s) fired.

    Each output row carries: all original event columns, plus rule_id,
    rule_name, severity, mitre_technique, and cluster_id (empty string for
    non-threshold rules).
    """
    results = []
    for rule in rules:
        flagged = _DISPATCH[rule.type](df, rule)
        if flagged.empty:
            continue
        flagged = flagged.copy()
        flagged["rule_id"] = rule.id
        flagged["rule_name"] = rule.name
        flagged["severity"] = rule.severity
        flagged["mitre_technique"] = rule.mitre_technique
        if "cluster_id" not in flagged.columns:
            flagged["cluster_id"] = ""
        results.append(flagged)

    if not results:
        return pd.DataFrame(
            columns=list(df.columns) + ["rule_id", "rule_name", "severity", "mitre_technique", "cluster_id"]
        )
    return pd.concat(results, ignore_index=True)
