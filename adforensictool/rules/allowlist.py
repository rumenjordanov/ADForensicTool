"""
Allowlist: suppress known-benign flagged events without editing the rules.

Format (YAML):

    allowlist:
      - description: "Nessus scanner"          # shown in the report/CLI
        rules: [brute_force, password_spray]   # optional; omit = every rule
        match:                                 # all conditions must hold
          - field: source_ip
            equals: 10.0.0.50
      - description: "Azure AD Connect sync account replicates by design"
        rules: [dcsync]
        match:
          - field: subject_user
            startswith: MSOL_

Conditions use the same syntax as rule `match:` lists (see
default_rules.yaml). Suppression runs after every rule has fired, so an
allowlisted brute force still lets "logon after brute force" fire for the
same account -- a scanner's noise is hidden, but a real compromise that
happens to follow it is not.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from adforensictool.rules.engine import Condition, RuleError, filter_by_conditions, parse_condition


@dataclass
class AllowEntry:
    description: str
    match: list[Condition]
    rules: list[str] = field(default_factory=list)


def parse_allowlist(data: Any) -> list[AllowEntry]:
    if data is None:
        return []
    if not isinstance(data, dict) or not isinstance(data.get("allowlist", []), list):
        raise RuleError("Allowlist file must be a mapping with a top-level 'allowlist' list")
    entries = []
    for i, raw in enumerate(data.get("allowlist") or []):
        label = f"allowlist entry #{i + 1}"
        if not isinstance(raw, dict):
            raise RuleError(f"{label}: expected a mapping")
        unknown = sorted(set(raw) - {"description", "rules", "match"})
        if unknown:
            raise RuleError(f"{label}: unknown key(s): {', '.join(unknown)}")
        if not raw.get("match"):
            raise RuleError(f"{label}: needs a non-empty 'match' list (an entry without conditions would hide everything)")
        description = str(raw.get("description") or label)
        rules = raw.get("rules") or []
        if isinstance(rules, str):
            rules = [rules]
        entries.append(
            AllowEntry(
                description=description,
                match=[parse_condition(c, description) for c in raw["match"]],
                rules=[str(r) for r in rules],
            )
        )
    return entries


def load_allowlist(yaml_path: str | Path) -> list[AllowEntry]:
    with open(yaml_path, encoding="utf-8") as f:
        return parse_allowlist(yaml.safe_load(f))


def unknown_rule_references(entries: list[AllowEntry], rule_ids: set[str]) -> list[str]:
    """Rule ids an allowlist scopes to that don't exist (likely typos)."""
    return sorted({r for e in entries for r in e.rules} - rule_ids)


def apply_allowlist(flagged: pd.DataFrame, entries: list[AllowEntry]) -> tuple[pd.DataFrame, dict[str, int]]:
    """Drop flagged rows matching any entry.

    Returns (kept rows, {entry description: number of rows it suppressed}).
    A row matched by several entries is counted under the first one.
    """
    counts: dict[str, int] = {}
    if flagged.empty or not entries:
        return flagged, counts

    remaining = flagged
    for entry in entries:
        scope = remaining if not entry.rules else remaining[remaining["rule_id"].isin(entry.rules)]
        hits = filter_by_conditions(scope, entry.match, [])
        if hits.empty:
            continue
        counts[entry.description] = counts.get(entry.description, 0) + len(hits)
        remaining = remaining.drop(index=hits.index)
    return remaining.reset_index(drop=True), counts
