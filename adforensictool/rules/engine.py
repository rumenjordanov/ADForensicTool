"""
Generic detection rule engine.

Loads rule definitions from a YAML file (see rules/default_rules.yaml for the
schema and comments) and applies them to a normalized event DataFrame
(the output of parser.evtx_parser.parse_evtx).

Rule types:

  - threshold:    N+ matching events for the same actor within a time window
                  (e.g. brute force: 5+ 4625s for one user in 10 minutes), or
                  N+ *distinct* values of some field per actor (e.g. password
                  spraying: one source IP failing against 10+ different users)
  - always_flag:  every matching event is inherently suspicious
                  (e.g. audit log cleared, privileged group membership change)
  - field_match:  a raw EventData field equals one of a set of values
                  (e.g. kerberoasting: TicketEncryptionType == RC4)
  - followed_by:  a matching event that happens shortly AFTER another rule
                  fired for the same actor (e.g. a successful logon within
                  an hour of a brute-force cluster against that account)

Every rule type also accepts `match:` (all conditions must hold) and
`exclude:` (any matching entry drops the event) condition lists, applied
before the type-specific logic. Conditions compare either a normalized
column (user, source_ip, ...) or a raw event_data field.

Linking flagged events from *different* rules into a single multi-stage
narrative is correlator/chain_builder.py's job; followed_by covers only the
"this event is suspicious *because* of what came before it" case.
"""
from __future__ import annotations

import bisect
import re
from collections import Counter
from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import timedelta
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

DEFAULT_RULES_PATH = Path(__file__).parent / "default_rules.yaml"

VALID_TYPES = {"threshold", "always_flag", "field_match", "followed_by"}
VALID_SEVERITIES = ("low", "medium", "high", "critical")
CONDITION_OPS = ("equals", "contains", "startswith", "endswith", "regex")

# Columns produced by parser.evtx_parser; a condition `field` naming one of
# these reads the normalized column, anything else reads event_data.
NORMALIZED_COLUMNS = {
    "event_id",
    "user",
    "user_sid",
    "subject_user",
    "target_group",
    "source_ip",
    "target_host",
    "logon_type",
    "process_name",
    "source_file",
}

FLAG_COLUMNS = ["rule_id", "rule_name", "severity", "mitre_technique", "cluster_id"]


class RuleError(ValueError):
    """A rules file is structurally invalid. Message names the offending rule."""


# --------------------------------------------------------------------------
# Value normalization
# --------------------------------------------------------------------------


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
            return value.casefold()
    return value


def actor_key(value: Any) -> str | None:
    """Canonical form of an account name for grouping/joining.

    The same account shows up as "jsmith", "JSmith", "CONTOSO\\jsmith" and
    "jsmith@CONTOSO.LOCAL" depending on the event ID; all of them should
    land in the same brute-force cluster or chain.
    """
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    text = str(value).strip()
    if not text:
        return None
    if "\\" in text:
        text = text.rsplit("\\", 1)[1]
    if "@" in text:
        text = text.split("@", 1)[0]
    return text.casefold() or None


def _group_key(value: Any) -> Any:
    if isinstance(value, str):
        return actor_key(value)
    return value


# --------------------------------------------------------------------------
# Conditions
# --------------------------------------------------------------------------


@dataclass
class Condition:
    field: str
    op: str
    values: list[Any]

    def __post_init__(self) -> None:
        if self.op == "regex":
            self._patterns = [re.compile(str(v), re.IGNORECASE) for v in self.values]
        elif self.op == "equals":
            self._targets = {_normalize_hex(str(v)) for v in self.values}
        else:
            self._needles = [str(v).casefold() for v in self.values]

    def test(self, value: Any) -> bool:
        if value is None or (isinstance(value, float) and pd.isna(value)):
            return False
        text = str(value)
        if self.op == "equals":
            return _normalize_hex(text) in self._targets
        if self.op == "regex":
            return any(p.search(text) for p in self._patterns)
        folded = text.casefold()
        if self.op == "contains":
            return any(n in folded for n in self._needles)
        if self.op == "startswith":
            return any(folded.startswith(n) for n in self._needles)
        return any(folded.endswith(n) for n in self._needles)


def _parse_condition(raw: Any, rule_id: str) -> Condition:
    if not isinstance(raw, dict) or "field" not in raw:
        raise RuleError(f"Rule '{rule_id}': each condition needs a 'field' and one of {', '.join(CONDITION_OPS)}")
    ops = [k for k in raw if k != "field"]
    if len(ops) != 1 or ops[0] not in CONDITION_OPS:
        raise RuleError(
            f"Rule '{rule_id}': condition on '{raw['field']}' must have exactly one of "
            f"{', '.join(CONDITION_OPS)} (got: {', '.join(ops) or 'none'})"
        )
    op = ops[0]
    values = raw[op]
    if not isinstance(values, list):
        values = [values]
    if not values:
        raise RuleError(f"Rule '{rule_id}': condition on '{raw['field']}' has an empty '{op}' list")
    try:
        return Condition(field=str(raw["field"]), op=op, values=values)
    except re.error as exc:
        raise RuleError(f"Rule '{rule_id}': invalid regex on '{raw['field']}': {exc}") from exc


def _parse_exclude(raw: Any, rule_id: str) -> list[list[Condition]]:
    """exclude entries are single conditions, or {all: [...]} for AND-groups."""
    if not isinstance(raw, list):
        raise RuleError(f"Rule '{rule_id}': 'exclude' must be a list")
    groups = []
    for entry in raw:
        if isinstance(entry, dict) and set(entry) == {"all"}:
            groups.append([_parse_condition(c, rule_id) for c in entry["all"]])
        else:
            groups.append([_parse_condition(entry, rule_id)])
    return groups


def _field_value(row: pd.Series, field: str) -> Any:
    if field in NORMALIZED_COLUMNS and field in row.index:
        return row[field]
    event_data = row.get("event_data")
    if isinstance(event_data, dict):
        return event_data.get(field)
    return None


def filter_by_conditions(
    df: pd.DataFrame, match: list[Condition], exclude: list[list[Condition]]
) -> pd.DataFrame:
    """Keep rows where every `match` condition holds and no `exclude` group does."""
    if df.empty or (not match and not exclude):
        return df

    def keep(row: pd.Series) -> bool:
        if not all(c.test(_field_value(row, c.field)) for c in match):
            return False
        return not any(all(c.test(_field_value(row, c.field)) for c in group) for group in exclude)

    return df[df.apply(keep, axis=1)]


# --------------------------------------------------------------------------
# Rule definition + loading
# --------------------------------------------------------------------------


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    mitre_technique: str
    type: str
    event_ids: list[int]
    description: str = ""
    match: list[Condition] = dc_field(default_factory=list)
    exclude: list[list[Condition]] = dc_field(default_factory=list)
    # threshold
    group_by: str | None = None
    window_minutes: float | None = None
    min_count: int | None = None
    distinct_field: str | None = None
    min_distinct: int | None = None
    # field_match (legacy single-condition form; folded into `match`)
    field: str | None = None
    equals: list[str] = dc_field(default_factory=list)
    # followed_by
    after: list[str] = dc_field(default_factory=list)
    within_minutes: float | None = None
    join_on: list[str] = dc_field(default_factory=lambda: ["user"])

    def __post_init__(self) -> None:
        if self.type not in VALID_TYPES:
            raise RuleError(f"Rule '{self.id}': unknown type '{self.type}' (valid: {', '.join(sorted(VALID_TYPES))})")
        if self.severity not in VALID_SEVERITIES:
            raise RuleError(f"Rule '{self.id}': severity must be one of {', '.join(VALID_SEVERITIES)}, got '{self.severity}'")
        if not self.event_ids or not all(isinstance(e, int) for e in self.event_ids):
            raise RuleError(f"Rule '{self.id}': event_ids must be a non-empty list of integers")

        if self.field or self.equals:
            if not (self.field and self.equals):
                raise RuleError(f"Rule '{self.id}': 'field' and 'equals' must be given together")
            self.match = [Condition(self.field, "equals", list(self.equals)), *self.match]

        if self.type == "threshold":
            if not (self.group_by and self.window_minutes and (self.min_count or self.min_distinct)):
                raise RuleError(f"Rule '{self.id}': threshold rules require group_by, window_minutes and min_count or min_distinct")
            if bool(self.distinct_field) != bool(self.min_distinct):
                raise RuleError(f"Rule '{self.id}': 'distinct_field' and 'min_distinct' must be given together")
        if self.type == "field_match" and not self.match:
            raise RuleError(f"Rule '{self.id}': field_match rules require field/equals or a 'match' list")
        if self.type == "followed_by" and not (self.after and self.within_minutes):
            raise RuleError(f"Rule '{self.id}': followed_by rules require 'after' and 'within_minutes'")


_RULE_KEYS = {
    "id", "name", "severity", "mitre_technique", "type", "event_ids", "description", "match", "exclude",
    "group_by", "window_minutes", "min_count", "distinct_field", "min_distinct",
    "field", "equals", "after", "within_minutes", "join_on",
}  # fmt: skip
_REQUIRED_KEYS = ("id", "name", "severity", "mitre_technique", "type", "event_ids")


def rule_from_dict(raw: Any, index: int = 0) -> Rule:
    if not isinstance(raw, dict):
        raise RuleError(f"Rule #{index + 1}: expected a mapping, got {type(raw).__name__}")
    rule_id = str(raw.get("id", f"#{index + 1}"))
    missing = [k for k in _REQUIRED_KEYS if k not in raw]
    if missing:
        raise RuleError(f"Rule '{rule_id}': missing required key(s): {', '.join(missing)}")
    unknown = sorted(set(raw) - _RULE_KEYS)
    if unknown:
        raise RuleError(f"Rule '{rule_id}': unknown key(s): {', '.join(unknown)}")

    kwargs = dict(raw)
    kwargs["id"] = rule_id
    kwargs["severity"] = str(raw["severity"]).lower()
    kwargs["mitre_technique"] = str(raw["mitre_technique"])
    if isinstance(kwargs["event_ids"], int):
        kwargs["event_ids"] = [kwargs["event_ids"]]
    if "equals" in kwargs and not isinstance(kwargs["equals"], list):
        kwargs["equals"] = [kwargs["equals"]]
    kwargs["match"] = [_parse_condition(c, rule_id) for c in raw.get("match") or []]
    kwargs["exclude"] = _parse_exclude(raw.get("exclude") or [], rule_id)
    for list_key in ("after", "join_on"):
        if list_key in kwargs and isinstance(kwargs[list_key], str):
            kwargs[list_key] = [kwargs[list_key]]
    return Rule(**kwargs)


def _order_rules(rules: list[Rule]) -> list[Rule]:
    """Validate cross-rule references and order rules so every followed_by
    rule runs after the rules it depends on (original order otherwise)."""
    by_id: dict[str, Rule] = {}
    for rule in rules:
        if rule.id in by_id:
            raise RuleError(f"Duplicate rule id '{rule.id}'")
        by_id[rule.id] = rule
    for rule in rules:
        for dep in rule.after:
            if dep not in by_id:
                raise RuleError(f"Rule '{rule.id}': 'after' references unknown rule '{dep}'")

    ordered: list[Rule] = []
    state: dict[str, str] = {}

    def visit(rule: Rule, path: list[str]) -> None:
        if state.get(rule.id) == "done":
            return
        if state.get(rule.id) == "visiting":
            raise RuleError(f"Circular 'after' dependency: {' -> '.join([*path, rule.id])}")
        state[rule.id] = "visiting"
        for dep in rule.after:
            visit(by_id[dep], [*path, rule.id])
        state[rule.id] = "done"
        ordered.append(rule)

    for rule in rules:
        visit(rule, [])
    return ordered


def parse_rules(data: Any) -> list[Rule]:
    if data is None:
        return []
    if not isinstance(data, dict) or not isinstance(data.get("rules", []), list):
        raise RuleError("Rules file must be a mapping with a top-level 'rules' list")
    rules = [rule_from_dict(raw, i) for i, raw in enumerate(data.get("rules") or [])]
    return _order_rules(rules)


def load_rules(yaml_path: str | Path) -> list[Rule]:
    with open(yaml_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return parse_rules(data)


def merge_rules(*rule_lists: list[Rule]) -> list[Rule]:
    """Combine rule sets (e.g. YAML + converted Sigma), re-validating ids/deps."""
    return _order_rules([r for rules in rule_lists for r in rules])


# --------------------------------------------------------------------------
# Rule type implementations
# --------------------------------------------------------------------------


def _candidates(df: pd.DataFrame, rule: Rule) -> pd.DataFrame:
    subset = df[df["event_id"].isin(rule.event_ids)]
    return filter_by_conditions(subset, rule.match, rule.exclude).copy()


def _apply_threshold(df: pd.DataFrame, rule: Rule, _flagged: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Flag events forming a qualifying cluster within window_minutes.

    A window qualifies when it holds >= min_count events and/or >= min_distinct
    distinct values of distinct_field (whichever are configured). Clusters
    are computed per group_by value (account names compared
    case/domain-insensitively) using a sliding window over sorted timestamps,
    then adjacent qualifying windows are merged so each contiguous burst
    gets a single cluster_id rather than many overlapping ones.
    """
    subset = _candidates(df, rule)
    if subset.empty or rule.group_by not in subset.columns:
        return subset.iloc[0:0]
    # An event with no timestamp can't sit inside a time window; left in,
    # NaT comparisons are always False, so it would silently join whatever
    # cluster happened to be open.
    subset = subset[subset["timestamp"].notna()]

    window = timedelta(minutes=rule.window_minutes)
    flagged_frames = []
    cluster_counter = 0
    group_keys = subset[rule.group_by].map(_group_key)

    for _, group in subset.groupby(group_keys, dropna=True):
        group = group.sort_values("timestamp").reset_index(drop=True)
        timestamps = group["timestamp"]
        distinct_values = (
            [_group_key(_field_value(row, rule.distinct_field)) for _, row in group.iterrows()]
            if rule.distinct_field
            else None
        )
        seen: Counter = Counter()
        left = 0
        cluster_ranges: list[list[int]] = []

        for right in range(len(group)):
            if distinct_values is not None and distinct_values[right] is not None:
                seen[distinct_values[right]] += 1
            while timestamps[right] - timestamps[left] > window:
                if distinct_values is not None and distinct_values[left] is not None:
                    seen[distinct_values[left]] -= 1
                    if not seen[distinct_values[left]]:
                        del seen[distinct_values[left]]
                left += 1

            qualifies = (rule.min_count is None or right - left + 1 >= rule.min_count) and (
                rule.min_distinct is None or len(seen) >= rule.min_distinct
            )
            if qualifies:
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


def _apply_always_flag(df: pd.DataFrame, rule: Rule, _flagged: dict[str, pd.DataFrame]) -> pd.DataFrame:
    return _candidates(df, rule)


def _join_keys(row: pd.Series, columns: list[str]) -> set[str]:
    keys = set()
    for col in columns:
        key = actor_key(_field_value(row, col))
        if key:
            keys.add(f"{col}:{key}")
    return keys


def _apply_followed_by(df: pd.DataFrame, rule: Rule, flagged: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Flag candidate events within within_minutes AFTER an event flagged by
    any of rule.after, sharing a join_on value (e.g. the same user)."""
    priors = [flagged[r] for r in rule.after if r in flagged and not flagged[r].empty]
    subset = _candidates(df, rule)
    if subset.empty or not priors:
        return subset.iloc[0:0]

    prior_times: dict[str, list[pd.Timestamp]] = {}
    for prior in priors:
        for _, row in prior.iterrows():
            if pd.isna(row["timestamp"]):
                continue
            for key in _join_keys(row, rule.join_on):
                prior_times.setdefault(key, []).append(row["timestamp"])
    for times in prior_times.values():
        times.sort()

    window = timedelta(minutes=rule.within_minutes)

    def follows(row: pd.Series) -> bool:
        ts = row["timestamp"]
        if pd.isna(ts):
            return False
        for key in _join_keys(row, rule.join_on):
            times = prior_times.get(key)
            if not times:
                continue
            idx = bisect.bisect_right(times, ts) - 1
            if idx >= 0 and ts - times[idx] <= window:
                return True
        return False

    return subset[subset.apply(follows, axis=1)]


_DISPATCH = {
    "threshold": _apply_threshold,
    "always_flag": _apply_always_flag,
    "field_match": _apply_always_flag,  # match conditions already did the work
    "followed_by": _apply_followed_by,
}


def apply_rules(df: pd.DataFrame, rules: list[Rule]) -> pd.DataFrame:
    """Run every rule against df, returning one combined DataFrame of flagged
    events tagged with which rule(s) fired, in timestamp order.

    Each output row carries: all original event columns, plus rule_id,
    rule_name, severity, mitre_technique, and cluster_id (empty string for
    non-threshold rules). An event that trips several rules appears once
    per rule.
    """
    flagged_by_rule: dict[str, pd.DataFrame] = {}
    results = []
    for rule in _order_rules(rules):
        if df.empty:
            break
        flagged = _DISPATCH[rule.type](df, rule, flagged_by_rule)
        flagged_by_rule[rule.id] = flagged
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
        return pd.DataFrame(columns=list(df.columns) + FLAG_COLUMNS)
    combined = pd.concat(results, ignore_index=True)
    combined.sort_values("timestamp", kind="stable", inplace=True, ignore_index=True)
    return combined
