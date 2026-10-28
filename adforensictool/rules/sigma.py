"""
Converts a practical subset of Sigma rules (https://sigmahq.io) for the
Windows Security/System logs into engine Rules, so community detections can
run alongside default_rules.yaml.

Supported
---------
- logsource: product windows, service security or system (-> rule channels)
- detection: named search identifiers whose value is a field map. A list
  value means "any of"; field modifiers contains / startswith / endswith /
  re, optionally with |all (every value must match). Plain values may use
  Sigma wildcards * and ?.
- condition: terms joined by "and", where a term is one of
      sel                 not sel
      all of sel*         not 1 of filter*        not (f1 or f2 ...)
  Positive terms become the rule's `match` list (EventID -> event_ids);
  negated ones become `exclude` groups.
- level -> severity (informational -> low); first attack.tNNNN[.NNN] tag ->
  mitre_technique.

Anything else (OR across positive selections, keyword lists, count/
aggregation conditions, other log sources, rules without an EventID) is
skipped with a reason rather than converted approximately: a rule that
silently matches more or less than its author intended is worse than no
rule.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from adforensictool.rules.engine import Condition, Rule, RuleError

SERVICE_CHANNELS = {"security": "Security", "system": "System"}
LEVELS = {"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
MODIFIER_OPS = {"contains": "contains", "startswith": "startswith", "endswith": "endswith", "re": "regex"}
FIELD_NAMES = {"eventid": "event_id"}  # Sigma field -> engine field, where they differ

_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_IDENT = r"[A-Za-z_][A-Za-z0-9_]*\*?"


class SigmaUnsupported(Exception):
    """This rule uses Sigma features outside the supported subset."""


@dataclass
class SigmaResult:
    rules: list[Rule]
    skipped: list[tuple[str, str]]  # (file, reason)


def _wildcard_to_regex(value: str) -> str:
    parts = []
    for ch in value:
        parts.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return "^" + "".join(parts) + "$"


def _conditions_for(field_spec: str, value: Any) -> tuple[str, list[Condition]]:
    """One Sigma `field|mod|mod: value(s)` entry -> (engine field, conditions)."""
    field, *mods = field_spec.split("|")
    field = FIELD_NAMES.get(field.lower(), field)
    values = value if isinstance(value, list) else [value]
    if not values or any(v is None or isinstance(v, dict | list) for v in values):
        raise SigmaUnsupported(f"unsupported value for field '{field_spec}'")
    values = [str(v).lower() if isinstance(v, bool) else str(v) for v in values]

    match_all = "all" in mods
    mods = [m for m in mods if m != "all"]
    if len(mods) > 1 or (mods and mods[0] not in MODIFIER_OPS):
        raise SigmaUnsupported(f"unsupported modifier(s) in '{field_spec}'")

    if mods:
        op = MODIFIER_OPS[mods[0]]
        conditions = [Condition(field, op, [v]) for v in values] if match_all else [Condition(field, op, values)]
        return field, conditions

    if match_all:
        raise SigmaUnsupported(f"'|all' without another modifier in '{field_spec}'")
    plain = [v for v in values if "*" not in v and "?" not in v]
    wild = [_wildcard_to_regex(v) for v in values if "*" in v or "?" in v]
    if plain and wild:
        # OR of an equals and a regex in one condition: fold equals into the regex
        wild += ["^" + re.escape(v) + "$" for v in plain]
        plain = []
    return field, [Condition(field, "equals", plain)] if plain else [Condition(field, "regex", wild)]


def _selection_conditions(name: str, selection: Any) -> list[Condition]:
    if not isinstance(selection, dict) or not selection:
        raise SigmaUnsupported(f"search identifier '{name}' is not a field map (lists/keywords are unsupported)")
    conditions: list[Condition] = []
    for field_spec, value in selection.items():
        conditions += _conditions_for(str(field_spec), value)[1]
    return conditions


def _expand(term: str, detection: dict[str, Any]) -> list[str]:
    if term.endswith("*"):
        names = [n for n in detection if n != "condition" and n.startswith(term[:-1])]
        if not names:
            raise SigmaUnsupported(f"condition pattern '{term}' matches no search identifier")
        return names
    if term not in detection or term == "condition":
        raise SigmaUnsupported(f"condition references unknown identifier '{term}'")
    return [term]


def _parse_condition(condition: str, detection: dict[str, Any]) -> tuple[list[str], list[str]]:
    """-> (positive identifiers, negated identifiers)."""
    if "|" in condition:
        raise SigmaUnsupported("aggregation conditions (| count() ...) are unsupported")
    positive: list[str] = []
    negative: list[str] = []
    for raw_term in re.split(r"\s+and\s+", condition.strip()):
        term = raw_term.strip()
        if m := re.fullmatch(rf"not\s+\(\s*({_IDENT}(?:\s+or\s+{_IDENT})*)\s*\)", term):
            for name in re.split(r"\s+or\s+", m.group(1)):
                negative += _expand(name, detection)
        elif m := re.fullmatch(rf"not\s+1\s+of\s+({_IDENT})", term):
            negative += _expand(m.group(1), detection)
        elif m := re.fullmatch(rf"not\s+({_IDENT})", term):
            if m.group(1).endswith("*"):
                raise SigmaUnsupported(f"ambiguous negated pattern '{term}'")
            negative += _expand(m.group(1), detection)
        elif m := re.fullmatch(rf"all\s+of\s+({_IDENT})", term):
            positive += _expand(m.group(1), detection)
        elif m := re.fullmatch(rf"1\s+of\s+({_IDENT})", term):
            names = _expand(m.group(1), detection)
            if len(names) != 1:
                raise SigmaUnsupported(f"'{term}' is an OR across selections, which is unsupported")
            positive += names
        elif re.fullmatch(_IDENT, term) and not term.endswith("*"):
            positive += _expand(term, detection)
        else:
            raise SigmaUnsupported(f"unsupported condition syntax: '{term}'")
    if not positive:
        raise SigmaUnsupported("condition has no positive selection")
    return positive, negative


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:50] or "rule"


def sigma_to_rule(doc: Any, source: str = "") -> Rule:
    """Convert one parsed Sigma document to a Rule, or raise SigmaUnsupported."""
    if not isinstance(doc, dict) or "detection" not in doc:
        raise SigmaUnsupported("not a Sigma detection rule")
    logsource = doc.get("logsource") or {}
    if str(logsource.get("product", "")).lower() != "windows":
        raise SigmaUnsupported(f"logsource product '{logsource.get('product')}' (only windows is supported)")
    service = str(logsource.get("service", "")).lower()
    if service not in SERVICE_CHANNELS:
        raise SigmaUnsupported(f"logsource service '{logsource.get('service') or logsource.get('category')}' (only security/system)")

    detection = doc["detection"]
    if not isinstance(detection, dict) or not isinstance(detection.get("condition"), str):
        raise SigmaUnsupported("detection needs a single string condition")
    if "timeframe" in detection:
        raise SigmaUnsupported("timeframe/aggregation rules are unsupported")
    positive, negative = _parse_condition(detection["condition"], detection)

    match: list[Condition] = []
    event_ids: list[int] = []
    for name in positive:
        for cond in _selection_conditions(name, detection[name]):
            if cond.field == "event_id" and cond.op == "equals":
                ids = [int(v) for v in cond.values if str(v).isdigit()]
                if len(ids) != len(cond.values):
                    raise SigmaUnsupported("non-numeric EventID")
                event_ids = sorted(set(event_ids) & set(ids)) if event_ids else ids
                if not event_ids:
                    raise SigmaUnsupported("positive selections require disjoint EventIDs (never matches)")
            else:
                match.append(cond)
    if not event_ids:
        raise SigmaUnsupported("no EventID in the positive selection(s)")
    exclude = [_selection_conditions(name, detection[name]) for name in negative]

    level = str(doc.get("level", "medium")).lower()
    if level not in LEVELS:
        raise SigmaUnsupported(f"unknown level '{level}'")
    technique = next(
        (m.group(1).upper() for tag in doc.get("tags") or [] if (m := _TECHNIQUE_TAG.match(str(tag)))), "Sigma"
    )
    title = str(doc.get("title") or Path(source).stem or "Sigma rule")
    rule_id = "sigma_" + (_slug(str(doc["id"]))[:12] + "_" if doc.get("id") else "") + _slug(title)

    try:
        return Rule(
            id=rule_id,
            name=f"{title} (Sigma)",
            severity=LEVELS[level],
            mitre_technique=technique,
            type="field_match" if match else "always_flag",
            event_ids=event_ids,
            description=str(doc.get("description") or "").strip(),
            channels=[SERVICE_CHANNELS[service]],
            match=match,
            exclude=exclude,
        )
    except RuleError as exc:
        raise SigmaUnsupported(str(exc)) from exc


def load_sigma(paths: list[str]) -> SigmaResult:
    """Convert every Sigma rule file under `paths` (files or directories,
    *.yml / *.yaml recursively). Files that can't be converted are listed in
    `skipped` with the reason, never silently dropped."""
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files += sorted((p for p in path.rglob("*") if p.suffix.lower() in (".yml", ".yaml")), key=lambda p: str(p).casefold())
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(f"Sigma path not found: {path}")

    rules: list[Rule] = []
    skipped: list[tuple[str, str]] = []
    seen_ids: set[str] = set()
    for file in files:
        try:
            docs = [d for d in yaml.safe_load_all(file.read_text(encoding="utf-8")) if d is not None]
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            skipped.append((str(file), f"unreadable YAML: {exc.__class__.__name__}"))
            continue
        if len(docs) != 1:
            skipped.append((str(file), "multi-document Sigma rule collections are unsupported"))
            continue
        try:
            rule = sigma_to_rule(docs[0], str(file))
        except (SigmaUnsupported, re.error) as exc:
            skipped.append((str(file), str(exc)))
            continue
        if rule.id in seen_ids:
            skipped.append((str(file), f"duplicate rule id '{rule.id}'"))
            continue
        seen_ids.add(rule.id)
        rules.append(rule)
    return SigmaResult(rules, skipped)
