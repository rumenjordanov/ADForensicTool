from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from adforensictool.parser.evtx_parser import normalize_record
from adforensictool.rules.allowlist import apply_allowlist, load_allowlist, parse_allowlist, unknown_rule_references
from adforensictool.rules.engine import DEFAULT_RULES_PATH, RuleError, apply_rules, load_rules
from tests.fixtures.sample_events import directory_access_xml, failed_logon_xml, successful_logon_xml

EXAMPLE_ALLOWLIST = Path(__file__).parent.parent / "examples" / "allowlist.example.yaml"


@pytest.fixture(scope="module")
def rules():
    return load_rules(DEFAULT_RULES_PATH)


def _flag(rules, xml):
    return apply_rules(pd.DataFrame([normalize_record(x) for x in xml]), rules)


def _brute_force(user="jsmith", ip="203.0.113.44"):
    return [failed_logon_xml(f"2026-06-08T02:1{i}:00Z", user=user, ip=ip) for i in range(5)]


def test_suppresses_matching_events_and_counts_them(rules):
    flagged = _flag(rules, _brute_force(ip="10.0.0.50") + _brute_force(user="jdoe"))
    entries = parse_allowlist(
        {"allowlist": [{"description": "scanner", "match": [{"field": "source_ip", "equals": "10.0.0.50"}]}]}
    )
    kept, counts = apply_allowlist(flagged, entries)
    assert set(kept["user"]) == {"jdoe"}
    assert counts == {"scanner": 5}


def test_rule_scope_limits_suppression(rules):
    xml = _brute_force(ip="10.0.0.50") + [directory_access_xml("2026-06-08T03:00:00Z", performed_by="jsmith")]
    flagged = _flag(rules, xml)
    entries = parse_allowlist(
        {"allowlist": [{"description": "only dcsync", "rules": "dcsync", "match": [{"field": "user", "equals": "jsmith"}]}]}
    )
    kept, counts = apply_allowlist(flagged, entries)
    assert set(kept["rule_id"]) == {"brute_force"}
    assert counts == {"only dcsync": 1}


def test_suppressing_a_scanner_does_not_hide_a_compromise_that_follows(rules):
    """Allowlisting runs after every rule fired, so 'logon after brute force'
    still fires even when the brute force itself is allowlisted."""
    xml = _brute_force(ip="10.0.0.50") + [successful_logon_xml("2026-06-08T02:30:00Z", ip="203.0.113.99")]
    flagged = _flag(rules, xml)
    entries = parse_allowlist(
        {"allowlist": [{"description": "scanner", "rules": ["brute_force"], "match": [{"field": "source_ip", "equals": "10.0.0.50"}]}]}
    )
    kept, _ = apply_allowlist(flagged, entries)
    assert list(kept["rule_id"]) == ["logon_after_brute_force"]


def test_no_entries_or_no_flags_is_a_no_op(rules):
    flagged = _flag(rules, _brute_force())
    assert apply_allowlist(flagged, [])[0] is flagged
    empty = flagged.iloc[0:0]
    kept, counts = apply_allowlist(empty, parse_allowlist({"allowlist": [{"match": [{"field": "user", "equals": "x"}]}]}))
    assert kept.empty and counts == {}


@pytest.mark.parametrize(
    "data, message",
    [
        ({"allowlist": [{"description": "everything"}]}, "non-empty 'match'"),
        ({"allowlist": [{"match": [{"field": "user", "equals": "x"}], "rule": "typo"}]}, "unknown key(s): rule"),
        ({"allowlist": ["just a string"]}, "expected a mapping"),
        (["not", "a", "mapping"], "top-level 'allowlist' list"),
    ],
)
def test_invalid_allowlists(data, message):
    with pytest.raises(RuleError) as exc_info:
        parse_allowlist(data)
    assert message in str(exc_info.value)


def test_unknown_rule_references(rules):
    entries = parse_allowlist({"allowlist": [{"rules": ["brute_force", "brute_forse"], "match": [{"field": "user", "equals": "x"}]}]})
    assert unknown_rule_references(entries, {r.id for r in rules}) == ["brute_forse"]


def test_example_allowlist_is_valid(rules):
    entries = load_allowlist(EXAMPLE_ALLOWLIST)
    assert entries
    assert unknown_rule_references(entries, {r.id for r in rules}) == []
