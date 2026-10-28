from __future__ import annotations

import textwrap
from pathlib import Path

import pandas as pd
import pytest
import yaml

from adforensictool.parser.evtx_parser import normalize_record
from adforensictool.rules.engine import DEFAULT_RULES_PATH, apply_rules, load_rules, merge_rules
from adforensictool.rules.sigma import SigmaUnsupported, load_sigma, sigma_to_rule
from tests.fixtures.sample_events import (
    failed_logon_xml,
    kerberoasting_xml,
    make_event_xml,
    service_installed_xml,
    system_service_installed_xml,
)

EXAMPLE_SIGMA_DIR = Path(__file__).parent.parent / "examples" / "sigma"

KERBEROAST = textwrap.dedent(
    """
    title: Suspicious Kerberos RC4 Ticket Encryption
    id: 496a0e47-0a33-4dca-b009-9e6ca3591f39
    status: test
    logsource:
        product: windows
        service: security
    detection:
        selection:
            EventID: 4769
            TicketOptions: '0x40810000'
            TicketEncryptionType: '0x17'
        reduction:
            - ServiceName|endswith: '$'
        condition: selection and not reduction
    level: medium
    tags:
        - attack.credential_access
        - attack.t1558.003
    """
)


def _rule(text: str):
    return sigma_to_rule(yaml.safe_load(textwrap.dedent(text)))


def _flag(rules, xml):
    return apply_rules(pd.DataFrame([normalize_record(x) for x in xml]), rules)


def _sigma(detection: str, service: str = "security", extra: str = "") -> str:
    return f"title: T\nlogsource:\n  product: windows\n  service: {service}\ndetection:\n{textwrap.indent(textwrap.dedent(detection), '  ')}{extra}"


# -- conversion ----------------------------------------------------------------------------


def test_metadata_mapping():
    rule = _rule(
        _sigma(
            """
            selection:
              EventID: [4625, 4771]
            condition: selection
            """,
            extra="level: informational\ntags: [attack.credential_access, attack.t1110.001]\n",
        )
    )
    assert rule.event_ids == [4625, 4771]
    assert rule.severity == "low"
    assert rule.mitre_technique == "T1110.001"
    assert rule.channels == ["Security"]
    assert rule.type == "always_flag"
    assert rule.id.startswith("sigma_") and rule.name == "T (Sigma)"


def test_list_of_maps_selection_is_rejected_not_approximated():
    """SigmaHQ's real kerberoasting rule writes its filter as a list of maps
    (OR of alternatives); that shape is outside the subset and must be
    skipped with a reason rather than mis-converted."""
    with pytest.raises(SigmaUnsupported, match="not a field map"):
        sigma_to_rule(yaml.safe_load(KERBEROAST))


@pytest.mark.parametrize(
    "detection, user, fires",
    [
        ("selection:\n  EventID: 4625\n  TargetUserName: JSMITH\ncondition: selection", "jsmith", True),
        ("selection:\n  EventID: 4625\n  TargetUserName: [a, jsmith]\ncondition: selection", "jsmith", True),
        ("selection:\n  EventID: 4625\n  TargetUserName: 'j*th'\ncondition: selection", "jsmith", True),
        ("selection:\n  EventID: 4625\n  TargetUserName: 'j?mith'\ncondition: selection", "jsmith", True),
        ("selection:\n  EventID: 4625\n  TargetUserName: 'j?ith'\ncondition: selection", "jsmith", False),  # ? = one char
        ("selection:\n  EventID: 4625\n  TargetUserName|contains: smi\ncondition: selection", "jsmith", True),
        ("selection:\n  EventID: 4625\n  TargetUserName|startswith: js\ncondition: selection", "jsmith", True),
        ("selection:\n  EventID: 4625\n  TargetUserName|re: '^j.*h$'\ncondition: selection", "jsmith", True),
        ("selection:\n  EventID: 4625\n  TargetUserName|contains|all: [js, th]\ncondition: selection", "jsmith", True),
        ("selection:\n  EventID: 4625\n  TargetUserName|contains|all: [js, xx]\ncondition: selection", "jsmith", False),
        ("selection:\n  EventID: 4625\nfilter:\n  TargetUserName: jsmith\ncondition: selection and not filter", "jsmith", False),
        ("selection:\n  EventID: 4625\nf_a:\n  TargetUserName: x\nf_b:\n  TargetUserName: jsmith\ncondition: selection and not 1 of f_*", "jsmith", False),
        ("selection:\n  EventID: 4625\nf_a:\n  TargetUserName: x\nf_b:\n  TargetUserName: jsmith\ncondition: selection and not (f_a or f_b)", "jsmith", False),
        ("sel_id:\n  EventID: 4625\nsel_user:\n  TargetUserName: jsmith\ncondition: all of sel_*", "jsmith", True),
        ("sel_id:\n  EventID: 4625\nsel_user:\n  TargetUserName: other\ncondition: all of sel_*", "jsmith", False),
        ("selection:\n  EventID: 4625\n  Status: '0xC000006D'\ncondition: selection", "jsmith", True),
    ],
)
def test_detection_semantics(detection, user, fires):
    rule = _rule(_sigma(detection))
    assert (len(_flag([rule], [failed_logon_xml("2026-06-08T02:10:00Z", user=user)])) == 1) is fires


@pytest.mark.parametrize(
    "text, reason",
    [
        (_sigma("selection:\n  EventID: 4625\ncondition: selection | count() > 5"), "aggregation"),
        (_sigma("keywords:\n  - mimikatz\ncondition: keywords"), "not a field map"),
        (_sigma("a:\n  EventID: 4625\nb:\n  EventID: 4624\ncondition: a or b"), "unsupported condition syntax"),
        (_sigma("a:\n  EventID: 4625\nb:\n  EventID: 4624\ncondition: 1 of z*"), "matches no search identifier"),
        (_sigma("sel_a:\n  EventID: 4625\nsel_b:\n  EventID: 4624\ncondition: 1 of sel_*"), "OR across selections"),
        (_sigma("selection:\n  TargetUserName: x\ncondition: selection"), "no EventID"),
        (_sigma("selection:\n  EventID: 4625\ncondition: selection", service="powershell"), "only security/system"),
        (_sigma("selection:\n  EventID: 4625\n  X|base64offset|contains: y\ncondition: selection"), "unsupported modifier"),
        (_sigma("selection:\n  EventID: 4625\n  X: null\ncondition: selection"), "unsupported value"),
        (_sigma("selection:\n  EventID: 4625\ncondition: not selection"), "no positive selection"),
        (_sigma("selection:\n  EventID: 4625\ncondition: selection and missing"), "unknown identifier"),
    ],
)
def test_unsupported_rules_are_rejected_with_reasons(text, reason):
    with pytest.raises(SigmaUnsupported, match=reason):
        _rule(text)


def test_system_service_maps_to_system_channel():
    rule = _rule(_sigma("selection:\n  EventID: 7045\n  ServiceName: PSEXESVC\ncondition: selection", service="system"))
    assert rule.channels == ["System"]
    assert len(_flag([rule], [system_service_installed_xml("2026-06-08T02:10:00Z")])) == 1
    # the same Event ID logged in the Security channel is not this rule's event
    assert _flag([rule], [make_event_xml(7045, "2026-06-08T02:10:00Z", data={"ServiceName": "PSEXESVC"})]).empty


# -- loading files ----------------------------------------------------------------------------


def test_load_sigma_directory_reports_skips(tmp_path):
    (tmp_path / "good.yml").write_text(_sigma("selection:\n  EventID: 4697\n  ServiceName: PSEXESVC\ncondition: selection"))
    (tmp_path / "kerberoast.yml").write_text(KERBEROAST)
    (tmp_path / "broken.yaml").write_text("title: [unclosed")
    (tmp_path / "multi.yml").write_text(_sigma("selection:\n  EventID: 1\ncondition: selection") + "\n---\ntitle: second\n")
    (tmp_path / "readme.md").write_text("not a rule")

    result = load_sigma([str(tmp_path)])
    assert [r.name for r in result.rules] == ["T (Sigma)"]
    reasons = {Path(f).name: why for f, why in result.skipped}
    assert set(reasons) == {"kerberoast.yml", "broken.yaml", "multi.yml"}
    assert "unreadable YAML" in reasons["broken.yaml"]
    assert "multi-document" in reasons["multi.yml"]

    merged = merge_rules(load_rules(DEFAULT_RULES_PATH), result.rules)
    hits = _flag(merged, [service_installed_xml("2026-06-08T02:10:00Z")])
    assert set(hits["rule_name"]) == {"Service Installed", "T (Sigma)"}


def test_load_sigma_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_sigma([str(tmp_path / "nope")])


def test_example_sigma_rules_convert_and_fire():
    result = load_sigma([str(EXAMPLE_SIGMA_DIR)])
    assert result.skipped == []
    assert len(result.rules) >= 2
    xml = [kerberoasting_xml("2026-06-08T02:10:00Z", user="jsmith", service="MSSQLSvc/db01")]
    xml += [kerberoasting_xml("2026-06-08T02:11:00Z", user="jsmith", service="FILE01$")]
    hits = _flag(result.rules, xml)
    assert len(hits[hits["rule_name"].str.contains("RC4")]) == 1
