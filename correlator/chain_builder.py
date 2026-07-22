"""
STUB -- not yet implemented. Links flagged events (rules.engine.apply_rules
output) into multi-stage "attack chains" spanning different detection rules.

Right now, rules/engine.py flags events one rule at a time and has no
concept of "the brute force on jsmith and the group-membership change on
jsmith are the same incident." That's what this module needs to add.

--------------------------------------------------------------------------
Intended design (for whoever picks this up next):
--------------------------------------------------------------------------

1. Group flagged events by shared actor: same `user`, same `target_host`, or
   same `source_ip` -- these are the threads a real intrusion leaves across
   otherwise-unrelated rule firings.

2. Within a configurable time window (e.g. 30-60 min, wider than any single
   rule's own window_minutes since escalation can lag the initial access),
   look for flagged events matching a known attack SEQUENCE, not just any
   co-occurrence. Sequence, not just proximity, is what turns "some flagged
   events near each other" into "an attack chain" -- e.g.:

     KNOWN_SEQUENCES = [
         ["brute_force", "privilege_escalation"],
         ["brute_force", "kerberoasting"],
         ["privilege_escalation", "audit_log_cleared"],
         # add: successful-logon-after-brute-force, then
         # new-service-or-scheduled-task-after-suspicious-logon, once those
         # two rules exist (they need correlation to detect at all -- see
         # the note in rules/default_rules.yaml).
     ]

   A chain is a maximal run of flagged events, for one actor, whose rule_ids
   (in timestamp order) match a prefix of one of these sequences.

3. Each resulting Chain gets:
   - severity: max severity across its stages (critical > high > medium > low)
   - a MITRE technique per stage, taken directly from the stage's rule
     (rules already carry mitre_technique -- no new mapping needed here)
   - start_time / end_time spanning its first and last event

4. Output feeds two consumers:
   - excel_export/report.py's Attack Chains tab (replacing the per-rule
     grouping it falls back to today)
   - narrator/narrate.py, which turns each Chain into the plain-English
     sentence described in that module's docstring

--------------------------------------------------------------------------
Open questions to resolve before implementing (don't guess silently):
--------------------------------------------------------------------------
- Should actor-matching require ALL of user/host/ip to match, or ANY one of
  them? (ANY is more sensitive but risks stitching together unrelated
  events for shared infra like a jump host.)
- Should a single flagged event ever belong to more than one chain?
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd


@dataclass
class ChainStage:
    rule_id: str
    rule_name: str
    mitre_technique: str
    timestamp: pd.Timestamp
    event_id: int


@dataclass
class Chain:
    id: str
    actor: dict[str, str | None]  # e.g. {"user": "jsmith", "source_ip": "203.0.113.44"}
    stages: list[ChainStage] = field(default_factory=list)
    severity: str = "low"
    start_time: pd.Timestamp | None = None
    end_time: pd.Timestamp | None = None


def build_chains(flagged: pd.DataFrame, window_minutes: float = 30) -> list[Chain]:
    """TODO: implement per the design notes above.

    Returns an empty list for now so callers (main.py, excel_export) can be
    written against the final signature immediately without waiting on this
    module -- an empty chain list is a valid, honest answer for "no
    correlation logic exists yet," not an error.
    """
    return []
