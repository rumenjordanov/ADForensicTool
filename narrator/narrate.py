"""
STUB -- not yet implemented. Turns a correlator.chain_builder.Chain into a
single plain-English, timestamp-anchored sentence for the Executive Summary
tab and (eventually) a narrative section of its own.

Target output, per the project spec, for a chain of
[brute_force -> privilege_escalation]:

    "02:14-02:51 - 47 failed logons against jsmith from 203.0.113.44,
    followed by a successful logon at 02:52 and addition to Domain Admins
    at 02:53."

--------------------------------------------------------------------------
Intended design:
--------------------------------------------------------------------------
1. One sentence-template per KNOWN_SEQUENCE in chain_builder.py, keyed by
   the tuple of rule_ids in the chain. Each template fills in from the
   chain's stages: actor identifiers (user/host/ip), per-stage timestamps,
   and any rule-specific detail worth surfacing (failed-logon count for
   brute force, target group name for privilege escalation, etc.) --
   note the detail fields aren't on ChainStage yet; pull them from the
   underlying flagged-event rows (raw_message / event_data) once this is
   wired up.

2. Sequences without a hand-written template should still produce a
   generic fallback sentence (e.g. "N events across M rule(s) involving
   <actor> between <start> and <end>") rather than crashing -- new
   detection rules will otherwise silently break narration until someone
   adds a template for the new sequence they can now form.

3. Keep this module free of any Excel/pandas-report formatting concerns --
   it should just return strings. excel_export/report.py decides where
   those strings get placed.

--------------------------------------------------------------------------
Open question to resolve before implementing:
--------------------------------------------------------------------------
- Do templates need to support partial/in-progress chains (e.g. brute force
  detected but the escalation stage hasn't happened, or the log ends mid-
  chain), or is narration only ever run against complete sequences?
"""
from __future__ import annotations

from correlator.chain_builder import Chain


def narrate_chain(chain: Chain) -> str:
    """TODO: implement per the design notes above.

    Returns a generic placeholder sentence for now so callers can be
    written against the final signature immediately.
    """
    actor_desc = ", ".join(f"{k}={v}" for k, v in chain.actor.items() if v)
    return (
        f"[narration not yet implemented] {len(chain.stages)} stage(s) "
        f"involving {actor_desc or 'unknown actor'} between "
        f"{chain.start_time} and {chain.end_time}"
    )
