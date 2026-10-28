"""
Turns a correlator.chain_builder.Chain into plain-English, timestamp-anchored
text for the report, e.g. for [brute_force -> logon_after_brute_force ->
privilege_escalation]:

    "2026-06-08 02:14-02:53 UTC: 47 failed logons against jsmith from
    203.0.113.44 (02:14-02:51), followed by a successful logon as jsmith at
    02:52 and jsmith added to Domain Admins by administrator at 02:53."

Design
------
- One phrase builder per rule id, pulling detail (counts, group names,
  service/task names, who did it) from the stage's underlying flagged
  events. Rules without a builder get a generic phrase, so new detection
  rules never break narration.
- Phrases are built per stage rather than per known sequence, so partial or
  in-progress chains (brute force + logon, but the log ends before any
  escalation) and sequences nobody anticipated narrate just as well.
- Consecutive stages of the same rule are merged into one phrase ("3 RC4
  service tickets requested ..." instead of three separate clauses).
- An event that tripped several rules (a 4697 is both service_installed and
  persistence_after_suspicious_logon) is described once, under its most
  severe rule.
- No Excel/report concerns here: everything returns plain strings.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import tzinfo

import pandas as pd

from adforensictool.correlator.chain_builder import SEVERITY_RANK, Chain, ChainStage

_MAX_LISTED = 3  # list at most this many names before summarizing as "and N more"


class _Clock:
    """Formats timestamps for one chain: HH:MM when the chain fits in a
    single day, otherwise MM-DD HH:MM; converted to the display timezone."""

    def __init__(self, chain: Chain, tz: tzinfo | None) -> None:
        self.tz = tz
        start, end = self._local(chain.start_time), self._local(chain.end_time)
        self.multi_day = start.date() != end.date()

    def _local(self, ts: pd.Timestamp) -> pd.Timestamp:
        return ts.tz_convert(self.tz) if self.tz is not None else ts

    def time(self, ts: pd.Timestamp) -> str:
        return self._local(ts).strftime("%m-%d %H:%M" if self.multi_day else "%H:%M")

    def span(self, start: pd.Timestamp, end: pd.Timestamp) -> str:
        a, b = self.time(start), self.time(end)
        return f"at {a}" if a == b else f"({a}-{b})"

    def zone_name(self, ts: pd.Timestamp) -> str:
        return self._local(ts).strftime("%Z") or "UTC"


def _names(values: list[str]) -> str:
    values = [v for v in values if v]
    if not values:
        return "an unknown account"
    if len(values) <= _MAX_LISTED:
        return ", ".join(values[:-1]) + (" and " if len(values) > 1 else "") + values[-1]
    return f"{', '.join(values[:_MAX_LISTED])} and {len(values) - _MAX_LISTED} more"


def _column(events: pd.DataFrame, column: str) -> list[str]:
    if column not in events:
        return []
    return list(dict.fromkeys(str(v) for v in events[column] if v is not None and not pd.isna(v) and str(v).strip()))


def _field(events: pd.DataFrame, name: str) -> list[str]:
    if "event_data" not in events:
        return []
    values = (d.get(name) if isinstance(d, dict) else None for d in events["event_data"])
    return list(dict.fromkeys(v for v in values if v and v != "-"))


def _by(events: pd.DataFrame) -> str:
    subjects = _column(events, "subject_user")
    return f" by {_names(subjects)}" if subjects else ""


Phrase = Callable[[pd.DataFrame, str], str]


def _brute_force(ev: pd.DataFrame, when: str) -> str:
    ips = _column(ev, "source_ip")
    origin = f" from {_names(ips)}" if ips else ""
    return f"{len(ev)} failed logons against {_names(_column(ev, 'user'))}{origin} {when}"


def _password_spray(ev: pd.DataFrame, when: str) -> str:
    users = _column(ev, "user")
    return f"password spraying from {_names(_column(ev, 'source_ip'))}: {len(ev)} failed logons against {len(users)} different accounts {when}"


def _lockout(ev: pd.DataFrame, when: str) -> str:
    return f"{_names(_column(ev, 'user'))} locked out {when}"


def _logon_after(ev: pd.DataFrame, when: str) -> str:
    ips = _column(ev, "source_ip")
    origin = f" from {_names(ips)}" if ips else ""
    noun = "a successful logon" if len(ev) == 1 else f"{len(ev)} successful logons"
    return f"{noun} as {_names(_column(ev, 'user'))}{origin} {when}"


def _pass_the_hash(ev: pd.DataFrame, when: str) -> str:
    outbound = _field(ev, "TargetOutboundUserName")
    creds = f" using {_names(outbound)}'s credentials" if outbound else ""
    return f"a pass-the-hash style (NewCredentials) logon by {_names(_column(ev, 'user'))}{creds} {when}"


def _kerberoasting(ev: pd.DataFrame, when: str) -> str:
    noun = "an RC4 service ticket" if len(ev) == 1 else f"{len(ev)} RC4 service tickets"
    return f"{noun} for {_names(_field(ev, 'ServiceName'))} requested by {_names(_column(ev, 'user'))} (Kerberoasting) {when}"


def _asrep(ev: pd.DataFrame, when: str) -> str:
    return f"a TGT issued without pre-authentication for {_names(_column(ev, 'user'))} (AS-REP roasting) {when}"


def _dcsync(ev: pd.DataFrame, when: str) -> str:
    return f"directory replication (DCSync) performed by {_names(_column(ev, 'user'))} {when}"


def _group_change(ev: pd.DataFrame, when: str) -> str:
    groups = _column(ev, "target_group")
    target = f" to {_names(groups)}" if groups else " to a privileged group"
    return f"{_names(_column(ev, 'user'))} added{target}{_by(ev)} {when}"


def _account_created(ev: pd.DataFrame, when: str) -> str:
    noun = "new account" if len(ev) == 1 else "new accounts"
    return f"{noun} {_names(_column(ev, 'user'))} created{_by(ev)} {when}"


def _scheduled_task(ev: pd.DataFrame, when: str) -> str:
    noun = "scheduled task" if len(ev) == 1 else "scheduled tasks"
    return f"{noun} {_names(_field(ev, 'TaskName'))} created{_by(ev)} {when}"


def _service(ev: pd.DataFrame, when: str) -> str:
    noun = "service" if len(ev) == 1 else "services"
    return f"{noun} {_names(_field(ev, 'ServiceName'))} installed{_by(ev)} {when}"


def _persistence(ev: pd.DataFrame, when: str) -> str:
    # This rule spans several event types: describe each by its own phrase.
    by_event = {4720: _account_created, 4698: _scheduled_task, 4697: _service, 7045: _service}
    parts = []
    for event_id, group in ev.groupby("event_id", sort=False):
        builder = by_event.get(int(event_id), _generic_for("persistence"))
        parts.append(builder(group, when))
    return " and ".join(parts)


def _log_cleared(ev: pd.DataFrame, when: str) -> str:
    return f"the Security event log cleared by {_names(_column(ev, 'user'))} {when}"


def _audit_policy(ev: pd.DataFrame, when: str) -> str:
    return f"audit policy weakened (auditing removed) by {_names(_column(ev, 'user'))} {when}"


def _dsrm(ev: pd.DataFrame, when: str) -> str:
    return f"the DSRM administrator password set by {_names(_column(ev, 'user'))} {when}"


def _generic_for(label: str) -> Phrase:
    def phrase(ev: pd.DataFrame, when: str) -> str:
        users = _column(ev, "user")
        who = f" involving {_names(users)}" if users else ""
        return f"{label} ({len(ev)} event{'s' if len(ev) != 1 else ''}){who} {when}"

    return phrase


PHRASES: dict[str, Phrase] = {
    "brute_force": _brute_force,
    "password_spray": _password_spray,
    "account_lockout": _lockout,
    "logon_after_brute_force": _logon_after,
    "pass_the_hash": _pass_the_hash,
    "kerberoasting": _kerberoasting,
    "asrep_roasting": _asrep,
    "dcsync": _dcsync,
    "privilege_escalation": _group_change,
    "account_created": _account_created,
    "scheduled_task_created": _scheduled_task,
    "service_installed": _service,
    "persistence_after_suspicious_logon": _persistence,
    "audit_log_cleared": _log_cleared,
    "audit_policy_changed": _audit_policy,
    "dsrm_password_set": _dsrm,
}


def _event_keys(stage: ChainStage) -> frozenset:
    """Identity of the underlying events, independent of which rule flagged them."""
    ev = stage.events
    cols = [c for c in ("timestamp", "event_id", "raw_message") if c in ev]
    return frozenset(map(tuple, ev[cols].astype(str).values.tolist()))


def _narratable_stages(chain: Chain) -> list[ChainStage]:
    """Drop stages whose events are all described by a more severe stage."""
    keyed = [(stage, _event_keys(stage)) for stage in chain.stages]
    keep = []
    for stage, keys in keyed:
        covered = any(
            other is not stage
            and keys <= other_keys
            and (
                SEVERITY_RANK.get(other.severity, -1) > SEVERITY_RANK.get(stage.severity, -1)
                or (other.severity == stage.severity and keys < other_keys)
            )
            for other, other_keys in keyed
        )
        if not covered:
            keep.append(stage)
    return keep


def _segments(stages: list[ChainStage]) -> list[list[ChainStage]]:
    """Merge consecutive stages of the same rule."""
    segments: list[list[ChainStage]] = []
    for stage in stages:
        if segments and segments[-1][-1].rule_id == stage.rule_id:
            segments[-1].append(stage)
        else:
            segments.append([stage])
    return segments


def _join(phrases: list[str]) -> str:
    if len(phrases) == 1:
        return phrases[0]
    rest = phrases[1:]
    tail = rest[0] if len(rest) == 1 else ", ".join(rest[:-1]) + " and " + rest[-1]
    return f"{phrases[0]}, followed by {tail}"


def narrate_stages(chain: Chain, tz: tzinfo | None = None) -> list[str]:
    """One phrase per (merged) stage, in time order, each anchored in time."""
    clock = _Clock(chain, tz)
    phrases = []
    for segment in _segments(_narratable_stages(chain)):
        events = pd.concat([s.events for s in segment])
        when = clock.span(min(s.start_time for s in segment), max(s.end_time for s in segment))
        rule_id = segment[0].rule_id
        builder = PHRASES.get(rule_id) or _generic_for(segment[0].rule_name)
        phrases.append(builder(events, when))
    return phrases


def narrate_chain(chain: Chain, tz: tzinfo | None = None) -> str:
    """The whole chain as one timestamp-anchored sentence."""
    clock = _Clock(chain, tz)
    start, end = clock._local(chain.start_time), clock._local(chain.end_time)
    if clock.multi_day:
        span = f"{start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M}"
    else:
        span = f"{start:%Y-%m-%d %H:%M}" + (f"-{end:%H:%M}" if f"{end:%H:%M}" != f"{start:%H:%M}" else "")
    text = _join(narrate_stages(chain, tz))
    return f"{span} {clock.zone_name(chain.start_time)}: {text[0].upper()}{text[1:]}."


def chain_headline(chain: Chain, arrow: str = "→") -> str:
    """Short title, e.g. 'Credential Access → Initial Access → Persistence (jsmith)'.

    Pass arrow="->" for consoles whose code page lacks "→".
    """
    who = _names(chain.users) if chain.users else _names(chain.source_ips)
    return f"{f' {arrow} '.join(chain.tactics)} ({who})"
