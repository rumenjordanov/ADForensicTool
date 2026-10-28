"""
Links flagged events (rules.engine.apply_rules output) into multi-stage
"attack chains" spanning different detection rules -- the step that turns
"the brute force on jsmith" and "the Domain Admins change for jsmith" into
one incident.

How it works
------------
1. Stages. Each threshold cluster (all events sharing a cluster_id, e.g. one
   brute-force burst) becomes one stage; every other flagged event is a
   stage on its own.

2. Identities. A stage is tied to the accounts involved: normalized `user`
   names (jsmith == CONTOSO\\JSmith == jsmith@contoso.local), `user_sid`s,
   and the `subject_user` who performed the action (so "jsmith logged on"
   links to "jsmith created account backdoor"). Machine accounts (NAME$)
   are not used as subjects -- domain controllers are the subject of
   countless routine events.

   Source IP is used only when a stage has no account identity, or spans
   several accounts (a password spray: the IP *is* the actor). Linking
   every stage by IP would glue unrelated users together through shared
   infrastructure (NAT, jump hosts, VPN concentrators). Host is never used:
   every event in a DC's Security log has the same Computer.

3. Linking. Two stages are joined when they share an identity and the later
   one starts within `window_minutes` of the earlier one ending. Joins are
   transitive (connected components), so a chain can span longer than the
   window as long as each step follows the previous one closely.

4. Chains. A component becomes a Chain when it spans at least two different
   rules. Each flagged event belongs to at most one chain. Severity is the
   highest stage severity; each stage carries its ATT&CK tactic so the
   narrator can describe the progression in kill-chain terms.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from adforensictool.rules.engine import actor_key

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ATT&CK tactic per default rule; anything else falls back on the technique.
RULE_TACTICS = {
    "brute_force": "Credential Access",
    "password_spray": "Credential Access",
    "account_lockout": "Credential Access",
    "kerberoasting": "Credential Access",
    "asrep_roasting": "Credential Access",
    "dcsync": "Credential Access",
    "logon_after_brute_force": "Initial Access",
    "pass_the_hash": "Lateral Movement",
    "privilege_escalation": "Privilege Escalation",
    "account_created": "Persistence",
    "scheduled_task_created": "Persistence",
    "service_installed": "Persistence",
    "persistence_after_suspicious_logon": "Persistence",
    "dsrm_password_set": "Persistence",
    "audit_log_cleared": "Defense Evasion",
    "audit_policy_changed": "Defense Evasion",
}
TECHNIQUE_TACTICS = {
    "T1110": "Credential Access",
    "T1558": "Credential Access",
    "T1003": "Credential Access",
    "T1078": "Initial Access",
    "T1550": "Lateral Movement",
    "T1021": "Lateral Movement",
    "T1098": "Persistence",
    "T1136": "Persistence",
    "T1053": "Persistence",
    "T1543": "Persistence",
    "T1070": "Defense Evasion",
    "T1562": "Defense Evasion",
}


def tactic_for(rule_id: str, technique: str) -> str:
    if rule_id in RULE_TACTICS:
        return RULE_TACTICS[rule_id]
    return TECHNIQUE_TACTICS.get(str(technique).split(".")[0], "Other")


@dataclass
class ChainStage:
    rule_id: str
    rule_name: str
    severity: str
    mitre_technique: str
    tactic: str
    start_time: pd.Timestamp
    end_time: pd.Timestamp
    event_count: int
    users: list[str]
    source_ips: list[str]
    # The flagged rows behind this stage (for narration detail), sliced out of
    # the full flagged frame only when first needed: building a DataFrame per
    # stage up front dominated runtime on logs with thousands of findings.
    _source: pd.DataFrame = field(repr=False, compare=False)
    _index: list = field(repr=False, compare=False)
    _events: pd.DataFrame | None = field(default=None, init=False, repr=False, compare=False)

    @property
    def events(self) -> pd.DataFrame:
        if self._events is None:
            self._events = self._source.loc[self._index]
        return self._events

    @property
    def timestamp(self) -> pd.Timestamp:
        return self.start_time


@dataclass
class Chain:
    id: str
    users: list[str]
    source_ips: list[str]
    stages: list[ChainStage] = field(default_factory=list)
    severity: str = "low"
    start_time: pd.Timestamp | None = None
    end_time: pd.Timestamp | None = None

    @property
    def tactics(self) -> list[str]:
        """Distinct tactics in order of first appearance."""
        return list(dict.fromkeys(s.tactic for s in self.stages))

    @property
    def event_count(self) -> int:
        return sum(s.event_count for s in self.stages)


def _text(value) -> str | None:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    text = str(value).strip()
    return text or None


def _distinct(records: list[dict], column: str) -> list[str]:
    return list(dict.fromkeys(t for r in records if (t := _text(r.get(column)))))


def _is_machine(name: str) -> bool:
    return name.endswith("$")


def _identities(records: list[dict], source_ips: list[str]) -> set[str]:
    keys: set[str] = set()
    distinct_users: set[str | None] = set()
    for row in records:
        user = _text(row.get("user"))
        subject = _text(row.get("subject_user"))
        if user:
            distinct_users.add(actor_key(user))
            # A machine account as the event's account (e.g. a task created
            # by DC01$) says nothing about who the attacker is; neither does
            # its SID, which on such rows is the machine's.
            if not _is_machine(user):
                keys.add(f"user:{actor_key(user)}")
                if sid := _text(row.get("user_sid")):
                    keys.add(f"sid:{sid}")
        if subject and not _is_machine(subject):
            keys.add(f"user:{actor_key(subject)}")
    if not keys or len(distinct_users) > 1:
        keys.update(f"ip:{ip}" for ip in source_ips)
    return keys


def _split_stages(flagged: pd.DataFrame) -> list[tuple[ChainStage, set[str]]]:
    """Returns (stage, identity keys) pairs in start-time order."""
    rows = flagged[flagged["timestamp"].notna()]
    groups: dict[tuple, list[tuple]] = {}
    for idx, record in zip(rows.index, rows.to_dict("records"), strict=True):
        cluster = _text(record.get("cluster_id"))
        key = (record["rule_id"], cluster) if cluster else ("__single__", idx)
        groups.setdefault(key, []).append((idx, record))

    out = []
    for members in groups.values():
        index = [idx for idx, _ in members]
        records = [rec for _, rec in members]
        first = records[0]
        times = [r["timestamp"] for r in records]
        source_ips = _distinct(records, "source_ip")
        stage = ChainStage(
            rule_id=str(first["rule_id"]),
            rule_name=str(first["rule_name"]),
            severity=str(first["severity"]).lower(),
            mitre_technique=str(first["mitre_technique"]),
            tactic=tactic_for(str(first["rule_id"]), str(first["mitre_technique"])),
            start_time=min(times),
            end_time=max(times),
            event_count=len(records),
            users=_distinct(records, "user"),
            source_ips=source_ips,
            _source=rows,
            _index=index,
        )
        out.append((stage, _identities(records, source_ips)))
    out.sort(key=lambda pair: (pair[0].start_time, pair[0].end_time))
    return out


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def build_chains(flagged: pd.DataFrame, window_minutes: float = 60) -> list[Chain]:
    """Group flagged events into attack chains (see module docstring).

    Returns chains ordered by severity (highest first), then start time.
    """
    if flagged is None or flagged.empty:
        return []

    split = _split_stages(flagged)
    stages = [stage for stage, _ in split]
    window = pd.Timedelta(minutes=window_minutes)
    uf = _UnionFind(len(stages))

    by_identity: dict[str, list[int]] = {}
    for i, (_, keys) in enumerate(split):
        for key in keys:
            by_identity.setdefault(key, []).append(i)

    for members in by_identity.values():
        # members are in start-time order; link each stage to the run before
        # it if it starts within the window of that run's latest end.
        run_end = None
        prev = None
        for i in members:
            stage = stages[i]
            if prev is not None and stage.start_time - run_end <= window:
                uf.union(prev, i)
                run_end = max(run_end, stage.end_time)
            else:
                run_end = stage.end_time
            prev = i

    components: dict[int, list[ChainStage]] = {}
    for i, stage in enumerate(stages):
        components.setdefault(uf.find(i), []).append(stage)

    chains = []
    for members in components.values():
        if len({s.rule_id for s in members}) < 2:
            continue
        members.sort(key=lambda s: (s.start_time, s.end_time))
        users: list[str] = []
        ips: list[str] = []
        for s in members:
            users += [u for u in s.users if u not in users]
            ips += [ip for ip in s.source_ips if ip not in ips]
        chains.append(
            Chain(
                id="",
                users=users,
                source_ips=ips,
                stages=members,
                severity=max((s.severity for s in members), key=lambda sev: SEVERITY_RANK.get(sev, -1)),
                start_time=members[0].start_time,
                end_time=max(s.end_time for s in members),
            )
        )

    chains.sort(key=lambda c: (-SEVERITY_RANK.get(c.severity, -1), c.start_time))
    for n, chain in enumerate(chains, start=1):
        chain.id = f"chain-{n}"
    return chains
