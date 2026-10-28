"""
Parses Windows Security.evtx exports into a normalized pandas DataFrame.

Split into two layers on purpose:
  - `parse_evtx`: walks a .evtx file with python-evtx and yields raw per-record XML.
  - `normalize_record`: pure function, XML string -> dict. No file I/O, no
    dependency on the evtx binary format.

Keeping the XML -> dict step pure and file-independent means it can be unit
tested with hand-written XML strings shaped like real Windows Security event
log entries, without needing a real .evtx fixture.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pandas as pd

ProgressCallback = Callable[[int], None]
PROGRESS_INTERVAL = 500  # records between progress_callback invocations

# Windows Event Log XML namespace. Every element in a Security.evtx record's
# XML rendering lives in this namespace.
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Normalized column -> candidate EventData "Name" attributes, in priority
# order. The first one present in a given record wins. Different Event IDs
# use different field names for conceptually the same thing (e.g. 4624/4625
# use "IpAddress", 4768/4769 use "IpAddress" too, but older/rarer events can
# use "SourceAddress").
_FIELD_ALIASES: dict[str, list[str]] = {
    "user": ["TargetUserName", "SubjectUserName"],
    "user_sid": ["TargetUserSid", "TargetSid", "SubjectUserSid"],
    "subject_user": ["SubjectUserName"],
    "target_group": [],
    "source_ip": ["IpAddress", "SourceAddress", "ClientAddress"],
    "logon_type": ["LogonType"],
    "process_name": ["ProcessName", "NewProcessName"],
}

# Per-Event-ID overrides of _FIELD_ALIASES, for events where the generic
# "TargetUserName first" guess points at the wrong thing. `user` is always
# meant to be *the account the event is about* -- the one an analyst would
# follow from event to event -- and `subject_user` the account that
# performed the action.
_MEMBER_CHANGE = {
    # TargetUserName on these is the GROUP ("Domain Admins"), not a user.
    # The account that was added/removed is MemberName (a DN) / MemberSid.
    "user": ["MemberName"],
    "user_sid": ["MemberSid"],
    "target_group": ["TargetUserName"],
}
_PERFORMED_BY_SUBJECT = {
    # No meaningful target account: the interesting account is whoever did it.
    "user": ["SubjectUserName"],
    "user_sid": ["SubjectUserSid"],
}
_EVENT_FIELD_OVERRIDES: dict[int, dict[str, list[str]]] = {
    **{eid: _MEMBER_CHANGE for eid in (4728, 4729, 4732, 4733, 4756, 4757)},
    # 1102 log cleared, 4662 directory object access (DCSync), 4697 service
    # installed, 4698 scheduled task created, 4719 audit policy changed,
    # 4794 DSRM password set
    **{eid: _PERFORMED_BY_SUBJECT for eid in (1102, 4662, 4697, 4698, 4719, 4794)},
}

REQUIRED_COLUMNS = [
    "timestamp",
    "event_id",
    "user",
    "user_sid",
    "subject_user",
    "target_group",
    "source_ip",
    "target_host",
    "logon_type",
    "process_name",
    "raw_message",
]

# Placeholder values Windows writes into empty fields. Treated as "absent"
# so e.g. a 4625's SubjectUserName "-" never becomes someone's identity
# (S-1-0-0 is the NULL SID, used the same way for SID fields).
_EMPTY_VALUES = {"", "-", "S-1-0-0"}

_DN_CN_RE = re.compile(r"^CN=((?:\\.|[^,])+)", re.IGNORECASE)


@dataclass
class ParseStats:
    """Counters filled in by parse_evtx, for the CLI and the report.

    A large records_skipped count is worth an analyst's attention by itself:
    it can mean a corrupted export, or a log someone tampered with.
    """

    records_read: int = 0
    records_skipped: int = 0


def _parse_timestamp(text: str | None) -> pd.Timestamp:
    """SystemTime string -> UTC Timestamp (NaT if missing/bogus).

    datetime.fromisoformat covers every form seen in practice (python-evtx's
    "2026-06-08 02:14:00.681640+00:00", Windows' 7-digit "...00.6816400Z",
    naive values) and is ~50x faster than pd.to_datetime, which re-guesses
    the format on every call and dominated parse time on large logs.
    python-evtx renders an empty FILETIME as datetime.min (year 1); that's
    "no timestamp", not a real time, and would sort ahead of everything.
    """
    if not text:
        return pd.NaT
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return pd.to_datetime(text, utc=True, errors="coerce")
    if dt.year < 1700:
        return pd.NaT
    dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    return pd.Timestamp(dt)


def _account_from_dn(value: str) -> str:
    """'CN=Smith\\, John,CN=Users,DC=contoso,DC=local' -> 'Smith, John'."""
    match = _DN_CN_RE.match(value)
    if not match:
        return value
    return re.sub(r"\\(.)", r"\1", match.group(1))


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _extract_fields(root: ET.Element) -> dict[str, str]:
    """Collect every named data field on the record.

    Most Security events carry their fields as <EventData><Data Name="...">,
    but some (notably 1102 audit log cleared) use <UserData><SomeElement>
    with child elements instead -- e.g. UserData/LogFileCleared/SubjectUserName.
    Both end up in one flat dict.
    """
    fields: dict[str, str] = {}
    event_data_el = root.find("e:EventData", _NS)
    if event_data_el is not None:
        for data_el in event_data_el.findall("e:Data", _NS):
            name = data_el.get("Name")
            if name:
                fields[name] = data_el.text or ""

    user_data_el = root.find("e:UserData", _NS)
    if user_data_el is not None:
        for container in user_data_el:
            for child in container:
                fields.setdefault(_local_name(child.tag), child.text or "")
    return fields


def normalize_record(xml_string: str) -> dict[str, Any]:
    """Convert one Security event's XML rendering into a normalized dict.

    Returns a dict with the REQUIRED_COLUMNS plus an `event_data` dict
    holding every raw data field from the record, so rule-specific logic
    (e.g. kerberoasting's TicketEncryptionType) can reach fields that don't
    have a place in the common schema.
    """
    root = ET.fromstring(xml_string)

    system = root.find("e:System", _NS)
    if system is None:
        raise ValueError("Record XML missing <System> element")

    event_id_el = system.find("e:EventID", _NS)
    event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else None

    time_created = system.find("e:TimeCreated", _NS)
    timestamp = time_created.get("SystemTime") if time_created is not None else None

    computer_el = system.find("e:Computer", _NS)
    target_host = computer_el.text if computer_el is not None else None

    event_data = _extract_fields(root)
    aliases = {**_FIELD_ALIASES, **_EVENT_FIELD_OVERRIDES.get(event_id, {})}

    def first_present(column: str) -> str | None:
        for name in aliases[column]:
            value = event_data.get(name)
            if value is not None and value.strip() not in _EMPTY_VALUES:
                return value
        return None

    user = first_present("user")
    if user and user.upper().startswith("CN="):
        user = _account_from_dn(user)

    # Kerberos events (4768/4769/4771) log IPv4 clients as IPv4-mapped IPv6
    # ("::ffff:10.0.0.5") while NTLM's 4625 logs "10.0.0.5"; one attacker
    # address must look the same in both to be grouped/correlated.
    source_ip = first_present("source_ip")
    if source_ip and source_ip.lower().startswith("::ffff:") and "." in source_ip:
        source_ip = source_ip[7:]

    return {
        "timestamp": _parse_timestamp(timestamp),
        "event_id": event_id,
        "user": user,
        "user_sid": first_present("user_sid"),
        "subject_user": first_present("subject_user"),
        "target_group": first_present("target_group"),
        "source_ip": source_ip,
        "target_host": target_host,
        "logon_type": first_present("logon_type"),
        "process_name": first_present("process_name"),
        "raw_message": "; ".join(f"{k}={v}" for k, v in event_data.items()),
        "event_data": event_data,
    }


def _iter_record_xml(evtx_path: str) -> Iterator[str]:
    """Yield the XML rendering of every record in a .evtx file.

    Isolated into its own generator so `parse_evtx` stays a thin wrapper and
    the python-evtx dependency only shows up here.
    """
    import Evtx.Evtx as evtx  # python-evtx package, imports as "Evtx"

    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            yield record.xml()


def empty_events_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=REQUIRED_COLUMNS + ["event_data"])


def parse_evtx(
    evtx_path: str,
    progress_callback: ProgressCallback | None = None,
    stats: ParseStats | None = None,
) -> pd.DataFrame:
    """Parse a Security.evtx file into a normalized DataFrame.

    Records that fail to parse (malformed/truncated XML, which does happen
    with corrupted or partially-overwritten log exports) are skipped rather
    than aborting the whole run. Pass a ParseStats to find out how many.

    progress_callback, if given, is called with the running count of
    records processed every PROGRESS_INTERVAL records -- large Security.evtx
    exports (hundreds of thousands of records) can take a while to parse,
    and a CLI sitting silent for a minute-plus reads as hung rather than
    working.
    """
    stats = stats if stats is not None else ParseStats()
    rows = []
    processed = 0
    for xml_string in _iter_record_xml(evtx_path):
        processed += 1
        try:
            rows.append(normalize_record(xml_string))
        except (ET.ParseError, ValueError):
            stats.records_skipped += 1
        if progress_callback and processed % PROGRESS_INTERVAL == 0:
            progress_callback(processed)
    stats.records_read += processed

    if progress_callback:
        progress_callback(processed)

    if not rows:
        return empty_events_frame()

    df = pd.DataFrame(rows)
    df.sort_values("timestamp", inplace=True, ignore_index=True)
    return df
