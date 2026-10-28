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

import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
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
    "source_ip": ["IpAddress", "SourceAddress"],
    "logon_type": ["LogonType"],
    "process_name": ["ProcessName", "NewProcessName"],
}

REQUIRED_COLUMNS = [
    "timestamp",
    "event_id",
    "user",
    "source_ip",
    "target_host",
    "logon_type",
    "process_name",
    "raw_message",
]


def normalize_record(xml_string: str) -> dict[str, Any]:
    """Convert one Security event's XML rendering into a normalized dict.

    Returns a dict with the 8 REQUIRED_COLUMNS plus an `event_data` dict
    holding every raw <Data Name="..."> field from the record, so
    rule-specific logic (e.g. kerberoasting's TicketEncryptionType, or
    privilege-escalation's MemberName/TargetUserName-as-group) can reach
    fields that don't have a place in the common schema.
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

    event_data: dict[str, str] = {}
    event_data_el = root.find("e:EventData", _NS)
    if event_data_el is not None:
        for data_el in event_data_el.findall("e:Data", _NS):
            name = data_el.get("Name")
            if name:
                event_data[name] = data_el.text or ""

    def first_present(candidates: list[str]) -> str | None:
        for name in candidates:
            if name in event_data and event_data[name]:
                return event_data[name]
        return None

    record = {
        "timestamp": pd.to_datetime(timestamp, utc=True) if timestamp else pd.NaT,
        "event_id": event_id,
        "user": first_present(_FIELD_ALIASES["user"]),
        "source_ip": first_present(_FIELD_ALIASES["source_ip"]),
        "target_host": target_host,
        "logon_type": first_present(_FIELD_ALIASES["logon_type"]),
        "process_name": first_present(_FIELD_ALIASES["process_name"]),
        "raw_message": "; ".join(f"{k}={v}" for k, v in event_data.items()),
        "event_data": event_data,
    }
    return record


def _iter_record_xml(evtx_path: str) -> Iterator[str]:
    """Yield the XML rendering of every record in a .evtx file.

    Isolated into its own generator so `parse_evtx` stays a thin wrapper and
    the python-evtx dependency only shows up here.
    """
    import Evtx.Evtx as evtx  # python-evtx package, imports as "Evtx"

    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            yield record.xml()


def parse_evtx(evtx_path: str, progress_callback: ProgressCallback | None = None) -> pd.DataFrame:
    """Parse a Security.evtx file into a normalized DataFrame.

    Records that fail to parse (malformed/truncated XML, which does happen
    with corrupted or partially-overwritten log exports) are skipped rather
    than aborting the whole run; skipped-record count is worth logging by
    the caller if it becomes large.

    progress_callback, if given, is called with the running count of
    records processed every PROGRESS_INTERVAL records -- large Security.evtx
    exports (hundreds of thousands of records) can take a while to parse,
    and a CLI sitting silent for a minute-plus reads as hung rather than
    working.
    """
    rows = []
    processed = 0
    for xml_string in _iter_record_xml(evtx_path):
        processed += 1
        try:
            rows.append(normalize_record(xml_string))
        except (ET.ParseError, ValueError):
            pass
        if progress_callback and processed % PROGRESS_INTERVAL == 0:
            progress_callback(processed)

    if progress_callback:
        progress_callback(processed)

    if not rows:
        return pd.DataFrame(columns=REQUIRED_COLUMNS + ["event_data"])

    df = pd.DataFrame(rows)
    df.sort_values("timestamp", inplace=True, ignore_index=True)
    return df
