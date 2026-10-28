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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
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
    "record_id",
    "channel",
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
    records_skipped: int = 0  # unreadable / unparseable (corruption, tampering)
    records_filtered: int = 0  # Event IDs no rule looks at, skipped on purpose
    records_duplicate: int = 0  # same record found in more than one input file
    files: int = 0
    # (file, channel, computer) -> [lowest EventRecordID, highest, records seen]
    record_ranges: dict[tuple[str, str, str], list[int]] = field(default_factory=dict)

    def note_record_id(self, file: str, channel: str, computer: str, record_id: int) -> None:
        key = (file, channel, computer)
        rng = self.record_ranges.get(key)
        if rng is None:
            self.record_ranges[key] = [record_id, record_id, 1]
        else:
            rng[0] = min(rng[0], record_id)
            rng[1] = max(rng[1], record_id)
            rng[2] += 1

    def record_id_gaps(self) -> list[tuple[str, str, str, int, int, int]]:
        """(file, channel, computer, first id, last id, missing count) for
        every log whose EventRecordIDs are not contiguous.

        Windows numbers records sequentially, so in a complete export a gap
        means records were lost or deleted -- removing individual records
        is a known anti-forensics technique that, unlike clearing the log,
        leaves no 1102. Filtered exports (wevtutil /q, Event Viewer "Save
        Filtered Log File As") have gaps by design.
        """
        gaps = []
        for (file, channel, computer), (low, high, count) in self.record_ranges.items():
            missing = (high - low + 1) - count
            if missing > 0:
                gaps.append((file, channel, computer, low, high, missing))
        return gaps


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

    record_id_el = system.find("e:EventRecordID", _NS)
    record_id = int(record_id_el.text) if record_id_el is not None and (record_id_el.text or "").strip().isdigit() else None
    channel_el = system.find("e:Channel", _NS)
    channel = channel_el.text if channel_el is not None else None

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
        "record_id": record_id,
        "channel": channel,
        "event_data": event_data,
    }


# --------------------------------------------------------------------------
# Reading .evtx files
# --------------------------------------------------------------------------

BACKENDS = ("auto", "python", "rust")

# Yielded by the record iterators in place of XML for a record (or a run of
# records) that could not be read: (number of records lost).
_Lost = int

_NO_RECORD = 0xFFFFFFFFFFFFFFFF  # chunk header record number meaning "none"


def rust_backend_available() -> bool:
    """True when pyevtx-rs ('evtx') is importable. On Windows it cannot be
    installed next to python-evtx ('Evtx'): the two package directories
    collide on a case-insensitive filesystem."""
    try:
        from evtx import PyEvtxParser  # noqa: F401
    except ImportError:
        return False
    return True


def resolve_backend(requested: str = "auto") -> str:
    if requested not in BACKENDS:
        raise ValueError(f"unknown backend '{requested}' (choose from {', '.join(BACKENDS)})")
    if requested == "auto":
        return "rust" if rust_backend_available() else "python"
    if requested == "rust" and not rust_backend_available():
        raise ValueError(
            "the 'rust' backend needs the pyevtx-rs package (pip install evtx). On Windows it cannot share an "
            "environment with python-evtx -- see README"
        )
    return requested


def _iter_python_evtx(evtx_path: str) -> Iterator[str | _Lost]:
    """python-evtx, read defensively.

    A single corrupted record used to raise out of python-evtx's record
    generator and abort the entire parse, discarding every valid event --
    exactly the wrong failure mode for logs that may have been tampered
    with. Records are now read chunk by chunk: a bad record is skipped, a
    chunk whose record chain is broken is abandoned after its readable
    records, and every later chunk is still read. Each chunk header says
    which record numbers it holds, so the number of records lost is exact.
    """
    import logging

    import Evtx.Evtx as evtx  # python-evtx package, imports as "Evtx"

    logging.getLogger("Evtx").setLevel(logging.ERROR)  # it logs a warning per bad token

    with evtx.Evtx(evtx_path) as log:
        chunks = log.chunks()
        while True:
            try:
                chunk = next(chunks)
            except StopIteration:
                return
            except Exception:  # unreadable chunk header: nothing after it can be located
                yield 1
                return
            try:
                first, last = chunk.log_first_record_number(), chunk.log_last_record_number()
                if _NO_RECORD in (first, last):
                    expected = 0  # an empty chunk, e.g. in an export that matched nothing
                else:
                    expected = last - first + 1
                    if not 0 < expected < 100_000:
                        expected = None  # header itself damaged: don't trust it
            except Exception:
                expected = None

            seen = 0
            records = chunk.records()
            while True:
                try:
                    record = next(records)
                except StopIteration:
                    break
                except Exception:
                    break  # record chain broken; the remainder is counted below
                seen += 1
                try:
                    yield record.xml()
                except Exception:
                    yield 1
            if expected is not None and seen < expected:
                yield expected - seen


def _iter_rust_evtx(evtx_path: str) -> Iterator[str | _Lost]:
    """pyevtx-rs: a Rust parser, several times faster than python-evtx. It
    recovers from corrupt records itself; per-record failures surface as
    exceptions or error objects, which are counted as lost records."""
    from evtx import PyEvtxParser

    records = iter(PyEvtxParser(evtx_path).records())
    while True:
        try:
            record = next(records)
        except StopIteration:
            return
        except Exception:
            yield 1
            continue
        if isinstance(record, dict) and isinstance(record.get("data"), str):
            yield record["data"]
        else:
            yield 1


def _iter_record_xml(evtx_path: str, backend: str = "python") -> Iterator[str | _Lost]:
    """Yield the XML rendering of every record in a .evtx file, or an int
    (number of records lost) where records could not be read."""
    if backend == "rust":
        return _iter_rust_evtx(evtx_path)
    return _iter_python_evtx(evtx_path)


_EVENT_ID_RE = re.compile(r"<EventID[^>]*>\s*(\d+)\s*</EventID>")
_RECORD_ID_RE = re.compile(r"<EventRecordID>\s*(\d+)\s*</EventRecordID>")
_CHANNEL_RE = re.compile(r"<Channel>([^<]*)</Channel>")
_COMPUTER_RE = re.compile(r"<Computer>([^<]*)</Computer>")


def empty_events_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=REQUIRED_COLUMNS + ["event_data"])


def parse_evtx(
    evtx_path: str,
    progress_callback: ProgressCallback | None = None,
    stats: ParseStats | None = None,
    event_ids: set[int] | None = None,
    backend: str = "python",
) -> pd.DataFrame:
    """Parse one .evtx file into a normalized DataFrame.

    Records that can't be read or parsed (corrupted/truncated exports, or a
    log someone tampered with) are skipped rather than aborting the whole
    run. Pass a ParseStats to find out how many.

    event_ids, if given, limits full parsing to those Event IDs (typically
    every ID some rule looks at): other records are recognized by a cheap
    regex on their EventID and counted in stats.records_filtered.

    progress_callback, if given, is called with the running count of
    records processed every PROGRESS_INTERVAL records -- large Security.evtx
    exports (hundreds of thousands of records) can take a while to parse,
    and a CLI sitting silent for a minute-plus reads as hung rather than
    working.
    """
    stats = stats if stats is not None else ParseStats()
    rows = []
    processed = 0
    for item in _iter_record_xml(evtx_path, backend):
        if isinstance(item, int):
            processed += item
            stats.records_skipped += item
            continue
        processed += 1
        # Track EventRecordIDs of every readable record -- including ones the
        # prefilter drops below, which would otherwise look like gaps.
        record_id = _RECORD_ID_RE.search(item)
        if record_id:
            channel, computer = _CHANNEL_RE.search(item), _COMPUTER_RE.search(item)
            stats.note_record_id(
                evtx_path,
                channel.group(1) if channel else "",
                computer.group(1) if computer else "",
                int(record_id.group(1)),
            )
        if event_ids is not None:
            match = _EVENT_ID_RE.search(item)
            if match and int(match.group(1)) not in event_ids:
                stats.records_filtered += 1
                continue
        try:
            rows.append(normalize_record(item))
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
    df = df.sort_values("timestamp", ignore_index=True)
    return df


def find_evtx_files(inputs: list[str]) -> list[Path]:
    """Expand a mix of files and directories (searched recursively for
    *.evtx) into a de-duplicated, ordered list of files."""
    found: list[Path] = []
    for raw in inputs:
        path = Path(raw)
        if path.is_dir():
            # casefolded sort: Path ordering is case-insensitive on Windows only,
            # and the same inputs should come out in the same order everywhere
            evtx = [p for p in path.rglob("*") if p.is_file() and p.suffix.lower() == ".evtx"]
            found += sorted(evtx, key=lambda p: str(p).casefold())
        elif path.is_file():
            found.append(path)
        else:
            raise FileNotFoundError(f"input not found: {path}")
    unique: dict[Path, Path] = {}
    for p in found:
        unique.setdefault(p.resolve(), p)
    return list(unique.values())


def parse_evtx_files(
    paths: list[Path],
    progress_callback: Callable[[Path, int], None] | None = None,
    stats: ParseStats | None = None,
    event_ids: set[int] | None = None,
    backend: str = "python",
) -> pd.DataFrame:
    """Parse several .evtx files into one DataFrame with a `source_file`
    column. Records present in more than one file (overlapping exports of
    the same log) are kept once, keyed on channel + computer + EventRecordID."""
    stats = stats if stats is not None else ParseStats()
    frames = []
    for path in paths:
        callback = (lambda count, p=path: progress_callback(p, count)) if progress_callback else None
        df = parse_evtx(str(path), progress_callback=callback, stats=stats, event_ids=event_ids, backend=backend)
        stats.files += 1
        if not df.empty:
            df["source_file"] = str(path)
            frames.append(df)

    if not frames:
        frame = empty_events_frame()
        frame["source_file"] = pd.Series(dtype=object)
        return frame

    df = pd.concat(frames, ignore_index=True)
    if len(paths) > 1:
        keyed = df["record_id"].notna()
        dupes = df[keyed].duplicated(subset=["channel", "target_host", "record_id"], keep="first")
        stats.records_duplicate += int(dupes.sum())
        df = df.drop(index=dupes[dupes].index)
    df = df.sort_values("timestamp", kind="stable", ignore_index=True)
    return df
