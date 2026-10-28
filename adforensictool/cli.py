"""
ADForensicTool CLI entry point.

Usage:
    adforensictool --input path/to/security.evtx --output report.xlsx
    python -m adforensictool ...   (or python main.py ... from a source checkout)
"""
from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

import yaml

from adforensictool import console
from adforensictool.correlator.chain_builder import build_chains
from adforensictool.excel_export.report import build_report
from adforensictool.narrator.narrate import chain_headline, narrate_chain
from adforensictool.parser.evtx_parser import BACKENDS, ParseStats, find_evtx_files, parse_evtx_files, resolve_backend
from adforensictool.rules.allowlist import AllowEntry, apply_allowlist, load_allowlist, unknown_rule_references
from adforensictool.rules.engine import DEFAULT_RULES_PATH, RuleError, apply_rules, load_rules
from adforensictool.version import __version__

T = TypeVar("T")


def _positive_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if value <= 0:
        raise argparse.ArgumentTypeError(f"must be greater than 0, got {text}")
    return value


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ADForensicTool",
        description="Reconstruct an attack narrative from Windows Security (.evtx) event log exports.",
    )
    parser.add_argument(
        "--input",
        required=True,
        nargs="+",
        metavar="PATH",
        help="One or more .evtx files and/or directories (searched recursively), e.g. exports from several DCs "
        "plus their System.evtx",
    )
    parser.add_argument("--output", required=True, help="Path to write the .xlsx report to")
    parser.add_argument(
        "--rules",
        default=str(DEFAULT_RULES_PATH),
        help="Path to a detection rules YAML file (default: rules/default_rules.yaml)",
    )
    parser.add_argument(
        "--allowlist",
        help="YAML file of known-benign activity to suppress from the results (see rules/allowlist.py)",
    )
    parser.add_argument(
        "--chain-window",
        type=_positive_float,
        default=60,
        metavar="MINUTES",
        help="Max gap between two detections for the same account to be linked into one attack chain (default: 60)",
    )
    parser.add_argument(
        "--backend",
        choices=BACKENDS,
        default="auto",
        help="evtx parser: 'rust' (pyevtx-rs, much faster, if installed), 'python' (python-evtx), "
        "or 'auto' (default: rust when available)",
    )
    parser.add_argument(
        "--all-events",
        action="store_true",
        help="Fully parse every record, not just the Event IDs the rules look at (slower; same detections)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show full tracebacks on failure instead of a one-line error message",
    )
    parser.add_argument("--version", action="version", version=f"ADForensicTool {__version__}")
    return parser.parse_args(argv)


def _load_config(loader: Callable[[Path], T], path: Path, kind: str) -> T | None:
    """Run a YAML config loader, turning expected failures into one clean
    error line. Returns None on failure (already reported)."""
    if not path.is_file():
        console.error(f"{kind} file not found: {path}")
        return None
    try:
        return loader(path)
    except yaml.YAMLError as exc:
        console.error(f"malformed {kind} file {path}: {exc}")
    except RuleError as exc:
        console.error(f"invalid {kind} file {path}: {exc}")
    return None


def describe_sources(paths: list[Path], limit: int = 3) -> str:
    """Short provenance line for the report banner: file names, not full
    paths (those are in the source_file column)."""
    names = [p.name for p in paths]
    if len(names) <= limit:
        return ", ".join(names)
    return f"{len(names)} files: {', '.join(names[:limit])} +{len(names) - limit} more"


def _run(args: argparse.Namespace) -> int:
    try:
        input_paths = find_evtx_files(args.input)
    except FileNotFoundError as exc:
        console.error(str(exc))
        return 1
    if not input_paths:
        console.error(f"no .evtx files found in: {', '.join(args.input)}")
        return 1
    try:
        backend = resolve_backend(args.backend)
    except ValueError as exc:
        console.error(str(exc))
        return 1

    # Load all configuration before parsing: a typo in a rules/allowlist
    # file should fail in a second, not after minutes spent parsing a log.
    rules_path = Path(args.rules)
    console.info(f"Loading rules from {rules_path} ...")
    rules = _load_config(load_rules, rules_path, "rules")
    if rules is None:
        return 1
    if rules:
        console.success(f"Loaded {len(rules)} rule(s)")
    else:
        console.warn(f"{rules_path} contains no rules -- nothing will be flagged")

    allowlist: list[AllowEntry] = []
    if args.allowlist:
        allowlist_path = Path(args.allowlist)
        loaded = _load_config(load_allowlist, allowlist_path, "allowlist")
        if loaded is None:
            return 1
        allowlist = loaded
        console.success(f"Loaded {len(allowlist)} allowlist entr{'y' if len(allowlist) == 1 else 'ies'}")
        for rule_id in unknown_rule_references(allowlist, {r.id for r in rules}):
            console.warn(f"allowlist refers to unknown rule '{rule_id}' (typo?) -- that scope matches nothing")

    # Only fully parse Event IDs some rule looks at (unless asked otherwise).
    event_ids = None if args.all_events or not rules else {eid for r in rules for eid in r.event_ids}
    console.info(f"Parsing {len(input_paths)} file(s) with the {backend} backend ...")

    def _report_progress(path: Path, count: int) -> None:
        console.progress(f"Parsing {path.name} ... {count} record(s) processed")

    stats = ParseStats()
    df = parse_evtx_files(input_paths, progress_callback=_report_progress, stats=stats, event_ids=event_ids, backend=backend)
    console.progress_done()
    console.success(
        f"Read {stats.records_read} record(s) from {stats.files} file(s); "
        f"{len(df)} with Event IDs the rules use were parsed in full"
    )
    if stats.records_duplicate:
        console.info(f"  {stats.records_duplicate} duplicate record(s) across overlapping inputs counted once")
    if stats.records_skipped:
        console.warn(
            f"{stats.records_skipped} record(s) could not be read or parsed and were skipped "
            "(corrupted export or possible tampering -- verify the source log)"
        )
    for file, channel, computer, low, high, missing in stats.record_id_gaps():
        console.warn(
            f"{Path(file).name} [{channel or '?'} @ {computer or '?'}]: {missing} EventRecordID(s) missing between "
            f"{low} and {high} -- expected for a filtered export, otherwise records were lost or deleted"
        )

    console.info("Applying detection rules ...")
    flagged = apply_rules(df, rules)
    flagged, suppressed = apply_allowlist(flagged, allowlist)
    console.success(f"{len(flagged)} event(s) flagged")
    for description, count in suppressed.items():
        console.info(f"  {count} flagged event(s) suppressed by allowlist: {description}")

    console.info("Correlating flagged events into attack chains ...")
    chains = build_chains(flagged, window_minutes=args.chain_window)
    if chains:
        console.warn(f"{len(chains)} attack chain(s) identified:")
        for chain in chains:
            console.detail(f"[{chain.severity.upper()}] {chain.id}: {chain_headline(chain, arrow='->')}")
            console.detail(f"  {narrate_chain(chain)}")
    else:
        console.success("No multi-stage attack chains identified")

    console.info(f"Writing report to {args.output} ...")
    build_report(
        df,
        flagged,
        rules,
        args.output,
        source_file=describe_sources(input_paths),
        parse_stats=stats,
        suppressed=suppressed,
        chains=chains,
    )
    console.success(f"Report written to {args.output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return _run(args)
    except Exception as exc:
        if args.debug:
            raise
        console.error(f"{exc.__class__.__name__}: {exc} (re-run with --debug for a full traceback)")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
