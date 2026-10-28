"""
Small colored console output helpers for the CLI, styled like the familiar
bracket-prefix convention from security tooling ([*] info, [+] success,
[!] warn, [-] error) rather than Python's logging module -- this is a
single-command CLI, not a long-running service, so a lightweight
print-based approach reads better than logger boilerplate.
"""
from __future__ import annotations

import sys

from colorama import Fore, Style
from colorama import init as _colorama_init

_colorama_init(autoreset=True)


def info(message: str) -> None:
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {message}")


def success(message: str) -> None:
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")


def warn(message: str) -> None:
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}", file=sys.stderr)


def error(message: str) -> None:
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {message}", file=sys.stderr)


def progress(message: str) -> None:
    """Show a live counter, overwriting the current line in place.

    Falls back to one line per call when stdout isn't a real terminal (piped
    output, redirected to a file, CI logs) -- otherwise the \\r characters
    have nothing to overwrite and just concatenate into unreadable garbage.
    """
    if sys.stdout.isatty():
        print(f"\r{Fore.CYAN}[*]{Style.RESET_ALL} {message}", end="", flush=True)
    else:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {message}")


def progress_done() -> None:
    """Advance past a line left open by progress() calls."""
    if sys.stdout.isatty():
        print()
