# SPDX-License-Identifier: AGPL-3.0-or-later
# Modernized rewrite of hash-id, originally by Zion3R (www.Blackploit.com).
"""Command-line interface for hash-id."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .banner import logo
from .core import identify_hash, split_results
from .data import Signature

SEPARATOR = "-" * 50
PROMPT = " HASH: "

__all__ = ["main", "build_parser", "format_result", "format_json"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hash-id",
        description="Identify the different types of hashes used to hash "
        "data and especially passwords.",
    )
    parser.add_argument(
        "hashes",
        nargs="*",
        metavar="HASH",
        help="hash(es) to identify; with no arguments, starts an interactive "
        "session (or reads hashes from standard input when piped)",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of the classic report",
    )
    parser.add_argument(
        "-b",
        "--banner",
        action="store_true",
        help="show the banner even when identifying hashes non-interactively",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="suppress the banner in interactive mode",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"hash-id {__version__}",
    )
    return parser


def format_result(matches: Sequence[Signature]) -> str:
    """Render the result block printed after a hash prompt."""
    if not matches:
        return "\n Not Found."
    possible, least_possible = split_results(tuple(matches))
    lines = ["", "Possible Hashs:"]
    lines.extend(f"[+] {match.name}" for match in possible)
    if least_possible:
        lines.append("")
        lines.append("Least Possible Hashs:")
        lines.extend(f"[+] {match.name}" for match in least_possible)
    return "\n".join(lines)


def _as_json_object(value: str, matches: Sequence[Signature]) -> dict[str, object]:
    possible, least_possible = split_results(tuple(matches))
    return {
        "hash": value,
        "possible": [match.name for match in possible],
        "least_possible": [match.name for match in least_possible],
    }


def format_json(results: Sequence[tuple[str, tuple[Signature, ...]]]) -> str:
    return json.dumps(
        [_as_json_object(value, matches) for value, matches in results],
        indent=2,
        ensure_ascii=False,
    )


def _print_text_report(results: Sequence[tuple[str, tuple[Signature, ...]]]) -> None:
    blocks = []
    for value, matches in results:
        blocks.append(f"{SEPARATOR}\n{PROMPT}{value}\n{format_result(matches)}")
    sys.stdout.write("\n".join(blocks) + "\n")


def _run_batch(
    values: Sequence[str],
    *,
    as_json: bool,
    show_banner: bool,
) -> None:
    results = [(value, identify_hash(value)) for value in values]
    if show_banner:
        print(logo())
    if as_json:
        print(format_json(results))
    else:
        _print_text_report(results)


def _interactive(*, show_banner: bool) -> int:
    if show_banner:
        print(logo())
    while True:
        try:
            print(SEPARATOR)
            value = input(PROMPT).strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n\tBye!")
            return 0
        if value:
            print(format_result(identify_hash(value)))


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    hashes = [value.strip() for value in args.hashes if value.strip()]

    if hashes:
        _run_batch(hashes, as_json=args.json, show_banner=args.banner)
        return 0

    if sys.stdin.isatty():
        return _interactive(show_banner=not args.no_banner)

    piped = [line.strip() for line in sys.stdin if line.strip()]
    _run_batch(piped, as_json=args.json, show_banner=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
