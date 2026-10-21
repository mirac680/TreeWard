from __future__ import annotations

import argparse
import math
import os
import sys
import tomllib
from pathlib import Path
from typing import Any

from . import __version__
from .models import ScanSummary
from .render import has_blocking_findings, render_json, render_sarif, render_text
from .scanner import (
    DEFAULT_MAX_FILE_SIZE_MB,
    HARD_MAX_FILE_SIZE_MB,
    ScanError,
    find_repository_root,
    scan_repository,
)

_FAIL_CHOICES = ("high", "medium", "low", "never")


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive number") from exc
    if not math.isfinite(parsed) or parsed <= 0 or parsed > HARD_MAX_FILE_SIZE_MB:
        raise argparse.ArgumentTypeError(
            f"must be greater than 0 and no more than {HARD_MAX_FILE_SIZE_MB:g} MiB"
        )
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="treeward",
        description="Check a Git repository for common publish-time hazards.",
        epilog=(
            "TreeWard scans tracked and non-ignored untracked files in the working tree. "
            "It does not scan the Git index or history, and cannot prove a repository is safe to publish."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="repository directory or a directory inside it (default: current directory)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the report to this file instead of standard output",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="TOML config file (default: .treeward.toml at the repository root)",
    )
    parser.add_argument(
        "--max-file-size-mb",
        type=_positive_float,
        help=f"skip larger files (default: {DEFAULT_MAX_FILE_SIZE_MB:g} MiB; max: {HARD_MAX_FILE_SIZE_MB:g} MiB)",
    )
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_CHOICES,
        help="exit 1 when findings at this severity or higher exist (default: high)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _read_config(path: Path) -> tuple[float, list[str], str]:
    if not path.exists():
        return DEFAULT_MAX_FILE_SIZE_MB, [], "high"
    try:
        with path.open("rb") as stream:
            raw: Any = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ScanError(f"Could not read config {path}: {exc}") from exc
    scan = raw.get("scan", {})
    if not isinstance(scan, dict):
        raise ScanError("Config section [scan] must be a table.")
    max_size = scan.get("max_file_size_mb", DEFAULT_MAX_FILE_SIZE_MB)
    if isinstance(max_size, bool) or not isinstance(max_size, (int, float)):
        raise ScanError("scan.max_file_size_mb must be a number.")
    max_size = float(max_size)
    if not math.isfinite(max_size) or max_size <= 0 or max_size > HARD_MAX_FILE_SIZE_MB:
        raise ScanError(
            f"scan.max_file_size_mb must be greater than 0 and no more than {HARD_MAX_FILE_SIZE_MB:g}."
        )
    excludes = scan.get("exclude", [])
    if not isinstance(excludes, list) or any(not isinstance(item, str) for item in excludes):
        raise ScanError("scan.exclude must be a list of path patterns.")
    fail_on = scan.get("fail_on", raw.get("fail_on", "high"))
    if fail_on not in _FAIL_CHOICES:
        raise ScanError(f"fail_on must be one of: {', '.join(_FAIL_CHOICES)}.")
    return max_size, excludes, fail_on


def _format(summary: ScanSummary, name: str, *, color: bool = False) -> str:
    if name == "json":
        return render_json(summary)
    if name == "sarif":
        return render_sarif(summary)
    return render_text(summary, color=color)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        repo_root = find_repository_root(Path(args.path))
        config_path = args.config.expanduser().resolve() if args.config else repo_root / ".treeward.toml"
        if args.config and not config_path.is_file():
            raise ScanError(f"Config file does not exist or is not a file: {config_path}")
        configured_size, excludes, configured_fail_on = _read_config(config_path)
        summary = scan_repository(
            repo_root,
            max_file_size_mb=args.max_file_size_mb or configured_size,
            excludes=excludes,
        )
        report = _format(
            summary,
            args.format,
            color=(
                args.format == "text"
                and args.output is None
                and sys.stdout.isatty()
                and "NO_COLOR" not in os.environ
            ),
        )
        if args.output:
            try:
                args.output.expanduser().write_text(report, encoding="utf-8")
            except OSError as exc:
                raise ScanError(f"Could not write report to {args.output}: {exc}") from exc
        else:
            sys.stdout.write(report)
        fail_on = args.fail_on or configured_fail_on
        return 1 if has_blocking_findings(summary.findings, fail_on) else 0
    except ScanError as exc:
        print(f"treeward: error: {exc}", file=sys.stderr)
        return 2
