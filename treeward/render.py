from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from urllib.parse import quote

from . import __version__
from .models import Finding, ScanSummary
from .scanner import RULES

_LEVEL = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _console_safe(value: str) -> str:
    return "".join(
        char
        if char.isprintable()
        else f"\\u{ord(char):04x}" if ord(char) <= 0xFFFF
        else f"\\U{ord(char):08x}"
        for char in value
    )


def counts(findings: tuple[Finding, ...]) -> dict[str, int]:
    found = Counter(item.severity for item in findings)
    return {
        "high": found["high"],
        "medium": found["medium"],
        "low": found["low"],
        "info": found["info"],
    }


def has_blocking_findings(findings: tuple[Finding, ...], fail_on: str) -> bool:
    if fail_on == "never":
        return False
    cutoff = _LEVEL[fail_on]
    return any(_LEVEL[item.severity] <= cutoff for item in findings)


def render_text(summary: ScanSummary, *, color: bool = False) -> str:
    def paint(value: str, code: str) -> str:
        return f"\033[{code}m{value}\033[0m" if color else value

    totals = counts(summary.findings)
    lines = [
        f"TreeWard scanned {_console_safe(summary.root)}",
        f"Checked {summary.files_checked} text files; skipped {summary.files_skipped} files.",
        "Scope: tracked and non-ignored untracked working-tree files; the Git index and history are not scanned.",
        "",
    ]
    if not summary.findings:
        lines.append(paint("No findings.", "32"))
    else:
        for finding in summary.findings:
            label = finding.severity.upper()
            label_color = {
                "high": "31;1",
                "medium": "33;1",
                "low": "36;1",
                "info": "34;1",
            }[finding.severity]
            safe_path = _console_safe(finding.path)
            where = f"{safe_path}:{finding.line}" if finding.line else safe_path
            lines.append(
                f"{paint(label, label_color)} {finding.rule_id} {where} — {finding.message}"
            )
            lines.append(f"  Fix: {finding.remediation}")
        lines.append("")
        lines.append(
            "Summary: "
            + ", ".join(
                f"{key} {totals[key]}"
                for key in ("high", "medium", "low", "info")
            )
        )
    return "\n".join(lines) + "\n"


def render_json(summary: ScanSummary) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "tool": {"name": "TreeWard", "version": __version__},
            "scan": {
                "root": ".",
                "files_checked": summary.files_checked,
                "files_skipped": summary.files_skipped,
                "index_scanned": False,
                "history_scanned": False,
            },
            "summary": counts(summary.findings),
            "findings": [finding.to_dict() for finding in summary.findings],
        },
        indent=2,
        ensure_ascii=True,
    ) + "\n"


def _source_root_uri(root: str) -> str:
    uri = Path(root).as_uri()
    return uri if uri.endswith("/") else uri + "/"


def render_sarif(summary: ScanSummary) -> str:
    rules = [
        {
            "id": rule_id,
            "name": info["name"],
            "shortDescription": {"text": info["description"]},
            "help": {"text": info["remediation"]},
        }
        for rule_id, info in RULES.items()
    ]
    results = []
    for finding in summary.findings:
        result: dict[str, object] = {
            "ruleId": finding.rule_id,
            "level": {
                "high": "error",
                "medium": "warning",
                "low": "note",
                "info": "note",
            }[finding.severity],
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": quote(
                                finding.path.replace("\\", "/"),
                                safe="/.-_",
                                errors="surrogateescape",
                            ),
                            "uriBaseId": "%SRCROOT%",
                        },
                        **(
                            {"region": {"startLine": finding.line}}
                            if finding.line is not None
                            else {}
                        ),
                    }
                }
            ],
        }
        results.append(result)
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "TreeWard",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": _source_root_uri(summary.root)}
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"
