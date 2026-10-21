from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

Severity = Literal["high", "medium", "low", "info"]


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    path: str
    message: str
    remediation: str
    line: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ScanSummary:
    root: str
    files_checked: int
    files_skipped: int
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "files_checked": self.files_checked,
            "files_skipped": self.files_skipped,
            "findings": [finding.to_dict() for finding in self.findings],
        }
