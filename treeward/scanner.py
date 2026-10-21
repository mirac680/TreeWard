from __future__ import annotations

import fnmatch
import math
import os
import re
import subprocess
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from .models import Finding, ScanSummary

DEFAULT_MAX_FILE_SIZE_MB = 2.0
HARD_MAX_FILE_SIZE_MB = 100.0

RULES: dict[str, dict[str, str]] = {
    "TW001": {
        "name": "Private key material",
        "description": "A private key marker was found in a repository file.",
        "remediation": "Remove the key from the repository and rotate or revoke it. If it was committed before, remove it from Git history as well.",
    },
    "TW002": {
        "name": "Known credential pattern",
        "description": "A string matched a pattern used by a known credential provider.",
        "remediation": "Revoke or rotate the credential, then remove it from the repository and any affected Git history.",
    },
    "TW003": {
        "name": "Credential-like assignment",
        "description": "A non-placeholder value is assigned to a credential-like setting.",
        "remediation": "Move the value to a secret store or an untracked environment file. Use a clearly fake placeholder in examples.",
    },
    "TW004": {
        "name": "Sensitive file name",
        "description": "The file name commonly indicates local credentials or private key material.",
        "remediation": "Confirm the file belongs in the public repository. If it contains a credential, revoke it and remove it from Git history.",
    },
    "TW005": {
        "name": "Large file",
        "description": "The file exceeds the configured size limit.",
        "remediation": "Remove generated or accidental large files. For intentional assets, consider Git LFS and document why they are needed.",
    },
    "TW006": {
        "name": "AWS access key identifier",
        "description": "An AWS access key identifier was found. The identifier alone is not a secret credential.",
        "remediation": "Check whether this identifier is active and whether a secret access key was exposed alongside it. Revoke or rotate the key if needed.",
    },
    "TW101": {
        "name": "README missing",
        "description": "No top-level README was found.",
        "remediation": "Add a README with the project purpose, installation steps, a short example, and contribution guidance.",
    },
    "TW102": {
        "name": "License missing",
        "description": "No top-level license file was found.",
        "remediation": "Choose a license that fits your project and add its full text as a LICENSE file.",
    },
}

_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|"
    r"-----BEGIN PGP PRIVATE KEY BLOCK-----"
)
_AWS_ACCESS_KEY_ID = re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")
_KNOWN_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"gh[pousr]_[A-Za-z0-9]{30,}|"
    r"github_pat_[A-Za-z0-9_]{40,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"sk_live_[A-Za-z0-9]{16,}|"
    r"rk_live_[A-Za-z0-9]{16,}|"
    r"AIza[0-9A-Za-z_-]{30,}"
    r")(?![A-Za-z0-9_])"
)
_CALL_REFERENCE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*\([^)]*\)$")
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(?P<key>
      (?:[a-z0-9]+[_-])*
      (?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|
        aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key|
        bearer[_-]?token|refresh[_-]?token|token|
        password|passwd|passphrase|secret[_-]?key|secret|private[_-]?key|signing[_-]?key)
    )\b
    \s*[:=]\s*
    (?P<quote>["']?)
    (?P<value>[^\s"'#;,]{8,})
    """
)
_PLACEHOLDER_PREFIXES = (
    "your_",
    "your-",
    "example_",
    "example-",
    "insert_",
    "insert-",
    "placeholder",
    "changeme",
    "change_me",
    "replace_me",
    "replace-",
    "dummy",
    "fake",
    chr(36) + "{",
    chr(36) + "(",
)
_PLACEHOLDER_WORD = re.compile(
    r"(?i)(?:^|[_-])(?:example|sample|test|changeme|change_me|replace|"
    r"redacted|placeholder|dummy|fake|todo|insert|x{4,})(?:$|[_-])"
)
_DYNAMIC_REFERENCE_PREFIXES = (
    "os.environ",
    "process.env",
    "getenv(",
    "env[",
    "env(",
    "settings.",
    "settings[",
    "config.",
    "config[",
    "vault.",
    "secret_manager.",
    "secrets.",
)
_PLACEHOLDER_VALUES = {
    "password",
    "secret",
    "token",
    "api_key",
    "access_token",
    "client_secret",
    "none",
    "null",
    "undefined",
    "notasecret",
    "not-a-secret",
}
_SAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist")
_SENSITIVE_EXACT = {
    ".env",
    ".envrc",
    ".netrc",
    "credentials",
    "credentials.json",
    "kubeconfig",
    "service-account.json",
    "terraform.tfstate",
    "secrets.yaml",
    "secrets.yml",
}
_README_NAMES = {"readme", "readme.adoc", "readme.md", "readme.rst", "readme.txt"}
_LICENSE_NAMES = {
    "license",
    "license.md",
    "license.txt",
    "license.rst",
    "copying",
    "copying.md",
    "copying.txt",
    "unlicense",
    "unlicense.txt",
}


class ScanError(RuntimeError):
    """An expected, user-correctable scan error."""


def find_repository_root(path: Path) -> Path:
    candidate = path.expanduser().resolve()
    if not candidate.exists():
        raise ScanError(f"Path does not exist: {candidate}")
    if not candidate.is_dir():
        raise ScanError(f"Expected a directory: {candidate}")
    try:
        result = subprocess.run(
            ["git", "-C", str(candidate), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise ScanError("Git was not found. Install Git and try again.") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip()
        suffix = f" ({detail})" if detail else ""
        raise ScanError(f"Not inside a Git repository: {candidate}{suffix}") from exc
    return Path(result.stdout.strip()).resolve()


def list_repository_files(root: Path) -> list[Path]:
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            check=True,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise ScanError("Git was not found. Install Git and try again.") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", errors="replace").strip()
        raise ScanError(f"Could not list repository files: {detail or 'git ls-files failed'}") from exc

    entries = result.stdout.split(b"\0")
    paths: list[Path] = []
    for entry in entries:
        if not entry:
            continue
        relative = entry.decode("utf-8", errors="surrogateescape").replace("\\", "/")
        paths.append(root.joinpath(*PurePosixPath(relative).parts))
    return paths


def is_sensitive_filename(relative: str) -> bool:
    path = PurePosixPath(relative)
    basename = path.name.lower()
    if basename in _SENSITIVE_EXACT:
        return True
    if basename.startswith(".env.") and not basename.endswith(_SAMPLE_SUFFIXES):
        return True
    if basename.endswith(".pub") and basename.startswith(
        ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")
    ):
        return False
    if basename.startswith(("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")):
        return True
    if path.suffix.lower() in {".jks", ".keystore", ".p12", ".pfx", ".key"}:
        return True
    return False


def _matches_excludes(relative: str, patterns: Iterable[str]) -> bool:
    normalized = relative.replace("\\", "/")
    for raw in patterns:
        pattern = raw.strip().replace("\\", "/").strip("/")
        if not pattern:
            continue
        if pattern.endswith("/**"):
            directory = pattern[:-3].rstrip("/")
            if normalized == directory or normalized.startswith(directory + "/"):
                return True
        if fnmatch.fnmatchcase(normalized, pattern):
            return True
        if "/" not in pattern and any(
            fnmatch.fnmatchcase(part, pattern)
            for part in PurePosixPath(normalized).parts
        ):
            return True
    return False


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'").strip().lower()
    if normalized in _PLACEHOLDER_VALUES:
        return True
    if _CALL_REFERENCE.fullmatch(normalized):
        return True
    if any(normalized.startswith(prefix) for prefix in _PLACEHOLDER_PREFIXES):
        return True
    reference = normalized.lstrip("([")
    if any(reference.startswith(prefix) for prefix in _DYNAMIC_REFERENCE_PREFIXES):
        return True
    return _PLACEHOLDER_WORD.search(normalized) is not None


def _credential_findings(text: str, relative: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if _PRIVATE_KEY.search(line):
            findings.append(
                Finding(
                    "TW001",
                    "high",
                    relative,
                    "A private key marker appears in this file.",
                    RULES["TW001"]["remediation"],
                    line_number,
                )
            )
            continue
        if _KNOWN_TOKEN.search(line):
            findings.append(
                Finding(
                    "TW002",
                    "high",
                    relative,
                    "A value matches a known credential pattern. The value was not included in this report.",
                    RULES["TW002"]["remediation"],
                    line_number,
                )
            )
            continue
        if _AWS_ACCESS_KEY_ID.search(line):
            findings.append(
                Finding(
                    "TW006",
                    "medium",
                    relative,
                    "An AWS access key identifier was found. The identifier alone is not a secret credential.",
                    RULES["TW006"]["remediation"],
                    line_number,
                )
            )
            continue
        assignment = _CREDENTIAL_ASSIGNMENT.search(line)
        if assignment:
            value = assignment.group("value").rstrip("\"'")
            if len(value) >= 8 and not _is_placeholder(value):
                key = assignment.group("key").lower().replace("-", "_")
                findings.append(
                    Finding(
                        "TW003",
                        "medium",
                        relative,
                        f"A value is assigned to credential-like setting {key!r}; the value was redacted.",
                        RULES["TW003"]["remediation"],
                        line_number,
                    )
                )
    return findings


def _check_metadata(files: set[str]) -> list[Finding]:
    names = {
        PurePosixPath(path).name.lower()
        for path in files
        if PurePosixPath(path).parent == PurePosixPath(".")
    }
    has_license = bool(names.intersection(_LICENSE_NAMES)) or any(
        name.startswith("license-") for name in names
    )
    findings: list[Finding] = []
    if not names.intersection(_README_NAMES):
        findings.append(
            Finding(
                "TW101",
                "info",
                "README.md",
                "No top-level README was found.",
                RULES["TW101"]["remediation"],
            )
        )
    if not has_license:
        findings.append(
            Finding(
                "TW102",
                "info",
                "LICENSE",
                "No top-level license file was found.",
                RULES["TW102"]["remediation"],
            )
        )
    return findings


def scan_repository(
    root: Path,
    *,
    max_file_size_mb: float = DEFAULT_MAX_FILE_SIZE_MB,
    excludes: Iterable[str] = (),
) -> ScanSummary:
    if not math.isfinite(max_file_size_mb) or max_file_size_mb <= 0:
        raise ScanError("Maximum file size must be a positive number.")
    if max_file_size_mb > HARD_MAX_FILE_SIZE_MB:
        raise ScanError(f"Maximum file size cannot exceed {HARD_MAX_FILE_SIZE_MB:g} MiB.")

    repo_root = find_repository_root(root)
    max_bytes = int(max_file_size_mb * 1024 * 1024)
    findings: list[Finding] = []
    checked = 0
    skipped = 0
    scanned_paths: set[str] = set()

    for path in list_repository_files(repo_root):
        try:
            relative = path.relative_to(repo_root).as_posix()
        except ValueError:
            continue
        if relative.startswith(".git/") or _matches_excludes(relative, excludes):
            skipped += 1
            continue
        try:
            is_link = path.is_symlink()
            if not path.exists() and not is_link:
                skipped += 1
                continue
        except OSError:
            skipped += 1
            continue
        scanned_paths.add(relative)
        if is_sensitive_filename(relative):
            findings.append(
                Finding(
                    "TW004",
                    "high",
                    relative,
                    "This file name commonly indicates local credentials or private key material.",
                    RULES["TW004"]["remediation"],
                )
            )

        try:
            if is_link:
                skipped += 1
                continue
            stat = path.stat()
        except OSError:
            skipped += 1
            continue
        if not path.is_file():
            skipped += 1
            continue
        if stat.st_size > max_bytes:
            findings.append(
                Finding(
                    "TW005",
                    "medium",
                    relative,
                    f"File size is {stat.st_size / (1024 * 1024):.1f} MiB; the configured limit is {max_file_size_mb:g} MiB.",
                    RULES["TW005"]["remediation"],
                )
            )
            skipped += 1
            continue
        try:
            with path.open("rb") as stream:
                data = stream.read(max_bytes + 1)
        except OSError:
            skipped += 1
            continue
        if len(data) > max_bytes:
            findings.append(
                Finding(
                    "TW005",
                    "medium",
                    relative,
                    f"File grew beyond the configured {max_file_size_mb:g} MiB limit while it was read.",
                    RULES["TW005"]["remediation"],
                )
            )
            skipped += 1
            continue
        if b"\0" in data:
            skipped += 1
            continue
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            skipped += 1
            continue
        checked += 1
        findings.extend(_credential_findings(content, relative))

    findings.extend(_check_metadata(scanned_paths))
    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(
        key=lambda item: (
            severity_order[item.severity],
            item.path.casefold(),
            item.line or 0,
            item.rule_id,
        )
    )
    return ScanSummary(
        root=os.fspath(repo_root),
        files_checked=checked,
        files_skipped=skipped,
        findings=tuple(findings),
    )
