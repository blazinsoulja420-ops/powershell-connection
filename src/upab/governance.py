from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .models import Decision


AUTHORITY_PRECEDENCE = (
    "EXTERNAL_CONSTRAINTS",
    "UNIVERSAL_GOVERNANCE_UPGS",
    "UPRS",
    "PROJECT_GOVERNANCE",
    "PROJECT_RULES",
    "PHASE_CONTROLS",
    "AUTHORIZED_SCOPE",
    "TASK_AUTHORIZATION",
    "CURRENT_EXECUTION_INSTRUCTION",
)

READ_TOOLS = {
    "read_file",
    "list_files",
    "hash_file",
    "git_status",
    "git_diff",
}

DENY_POWERSHELL_PATTERNS = [
    r"(?i)\bRemove-Item\b",
    r"(?i)\bClear-Content\b",
    r"(?i)\bSet-Content\b",
    r"(?i)\bAdd-Content\b",
    r"(?i)\bOut-File\b",
    r"(?i)\bNew-Item\b",
    r"(?i)\bCopy-Item\b",
    r"(?i)\bMove-Item\b",
    r"(?i)\bRename-Item\b",
    r"(?i)\bFormat-(Volume|Disk)\b",
    r"(?i)\bClear-Disk\b",
    r"(?i)\bInitialize-Disk\b",
    r"(?i)\bSet-Partition\b",
    r"(?i)\bdiskpart(?:\.exe)?\b",
    r"(?i)\bSet-ExecutionPolicy\b",
    r"(?i)\breg(?:\.exe)?\s+(add|delete|import|restore)\b",
    r"(?i)\b(sc|net)\.exe\b",
    r"(?i)\b(New|Set|Stop|Remove)-Service\b",
    r"(?i)\b(Start-Process).*-Verb\s+RunAs\b",
    r"(?i)\brunas(?:\.exe)?\b",
    r"(?i)\b(Stop-Computer|Restart-Computer|shutdown(?:\.exe)?)\b",
    r"(?i)\b(Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)\b",
    r"(?i)\b(curl|wget|ssh|scp|ftp|bitsadmin)(?:\.exe)?\b",
    r"(?i)\b(winget|choco|scoop)(?:\.exe)?\b",
    r"(?i)\bpip(?:3)?\s+install\b",
    r"(?i)\bnpm\s+(install|i)\b",
    r"(?i)\bdotnet\s+tool\s+install\b",
    r"(?i)\bgit\s+push\b",
    r"(?i)\bgit\s+commit\b",
    r"(?i)\bgit\s+reset\s+--hard\b",
    r"(?i)\bgit\s+clean\b",
    r"(?i)\bgit\s+checkout\s+--\b",
    r"(?i)\bgit\s+restore\b",
    r"(?i)\bGet-ChildItem\s+Env:",
    r"(?i)\$env:",
]

CHAINING_RE = re.compile(r"(;|&&|\|\||\r|\n|`)")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


class GovernanceGate:
    def __init__(self, cfg: dict[str, Any], repo_root: Path):
        self.cfg = cfg
        self.repo_root = repo_root.resolve()
        self.gov = cfg["governance"]
        self.authorized_write_paths = set(self.gov["authorized_write_paths"])

    def canonical_binding_status(self) -> tuple[bool, str]:
        path_value = self.gov.get("canonical_package_path")
        if not path_value:
            return False, "canonical_package_path is not configured"
        path = Path(path_value)
        if not path.is_file():
            return False, f"canonical governance package not found: {path}"
        actual = sha256_file(path)
        expected = self.gov["canonical_package_sha256"].upper()
        if actual != expected:
            return False, f"canonical package SHA-256 mismatch: expected={expected}, actual={actual}"
        return True, f"UPGS {self.gov['upgs_version']} package hash verified"

    def mutation_authority_status(self) -> tuple[bool, str]:
        if self.gov.get("read_only", True):
            return False, "read_only=true"
        if self.gov.get("require_canonical_for_mutation", True):
            ok, reason = self.canonical_binding_status()
            if not ok:
                return False, reason
        return True, "mutation authority prerequisites satisfied"

    def resolve_repo_path(self, rel: str) -> tuple[Path | None, str]:
        if not isinstance(rel, str) or not rel.strip():
            return None, "path is required"
        normalized = rel.replace("\\", "/").lstrip("/")
        candidate = (self.repo_root / normalized).resolve()
        try:
            candidate.relative_to(self.repo_root)
        except ValueError:
            return None, "path escapes repository root"
        return candidate, normalized

    def authorize(self, tool: str, args: dict[str, Any]) -> Decision:
        if tool in READ_TOOLS:
            if tool in {"read_file", "list_files", "hash_file"}:
                path_value = args.get("path", ".")
                path, _ = self.resolve_repo_path(path_value)
                if path is None:
                    return Decision(False, "SCOPE_PATH_ESCAPE", "Path escapes repository root", "HIGH", True)
            return Decision(True, "ALLOW_READ", "Read-only repository operation allowed")

        if tool == "run_powershell":
            command = str(args.get("command", "")).strip()
            if not command:
                return Decision(False, "PS_EMPTY", "PowerShell command is empty", "LOW", False)
            if CHAINING_RE.search(command):
                return Decision(
                    False,
                    "PS_CHAINING_DENIED",
                    "PowerShell command chaining/newlines/backticks are denied in v1",
                    "HIGH",
                    True,
                )
            for pattern in DENY_POWERSHELL_PATTERNS:
                if re.search(pattern, command):
                    return Decision(
                        False,
                        "PS_DENY_PATTERN",
                        "PowerShell command matched a denied mutation/security/network pattern",
                        "HIGH",
                        True,
                    )
            allowed = self.gov.get("powershell_allow_prefixes", [])
            if not any(command.lower().startswith(x.lower()) for x in allowed):
                return Decision(
                    False,
                    "PS_PREFIX_NOT_ALLOWED",
                    "PowerShell command is outside the configured read-only allow-list",
                    "MEDIUM",
                    True,
                )
            return Decision(True, "ALLOW_PS_READ", "Allow-listed read-only PowerShell command")

        if tool == "run_tests":
            if not self.gov.get("allow_test_execution", False):
                return Decision(False, "TESTS_DISABLED", "Test execution is disabled", "MEDIUM", True)
            return Decision(
                True,
                "ALLOW_TEST",
                "Operator-configured test command allowed; repository test code is trusted-code execution",
                "MEDIUM",
                False,
            )

        if tool == "write_file":
            ok, reason = self.mutation_authority_status()
            if not ok:
                return Decision(False, "MUTATION_PRECONDITION", reason, "HIGH", True)
            path, normalized = self.resolve_repo_path(str(args.get("path", "")))
            if path is None:
                return Decision(False, "SCOPE_PATH_ESCAPE", "Path escapes repository root", "HIGH", True)
            if normalized not in self.authorized_write_paths:
                return Decision(
                    False,
                    "WRITE_NOT_IN_MANIFEST",
                    f"Write path is not in exact authorized manifest: {normalized}",
                    "HIGH",
                    True,
                )
            return Decision(True, "ALLOW_MANIFEST_WRITE", f"Exact manifest write allowed: {normalized}", "MEDIUM")

        if tool == "rollback_last_write":
            ok, reason = self.mutation_authority_status()
            if not ok:
                return Decision(False, "ROLLBACK_PRECONDITION", reason, "HIGH", True)
            return Decision(True, "ALLOW_SESSION_ROLLBACK", "Rollback limited to current-session write backup", "MEDIUM")

        return Decision(False, "UNKNOWN_TOOL", f"Unknown or unauthorized tool: {tool}", "HIGH", True)
