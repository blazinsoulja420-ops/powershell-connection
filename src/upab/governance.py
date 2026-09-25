from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .models import Decision
from .powershell_commands import COMMANDS


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
            if "command" in args:
                return Decision(False, "PS_RAW_COMMAND_UNSUPPORTED", "Raw PowerShell command input is unsupported", "HIGH", True)
            command_id = args.get("command_id")
            if not isinstance(command_id, str) or not command_id:
                return Decision(False, "PS_COMMAND_ID_REQUIRED", "command_id is required", "MEDIUM", True)
            if command_id not in COMMANDS:
                return Decision(False, "PS_COMMAND_UNKNOWN", "Unknown structured PowerShell command", "MEDIUM", True)
            if command_id not in self.gov.get("powershell_allowed_command_ids", []):
                return Decision(False, "PS_COMMAND_NOT_ALLOWED", "Structured PowerShell command is not allowed", "MEDIUM", True)
            return Decision(True, "ALLOW_PS_READ", "Registered read-only PowerShell operation allowed")

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
