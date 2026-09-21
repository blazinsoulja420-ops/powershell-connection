from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .evidence import EvidenceLog
from .gitguard import GitGuard, GitGuardError
from .governance import GovernanceGate, sha256_file
from .models import ToolResult
from .security import redact, sanitized_env


class ToolExecutor:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.repo_root = Path(cfg["repository"]["root"]).resolve()
        if not self.repo_root.is_dir():
            raise FileNotFoundError(f"Repository root does not exist: {self.repo_root}")

        self.gov = cfg["governance"]
        self.gate = GovernanceGate(cfg, self.repo_root)
        self.evidence = EvidenceLog(
            cfg["state"]["directory"],
            max_output_chars=int(self.gov["max_output_chars"]),
        )
        self.git = GitGuard(self.repo_root, cfg["repository"].get("expected_head"))
        self.last_backup: dict[str, Any] | None = None
        self.write_history: list[dict[str, Any]] = []

    def _record_decision(self, tool: str, args: dict[str, Any], decision) -> None:
        summary = dict(args)
        if "content" in summary:
            content = str(summary.pop("content"))
            summary["content_sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest().upper()
            summary["content_chars"] = len(content)
        self.evidence.append({
            "event": "governance_decision",
            "tool": tool,
            "args": summary,
            "allowed": decision.allowed,
            "code": decision.code,
            "reason": decision.reason,
            "risk": decision.risk,
            "fatal": decision.fatal,
        })

    def _guard_session(self) -> None:
        self.git.assert_head_unchanged()
        self.git.assert_no_unexpected_changes()

    def _process(
        self,
        argv: list[str],
        timeout: int,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            argv,
            cwd=str(cwd or self.repo_root),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=sanitized_env(),
        )

    def execute(self, tool: str, args: dict[str, Any]) -> ToolResult:
        decision = self.gate.authorize(tool, args)
        self._record_decision(tool, args, decision)
        if not decision.allowed:
            return ToolResult(False, f"BLOCKED [{decision.code}]: {decision.reason}", fatal=decision.fatal)

        started = time.monotonic()
        try:
            self._guard_session()

            if tool == "read_file":
                result = self._read_file(args)
            elif tool == "list_files":
                result = self._list_files(args)
            elif tool == "hash_file":
                result = self._hash_file(args)
            elif tool == "git_status":
                result = ToolResult(True, self.git.status_text())
            elif tool == "git_diff":
                result = self._git_diff(args)
            elif tool == "run_powershell":
                result = self._run_powershell(args)
            elif tool == "run_tests":
                result = self._run_tests(args)
            elif tool == "write_file":
                result = self._write_file(args)
            elif tool == "rollback_last_write":
                result = self._rollback_last_write()
            else:
                result = ToolResult(False, f"Unsupported tool: {tool}", fatal=True)

        except (OSError, subprocess.SubprocessError, GitGuardError, ValueError) as exc:
            result = ToolResult(False, f"{type(exc).__name__}: {exc}", fatal=True)

        duration_ms = round((time.monotonic() - started) * 1000, 2)
        self.evidence.append({
            "event": "tool_result",
            "tool": tool,
            "ok": result.ok,
            "fatal": result.fatal,
            "duration_ms": duration_ms,
            "output": result.output,
            "metadata": result.metadata,
        })
        return result

    def _resolve(self, raw: str) -> tuple[Path, str]:
        path, normalized = self.gate.resolve_repo_path(raw)
        if path is None:
            raise ValueError("Path escapes repository root")
        return path, normalized

    def _read_file(self, args: dict[str, Any]) -> ToolResult:
        path, rel = self._resolve(str(args["path"]))
        if not path.is_file():
            return ToolResult(False, f"Not a file: {rel}")
        limit = int(self.gov["max_file_read_bytes"])
        data = path.read_bytes()
        if len(data) > limit:
            data = data[:limit]
            suffix = f"\n\n[TRUNCATED at {limit} bytes]"
        else:
            suffix = ""
        text = data.decode("utf-8", errors="replace") + suffix
        return ToolResult(True, text, {"path": rel, "bytes_returned": len(data)})

    def _list_files(self, args: dict[str, Any]) -> ToolResult:
        path, rel = self._resolve(str(args.get("path", ".")))
        if not path.is_dir():
            return ToolResult(False, f"Not a directory: {rel}")
        limit = int(self.gov["max_list_entries"])
        entries: list[str] = []
        for item in path.rglob("*"):
            try:
                rp = item.resolve().relative_to(self.repo_root)
            except ValueError:
                continue
            parts = rp.parts
            if ".git" in parts:
                continue
            entries.append(str(rp).replace("\\", "/") + ("/" if item.is_dir() else ""))
            if len(entries) >= limit:
                break
        entries.sort()
        suffix = "\n[TRUNCATED]" if len(entries) >= limit else ""
        return ToolResult(True, "\n".join(entries) + suffix, {"count": len(entries)})

    def _hash_file(self, args: dict[str, Any]) -> ToolResult:
        path, rel = self._resolve(str(args["path"]))
        if not path.is_file():
            return ToolResult(False, f"Not a file: {rel}")
        return ToolResult(True, sha256_file(path), {"path": rel, "algorithm": "SHA-256"})

    def _git_diff(self, args: dict[str, Any]) -> ToolResult:
        if not self.git.is_git:
            return ToolResult(False, "NOT_A_GIT_REPOSITORY")
        path = args.get("path")
        argv = ["git", "-C", str(self.repo_root), "--no-pager", "diff", "--"]
        if path:
            _, rel = self._resolve(str(path))
            argv.append(rel)
        cp = self._process(argv, int(self.gov["max_command_seconds"]))
        output = (cp.stdout or "") + (("\nSTDERR:\n" + cp.stderr) if cp.stderr else "")
        return ToolResult(cp.returncode == 0, redact(output, int(self.gov["max_output_chars"])), {"returncode": cp.returncode})

    def _run_powershell(self, args: dict[str, Any]) -> ToolResult:
        command = str(args["command"])
        exe = str(self.gov.get("powershell_executable", "powershell.exe"))
        cp = self._process(
            [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            int(self.gov["max_command_seconds"]),
        )
        output = (cp.stdout or "") + (("\nSTDERR:\n" + cp.stderr) if cp.stderr else "")
        return ToolResult(cp.returncode == 0, redact(output, int(self.gov["max_output_chars"])), {"returncode": cp.returncode})

    def _run_tests(self, args: dict[str, Any]) -> ToolResult:
        base = self.gov.get("test_command")
        if not isinstance(base, list) or not base:
            return ToolResult(False, "No operator test_command configured", fatal=True)
        extra = args.get("args") or []
        if not isinstance(extra, list) or not all(isinstance(x, str) for x in extra):
            return ToolResult(False, "Test args must be an array of strings", fatal=True)
        before = self.git.status_paths() if self.git.is_git else set()
        cp = self._process(
            [*base, *extra],
            int(self.gov["max_command_seconds"]),
        )
        after = self.git.status_paths() if self.git.is_git else set()
        unexpected = after - before
        if unexpected:
            return ToolResult(
                False,
                "Test execution changed repository paths unexpectedly: " + ", ".join(sorted(unexpected)),
                {"returncode": cp.returncode},
                fatal=True,
            )
        output = (cp.stdout or "") + (("\nSTDERR:\n" + cp.stderr) if cp.stderr else "")
        return ToolResult(cp.returncode == 0, redact(output, int(self.gov["max_output_chars"])), {"returncode": cp.returncode})

    def _write_file(self, args: dict[str, Any]) -> ToolResult:
        self.git.assert_mutation_ready(set(self.gov["authorized_write_paths"]))

        path, rel = self._resolve(str(args["path"]))
        content = str(args["content"])
        expected = args.get("expected_sha256")
        existed = path.exists()

        if existed:
            if not path.is_file():
                return ToolResult(False, f"Target exists but is not a file: {rel}", fatal=True)
            actual = sha256_file(path)
            if self.gov.get("require_expected_hash_for_overwrite", True):
                if not expected:
                    return ToolResult(False, f"Existing file requires expected_sha256: {rel}", fatal=True)
                if actual.upper() != str(expected).upper():
                    return ToolResult(
                        False,
                        f"Pre-write hash mismatch for {rel}: expected={expected}, actual={actual}",
                        fatal=True,
                    )
        elif expected:
            return ToolResult(False, f"expected_sha256 supplied but target does not exist: {rel}", fatal=True)

        backup = self.evidence.backup_path_for_write(rel, len(self.write_history) + 1)
        if existed:
            shutil.copy2(path, backup)
        else:
            marker = backup.with_suffix(backup.suffix + ".NEWFILE")
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text("NEW_FILE_CREATED_BY_SESSION\n", encoding="utf-8")
            backup = marker

        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".upab-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
                fh.write(content)
            os.replace(tmp_name, path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

        new_hash = sha256_file(path)
        self.git.mark_owned_change(rel)
        self.git.assert_head_unchanged()
        self.git.assert_no_unexpected_changes()

        entry = {
            "path": rel,
            "backup": str(backup),
            "was_new": not existed,
        }
        self.write_history.append(entry)
        self.last_backup = entry
        return ToolResult(
            True,
            f"WROTE {rel}",
            {"path": rel, "sha256": new_hash, "backup": str(backup)},
        )

    def _restore_write_entry(self, entry: dict[str, Any]) -> ToolResult:
        rel = entry["path"]
        path, _ = self._resolve(rel)
        backup = Path(entry["backup"])
        if entry["was_new"]:
            if path.exists():
                path.unlink()
        else:
            if not backup.is_file():
                return ToolResult(False, f"Backup is missing: {backup}", fatal=True)
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup, path)
        return ToolResult(True, f"ROLLED_BACK {rel}")

    def _rollback_last_write(self) -> ToolResult:
        if not self.write_history:
            return ToolResult(False, "No current-session write is available to roll back")
        entry = self.write_history.pop()
        result = self._restore_write_entry(entry)
        self.last_backup = self.write_history[-1] if self.write_history else None
        return result

    def rollback_all_session_writes(self) -> ToolResult:
        if not self.write_history:
            return ToolResult(True, "NO_SESSION_WRITES_TO_ROLL_BACK", {"rolled_back": []})
        rolled_back: list[str] = []
        while self.write_history:
            entry = self.write_history.pop()
            result = self._restore_write_entry(entry)
            if not result.ok:
                self.last_backup = self.write_history[-1] if self.write_history else None
                return ToolResult(
                    False,
                    f"ROLLBACK_INCOMPLETE after {rolled_back}: {result.output}",
                    {"rolled_back": rolled_back},
                    fatal=True,
                )
            rolled_back.append(entry["path"])
        self.last_backup = None
        self.evidence.append({
            "event": "transaction_rollback",
            "rolled_back": rolled_back,
        })
        return ToolResult(True, "ROLLED_BACK_SESSION_WRITES", {"rolled_back": rolled_back})
