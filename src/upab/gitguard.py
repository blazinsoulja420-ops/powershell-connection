from __future__ import annotations

import subprocess
from pathlib import Path

from .security import sanitized_env


class GitGuardError(RuntimeError):
    pass


def _run(repo: Path, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env=sanitized_env(),
    )


class GitGuard:
    def __init__(self, repo_root: Path, expected_head: str | None = None):
        self.repo_root = repo_root
        self.is_git = (repo_root / ".git").exists() or _run(
            repo_root, ["rev-parse", "--is-inside-work-tree"]
        ).returncode == 0

        self.baseline_head: str | None = None
        self.initial_paths: set[str] = set()
        self.owned_changes: set[str] = set()

        if self.is_git:
            actual = self.current_head()
            if expected_head and actual != expected_head:
                raise GitGuardError(
                    f"HEAD mismatch: expected {expected_head}, actual {actual}"
                )
            self.baseline_head = expected_head or actual
            self.initial_paths = self.status_paths()

    def current_head(self) -> str:
        cp = _run(self.repo_root, ["rev-parse", "HEAD"])
        if cp.returncode != 0:
            raise GitGuardError(cp.stderr.strip() or "Unable to read Git HEAD")
        return cp.stdout.strip()

    def status_text(self) -> str:
        if not self.is_git:
            return "NOT_A_GIT_REPOSITORY"
        cp = _run(
            self.repo_root,
            ["status", "--porcelain=v1", "--untracked-files=all"],
        )
        if cp.returncode != 0:
            raise GitGuardError(cp.stderr.strip() or "git status failed")
        return cp.stdout

    def status_paths(self) -> set[str]:
        paths: set[str] = set()
        for line in self.status_text().splitlines():
            if len(line) < 4:
                continue
            raw = line[3:].strip()
            if " -> " in raw:
                raw = raw.split(" -> ", 1)[1]
            paths.add(raw.replace("\\", "/").strip('"'))
        return paths

    def assert_head_unchanged(self) -> None:
        if self.is_git and self.baseline_head:
            actual = self.current_head()
            if actual != self.baseline_head:
                raise GitGuardError(
                    f"Repository HEAD changed during session: baseline={self.baseline_head}, actual={actual}"
                )

    def assert_no_unexpected_changes(self) -> None:
        if not self.is_git:
            return
        current = self.status_paths()
        allowed = self.initial_paths | self.owned_changes
        unexpected = current - allowed
        if unexpected:
            raise GitGuardError(
                "Unexpected repository path changes detected: "
                + ", ".join(sorted(unexpected))
            )

    def assert_mutation_ready(self, authorized_paths: set[str]) -> None:
        self.assert_head_unchanged()
        self.assert_no_unexpected_changes()
        unauthorized_preexisting = self.initial_paths - authorized_paths
        if unauthorized_preexisting:
            raise GitGuardError(
                "Mutation blocked because the session began with changed paths outside "
                "the authorized manifest: "
                + ", ".join(sorted(unauthorized_preexisting))
            )

    def mark_owned_change(self, rel_path: str) -> None:
        self.owned_changes.add(rel_path.replace("\\", "/"))
