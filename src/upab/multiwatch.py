"""Fail-closed five-project registry preflight; no clipboard or task execution.

This module deliberately only verifies operator-selected repository bindings.
It does NOT install, enable, or run watchers or create project state.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

SCHEMA = "upab.multi-project.registry.v1"
_NAME = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_PROFILE_KEYS = frozenset(
    {
        "id", "repository", "channel_id", "watch_enabled",
        "execution_enabled", "local_root", "state_directory",
    }
)


class RegistryError(ValueError):
    pass


@dataclass(frozen=True)
class ProjectProfile:
    id: str
    repository: str
    channel_id: str
    watch_enabled: bool
    root: Path | None
    state_directory: Path | None

    def preflight(self) -> dict[str, str]:
        """Read-only repository identity check; never execute a relay task."""
        status = "NOT_ARMED"
        if self.watch_enabled:
            assert self.root is not None
            try:
                proc = subprocess.run(
                    ["git", "-C", str(self.root), "remote", "get-url", "origin"],
                    capture_output=True, text=True, timeout=8, check=False,
                    stdin=subprocess.DEVNULL,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise RegistryError(f"{self.id}: git identity unavailable ({type(exc).__name__})") from exc
            if proc.returncode != 0:
                raise RegistryError(f"{self.id}: repository origin unavailable")
            origin = _github_repo_from_origin(proc.stdout.strip())
            if origin.casefold() != self.repository.casefold():
                raise RegistryError(f"{self.id}: repository origin does not match approved binding")
            status = "READY_READ_ONLY_PREFLIGHT"
        return {
            "id": self.id,
            "repository": self.repository,
            "watcher": status,
            "execution": "DISABLED",
        }


def _github_repo_from_origin(origin: str) -> str:
    if origin.startswith("git@github.com:"):
        candidate = origin[len("git@github.com:"):]
    else:
        parts = urlsplit(origin)
        if (
            parts.hostname != "github.com"
            or parts.scheme not in {"https", "ssh"}
            or parts.query or parts.fragment or parts.password
            or (parts.username and not (parts.scheme == "ssh" and parts.username == "git"))
        ):
            raise RegistryError("repository origin is not an approved GitHub remote")
        candidate = parts.path.lstrip("/")
    if candidate.endswith(".git"):
        candidate = candidate[:-4]
    if not _REPOSITORY.fullmatch(candidate):
        raise RegistryError("repository origin is not an exact owner/repository path")
    return candidate


def _optional_absolute(value: object, name: str, *, must_exist: bool) -> Path | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise RegistryError(f"{name} must be an absolute path or null")
    raw = Path(value).expanduser()
    if not raw.is_absolute():
        raise RegistryError(f"{name} must be an absolute path")
    try:
        canonical = raw.resolve(strict=must_exist)
    except (OSError, RuntimeError) as exc:
        raise RegistryError(f"{name} could not be resolved ({type(exc).__name__})") from exc
    if must_exist and not canonical.is_dir():
        raise RegistryError(f"{name} must point to an existing directory")
    return canonical


def _overlap(a: Path, b: Path) -> bool:
    return a == b or a.is_relative_to(b) or b.is_relative_to(a)


class ProjectRegistry:
    def __init__(self, projects: tuple[ProjectProfile, ...]):
        self.projects = projects

    @classmethod
    def from_object(cls, raw: object) -> "ProjectRegistry":
        if not isinstance(raw, dict) or set(raw) != {"schema", "projects"}:
            raise RegistryError("registry must contain exactly schema and projects")
        if raw["schema"] != SCHEMA:
            raise RegistryError("unsupported multi-project registry schema")
        source = raw["projects"]
        if not isinstance(source, list) or not 1 <= len(source) <= 64:
            raise RegistryError("projects must be a non-empty array with at most 64 profiles")

        names: set[str] = set()
        repositories: set[str] = set()
        channels: set[str] = set()
        profiles: list[ProjectProfile] = []

        for item in source:
            if not isinstance(item, dict) or set(item) != _PROFILE_KEYS:
                raise RegistryError("project profile has missing or unknown fields")
            name, repo, channel = item["id"], item["repository"], item["channel_id"]
            if not isinstance(name, str) or not _NAME.fullmatch(name):
                raise RegistryError("invalid project id")
            if not isinstance(repo, str) or not _REPOSITORY.fullmatch(repo):
                raise RegistryError(f"{name}: invalid repository identifier")
            if not isinstance(channel, str) or not _NAME.fullmatch(channel):
                raise RegistryError(f"{name}: invalid channel identifier")
            if name.casefold() in names or repo.casefold() in repositories or channel.casefold() in channels:
                raise RegistryError(f"{name}: duplicated project, repository, or channel")
            names.add(name.casefold())
            repositories.add(repo.casefold())
            channels.add(channel.casefold())
            if type(item["watch_enabled"]) is not bool or type(item["execution_enabled"]) is not bool:
                raise RegistryError(f"{name}: watcher/execution flags must be booleans")
            if item["execution_enabled"]:
                raise RegistryError(f"{name}: this candidate never authorizes task execution")
            active = item["watch_enabled"]
            root = _optional_absolute(item["local_root"], f"{name}.local_root", must_exist=active)
            state = _optional_absolute(item["state_directory"], f"{name}.state_directory", must_exist=active)
            if active and (root is None or state is None):
                raise RegistryError(f"{name}: enabled preflight requires both bound paths")
            profiles.append(ProjectProfile(name, repo, channel, active, root, state))

        # No nested projects; state must be separate from all repository roots
        # and from all other project state, even when currently disarmed.
        rooted = [(p.id, p.root) for p in profiles if p.root is not None]
        states = [(p.id, p.state_directory) for p in profiles if p.state_directory is not None]
        for i, (id_a, a) in enumerate(rooted):
            for id_b, b in rooted[i + 1:]:
                if _overlap(a, b):
                    raise RegistryError(f"{id_a}/{id_b}: repository roots overlap")
            for id_b, b in states:
                if _overlap(a, b):
                    raise RegistryError(f"{id_a}/{id_b}: state overlaps repository root")
        for i, (id_a, a) in enumerate(states):
            for id_b, b in states[i + 1:]:
                if _overlap(a, b):
                    raise RegistryError(f"{id_a}/{id_b}: state directories overlap")
        return cls(tuple(profiles))

    @classmethod
    def from_file(cls, path: str | Path) -> "ProjectRegistry":
        try:
            with Path(path).open("r", encoding="utf-8-sig") as handle:
                return cls.from_object(json.load(handle))
        except (OSError, json.JSONDecodeError) as exc:
            raise RegistryError(f"registry unreadable ({type(exc).__name__})") from exc

    def preflight(self) -> list[dict[str, str]]:
        return [profile.preflight() for profile in self.projects]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only UPAB project binding preflight")
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        registry = ProjectRegistry.from_file(args.config)
        report = registry.preflight()
    except RegistryError as exc:
        print(f"PROJECT_PREFLIGHT_BLOCKED: {exc}", file=sys.stderr)
        return 7
    print(json.dumps({"schema": SCHEMA, "profiles": report}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
