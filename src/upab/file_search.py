from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class FileSearchMatch:
    path: str
    kind: str
    size: int | None = None


def search_files(
    roots: Iterable[Path],
    *,
    query: str,
    max_results: int = 200,
    include_directories: bool = False,
) -> tuple[FileSearchMatch, ...]:
    q = query.strip().lower()
    if not q:
        raise ValueError("query is required")
    results: list[FileSearchMatch] = []
    for root in roots:
        root = root.resolve()
        if not root.exists():
            continue
        for item in root.rglob("*"):
            try:
                name = item.name.lower()
                if q not in name:
                    continue
                if item.is_dir() and not include_directories:
                    continue
                results.append(
                    FileSearchMatch(
                        path=str(item),
                        kind="directory" if item.is_dir() else "file",
                        size=None if item.is_dir() else item.stat().st_size,
                    )
                )
                if len(results) >= max_results:
                    return tuple(results)
            except (OSError, PermissionError):
                continue
    return tuple(results)
