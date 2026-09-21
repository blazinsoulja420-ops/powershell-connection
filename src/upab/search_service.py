from __future__ import annotations

from pathlib import Path
from typing import Iterable

from upab.file_search import FileSearchMatch, search_files


def resolve_search_roots(configured_roots: Iterable[str]) -> tuple[Path, ...]:
    roots: list[Path] = []
    for raw in configured_roots:
        path = Path(raw).expanduser().resolve()
        if path.exists():
            roots.append(path)
    return tuple(roots)


def find_files(configured_roots: Iterable[str], query: str, max_results: int = 200) -> tuple[FileSearchMatch, ...]:
    roots = resolve_search_roots(configured_roots)
    if not roots:
        raise ValueError("no configured search roots are available")
    return search_files(roots, query=query, max_results=max_results)
