"""Human-reviewed intake proposals for Universal AI's multi-project manager.

No filesystem mutations, chat API calls, clipboard reads or approvals exist here.
Untrusted text can ONLY produce a suggestion; it can never grant authority.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
import unicodedata
from typing import Any

from .multiwatch import ProjectRegistry, RegistryError

MAX_REGISTERED_PROJECTS = 64
INTAKE_SCHEMA = "upab.project-intake.proposal.v1"
_WORD = re.compile(r"[^a-z0-9]+")
_EXPLICIT = re.compile(
    r"^(?:please\s+)?(?:create|start|make|set\s+up|initialize|register)\s+"
    r"(?:(?:me\s+)?(?:a\s+)?)?(?:brand[\s-]+new\s+|new\s+)?"
    r"project(?:\s+(?:called|named|for)\s+(.+))?$",
    re.IGNORECASE,
)
_IDEA = re.compile(
    r"^(?:i\s+(?:want|would\s+like|plan|hope)\s+to\s+"
    r"(?:build|create|develop|make)|"
    r"i(?:'m|\s+am)\s+(?:thinking|planning)\s+"
    r"(?:of|about)\s+(?:building|creating|developing)|"
    r"what\s+if\s+(?:we|i)\s+(?:build|create)|"
    r"could\s+we\s+(?:build|create)|"
    r"let'?s\s+(?:build|create))\b(?:\s+(.+))?$",
    re.IGNORECASE,
)
_NEGATE = re.compile(
    r"^(?:do\s+not|don't|never|stop|avoid|how\s+(?:do|can|would)|"
    r"why\s+(?:did|would)|can\s+you\s+explain|"
    r"i\s+do\s+not|i\s+don't)\b", re.IGNORECASE,
)
_LEADING = re.compile(r"^(?:an?\s+|the\s+|new\s+)+", re.IGNORECASE)
_TRAILING = re.compile(r"(?:[.!?])+$")
_GENERIC_NAMES = frozenset({"project", "app", "application", "system", "software", "tool", "a", "new"})
_WORKSTREAMS = (
    "main-command-center",
    "research-discovery",
    "development-coding",
    "testing-debugging",
    "security-audit",
    "deployment-integration",
)


class IntakeError(ValueError):
    pass


def slugify(label: str) -> str:
    ascii_text = unicodedata.normalize("NFKD", label).encode("ascii", "ignore").decode("ascii")
    candidate = _WORD.sub("-", ascii_text.lower()).strip("-")
    if not candidate or len(candidate) < 2 or len(candidate) > 63:
        raise IntakeError("project name must be 2-63 normalized characters")
    if candidate in _GENERIC_NAMES:
        raise IntakeError("project name is too generic")
    return candidate


def _safe_text(text: object) -> str:
    if not isinstance(text, str):
        raise IntakeError("request must be a single text string")
    if len(text) > 500:
        raise IntakeError("request exceeds 500 characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise IntakeError("request must be one line without control characters")
    normalized = unicodedata.normalize("NFKC", text).strip()
    if not normalized:
        raise IntakeError("request is empty")
    return normalized


def _clean_name(raw: str) -> str:
    value = _TRAILING.sub("", raw.strip())
    value = re.sub(r"^(?:called|named)\s+", "", value, flags=re.IGNORECASE)
    value = _LEADING.sub("", value).strip()
    if not value:
        raise IntakeError("project name missing")
    # Preserve the original proposed title only as safe display text, not as a command.
    return value[:120]


def _reviewable_name(raw: str) -> str | None:
    try:
        return _clean_name(raw)
    except IntakeError:
        return None


def _guess_idea_name(details: str) -> str:
    details = details.strip()
    named = re.search(r"\b(?:called|named)\s+(.+)$", details, re.IGNORECASE)
    if named:
        return _clean_name(named.group(1))
    # A name derived from conversational phrasing is ONLY a suggestion.
    return _clean_name(details)


def _reviewable_idea_name(details: str) -> str | None:
    try:
        return _guess_idea_name(details)
    except IntakeError:
        return None


def _aliases(profile) -> set[str]:
    repo_name = profile.repository.split("/", 1)[1]
    names = (profile.id, repo_name, repo_name.split("-", 1)[-1])
    return {_WORD.sub("", x.casefold()) for x in names}


def _duplicates(registry: ProjectRegistry, candidate: str) -> list[str]:
    search = _WORD.sub("", candidate.casefold())
    matches = []
    for p in registry.projects:
        aliases = _aliases(p)
        close = any(
            search == alias
            or (len(search) >= 4 and len(alias) >= 4
                and (search.startswith(alias + "v2") or alias.startswith(search + "v2")))
            or difflib.SequenceMatcher(None, search, alias).ratio() >= 0.86
            for alias in aliases
        )
        # Catch exact first-term aliases such as "UASN AI Specialist".
        if not close and len(p.id) >= 4:
            close = candidate.startswith(p.id + "-")
        if close:
            matches.append(p.id)
    return matches


def classify_request(request: str, registry: ProjectRegistry) -> dict[str, Any]:
    """Classify ONLY manually submitted text; NEVER create/approve anything."""
    text = _safe_text(request)
    normalized = text
    mode: str = "none"
    candidate_name: str | None = None

    if not _NEGATE.match(normalized):
        explicit = _EXPLICIT.fullmatch(normalized)
        if explicit is None:
            explicit = _EXPLICIT.fullmatch(_TRAILING.sub("", normalized))
        if explicit:
            mode = "explicit"
            if explicit.group(1):
                candidate_name = _reviewable_name(explicit.group(1))
        else:
            idea = _IDEA.fullmatch(normalized)
            if idea is None:
                idea = _IDEA.fullmatch(_TRAILING.sub("", normalized))
            if idea and idea.group(1):
                mode = "idea"
                candidate_name = _reviewable_idea_name(idea.group(1))

    slug: str | None = None
    needs_name = False
    if mode != "none":
        if candidate_name is None:
            needs_name = True
        else:
            try:
                slug = slugify(candidate_name)
            except IntakeError:
                needs_name = True
                candidate_name = None

    duplicate_ids = _duplicates(registry, slug) if slug else []
    capacity = len(registry.projects) >= MAX_REGISTERED_PROJECTS
    if mode == "none":
        status = "NO_PROJECT_REQUEST"
    elif duplicate_ids:
        status = "REVIEW_EXISTING"
    elif capacity:
        status = "CAPACITY_BLOCKED"
    elif mode == "explicit":
        status = "PROPOSED_EXPLICIT"
    else:
        status = "SUGGESTED_IDEA"

    # Derive a stable non-secret proposal ID. This is NOT authentication.
    fingerprint = hashlib.sha256(
        json.dumps({"mode": mode, "slug": slug, "source": normalized.casefold()},
                   sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:24]
    return {
        "schema": INTAKE_SCHEMA,
        "proposal_id": fingerprint if mode != "none" else None,
        "status": status,
        "detection_mode": mode,
        "suggested_name": candidate_name,
        "suggested_project_id": slug,
        "name_requires_review": needs_name,
        "possible_existing_projects": duplicate_ids,
        "registered_projects": len(registry.projects),
        "max_registered_projects": MAX_REGISTERED_PROJECTS,
        "suggested_workstreams": list(_WORKSTREAMS) if mode != "none" else [],
        "approval_state": "NOT_REQUESTED",
        "requires_explicit_owner_approval": mode != "none",
        "creation_authorized": False,
        "creates_folders": False,
        "creates_chats": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Propose projects from explicit commands or ideas, without side effects"
    )
    parser.add_argument("--registry", required=True, help="Existing multi-project registry JSON")
    parser.add_argument("--text", required=True, help="One manually submitted user request")
    args = parser.parse_args(argv)
    try:
        registry = ProjectRegistry.from_file(args.registry)
        proposal = classify_request(args.text, registry)
    except (RegistryError, IntakeError) as exc:
        print("PROJECT_INTAKE_BLOCKED: " + str(exc), file=sys.stderr)
        return 7
    print(json.dumps(proposal, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
