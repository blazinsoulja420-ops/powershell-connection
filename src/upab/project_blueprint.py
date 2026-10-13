"""Preview-only project folder and ChatGPT workstream blueprints.

Generates text descriptions. Never creates directories, Git repos, chats,
tasks, integrations or approvals.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .multiwatch import ProjectRegistry, RegistryError
from .project_intake import IntakeError, classify_request


BLUEPRINT_SCHEMA = "upab.project-blueprint.preview.v1"
_FOLDERS = (
    "docs",
    "docs/handoffs",
    "src",
    "tests",
    "evidence",
    "research",
)
_FILES = (
    "README.md",
    "docs/PROJECT_CHARTER.md",
    "docs/REQUIREMENTS.md",
    "docs/ARCHITECTURE.md",
    "docs/SECURITY.md",
    "docs/TEST_PLAN.md",
    "docs/RELEASE_CHECKLIST.md",
)
_ROLES = (
    ("main-command-center", "Main Command Center", "Discovery"),
    ("research-discovery", "Research & Discovery", "Research"),
    ("development-coding", "Development & Coding", "Architecture"),
    ("testing-debugging", "Testing & Debugging", "Testing"),
    ("security-audit", "Security & Audit", "Security"),
    ("deployment-integration", "Deployment & Integration", "Deployment"),
)


class BlueprintError(ValueError):
    pass


def preview_blueprint(proposal: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(proposal, dict):
        raise BlueprintError("missing validated intake proposal")
    if proposal.get("schema") != "upab.project-intake.proposal.v1":
        raise BlueprintError("unexpected proposal schema")
    if proposal.get("creation_authorized") is not False:
        raise BlueprintError("creation authorization is forbidden in preview")
    if proposal.get("status") not in {"PROPOSED_EXPLICIT", "SUGGESTED_IDEA"}:
        raise BlueprintError("cannot blueprint an existing, blocked, or non-project request")
    slug = proposal.get("suggested_project_id")
    if (not isinstance(slug, str) or not 2 <= len(slug) <= 63
            or not slug[0].isalpha()
            or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in slug)):
        raise BlueprintError("project ID must be reviewed and normalized first")
    project_title = slug.replace("-", " ").title()
    chats = []
    for role, name, mode in _ROLES:
        prompt = (
            f"PROJECT: {project_title}\n"
            f"PROJECT ID (PROPOSED): {slug}\n"
            f"WORKSTREAM: {name}\n"
            f"INITIAL MODE: {mode}\n\n"
            "MISSION: Define and advance the assigned independent project workstream.\n"
            "This is a draft chat workspace. No project, repository, file or "
            "ChatGPT conversation has been created by this preview.\n"
            "Begin with context and evidence assessment. Do not invent repository "
            "paths, implementation status or authorizations.\n"
            "Preserve project isolation and existing security policy. "
            "Any proposed file mutation, integration, deployment, paid service "
            "or security-sensitive action requires separate verified authority.\n"
            "Record decisions, risks, validation evidence and a specific next step. "
            "Coordinate through the project's Main Command Center; do not "
            "automatically approve or merge changes.\n"
        )
        chats.append({
            "workstream_id": role,
            "proposed_chat_title": f"{project_title} — {name}",
            "starting_prompt": prompt,
            "chat_created": False,
        })
    return {
        "schema": BLUEPRINT_SCHEMA,
        "proposal_id": proposal.get("proposal_id"),
        "project_id": slug,
        "status": "PREVIEW_ONLY",
        "review_required": True,
        "creation_authorized": False,
        "folder_created": False,
        "repo_created": False,
        "chat_created": False,
        "root_path": None,
        "relative_folders": list(_FOLDERS),
        "relative_files": list(_FILES),
        "proposed_chats": chats,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Show proposed folder skeleton and chat prompts without creating anything"
    )
    parser.add_argument("--registry", required=True)
    parser.add_argument("--text", required=True)
    args = parser.parse_args(argv)
    try:
        registry = ProjectRegistry.from_file(args.registry)
        proposal = classify_request(args.text, registry)
        preview = preview_blueprint(proposal)
    except (RegistryError, IntakeError, BlueprintError) as exc:
        print("PROJECT_BLUEPRINT_BLOCKED: " + str(exc), file=sys.stderr)
        return 7
    print(json.dumps(preview, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
