from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence


@dataclass(frozen=True)
class ChatMessage:
    chat_id: str
    message_id: str
    role: str
    content: str
    project_hint: str | None = None
    chat_title: str | None = None


@dataclass(frozen=True)
class NextReplySuggestion:
    chat_id: str
    source_message_id: str
    reply: str
    rationale: str
    confidence: str = "INFERRED"


@dataclass(frozen=True)
class ChatClassification:
    chat_id: str
    project_id: str | None
    canonical_topic: str
    suggested_chat_title: str
    suggested_folder: str | None
    merge_with_chat_ids: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class CleanupPlan:
    classifications: tuple[ChatClassification, ...]
    warnings: tuple[str, ...] = ()
    destructive_actions_authorized: bool = False


def suggest_next_reply(message: ChatMessage) -> NextReplySuggestion:
    text = " ".join(message.content.split())
    if not text:
        raise ValueError("message content is required")
    return NextReplySuggestion(
        chat_id=message.chat_id,
        source_message_id=message.message_id,
        reply=(
            "Continue from the latest verified checkpoint. Inspect the authoritative "
            "project state first, preserve completed work, resolve blockers, and take "
            "the strongest safe next action within existing authorization."
        ),
        rationale=(
            "Default continuation preserves project continuity without inventing new "
            "authority or asking the user to repeat known context."
        ),
    )


def classify_chat(
    *,
    chat_id: str,
    title: str,
    content: str,
    known_projects: Mapping[str, Sequence[str]],
) -> ChatClassification:
    haystack = f"{title}\n{content}".lower()
    matches: list[tuple[str, int]] = []
    for project_id, aliases in known_projects.items():
        score = sum(1 for alias in aliases if alias.lower() in haystack)
        if score:
            matches.append((project_id, score))
    matches.sort(key=lambda item: (-item[1], item[0]))
    project_id = matches[0][0] if matches else None
    canonical_topic = title.strip() or "Untitled Chat"
    folder = project_id if project_id else None
    evidence = tuple(f"{pid}:{score}" for pid, score in matches[:3])
    return ChatClassification(
        chat_id=chat_id,
        project_id=project_id,
        canonical_topic=canonical_topic,
        suggested_chat_title=canonical_topic,
        suggested_folder=folder,
        evidence=evidence,
    )


def build_cleanup_plan(
    classifications: Iterable[ChatClassification],
    *,
    duplicate_groups: Mapping[str, Sequence[str]] | None = None,
) -> CleanupPlan:
    duplicate_groups = duplicate_groups or {}
    result: list[ChatClassification] = []
    for item in classifications:
        merge_ids = tuple(
            chat
            for group in duplicate_groups.values()
            if item.chat_id in group
            for chat in group
            if chat != item.chat_id
        )
        result.append(
            ChatClassification(
                chat_id=item.chat_id,
                project_id=item.project_id,
                canonical_topic=item.canonical_topic,
                suggested_chat_title=item.suggested_chat_title,
                suggested_folder=item.suggested_folder,
                merge_with_chat_ids=merge_ids,
                evidence=item.evidence,
            )
        )
    return CleanupPlan(
        classifications=tuple(result),
        warnings=(
            "Plan only: do not rename, move, merge, archive, or delete chats without a supported authorized ChatGPT mutation capability.",
            "Preserve provenance when consolidating duplicate knowledge; never discard unique requirements, decisions, evidence, or unresolved conflicts.",
        ),
        destructive_actions_authorized=False,
    )
