"""Stage 37: cross-batch health sequence-continuity PREVIEW (review-only).

Compare already signed-but-UNTRUSTED health observations with caller-provided
prior sequence snapshots. Neither the snapshot nor the signing keys are
authenticated, securely stored, monotonic, or connected to Windows/GitHub.

This module offers deterministic fixture-only negative tests for replay,
regression and lost evidence. It MUST NOT be used as production anti-replay:
a caller can discard or replace the entire prior snapshot. It intentionally
does not persist snapshots, issue approvals, verify owners, launch watchers,
connect repositories, or establish healthy operational status.
"""
from __future__ import annotations

import re

from .v3_policy import PolicyBlocked
from .v3_portfolio_health_rollup import MAX_EPOCH, MAX_OBSERVATIONS
from .v3_portfolio_review import PROJECTS, POINDEXTER_MODULES
from .v3_signed_health_evidence_review import (
    HEX64, canonical_health_claim, review_signed_health_batch,
)

SCHEMA = "upab.watcher-v3.untrusted-sequence-review.v1"
SNAPSHOT_SCHEMA = "upab.watcher-v3.untrusted-health-sequence-snapshot.v1"
ENTRY_FIELDS = frozenset({
    "signer_key_sha256", "repository", "module_id", "last_sequence",
    "last_observed_at_epoch_s",
})
MAX_PRIOR_ENTRIES = MAX_OBSERVATIONS * 4  # review fixtures, never live state


def _valid_epoch(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_EPOCH


def _key(signer: str, repo: str, module: str | None) -> tuple[str, str, str]:
    return signer, repo, "" if module is None else module


def _parse_untrusted_snapshot(snapshot: object, now_epoch_s: int) -> dict[tuple[str, str, str], tuple[int, int]]:
    if type(snapshot) is not dict or set(snapshot) != {"schema", "entries"}:
        raise PolicyBlocked("untrusted sequence snapshot schema invalid")
    if snapshot["schema"] != SNAPSHOT_SCHEMA:
        raise PolicyBlocked("untrusted sequence snapshot version unsupported")
    entries = snapshot["entries"]
    if type(entries) is not list or len(entries) > MAX_PRIOR_ENTRIES:
        raise PolicyBlocked("untrusted sequence snapshot exceeds bounds")
    projects = set(PROJECTS)
    modules = {name for name, _ in POINDEXTER_MODULES}
    seen: dict[tuple[str, str, str], tuple[int, int]] = {}
    previous: tuple[str, str, str] | None = None
    for entry in entries:
        if type(entry) is not dict or set(entry) != ENTRY_FIELDS:
            raise PolicyBlocked("untrusted sequence entry malformed")
        signer, repo, module = (entry["signer_key_sha256"],
                                entry["repository"], entry["module_id"])
        if type(signer) is not str or not HEX64.fullmatch(signer):
            raise PolicyBlocked("untrusted sequence signer fingerprint malformed")
        if type(repo) is not str or repo not in projects:
            raise PolicyBlocked("unselected repository in sequence snapshot")
        if module is not None and (
            repo != "UP-UHAIB-001-Poindexter" or
            type(module) is not str or module not in modules
        ):
            raise PolicyBlocked("unapproved nested module in sequence snapshot")
        sequence, when = entry["last_sequence"], entry["last_observed_at_epoch_s"]
        if (not _valid_epoch(sequence) or sequence < 1
                or not _valid_epoch(when) or when > now_epoch_s):
            raise PolicyBlocked("untrusted sequence value or observation clock invalid")
        identity = _key(signer, repo, module)
        if previous is not None and identity <= previous:
            raise PolicyBlocked("duplicate or noncanonical sequence snapshot order")
        previous = identity
        seen[identity] = (sequence, when)
    return seen


def review_sequence_continuity(
    *, portfolio: object, envelopes: object, previous_snapshot: object,
    now_epoch_s: int, max_age_s: int = 300,
) -> dict[str, object]:
    """Check supplied snapshot consistency; never claim persistent protection."""
    if not _valid_epoch(now_epoch_s):
        raise PolicyBlocked("sequence-review clock invalid")
    # Full Stage36 cryptographic signature and Stage33/34 scope/freshness
    # validations happen even with an empty snapshot or evidence batch.
    health = review_signed_health_batch(
        portfolio=portfolio, envelopes=envelopes,
        now_epoch_s=now_epoch_s, max_age_s=max_age_s,
    )
    prior = _parse_untrusted_snapshot(previous_snapshot, now_epoch_s)
    matched = 0
    missing_prior = 0
    gaps = 0
    for envelope in envelopes:
        claim = envelope["claim"]
        # Already validated by signed batch; keep this explicit to ensure
        # the continuity comparison always binds the canonical claim.
        canonical_health_claim(claim)
        key = _key(envelope["public_key_sha256"],
                   claim["repository"], claim["module_id"])
        old = prior.get(key)
        if old is None:
            missing_prior += 1
        else:
            previous_sequence, previous_when = old
            if claim["sequence"] <= previous_sequence:
                raise PolicyBlocked("health sequence replay or regression")
            if claim["observed_at_epoch_s"] < previous_when:
                raise PolicyBlocked("health timestamp rollback for supplied signer/scope")
            if claim["sequence"] > previous_sequence + 1:
                gaps += 1
            matched += 1
    return {
        **health,
        "schema": SCHEMA,
        "status": "UNTRUSTED_SEQUENCE_CONTINUITY_PREVIEW_NOT_REPLAY_PROTECTION",
        "prior_snapshot_entries_supplied": len(prior),
        "signed_observations_with_matching_prior": matched,
        "signed_observations_with_missing_prior": missing_prior,
        "sequence_gaps_for_review": gaps,
        "caller_supplied_prior_snapshot_authenticated": False,
        "signature_signers_independently_trusted": False,
        "cross_restart_replay_prevented": False,
        "last_sequences_durably_persisted": False,
        "hardware_monotonic_store_verified": False,
        "owner_windows_hello_authenticated": False,
        "operational_health_verified": False,
        "live_monitoring_enabled": False,
        "project_roster_modified": False,
        "repository_connections_enabled": False,
        "task_execution_authorized": False,
        "settings_changed": False,
    }
