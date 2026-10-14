"""Stage 31: review-only publisher key lifecycle and rollback policy.

Pure candidate proposal evaluator. Accepts untrusted prior metadata and an
untrusted proposed transition. NO Windows Hello interaction, persistence,
key generation, signature validation, release approval, or execution.
None of this state is protected against local rollback or forgery.

Actual enrollment/rotation must later use hardware-bound authenticated
owner presence, independent trusted publisher-root evidence and, for
rotation, verifiable old/new key authorization. Revocation needs a
protected monotonic counter that this module does not provide.
"""
from __future__ import annotations

import json
import re

from .v3_policy import PolicyBlocked

SCHEMA = "upab.watcher-v3.publisher-key-review.v1"
_PROPOSAL = "upab.watcher-v3.publisher-transition-proposal.v1"
_PIN = re.compile(r"[0-9a-f]{64}\Z")
MAX_REVOKED = 32
MAX_EPOCH = 2**31 - 1
MAX_RELEASE_SEQUENCE = 2**53 - 1


def _pin(value: object) -> bool:
    return type(value) is str and bool(_PIN.fullmatch(value))


def _int_in_range(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _validate_prior(prior: object) -> dict[str, object] | None:
    if prior is None:
        return None
    if type(prior) is not dict or set(prior) != {
        "schema", "epoch", "active_key_sha256", "revoked_key_sha256",
        "minimum_release_sequence"
    }:
        raise PolicyBlocked("untrusted previous publisher state malformed")
    if prior["schema"] != SCHEMA:
        raise PolicyBlocked("publisher state schema unknown")
    if not _int_in_range(prior["epoch"], MAX_EPOCH) or prior["epoch"] < 1:
        raise PolicyBlocked("publisher state epoch invalid")
    if not _int_in_range(prior["minimum_release_sequence"], MAX_RELEASE_SEQUENCE):
        raise PolicyBlocked("publisher release floor invalid")
    active = prior["active_key_sha256"]
    if active is not None and not _pin(active):
        raise PolicyBlocked("publisher active key pin invalid")
    revoked = prior["revoked_key_sha256"]
    if (type(revoked) is not list or len(revoked) > MAX_REVOKED
            or any(not _pin(value) for value in revoked)
            or len(revoked) != len(set(revoked))
            or revoked != sorted(revoked)
            or active in revoked):
        raise PolicyBlocked("publisher revoked key list invalid")
    if active is None and not revoked:
        raise PolicyBlocked("inactive publisher root lacks revocation history")
    return prior


def review_publisher_transition(
    prior: object, proposal: object
) -> dict[str, object]:
    """Validate a proposed state transition, never enroll or activate it."""
    old = _validate_prior(prior)
    if type(proposal) is not dict or set(proposal) != {
        "schema", "action", "next_epoch", "new_key_sha256",
        "minimum_release_sequence"
    }:
        raise PolicyBlocked("publisher proposal schema invalid")
    if proposal["schema"] != _PROPOSAL:
        raise PolicyBlocked("publisher proposal version invalid")
    action = proposal["action"]
    if action not in ("ENROLL", "ROTATE", "REVOKE") or type(action) is not str:
        raise PolicyBlocked("unknown publisher transition")
    epoch = proposal["next_epoch"]
    floor = proposal["minimum_release_sequence"]
    if (not _int_in_range(epoch, MAX_EPOCH)
            or not _int_in_range(floor, MAX_RELEASE_SEQUENCE)):
        raise PolicyBlocked("publisher epoch or rollback floor invalid")
    required_epoch = 1 if old is None else old["epoch"] + 1
    if epoch != required_epoch:
        raise PolicyBlocked("publisher epoch skipped, repeated or rolled back")
    if old is not None and floor < old["minimum_release_sequence"]:
        raise PolicyBlocked("publisher release floor rollback forbidden")

    key = proposal["new_key_sha256"]
    if action == "ENROLL":
        if old is not None or not _pin(key):
            raise PolicyBlocked("initial enrollment needs a new key and no prior state")
        future_active = key
        revoked: list[str] = []
        required = "OFFLINE_OWNER_BOOTSTRAP_AND_PUBLISHER_PROOF"
    elif action == "ROTATE":
        if (old is None or old["active_key_sha256"] is None
                or not _pin(key) or key == old["active_key_sha256"]
                or key in old["revoked_key_sha256"]):
            raise PolicyBlocked("publisher rotation violates key lifecycle policy")
        future_active = key
        revoked = sorted([*old["revoked_key_sha256"], old["active_key_sha256"]])
        required = "OWNER_PLUS_OLD_AND_NEW_PUBLISHER_SIGNED_ROTATION"
    else:
        if (old is None or old["active_key_sha256"] is None
                or key is not None):
            raise PolicyBlocked("publisher revocation requires active old key only")
        future_active = None
        revoked = sorted([*old["revoked_key_sha256"], old["active_key_sha256"]])
        required = "OWNER_AUTHENTICATED_EMERGENCY_REVOCATION"

    if len(revoked) > MAX_REVOKED:
        raise PolicyBlocked("publisher revoked-key registry capacity exceeded")
    # A downstream *human-reviewed proposal*, not a trusted state receipt.
    candidate_state = {
        "schema": SCHEMA,
        "epoch": epoch,
        "active_key_sha256": future_active,
        "revoked_key_sha256": revoked,
        "minimum_release_sequence": floor,
    }
    return {
        "schema": "upab.watcher-v3.publisher-lifecycle-review-result.v1",
        "status": "PROPOSAL_FORMAT_VALID_BUT_UNAUTHORIZED",
        "proposed_action": action,
        "proposed_epoch": epoch,
        "proposed_minimum_release_sequence": floor,
        "proposed_key_active": future_active is not None,
        "proposed_revoked_key_count": len(revoked),
        "required_external_ceremony": required,
        # No key fingerprint, path, full candidate-state or prior state leaks.
        "prior_state_cryptographically_authenticated": False,
        "owner_identity_verified": False,
        "trusted_root_enrolled": False,
        "publisher_signatures_verified": False,
        "monotonic_counter_protected": False,
        "trusted_revocation_registry_updated": False,
        "roll_forward_state_committed": False,
        "installation_authorized": False,
        "migration_authorized": False,
        "task_execution_authorized": False,
        "writes_performed": False,
    }


def review_json(prior_json: str | None, proposal_json: str) -> dict[str, object]:
    """Bounded fixture entrypoint for ephemeral synthetic inputs only."""
    if (type(proposal_json) is not str or len(proposal_json) > 8192
            or (prior_json is not None and
                (type(prior_json) is not str or len(prior_json) > 8192))):
        raise PolicyBlocked("publisher review JSON size/type invalid")
    try:
        prior = None if prior_json is None else json.loads(prior_json)
        proposal = json.loads(proposal_json)
    except ValueError as exc:
        raise PolicyBlocked("publisher review JSON malformed") from exc
    return review_publisher_transition(prior, proposal)
