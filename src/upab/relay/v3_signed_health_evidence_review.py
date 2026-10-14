"""Stage 36: signed health-evidence consistency REVIEW, NEVER monitor activation.

Demonstrates actual Ed25519 verification of carefully bounded *caller-supplied*
health claims. The signer public key, SHA256 pin, prior sequence and source
identity are NOT authenticated, protected, enrolled, or connected to GitHub
or Windows by this module. Anyone could forge a new key and sign fake OK.

Reuses Stage 33 roster validation and Stage 34 stale/UNKNOWN rollup. Reports
can contain no executable command, path, secret, URL, host name, or free text.
No I/O, network, persistence, signing key generation, OS process, or startup.
"""
from __future__ import annotations

import hashlib
import json
import re

from .v3_policy import PolicyBlocked
from .v3_portfolio_health_rollup import (
    CONDITIONS, MAX_EPOCH, MAX_OBSERVATIONS, OBSERVATION_SCHEMA,
    review_health_rollup,
)
from .v3_portfolio_review import PROJECTS, POINDEXTER_MODULES

SCHEMA = "upab.watcher-v3.signed-health-evidence-review.v1"
ENVELOPE_SCHEMA = "upab.watcher-v3.health-signature-envelope.v1"
CLAIM_SCHEMA = "upab.watcher-v3.health-claim.v1"
DOMAIN = b"UPAB-WATCHER-V3-HEALTH-EVIDENCE-REVIEW-ONLY-v1\x00"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")
SOURCE_KINDS = frozenset({"LOCAL_WATCHER", "GITHUB_CI"})
CLAIM_FIELDS = frozenset({
    "schema", "repository", "module_id", "condition",
    "observed_at_epoch_s", "sequence", "source_kind",
})
ENVELOPE_FIELDS = frozenset({
    "schema", "claim", "public_key_hex", "public_key_sha256",
    "signature_hex",
})


def canonical_health_claim(claim: object) -> bytes:
    """Strict public structural validation; no arbitrary data or code fields."""
    if type(claim) is not dict or set(claim) != CLAIM_FIELDS:
        raise PolicyBlocked("signed health claim has missing/extra fields")
    if claim["schema"] != CLAIM_SCHEMA:
        raise PolicyBlocked("signed health claim schema invalid")
    repo, module = claim["repository"], claim["module_id"]
    if type(repo) is not str or repo not in PROJECTS:
        raise PolicyBlocked("unselected or excluded health repository")
    valid_modules = {name for name, _ in POINDEXTER_MODULES}
    if module is not None and (
        repo != "UP-UHAIB-001-Poindexter" or type(module) is not str
        or module not in valid_modules
    ):
        raise PolicyBlocked("unapproved nested module identity")
    if (type(claim["condition"]) is not str
            or claim["condition"] not in CONDITIONS):
        raise PolicyBlocked("unknown health condition")
    if (type(claim["observed_at_epoch_s"]) is not int
            or not 0 <= claim["observed_at_epoch_s"] <= MAX_EPOCH
            or type(claim["sequence"]) is not int
            or not 1 <= claim["sequence"] <= MAX_EPOCH):
        raise PolicyBlocked("health timestamp or sequence invalid")
    if (type(claim["source_kind"]) is not str
            or claim["source_kind"] not in SOURCE_KINDS):
        raise PolicyBlocked("health observation source class invalid")
    if module is not None and claim["source_kind"] != "LOCAL_WATCHER":
        raise PolicyBlocked("module source type cannot be a repo CI claim")
    wire = json.dumps(
        claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    if not 1 <= len(wire) <= 1024:
        raise PolicyBlocked("health claim exceeds fixed bound")
    return wire


def review_signed_health_batch(
    *, portfolio: object, envelopes: object, now_epoch_s: int,
    max_age_s: int = 300
) -> dict[str, object]:
    """Validate signatures then summarize as UNTRUSTED observations only."""
    if type(envelopes) is not list or len(envelopes) > MAX_OBSERVATIONS:
        raise PolicyBlocked("signed evidence batch exceeds portfolio bounds")
    # Always validate the portfolio and clock even if the batch is empty.
    baseline = review_health_rollup(
        portfolio=portfolio, observations=[],
        now_epoch_s=now_epoch_s, max_age_s=max_age_s
    )
    observations: list[dict[str, object]] = []
    seen: set[tuple[str, str | None]] = set()
    # Import only the maintained backend; no homegrown crypto fallback.
    if envelopes:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
        except ImportError as exc:
            raise PolicyBlocked("maintained signature verification backend unavailable") from exc
    for envelope in envelopes:
        if type(envelope) is not dict or set(envelope) != ENVELOPE_FIELDS:
            raise PolicyBlocked("signed evidence envelope malformed")
        if envelope["schema"] != ENVELOPE_SCHEMA:
            raise PolicyBlocked("signed evidence version unsupported")
        for field, pattern in (
            ("public_key_hex", HEX64),
            ("public_key_sha256", HEX64),
            ("signature_hex", HEX128),
        ):
            value = envelope[field]
            if type(value) is not str or not pattern.fullmatch(value):
                raise PolicyBlocked("signed evidence key/pin/signature malformed")
        claim = envelope["claim"]
        payload = canonical_health_claim(claim)
        identity = (claim["repository"], claim["module_id"])
        if identity in seen:
            raise PolicyBlocked("duplicate signed health identity")
        seen.add(identity)
        pubkey = bytes.fromhex(envelope["public_key_hex"])
        if hashlib.sha256(pubkey).hexdigest() != envelope["public_key_sha256"]:
            raise PolicyBlocked("signed evidence provided key/pin mismatch")
        try:
            verifier = Ed25519PublicKey.from_public_bytes(pubkey)
            verifier.verify(
                bytes.fromhex(envelope["signature_hex"]), DOMAIN + payload
            )
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise PolicyBlocked("signed evidence cryptographic mismatch") from exc
        # Never upgrade signer claims to authenticated health observations.
        observations.append({
            "schema": OBSERVATION_SCHEMA,
            "repository": claim["repository"],
            "module_id": claim["module_id"],
            "condition": claim["condition"],
            "observed_at_epoch_s": claim["observed_at_epoch_s"],
            "origin": "UNTRUSTED_REVIEW_FIXTURE",
        })
    counts = review_health_rollup(
        portfolio=portfolio, observations=observations,
        now_epoch_s=now_epoch_s, max_age_s=max_age_s
    ) if observations else baseline
    return {
        **counts,
        "schema": SCHEMA,
        "status": "SIGNATURE_CONSISTENCY_ONLY_UNTRUSTED_SIGNER",
        "signature_consistent_untrusted_observations": len(observations),
        "signer_keys_independently_enrolled": False,
        "signed_claim_origins_authenticated": False,
        "replay_protected_across_batches": False,
        "last_accepted_sequences_protected": False,
        "github_ci_authenticity_verified": False,
        "windows_observer_identity_verified": False,
        "publisher_owner_authenticated": False,
        "verified_healthy_projects": 0,
        "verified_healthy_modules": 0,
        "live_monitoring_enabled": False,
        "task_execution_authorized": False,
        "settings_changed": False,
    }
