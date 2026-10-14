"""Stage 9 strict candidate protocol for a future protected Windows broker.

NO named pipe listener is created. No peer impersonation, ACL enforcement,
Windows Hello, owner approval or task execution is implemented. A valid
untrusted frame can only produce a public, non-sensitive DENIED preview.

A real server must create a single-instance, same-user, local-only named pipe
using an explicit security descriptor, then impersonate and verify the client
token/session per request. Do not enable an IPC listener from this module.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .v3_policy import PolicyBlocked

PIPE_NAME = r"\\.\pipe\UPAB.WatcherV3.OwnerReview.v1"
MAX_FRAME_BYTES = 4096
SCHEMA = "upab.watcher-v3.owner-broker-request.v1"
_ALLOWED_METHODS = frozenset({"status", "review_preview"})
_NO_AUTHORITY = {
    "owner_authenticated": False,
    "peer_authenticated": False,
    "presence_verified": False,
    "approval_issued": False,
    "execution_authorized": False,
}


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise PolicyBlocked("duplicate broker request field")
        out[key] = value
    return out


def validate_untrusted_frame(wire: bytes) -> dict[str, Any]:
    if type(wire) is not bytes or not 2 <= len(wire) <= MAX_FRAME_BYTES:
        raise PolicyBlocked("broker request must be bounded bytes")
    try:
        decoded = wire.decode("utf-8", "strict")
        body = json.loads(decoded, object_pairs_hook=_unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              PolicyBlocked("nonfinite JSON not accepted")
                          ))
    except (UnicodeError, ValueError) as exc:
        raise PolicyBlocked("malformed broker request") from exc
    if not isinstance(body, dict) or set(body) != {
        "schema", "method", "request_id", "payload"
    }:
        raise PolicyBlocked("unknown or missing broker fields")
    if body["schema"] != SCHEMA:
        raise PolicyBlocked("unsupported broker protocol")
    method = body["method"]
    if not isinstance(method, str) or method not in _ALLOWED_METHODS:
        raise PolicyBlocked("broker method is not available")
    ref = body["request_id"]
    if not isinstance(ref, str) or not re.fullmatch(r"[a-f0-9]{32}", ref):
        raise PolicyBlocked("invalid broker request ID")
    payload = body["payload"]
    if method == "status":
        if payload != {}:
            raise PolicyBlocked("status request has invalid payload")
        report = {"status": "AUTHENTICATION_SERVICE_NOT_CONNECTED"}
    else:
        # Even the preview cannot inspect task source or accept real approval.
        if not isinstance(payload, dict) or set(payload) != {
            "task_id", "task_sha256"
        }:
            raise PolicyBlocked("review preview requires only fixed metadata")
        task_id, digest = payload["task_id"], payload["task_sha256"]
        if (not isinstance(task_id, str) or
                not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", task_id)):
            raise PolicyBlocked("invalid candidate task ID")
        if (not isinstance(digest, str) or
                not re.fullmatch(r"[a-fA-F0-9]{64}", digest)):
            raise PolicyBlocked("invalid candidate task hash")
        report = {"status": "REVIEW_PREVIEW_ONLY"}
    return {
        "schema": "upab.watcher-v3.owner-broker-preview.v1",
        "request_id": ref,
        "method": method,
        **report,
        **_NO_AUTHORITY,
        "listener_running": False,
        "changes_performed": False,
    }


def broker_security_requirements() -> dict[str, Any]:
    """Static, machine-readable gating checklist; not a service launcher."""
    return {
        "pipe_name": PIPE_NAME,
        "max_request_bytes": MAX_FRAME_BYTES,
        "windows_only": True,
        "enforce_same_session": True,
        "deny_remote_pipe_clients": True,
        "require_explicit_owner_only_dacl": True,
        "reject_low_integrity_and_anonymous": True,
        "impersonate_and_verify_peer_token": True,
        "human_presence_requires_windows_hello_or_verified_equivalent": True,
        "protect_verifier_secret_in_separate_broker_process": True,
        "approval_proof_single_use_and_scope_bound": True,
        "service_implemented": False,
        "production_execution_enabled": False,
    }
