"""Stage 16: read-only owner-initiated Windows Hello enrollment preflight.

Reports if the Windows native credential-creation APIs exist and whether
an RP/origin pair meets basic safe *syntax*. Never calls MakeCredential,
prompts Windows Hello, creates/stores a credential, authorizes a task, or
starts the watcher. An RP name supplied by an untrusted caller is NOT an
authenticated relying party; live RP authority must be independently
established by an owner-reviewed, protected broker.

This is the last non-interactive acceptance gate before on-device enrollment.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import re
import sys
from urllib.parse import urlsplit

from .v3_policy import PolicyBlocked
from .v3_webauthn_preflight import windows_webauthn_preflight
from .v3_windows_identity import read_windows_identity_evidence

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_RESERVED_SUFFIXES = (
    ".invalid", ".test", ".localhost", ".example",
    ".example.com", ".example.net", ".example.org",
)


def validate_rp_candidate(*, rp_id: str, origin: str) -> dict[str, object]:
    """Check syntax only, never establish domain possession/trust."""
    if (type(rp_id) is not str or len(rp_id) > 253
            or rp_id != rp_id.lower() or rp_id.endswith(".")):
        raise PolicyBlocked("invalid RP ID candidate")
    labels = rp_id.split(".")
    if (len(labels) < 2 or
            any(not _LABEL.fullmatch(label) for label in labels)
            or any(rp_id == suffix[1:] or rp_id.endswith(suffix)
                   for suffix in _RESERVED_SUFFIXES)):
        raise PolicyBlocked("RP ID is invalid or reserved for testing")
    if type(origin) is not str or origin != "https://" + rp_id:
        raise PolicyBlocked("only exact HTTPS RP origin is accepted")
    try:
        parsed = urlsplit(origin)
        if (parsed.scheme != "https" or parsed.hostname != rp_id
                or parsed.username is not None or parsed.password is not None
                or parsed.port is not None or parsed.path
                or parsed.query or parsed.fragment):
            raise PolicyBlocked("noncanonical origin")
    except ValueError as exc:
        raise PolicyBlocked("invalid origin URL components") from exc
    return {
        "rp_syntax_accepted": True,
        "origin_syntax_accepted": True,
        "rp_domain_ownership_verified": False,
        "https_origin_ownership_verified": False,
        "owner_approved_this_rp": False,
        "allow_credential_creation": False,
    }


def preflight_owner_enrollment(
    *, rp_id: str | None = None, origin: str | None = None
) -> dict[str, object]:
    """Native Windows readiness observation, **never** credential creation.

    This preflight is safe for an interactive PowerShell session. It requires
    no credentials, network calls, files, admin privileges, or external API.
    """
    if sys.platform != "win32":
        raise PolicyBlocked("Windows Hello readiness requires Windows")
    if (rp_id is None) != (origin is None):
        raise PolicyBlocked("RP ID and exact origin must be supplied together")
    candidate = None
    if rp_id is not None:
        candidate = validate_rp_candidate(rp_id=rp_id, origin=origin)
    discovery = windows_webauthn_preflight()
    identity = read_windows_identity_evidence()
    if identity["process_user_sid"][:4] != "S-1-":
        raise PolicyBlocked("unexpected current Windows process identity")
    api_symbols = {"WebAuthNAuthenticatorMakeCredential",
                   "WebAuthNFreeCredentialAttestation",
                   "WebAuthNCancelCurrentOperation"}
    available = set()
    if discovery["os_webauthn_api"] == "PRESENT":
        try:
            dll = ctypes.WinDLL("webauthn.dll", use_last_error=True)
            available = {name for name in api_symbols if hasattr(dll, name)}
        except OSError:
            available = set()
    return {
        "schema": "upab.watcher-v3.owner-enrollment-preflight.v1",
        "platform": "Windows",
        "api_version": discovery["api_version"],
        "webauthn_api_available": discovery["os_webauthn_api"] == "PRESENT",
        "platform_authenticator": discovery["platform_authenticator"],
        "native_credential_create_api_present": (
            "WebAuthNAuthenticatorMakeCredential" in available
        ),
        "native_free_attestation_api_present": (
            "WebAuthNFreeCredentialAttestation" in available
        ),
        "native_cancel_api_present": (
            "WebAuthNCancelCurrentOperation" in available
        ),
        "process_session_observed": True,
        "interactive_user_presence_proven": False,
        "rp_candidate_syntax_accepted": candidate is not None,
        "rp_ownership_proven": False,
        "trusted_rp_configuration": False,
        "protected_challenge_issuer_connected": False,
        "credential_registered": False,
        "windows_hello_prompt_displayed": False,
        "owner_approval_issued": False,
        "execution_authorized": False,
        "safe_to_invoke_make_credential": False,
        "status": "BLOCKED_NEEDS_TRUSTED_RP_AND_OWNER_CEREMONY",
        "missing_gates": [
            "OWNER_VERIFIED_RP_ID_AND_HTTPS_ORIGIN",
            "OWNER_INITIATED_INTERACTIVE_UI_WITH_APPROVED_WINDOW",
            "TRUSTED_CHALLENGE_AND_USER_HANDLE_ISSUER",
            "VERIFIED_CREDENTIAL_REGISTRATION_AND_P256_KEY",
            "PROTECTED_REGISTRY_AND_REPLAY_LEDGER",
            "SEPARATE_SCOPED_APPROVAL_FOR_ACTUAL_TASKS",
            "LEGACY_WATCHER_MIGRATION_AND_WINDOWS_ACCEPTANCE",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="READ-ONLY Windows Hello enrollment capability preflight"
    )
    parser.add_argument("--rp-id", help="Optional candidate RP domain, not an approval")
    parser.add_argument("--origin", help="Optional HTTPS origin; must match RP ID")
    args = parser.parse_args(argv)
    try:
        result = preflight_owner_enrollment(rp_id=args.rp_id, origin=args.origin)
    except (OSError, PolicyBlocked) as exc:
        print("WATCHER_V3_ENROLLMENT_PREFLIGHT_BLOCKED: " +
              type(exc).__name__, file=sys.stderr)
        return 7
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
