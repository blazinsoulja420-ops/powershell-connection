"""Stage 11: read-only Windows WebAuthn capability discovery.

Uses the OS WebAuthn DLL only to test interface presence and whether a
platform authenticator reports availability. It NEVER enrolls credentials,
requests a user assertion, prompts Windows Hello, signs a task, or approves
execution. A positive capability result is NOT proof of owner presence.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from .v3_policy import PolicyBlocked


def windows_webauthn_preflight() -> dict[str, object]:
    if sys.platform != "win32":
        raise PolicyBlocked("native WebAuthn preflight requires Windows")
    base: dict[str, object] = {
        "schema": "upab.watcher-v3.webauthn-preflight.v1",
        "os_webauthn_api": "UNAVAILABLE",
        "api_version": None,
        "platform_authenticator": "UNKNOWN",
        "credential_enrolled": "UNKNOWN",
        "user_verification_performed": False,
        "owner_authenticated": False,
        "approval_issued": False,
        "execution_authorized": False,
    }
    try:
        lib = ctypes.WinDLL("webauthn.dll", use_last_error=True)
        version_api = lib.WebAuthNGetApiVersionNumber
    except (OSError, AttributeError):
        return base
    version_api.argtypes = []
    version_api.restype = wintypes.DWORD
    version = int(version_api())
    if version < 1 or version > 100:
        raise PolicyBlocked("Windows WebAuthn API returned invalid version")
    base["api_version"] = version
    base["os_webauthn_api"] = "PRESENT"
    try:
        availability_api = lib.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable
    except AttributeError:
        return base
    availability_api.argtypes = [ctypes.POINTER(wintypes.BOOL)]
    availability_api.restype = ctypes.c_long
    present = wintypes.BOOL()
    # HRESULT is an integer status; negative values indicate failure.
    hr = int(availability_api(ctypes.byref(present)))
    if hr < 0:
        base["platform_authenticator"] = "UNKNOWN"
    else:
        base["platform_authenticator"] = "REPORTED_AVAILABLE" if present.value else "REPORTED_UNAVAILABLE"
    return base
