"""Stage 12 Windows CNG WebAuthn ES256 *assertion validation candidate*.

Verifies a trusted-registration-candidate P-256 public key against strict
fixed-format authenticator and client data using Windows BCrypt. This module
does not enroll credentials, authenticate a real owner, persist replay state,
issue an approval, connect repositories or execute tasks.

Even a cryptographically valid signature ALWAYS returns
owner_authenticated=False and execution_authorized=False. The caller must
not infer trusted enrollment from a caller-supplied public key or RP origin.

Reference: W3C WebAuthn L2 assertion verification steps and Windows CNG
BCRYPT_ECDSA_P256_ALGORITHM/ECCPUBLICBLOB/BCryptVerifySignature.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import re
import struct
import sys
from urllib.parse import urlsplit

from .v3_policy import PolicyBlocked

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
ECC_PUBLIC_P256_MAGIC = 0x31534345
MAX_CLIENT_BYTES = 2048
MAX_SIGNATURE_BYTES = 80


def _unique_pairs(items):
    result = {}
    for k, v in items:
        if k in result:
            raise PolicyBlocked("duplicate client-data JSON property")
        result[k] = v
    return result


def _der_integer(der: bytes, index: int) -> tuple[int, int]:
    if index + 2 > len(der) or der[index] != 0x02:
        raise PolicyBlocked("ECDSA integer missing")
    n = der[index + 1]
    index += 2
    if not 1 <= n <= 33 or index + n > len(der):
        raise PolicyBlocked("invalid ECDSA integer length")
    item = der[index:index+n]
    if item[0] & 0x80 or (n > 1 and item[0] == 0 and not (item[1] & 0x80)):
        raise PolicyBlocked("ECDSA integer not minimally encoded")
    value = int.from_bytes(item, "big")
    if not 1 <= value < P256_ORDER:
        raise PolicyBlocked("ECDSA scalar is invalid")
    return value, index + n


def _ecdsa_der_to_cng(der: bytes) -> bytes:
    if (type(der) is not bytes or not 8 <= len(der) <= MAX_SIGNATURE_BYTES
            or der[0] != 0x30 or der[1] != len(der) - 2):
        raise PolicyBlocked("invalid DER ECDSA signature")
    r, at = _der_integer(der, 2)
    s, at = _der_integer(der, at)
    if at != len(der):
        raise PolicyBlocked("trailing data in ECDSA signature")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_es256_with_windows_cng(
    *, x: bytes, y: bytes, payload_digest: bytes, signature_der: bytes,
) -> bool:
    """Verify ES256 using Windows CNG; no private-key API or package dependency."""
    if sys.platform != "win32":
        raise PolicyBlocked("ES256 Windows CNG requires Windows")
    if (type(x) is not bytes or len(x) != 32
            or type(y) is not bytes or len(y) != 32
            or type(payload_digest) is not bytes or len(payload_digest) != 32):
        raise PolicyBlocked("expected P-256 coordinates and SHA-256 digest")
    signature = _ecdsa_der_to_cng(signature_der)

    bcrypt = ctypes.WinDLL("bcrypt", use_last_error=True)
    handle = ctypes.c_void_p
    bcrypt.BCryptOpenAlgorithmProvider.argtypes = [
        ctypes.POINTER(handle), ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong
    ]
    bcrypt.BCryptOpenAlgorithmProvider.restype = ctypes.c_long
    bcrypt.BCryptImportKeyPair.argtypes = [
        handle, handle, ctypes.c_wchar_p, ctypes.POINTER(handle),
        ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong
    ]
    bcrypt.BCryptImportKeyPair.restype = ctypes.c_long
    bcrypt.BCryptVerifySignature.argtypes = [
        handle, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
        ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong
    ]
    bcrypt.BCryptVerifySignature.restype = ctypes.c_long
    bcrypt.BCryptDestroyKey.argtypes = [handle]
    bcrypt.BCryptDestroyKey.restype = ctypes.c_long
    bcrypt.BCryptCloseAlgorithmProvider.argtypes = [handle, ctypes.c_ulong]
    bcrypt.BCryptCloseAlgorithmProvider.restype = ctypes.c_long

    algorithm = handle()
    key = handle()
    if bcrypt.BCryptOpenAlgorithmProvider(
        ctypes.byref(algorithm), "ECDSA_P256", None, 0
    ) != 0:
        raise PolicyBlocked("Windows ECDSA provider not available")
    try:
        key_blob = ctypes.create_string_buffer(
            struct.pack("<II", ECC_PUBLIC_P256_MAGIC, 32) + x + y
        )
        if bcrypt.BCryptImportKeyPair(
            algorithm, None, "ECCPUBLICBLOB", ctypes.byref(key),
            ctypes.cast(key_blob, ctypes.c_void_p),
            ctypes.sizeof(key_blob) - 1, 0
        ) != 0:
            raise PolicyBlocked("Windows rejected the candidate P-256 public key")
        digest_buf = ctypes.create_string_buffer(payload_digest)
        signature_buf = ctypes.create_string_buffer(signature)
        return bcrypt.BCryptVerifySignature(
            key, None,
            ctypes.cast(digest_buf, ctypes.c_void_p), 32,
            ctypes.cast(signature_buf, ctypes.c_void_p), 64, 0
        ) == 0
    finally:
        if key.value:
            bcrypt.BCryptDestroyKey(key)
        bcrypt.BCryptCloseAlgorithmProvider(algorithm, 0)


def inspect_es256_assertion(
    *, expected_challenge: bytes,
    expected_origin: str,
    expected_rp_id: str,
    credential_public_x: bytes,
    credential_public_y: bytes,
    client_data_json: bytes,
    authenticator_data: bytes,
    signature_der: bytes,
    previous_sign_count: int,
) -> dict[str, object]:
    """Validate an isolated signed assertion, but never issue owner approval.

    All registration, previous-counter, origin and challenge arguments must
    eventually come from a protected trusted enrollment/nonce broker.
    Passing attacker-controlled values produces NO owner authorization.
    """
    if type(expected_challenge) is not bytes or len(expected_challenge) != 32:
        raise PolicyBlocked("expected challenge must be 32 bytes")
    if (not isinstance(expected_rp_id, str) or
            not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,251}", expected_rp_id)
            or ".." in expected_rp_id or expected_rp_id.endswith(".")):
        raise PolicyBlocked("untrusted RP ID")
    if not isinstance(expected_origin, str) or len(expected_origin) > 300:
        raise PolicyBlocked("invalid origin")
    origin = urlsplit(expected_origin)
    if (origin.scheme != "https" or origin.hostname != expected_rp_id
            or origin.username or origin.password or origin.port is not None
            or origin.query or origin.fragment or origin.path
            or expected_origin != "https://" + expected_rp_id):
        raise PolicyBlocked("expected RP and HTTPS origin not strictly bound")
    if (type(client_data_json) is not bytes
            or not 2 <= len(client_data_json) <= MAX_CLIENT_BYTES):
        raise PolicyBlocked("client data size invalid")
    try:
        data = json.loads(client_data_json.decode("utf-8", "strict"),
                          object_pairs_hook=_unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              PolicyBlocked("invalid client JSON number")
                          ))
    except (UnicodeError, ValueError) as exc:
        raise PolicyBlocked("malformed signed client data") from exc
    if not isinstance(data, dict) or set(data) != {
        "type", "challenge", "origin", "crossOrigin"
    }:
        raise PolicyBlocked("unexpected client data fields")
    if data["type"] != "webauthn.get" or data["origin"] != expected_origin:
        raise PolicyBlocked("client assertion origin/type mismatch")
    if data["crossOrigin"] is not False:
        raise PolicyBlocked("cross-origin assertion not permitted")
    encoded = data["challenge"]
    if not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded):
        raise PolicyBlocked("client challenge encoding malformed")
    try:
        decoded = base64.urlsafe_b64decode(encoded + "=")
    except ValueError as exc:
        raise PolicyBlocked("client challenge invalid") from exc
    if (decoded != expected_challenge
            or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != encoded):
        raise PolicyBlocked("client challenge not bound")
    if type(authenticator_data) is not bytes or len(authenticator_data) != 37:
        raise PolicyBlocked("only extension-free assertion data is supported")
    if authenticator_data[:32] != hashlib.sha256(expected_rp_id.encode("ascii")).digest():
        raise PolicyBlocked("RP ID hash mismatch")
    flags = authenticator_data[32]
    # UP (0x01) + UV (0x04) required; AT/ED and reserved bits forbidden.
    if (flags & 0x05) != 0x05 or (flags & 0xE2):
        raise PolicyBlocked("user presence, verification, or extensions unsupported")
    # The BS bit cannot be set without BE (WebAuthn backup semantics).
    if (flags & 0x10) and not (flags & 0x08):
        raise PolicyBlocked("backup flag state inconsistent")
    count = int.from_bytes(authenticator_data[33:37], "big")
    if (type(previous_sign_count) is not int or
            not 0 <= previous_sign_count < 2**32 or
            count == 0 or count <= previous_sign_count):
        # Deliberately excludes authenticators with zero-valued counters.
        # Future policy must explicitly handle zero counters without replay.
        raise PolicyBlocked("sign counter must advance under v3 candidate policy")
    signed_hash = hashlib.sha256(
        authenticator_data + hashlib.sha256(client_data_json).digest()
    ).digest()
    signature_matches = verify_es256_with_windows_cng(
        x=credential_public_x,
        y=credential_public_y,
        payload_digest=signed_hash,
        signature_der=signature_der,
    )
    return {
        "schema": "upab.watcher-v3.assertion-crypto-candidate.v1",
        "signed_assertion_valid": bool(signature_matches),
        "signed_user_verified_flag": bool(signature_matches and flags & 0x04),
        "new_sign_count": count if signature_matches else None,
        "trusted_credential_enrollment_proven": False,
        "challenge_replay_protection_connected": False,
        "owner_authenticated": False,
        "approval_issued": False,
        "execution_authorized": False,
        "task_executed": False,
    }
