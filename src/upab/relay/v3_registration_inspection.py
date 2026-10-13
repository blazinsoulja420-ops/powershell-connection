"""Stage 15 bounded WebAuthn registration-response inspection: NO ENROLLMENT.

Parses extension-free WebAuthn attestationObject with fmt='none' only,
clientDataJSON with an exact, caller-supplied RP/origin/challenge binding,
and authenticatorData with AT+UP+UV. Reads an ES256/P-256 COSE public key.
The calling application has NOT established trustworthy RP registration,
human owner consent, enrollment, attestation roots, or a protected credential
record. 'none' conveys no attestation provenance.

A successfully parsed response is ONLY an untrusted registration *candidate*.
It cannot be imported into the production approval path, authenticate a
human, create user credentials, or execute a task. No side effects.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from urllib.parse import urlsplit

from .v3_policy import PolicyBlocked

MAX_ATTESTATION_BYTES = 8192
MAX_CLIENT_BYTES = 2048
MAX_CREDENTIAL_ID_BYTES = 1024


class _CBOR:
    """Strict small definite-length CBOR subset for a WebAuthn candidate.

    Rejects indefinite lengths, tags, simple/float values, duplicate map
    keys, overlong integer encoding, deep recursion and trailing bytes.
    This is not a general-purpose CBOR decoder.
    """

    def __init__(self, wire: bytes):
        if type(wire) is not bytes or not 1 <= len(wire) <= MAX_ATTESTATION_BYTES:
            raise PolicyBlocked("bounded CBOR bytes required")
        self.wire = wire
        self.index = 0

    def _read(self, length: int) -> bytes:
        if length < 0 or self.index + length > len(self.wire):
            raise PolicyBlocked("truncated CBOR data")
        fragment = self.wire[self.index:self.index + length]
        self.index += length
        return fragment

    def _size(self, low: int) -> int:
        if low < 24:
            return low
        sizes = {24: 1, 25: 2, 26: 4}
        if low not in sizes:
            raise PolicyBlocked("indefinite or oversized CBOR length")
        bits = sizes[low]
        value = int.from_bytes(self._read(bits), "big")
        lower_bound = {24: 24, 25: 256, 26: 65536}[low]
        if value < lower_bound:
            raise PolicyBlocked("noncanonical CBOR length")
        return value

    def decode(self, depth: int = 0):
        if depth > 6:
            raise PolicyBlocked("CBOR nesting too deep")
        marker = self._read(1)[0]
        major, low = marker >> 5, marker & 31
        if major not in (0, 1, 2, 3, 4, 5):
            raise PolicyBlocked("unsupported CBOR type")
        count = self._size(low)
        if major == 0:
            return count
        if major == 1:
            return -1 - count
        if major == 2:
            if count > MAX_ATTESTATION_BYTES:
                raise PolicyBlocked("CBOR byte string over bound")
            return self._read(count)
        if major == 3:
            if count > 512:
                raise PolicyBlocked("CBOR text over bound")
            try:
                return self._read(count).decode("utf-8", "strict")
            except UnicodeError as exc:
                raise PolicyBlocked("CBOR UTF-8 invalid") from exc
        if count > 16:
            raise PolicyBlocked("CBOR array or map has too many entries")
        if major == 4:
            return [self.decode(depth + 1) for _ in range(count)]
        result = {}
        for _ in range(count):
            key = self.decode(depth + 1)
            if type(key) not in (int, str):
                raise PolicyBlocked("unsupported CBOR map key")
            if key in result:
                raise PolicyBlocked("duplicate CBOR map key")
            result[key] = self.decode(depth + 1)
        return result

    def complete(self):
        value = self.decode()
        if self.index != len(self.wire):
            raise PolicyBlocked("trailing CBOR data")
        return value


def _unique_json_fields(items):
    result = {}
    for key, value in items:
        if key in result:
            raise PolicyBlocked("duplicate registration client JSON field")
        result[key] = value
    return result


def _expected_rp_origin(rp_id: str, origin: str) -> None:
    if (not isinstance(rp_id, str) or len(rp_id) > 253 or
            not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,251}", rp_id)
            or ".." in rp_id or rp_id.endswith(".")):
        raise PolicyBlocked("invalid relying party identifier")
    if (not isinstance(origin, str) or
            origin != "https://" + rp_id):
        raise PolicyBlocked("origin must be exact RP HTTPS origin")
    try:
        url = urlsplit(origin)
        if (url.scheme != "https" or url.hostname != rp_id
                or url.username is not None or url.password is not None
                or url.port is not None or url.path or url.query or url.fragment):
            raise PolicyBlocked("invalid origin components")
    except ValueError as exc:
        raise PolicyBlocked("malformed origin") from exc


def _validate_client(client_data: bytes, challenge: bytes, origin: str) -> None:
    if type(client_data) is not bytes or not 2 <= len(client_data) <= MAX_CLIENT_BYTES:
        raise PolicyBlocked("registration client data out of bounds")
    try:
        data = json.loads(
            client_data.decode("utf-8", "strict"),
            object_pairs_hook=_unique_json_fields,
            parse_constant=lambda _: (_ for _ in ()).throw(
                PolicyBlocked("nonfinite registration client JSON")
            ),
        )
    except (UnicodeError, ValueError) as exc:
        raise PolicyBlocked("registration client data malformed") from exc
    if not isinstance(data, dict):
        raise PolicyBlocked("registration client data is not an object")
    if (set(data) not in (
                {"type", "challenge", "origin"},
                {"type", "challenge", "origin", "crossOrigin"},
            ) or data["type"] != "webauthn.create" or
            data["origin"] != origin or data.get("crossOrigin", False) is not False):
        raise PolicyBlocked("registration client origin or type mismatch")
    encoded = data["challenge"]
    if not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded):
        raise PolicyBlocked("registration challenge is not canonical base64url")
    try:
        result = base64.urlsafe_b64decode(encoded + "=")
    except (ValueError, base64.binascii.Error) as exc:
        raise PolicyBlocked("registration challenge base64url invalid") from exc
    if (result != challenge or
            base64.urlsafe_b64encode(result).rstrip(b"=").decode("ascii") != encoded):
        raise PolicyBlocked("registration challenge does not match")


def inspect_registration_candidate(
    *, expected_challenge: bytes, expected_rp_id: str,
    expected_origin: str, client_data_json: bytes, attestation_object: bytes,
) -> dict[str, object]:
    """Read-only strict validation. NEVER asserts owner enrollment.

    Expected RP/origin/challenge are caller-supplied in this candidate and
    therefore cannot establish a trustworthy relying party or owner identity.
    A real relying party would have to independently verify those values.
    """
    if type(expected_challenge) is not bytes or len(expected_challenge) != 32:
        raise PolicyBlocked("32-byte challenge required")
    _expected_rp_origin(expected_rp_id, expected_origin)
    _validate_client(client_data_json, expected_challenge, expected_origin)
    root = _CBOR(attestation_object).complete()
    if (not isinstance(root, dict) or set(root) != {"fmt", "authData", "attStmt"}
            or root["fmt"] != "none" or root["attStmt"] != {}):
        raise PolicyBlocked("only unsigned none attestation supported")
    auth = root["authData"]
    if type(auth) is not bytes or not 56 <= len(auth) <= MAX_ATTESTATION_BYTES:
        raise PolicyBlocked("attested authenticator data is malformed")
    if auth[:32] != hashlib.sha256(expected_rp_id.encode("ascii")).digest():
        raise PolicyBlocked("registration RP ID hash mismatch")
    flags = auth[32]
    # UP=0x01, UV=0x04, AT=0x40 required. ED=0x80, RFU bits 1/5 denied.
    if flags & 0x45 != 0x45 or flags & 0xA2:
        raise PolicyBlocked("registration UP/UV/AT missing or unsupported extensions")
    if (flags & 0x10) and not (flags & 0x08):
        raise PolicyBlocked("registration backup-state flag inconsistent")
    sign_count = int.from_bytes(auth[33:37], "big")
    aaguid = auth[37:53]
    credential_length = int.from_bytes(auth[53:55], "big")
    if not 1 <= credential_length <= MAX_CREDENTIAL_ID_BYTES:
        raise PolicyBlocked("invalid credential identifier size")
    end_credential = 55 + credential_length
    if end_credential >= len(auth):
        raise PolicyBlocked("credential public key missing")
    credential_id = auth[55:end_credential]
    cbor = _CBOR(auth[end_credential:])
    cose = cbor.complete()
    if (not isinstance(cose, dict) or set(cose) != {1, 3, -1, -2, -3}
            or type(cose[1]) is not int or cose[1] != 2
            or type(cose[3]) is not int or cose[3] != -7
            or type(cose[-1]) is not int or cose[-1] != 1
            or type(cose[-2]) is not bytes or len(cose[-2]) != 32
            or type(cose[-3]) is not bytes or len(cose[-3]) != 32):
        raise PolicyBlocked("unsupported COSE ES256/P-256 registration key")
    # This parser does not prove the EC coordinates are on the P-256 curve,
    # and does not accept any attestation metadata as a trust anchor.
    public_key_hash = hashlib.sha256(
        b"upab-web-authn-p256-v1\0" + cose[-2] + cose[-3]
    ).hexdigest()
    return {
        "schema": "upab.watcher-v3.registration-inspection.v1",
        "format": "none",
        "credential_id_sha256": hashlib.sha256(credential_id).hexdigest(),
        "public_key_sha256": public_key_hash,
        "aaguid_sha256": hashlib.sha256(aaguid).hexdigest(),
        "registration_sign_counter": sign_count,
        "user_present_flag": True,
        "user_verified_flag": True,
        "key_algorithm": "ES256",
        "attestation_trust_verified": False,
        "trusted_relying_party_configured": False,
        "challenge_was_issued_by_trusted_broker": False,
        "credential_record_stored": False,
        "owner_authenticated": False,
        "approval_issued": False,
        "execution_authorized": False,
        "real_task_executed": False,
    }
