"""Stage 9 Windows DPAPI in-memory protection primitive (candidate only).

CryptProtectData scopes bytes to the current Windows user's credentials
without CRYPTPROTECT_LOCAL_MACHINE. This is NOT Windows Hello, user presence,
authentication, human approval, or authorization to execute tasks.

No file/key store, IPC listener, command runner, or approval issuer is here.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from .v3_policy import PolicyBlocked

CRYPTPROTECT_UI_FORBIDDEN = 0x1
_ENTROPY = b"UPAB-WATCHER-V3-DPAPI-CANDIDATE-v1"


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _blob(data: bytes):
    if not isinstance(data, bytes) or not 1 <= len(data) <= 65536:
        raise PolicyBlocked("DPAPI input must be bounded bytes")
    buffer = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer


def _api():
    if sys.platform != "win32":
        raise PolicyBlocked("current-user DPAPI requires Windows")
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    blob_ptr = ctypes.POINTER(DATA_BLOB)
    crypt.CryptProtectData.argtypes = [
        blob_ptr, wintypes.LPCWSTR, blob_ptr, wintypes.LPVOID,
        wintypes.LPVOID, wintypes.DWORD, blob_ptr,
    ]
    crypt.CryptProtectData.restype = wintypes.BOOL
    crypt.CryptUnprotectData.argtypes = [
        blob_ptr, ctypes.POINTER(wintypes.LPWSTR), blob_ptr,
        wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, blob_ptr,
    ]
    crypt.CryptUnprotectData.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    return crypt, kernel


def protect_for_current_user(plaintext: bytes) -> bytes:
    """Encrypt in memory; NEVER persist a credential from this module."""
    input_blob, input_keepalive = _blob(plaintext)
    entropy_blob, entropy_keepalive = _blob(_ENTROPY)
    crypt, kernel = _api()
    encrypted = DATA_BLOB()
    try:
        if not crypt.CryptProtectData(
            ctypes.byref(input_blob), None, ctypes.byref(entropy_blob),
            None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(encrypted),
        ):
            raise PolicyBlocked("Windows DPAPI encryption failed")
        if not encrypted.pbData or encrypted.cbData == 0 or encrypted.cbData > 131072:
            raise PolicyBlocked("invalid DPAPI ciphertext size")
        return ctypes.string_at(encrypted.pbData, encrypted.cbData)
    finally:
        if encrypted.pbData:
            kernel.LocalFree(ctypes.cast(encrypted.pbData, wintypes.HLOCAL))
        # These Python copies are not guaranteed to be securely zeroized.
        del input_keepalive, entropy_keepalive


def unprotect_for_current_user(ciphertext: bytes) -> bytes:
    """Decrypt bounded ciphertext using the original user-bound DPAPI context."""
    input_blob, input_keepalive = _blob(ciphertext)
    entropy_blob, entropy_keepalive = _blob(_ENTROPY)
    crypt, kernel = _api()
    decrypted = DATA_BLOB()
    description = wintypes.LPWSTR()
    try:
        if not crypt.CryptUnprotectData(
            ctypes.byref(input_blob), ctypes.byref(description),
            ctypes.byref(entropy_blob), None, None,
            CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(decrypted),
        ):
            raise PolicyBlocked("Windows DPAPI decryption failed")
        if not decrypted.pbData or decrypted.cbData == 0 or decrypted.cbData > 65536:
            raise PolicyBlocked("invalid DPAPI plaintext size")
        return ctypes.string_at(decrypted.pbData, decrypted.cbData)
    finally:
        if decrypted.pbData:
            ctypes.memset(decrypted.pbData, 0, decrypted.cbData)
            kernel.LocalFree(ctypes.cast(decrypted.pbData, wintypes.HLOCAL))
        if description:
            kernel.LocalFree(ctypes.cast(description, wintypes.HLOCAL))
        del input_keepalive, entropy_keepalive
