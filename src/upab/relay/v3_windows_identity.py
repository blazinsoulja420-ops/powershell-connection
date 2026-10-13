"""Read-only Windows process identity evidence for future owner-approval broker.

Windows logon identity of THIS process is NOT proof of current human presence,
physical owner consent, user verification, or an authorized task. This module
cannot issue approval proofs, authorize execution, connect a repo or run tasks.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from .v3_policy import PolicyBlocked


TOKEN_QUERY = 0x0008
TOKEN_USER = 1
ERROR_INSUFFICIENT_BUFFER = 122
MAX_TOKEN_USER_BYTES = 16384


def read_windows_identity_evidence() -> dict[str, object]:
    if sys.platform != "win32":
        raise PolicyBlocked("Windows identity evidence requires Windows")

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetCurrentProcessId.argtypes = []
    kernel.GetCurrentProcessId.restype = wintypes.DWORD
    kernel.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.ProcessIdToSessionId.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
    ]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
    ]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)
    ]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        raise PolicyBlocked("cannot read local process token")
    try:
        size = wintypes.DWORD()
        ctypes.set_last_error(0)
        advapi.GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(size))
        if (ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER
                or not 1 <= size.value <= MAX_TOKEN_USER_BYTES):
            raise PolicyBlocked("invalid token identity buffer size")
        buf = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, TOKEN_USER, buf, size, ctypes.byref(size)):
            raise PolicyBlocked("unable to read process identity")
        # TOKEN_USER begins with SID_AND_ATTRIBUTES: first field is a PSID.
        sid_address = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        if not sid_address:
            raise PolicyBlocked("missing process SID")
        string_sid = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(
            ctypes.c_void_p(sid_address), ctypes.byref(string_sid)
        ):
            raise PolicyBlocked("cannot encode process SID")
        try:
            sid = string_sid.value
        finally:
            kernel.LocalFree(ctypes.cast(string_sid, wintypes.HLOCAL))
        if not sid or not sid.startswith("S-1-") or len(sid) > 256:
            raise PolicyBlocked("unexpected SID format")
        session = wintypes.DWORD()
        if not kernel.ProcessIdToSessionId(
            kernel.GetCurrentProcessId(), ctypes.byref(session)
        ):
            raise PolicyBlocked("cannot determine Windows session")
        return {
            "schema": "upab.watcher-v3.windows-identity-evidence.v1",
            "process_user_sid": sid,
            "process_session_id": int(session.value),
            "process_identity_observed": True,
            "owner_authenticated": False,
            "human_present": False,
            "task_approved": False,
            "execution_allowed": False,
        }
    finally:
        kernel.CloseHandle(token)
