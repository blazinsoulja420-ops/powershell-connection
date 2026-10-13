"""Windows-native named-pipe DACL construction preflight (no pipe created).

Builds a protected ACL that grants full pipe access only to the current
process account and LocalSystem. This is still NOT an applied endpoint ACL:
creation, remote-client rejection, impersonation, per-client identity and
human-presence verification remain separate release gates.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from .v3_policy import PolicyBlocked
from .v3_windows_identity import read_windows_identity_evidence

SDDL_REVISION_1 = 1


def preview_owner_pipe_security() -> dict[str, object]:
    if sys.platform != "win32":
        raise PolicyBlocked("named-pipe ACL preflight requires Windows")
    owner = read_windows_identity_evidence()
    sid = owner["process_user_sid"]
    if not isinstance(sid, str) or not sid.startswith("S-1-"):
        raise PolicyBlocked("process token SID invalid")
    # Protected DACL: SY is LocalSystem; second principal is exact token SID.
    # No anonymous, Everyone, authenticated-users or administrators ACE.
    sddl = "D:P(A;;GA;;;SY)(A;;GA;;;" + sid + ")"
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorDacl.argtypes = [
        wintypes.LPVOID, ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.BOOL),
    ]
    advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel.LocalFree.restype = wintypes.HLOCAL
    description = wintypes.LPVOID()
    total_size = wintypes.DWORD()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, ctypes.byref(description), ctypes.byref(total_size)
    ):
        raise PolicyBlocked("Windows rejected proposed protected DACL")
    try:
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        dacl = wintypes.LPVOID()
        if not advapi.GetSecurityDescriptorDacl(
            description, ctypes.byref(present), ctypes.byref(dacl),
            ctypes.byref(defaulted)
        ):
            raise PolicyBlocked("Windows could not verify security descriptor DACL")
        if not present.value or not dacl.value or total_size.value < 16:
            raise PolicyBlocked("invalid or null proposed DACL")
        return {
            "schema": "upab.watcher-v3.pipe-dacl-preview.v1",
            "native_sddl_accepted": True,
            "protected_dacl_present": True,
            "explicit_current_token_user_ace": True,
            "localsystem_ace": True,
            "broad_principal_aces_requested": False,
            "pipe_created": False,
            "security_descriptor_applied": False,
            "peer_authenticated": False,
            "owner_authenticated": False,
            "execution_authorized": False,
        }
    finally:
        kernel.LocalFree(ctypes.cast(description, wintypes.HLOCAL))
