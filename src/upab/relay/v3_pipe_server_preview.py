"""Stage 10 Windows named-pipe transport acceptance CANDIDATE (denial only).

Opens a *single-use* current-user-only local pipe with a protected DACL,
PIPE_REJECT_REMOTE_CLIENTS, FILE_FLAG_FIRST_PIPE_INSTANCE and bounded
overlapped I/O. Verifies the actual communicating client by impersonating
the pipe client AFTER receiving its bytes, reading the impersonation token
SID and integrity level, and cross-checking the kernel-reported client
session against the server session. Always reverts impersonation.

This module never authenticates human presence, approves a task, executes
a command, emits credentials, or calls the legacy watcher. The only exposed
operations remain the inert status/review_preview broker contract.
Not installed, auto-started, or callable via the active watcher.
"""
from __future__ import annotations

import ctypes
import json
import re
import sys
from ctypes import wintypes

from .v3_broker_contract import PIPE_NAME, MAX_FRAME_BYTES, validate_untrusted_frame
from .v3_policy import PolicyBlocked
from .v3_windows_identity import read_windows_identity_evidence

PIPE_ACCESS_DUPLEX = 0x00000003
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
FILE_FLAG_OVERLAPPED = 0x40000000
PIPE_TYPE_MESSAGE = 0x00000004
PIPE_READMODE_MESSAGE = 0x00000002
PIPE_WAIT = 0x00000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
ERROR_IO_PENDING = 997
ERROR_PIPE_CONNECTED = 535
ERROR_MORE_DATA = 234
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
TOKEN_QUERY = 0x0008
TOKEN_USER = 1
TOKEN_INTEGRITY_LEVEL = 25
SECURITY_SQOS_PRESENT = 0x00100000
MAX_RESPONSE_BYTES = 4096


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


def _windows():
    if sys.platform != "win32":
        raise PolicyBlocked("Windows pipe broker requires Windows")
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    k.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(SECURITY_ATTRIBUTES),
    ]
    k.CreateNamedPipeW.restype = wintypes.HANDLE
    k.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    k.CreateEventW.restype = wintypes.HANDLE
    k.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.POINTER(OVERLAPPED)]
    k.ConnectNamedPipe.restype = wintypes.BOOL
    k.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                           ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(OVERLAPPED)]
    k.ReadFile.restype = wintypes.BOOL
    k.WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
                            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(OVERLAPPED)]
    k.WriteFile.restype = wintypes.BOOL
    k.GetOverlappedResult.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(OVERLAPPED),
        ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
    ]
    k.GetOverlappedResult.restype = wintypes.BOOL
    k.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(OVERLAPPED)]
    k.CancelIoEx.restype = wintypes.BOOL
    k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k.WaitForSingleObject.restype = wintypes.DWORD
    k.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    k.GetNamedPipeClientProcessId.restype = wintypes.BOOL
    k.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    k.ProcessIdToSessionId.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CloseHandle.restype = wintypes.BOOL
    k.LocalFree.argtypes = [wintypes.HLOCAL]
    k.LocalFree.restype = wintypes.HLOCAL
    k.GetCurrentThread.argtypes = []
    k.GetCurrentThread.restype = wintypes.HANDLE
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.DWORD),
    ]
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    a.ImpersonateNamedPipeClient.argtypes = [wintypes.HANDLE]
    a.ImpersonateNamedPipeClient.restype = wintypes.BOOL
    a.RevertToSelf.argtypes = []
    a.RevertToSelf.restype = wintypes.BOOL
    a.OpenThreadToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    a.OpenThreadToken.restype = wintypes.BOOL
    a.GetTokenInformation.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    a.GetTokenInformation.restype = wintypes.BOOL
    a.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR),
    ]
    a.ConvertSidToStringSidW.restype = wintypes.BOOL
    return k, a


def _sid_from_token(k, a, token, info_class: int) -> str:
    needed = wintypes.DWORD(0)
    a.GetTokenInformation(token, info_class, None, 0, ctypes.byref(needed))
    if not 8 <= needed.value <= 16384:
        raise PolicyBlocked("invalid client token buffer length")
    buffer = ctypes.create_string_buffer(needed.value)
    if not a.GetTokenInformation(
        token, info_class, buffer, needed, ctypes.byref(needed)
    ):
        raise PolicyBlocked("client token information unavailable")
    sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
    if not sid_pointer:
        raise PolicyBlocked("client token SID unavailable")
    target = wintypes.LPWSTR()
    if not a.ConvertSidToStringSidW(
        ctypes.c_void_p(sid_pointer), ctypes.byref(target)
    ):
        raise PolicyBlocked("client token SID cannot be formatted")
    try:
        result = target.value
    finally:
        k.LocalFree(ctypes.cast(target, wintypes.HLOCAL))
    if not result or len(result) > 256:
        raise PolicyBlocked("client SID format invalid")
    return result


def _verify_peer(k, a, pipe, expected_user: str, expected_session: int) -> None:
    """Do not return/encode the SID or PID; a verified peer is not an owner approval."""
    client_pid = wintypes.ULONG()
    if not k.GetNamedPipeClientProcessId(pipe, ctypes.byref(client_pid)):
        raise PolicyBlocked("cannot verify connecting process")
    session = wintypes.DWORD()
    if not k.ProcessIdToSessionId(client_pid.value, ctypes.byref(session)):
        raise PolicyBlocked("client Windows session unavailable")
    if session.value != expected_session:
        raise PolicyBlocked("client session mismatch")
    if not a.ImpersonateNamedPipeClient(pipe):
        raise PolicyBlocked("cannot impersonate local pipe client")
    token = wintypes.HANDLE()
    try:
        if not a.OpenThreadToken(k.GetCurrentThread(), TOKEN_QUERY, True, ctypes.byref(token)):
            raise PolicyBlocked("client impersonation token unavailable")
        user_sid = _sid_from_token(k, a, token, TOKEN_USER)
        integrity_sid = _sid_from_token(k, a, token, TOKEN_INTEGRITY_LEVEL)
        if user_sid != expected_user:
            raise PolicyBlocked("client Windows SID mismatch")
        if not re.fullmatch(r"S-1-16-[0-9]+", integrity_sid):
            raise PolicyBlocked("client integrity level unrecognized")
        level = int(integrity_sid.split("-")[-1])
        if level < 8192:
            raise PolicyBlocked("low integrity client not admitted")
    finally:
        if token:
            k.CloseHandle(token)
        if not a.RevertToSelf():
            # Fail hard: an unreverted impersonation context is unsafe.
            raise PolicyBlocked("failed to restore server Windows token")


class DenyOnlyPipeServer:
    """One connection, bounded waits, deny-only protocol, no actual task work."""

    def __init__(self):
        if sys.platform != "win32":
            raise PolicyBlocked("named pipe transport requires Windows")

    @staticmethod
    def _event(k) -> wintypes.HANDLE:
        event = k.CreateEventW(None, True, False, None)
        if not event:
            raise PolicyBlocked("cannot create bounded I/O event")
        return event

    @staticmethod
    def _completion(k, pipe, pending: OVERLAPPED, timeout_ms: int) -> int:
        state = k.WaitForSingleObject(pending.hEvent, timeout_ms)
        if state != WAIT_OBJECT_0:
            k.CancelIoEx(pipe, ctypes.byref(pending))
            # Caller closes pipe after this. Do not block forever on cancel.
            raise PolicyBlocked("local pipe operation timed out or failed")
        transferred = wintypes.DWORD()
        if not k.GetOverlappedResult(pipe, ctypes.byref(pending), ctypes.byref(transferred), False):
            raise PolicyBlocked("local pipe operation completion failed")
        return transferred.value

    def serve_once(self, *, timeout_ms: int = 5000) -> dict[str, object]:
        if type(timeout_ms) is not int or not 200 <= timeout_ms <= 30000:
            raise PolicyBlocked("pipe timeout must be 200..30000 ms")
        k, a = _windows()
        server = read_windows_identity_evidence()
        sid = server["process_user_sid"]
        session = server["process_session_id"]
        sddl = "D:P(A;;GA;;;" + sid + ")"
        descriptor = wintypes.LPVOID()
        desc_size = wintypes.DWORD()
        if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), ctypes.byref(desc_size)
        ):
            raise PolicyBlocked("cannot construct restricted pipe security")
        security = SECURITY_ATTRIBUTES(
            ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False
        )
        invalid = ctypes.c_void_p(-1).value
        pipe = None
        try:
            pipe = k.CreateNamedPipeW(
                PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1, MAX_RESPONSE_BYTES, MAX_FRAME_BYTES + 1, timeout_ms,
                ctypes.byref(security),
            )
            if not pipe or pipe == invalid:
                raise PolicyBlocked("cannot exclusively create protected local pipe")
            # Connection needs overlapped mode for a finite wait.
            connection_event = self._event(k)
            try:
                ov = OVERLAPPED()
                ov.hEvent = connection_event
                ok = k.ConnectNamedPipe(pipe, ctypes.byref(ov))
                if not ok:
                    err = ctypes.get_last_error()
                    if err == ERROR_IO_PENDING:
                        self._completion(k, pipe, ov, timeout_ms)
                    elif err != ERROR_PIPE_CONNECTED:
                        raise PolicyBlocked("local pipe connection failed")
            finally:
                k.CloseHandle(connection_event)

            # Read a complete request (limit + 1 triggers refusal for >limit).
            request_event = self._event(k)
            try:
                ov = OVERLAPPED()
                ov.hEvent = request_event
                buffer = ctypes.create_string_buffer(MAX_FRAME_BYTES + 1)
                received = wintypes.DWORD()
                ok = k.ReadFile(
                    pipe, buffer, MAX_FRAME_BYTES + 1, ctypes.byref(received),
                    ctypes.byref(ov)
                )
                if not ok:
                    err = ctypes.get_last_error()
                    if err == ERROR_IO_PENDING:
                        size = self._completion(k, pipe, ov, timeout_ms)
                    elif err == ERROR_MORE_DATA:
                        raise PolicyBlocked("broker request exceeds frame bound")
                    else:
                        raise PolicyBlocked("pipe read failed")
                else:
                    size = received.value
                if not 2 <= size <= MAX_FRAME_BYTES:
                    raise PolicyBlocked("invalid broker frame length")
                _verify_peer(k, a, pipe, sid, session)
                preview = validate_untrusted_frame(buffer.raw[:size])
            finally:
                k.CloseHandle(request_event)

            # Authoritative response remains non-approving, always.
            preview["transport_peer_verified"] = True
            preview["owner_authenticated"] = False
            preview["execution_authorized"] = False
            preview["listener_running"] = True
            response = json.dumps(preview, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if len(response) > MAX_RESPONSE_BYTES:
                raise PolicyBlocked("broker response exceeds size bound")
            output_event = self._event(k)
            try:
                ov = OVERLAPPED()
                ov.hEvent = output_event
                count = wintypes.DWORD()
                payload = ctypes.create_string_buffer(response, len(response))
                done = k.WriteFile(
                    pipe, payload, len(response), ctypes.byref(count), ctypes.byref(ov)
                )
                if not done:
                    if ctypes.get_last_error() != ERROR_IO_PENDING:
                        raise PolicyBlocked("cannot send denial-only response")
                    wrote = self._completion(k, pipe, ov, timeout_ms)
                else:
                    wrote = count.value
                if wrote != len(response):
                    raise PolicyBlocked("partial pipe response")
            finally:
                k.CloseHandle(output_event)
            return {
                "status": "ONE_DENIAL_ONLY_RESPONSE_SERVED",
                "peer_verified": True,
                "human_approved": False,
                "task_executed": False,
            }
        finally:
            if pipe and pipe != invalid:
                k.CloseHandle(pipe)
            k.LocalFree(ctypes.cast(descriptor, wintypes.HLOCAL))
