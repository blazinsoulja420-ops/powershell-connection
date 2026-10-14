from __future__ import annotations

import ctypes
import json
import sys
import threading
import time
import unittest
from ctypes import wintypes

from upab.relay.v3_broker_contract import PIPE_NAME, SCHEMA
from upab.relay.v3_pipe_server_preview import DenyOnlyPipeServer
from upab.relay.v3_policy import PolicyBlocked

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
ERROR_FILE_NOT_FOUND = 2
ERROR_PIPE_BUSY = 231


def _client_exchange(request: bytes, *, expect_response: bool = True):
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    k.CreateFileW.restype = wintypes.HANDLE
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CloseHandle.restype = wintypes.BOOL
    k.WriteFile.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    k.WriteFile.restype = wintypes.BOOL
    k.ReadFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    k.ReadFile.restype = wintypes.BOOL
    handle = None
    for _ in range(60):
        trial = k.CreateFileW(
            PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None
        )
        if trial and trial != ctypes.c_void_p(-1).value:
            handle = trial
            break
        if ctypes.get_last_error() not in (ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY):
            raise RuntimeError("local test client could not open pipe")
        time.sleep(0.05)
    if handle is None:
        raise RuntimeError("bounded test client failed to connect")
    try:
        sent = wintypes.DWORD()
        payload = ctypes.create_string_buffer(request, len(request))
        if not k.WriteFile(
            handle, payload, len(request), ctypes.byref(sent), None
        ):
            raise RuntimeError("fixture pipe write failed")
        if sent.value != len(request):
            raise RuntimeError("partial fixture pipe write")
        data = ctypes.create_string_buffer(4096)
        got = wintypes.DWORD()
        success = k.ReadFile(handle, data, 4096, ctypes.byref(got), None)
        if expect_response:
            if not success:
                raise RuntimeError("expected denial-only response was not readable")
            return json.loads(data.raw[:got.value])
        if success:
            raise RuntimeError("unexpected response to prohibited frame")
        return {"server_rejected": True}
    finally:
        k.CloseHandle(handle)


@unittest.skipUnless(sys.platform == "win32", "Win32 local IPC only")
class NativeDenyOnlyPipeTests(unittest.TestCase):
    def _serve(self, wire, *, expect_response=True):
        answer = []
        def server():
            try:
                answer.append(("ok", DenyOnlyPipeServer().serve_once(timeout_ms=8000)))
            except Exception as exc:
                answer.append(("blocked", type(exc).__name__))
        thread = threading.Thread(target=server)
        thread.start()
        try:
            reply = _client_exchange(wire, expect_response=expect_response)
        finally:
            thread.join(timeout=12)
        self.assertFalse(thread.is_alive(), "pipe server did not terminate after bounded test")
        self.assertEqual(len(answer), 1)
        return reply, answer[0]

    def test_local_same_user_status_response_never_approves(self):
        frame = json.dumps({
            "schema": SCHEMA, "method": "status", "request_id": "a"*32,
            "payload": {},
        }, separators=(",", ":")).encode("utf-8")
        reply, result = self._serve(frame)
        self.assertEqual(result[0], "ok", result)
        self.assertTrue(reply["transport_peer_verified"])
        self.assertFalse(reply["owner_authenticated"])
        self.assertFalse(reply["presence_verified"])
        self.assertFalse(reply["approval_issued"])
        self.assertFalse(reply["execution_authorized"])
        self.assertFalse(reply["changes_performed"])
        self.assertEqual(result[1]["status"], "ONE_DENIAL_ONLY_RESPONSE_SERVED")
        self.assertFalse(result[1]["task_executed"])

    def test_local_review_preview_refuses_execution(self):
        frame = json.dumps({
            "schema": SCHEMA, "method": "review_preview", "request_id": "b"*32,
            "payload": {"task_id": "fixture", "task_sha256": "A"*64},
        }, separators=(",", ":")).encode("utf-8")
        reply, result = self._serve(frame)
        self.assertEqual(result[0], "ok", result)
        self.assertEqual(reply["status"], "REVIEW_PREVIEW_ONLY")
        self.assertFalse(reply["execution_authorized"])
        self.assertNotIn("task_sha256", reply)

    def test_execution_requests_get_disconnected_without_response(self):
        frame = json.dumps({
            "schema": SCHEMA, "method": "execute", "request_id": "c"*32,
            "payload": {"script": "not authorized"},
        }, separators=(",", ":")).encode("utf-8")
        reply, result = self._serve(frame, expect_response=False)
        self.assertEqual(result[0], "blocked", result)
        self.assertEqual(result[1], "PolicyBlocked")
        self.assertTrue(reply["server_rejected"])

    def test_unconnected_server_times_out_without_becoming_persistent(self):
        started = time.monotonic()
        with self.assertRaises(PolicyBlocked):
            DenyOnlyPipeServer().serve_once(timeout_ms=250)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_oversized_frame_is_rejected_without_response(self):
        frame = b"X" * 4097
        reply, result = self._serve(frame, expect_response=False)
        self.assertEqual(result[0], "blocked", result)
        self.assertEqual(result[1], "PolicyBlocked")
        self.assertTrue(reply["server_rejected"])

    def test_invalid_connection_timeout_is_refused(self):
        with self.assertRaises(PolicyBlocked):
            DenyOnlyPipeServer().serve_once(timeout_ms=0)

    def test_no_command_or_approval_method(self):
        service = DenyOnlyPipeServer()
        for name in ("run_shell", "approve", "authorize", "connect_repo",
                     "issue_proof", "deploy"):
            self.assertFalse(hasattr(service, name))


if __name__ == "__main__":
    unittest.main()
