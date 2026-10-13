"""Bounded Windows clipboard text adapter, isolated from v1 clipboard behavior."""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from .clipboard_events_v2 import ClipboardEventError, ClipboardTooLarge


class BoundedWindowsClipboard:
    CF_UNICODETEXT = 13

    def __init__(self):
        if sys.platform != "win32":
            raise ClipboardEventError("bounded clipboard adapter requires Windows")
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        u, k = self.user32, self.kernel32
        u.OpenClipboard.argtypes = [wintypes.HWND]
        u.OpenClipboard.restype = wintypes.BOOL
        u.CloseClipboard.argtypes = []
        u.CloseClipboard.restype = wintypes.BOOL
        u.GetClipboardData.argtypes = [wintypes.UINT]
        u.GetClipboardData.restype = wintypes.HANDLE
        k.GlobalSize.argtypes = [wintypes.HGLOBAL]
        k.GlobalSize.restype = ctypes.c_size_t
        k.GlobalLock.argtypes = [wintypes.HGLOBAL]
        k.GlobalLock.restype = wintypes.LPVOID
        k.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        k.GlobalUnlock.restype = wintypes.BOOL

    def get_text_limited(self, max_chars: int) -> str:
        if type(max_chars) is not int or not 256 <= max_chars <= 1048576:
            raise ValueError("max_chars must be in 256..1048576")
        if not self.user32.OpenClipboard(None):
            raise ClipboardEventError("clipboard temporarily unavailable")
        try:
            handle = self.user32.GetClipboardData(self.CF_UNICODETEXT)
            if not handle:
                return ""
            nbytes = self.kernel32.GlobalSize(handle)
            # A Windows WCHAR is 2 bytes. Fail closed if the allocation size
            # itself exceeds our fixed content limit BEFORE decoding/copying.
            if nbytes > 2 * (max_chars + 1):
                raise ClipboardTooLarge("clipboard text allocation exceeds limit")
            if nbytes == 0 or nbytes % 2:
                raise ClipboardEventError("clipboard unicode allocation invalid")
            pointer = self.kernel32.GlobalLock(handle)
            if not pointer:
                raise ClipboardEventError("cannot lock clipboard allocation")
            try:
                text = ctypes.wstring_at(pointer, nbytes // 2).split("\x00", 1)[0]
                if len(text) > max_chars:
                    raise ClipboardTooLarge("clipboard text exceeds limit")
                return text
            finally:
                self.kernel32.GlobalUnlock(handle)
        finally:
            self.user32.CloseClipboard()
