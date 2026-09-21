from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes


class ClipboardError(RuntimeError):
    pass


class WindowsClipboard:
    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002

    def __init__(self):
        if sys.platform != "win32":
            raise ClipboardError("WindowsClipboard is only available on Windows")
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.user32.OpenClipboard.argtypes = [wintypes.HWND]
        self.user32.OpenClipboard.restype = wintypes.BOOL
        self.user32.CloseClipboard.argtypes = []
        self.user32.CloseClipboard.restype = wintypes.BOOL
        self.user32.GetClipboardData.argtypes = [wintypes.UINT]
        self.user32.GetClipboardData.restype = wintypes.HANDLE
        self.user32.EmptyClipboard.argtypes = []
        self.user32.EmptyClipboard.restype = wintypes.BOOL
        self.user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        self.user32.SetClipboardData.restype = wintypes.HANDLE
        self.kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        self.kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
        self.kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        self.kernel32.GlobalLock.restype = wintypes.LPVOID
        self.kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        self.kernel32.GlobalUnlock.restype = wintypes.BOOL
        self.kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
        self.kernel32.GlobalFree.restype = wintypes.HGLOBAL

    def _open(self) -> None:
        if not self.user32.OpenClipboard(None):
            raise ClipboardError("Unable to open Windows clipboard")

    def get_text(self) -> str:
        self._open()
        try:
            handle = self.user32.GetClipboardData(self.CF_UNICODETEXT)
            if not handle:
                return ""
            pointer = self.kernel32.GlobalLock(handle)
            if not pointer:
                raise ClipboardError("Unable to lock clipboard text")
            try:
                return ctypes.wstring_at(pointer)
            finally:
                self.kernel32.GlobalUnlock(handle)
        finally:
            self.user32.CloseClipboard()

    def set_text(self, text: str) -> None:
        data = (text + "\0").encode("utf-16-le")
        self._open()
        handle = None
        try:
            if not self.user32.EmptyClipboard():
                raise ClipboardError("Unable to empty Windows clipboard")
            handle = self.kernel32.GlobalAlloc(self.GMEM_MOVEABLE, len(data))
            if not handle:
                raise ClipboardError("Unable to allocate clipboard memory")
            pointer = self.kernel32.GlobalLock(handle)
            if not pointer:
                raise ClipboardError("Unable to lock clipboard memory")
            try:
                ctypes.memmove(pointer, data, len(data))
            finally:
                self.kernel32.GlobalUnlock(handle)
            if not self.user32.SetClipboardData(self.CF_UNICODETEXT, handle):
                raise ClipboardError("Unable to set clipboard data")
            handle = None  # clipboard owns the allocation now
        finally:
            if handle:
                self.kernel32.GlobalFree(handle)
            self.user32.CloseClipboard()


class MemoryClipboard:
    def __init__(self, text: str = ""):
        self.text = text

    def get_text(self) -> str:
        return self.text

    def set_text(self, text: str) -> None:
        self.text = text
