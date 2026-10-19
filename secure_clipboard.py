"""
secure_clipboard.py — Área de transferência com cuidados extras para segredos.

No Windows, o texto é gravado junto com os formatos que pedem ao sistema para NÃO
guardá-lo no histórico (Win+V), NÃO sincronizá-lo com a nuvem e para que
gerenciadores de clipboard o ignorem. Em outros sistemas usa o clipboard do Tk.
"""
from __future__ import annotations

import hashlib
import sys
import time
import tkinter as tk


def digest(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest()


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _user32.OpenClipboard.argtypes = [wintypes.HWND]
    _user32.OpenClipboard.restype = wintypes.BOOL
    _user32.CloseClipboard.argtypes = []
    _user32.CloseClipboard.restype = wintypes.BOOL
    _user32.EmptyClipboard.argtypes = []
    _user32.EmptyClipboard.restype = wintypes.BOOL
    _user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    _user32.SetClipboardData.restype = wintypes.HANDLE
    _user32.GetClipboardData.argtypes = [wintypes.UINT]
    _user32.GetClipboardData.restype = wintypes.HANDLE
    _user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
    _user32.IsClipboardFormatAvailable.restype = wintypes.BOOL
    _user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    _user32.RegisterClipboardFormatW.restype = wintypes.UINT
    _kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    _kernel32.GlobalAlloc.restype = wintypes.HANDLE
    _kernel32.GlobalLock.argtypes = [wintypes.HANDLE]
    _kernel32.GlobalLock.restype = wintypes.LPVOID
    _kernel32.GlobalUnlock.argtypes = [wintypes.HANDLE]
    _kernel32.GlobalUnlock.restype = wintypes.BOOL
    _kernel32.GlobalFree.argtypes = [wintypes.HANDLE]
    _kernel32.GlobalFree.restype = wintypes.HANDLE

    _CF_UNICODETEXT = 13
    _GMEM_MOVEABLE = 0x0002
    _PRIVACY_FORMATS = ("ExcludeClipboardContentFromMonitorProcessing",
                        "CanIncludeInClipboardHistory",
                        "CanUploadToCloudClipboard")

    class _Clipboard:
        def __init__(self, root: tk.Misc):
            # Com hwnd nulo, SetClipboardData falha após EmptyClipboard; usa a janela do Tk.
            self.hwnd = root.winfo_id()

        def __enter__(self):
            for _ in range(25):
                if _user32.OpenClipboard(self.hwnd):
                    return self
                time.sleep(0.02)
            raise OSError("A área de transferência está em uso por outro programa.")

        def __exit__(self, *exc):
            _user32.CloseClipboard()

    def _set(fmt: int, data: bytes) -> None:
        handle = _kernel32.GlobalAlloc(_GMEM_MOVEABLE, len(data))
        if not handle:
            raise MemoryError("GlobalAlloc falhou")
        ptr = _kernel32.GlobalLock(handle)
        if not ptr:
            _kernel32.GlobalFree(handle)
            raise MemoryError("GlobalLock falhou")
        ctypes.memmove(ptr, data, len(data))
        _kernel32.GlobalUnlock(handle)
        if not _user32.SetClipboardData(fmt, handle):
            _kernel32.GlobalFree(handle)
            raise OSError(f"SetClipboardData falhou ({ctypes.get_last_error()})")

    def copy(root: tk.Misc, text: str) -> None:
        with _Clipboard(root):
            _user32.EmptyClipboard()
            _set(_CF_UNICODETEXT, text.encode("utf-16-le", "surrogatepass") + b"\x00\x00")
            for name in _PRIVACY_FORMATS:
                fmt = _user32.RegisterClipboardFormatW(name)
                if fmt:
                    _set(fmt, (0).to_bytes(4, "little"))

    def paste(root: tk.Misc) -> str | None:
        with _Clipboard(root):
            if not _user32.IsClipboardFormatAvailable(_CF_UNICODETEXT):
                return None
            handle = _user32.GetClipboardData(_CF_UNICODETEXT)
            if not handle:
                return None
            ptr = _kernel32.GlobalLock(handle)
            if not ptr:
                return None
            try:
                return ctypes.wstring_at(ptr)
            finally:
                _kernel32.GlobalUnlock(handle)

    def clear(root: tk.Misc) -> None:
        with _Clipboard(root):
            _user32.EmptyClipboard()

else:
    def copy(root: tk.Misc, text: str) -> None:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update_idletasks()

    def paste(root: tk.Misc) -> str | None:
        try:
            return root.clipboard_get()
        except tk.TclError:
            return None

    def clear(root: tk.Misc) -> None:
        root.clipboard_clear()
