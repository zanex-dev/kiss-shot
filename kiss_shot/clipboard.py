# -*- coding: utf-8 -*-
"""
跨平台零依赖剪贴板读取模块 (kiss_shot/clipboard.py)
- Windows: 直接调用 Win32 user32/kernel32 API，零子进程开销
- macOS: 调用系统内置 pbpaste
- Linux: 依次尝试 wl-paste / xclip，无图形环境时静默返回空字符串（兼容无头服务器与 CI）
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    CF_UNICODETEXT = 13
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _user32.OpenClipboard.argtypes = [wintypes.HWND]
    _user32.OpenClipboard.restype = wintypes.BOOL
    _user32.CloseClipboard.argtypes = []
    _user32.CloseClipboard.restype = wintypes.BOOL
    _user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
    _user32.IsClipboardFormatAvailable.restype = wintypes.BOOL
    _user32.GetClipboardData.argtypes = [wintypes.UINT]
    _user32.GetClipboardData.restype = wintypes.HANDLE
    _kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalLock.restype = wintypes.LPVOID
    _kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalUnlock.restype = wintypes.BOOL

    def read_clipboard_text() -> str:
        if not _user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
            return ""
        for _ in range(3):
            if _user32.OpenClipboard(None):
                try:
                    handle = _user32.GetClipboardData(CF_UNICODETEXT)
                    if not handle:
                        return ""
                    ptr = _kernel32.GlobalLock(handle)
                    if not ptr:
                        return ""
                    try:
                        return ctypes.wstring_at(ptr) or ""
                    finally:
                        _kernel32.GlobalUnlock(handle)
                finally:
                    _user32.CloseClipboard()
            time.sleep(0.02)
        return ""

elif sys.platform == "darwin":

    def read_clipboard_text() -> str:
        try:
            res = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=1.0, check=False)
            return res.stdout if res.returncode == 0 else ""
        except Exception:
            return ""

else:

    def read_clipboard_text() -> str:
        try:
            if shutil.which("wl-paste"):
                res = subprocess.run(
                    ["wl-paste", "--no-newline"],
                    capture_output=True,
                    text=True,
                    timeout=1.0,
                    check=False,
                )
                if res.returncode == 0:
                    return res.stdout
            if shutil.which("xclip"):
                res = subprocess.run(
                    ["xclip", "-selection", "clipboard", "-o"],
                    capture_output=True,
                    text=True,
                    timeout=1.0,
                    check=False,
                )
                if res.returncode == 0:
                    return res.stdout
        except Exception:
            pass
        return ""
