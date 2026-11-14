# -*- coding: utf-8 -*-
"""
跨平台零依赖安全剪贴板模块 (kiss_shot/clipboard.py)
- Windows: 直接调用 Win32 user32/kernel32 API，通过 GlobalSize 严格约束读取边界（防止畸形内存块越界崩溃），
  并在复制敏感密文/口令时同步写入微软官方剪贴板历史 (Win+V) 与云同步豁免标记。
- macOS: 调用系统内置 pbpaste / pbcopy。
- Linux: 依次尝试 wl-paste / wl-copy / xclip，无图形环境时静默回退（兼容无头服务器与 CI）。
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
    GMEM_MOVEABLE = 0x0002

    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _user32.OpenClipboard.argtypes = [wintypes.HWND]
    _user32.OpenClipboard.restype = wintypes.BOOL
    _user32.CloseClipboard.argtypes = []
    _user32.CloseClipboard.restype = wintypes.BOOL
    _user32.EmptyClipboard.argtypes = []
    _user32.EmptyClipboard.restype = wintypes.BOOL
    _user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
    _user32.IsClipboardFormatAvailable.restype = wintypes.BOOL
    _user32.GetClipboardData.argtypes = [wintypes.UINT]
    _user32.GetClipboardData.restype = wintypes.HANDLE
    _user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    _user32.SetClipboardData.restype = wintypes.HANDLE
    _user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    _user32.RegisterClipboardFormatW.restype = wintypes.UINT

    _kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    _kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    _kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalFree.restype = wintypes.HGLOBAL
    _kernel32.GlobalSize.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalSize.restype = ctypes.c_size_t
    _kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalLock.restype = wintypes.LPVOID
    _kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalUnlock.restype = wintypes.BOOL

    _FMT_EXCLUDE_MONITOR = _user32.RegisterClipboardFormatW("ExcludeClipboardContentFromMonitorProcessing")
    _FMT_CAN_INCLUDE_HISTORY = _user32.RegisterClipboardFormatW("CanIncludeInClipboardHistory")
    _FMT_CAN_UPLOAD_CLOUD = _user32.RegisterClipboardFormatW("CanUploadToCloudClipboard")

    def _alloc_clipboard_bytes(raw: bytes) -> wintypes.HGLOBAL:
        hmem = _kernel32.GlobalAlloc(GMEM_MOVEABLE, len(raw))
        if not hmem:
            return None
        ptr = _kernel32.GlobalLock(hmem)
        if not ptr:
            _kernel32.GlobalFree(hmem)
            return None
        try:
            ctypes.memmove(ptr, raw, len(raw))
        finally:
            _kernel32.GlobalUnlock(hmem)
        return hmem

    def read_clipboard_text() -> str:
        if not _user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
            return ""
        for _ in range(3):
            if _user32.OpenClipboard(None):
                try:
                    handle = _user32.GetClipboardData(CF_UNICODETEXT)
                    if not handle:
                        return ""
                    byte_len = _kernel32.GlobalSize(handle)
                    if byte_len < 2:
                        return ""
                    max_wchars = min(byte_len // 2, 1_048_576)
                    ptr = _kernel32.GlobalLock(handle)
                    if not ptr:
                        return ""
                    try:
                        raw_w = ctypes.wstring_at(ptr, max_wchars)
                        nul_pos = raw_w.find("\x00")
                        return raw_w[:nul_pos] if nul_pos >= 0 else raw_w
                    finally:
                        _kernel32.GlobalUnlock(handle)
                finally:
                    _user32.CloseClipboard()
            time.sleep(0.02)
        return ""

    def write_clipboard_secret(text: str) -> bool:
        """写入敏感文本至 Windows 剪贴板，同时禁止 Win+V 剪贴板历史留存与跨设备云剪贴板同步"""
        encoded = text.encode("utf-16-le") + b"\x00\x00"
        dword_zero = (0).to_bytes(4, "little")
        for _ in range(3):
            if _user32.OpenClipboard(None):
                try:
                    _user32.EmptyClipboard()
                    h_txt = _alloc_clipboard_bytes(encoded)
                    if not h_txt:
                        return False
                    if not _user32.SetClipboardData(CF_UNICODETEXT, h_txt):
                        _kernel32.GlobalFree(h_txt)
                        return False
                    for fmt_id in (_FMT_EXCLUDE_MONITOR, _FMT_CAN_INCLUDE_HISTORY, _FMT_CAN_UPLOAD_CLOUD):
                        if fmt_id:
                            h_flag = _alloc_clipboard_bytes(dword_zero)
                            if h_flag and not _user32.SetClipboardData(fmt_id, h_flag):
                                _kernel32.GlobalFree(h_flag)
                    return True
                finally:
                    _user32.CloseClipboard()
            time.sleep(0.02)
        return False

    def clear_clipboard_text() -> None:
        for _ in range(3):
            if _user32.OpenClipboard(None):
                try:
                    _user32.EmptyClipboard()
                    return
                finally:
                    _user32.CloseClipboard()
            time.sleep(0.02)

elif sys.platform == "darwin":

    def read_clipboard_text() -> str:
        try:
            res = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=1.0, check=False)
            return res.stdout if res.returncode == 0 else ""
        except Exception:
            return ""

    def write_clipboard_secret(text: str) -> bool:
        try:
            res = subprocess.run(["pbcopy"], input=text, text=True, timeout=1.0, check=False)
            return res.returncode == 0
        except Exception:
            return False

    def clear_clipboard_text() -> None:
        write_clipboard_secret("")

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

    def write_clipboard_secret(text: str) -> bool:
        try:
            if shutil.which("wl-copy"):
                res = subprocess.run(["wl-copy"], input=text, text=True, timeout=1.0, check=False)
                return res.returncode == 0
            if shutil.which("xclip"):
                res = subprocess.run(
                    ["xclip", "-selection", "clipboard"],
                    input=text,
                    text=True,
                    timeout=1.0,
                    check=False,
                )
                return res.returncode == 0
        except Exception:
            pass
        return False

    def clear_clipboard_text() -> None:
        write_clipboard_secret("")
