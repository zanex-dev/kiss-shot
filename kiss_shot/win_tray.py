# -*- coding: utf-8 -*-
"""
零依赖原生 Win32 桌面壳层、开始菜单快捷方式与系统托盘控制器 (win_tray.py)
- 100% 构建于 Python 标准库与原生 Win32 / COM ctypes（零第三方依赖、零外部进程调用）
- SetCurrentProcessExplicitAppUserModelID + COM IPropertyStore (PKEY_AppUserModel_ID) 原生开始菜单/任务栏独立身份绑定
- LoadImageW 多尺寸高清 .ico 注入 + Explorer 重启 (TaskbarCreated) 自动重挂
- AllowSetForegroundWindow + 跨进程 PostMessageW 单实例唤醒（支持托盘隐藏态无缝唤起）
- 独立 Win32 消息泵守护线程 + 线程安全回调派发（0% 待机 CPU，非 Windows 平台自动安全降级）
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import sys
import threading
from typing import Callable, Optional, Sequence, Tuple

MenuSpec = Optional[Tuple[str, Callable[[], None]]]

IS_WIN32 = sys.platform == "win32"

WM_NULL = 0x0000
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_APP = 0x8000
WM_TRAY_CALLBACK = WM_APP + 101
WM_APP_SHOW_PANEL = WM_APP + 102

WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_CONTEXTMENU = 0x007B

NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002

NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
NIF_INFO = 0x00000010
NIIF_INFO = 0x00000001
NIIF_NOSOUND = 0x00000010

IMAGE_ICON = 1
LR_LOADFROMFILE = 0x00000010
SM_CXSMICON = 49
SM_CYSMICON = 50
IDI_APPLICATION = 32512

MF_STRING = 0x00000000
MF_SEPARATOR = 0x00000800
TPM_LEFTALIGN = 0x0000
TPM_BOTTOMALIGN = 0x0020
TPM_RIGHTBUTTON = 0x0002
TPM_NONOTIFY = 0x0080
TPM_RETURNCMD = 0x0100

SW_RESTORE = 9
CSIDL_PROGRAMS = 0x0002
SHCNE_ASSOCCHANGED = 0x08000000
SHCNF_IDLIST = 0x0000
VT_LPWSTR = 31

if IS_WIN32:
    WNDPROC = ctypes.WINFUNCTYPE(
        ctypes.c_ssize_t,
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    )

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [
            ("style", wintypes.UINT),
            ("lpfnWndProc", WNDPROC),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE),
            ("hIcon", wintypes.HICON),
            ("hCursor", wintypes.HANDLE),
            ("hbrBackground", wintypes.HBRUSH),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
        ]

    class POINT(ctypes.Structure):
        _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]

    class NOTIFYICONDATAW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("hWnd", wintypes.HWND),
            ("uID", wintypes.UINT),
            ("uFlags", wintypes.UINT),
            ("uCallbackMessage", wintypes.UINT),
            ("hIcon", wintypes.HICON),
            ("szTip", wintypes.WCHAR * 128),
            ("dwState", wintypes.DWORD),
            ("dwStateMask", wintypes.DWORD),
            ("szInfo", wintypes.WCHAR * 256),
            ("uTimeoutOrVersion", wintypes.UINT),
            ("szInfoTitle", wintypes.WCHAR * 64),
            ("dwInfoFlags", wintypes.DWORD),
            ("guidItem", ctypes.c_byte * 16),
            ("hBalloonIcon", wintypes.HICON),
        ]

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

        @classmethod
        def from_str(cls, text: str) -> "GUID":
            g = cls()
            ole32 = ctypes.WinDLL("ole32", use_last_error=True)
            ole32.CLSIDFromString.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(GUID)]
            ole32.CLSIDFromString.restype = ctypes.c_long
            if ole32.CLSIDFromString(text, ctypes.byref(g)) != 0:
                raise ValueError(f"Invalid GUID: {text}")
            return g

    class PROPERTYKEY(ctypes.Structure):
        _fields_ = [("fmtid", GUID), ("pid", wintypes.DWORD)]

    class PROPVARIANT(ctypes.Structure):
        _fields_ = [
            ("vt", wintypes.USHORT),
            ("wReserved1", wintypes.USHORT),
            ("wReserved2", wintypes.USHORT),
            ("wReserved3", wintypes.USHORT),
            ("pwszVal", wintypes.LPWSTR),
            ("pad", ctypes.c_void_p),
        ]


def enable_high_dpi() -> None:
    if IS_WIN32:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass


def set_app_user_model_id(app_id: str) -> bool:
    """Bind process to an explicit Windows AppUserModelID before Tk initializes."""
    if not IS_WIN32 or not app_id:
        return False
    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell32.SetCurrentProcessExplicitAppUserModelID.argtypes = [wintypes.LPCWSTR]
        shell32.SetCurrentProcessExplicitAppUserModelID.restype = ctypes.c_long
        return shell32.SetCurrentProcessExplicitAppUserModelID(app_id) == 0
    except Exception:
        return False


def get_start_menu_programs_dir() -> Optional[Path]:
    """Resolve current user's Start Menu Programs folder via Win32 SHGetFolderPathW."""
    if not IS_WIN32:
        return None
    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell32.SHGetFolderPathW.argtypes = [
            wintypes.HWND,
            ctypes.c_int,
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
        ]
        shell32.SHGetFolderPathW.restype = ctypes.c_long
        buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        if shell32.SHGetFolderPathW(None, CSIDL_PROGRAMS, None, 0, buf) == 0 and buf.value:
            return Path(buf.value)
    except Exception:
        pass
    return None


def _com_vtbl_call(ptr: ctypes.c_void_p, index: int, restype: object, *argtypes: object) -> Callable[..., int]:
    vtbl = ctypes.cast(ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    fn_type = ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)  # type: ignore[arg-type]
    return fn_type(vtbl[index])


def install_start_menu_shortcut(
    shortcut_name: str,
    arguments: str,
    working_dir: Path | str,
    icon_path: Optional[Path | str],
    app_id: str,
    description: str = "",
    target_dir: Optional[Path | str] = None,
    target_exe: Optional[Path | str] = None,
) -> dict[str, object]:
    """
    Create a Windows Start Menu .lnk stamped with PKEY_AppUserModel_ID via pure ctypes COM
    (IShellLinkW + IPropertyStore + IPersistFile) so Taskbar & Start pinning work natively.
    """
    if not IS_WIN32:
        return {"ok": False, "path": "", "message": "Start Menu shortcuts require Windows."}

    dest_dir = Path(target_dir) if target_dir else get_start_menu_programs_dir()
    if dest_dir is None:
        return {"ok": False, "path": "", "message": "Cannot resolve Start Menu Programs folder."}
    dest_dir.mkdir(parents=True, exist_ok=True)

    fname = shortcut_name if shortcut_name.lower().endswith(".lnk") else f"{shortcut_name}.lnk"
    lnk_path = dest_dir / fname

    if target_exe:
        exe_str = str(target_exe)
    else:
        py_path = Path(sys.executable)
        pyw_path = py_path.with_name("pythonw.exe")
        exe_str = str(pyw_path if pyw_path.is_file() else py_path)

    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    ole32.CoInitialize.argtypes = [wintypes.LPVOID]
    ole32.CoInitialize.restype = ctypes.c_long
    ole32.CoUninitialize.argtypes = []
    ole32.CoUninitialize.restype = None
    ole32.CoCreateInstance.argtypes = [
        ctypes.POINTER(GUID),
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(GUID),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    ole32.CoCreateInstance.restype = ctypes.c_long

    clsid_shell_link = GUID.from_str("{00021401-0000-0000-C000-000000000046}")
    iid_shell_link_w = GUID.from_str("{000214F9-0000-0000-C000-000000000046}")
    iid_persist_file = GUID.from_str("{0000010B-0000-0000-C000-000000000046}")
    iid_prop_store = GUID.from_str("{886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99}")
    pkey_appid = PROPERTYKEY(GUID.from_str("{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}"), 5)

    hr_init = ole32.CoInitialize(None)
    need_uninit = hr_init in (0, 1)
    sl = ctypes.c_void_p()
    ps = ctypes.c_void_p()
    pf = ctypes.c_void_p()
    try:
        hr = ole32.CoCreateInstance(
            ctypes.byref(clsid_shell_link),
            None,
            1,  # CLSCTX_INPROC_SERVER
            ctypes.byref(iid_shell_link_w),
            ctypes.byref(sl),
        )
        if hr != 0 or not sl.value:
            return {"ok": False, "path": str(lnk_path), "message": f"CoCreateInstance failed: 0x{hr & 0xFFFFFFFF:08X}"}

        # IShellLinkW vtable: 0=QI, 2=Release, 7=SetDescription, 9=SetWorkingDirectory, 11=SetArguments, 17=SetIconLocation, 20=SetPath
        if _com_vtbl_call(sl, 20, ctypes.c_long, wintypes.LPCWSTR)(sl, exe_str) != 0:
            return {"ok": False, "path": str(lnk_path), "message": "IShellLinkW::SetPath failed."}
        if arguments:
            _com_vtbl_call(sl, 11, ctypes.c_long, wintypes.LPCWSTR)(sl, arguments)
        if working_dir:
            _com_vtbl_call(sl, 9, ctypes.c_long, wintypes.LPCWSTR)(sl, str(working_dir))
        if description:
            _com_vtbl_call(sl, 7, ctypes.c_long, wintypes.LPCWSTR)(sl, description[:255])
        if icon_path and Path(icon_path).is_file():
            _com_vtbl_call(sl, 17, ctypes.c_long, wintypes.LPCWSTR, ctypes.c_int)(sl, str(icon_path), 0)

        if app_id:
            hr_qi = _com_vtbl_call(
                sl, 0, ctypes.c_long, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)
            )(sl, ctypes.byref(iid_prop_store), ctypes.byref(ps))
            if hr_qi == 0 and ps.value:
                pv = PROPVARIANT()
                pv.vt = VT_LPWSTR
                app_buf = ctypes.create_unicode_buffer(app_id)
                pv.pwszVal = ctypes.cast(app_buf, wintypes.LPWSTR)
                _com_vtbl_call(ps, 6, ctypes.c_long, ctypes.POINTER(PROPERTYKEY), ctypes.POINTER(PROPVARIANT))(
                    ps, ctypes.byref(pkey_appid), ctypes.byref(pv)
                )
                _com_vtbl_call(ps, 7, ctypes.c_long)(ps)

        hr_pf = _com_vtbl_call(
            sl, 0, ctypes.c_long, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)
        )(sl, ctypes.byref(iid_persist_file), ctypes.byref(pf))
        if hr_pf != 0 or not pf.value:
            return {"ok": False, "path": str(lnk_path), "message": "QueryInterface(IPersistFile) failed."}

        hr_save = _com_vtbl_call(pf, 6, ctypes.c_long, wintypes.LPCWSTR, wintypes.BOOL)(pf, str(lnk_path), True)
        if hr_save != 0:
            return {"ok": False, "path": str(lnk_path), "message": f"IPersistFile::Save failed: 0x{hr_save & 0xFFFFFFFF:08X}"}
    finally:
        if pf.value:
            _com_vtbl_call(pf, 2, wintypes.ULONG)(pf)
        if ps.value:
            _com_vtbl_call(ps, 2, wintypes.ULONG)(ps)
        if sl.value:
            _com_vtbl_call(sl, 2, wintypes.ULONG)(sl)
        if need_uninit:
            ole32.CoUninitialize()

    if target_dir is None:
        try:
            shell32 = ctypes.WinDLL("shell32", use_last_error=True)
            shell32.SHChangeNotify.argtypes = [wintypes.LONG, wintypes.UINT, wintypes.LPCVOID, wintypes.LPCVOID]
            shell32.SHChangeNotify.restype = None
            shell32.SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)
        except Exception:
            pass

    return {"ok": True, "path": str(lnk_path), "message": f"Start Menu shortcut registered: {lnk_path}"}


def remove_start_menu_shortcut(shortcut_name: str, target_dir: Optional[Path | str] = None) -> dict[str, object]:
    if not IS_WIN32:
        return {"ok": False, "path": "", "message": "Start Menu shortcuts require Windows."}
    dest_dir = Path(target_dir) if target_dir else get_start_menu_programs_dir()
    if dest_dir is None:
        return {"ok": False, "path": "", "message": "Cannot resolve Start Menu Programs folder."}
    fname = shortcut_name if shortcut_name.lower().endswith(".lnk") else f"{shortcut_name}.lnk"
    lnk_path = dest_dir / fname
    removed = False
    if lnk_path.is_file():
        lnk_path.unlink(missing_ok=True)
        removed = True
    return {
        "ok": True,
        "removed": removed,
        "path": str(lnk_path),
        "message": f"Removed shortcut: {lnk_path}" if removed else f"Shortcut not present: {lnk_path}",
    }


def apply_tk_window_icon(root: object, ico_path: Optional[Path | str]) -> bool:
    """Apply multi-size .ico to a Tkinter root window cleanly without crashing if absent."""
    if not ico_path:
        return False
    p = Path(ico_path)
    if not p.is_file():
        return False
    try:
        if IS_WIN32:
            root.iconbitmap(default=str(p))  # type: ignore[attr-defined]
            return True
    except Exception:
        pass
    return False


def bring_tk_window_to_front(root: object) -> None:
    """Restore a withdrawn or minimized Tk window and bring it to foreground on Windows."""
    try:
        root.deiconify()  # type: ignore[attr-defined]
        root.state("normal")  # type: ignore[attr-defined]
        root.lift()  # type: ignore[attr-defined]
        root.focus_force()  # type: ignore[attr-defined]
    except Exception:
        pass
    if not IS_WIN32:
        return
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.GetParent.argtypes = [wintypes.HWND]
        user32.GetParent.restype = wintypes.HWND
        user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.ShowWindow.restype = wintypes.BOOL
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.SetForegroundWindow.restype = wintypes.BOOL

        wid = int(root.winfo_id())  # type: ignore[attr-defined]
        hwnd = user32.GetParent(wid) or wid
        if hwnd:
            user32.ShowWindow(hwnd, SW_RESTORE)
            user32.SetForegroundWindow(hwnd)
    except Exception:
        pass


def signal_existing_instance(tray_class_name: str, fallback_window_title: str = "") -> bool:
    """
    If another instance is already running (even withdrawn to system tray), grant it
    foreground activation permission and signal it to restore its main window.
    """
    if not IS_WIN32:
        return False
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        user32.FindWindowW.restype = wintypes.HWND
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        user32.AllowSetForegroundWindow.argtypes = [wintypes.DWORD]
        user32.AllowSetForegroundWindow.restype = wintypes.BOOL
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.PostMessageW.restype = wintypes.BOOL
        user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.ShowWindow.restype = wintypes.BOOL
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.SetForegroundWindow.restype = wintypes.BOOL

        hwnd_tray = user32.FindWindowW(tray_class_name, None) if tray_class_name else 0
        if hwnd_tray:
            pid = wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd_tray, ctypes.byref(pid))
            if pid.value:
                user32.AllowSetForegroundWindow(pid.value)
            user32.PostMessageW(hwnd_tray, WM_APP_SHOW_PANEL, 0, 0)
            return True

        if fallback_window_title:
            hwnd_win = user32.FindWindowW(None, fallback_window_title)
            if hwnd_win:
                user32.ShowWindow(hwnd_win, SW_RESTORE)
                user32.SetForegroundWindow(hwnd_win)
                return True
    except Exception:
        pass
    return False


class Win32TrayController:
    """
    Zero-polling Win32 system tray icon running on a dedicated message-loop daemon thread.
    Dispatches all UI callbacks via `dispatch_ui` so Tk is only touched on its main thread.
    """

    def __init__(
        self,
        class_name: str,
        tooltip: str,
        ico_path: Optional[Path | str],
        on_open: Callable[[], None],
        menu_builder: Callable[[], Sequence[MenuSpec]],
        dispatch_ui: Callable[[Callable[[], None]], None],
    ) -> None:
        self.class_name = class_name
        self._tooltip = (tooltip or "")[:127]
        self.ico_path = str(ico_path) if ico_path and Path(ico_path).is_file() else ""
        self.on_open = on_open
        self.menu_builder = menu_builder
        self.dispatch_ui = dispatch_ui

        self._hwnd: int = 0
        self._hicon: int = 0
        self._owns_icon = False
        self._started = threading.Event()
        self._active = False
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._wndproc_ref: Optional[object] = None
        self._msg_taskbar_created: int = 0

    @property
    def active(self) -> bool:
        return self._active or self.ensure_registered()

    def ensure_registered(self) -> bool:
        if not IS_WIN32:
            return False
        if self._active:
            return True
        with self._lock:
            hwnd = self._hwnd
        if not hwnd:
            return False
        try:
            shell32 = ctypes.WinDLL("shell32", use_last_error=True)
            shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
            shell32.Shell_NotifyIconW.restype = wintypes.BOOL
            nid = self._make_nid(NIF_MESSAGE | NIF_ICON | NIF_TIP)
            ok = bool(shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)))
            if ok:
                self._active = True
            return ok
        except Exception:
            return False

    def start(self, timeout: float = 2.0) -> bool:
        if not IS_WIN32:
            return False
        if self._thread is not None and self._thread.is_alive():
            return self._active
        self._started.clear()
        self._thread = threading.Thread(target=self._thread_main, name=f"Tray-{self.class_name}", daemon=True)
        self._thread.start()
        self._started.wait(timeout=timeout)
        return self._active

    def update_tooltip(self, tooltip: str) -> None:
        if not IS_WIN32:
            return
        with self._lock:
            self._tooltip = (tooltip or "")[:127]
            hwnd = self._hwnd
        if not hwnd or not self._active:
            return
        try:
            shell32 = ctypes.WinDLL("shell32", use_last_error=True)
            shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
            shell32.Shell_NotifyIconW.restype = wintypes.BOOL
            nid = self._make_nid(NIF_TIP)
            shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
        except Exception:
            pass

    def notify_balloon(self, title: str, message: str) -> None:
        if not IS_WIN32 or not self._active or not self._hwnd:
            return
        try:
            shell32 = ctypes.WinDLL("shell32", use_last_error=True)
            shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
            shell32.Shell_NotifyIconW.restype = wintypes.BOOL
            nid = self._make_nid(NIF_INFO)
            nid.szInfoTitle = (title or "")[:63]
            nid.szInfo = (message or "")[:255]
            nid.dwInfoFlags = NIIF_INFO | NIIF_NOSOUND
            shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
        except Exception:
            pass

    def stop(self) -> None:
        if not IS_WIN32:
            return
        with self._lock:
            hwnd = self._hwnd
        if hwnd:
            try:
                user32 = ctypes.WinDLL("user32", use_last_error=True)
                user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
                user32.PostMessageW.restype = wintypes.BOOL
                user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            except Exception:
                pass
        if self._thread is not None and self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._thread.join(timeout=1.5)

    def _make_nid(self, flags: int) -> "NOTIFYICONDATAW":
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self._hwnd
        nid.uID = 1
        nid.uFlags = flags
        nid.uCallbackMessage = WM_TRAY_CALLBACK
        nid.hIcon = self._hicon
        nid.szTip = self._tooltip
        return nid

    def _thread_main(self) -> None:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)

        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
        user32.RegisterWindowMessageW.restype = wintypes.UINT
        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.DefWindowProcW.restype = ctypes.c_ssize_t
        user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        user32.RegisterClassW.restype = wintypes.ATOM
        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
        ]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.DestroyWindow.restype = wintypes.BOOL
        user32.PostQuitMessage.argtypes = [ctypes.c_int]
        user32.PostQuitMessage.restype = None
        user32.GetSystemMetrics.argtypes = [ctypes.c_int]
        user32.GetSystemMetrics.restype = ctypes.c_int
        user32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.UINT]
        user32.LoadImageW.restype = wintypes.HANDLE
        user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
        user32.LoadIconW.restype = wintypes.HICON
        user32.DestroyIcon.argtypes = [wintypes.HICON]
        user32.DestroyIcon.restype = wintypes.BOOL
        user32.CreatePopupMenu.argtypes = []
        user32.CreatePopupMenu.restype = wintypes.HMENU
        user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
        user32.AppendMenuW.restype = wintypes.BOOL
        user32.SetMenuDefaultItem.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.UINT]
        user32.SetMenuDefaultItem.restype = wintypes.BOOL
        user32.DestroyMenu.argtypes = [wintypes.HMENU]
        user32.DestroyMenu.restype = wintypes.BOOL
        user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
        user32.GetCursorPos.restype = wintypes.BOOL
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.SetForegroundWindow.restype = wintypes.BOOL
        user32.TrackPopupMenu.argtypes = [
            wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int,
            ctypes.c_int, wintypes.HWND, wintypes.LPVOID,
        ]
        user32.TrackPopupMenu.restype = wintypes.BOOL
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.PostMessageW.restype = wintypes.BOOL
        user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        user32.GetMessageW.restype = wintypes.BOOL
        user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.TranslateMessage.restype = wintypes.BOOL
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.DispatchMessageW.restype = ctypes.c_ssize_t

        shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
        shell32.Shell_NotifyIconW.restype = wintypes.BOOL

        self._msg_taskbar_created = int(user32.RegisterWindowMessageW("TaskbarCreated") or 0)
        hinst = kernel32.GetModuleHandleW(None)

        def _add_tray_icon() -> bool:
            nid = self._make_nid(NIF_MESSAGE | NIF_ICON | NIF_TIP)
            return bool(shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)))

        def _remove_tray_icon() -> None:
            if self._hwnd:
                nid = self._make_nid(0)
                shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))

        def _show_popup_menu(hwnd: int) -> None:
            items = list(self.menu_builder())
            hmenu = user32.CreatePopupMenu()
            if not hmenu:
                return
            callbacks: dict[int, Callable[[], None]] = {}
            try:
                cmd_id = 1001
                first_cmd = 0
                for spec in items:
                    if spec is None:
                        user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)
                    else:
                        label, cb = spec
                        user32.AppendMenuW(hmenu, MF_STRING, cmd_id, label)
                        callbacks[cmd_id] = cb
                        if first_cmd == 0:
                            first_cmd = cmd_id
                        cmd_id += 1
                if first_cmd:
                    user32.SetMenuDefaultItem(hmenu, first_cmd, 0)
                pt = POINT()
                user32.GetCursorPos(ctypes.byref(pt))
                user32.SetForegroundWindow(hwnd)
                chosen = int(
                    user32.TrackPopupMenu(
                        hmenu,
                        TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON | TPM_NONOTIFY | TPM_RETURNCMD,
                        pt.x,
                        pt.y,
                        0,
                        hwnd,
                        None,
                    )
                )
                user32.PostMessageW(hwnd, WM_NULL, 0, 0)
                if chosen in callbacks:
                    self.dispatch_ui(callbacks[chosen])
            finally:
                user32.DestroyMenu(hmenu)

        def _wnd_proc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
            if msg == WM_APP_SHOW_PANEL:
                self.dispatch_ui(self.on_open)
                return 0
            if self._msg_taskbar_created and msg == self._msg_taskbar_created:
                self._active = _add_tray_icon()
                return 0
            if msg == WM_TRAY_CALLBACK:
                ev = int(lparam) & 0xFFFF
                if ev in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                    self.dispatch_ui(self.on_open)
                    return 0
                if ev in (WM_RBUTTONUP, WM_CONTEXTMENU):
                    _show_popup_menu(hwnd)
                    return 0
            if msg == WM_CLOSE:
                _remove_tray_icon()
                user32.DestroyWindow(hwnd)
                return 0
            if msg == WM_DESTROY:
                _remove_tray_icon()
                user32.PostQuitMessage(0)
                return 0
            return int(user32.DefWindowProcW(hwnd, msg, wparam, lparam))

        self._wndproc_ref = WNDPROC(_wnd_proc)
        wc = WNDCLASSW()
        wc.lpfnWndProc = self._wndproc_ref  # type: ignore[assignment]
        wc.hInstance = hinst
        wc.lpszClassName = self.class_name
        user32.RegisterClassW(ctypes.byref(wc))

        hwnd = user32.CreateWindowExW(
            0,
            self.class_name,
            f"{self.class_name}_Host",
            0,
            0, 0, 0, 0,
            None,
            None,
            hinst,
            None,
        )
        if not hwnd:
            self._started.set()
            return

        hicon = 0
        if self.ico_path:
            cx = max(16, int(user32.GetSystemMetrics(SM_CXSMICON) or 16))
            cy = max(16, int(user32.GetSystemMetrics(SM_CYSMICON) or 16))
            hicon = int(user32.LoadImageW(None, self.ico_path, IMAGE_ICON, cx, cy, LR_LOADFROMFILE) or 0)
            if hicon:
                self._owns_icon = True
        if not hicon:
            hicon = int(user32.LoadIconW(None, ctypes.cast(IDI_APPLICATION, wintypes.LPCWSTR)) or 0)

        with self._lock:
            self._hwnd = int(hwnd)
            self._hicon = int(hicon)

        self._active = _add_tray_icon()
        self._started.set()

        msg = wintypes.MSG()
        while int(user32.GetMessageW(ctypes.byref(msg), None, 0, 0)) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        with self._lock:
            self._active = False
            self._hwnd = 0
        if self._owns_icon and hicon:
            user32.DestroyIcon(hicon)
            self._owns_icon = False
