# -*- coding: utf-8 -*-
"""
零信任远程算力网关 · 本地跨平台桌面控制台与离线视觉工作台 (kiss_shot/panel.py)
- 100% 运行于用户本机，所有密钥派生、提示词加密、参考图/局部重绘蒙版加密、队列封装与归档解密均在本地闭环完成。
- 静态凭据与本地作品画廊配方分别存于 .kissshot_secrets.json 与 .kissshot_gallery_vault.json（Windows DPAPI / POSIX 0600）。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import secrets
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")

from huggingface_hub import CommitOperationAdd, CommitOperationDelete, HfApi, hf_hub_download

from .clipboard import clear_clipboard_text, read_clipboard_text, write_clipboard_secret
from .crypto import (
    ARCH_PRESETS,
    DEFAULT_LOCAL_PORT,
    DEFAULT_MAILBOX_REPO_NAME,
    build_custom_llm_entry,
    build_custom_media_entry,
    encrypt_bytes_aes,
    encrypt_payload_hex,
    encrypt_queue_job,
    get_merged_llm_presets,
    get_merged_media_presets,
    load_encrypted_secrets,
    migrate_output_vault,
    parse_hf_repo_id,
    record_gallery_items,
    save_encrypted_secrets,
    unpack_encrypted_zip,
)
from .local_bridge import (
    bind_sillytavern_client,
    configure_local_bridge,
    default_secrets_path,
    query_local_bridge_status,
    start_local_bridge_background,
)
from .studio_widgets import (
    GallerySidebar,
    MaskPainterDialog,
    MossLayoutDialog,
    open_path_cross_platform,
)
from .win_tray import (
    MenuSpec,
    Win32TrayController,
    apply_tk_window_icon,
    bring_tk_window_to_front,
    enable_high_dpi,
    set_app_user_model_id,
    signal_existing_instance,
)

APP_USER_MODEL_ID = "Trinity.KissShot.Panel"
TRAY_CLASS_NAME = "KissShotTrayHost_v1"
PANEL_WINDOW_TITLE = "Kiss-Shot · 零信任端到端加密推理与密文工作台"


def _get_icon_path() -> Path:
    return Path(__file__).resolve().parent.parent / "assets" / "app.ico"


def _resolve_default_work_dir(explicit_dir: Optional[str]) -> str:
    if explicit_dir:
        return os.path.abspath(explicit_dir)
    cwd = os.path.abspath(os.getcwd())
    if os.path.isfile(default_secrets_path(cwd)):
        return cwd
    repo_root = Path(__file__).resolve().parent.parent
    if (repo_root / "pyproject.toml").is_file():
        return str(repo_root)
    return cwd


def _open_directory_cross_platform(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    open_path_cross_platform(path)


def load_secrets(work_dir: str) -> Dict[str, Any]:
    default_out = os.path.join(work_dir, "outputs")
    return load_encrypted_secrets(
        default_secrets_path(work_dir),
        defaults={
            "passphrase": "",
            "hf_user": "",
            "hf_token": "",
            "mailbox_suffix": DEFAULT_MAILBOX_REPO_NAME,
            "client_dir": "",
            "output_dir": default_out,
            "custom_models": [],
            "custom_llms": [],
        },
    )


def save_secrets(work_dir: str, data: Dict[str, Any]) -> None:
    save_encrypted_secrets(default_secrets_path(work_dir), data)


class ZeroTrustBridgeApp(tk.Tk):
    def __init__(
        self,
        work_dir: str | None = None,
        port: int = DEFAULT_LOCAL_PORT,
        start_minimized: bool = False,
        enable_tray: bool = True,
    ) -> None:
        enable_high_dpi()
        set_app_user_model_id(APP_USER_MODEL_ID)
        super().__init__()
        self.work_dir = _resolve_default_work_dir(work_dir)
        self.port = port
        self.default_output_dir = os.path.join(self.work_dir, "outputs")
        self._clip_timer_id: str | None = None
        self._closing = False
        self._hidden_to_tray = False
        self._tray_hint_shown = False
        self._ui_queue: queue.SimpleQueue[Callable[[], None]] = queue.SimpleQueue()
        self._tray: Optional[Win32TrayController] = None
        self._inpaint_mask_png: Optional[bytes] = None
        self._auto_watch_active = False
        self._pull_lock = threading.Lock()
        self._ensured_repos: Set[str] = set()

        self.cfg = load_secrets(self.work_dir)
        raw_out = str(self.cfg.get("output_dir") or "").strip()
        self.output_dir = os.path.abspath(raw_out) if raw_out else self.default_output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        self.title(PANEL_WINDOW_TITLE)
        apply_tk_window_icon(self, _get_icon_path())
        self.geometry("1220x825")
        self.minsize(1020, 720)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.llm_catalog = get_merged_llm_presets(self.cfg.get("custom_llms"))
        self.llm_keys: List[str] = list(self.llm_catalog.keys())
        self.llm_labels: List[str] = [self.llm_catalog[k]["label"] for k in self.llm_keys]

        self.media_catalog = get_merged_media_presets(self.cfg.get("custom_models"))
        self.media_keys: List[str] = list(self.media_catalog.keys())
        self.media_labels: List[str] = [self.media_catalog[k]["label"] for k in self.media_keys]

        self._build_ui()
        self._apply_media_defaults(0)

        if enable_tray and sys.platform == "win32":
            self._tray = Win32TrayController(
                class_name=TRAY_CLASS_NAME,
                tooltip=f"Kiss-Shot · 本地加密网桥 127.0.0.1:{self.port}/v1",
                ico_path=_get_icon_path(),
                on_open=self.restore_from_tray,
                menu_builder=self._build_tray_menu,
                dispatch_ui=self._ui_call,
            )
            self._tray.start()

        start_local_bridge_background(
            port=self.port,
            work_dir=self.work_dir,
            watch_clipboard=True,
            on_status_change=lambda st: self._ui_call(lambda s=st: self._refresh_bridge_ui(s)),
        )
        self.after(50, self._pump_ui_queue)
        if start_minimized and self._tray is not None and self._tray.active:
            self.hide_to_tray(notify=False)
        else:
            self.after(600, self._poll_bridge_status)

    def _ui_call(self, cb: Callable[[], None]) -> None:
        if self._closing:
            return
        self._ui_queue.put(cb)

    def _pump_ui_queue(self) -> None:
        if self._closing:
            return
        for _ in range(128):
            try:
                cb = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                cb()
            except Exception:
                pass
        try:
            delay_ms = 400 if self._hidden_to_tray else 50
            self.after(delay_ms, self._pump_ui_queue)
        except Exception:
            pass

    def _copy_bridge_endpoint(self) -> None:
        url = f"http://127.0.0.1:{self.port}/v1"
        try:
            self.clipboard_clear()
            self.clipboard_append(url)
            self.status_var.set(f"✅ 已复制本地加密网桥端点：{url}")
        except Exception:
            pass

    def _build_tray_menu(self) -> List[MenuSpec]:
        return [
            ("✦ 打开控制台 (Kiss-Shot)", self.restore_from_tray),
            None,
            (f"📋 复制本地网桥地址 (127.0.0.1:{self.port}/v1)", self._copy_bridge_endpoint),
            ("📥 检查并拉取密文信箱 (阅后即焚)", lambda: self._pull_and_burn_inbox(silent_empty=False, auto_mode=False)),
            ("🧹 立即擦除剪贴板密钥", self._manual_scrub_clipboard),
            ("📁 打开本地解密产物目录", lambda: _open_directory_cross_platform(self.output_dir)),
            None,
            ("✕ 彻底退出 (关闭加密网桥)", self.exit_app),
        ]

    def hide_to_tray(self, notify: bool = True) -> None:
        if self._closing:
            return
        if self._tray is None or not self._tray.active:
            self.exit_app()
            return
        self._hidden_to_tray = True
        try:
            self.withdraw()
        except Exception:
            pass
        if notify and not self._tray_hint_shown:
            self._tray_hint_shown = True
            self._tray.notify_balloon(
                "Kiss-Shot 已驻留托盘",
                f"本地加密网桥 (127.0.0.1:{self.port}/v1) 与密文队列监听持续保活中。单击图标唤醒，右键可彻底退出。",
            )

    def restore_from_tray(self) -> None:
        if self._closing:
            return
        was_hidden = self._hidden_to_tray
        self._hidden_to_tray = False
        bring_tk_window_to_front(self)
        if was_hidden:
            self.after(100, self._poll_bridge_status)

    def exit_app(self) -> None:
        self._closing = True
        self._hidden_to_tray = False
        self._auto_watch_active = False
        if self._tray is not None:
            try:
                self._tray.stop()
            except Exception:
                pass
        try:
            self.destroy()
        except Exception:
            pass

    def _on_close(self) -> None:
        if self._tray is not None and self._tray.active:
            self.hide_to_tray(notify=True)
            return
        self.exit_app()

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        ui_font = "Microsoft YaHei UI" if sys.platform == "win32" else "Sans"
        style.configure("TButton", padding=5, font=(ui_font, 10))
        style.configure("Accent.TButton", padding=7, font=(ui_font, 10, "bold"))
        style.configure("TLabel", font=(ui_font, 10))
        style.configure("Header.TLabel", font=(ui_font, 11, "bold"))
        self._ui_font = ui_font

        top_bar = ttk.Frame(self, padding=(12, 8))
        top_bar.pack(fill=tk.X)
        self.status_var = tk.StringVar(
            value=f"就绪 · 本地 OpenAI 加密代理 http://127.0.0.1:{self.port}/v1 (PBKDF2 + AES-256-GCM AEAD)"
        )
        ttk.Label(top_bar, textvariable=self.status_var, foreground="#1a6b3c").pack(side=tk.LEFT)
        ttk.Button(top_bar, text="✕ 退出", command=self.exit_app).pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(
            top_bar,
            text="📁 打开本地解密产物目录",
            command=lambda: _open_directory_cross_platform(self.output_dir),
        ).pack(side=tk.RIGHT)
        ttk.Button(top_bar, text="🧹 擦除剪贴板", command=self._manual_scrub_clipboard).pack(
            side=tk.RIGHT, padx=(0, 8)
        )

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self.tab_llm = ttk.Frame(nb, padding=12)
        self.tab_media = ttk.Frame(nb, padding=12)
        self.tab_settings = ttk.Frame(nb, padding=12)

        nb.add(self.tab_llm, text=" 💬 1. 实时 OpenAI E2EE 流式推理网桥 ")
        nb.add(self.tab_media, text=" 🎨 2. 全自动密文队列与本地视觉工作台 ")
        nb.add(self.tab_settings, text=" 🔑 3. 本地零信任凭据与存储设置 ")

        self._build_llm_tab(ui_font)
        self._build_media_tab(ui_font)
        self._build_settings_tab()

    # -------------------- Tab 1: Streaming E2EE Bridge --------------------
    def _build_llm_tab(self, ui_font: str) -> None:
        f = self.tab_llm
        desc = (
            f"工作流：任意兼容 OpenAI 接口的本地客户端指向 http://127.0.0.1:{self.port}/v1 -> 本机 AEAD 逐帧加密 -> 远端动态随机路由。\n"
            "边缘反代与中转网络仅见高熵二进制流；流式 SSE 响应绑定递增序号 seq 与 EOF 认证标签，防窥探、防重放、防截断。"
        )
        ttk.Label(f, text=desc, foreground="#1a6b3c", justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 10))

        cfg_box = ttk.LabelFrame(f, text="1. 生成远端推理节点加密启动参数（可选：供 Notebook 模板解密拉取模型）", padding=10)
        cfg_box.pack(fill=tk.X, pady=(0, 10))

        r1 = ttk.Frame(cfg_box)
        r1.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(r1, text="模型预设：", style="Header.TLabel").pack(side=tk.LEFT)
        self.combo_llm = ttk.Combobox(r1, values=self.llm_labels, state="readonly", width=56, font=(ui_font, 10))
        self.combo_llm.current(0)
        self.combo_llm.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)
        self.combo_llm.bind("<<ComboboxSelected>>", lambda _e: self._apply_llm_defaults(self.combo_llm.current()))
        self.btn_del_llm = ttk.Button(
            r1, text="🗑️ 移除", command=self._delete_selected_custom_llm, state=tk.DISABLED
        )
        self.btn_del_llm.pack(side=tk.RIGHT)
        ttk.Button(
            r1,
            text="➕ 添加自定义 GGUF...",
            command=lambda: self._open_custom_repo_dialog(default_kind="llm"),
        ).pack(side=tk.RIGHT, padx=(0, 4))

        r2 = ttk.Frame(cfg_box)
        r2.pack(fill=tk.X)
        self.var_llm_ctx = tk.StringVar(value="16384")
        self.var_llm_img_tok = tk.StringVar(value="1280")
        self.var_custom_llm_repo = tk.StringVar(value="")

        ttk.Label(r2, text="上下文窗口:").pack(side=tk.LEFT)
        ttk.Combobox(
            r2,
            textvariable=self.var_llm_ctx,
            values=["8192", "16384", "32768", "65536"],
            state="readonly",
            width=8,
        ).pack(side=tk.LEFT, padx=(4, 14))

        ttk.Label(r2, text="视觉最大 Token:").pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self.var_llm_img_tok, width=7).pack(side=tk.LEFT, padx=(4, 14))

        ttk.Label(r2, text="临时单次覆盖 (可选 owner/repo/file.gguf):").pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self.var_custom_llm_repo, width=28).pack(
            side=tk.LEFT, padx=4, fill=tk.X, expand=True
        )

        btn_row = ttk.Frame(f)
        btn_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(
            btn_row,
            text="🔒 生成远端启动加密口令 KISSSHOT_LLM_HEX（自动复制）",
            style="Accent.TButton",
            command=self._generate_llm_hex,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Button(
            btn_row,
            text="🔗 一键写入可选本地客户端配置",
            command=self._bind_optional_client,
        ).pack(side=tk.LEFT)

        self.txt_llm_hex = scrolledtext.ScrolledText(f, height=4, font=("Consolas", 9), wrap=tk.CHAR)
        self.txt_llm_hex.pack(fill=tk.X, pady=(2, 10))

        bridge_box = ttk.LabelFrame(
            f,
            text="2. 握手票据绑定与隧道实时状态（复制远端输出的 KISSSHOT_TICKET:... 即自动秒连）",
            padding=10,
        )
        bridge_box.pack(fill=tk.BOTH, expand=True)

        self.var_bridge_status = tk.StringVar(
            value=f"🟡 本地网桥监听中 (http://127.0.0.1:{self.port}/v1) · 等待复制或粘贴 KISSSHOT_TICKET..."
        )
        ttk.Label(bridge_box, textvariable=self.var_bridge_status, style="Header.TLabel", foreground="#0b5cad").pack(
            anchor=tk.W, pady=(0, 8)
        )

        t_row = ttk.Frame(bridge_box)
        t_row.pack(fill=tk.X)
        self.var_ticket_input = tk.StringVar(value="")
        ttk.Entry(t_row, textvariable=self.var_ticket_input, font=("Consolas", 9)).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6)
        )
        ttk.Button(
            t_row,
            text="📋 粘贴票据并执行 AEAD 握手",
            style="Accent.TButton",
            command=self._paste_and_bind_ticket,
        ).pack(side=tk.LEFT)

    # -------------------- Tab 2: Automated Ciphertext Queue & Visual Studio --------------------
    def _build_media_tab(self, ui_font: str) -> None:
        outer = self.tab_media
        f = ttk.Frame(outer)
        f.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        self.gallery_sidebar = GallerySidebar(
            outer,
            output_dir=self.output_dir,
            on_restore_recipe=self._restore_gallery_recipe,
            on_send_to_img2img=self._load_image_for_img2img,
            on_send_to_i2v=self._load_image_for_i2v,
        )
        self.gallery_sidebar.pack(side=tk.RIGHT, fill=tk.Y)

        row_m = ttk.Frame(f)
        row_m.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(row_m, text="模型预设：", style="Header.TLabel").pack(side=tk.LEFT)
        self.combo_media = ttk.Combobox(row_m, values=self.media_labels, state="readonly", width=44, font=(ui_font, 10))
        self.combo_media.current(0)
        self.combo_media.pack(side=tk.LEFT, padx=6, fill=tk.X, expand=True)
        self.combo_media.bind("<<ComboboxSelected>>", lambda _e: self._apply_media_defaults(self.combo_media.current()))
        ttk.Button(row_m, text="重置提示词", command=self._fill_media_prompts).pack(side=tk.RIGHT)
        self.btn_del_media = ttk.Button(
            row_m, text="🗑️ 移除", command=self._delete_selected_custom_media, state=tk.DISABLED
        )
        self.btn_del_media.pack(side=tk.RIGHT, padx=(0, 4))
        ttk.Button(
            row_m,
            text="➕ 自定义 HF 模型...",
            command=lambda: self._open_custom_repo_dialog(default_kind="media"),
        ).pack(side=tk.RIGHT, padx=(0, 4))

        pos_hdr = ttk.Frame(f)
        pos_hdr.pack(fill=tk.X)
        ttk.Label(pos_hdr, text="正向提示词 (Prompt · 本地 AES-256-GCM 加密封装，支持 MOSS 空间构图 JSON):").pack(
            side=tk.LEFT
        )
        ttk.Button(pos_hdr, text="📐 MOSS 空间构图画板...", command=self._open_moss_layout_studio).pack(side=tk.RIGHT)

        self.txt_pos = scrolledtext.ScrolledText(f, height=4, font=("Consolas", 10), wrap=tk.WORD)
        self.txt_pos.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(f, text="反向提示词 (Negative Prompt):").pack(anchor=tk.W)
        self.txt_neg = scrolledtext.ScrolledText(f, height=2, font=("Consolas", 10), wrap=tk.WORD)
        self.txt_neg.pack(fill=tk.X, pady=(2, 6))

        p_box = ttk.LabelFrame(f, text="推理与后处理参数（切换模型自动匹配推荐值）", padding=6)
        p_box.pack(fill=tk.X, pady=(0, 6))

        self.var_w = tk.StringVar(value="1024")
        self.var_h = tk.StringVar(value="1344")
        self.var_steps = tk.StringVar(value="28")
        self.var_cfg = tk.StringVar(value="3.0")
        self.var_frames = tk.StringVar(value="1")
        self.var_batch = tk.StringVar(value="1")
        self.var_seed = tk.StringVar(value="-1")
        self.var_strength = tk.StringVar(value="0.65")
        self.var_upscale_2x = tk.BooleanVar(value=False)

        params = [
            ("宽(W):", self.var_w, 6),
            ("高(H):", self.var_h, 6),
            ("步数:", self.var_steps, 5),
            ("CFG:", self.var_cfg, 5),
            ("视频帧:", self.var_frames, 5),
            ("批次:", self.var_batch, 4),
            ("Seed(-1随机):", self.var_seed, 9),
        ]
        for idx, (lbl, var, w) in enumerate(params):
            ttk.Label(p_box, text=lbl).grid(row=0, column=idx * 2, sticky=tk.W, padx=(5 if idx else 0, 2))
            ttk.Entry(p_box, textvariable=var, width=w).grid(row=0, column=idx * 2 + 1, sticky=tk.W, padx=(0, 4))

        p_row2 = ttk.Frame(p_box)
        p_row2.grid(row=1, column=0, columnspan=14, sticky=tk.W, pady=(6, 0))
        ttk.Label(p_row2, text="重绘幅度 Strength (0.1~1.0，传入垫图时生效):").pack(side=tk.LEFT)
        ttk.Entry(p_row2, textvariable=self.var_strength, width=6).pack(side=tk.LEFT, padx=(4, 16))
        ttk.Checkbutton(
            p_row2,
            text="✨ 2x 超分高清放大（远端显存内分块 Real-ESRGAN 直出超清大图）",
            variable=self.var_upscale_2x,
        ).pack(side=tk.LEFT)

        ref_box = ttk.LabelFrame(
            f,
            text="参考图 / 垫图微调 (Img2Img) / 本地涂抹局部重绘 (Inpaint) / 图生视频首帧（AES-256-GCM 暂存阅后即焚）",
            padding=6,
        )
        ref_box.pack(fill=tk.X, pady=(0, 8))
        self.var_ref_img = tk.StringVar(value="")
        self.var_mask_badge = tk.StringVar(value="⚪ 未涂蒙版 (填底图即整图微调)")

        r_ref_top = ttk.Frame(ref_box)
        r_ref_top.pack(fill=tk.X)
        ttk.Entry(r_ref_top, textvariable=self.var_ref_img).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Button(r_ref_top, text="选择图片...", command=self._pick_ref_image).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(r_ref_top, text="🖌️ 涂抹局部重绘蒙版...", command=self._open_mask_painter).pack(
            side=tk.LEFT, padx=(0, 4)
        )
        ttk.Button(r_ref_top, text="清空", command=self._clear_ref_and_mask).pack(side=tk.LEFT)

        r_ref_bot = ttk.Frame(ref_box)
        r_ref_bot.pack(fill=tk.X, pady=(4, 0))
        ttk.Label(r_ref_bot, textvariable=self.var_mask_badge, foreground="#0b5cad").pack(side=tk.LEFT)

        # 全自动密文队列主控栏
        auto_row = ttk.Frame(f)
        auto_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(
            auto_row,
            text="🚀 一键加密入队 & 自动解密取回（双向密文队列模式）",
            style="Accent.TButton",
            command=self._submit_queue_and_autopull,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Button(
            auto_row,
            text="🛰️ 复制远端自动接单守护口令 (每场只需在 Cell 2 跑 1 次)",
            command=self._generate_daemon_hex,
        ).pack(side=tk.LEFT)

        # 手动单次兼容栏
        act_row = ttk.Frame(f)
        act_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(
            act_row,
            text="🔒 手动模式：生成单次 KISSSHOT_TASK_HEX 口令",
            command=self._generate_media_task,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Button(
            act_row,
            text="📥 立即扫描拉取密文信箱（阅后即焚）",
            command=lambda: self._pull_and_burn_inbox(silent_empty=False, auto_mode=False),
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0))

        sub_row = ttk.Frame(f)
        sub_row.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(sub_row, text="密文口令输出区（守护口令或单次口令均可粘贴至 remote_media_worker.ipynb Cell 2）：").pack(
            side=tk.LEFT
        )
        ttk.Button(sub_row, text="📂 手动解密本地归档 (.zip/.bin)...", command=self._decrypt_local_archive).pack(
            side=tk.RIGHT
        )

        self.txt_media_hex = scrolledtext.ScrolledText(f, height=3, font=("Consolas", 9), wrap=tk.CHAR)
        self.txt_media_hex.pack(fill=tk.BOTH, expand=True)

    # -------------------- Tab 3: Credentials & Storage --------------------
    def _build_settings_tab(self) -> None:
        f = self.tab_settings
        box = ttk.LabelFrame(
            f,
            text="本地零信任凭据与解密存储（保存在工作区 .kissshot_secrets.json，Windows DPAPI / POSIX 0600 保护）",
            padding=14,
        )
        box.pack(fill=tk.X, pady=(0, 12))

        self.var_pwd = tk.StringVar(value=self.cfg.get("passphrase", ""))
        self.var_hf_token = tk.StringVar(value=self.cfg.get("hf_token", ""))
        self.var_hf_user = tk.StringVar(value=self.cfg.get("hf_user", ""))
        self.var_mailbox_suffix = tk.StringVar(value=self.cfg.get("mailbox_suffix", DEFAULT_MAILBOX_REPO_NAME))
        self.var_client_dir = tk.StringVar(value=self.cfg.get("client_dir", ""))
        self.var_output_dir = tk.StringVar(value=self.output_dir)

        ttk.Label(box, text="1. 主加密口令 (Passphrase · 必填):").grid(row=0, column=0, sticky=tk.W, pady=6)
        ttk.Entry(box, textvariable=self.var_pwd, show="*", width=44).grid(row=0, column=1, sticky=tk.W, padx=8)
        ttk.Button(box, text="🎲 生成高熵口令", command=self._gen_random_pwd).grid(row=0, column=2, padx=4)
        ttk.Button(box, text="📋 复制口令(90s自毁)", command=self._copy_pwd_ephemeral).grid(row=0, column=3, padx=4)

        ttk.Label(box, text="2. HuggingFace Write Token (用于密文信箱):").grid(row=1, column=0, sticky=tk.W, pady=6)
        ttk.Entry(box, textvariable=self.var_hf_token, show="*", width=44).grid(row=1, column=1, sticky=tk.W, padx=8)

        ttk.Label(box, text="3. HuggingFace 用户名 (验证时自动填入):").grid(row=2, column=0, sticky=tk.W, pady=6)
        ttk.Entry(box, textvariable=self.var_hf_user, width=44).grid(row=2, column=1, sticky=tk.W, padx=8)

        ttk.Label(box, text="4. 私有中转仓库名后缀 (可自定义隔离):").grid(row=3, column=0, sticky=tk.W, pady=6)
        ttk.Entry(box, textvariable=self.var_mailbox_suffix, width=44).grid(row=3, column=1, sticky=tk.W, padx=8)

        ttk.Label(box, text="5. 本地客户端目录 (可选，如 SillyTavern 根目录):").grid(row=4, column=0, sticky=tk.W, pady=6)
        ttk.Entry(box, textvariable=self.var_client_dir, width=44).grid(row=4, column=1, sticky=tk.W, padx=8)
        ttk.Button(box, text="浏览...", command=self._pick_client_dir).grid(row=4, column=2, padx=4)

        ttk.Label(box, text="6. 本地解密产物与加密画廊目录:").grid(row=5, column=0, sticky=tk.W, pady=6)
        ttk.Entry(box, textvariable=self.var_output_dir, width=44).grid(row=5, column=1, sticky=tk.W, padx=8)
        ttk.Button(box, text="选择目录...", command=self._pick_output_dir).grid(row=5, column=2, padx=4)
        ttk.Button(box, text="恢复默认", command=lambda: self.var_output_dir.set(self.default_output_dir)).grid(
            row=5, column=3, padx=4
        )

        btn_bar = ttk.Frame(f)
        btn_bar.pack(fill=tk.X, pady=6)
        ttk.Button(btn_bar, text="💾 保存配置到本机", style="Accent.TButton", command=self._save_settings).pack(
            side=tk.LEFT, padx=(0, 10)
        )
        ttk.Button(
            btn_bar,
            text="🔍 验证 HF Token 并初始化私有中转仓 (Private)",
            command=self._verify_and_init_hf,
        ).pack(side=tk.LEFT)

    # -------------------- Catalog & Custom Repo Probing --------------------
    def _reload_catalogs(
        self,
        select_media_key: Optional[str] = None,
        select_llm_key: Optional[str] = None,
    ) -> None:
        cur_m = select_media_key or (self.media_keys[self.combo_media.current()] if self.media_keys else "")
        cur_l = select_llm_key or (self.llm_keys[self.combo_llm.current()] if self.llm_keys else "")

        self.media_catalog = get_merged_media_presets(self.cfg.get("custom_models"))
        self.media_keys = list(self.media_catalog.keys())
        self.media_labels = [self.media_catalog[k]["label"] for k in self.media_keys]

        self.llm_catalog = get_merged_llm_presets(self.cfg.get("custom_llms"))
        self.llm_keys = list(self.llm_catalog.keys())
        self.llm_labels = [self.llm_catalog[k]["label"] for k in self.llm_keys]

        self.combo_media["values"] = self.media_labels
        m_idx = self.media_keys.index(cur_m) if cur_m in self.media_keys else 0
        self.combo_media.current(m_idx)
        self._apply_media_defaults(m_idx)

        self.combo_llm["values"] = self.llm_labels
        l_idx = self.llm_keys.index(cur_l) if cur_l in self.llm_keys else 0
        self.combo_llm.current(l_idx)
        self._apply_llm_defaults(l_idx)

    def _update_custom_buttons(self) -> None:
        if hasattr(self, "btn_del_media") and self.media_keys:
            mk = self.media_keys[self.combo_media.current()]
            is_cm = bool(self.media_catalog.get(mk, {}).get("is_custom"))
            self.btn_del_media.configure(state=(tk.NORMAL if is_cm else tk.DISABLED))
        if hasattr(self, "btn_del_llm") and self.llm_keys:
            lk = self.llm_keys[self.combo_llm.current()]
            is_cl = bool(self.llm_catalog.get(lk, {}).get("is_custom"))
            self.btn_del_llm.configure(state=(tk.NORMAL if is_cl else tk.DISABLED))

    def _apply_llm_defaults(self, idx: int) -> None:
        if 0 <= idx < len(self.llm_keys):
            spec = self.llm_catalog[self.llm_keys[idx]]
            self.var_llm_ctx.set(str(spec.get("default_ctx", 16384)))
            self.var_llm_img_tok.set(str(spec.get("default_img_tokens", 1280)))
        self._update_custom_buttons()

    def _apply_media_defaults(self, idx: int) -> None:
        key = self.media_keys[idx]
        m = self.media_catalog[key]
        self.var_w.set(str(m["default_width"]))
        self.var_h.set(str(m["default_height"]))
        self.var_steps.set(str(m["default_steps"]))
        self.var_cfg.set(str(m["default_cfg"]))
        self.var_frames.set(str(m["default_frames"]))
        self._update_custom_buttons()
        if not self.txt_pos.get("1.0", tk.END).strip():
            self._fill_media_prompts()

    def _fill_media_prompts(self) -> None:
        key = self.media_keys[self.combo_media.current()]
        m = self.media_catalog[key]
        self.txt_pos.delete("1.0", tk.END)
        self.txt_pos.insert("1.0", m["default_pos"])
        self.txt_neg.delete("1.0", tk.END)
        self.txt_neg.insert("1.0", m["default_neg"])

    def _probe_hf_repo_metadata(self, src_repo: str, hf_token: str = "") -> Dict[str, Any]:
        """自动探测 HuggingFace 仓库结构：识别 Diffusers _class_name 或 GGUF 权重列表"""
        pull_tok: bool | str = False
        try:
            files = list(HfApi(token=False).list_repo_files(repo_id=src_repo, repo_type="model"))
        except Exception:
            if not hf_token:
                raise
            pull_tok = hf_token
            files = list(HfApi(token=hf_token).list_repo_files(repo_id=src_repo, repo_type="model"))

        gguf_all = [f for f in files if f.lower().endswith(".gguf")]
        mmproj_files = [f for f in gguf_all if "mmproj" in f.lower()]
        weight_ggufs = [f for f in gguf_all if "mmproj" not in f.lower()]
        if weight_ggufs:
            return {
                "kind": "llm",
                "files_count": len(files),
                "weight_ggufs": weight_ggufs,
                "mmproj_files": mmproj_files,
                "arch": "gguf",
                "skip_root": False,
            }

        has_index = "model_index.json" in files
        sub_sf = any("/" in f and f.lower().endswith(".safetensors") for f in files)
        root_sf = any("/" not in f and f.lower().endswith(".safetensors") for f in files)
        detected_arch = "auto"
        class_name = ""
        if has_index:
            with tempfile.TemporaryDirectory() as td:
                idx_p = hf_hub_download(
                    repo_id=src_repo, filename="model_index.json", repo_type="model", local_dir=td, token=pull_tok
                )
                with open(idx_p, "r", encoding="utf-8") as f_idx:
                    idx_obj = json.load(f_idx)
                class_name = str(idx_obj.get("_class_name") or "")
            cls_low = class_name.lower()
            if "mossimage" in cls_low:
                detected_arch = "moss"
            elif "stablediffusionxl" in cls_low:
                detected_arch = "sdxl"
            elif "flux" in cls_low:
                detected_arch = "flux"
            elif "cogvideoximagetovideo" in cls_low:
                detected_arch = "cogvideox_i2v"
            elif "hunyuanvideo15" in cls_low:
                detected_arch = "hunyuan15_t2v"
            elif "wanimagetovideo" in cls_low:
                detected_arch = "wan_i2v"
            elif "wan" in cls_low:
                detected_arch = "wan_t2v"
            else:
                detected_arch = "auto"
        elif root_sf:
            detected_arch = "sdxl"

        return {
            "kind": "media",
            "files_count": len(files),
            "arch": detected_arch,
            "class_name": class_name,
            "skip_root": bool(has_index and sub_sf and root_sf),
        }

    def _open_custom_repo_dialog(self, default_kind: str = "media") -> None:
        dlg = tk.Toplevel(self)
        dlg.title("➕ 添加自定义 HuggingFace 模型预设")
        apply_tk_window_icon(dlg, _get_icon_path())
        dlg.geometry("660x430")
        dlg.transient(self)
        dlg.grab_set()

        pad = ttk.Frame(dlg, padding=14)
        pad.pack(fill=tk.BOTH, expand=True)

        var_kind = tk.StringVar(value=default_kind)
        var_repo = tk.StringVar(value="")
        var_note = tk.StringVar(value="")
        var_skip_root = tk.BooleanVar(value=False)
        var_gguf_w = tk.StringVar(value="")
        var_gguf_mm = tk.StringVar(value="")
        var_probe_msg = tk.StringVar(
            value="输入 HuggingFace 仓库（owner/repo 或完整 URL），点击「自动探测仓库」可自动识别管线架构与权重文件。"
        )

        r_top = ttk.Frame(pad)
        r_top.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(r_top, text="预设类型：", style="Header.TLabel").pack(side=tk.LEFT)

        r_repo = ttk.Frame(pad)
        r_repo.pack(fill=tk.X, pady=4)
        ttk.Label(r_repo, text="HuggingFace 仓库:").pack(side=tk.LEFT)
        ttk.Entry(r_repo, textvariable=var_repo, width=36, font=("Consolas", 10)).pack(
            side=tk.LEFT, padx=6, fill=tk.X, expand=True
        )

        r_note = ttk.Frame(pad)
        r_note.pack(fill=tk.X, pady=4)
        ttk.Label(r_note, text="显示备注名 (可选):").pack(side=tk.LEFT)
        ttk.Entry(r_note, textvariable=var_note, width=30).pack(side=tk.LEFT, padx=6)

        ttk.Label(pad, textvariable=var_probe_msg, foreground="#0b5cad", wraplength=620, justify=tk.LEFT).pack(
            anchor=tk.W, pady=(4, 8)
        )

        media_panel = ttk.LabelFrame(pad, text="Diffusers 图像 / 视频管线参数", padding=10)
        arch_keys = list(ARCH_PRESETS.keys())
        arch_labels = [f"{k} — {ARCH_PRESETS[k]['label']}" for k in arch_keys]
        ttk.Label(media_panel, text="管线架构:").grid(row=0, column=0, sticky=tk.W, pady=4)
        cb_arch = ttk.Combobox(media_panel, values=arch_labels, state="readonly", width=50)
        cb_arch.current(0)
        cb_arch.grid(row=0, column=1, sticky=tk.W, padx=6, pady=4)
        ttk.Checkbutton(
            media_panel,
            text="跳过根目录重复的单文件 .safetensors（同时含 Diffusers 子目录与根目录大单文件时勾选）",
            variable=var_skip_root,
        ).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=2)

        llm_panel = ttk.LabelFrame(pad, text="GGUF 语言 / 多模态模型文件", padding=10)
        ttk.Label(llm_panel, text="主权重文件 (.gguf):").grid(row=0, column=0, sticky=tk.W, pady=4)
        cb_gguf_w = ttk.Combobox(llm_panel, textvariable=var_gguf_w, width=48, font=("Consolas", 9))
        cb_gguf_w.grid(row=0, column=1, sticky=tk.W, padx=6, pady=4)
        ttk.Label(llm_panel, text="视觉投影 mmproj (可选):").grid(row=1, column=0, sticky=tk.W, pady=4)
        cb_gguf_mm = ttk.Combobox(llm_panel, textvariable=var_gguf_mm, width=48, font=("Consolas", 9))
        cb_gguf_mm.grid(row=1, column=1, sticky=tk.W, padx=6, pady=4)

        def _sync_kind_ui() -> None:
            if var_kind.get() == "llm":
                media_panel.pack_forget()
                llm_panel.pack(fill=tk.X, pady=(0, 10))
            else:
                llm_panel.pack_forget()
                media_panel.pack(fill=tk.X, pady=(0, 10))

        ttk.Radiobutton(
            r_top, text="🎨 图像 / 视频生成管线", variable=var_kind, value="media", command=_sync_kind_ui
        ).pack(side=tk.LEFT, padx=(6, 14))
        ttk.Radiobutton(
            r_top, text="💬 GGUF 语言 / 视觉推理模型", variable=var_kind, value="llm", command=_sync_kind_ui
        ).pack(side=tk.LEFT)

        def _do_probe() -> None:
            try:
                src_r = parse_hf_repo_id(var_repo.get())
            except ValueError as exc:
                messagebox.showerror("仓库格式有误", str(exc), parent=dlg)
                return
            var_probe_msg.set(f"🔍 正在读取 {src_r} 仓库结构...")

            def _w() -> None:
                try:
                    m = self._probe_hf_repo_metadata(src_r, self.var_hf_token.get().strip())
                    self._ui_call(lambda: _apply_probe(m))
                except Exception as exc:
                    self._ui_call(lambda err=str(exc): var_probe_msg.set(f"❌ 探测失败：{err[:100]}"))

            def _apply_probe(meta: Dict[str, Any]) -> None:
                if meta["kind"] == "llm":
                    var_kind.set("llm")
                    _sync_kind_ui()
                    w_list = meta["weight_ggufs"]
                    cb_gguf_w["values"] = w_list
                    cb_gguf_mm["values"] = [""] + meta["mmproj_files"]
                    q4 = [x for x in w_list if "q4_k_m" in x.lower()]
                    var_gguf_w.set(q4[0] if q4 else w_list[0])
                    var_gguf_mm.set(meta["mmproj_files"][0] if meta["mmproj_files"] else "")
                    var_probe_msg.set(f"✅ 已识别为 GGUF 仓库：发现 {len(w_list)} 个量化权重。")
                else:
                    var_kind.set("media")
                    _sync_kind_ui()
                    ak = meta["arch"] if meta["arch"] in arch_keys else "auto"
                    cb_arch.current(arch_keys.index(ak))
                    var_skip_root.set(bool(meta.get("skip_root", False)))
                    cls_tip = f" ({meta['class_name']})" if meta.get("class_name") else ""
                    var_probe_msg.set(f"✅ 探测完成：共 {meta['files_count']} 个文件，匹配架构 [{ak.upper()}]{cls_tip}")

            threading.Thread(target=_w, daemon=True).start()

        ttk.Button(r_repo, text="🔍 自动探测仓库", command=_do_probe).pack(side=tk.RIGHT)
        _sync_kind_ui()

        def _save_entry() -> None:
            try:
                src_r = parse_hf_repo_id(var_repo.get())
            except ValueError as exc:
                messagebox.showerror("输入有误", str(exc), parent=dlg)
                return

            if var_kind.get() == "llm":
                wf = var_gguf_w.get().strip()
                if not wf:
                    messagebox.showwarning("缺少文件名", "请填写或通过自动探测选择主权重 .gguf 文件名！", parent=dlg)
                    return
                rec_l = {
                    "src_repo": src_r,
                    "src_file": wf,
                    "mmproj_repo": src_r if var_gguf_mm.get().strip() else "",
                    "mmproj_file": var_gguf_mm.get().strip(),
                    "note": var_note.get().strip(),
                }
                key, _ = build_custom_llm_entry(rec_l)
                cur = [x for x in self.cfg.get("custom_llms", []) if build_custom_llm_entry(x)[0] != key]
                cur.append(rec_l)
                self.cfg["custom_llms"] = cur
                if self.var_pwd.get().strip():
                    self._save_settings(silent=True)
                self._reload_catalogs(select_llm_key=key)
                self.status_var.set(f"✅ 已保存自定义 GGUF 模型预设：{src_r}/{wf}")
            else:
                sel_arch = arch_keys[cb_arch.current()]
                rec_m = {
                    "src_repo": src_r,
                    "arch": sel_arch,
                    "skip_root_safetensors": bool(var_skip_root.get()),
                    "note": var_note.get().strip(),
                }
                key, _ = build_custom_media_entry(rec_m)
                cur_m = [x for x in self.cfg.get("custom_models", []) if build_custom_media_entry(x)[0] != key]
                cur_m.append(rec_m)
                self.cfg["custom_models"] = cur_m
                if self.var_pwd.get().strip():
                    self._save_settings(silent=True)
                self._reload_catalogs(select_media_key=key)
                self.status_var.set(f"✅ 已保存自定义模型预设：{src_r} ({sel_arch.upper()})")
            dlg.destroy()

        b_bar = ttk.Frame(pad)
        b_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(6, 0))
        ttk.Button(b_bar, text="取消", command=dlg.destroy).pack(side=tk.RIGHT)
        ttk.Button(b_bar, text="💾 保存至本地预设列表", style="Accent.TButton", command=_save_entry).pack(
            side=tk.RIGHT, padx=6
        )

    def _delete_selected_custom_media(self) -> None:
        mk = self.media_keys[self.combo_media.current()]
        info = self.media_catalog.get(mk, {})
        if not info.get("is_custom"):
            return
        if not messagebox.askyesno("移除自定义预设", f"确定移除自定义模型预设吗？\n{info['label']}"):
            return
        self.cfg["custom_models"] = [
            x for x in self.cfg.get("custom_models", []) if build_custom_media_entry(x)[0] != mk
        ]
        if self.var_pwd.get().strip():
            self._save_settings(silent=True)
        self._reload_catalogs()

    def _delete_selected_custom_llm(self) -> None:
        lk = self.llm_keys[self.combo_llm.current()]
        info = self.llm_catalog.get(lk, {})
        if not info.get("is_custom"):
            return
        if not messagebox.askyesno("移除自定义预设", f"确定移除自定义 GGUF 预设吗？\n{info['label']}"):
            return
        self.cfg["custom_llms"] = [
            x for x in self.cfg.get("custom_llms", []) if build_custom_llm_entry(x)[0] != lk
        ]
        if self.var_pwd.get().strip():
            self._save_settings(silent=True)
        self._reload_catalogs()

    # -------------------- Visual Studio Actions --------------------
    def _pick_ref_image(self) -> None:
        p = filedialog.askopenfilename(
            title="选择需要端到端加密上传的本地参考图像（垫图 / 局部重绘 / 视频首帧）",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.webp *.bmp"), ("All files", "*.*")],
        )
        if p:
            self.var_ref_img.set(p)
            self._inpaint_mask_png = None
            self.var_mask_badge.set("⚪ 未涂蒙版 (整图垫图微调 / 视频首帧)")

    def _clear_ref_and_mask(self) -> None:
        self.var_ref_img.set("")
        self._inpaint_mask_png = None
        self.var_mask_badge.set("⚪ 未涂蒙版 (填底图即整图微调)")

    def _open_mask_painter(self) -> None:
        ref_p = self.var_ref_img.get().strip()
        if not ref_p or not os.path.isfile(ref_p):
            self._pick_ref_image()
            ref_p = self.var_ref_img.get().strip()
        if not ref_p or not os.path.isfile(ref_p):
            return

        def _on_mask_saved(mask_bytes: Optional[bytes]) -> None:
            self._inpaint_mask_png = mask_bytes
            if mask_bytes:
                self.var_mask_badge.set("🟢 已启用局部重绘蒙版（仅重绘涂红区域并高斯羽化融合）")
                self.status_var.set("🖌️ 局部重绘蒙版已就绪，投递任务时将自动以 AES-256-GCM 加密上传")
            else:
                self.var_mask_badge.set("⚪ 未涂蒙版 (整图垫图微调)")

        MaskPainterDialog(
            self,
            image_path=ref_p,
            on_save=_on_mask_saved,
            initial_mask_png=self._inpaint_mask_png,
            ico_path=_get_icon_path(),
        )

    def _open_moss_layout_studio(self) -> None:
        try:
            cw = int(self.var_w.get())
            ch = int(self.var_h.get())
        except ValueError:
            cw, ch = 1024, 1344
        if "moss_image_sft" in self.media_keys and self.media_keys[self.combo_media.current()] != "moss_image_sft":
            idx_m = self.media_keys.index("moss_image_sft")
            self.combo_media.current(idx_m)
            self._apply_media_defaults(idx_m)

        def _on_compiled(json_prompt: str) -> None:
            self.txt_pos.delete("1.0", tk.END)
            self.txt_pos.insert("1.0", json_prompt)
            self.status_var.set("📐 已编译 MOSS-Image 空间构图 JSON 到正向提示词")

        MossLayoutDialog(
            self,
            canvas_w=cw,
            canvas_h=ch,
            initial_prompt=self.txt_pos.get("1.0", tk.END).strip(),
            on_compile=_on_compiled,
            ico_path=_get_icon_path(),
        )

    def _restore_gallery_recipe(self, meta: Dict[str, Any]) -> None:
        m_key = str(meta.get("model") or meta.get("preset") or "")
        if m_key in self.media_keys:
            idx = self.media_keys.index(m_key)
            self.combo_media.current(idx)
            self._update_custom_buttons()
        if "prompt" in meta:
            self.txt_pos.delete("1.0", tk.END)
            self.txt_pos.insert("1.0", str(meta["prompt"]))
        if "negative_prompt" in meta:
            self.txt_neg.delete("1.0", tk.END)
            self.txt_neg.insert("1.0", str(meta["negative_prompt"]))
        for k_meta, var in (
            ("width", self.var_w),
            ("height", self.var_h),
            ("steps", self.var_steps),
            ("cfg", self.var_cfg),
            ("frames", self.var_frames),
            ("seed", self.var_seed),
            ("strength", self.var_strength),
        ):
            if meta.get(k_meta) is not None:
                var.set(str(meta[k_meta]))
        if meta.get("upscale_2x") is not None:
            self.var_upscale_2x.set(bool(meta["upscale_2x"]))
        self.status_var.set(f"🔒 已复刻作品参数与随机种子 (Seed: {meta.get('seed')})")

    def _load_image_for_img2img(self, path: str) -> None:
        cur_k = self.media_keys[self.combo_media.current()]
        if self.media_catalog[cur_k]["category"].startswith("video"):
            self.combo_media.current(0)
            self._apply_media_defaults(0)
        self.var_ref_img.set(path)
        self._inpaint_mask_png = None
        self.var_mask_badge.set("⚪ 未涂蒙版 (整图垫图微调)")
        self.status_var.set(f"🖌️ 已载入垫图：{os.path.basename(path)}（可调节重绘幅度，或点击涂抹局部重绘蒙版）")

    def _load_image_for_i2v(self, path: str) -> None:
        cur_k = self.media_keys[self.combo_media.current()]
        if self.media_catalog[cur_k]["category"] not in ("video_i2v", "video_ti2v"):
            target_idx = 0
            for idx, k in enumerate(self.media_keys):
                if self.media_catalog[k]["category"] in ("video_i2v", "video_ti2v"):
                    target_idx = idx
                    break
            self.combo_media.current(target_idx)
            self._apply_media_defaults(target_idx)
        self.var_ref_img.set(path)
        self._inpaint_mask_png = None
        self.var_mask_badge.set("🎬 视频首帧图已就绪")
        self.status_var.set(f"🎬 已将 {os.path.basename(path)} 设为图生视频首帧")

    # -------------------- Clipboard & Settings --------------------
    def _copy_ephemeral_secret(self, text: str, ttl_ms: int = 90_000) -> None:
        if not text:
            return
        if not write_clipboard_secret(text):
            self.clipboard_clear()
            self.clipboard_append(text)
        if self._clip_timer_id is not None:
            try:
                self.after_cancel(self._clip_timer_id)
            except Exception:
                pass

        def _scrub_if_unchanged() -> None:
            self._clip_timer_id = None
            try:
                if read_clipboard_text().strip() == text.strip():
                    clear_clipboard_text()
            except Exception:
                pass

        self._clip_timer_id = self.after(ttl_ms, _scrub_if_unchanged)

    def _manual_scrub_clipboard(self) -> None:
        clear_clipboard_text()
        self.status_var.set("🧹 已清空系统剪贴板")

    def _copy_pwd_ephemeral(self) -> None:
        pwd = self.var_pwd.get().strip()
        if not pwd:
            messagebox.showwarning("口令为空", "请先填写或生成主加密口令！")
            return
        self._copy_ephemeral_secret(pwd)
        self.status_var.set("📋 主口令已复制（已标记防剪贴板历史/防云同步，90 秒后自动销毁）")

    def _gen_random_pwd(self) -> None:
        pwd = secrets.token_urlsafe(20)
        self.var_pwd.set(pwd)
        self._save_settings(silent=True)
        self._copy_ephemeral_secret(pwd)
        messagebox.showinfo("已生成高熵口令", "已生成 160-bit 高熵加密口令并加密保存至本机（已复制，90 秒后自动擦除剪贴板）。")

    def _pick_client_dir(self) -> None:
        d = filedialog.askdirectory(title="选择本地客户端根目录（可选）")
        if d:
            self.var_client_dir.set(d)

    def _pick_output_dir(self) -> None:
        d = filedialog.askdirectory(
            title="选择解密产物与本地加密画廊保存目录",
            initialdir=self.output_dir if os.path.isdir(self.output_dir) else self.work_dir,
        )
        if d:
            self.var_output_dir.set(os.path.abspath(d))

    def _save_settings(self, silent: bool = False) -> bool:
        pwd = self.var_pwd.get().strip()
        if not pwd:
            if not silent:
                messagebox.showwarning("缺少口令", "请先填写或生成主加密口令 (Passphrase)！")
            return False
        suffix = self.var_mailbox_suffix.get().strip() or DEFAULT_MAILBOX_REPO_NAME
        raw_out = self.var_output_dir.get().strip()
        new_out = os.path.abspath(raw_out) if raw_out else self.default_output_dir
        try:
            os.makedirs(new_out, exist_ok=True)
        except Exception as exc:
            if not silent:
                messagebox.showerror("目录无效", f"无法创建解密产物保存目录：\n{new_out}\n\n{exc}")
            return False

        prev_out = self.output_dir
        migrated = 0
        if os.path.normcase(prev_out) != os.path.normcase(new_out) and os.path.isdir(prev_out):
            if silent or messagebox.askyesno(
                "迁移历史产物与加密配方",
                f"检测到产物目录变更：\n原目录：{prev_out}\n新目录：{new_out}\n\n是否将原目录中的已解密文件及加密画廊配方一并无损迁入新目录？",
            ):
                migrated = migrate_output_vault(prev_out, new_out)

        self.output_dir = new_out
        self.var_output_dir.set(new_out)
        self.cfg = {
            "passphrase": pwd,
            "hf_user": self.var_hf_user.get().strip(),
            "hf_token": self.var_hf_token.get().strip(),
            "mailbox_suffix": suffix,
            "client_dir": self.var_client_dir.get().strip(),
            "output_dir": new_out,
            "custom_models": list(self.cfg.get("custom_models", [])),
            "custom_llms": list(self.cfg.get("custom_llms", [])),
        }
        save_secrets(self.work_dir, self.cfg)
        if hasattr(self, "gallery_sidebar"):
            self.gallery_sidebar.output_dir = new_out
            self.gallery_sidebar.refresh()
        if not silent:
            mig_note = f"（已无损迁移 {migrated} 个历史产物）" if migrated else ""
            self.status_var.set(f"✅ 本地零信任凭据与存储配置已保存{mig_note}")
            messagebox.showinfo("已保存", f"凭据已安全加密保存至本工作区 .kissshot_secrets.json{mig_note}。")
        return True

    def _verify_and_init_hf(self) -> None:
        token = self.var_hf_token.get().strip()
        if not token:
            messagebox.showwarning("缺少 Token", "请先填写具有 Write 权限的 HuggingFace Token。")
            return
        suffix = self.var_mailbox_suffix.get().strip() or DEFAULT_MAILBOX_REPO_NAME
        self.status_var.set("正在验证 HuggingFace 令牌并初始化私有中转仓库...")

        def worker() -> None:
            try:
                api = HfApi(token=token)
                who = api.whoami()
                username = who["name"]
                mailbox_repo = f"{username}/{suffix}"
                api.create_repo(repo_id=mailbox_repo, repo_type="model", private=True, exist_ok=True)
                self._ensured_repos.add(mailbox_repo)
                self.after(0, lambda: self._on_hf_ready(username, mailbox_repo))
            except Exception as exc:
                self.after(0, lambda err=str(exc): self._on_error("HF 验证失败", err))

        threading.Thread(target=worker, daemon=True).start()

    def _on_hf_ready(self, username: str, mailbox_repo: str) -> None:
        self.var_hf_user.set(username)
        self._save_settings(silent=True)
        self.status_var.set(f"✅ HF 验证通过：{username} | 私有信箱 {mailbox_repo} (Private) 已就绪")
        messagebox.showinfo("初始化完成", f"账号：{username}\n私有密文中转仓：{mailbox_repo}")

    # -------------------- Bridge & Queue Execution --------------------
    def _generate_llm_hex(self) -> None:
        if not self._save_settings(silent=True):
            messagebox.showwarning("未设置口令", "请先在第 3 页设置主加密口令！")
            return
        pwd = self.cfg["passphrase"]
        llm_key = self.llm_keys[self.combo_llm.current()]
        spec = self.llm_catalog[llm_key]
        custom = self.var_custom_llm_repo.get().strip()

        w_repo, w_file = spec["src_repo"], spec["src_file"]
        if custom and "/" in custom:
            parts = custom.split("/")
            if len(parts) >= 3:
                w_repo = "/".join(parts[:2])
                w_file = "/".join(parts[2:])

        try:
            ctx_size = int(self.var_llm_ctx.get())
            img_tokens = int(self.var_llm_img_tok.get())
        except ValueError as exc:
            messagebox.showerror("参数格式错误", str(exc))
            return

        use_tok = bool((custom and "/" in custom) or spec.get("is_custom"))
        payload = {
            "type": "kissshot_llm_serve",
            "preset_key": llm_key,
            "weight_repo": w_repo,
            "weight_file": w_file,
            "mmproj_repo": spec["mmproj_repo"],
            "mmproj_file": spec["mmproj_file"],
            "ctx_size": ctx_size,
            "img_tokens": img_tokens,
            # Least privilege: only attach HF token when pulling a user-specified custom repository
            "hf_token": self.cfg.get("hf_token", "") if use_tok else "",
        }
        hex_tok = encrypt_payload_hex(payload, pwd)
        self.txt_llm_hex.delete("1.0", tk.END)
        self.txt_llm_hex.insert("1.0", hex_tok)
        self._copy_ephemeral_secret(hex_tok)
        self.status_var.set("✅ 远端启动密文 KISSSHOT_LLM_HEX 已生成并复制（90 秒自动销毁剪贴板）")

    def _bind_optional_client(self) -> None:
        cdir = self.cfg.get("client_dir", "").strip() or self.var_client_dir.get().strip()
        if not cdir:
            messagebox.showinfo(
                "标准 OpenAI 接入说明",
                f"任何兼容 OpenAI 的客户端可直接配置：\n\n"
                f"Base URL: http://127.0.0.1:{self.port}/v1\n"
                f"API Key: 任意非空字符串（如 kissshot-local）\n\n"
                f"如需一键写入本地客户端目录，可在第 3 页配置目录路径。",
            )
            return
        cnt, live_ok = bind_sillytavern_client(Path(cdir), port=self.port)
        messagebox.showinfo(
            "客户端绑定结果",
            f"已更新配置文件数量: {cnt}\n在线热同步状态: {'成功' if live_ok else '离线（下次启动生效）'}",
        )

    def _paste_and_bind_ticket(self) -> None:
        if not self._save_settings(silent=True):
            return
        raw = self.var_ticket_input.get().strip()
        if not raw:
            try:
                raw = self.clipboard_get().strip()
                self.var_ticket_input.set(raw)
            except Exception:
                pass
        if not raw:
            messagebox.showwarning("票据为空", "请先复制远端网关输出的 KISSSHOT_TICKET:... 握手票据。")
            return

        self.status_var.set("正在与远端动态路由执行端到端 AES-256-GCM 双向认证握手...")

        def worker() -> None:
            ok, msg = configure_local_bridge(raw, self.cfg["passphrase"], port=self.port, work_dir=self.work_dir)
            st = query_local_bridge_status(self.port, work_dir=self.work_dir) or {}
            self.after(0, lambda: self._on_ticket_bound(ok, msg, st))

        threading.Thread(target=worker, daemon=True).start()

    def _on_ticket_bound(self, ok: bool, msg: str, st: Dict[str, Any]) -> None:
        self._refresh_bridge_ui(st)
        if ok:
            self.var_ticket_input.set("")
            clear_clipboard_text()
            self.status_var.set(f"✅ {msg}（已自动擦除剪贴板票据）")
            messagebox.showinfo(
                "握手成功",
                f"{msg}\n\n剪贴板票据已自动销毁。\n本地端点已就绪：http://127.0.0.1:{self.port}/v1",
            )
        else:
            self._on_error("握手未通过", msg)

    def _refresh_bridge_ui(self, st: Dict[str, Any]) -> None:
        if not st or self._closing:
            return
        if st.get("connected") and not st.get("last_err"):
            cnt = st.get("req_count", 0)
            masked = st.get("endpoint_masked", "")
            self.var_bridge_status.set(
                f"🟢 端到端 AEAD 已连通 ({masked}) -> 127.0.0.1:{self.port}/v1 | 已加密转发 {cnt} 次请求"
            )
            if self._tray is not None and self._tray.active:
                self._tray.update_tooltip(f"Kiss-Shot [已加密连通] · 127.0.0.1:{self.port}/v1 (已转发 {cnt} 次)")
        elif st.get("connected") and st.get("last_err"):
            self.var_bridge_status.set(f"🟠 隧道连接异常 ({st.get('last_err', '')[:55]})")
            if self._tray is not None and self._tray.active:
                self._tray.update_tooltip(f"Kiss-Shot [连接异常] · 127.0.0.1:{self.port}/v1")
        else:
            self.var_bridge_status.set(
                f"🟡 本地加密网桥待命中 (127.0.0.1:{self.port}/v1) · 复制 KISSSHOT_TICKET 后自动秒连"
            )
            if self._tray is not None and self._tray.active:
                self._tray.update_tooltip(f"Kiss-Shot [待命监听] · 127.0.0.1:{self.port}/v1")

    def _poll_bridge_status(self) -> None:
        if self._closing or self._hidden_to_tray:
            return

        def worker() -> None:
            st = query_local_bridge_status(self.port, work_dir=self.work_dir)
            if st:
                self._ui_call(lambda s=st: self._refresh_bridge_ui(s))

        threading.Thread(target=worker, daemon=True).start()
        self.after(3000, self._poll_bridge_status)

    # -------------------- Media Task & Bidirectional Queue --------------------
    def _ensure_mailbox_once(self, api: HfApi, mailbox_repo: str) -> None:
        if mailbox_repo not in self._ensured_repos:
            api.create_repo(repo_id=mailbox_repo, repo_type="model", private=True, exist_ok=True)
            self._ensured_repos.add(mailbox_repo)

    def _build_media_payload_base(self) -> Optional[Tuple[Dict[str, Any], str, Optional[bytes]]]:
        if not self._save_settings(silent=True):
            messagebox.showwarning("未设置凭据", "请先在第 3 页配置主加密口令与 HuggingFace Token！")
            return None
        hf_token = self.cfg["hf_token"]
        hf_user = self.cfg["hf_user"]
        suffix = self.cfg.get("mailbox_suffix") or DEFAULT_MAILBOX_REPO_NAME
        if not hf_token or not hf_user:
            messagebox.showwarning("缺少 HF 配置", "异步密文信箱需要先在第 3 页验证 HuggingFace Write Token。")
            return None

        m_key = self.media_keys[self.combo_media.current()]
        m_spec = self.media_catalog[m_key]
        ref_local = self.var_ref_img.get().strip()
        mask_png = self._inpaint_mask_png if (ref_local and m_spec["category"].startswith("image")) else None

        if m_spec["category"] == "video_i2v" and not ref_local:
            messagebox.showwarning("缺少参考图", "当前选择了图生视频 (I2V) 模型，请先选择一张本地参考图或从右侧画廊指定！")
            return None

        try:
            strength_val = max(0.05, min(1.0, float(self.var_strength.get() or 0.65)))
            payload: Dict[str, Any] = {
                "type": "kissshot_media_infer",
                "preset_key": m_key,
                "src_repo": m_spec["src_repo"],
                "arch": m_spec["arch"],
                "variant": m_spec.get("variant"),
                "skip_root": bool(m_spec.get("skip_root_safetensors", False)),
                "hf_user": hf_user,
                "hf_token": hf_token,
                "mailbox_repo": f"{hf_user}/{suffix}",
                "prompt": self.txt_pos.get("1.0", tk.END).strip(),
                "negative_prompt": self.txt_neg.get("1.0", tk.END).strip(),
                "width": int(self.var_w.get()),
                "height": int(self.var_h.get()),
                "steps": int(self.var_steps.get()),
                "cfg": float(self.var_cfg.get()),
                "frames": int(self.var_frames.get()),
                "batch": int(self.var_batch.get()),
                "seed": int(self.var_seed.get()),
                "strength": strength_val,
                "upscale_2x": bool(self.var_upscale_2x.get()),
                "ref_staging_blob": "",
                "mask_staging_blob": "",
            }
        except ValueError as exc:
            messagebox.showerror("参数格式错误", str(exc))
            return None

        return payload, ref_local, mask_png

    def _prepare_staging_commits(
        self,
        payload: Dict[str, Any],
        ref_local: str,
        mask_png: Optional[bytes],
        pwd: str,
    ) -> List[CommitOperationAdd]:
        ops: List[CommitOperationAdd] = []
        if ref_local:
            if not os.path.isfile(ref_local):
                raise FileNotFoundError(ref_local)
            self._ui_call(lambda: self.status_var.set("正在本机执行参考图 AES-256-GCM 加密..."))
            with open(ref_local, "rb") as rf:
                enc_img = encrypt_bytes_aes(rf.read(), pwd)
            staging_rel = f"_staging/ref_{secrets.token_hex(6)}.bin"
            ops.append(CommitOperationAdd(path_in_repo=staging_rel, path_or_fileobj=enc_img))
            payload["ref_staging_blob"] = staging_rel

        if mask_png:
            self._ui_call(lambda: self.status_var.set("正在本机执行局部重绘蒙版 AES-256-GCM 加密..."))
            enc_mask = encrypt_bytes_aes(mask_png, pwd)
            mask_rel = f"_staging/mask_{secrets.token_hex(6)}.bin"
            ops.append(CommitOperationAdd(path_in_repo=mask_rel, path_or_fileobj=enc_mask))
            payload["mask_staging_blob"] = mask_rel
        return ops

    def _generate_daemon_hex(self) -> None:
        if not self._save_settings(silent=True):
            messagebox.showwarning("未设置凭据", "请先在第 3 页配置口令与 HuggingFace Token！")
            return
        hf_token = self.cfg["hf_token"]
        hf_user = self.cfg["hf_user"]
        pwd = self.cfg["passphrase"]
        suffix = self.cfg.get("mailbox_suffix") or DEFAULT_MAILBOX_REPO_NAME
        if not hf_token or not hf_user:
            messagebox.showwarning("缺少 HF 配置", "请先在第 3 页验证 HuggingFace Write Token。")
            return
        daemon_payload = {
            "type": "kissshot_media_daemon",
            "hf_user": hf_user,
            "hf_token": hf_token,
            "mailbox_repo": f"{hf_user}/{suffix}",
        }
        hex_tok = encrypt_payload_hex(daemon_payload, pwd)
        self.txt_media_hex.delete("1.0", tk.END)
        self.txt_media_hex.insert("1.0", hex_tok)
        self._copy_ephemeral_secret(hex_tok)
        self.status_var.set("🛰️ 远端自动接单守护口令已复制（90s自动销毁）！粘贴至 Cell 2 运行 1 次即可全程本地连发")
        messagebox.showinfo(
            "守护口令已复制",
            "已将 KISSSHOT_TASK_HEX（守护模式）复制到剪贴板！\n\n"
            "1. 粘贴到 remote_media_worker.ipynb 的 Cell 2 运行 1 次；\n"
            "2. 之后无需再切换窗口，直接在本面板点击「🚀 一键加密入队 & 自动解密取回」即可全自动推理并回传画廊。",
        )

    def _submit_queue_and_autopull(self) -> None:
        built = self._build_media_payload_base()
        if not built:
            return
        payload, ref_local, mask_png = built
        pwd = self.cfg["passphrase"]
        hf_token = self.cfg["hf_token"]
        self.status_var.set("🚀 正在使用 AAD_QUEUE 密封任务并原子投递至私有密文信箱...")

        def worker() -> None:
            try:
                api = HfApi(token=hf_token)
                ops = self._prepare_staging_commits(payload, ref_local, mask_png, pwd)
                job_bytes = encrypt_queue_job(payload, pwd)
                job_rel = f"_queue/job_{int(time.time())}_{secrets.token_hex(4)}.bin"
                ops.append(CommitOperationAdd(path_in_repo=job_rel, path_or_fileobj=job_bytes))
                self._ensure_mailbox_once(api, payload["mailbox_repo"])
                api.create_commit(
                    repo_id=payload["mailbox_repo"],
                    repo_type="model",
                    operations=ops,
                    commit_message="enqueue kissshot job",
                )
                self._ui_call(lambda jr=job_rel: self._on_job_enqueued(jr))
            except Exception as exc:
                self._ui_call(lambda err=str(exc): self._on_error("加密入队失败", err))

        threading.Thread(target=worker, daemon=True).start()

    def _on_job_enqueued(self, job_rel: str) -> None:
        self.status_var.set(f"⏳ 已投递队列密文 {os.path.basename(job_rel)} · 正在后台监听远端接单与加密归档回传...")
        start_ts = time.time()
        if not self._auto_watch_active:
            self._auto_watch_active = True
            self.after(1800, lambda: self._auto_watch_tick(job_rel, ticks=0, start_ts=start_ts))

    def _auto_watch_tick(self, job_rel: str, ticks: int, start_ts: Optional[float] = None) -> None:
        if self._closing or not self._auto_watch_active:
            return
        if ticks > 900:
            self._auto_watch_active = False
            return
        hf_token = self.cfg.get("hf_token", "")
        hf_user = self.cfg.get("hf_user", "")
        suffix = self.cfg.get("mailbox_suffix") or DEFAULT_MAILBOX_REPO_NAME
        if not hf_token or not hf_user:
            self._auto_watch_active = False
            return
        mailbox_repo = f"{hf_user}/{suffix}"
        t_base = start_ts or time.time()

        def worker() -> None:
            try:
                api = HfApi(token=hf_token)
                files = api.list_repo_files(repo_id=mailbox_repo, repo_type="model")
                inbox_files = sorted([f for f in files if f.startswith("_inbox/") and f.endswith(".bin")])
                queue_files = [f for f in files if f.startswith("_queue/") and f.endswith(".bin")]
                if inbox_files:
                    self._ui_call(
                        lambda inf=list(inbox_files): self._pull_and_burn_inbox(
                            silent_empty=True, auto_mode=True, known_inbox=inf
                        )
                    )
                    if not queue_files:
                        self._auto_watch_active = False
                        return
                elif job_rel not in queue_files:
                    waited = max(1, int(time.time() - t_base))
                    self._ui_call(
                        lambda w=waited: self.status_var.set(
                            f"🎨 远端 GPU 节点已接单并销毁队列密文，正在纯内存推理中... (已耗时 {w}s)"
                        )
                    )
                else:
                    self._ui_call(
                        lambda: self.status_var.set(
                            "⏳ 密文任务已在信箱排队 · 若远端尚未启动守护循环，请点右侧「🛰️ 复制远端自动接单守护口令」运行一次"
                        )
                    )
            except Exception:
                pass
            if self._auto_watch_active and not self._closing:
                self._ui_call(
                    lambda: self.after(2000, lambda: self._auto_watch_tick(job_rel, ticks + 1, start_ts=t_base))
                )

        threading.Thread(target=worker, daemon=True).start()

    def _generate_media_task(self) -> None:
        built = self._build_media_payload_base()
        if not built:
            return
        payload, ref_local, mask_png = built
        pwd = self.cfg["passphrase"]
        hf_token = self.cfg["hf_token"]

        def worker() -> None:
            try:
                api = HfApi(token=hf_token)
                ops = self._prepare_staging_commits(payload, ref_local, mask_png, pwd)
                if ops:
                    self._ensure_mailbox_once(api, payload["mailbox_repo"])
                    api.create_commit(
                        repo_id=payload["mailbox_repo"],
                        repo_type="model",
                        operations=ops,
                        commit_message="stage encrypted inputs",
                    )
                hex_tok = encrypt_payload_hex(payload, pwd)
                self.after(0, lambda h=hex_tok: self._on_media_hex_ready(h))
            except Exception as exc:
                self.after(0, lambda err=str(exc): self._on_error("加密任务生成失败", err))

        threading.Thread(target=worker, daemon=True).start()

    def _on_media_hex_ready(self, hex_tok: str) -> None:
        self.txt_media_hex.delete("1.0", tk.END)
        self.txt_media_hex.insert("1.0", hex_tok)
        self._copy_ephemeral_secret(hex_tok)
        self.status_var.set("✅ 任务密文 KISSSHOT_TASK_HEX 已生成并复制（90 秒自动销毁剪贴板）")

    def _pull_and_burn_inbox(
        self,
        silent_empty: bool = False,
        auto_mode: bool = False,
        known_inbox: Optional[List[str]] = None,
    ) -> None:
        if not self._save_settings(silent=True):
            return
        pwd = self.cfg["passphrase"]
        hf_token = self.cfg["hf_token"]
        hf_user = self.cfg["hf_user"]
        suffix = self.cfg.get("mailbox_suffix") or DEFAULT_MAILBOX_REPO_NAME
        if not hf_token or not hf_user:
            if not silent_empty:
                messagebox.showwarning("缺少 HF 配置", "请先在第 3 页验证 HuggingFace Token。")
            return

        if not self._pull_lock.acquire(blocking=False):
            return

        mailbox_repo = f"{hf_user}/{suffix}"
        self.status_var.set("📥 正在检查私有密文信箱并拉取双层 AEAD 归档...")

        def worker() -> None:
            try:
                api = HfApi(token=hf_token)
                if known_inbox:
                    inbox_files = sorted(known_inbox)
                else:
                    files = api.list_repo_files(repo_id=mailbox_repo, repo_type="model")
                    inbox_files = sorted([f for f in files if f.startswith("_inbox/") and f.endswith(".bin")])
                if not inbox_files:
                    if not silent_empty:
                        self.after(0, lambda: messagebox.showinfo("信箱为空", "当前私有中转仓没有待取回的加密分片。"))
                        self.after(0, lambda: self.status_var.set("私有密文信箱为空"))
                    return

                all_saved: List[str] = []
                burned_files: List[str] = []
                with tempfile.TemporaryDirectory() as tmpd:
                    for remote_f in inbox_files:
                        local_enc = hf_hub_download(
                            repo_id=mailbox_repo,
                            filename=remote_f,
                            repo_type="model",
                            token=hf_token,
                            local_dir=tmpd,
                        )
                        with open(local_enc, "rb") as zf_in:
                            zip_bytes = zf_in.read()
                        saved, meta = unpack_encrypted_zip(zip_bytes, pwd, self.output_dir, prefix="ks")
                        try:
                            record_gallery_items(self.output_dir, saved, meta)
                        except Exception:
                            pass
                        all_saved.extend(saved)
                        burned_files.append(remote_f)

                self.after(0, lambda p=list(all_saved), am=auto_mode: self._on_pulled_ok(p, auto_mode=am))
                if burned_files:
                    try:
                        api.create_commit(
                            repo_id=mailbox_repo,
                            repo_type="model",
                            operations=[CommitOperationDelete(path_in_repo=rf) for rf in burned_files],
                            commit_message="burn decrypted artifacts",
                        )
                    except Exception:
                        for rf in burned_files:
                            try:
                                api.delete_file(
                                    path_in_repo=rf,
                                    repo_id=mailbox_repo,
                                    repo_type="model",
                                    commit_message="burn decrypted artifact",
                                )
                            except Exception:
                                pass
            except Exception as exc:
                self.after(0, lambda err=str(exc): self._on_error("拉取或解密失败", err))
            finally:
                self._pull_lock.release()

        threading.Thread(target=worker, daemon=True).start()

    def _on_pulled_ok(self, paths: List[str], auto_mode: bool = False) -> None:
        try:
            self.gallery_sidebar.refresh(select_latest=True)
        except Exception:
            pass
        self.status_var.set(f"✅ 已解密还原 {len(paths)} 个产物至右侧画廊，云端密文已阅后即焚销毁")
        if auto_mode:
            if self._tray is not None and self._tray.active and self._hidden_to_tray:
                self._tray.notify_balloon(
                    "Kiss-Shot 密文产物已就绪",
                    f"已自动解密还原 {len(paths)} 个文件至本地画廊，远端密文分片已销毁。",
                )
            return
        if messagebox.askyesno(
            "解密完成（阅后即焚已执行）",
            f"已验证并解密 {len(paths)} 个文件至右侧画廊与目录：\n{self.output_dir}\n\n立即打开目录查看吗？",
        ):
            _open_directory_cross_platform(self.output_dir)

    def _decrypt_local_archive(self) -> None:
        if not self._save_settings(silent=True):
            return
        zpath = filedialog.askopenfilename(
            title="选择双层 AEAD (AES-256-GCM + WZ_AES) 加密归档",
            filetypes=[("Encrypted Archives", "*.zip *.bin"), ("All files", "*.*")],
        )
        if not zpath:
            return
        try:
            with open(zpath, "rb") as f:
                saved, meta = unpack_encrypted_zip(f.read(), self.cfg["passphrase"], self.output_dir, prefix="local")
            try:
                record_gallery_items(self.output_dir, saved, meta)
                self.gallery_sidebar.refresh(select_latest=True)
            except Exception:
                pass
            self.status_var.set(f"✅ 已解密本地归档 ({len(saved)} 个文件) 并载入画廊")
        except Exception as exc:
            self._on_error("解密失败", str(exc))

    def _on_error(self, title: str, err: str) -> None:
        self.status_var.set(f"❌ {title}: {err[:65]}")
        messagebox.showerror(title, err)


def run_panel(
    work_dir: str | None = None,
    port: int = DEFAULT_LOCAL_PORT,
    start_minimized: bool = False,
) -> None:
    enable_high_dpi()
    set_app_user_model_id(APP_USER_MODEL_ID)
    if signal_existing_instance(TRAY_CLASS_NAME, PANEL_WINDOW_TITLE):
        return
    app = ZeroTrustBridgeApp(work_dir=work_dir, port=port, start_minimized=start_minimized)
    app.mainloop()
