# -*- coding: utf-8 -*-
"""
零信任远程算力网关 · 本地跨平台桌面控制台 (kiss_shot/panel.py)
- 100% 运行于用户本机，所有密钥派生、提示词加密、图像加密与归档解密均在本地内存与磁盘内闭环完成。
- 凭据仅存于工作目录 .kissshot_secrets.json（已被 .gitignore 严格排除）。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Dict, List

from huggingface_hub import HfApi, hf_hub_download

from .clipboard import clear_clipboard_text, read_clipboard_text, write_clipboard_secret
from .crypto import (
    DEFAULT_LOCAL_PORT,
    DEFAULT_MAILBOX_REPO_NAME,
    LLM_PRESETS,
    MEDIA_PRESETS,
    encrypt_bytes_aes,
    encrypt_payload_hex,
    load_encrypted_secrets,
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


def _open_directory_cross_platform(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    if sys.platform == "win32":
        os.startfile(path)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


def load_secrets(work_dir: str) -> Dict[str, Any]:
    return load_encrypted_secrets(
        default_secrets_path(work_dir),
        defaults={
            "passphrase": "",
            "hf_user": "",
            "hf_token": "",
            "mailbox_suffix": DEFAULT_MAILBOX_REPO_NAME,
            "client_dir": "",
        },
    )


def save_secrets(work_dir: str, data: Dict[str, Any]) -> None:
    save_encrypted_secrets(default_secrets_path(work_dir), data)


class ZeroTrustBridgeApp(tk.Tk):
    def __init__(self, work_dir: str | None = None, port: int = DEFAULT_LOCAL_PORT) -> None:
        super().__init__()
        self.work_dir = os.path.abspath(work_dir or os.getcwd())
        self.port = port
        self.output_dir = os.path.join(self.work_dir, "outputs")
        self._clip_timer_id: str | None = None

        self.title("Kiss-Shot · 零信任端到端加密推理与密文信箱控制台")
        self.geometry("980x760")
        self.minsize(880, 680)

        self.cfg = load_secrets(self.work_dir)
        self.llm_keys: List[str] = list(LLM_PRESETS.keys())
        self.llm_labels: List[str] = [LLM_PRESETS[k]["label"] for k in self.llm_keys]
        self.media_keys: List[str] = list(MEDIA_PRESETS.keys())
        self.media_labels: List[str] = [MEDIA_PRESETS[k]["label"] for k in self.media_keys]

        self._build_ui()
        self._apply_media_defaults(0)

        start_local_bridge_background(
            port=self.port,
            work_dir=self.work_dir,
            watch_clipboard=True,
            on_status_change=lambda st: self.after(0, lambda s=st: self._refresh_bridge_ui(s)),
        )
        self.after(600, self._poll_bridge_status)

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        ui_font = "Microsoft YaHei UI" if sys.platform == "win32" else "Sans"
        style.configure("TButton", padding=5, font=(ui_font, 10))
        style.configure("Accent.TButton", padding=7, font=(ui_font, 10, "bold"))
        style.configure("TLabel", font=(ui_font, 10))
        style.configure("Header.TLabel", font=(ui_font, 11, "bold"))

        top_bar = ttk.Frame(self, padding=(12, 8))
        top_bar.pack(fill=tk.X)
        self.status_var = tk.StringVar(
            value=f"就绪 · 本地 OpenAI 加密代理 http://127.0.0.1:{self.port}/v1 (PBKDF2 + AES-256-GCM AEAD)"
        )
        ttk.Label(top_bar, textvariable=self.status_var, foreground="#1a6b3c").pack(side=tk.LEFT)
        ttk.Button(top_bar, text="📁 打开本地解密产物目录", command=lambda: _open_directory_cross_platform(self.output_dir)).pack(
            side=tk.RIGHT
        )
        ttk.Button(top_bar, text="🧹 擦除剪贴板", command=self._manual_scrub_clipboard).pack(
            side=tk.RIGHT, padx=(0, 8)
        )

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self.tab_llm = ttk.Frame(nb, padding=12)
        self.tab_media = ttk.Frame(nb, padding=12)
        self.tab_settings = ttk.Frame(nb, padding=12)

        nb.add(self.tab_llm, text=" 💬 1. 实时 OpenAI E2EE 流式推理网桥 ")
        nb.add(self.tab_media, text=" 🎨 2. 异步密文任务与阅后即焚信箱 ")
        nb.add(self.tab_settings, text=" 🔑 3. 本地零信任凭据设置 ")

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
        self.combo_llm = ttk.Combobox(r1, values=self.llm_labels, state="readonly", width=66, font=(ui_font, 10))
        self.combo_llm.current(0)
        self.combo_llm.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)

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

        ttk.Label(r2, text="自定义 HF 仓库覆盖 (可选 repo/file.gguf):").pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self.var_custom_llm_repo, width=28).pack(side=tk.LEFT, padx=4, fill=tk.X, expand=True)

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
        ttk.Button(t_row, text="📋 粘贴票据并执行 AEAD 握手", style="Accent.TButton", command=self._paste_and_bind_ticket).pack(
            side=tk.LEFT
        )

    # -------------------- Tab 2: Ephemeral Ciphertext Mailbox --------------------
    def _build_media_tab(self, ui_font: str) -> None:
        f = self.tab_media

        row_m = ttk.Frame(f)
        row_m.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(row_m, text="选择模型预设：", style="Header.TLabel").pack(side=tk.LEFT)
        self.combo_media = ttk.Combobox(row_m, values=self.media_labels, state="readonly", width=58, font=(ui_font, 10))
        self.combo_media.current(0)
        self.combo_media.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)
        self.combo_media.bind("<<ComboboxSelected>>", lambda _e: self._apply_media_defaults(self.combo_media.current()))
        ttk.Button(row_m, text="重置默认提示词", command=self._fill_media_prompts).pack(side=tk.RIGHT)

        ttk.Label(f, text="正向提示词 (Prompt · 本地 AES-256-GCM 加密后传输):").pack(anchor=tk.W)
        self.txt_pos = scrolledtext.ScrolledText(f, height=4, font=("Consolas", 10), wrap=tk.WORD)
        self.txt_pos.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(f, text="反向提示词 (Negative Prompt):").pack(anchor=tk.W)
        self.txt_neg = scrolledtext.ScrolledText(f, height=2, font=("Consolas", 10), wrap=tk.WORD)
        self.txt_neg.pack(fill=tk.X, pady=(2, 8))

        p_box = ttk.LabelFrame(f, text="推理参数", padding=8)
        p_box.pack(fill=tk.X, pady=(0, 8))

        self.var_w = tk.StringVar(value="1024")
        self.var_h = tk.StringVar(value="1024")
        self.var_steps = tk.StringVar(value="28")
        self.var_cfg = tk.StringVar(value="5.5")
        self.var_frames = tk.StringVar(value="1")
        self.var_batch = tk.StringVar(value="1")
        self.var_seed = tk.StringVar(value="-1")

        params = [
            ("宽(W):", self.var_w, 7),
            ("高(H):", self.var_h, 7),
            ("步数:", self.var_steps, 6),
            ("CFG:", self.var_cfg, 6),
            ("视频帧数:", self.var_frames, 6),
            ("批次:", self.var_batch, 5),
            ("种子(-1随机):", self.var_seed, 10),
        ]
        for idx, (lbl, var, w) in enumerate(params):
            ttk.Label(p_box, text=lbl).grid(row=0, column=idx * 2, sticky=tk.W, padx=(6 if idx else 0, 2))
            ttk.Entry(p_box, textvariable=var, width=w).grid(row=0, column=idx * 2 + 1, sticky=tk.W, padx=(0, 6))

        ref_box = ttk.LabelFrame(f, text="可选：图生视频 / 参考图加密上传（AES-256-GCM 暂存，远端读取后即刻销毁）", padding=8)
        ref_box.pack(fill=tk.X, pady=(0, 8))
        self.var_ref_img = tk.StringVar(value="")
        ttk.Entry(ref_box, textvariable=self.var_ref_img).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Button(ref_box, text="选择本地图片...", command=self._pick_ref_image).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(ref_box, text="清空", command=lambda: self.var_ref_img.set("")).pack(side=tk.LEFT)

        act_row = ttk.Frame(f)
        act_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(
            act_row,
            text="🔒 第一步：生成 AES-256 任务密文 KISSSHOT_TASK_HEX（自动复制）",
            style="Accent.TButton",
            command=self._generate_media_task,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Button(
            act_row,
            text="📥 第二步：从私有中转仓拉取解密并阅后即焚",
            style="Accent.TButton",
            command=self._pull_and_burn_inbox,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0))

        sub_row = ttk.Frame(f)
        sub_row.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(sub_row, text="生成的任务密文载荷：").pack(side=tk.LEFT)
        ttk.Button(sub_row, text="📂 手动解密本地加密归档 (.zip/.bin)...", command=self._decrypt_local_archive).pack(
            side=tk.RIGHT
        )

        self.txt_media_hex = scrolledtext.ScrolledText(f, height=5, font=("Consolas", 9), wrap=tk.CHAR)
        self.txt_media_hex.pack(fill=tk.BOTH, expand=True)

    # -------------------- Tab 3: Credentials --------------------
    def _build_settings_tab(self) -> None:
        f = self.tab_settings
        box = ttk.LabelFrame(f, text="本地零信任凭据（仅保存在工作区 .kissshot_secrets.json，绝不明文外发）", padding=14)
        box.pack(fill=tk.X, pady=(0, 12))

        self.var_pwd = tk.StringVar(value=self.cfg.get("passphrase", ""))
        self.var_hf_token = tk.StringVar(value=self.cfg.get("hf_token", ""))
        self.var_hf_user = tk.StringVar(value=self.cfg.get("hf_user", ""))
        self.var_mailbox_suffix = tk.StringVar(value=self.cfg.get("mailbox_suffix", DEFAULT_MAILBOX_REPO_NAME))
        self.var_client_dir = tk.StringVar(value=self.cfg.get("client_dir", ""))

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

    # -------------------- Actions --------------------
    def _apply_media_defaults(self, idx: int) -> None:
        key = self.media_keys[idx]
        m = MEDIA_PRESETS[key]
        self.var_w.set(str(m["default_width"]))
        self.var_h.set(str(m["default_height"]))
        self.var_steps.set(str(m["default_steps"]))
        self.var_cfg.set(str(m["default_cfg"]))
        self.var_frames.set(str(m["default_frames"]))
        if not self.txt_pos.get("1.0", tk.END).strip():
            self._fill_media_prompts()

    def _fill_media_prompts(self) -> None:
        key = self.media_keys[self.combo_media.current()]
        m = MEDIA_PRESETS[key]
        self.txt_pos.delete("1.0", tk.END)
        self.txt_pos.insert("1.0", m["default_pos"])
        self.txt_neg.delete("1.0", tk.END)
        self.txt_neg.insert("1.0", m["default_neg"])

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

    def _pick_ref_image(self) -> None:
        p = filedialog.askopenfilename(
            title="选择需要端到端加密上传的本地参考图像",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.webp *.bmp"), ("All files", "*.*")],
        )
        if p:
            self.var_ref_img.set(p)

    def _save_settings(self, silent: bool = False) -> bool:
        pwd = self.var_pwd.get().strip()
        if not pwd:
            if not silent:
                messagebox.showwarning("缺少口令", "请先填写或生成主加密口令 (Passphrase)！")
            return False
        suffix = self.var_mailbox_suffix.get().strip() or DEFAULT_MAILBOX_REPO_NAME
        self.cfg = {
            "passphrase": pwd,
            "hf_user": self.var_hf_user.get().strip(),
            "hf_token": self.var_hf_token.get().strip(),
            "mailbox_suffix": suffix,
            "client_dir": self.var_client_dir.get().strip(),
        }
        save_secrets(self.work_dir, self.cfg)
        if not silent:
            self.status_var.set("✅ 本地零信任凭据已保存")
            messagebox.showinfo("已保存", "凭据已安全保存至本工作区 .kissshot_secrets.json。")
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
                self.after(0, lambda: self._on_hf_ready(username, mailbox_repo))
            except Exception as exc:
                self.after(0, lambda err=str(exc): self._on_error("HF 验证失败", err))

        threading.Thread(target=worker, daemon=True).start()

    def _on_hf_ready(self, username: str, mailbox_repo: str) -> None:
        self.var_hf_user.set(username)
        self._save_settings(silent=True)
        self.status_var.set(f"✅ HF 验证通过：{username} | 私有信箱 {mailbox_repo} (Private) 已就绪")
        messagebox.showinfo("初始化完成", f"账号：{username}\n私有密文中转仓：{mailbox_repo}")

    def _generate_llm_hex(self) -> None:
        if not self._save_settings(silent=True):
            messagebox.showwarning("未设置口令", "请先在第 3 页设置主加密口令！")
            return
        pwd = self.cfg["passphrase"]
        llm_key = self.llm_keys[self.combo_llm.current()]
        spec = LLM_PRESETS[llm_key]
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

        is_custom_repo = bool(custom and "/" in custom)
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
            "hf_token": self.cfg.get("hf_token", "") if is_custom_repo else "",
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
            messagebox.showinfo("握手成功", f"{msg}\n\n剪贴板票据已自动销毁。\n本地端点已就绪：http://127.0.0.1:{self.port}/v1")
        else:
            self._on_error("握手未通过", msg)

    def _refresh_bridge_ui(self, st: Dict[str, Any]) -> None:
        if not st:
            return
        if st.get("connected") and not st.get("last_err"):
            cnt = st.get("req_count", 0)
            masked = st.get("endpoint_masked", "")
            self.var_bridge_status.set(
                f"🟢 端到端 AEAD 已连通 ({masked}) -> 127.0.0.1:{self.port}/v1 | 已加密转发 {cnt} 次请求"
            )
        elif st.get("connected") and st.get("last_err"):
            self.var_bridge_status.set(f"🟠 隧道连接异常 ({st.get('last_err', '')[:55]})")
        else:
            self.var_bridge_status.set(
                f"🟡 本地加密网桥待命中 (127.0.0.1:{self.port}/v1) · 复制 KISSSHOT_TICKET 后自动秒连"
            )

    def _poll_bridge_status(self) -> None:
        def worker() -> None:
            st = query_local_bridge_status(self.port, work_dir=self.work_dir)
            if st:
                self.after(0, lambda s=st: self._refresh_bridge_ui(s))

        threading.Thread(target=worker, daemon=True).start()
        self.after(3000, self._poll_bridge_status)

    def _generate_media_task(self) -> None:
        if not self._save_settings(silent=True):
            messagebox.showwarning("未设置凭据", "请先在第 3 页配置口令与 HuggingFace Token！")
            return
        pwd = self.cfg["passphrase"]
        hf_token = self.cfg["hf_token"]
        hf_user = self.cfg["hf_user"]
        suffix = self.cfg.get("mailbox_suffix") or DEFAULT_MAILBOX_REPO_NAME
        if not hf_token or not hf_user:
            messagebox.showwarning("缺少 HF 配置", "异步密文信箱需要先在第 3 页验证 HuggingFace Write Token。")
            return

        m_key = self.media_keys[self.combo_media.current()]
        m_spec = MEDIA_PRESETS[m_key]
        ref_local = self.var_ref_img.get().strip()

        try:
            payload: Dict[str, Any] = {
                "type": "kissshot_media_infer",
                "preset_key": m_key,
                "src_repo": m_spec["src_repo"],
                "arch": m_spec["arch"],
                "variant": m_spec["variant"],
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
                "ref_staging_blob": "",
            }
        except ValueError as exc:
            messagebox.showerror("参数格式错误", str(exc))
            return

        def worker() -> None:
            try:
                if ref_local:
                    if not os.path.isfile(ref_local):
                        raise FileNotFoundError(ref_local)
                    self.after(0, lambda: self.status_var.set("正在本机执行参考图 AES-256-GCM 加密并上传暂存分片..."))
                    with open(ref_local, "rb") as rf:
                        enc_img = encrypt_bytes_aes(rf.read(), pwd)
                    staging_rel = f"_staging/ref_{secrets.token_hex(6)}.bin"
                    api = HfApi(token=hf_token)
                    api.create_repo(repo_id=payload["mailbox_repo"], repo_type="model", private=True, exist_ok=True)
                    api.upload_file(
                        path_or_fileobj=enc_img,
                        path_in_repo=staging_rel,
                        repo_id=payload["mailbox_repo"],
                        repo_type="model",
                        commit_message="stage encrypted input",
                    )
                    payload["ref_staging_blob"] = staging_rel

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

    def _pull_and_burn_inbox(self) -> None:
        if not self._save_settings(silent=True):
            return
        pwd = self.cfg["passphrase"]
        hf_token = self.cfg["hf_token"]
        hf_user = self.cfg["hf_user"]
        suffix = self.cfg.get("mailbox_suffix") or DEFAULT_MAILBOX_REPO_NAME
        if not hf_token or not hf_user:
            messagebox.showwarning("缺少 HF 配置", "请先在第 3 页验证 HuggingFace Token。")
            return

        mailbox_repo = f"{hf_user}/{suffix}"
        self.status_var.set("正在检查私有密文信箱并拉取加密归档...")

        def worker() -> None:
            try:
                api = HfApi(token=hf_token)
                files = api.list_repo_files(repo_id=mailbox_repo, repo_type="model")
                inbox_files = sorted([f for f in files if f.startswith("_inbox/") and f.endswith(".bin")])
                if not inbox_files:
                    self.after(0, lambda: messagebox.showinfo("信箱为空", "当前私有中转仓没有待取回的加密分片。"))
                    self.after(0, lambda: self.status_var.set("私有密文信箱为空"))
                    return

                all_saved: List[str] = []
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
                        saved, _ = unpack_encrypted_zip(zip_bytes, pwd, self.output_dir, prefix="ztgb")
                        all_saved.extend(saved)
                        api.delete_file(
                            path_in_repo=remote_f,
                            repo_id=mailbox_repo,
                            repo_type="model",
                            commit_message="burn decrypted artifact",
                        )

                self.after(0, lambda p=all_saved: self._on_pulled_ok(p))
            except Exception as exc:
                self.after(0, lambda err=str(exc): self._on_error("拉取或解密失败", err))

        threading.Thread(target=worker, daemon=True).start()

    def _on_pulled_ok(self, paths: List[str]) -> None:
        self.status_var.set(f"✅ 已解密还原 {len(paths)} 个文件，云端密文已阅后即焚销毁")
        if messagebox.askyesno(
            "解密完成（阅后即焚已执行）",
            f"已验证并解密 {len(paths)} 个文件至：\n{self.output_dir}\n\n立即打开目录查看吗？",
        ):
            _open_directory_cross_platform(self.output_dir)

    def _decrypt_local_archive(self) -> None:
        if not self._save_settings(silent=True):
            return
        zpath = filedialog.askopenfilename(
            title="选择 WZ_AES 256-bit 加密归档",
            filetypes=[("Encrypted Archives", "*.zip *.bin"), ("All files", "*.*")],
        )
        if not zpath:
            return
        try:
            with open(zpath, "rb") as f:
                saved, _ = unpack_encrypted_zip(f.read(), self.cfg["passphrase"], self.output_dir, prefix="local")
            self.status_var.set(f"✅ 已解密本地归档 ({len(saved)} 个文件)")
        except Exception as exc:
            self._on_error("解密失败", str(exc))

    def _on_error(self, title: str, err: str) -> None:
        self.status_var.set(f"❌ {title}: {err[:65]}")
        messagebox.showerror(title, err)


def run_panel(work_dir: str | None = None, port: int = DEFAULT_LOCAL_PORT) -> None:
    app = ZeroTrustBridgeApp(work_dir=work_dir, port=port)
    app.mainloop()
