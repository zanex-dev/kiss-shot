# -*- coding: utf-8 -*-
"""
本地零信任离线视觉工作台组件库 (kiss_shot/studio_widgets.py)
- 100% 运行于用户本机内存与本地加密保险箱空间，无需在远端 GPU 暴露任何 WebUI 端口：
  1. MaskPainterDialog: 局部重绘 (Inpainting) 半透明画笔蒙版画板（支持画笔调节、15 步撤销、反选与擦除）
  2. MossLayoutDialog: OpenMOSS MOSS-Image 空间构图框画板（可视化编译 abs_centralized yxyx JSON）
  3. GallerySidebar: 本地加密作品画廊侧边栏（DPAPI / POSIX 0600 配方读取、一键复刻 Seed / 垫图重绘 / 送图生视频）
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Callable, Dict, List, Optional, Tuple

from PIL import Image, ImageDraw

try:
    from PIL import ImageTk
except Exception:  # pragma: no cover - headless fallback when Tcl/Tk bindings are absent
    ImageTk = None  # type: ignore[assignment]

from .crypto import load_gallery_vault
from .win_tray import apply_tk_window_icon


def open_path_cross_platform(path: str) -> None:
    """使用系统默认查看器打开文件或目录（跨平台兼容 Windows / macOS / Linux）"""
    if not path or not os.path.exists(path):
        return
    if sys.platform == "win32":
        os.startfile(path)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


def canvas_pt_to_centered(
    cx: int,
    cy: int,
    disp_w: int,
    disp_h: int,
    target_w: int,
    target_h: int,
) -> Tuple[int, int]:
    """将预览画布左上角原点坐标转换为 MOSS-Image 中心原点像素坐标 (x, y)"""
    px = max(0, min(target_w, int(round(cx * target_w / max(1, disp_w)))))
    py = max(0, min(target_h, int(round(cy * target_h / max(1, disp_h)))))
    return px - (target_w // 2), py - (target_h // 2)


def centered_pt_to_canvas(
    x: int,
    y: int,
    disp_w: int,
    disp_h: int,
    target_w: int,
    target_h: int,
) -> Tuple[int, int]:
    """将 MOSS-Image 中心原点像素坐标 (x, y) 还原为预览画布坐标"""
    px = x + (target_w // 2)
    py = y + (target_h // 2)
    return int(round(px * disp_w / max(1, target_w))), int(round(py * disp_h / max(1, target_h)))


def compile_moss_layout_json(summary_caption: str, boxes: List[Dict[str, Any]]) -> str:
    """将区域元素列表编译为符合 OpenMOSS MOSS-Image 规范的 abs_centralized yxyx JSON 字符串"""
    if not boxes:
        raise ValueError("At least one spatial bounding box is required")
    items_out: List[Dict[str, Any]] = []
    for b in boxes:
        kind = "text" if str(b.get("label")) == "text" else "object"
        bbox = [int(v) for v in b["bbox"]]
        if len(bbox) != 4:
            raise ValueError("Each bbox must contain 4 integers [y1, x1, y2, x2]")
        entry: Dict[str, Any] = {
            "label": kind,
            "caption": str(b.get("caption", "")).strip(),
            "bbox": bbox,
        }
        if kind == "text" and str(b.get("text", "")).strip():
            entry["text"] = str(b["text"]).strip()
        items_out.append(entry)
    has_text = any(it["label"] == "text" for it in items_out)
    layout_obj = {
        "summary": {
            "meta": ["poster"] if has_text else ["illustration"],
            "canvas": "single",
            "caption": summary_caption.strip(),
        },
        "items": items_out,
        "bbox_coord_space": "abs_centralized",
        "bbox_format": "yxyx",
    }
    return json.dumps(layout_obj, ensure_ascii=False)


def parse_moss_layout_json(raw_prompt: str) -> Tuple[str, List[Dict[str, Any]]]:
    """从现有正面提示词解析 MOSS-Image 空间布局 JSON；若为普通文本则原样作为全局描述返回"""
    text = (raw_prompt or "").strip()
    if not text.startswith("{"):
        return text, []
    try:
        parsed = json.loads(text)
        if not isinstance(parsed, dict) or "items" not in parsed:
            return text, []
        summary = str(parsed.get("summary", {}).get("caption", ""))
        boxes: List[Dict[str, Any]] = []
        for it in parsed.get("items", []):
            if isinstance(it, dict) and isinstance(it.get("bbox"), list) and len(it["bbox"]) == 4:
                boxes.append(
                    {
                        "label": "text" if str(it.get("label")) == "text" else "object",
                        "caption": str(it.get("caption", "")),
                        "text": str(it.get("text", "")),
                        "bbox": [int(x) for x in it["bbox"]],
                    }
                )
        return summary, boxes
    except Exception:
        return text, []


def render_binary_mask_png(mask_img: Image.Image) -> Optional[bytes]:
    """将灰度涂抹图层二值化并编码为无损 PNG 字节流；若未涂抹任何像素则返回 None"""
    gray = mask_img.convert("L")
    bw = gray.point(lambda v: 255 if v > 127 else 0)
    if bw.getbbox() is None:
        return None
    buf = io.BytesIO()
    bw.save(buf, format="PNG")
    return buf.getvalue()


class MaskPainterDialog(tk.Toplevel):
    """本地局部重绘 (Inpainting) 可视化涂抹蒙版画板"""

    def __init__(
        self,
        parent: tk.Misc,
        image_path: str,
        on_save: Callable[[Optional[bytes]], None],
        initial_mask_png: Optional[bytes] = None,
        ico_path: Optional[Path | str] = None,
    ) -> None:
        super().__init__(parent)
        self.title("🖌️ 本地局部重绘蒙版画板（左键涂红=重绘区域 · 右键擦除）")
        if ico_path and Path(ico_path).is_file():
            apply_tk_window_icon(self, ico_path)
        self.transient(parent)  # type: ignore[arg-type]
        self.grab_set()

        self.on_save = on_save
        self.src_img = Image.open(image_path).convert("RGBA")
        self.orig_w, self.orig_h = self.src_img.size

        max_cw, max_ch = 680, 540
        scale = min(max_cw / max(1, self.orig_w), max_ch / max(1, self.orig_h), 1.0)
        self.disp_w = max(64, int(round(self.orig_w * scale)))
        self.disp_h = max(64, int(round(self.orig_h * scale)))
        self.scale = scale
        self._display_base = self.src_img.resize((self.disp_w, self.disp_h), Image.Resampling.LANCZOS)

        if initial_mask_png:
            try:
                m = Image.open(io.BytesIO(initial_mask_png)).convert("L")
                self.mask_img = m.resize((self.orig_w, self.orig_h), Image.Resampling.NEAREST)
            except Exception:
                self.mask_img = Image.new("L", (self.orig_w, self.orig_h), 0)
        else:
            self.mask_img = Image.new("L", (self.orig_w, self.orig_h), 0)

        self._undo_stack: List[bytes] = []
        self._last_pt: Optional[Tuple[int, int]] = None
        self._tk_img: Any = None

        self.geometry(f"{max(760, self.disp_w + 60)}x{self.disp_h + 150}")
        self.resizable(False, False)

        root_pad = ttk.Frame(self, padding=10)
        root_pad.pack(fill=tk.BOTH, expand=True)

        tip = "操作指南：按住【鼠标左键】涂抹需要局部重绘的部位（半透明红区），按住【鼠标右键】擦除恢复原图；蒙版将在本机 AES-256-GCM 加密后上传。"
        ttk.Label(root_pad, text=tip, foreground="#0b5cad").pack(anchor=tk.W, pady=(0, 6))

        tool_bar = ttk.Frame(root_pad)
        tool_bar.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(tool_bar, text="画笔粗细:").pack(side=tk.LEFT)
        self.var_brush = tk.IntVar(value=max(18, int(min(self.orig_w, self.orig_h) * 0.04)))
        ttk.Scale(tool_bar, from_=6, to=160, variable=self.var_brush, orient=tk.HORIZONTAL, length=160).pack(
            side=tk.LEFT, padx=6
        )
        ttk.Button(tool_bar, text="↩ 撤销上一笔", command=self._undo).pack(side=tk.LEFT, padx=4)
        ttk.Button(tool_bar, text="🌓 反选重绘区", command=self._invert).pack(side=tk.LEFT, padx=4)
        ttk.Button(tool_bar, text="🗑️ 清空全部蒙版", command=self._clear_all).pack(side=tk.LEFT, padx=4)

        canvas_wrap = ttk.Frame(root_pad)
        canvas_wrap.pack(expand=True)
        self.canvas = tk.Canvas(
            canvas_wrap,
            width=self.disp_w,
            height=self.disp_h,
            bg="#222222",
            highlightthickness=1,
            highlightbackground="#888888",
            cursor="tcross",
        )
        self.canvas.pack()

        self.canvas.bind("<ButtonPress-1>", lambda e: self._start_stroke(e, 255))
        self.canvas.bind("<B1-Motion>", lambda e: self._move_stroke(e, 255))
        self.canvas.bind("<ButtonRelease-1>", lambda _e: self._end_stroke())
        self.canvas.bind("<ButtonPress-3>", lambda e: self._start_stroke(e, 0))
        self.canvas.bind("<B3-Motion>", lambda e: self._move_stroke(e, 0))
        self.canvas.bind("<ButtonRelease-3>", lambda _e: self._end_stroke())

        bot = ttk.Frame(root_pad)
        bot.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(bot, text="取消", command=self.destroy).pack(side=tk.RIGHT)
        ttk.Button(bot, text="🚫 清除蒙版 (改回整图 Img2Img)", command=self._disable_mask).pack(side=tk.RIGHT, padx=6)
        ttk.Button(bot, text="✅ 保存蒙版并启用局部重绘", style="Accent.TButton", command=self._save_and_close).pack(
            side=tk.RIGHT, padx=(0, 6)
        )

        self._render_preview()

    def _push_undo(self) -> None:
        buf = io.BytesIO()
        self.mask_img.save(buf, format="PNG")
        self._undo_stack.append(buf.getvalue())
        if len(self._undo_stack) > 15:
            self._undo_stack.pop(0)

    def _to_orig(self, cx: int, cy: int) -> Tuple[int, int]:
        ox = int(round(max(0, min(self.disp_w - 1, cx)) / self.scale))
        oy = int(round(max(0, min(self.disp_h - 1, cy)) / self.scale))
        return ox, oy

    def _paint_segment(self, p1: Tuple[int, int], p2: Tuple[int, int], val: int) -> None:
        r = max(2, int(self.var_brush.get()))
        draw = ImageDraw.Draw(self.mask_img)
        draw.line([p1, p2], fill=val, width=r * 2)
        for px, py in (p1, p2):
            draw.ellipse([px - r, py - r, px + r, py + r], fill=val)

    def _start_stroke(self, event: tk.Event, val: int) -> None:  # type: ignore[type-arg]
        self._push_undo()
        pt = self._to_orig(event.x, event.y)
        self._last_pt = pt
        self._paint_segment(pt, pt, val)
        self._render_preview()

    def _move_stroke(self, event: tk.Event, val: int) -> None:  # type: ignore[type-arg]
        pt = self._to_orig(event.x, event.y)
        prev = self._last_pt or pt
        self._paint_segment(prev, pt, val)
        self._last_pt = pt
        self._render_preview()

    def _end_stroke(self) -> None:
        self._last_pt = None

    def _undo(self) -> None:
        if not self._undo_stack:
            return
        raw = self._undo_stack.pop()
        self.mask_img = Image.open(io.BytesIO(raw)).convert("L")
        self._render_preview()

    def _invert(self) -> None:
        self._push_undo()
        self.mask_img = self.mask_img.point(lambda v: 0 if v > 127 else 255)
        self._render_preview()

    def _clear_all(self) -> None:
        self._push_undo()
        self.mask_img = Image.new("L", (self.orig_w, self.orig_h), 0)
        self._render_preview()

    def _render_preview(self) -> None:
        if ImageTk is None:
            return
        mask_small = self.mask_img.resize((self.disp_w, self.disp_h), Image.Resampling.NEAREST)
        alpha = mask_small.point(lambda v: 145 if v > 127 else 0)
        red_overlay = Image.new("RGBA", (self.disp_w, self.disp_h), (225, 29, 72, 0))
        red_overlay.putalpha(alpha)
        comp = Image.alpha_composite(self._display_base, red_overlay)
        self._tk_img = ImageTk.PhotoImage(comp)
        self.canvas.delete("all")
        self.canvas.create_image(0, 0, anchor=tk.NW, image=self._tk_img)

    def _disable_mask(self) -> None:
        self.on_save(None)
        self.destroy()

    def _save_and_close(self) -> None:
        png_bytes = render_binary_mask_png(self.mask_img)
        if png_bytes is None:
            messagebox.showwarning("未涂抹区域", "尚未涂抹任何重绘区域！若只需整图垫图重绘，请点「清除蒙版」。", parent=self)
            return
        self.on_save(png_bytes)
        self.destroy()


class MossLayoutDialog(tk.Toplevel):
    """OpenMOSS MOSS-Image 可视化空间构图框画板（自动换算中心原点 abs_centralized yxyx JSON）"""

    def __init__(
        self,
        parent: tk.Misc,
        canvas_w: int,
        canvas_h: int,
        initial_prompt: str,
        on_compile: Callable[[str], None],
        ico_path: Optional[Path | str] = None,
    ) -> None:
        super().__init__(parent)
        self.title(f"📐 MOSS-Image 可视化空间构图画板 ({canvas_w}×{canvas_h} · 中心原点坐标系)")
        if ico_path and Path(ico_path).is_file():
            apply_tk_window_icon(self, ico_path)
        self.transient(parent)  # type: ignore[arg-type]
        self.grab_set()

        self.target_w = max(256, (canvas_w // 16) * 16)
        self.target_h = max(256, (canvas_h // 16) * 16)
        self.on_compile = on_compile

        max_side = 500
        self.scale = min(max_side / self.target_w, max_side / self.target_h)
        self.disp_w = max(64, (int(round(self.target_w * self.scale)) // 2) * 2)
        self.disp_h = max(64, (int(round(self.target_h * self.scale)) // 2) * 2)

        default_summary, self.boxes = parse_moss_layout_json(initial_prompt)
        self._drag_start: Optional[Tuple[int, int]] = None
        self._temp_rect_id: Optional[int] = None

        ui_font = "Microsoft YaHei UI" if sys.platform == "win32" else "Sans"
        self.geometry("920x640")
        pad = ttk.Frame(self, padding=12)
        pad.pack(fill=tk.BOTH, expand=True)

        top_f = ttk.Frame(pad)
        top_f.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(top_f, text="全局画面与风格总述 (summary.caption):", style="Header.TLabel").pack(anchor=tk.W)
        self.var_summary = tk.StringVar(
            value=default_summary or "一张构图精致的高清插画海报，光影通透细腻，细节丰富"
        )
        ttk.Entry(top_f, textvariable=self.var_summary, font=(ui_font, 10)).pack(fill=tk.X, pady=(2, 0))

        mid = ttk.Frame(pad)
        mid.pack(fill=tk.BOTH, expand=True)

        left_c = ttk.LabelFrame(mid, text="1. 在画布上按住鼠标左键拖拽拉出位置框", padding=8)
        left_c.pack(side=tk.LEFT, fill=tk.BOTH)
        self.canvas = tk.Canvas(
            left_c,
            width=self.disp_w,
            height=self.disp_h,
            bg="#f8fafc",
            highlightthickness=1,
            highlightbackground="#64748b",
            cursor="crosshair",
        )
        self.canvas.pack(padx=6, pady=6)
        self.canvas.bind("<ButtonPress-1>", self._on_down)
        self.canvas.bind("<B1-Motion>", self._on_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_up)

        right_c = ttk.LabelFrame(mid, text="2. 已添加的空间区域元素（选中可编辑或删除）", padding=8)
        right_c.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))

        self.listbox = tk.Listbox(right_c, height=10, font=(ui_font, 9))
        self.listbox.pack(fill=tk.X, pady=(0, 8))
        self.listbox.bind("<<ListboxSelect>>", self._on_select_box)

        form = ttk.Frame(right_c)
        form.pack(fill=tk.X)
        ttk.Label(form, text="元素类型:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.var_kind = tk.StringVar(value="object")
        r_k = ttk.Frame(form)
        r_k.grid(row=0, column=1, sticky=tk.W, pady=3)
        ttk.Radiobutton(r_k, text="🎨 主体/物体 (object)", variable=self.var_kind, value="object").pack(side=tk.LEFT)
        ttk.Radiobutton(r_k, text="🔤 画面文字 (text)", variable=self.var_kind, value="text").pack(side=tk.LEFT, padx=8)

        ttk.Label(form, text="区域画面描述:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.var_item_cap = tk.StringVar(value="")
        ttk.Entry(form, textvariable=self.var_item_cap, width=34).grid(row=1, column=1, sticky=tk.EW, pady=3)

        ttk.Label(form, text="渲染文字内容(仅text填):").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.var_item_txt = tk.StringVar(value="")
        ttk.Entry(form, textvariable=self.var_item_txt, width=34).grid(row=2, column=1, sticky=tk.EW, pady=3)
        form.columnconfigure(1, weight=1)

        btn_edit = ttk.Frame(right_c)
        btn_edit.pack(fill=tk.X, pady=8)
        ttk.Button(btn_edit, text="💾 更新选中框描述", command=self._update_selected).pack(side=tk.LEFT)
        ttk.Button(btn_edit, text="🗑️ 删除选中框", command=self._delete_selected).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_edit, text="🧹 清空全部框", command=self._clear_boxes).pack(side=tk.RIGHT)

        bot = ttk.Frame(pad)
        bot.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(bot, text="取消", command=self.destroy).pack(side=tk.RIGHT)
        ttk.Button(
            bot,
            text="✅ 编译为 MOSS 空间 JSON 并填入正向提示词",
            style="Accent.TButton",
            command=self._compile_and_close,
        ).pack(side=tk.RIGHT, padx=8)

        self._ui_font = ui_font
        self._redraw()

    def _on_down(self, e: tk.Event) -> None:  # type: ignore[type-arg]
        self._drag_start = (e.x, e.y)

    def _on_drag(self, e: tk.Event) -> None:  # type: ignore[type-arg]
        if not self._drag_start:
            return
        if self._temp_rect_id is not None:
            self.canvas.delete(self._temp_rect_id)
        x0, y0 = self._drag_start
        self._temp_rect_id = self.canvas.create_rectangle(x0, y0, e.x, e.y, outline="#e11d48", width=2, dash=(4, 2))

    def _on_up(self, e: tk.Event) -> None:  # type: ignore[type-arg]
        if not self._drag_start:
            return
        x0, y0 = self._drag_start
        self._drag_start = None
        if self._temp_rect_id is not None:
            self.canvas.delete(self._temp_rect_id)
            self._temp_rect_id = None
        if abs(e.x - x0) < 12 or abs(e.y - y0) < 12:
            return
        cx1, cy1 = canvas_pt_to_centered(min(x0, e.x), min(y0, e.y), self.disp_w, self.disp_h, self.target_w, self.target_h)
        cx2, cy2 = canvas_pt_to_centered(max(x0, e.x), max(y0, e.y), self.disp_w, self.disp_h, self.target_w, self.target_h)
        kind = self.var_kind.get()
        cap = self.var_item_cap.get().strip() or (
            "醒目的双语排版标题文字" if kind == "text" else f"区域主体元素 #{len(self.boxes) + 1}"
        )
        txt = self.var_item_txt.get().strip()
        self.boxes.append(
            {
                "label": kind,
                "caption": cap,
                "text": txt if kind == "text" else "",
                "bbox": [cy1, cx1, cy2, cx2],  # yxyx
            }
        )
        self._redraw(select_idx=len(self.boxes) - 1)

    def _on_select_box(self, _e: Any = None) -> None:
        sel = self.listbox.curselection()
        if not sel:
            return
        b = self.boxes[sel[0]]
        self.var_kind.set(b["label"])
        self.var_item_cap.set(b["caption"])
        self.var_item_txt.set(b.get("text", ""))
        self._redraw(select_idx=sel[0], refresh_list=False)

    def _update_selected(self) -> None:
        sel = self.listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        kind = self.var_kind.get()
        self.boxes[idx]["label"] = kind
        self.boxes[idx]["caption"] = self.var_item_cap.get().strip()
        self.boxes[idx]["text"] = self.var_item_txt.get().strip() if kind == "text" else ""
        self._redraw(select_idx=idx)

    def _delete_selected(self) -> None:
        sel = self.listbox.curselection()
        if not sel:
            return
        self.boxes.pop(sel[0])
        self._redraw()

    def _clear_boxes(self) -> None:
        self.boxes.clear()
        self._redraw()

    def _redraw(self, select_idx: Optional[int] = None, refresh_list: bool = True) -> None:
        self.canvas.delete("all")
        mx, my = self.disp_w // 2, self.disp_h // 2
        self.canvas.create_line(mx, 0, mx, self.disp_h, fill="#cbd5e1", dash=(3, 3))
        self.canvas.create_line(0, my, self.disp_w, my, fill="#cbd5e1", dash=(3, 3))
        self.canvas.create_text(mx + 4, my + 4, text="(0,0)", anchor=tk.NW, fill="#94a3b8", font=("Consolas", 8))

        if refresh_list:
            self.listbox.delete(0, tk.END)
        for i, b in enumerate(self.boxes):
            y1, x1, y2, x2 = b["bbox"]
            dx1, dy1 = centered_pt_to_canvas(x1, y1, self.disp_w, self.disp_h, self.target_w, self.target_h)
            dx2, dy2 = centered_pt_to_canvas(x2, y2, self.disp_w, self.disp_h, self.target_w, self.target_h)
            is_sel = i == select_idx
            color = "#be123c" if b["label"] == "text" else "#0284c7"
            self.canvas.create_rectangle(dx1, dy1, dx2, dy2, outline=color, width=3 if is_sel else 2)
            tag_txt = f"#{i + 1} [{b['label']}] {b.get('text') or b['caption'][:10]}"
            self.canvas.create_text(
                dx1 + 4,
                dy1 + 4,
                text=tag_txt,
                anchor=tk.NW,
                fill=color,
                font=(self._ui_font, 8, "bold"),
            )
            if refresh_list:
                self.listbox.insert(tk.END, f"#{i + 1} [{b['label']}] {b['caption']} {b['bbox']}")
        if refresh_list and select_idx is not None and 0 <= select_idx < len(self.boxes):
            self.listbox.selection_set(select_idx)

    def _compile_and_close(self) -> None:
        if not self.boxes:
            messagebox.showwarning("尚未拉框", "请先在左侧画布上按住鼠标左键拖出至少 1 个区域框！", parent=self)
            return
        compiled = compile_moss_layout_json(self.var_summary.get(), self.boxes)
        self.on_compile(compiled)
        self.destroy()


class GallerySidebar(ttk.LabelFrame):
    """本地作品画廊侧边栏（解密产物以明文落盘便于系统查看；配方元数据索引由 DPAPI / POSIX 0600 保护）"""

    def __init__(
        self,
        parent: tk.Misc,
        output_dir: str,
        on_restore_recipe: Callable[[Dict[str, Any]], None],
        on_send_to_img2img: Callable[[str], None],
        on_send_to_i2v: Callable[[str], None],
    ) -> None:
        super().__init__(parent, text="🖼️ 本地作品画廊（明文产物 · DPAPI/0600 配方索引）", padding=8)
        self.output_dir = output_dir
        self.on_restore_recipe = on_restore_recipe
        self.on_send_to_img2img = on_send_to_img2img
        self.on_send_to_i2v = on_send_to_i2v
        self._thumb_ref: Any = None
        self._files: List[str] = []
        self._vault: Dict[str, Dict[str, Any]] = {}

        self.preview_lbl = tk.Label(
            self,
            text="暂无选中产物\n解密明文落盘后自动在此预览",
            width=28,
            height=11,
            bg="#f1f5f9",
            fg="#64748b",
            relief=tk.GROOVE,
        )
        self.preview_lbl.pack(fill=tk.X, pady=(0, 6))
        self.preview_lbl.bind("<Double-Button-1>", lambda _e: self.open_selected_file())

        self.var_meta = tk.StringVar(value="产物以明文落盘至输出目录，配方索引由 DPAPI/0600 保护（双击打开）")
        ttk.Label(self, textvariable=self.var_meta, foreground="#334155", wraplength=240, justify=tk.LEFT).pack(
            anchor=tk.W, pady=(0, 4)
        )

        list_frame = ttk.Frame(self)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 6))
        sb = ttk.Scrollbar(list_frame, orient=tk.VERTICAL)
        self.listbox = tk.Listbox(list_frame, height=7, font=("Consolas", 9), yscrollcommand=sb.set)
        sb.configure(command=self.listbox.yview)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)
        self.listbox.bind("<Double-Button-1>", lambda _e: self.open_selected_file())

        b1 = ttk.Frame(self)
        b1.pack(fill=tk.X, pady=2)
        ttk.Button(b1, text="🔒 复刻参数&Seed", command=self._act_restore).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 2)
        )
        ttk.Button(b1, text="🖌️ 垫图/局部重绘", command=self._act_img2img).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(2, 0)
        )

        b2 = ttk.Frame(self)
        b2.pack(fill=tk.X, pady=2)
        ttk.Button(b2, text="🎬 设为图生视频 (I2V) 首帧", command=self._act_i2v).pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )

        b3 = ttk.Frame(self)
        b3.pack(fill=tk.X, pady=(2, 0))
        ttk.Button(b3, text="🔍 打开原文件", command=self.open_selected_file).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 2)
        )
        ttk.Button(b3, text="🔄 刷新画廊", command=self.refresh).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(2, 0)
        )

        self.refresh()

    def refresh(self, select_latest: bool = False) -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        self._vault = load_gallery_vault(self.output_dir)
        valid_exts = (".png", ".jpg", ".jpeg", ".webp", ".mp4")
        all_f = [
            os.path.join(self.output_dir, fn)
            for fn in os.listdir(self.output_dir)
            if not fn.startswith(".") and fn.lower().endswith(valid_exts)
        ]
        all_f.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        self._files = all_f[:120]

        self.listbox.delete(0, tk.END)
        for p in self._files:
            bn = os.path.basename(p)
            icon = "🎬" if bn.lower().endswith(".mp4") else "🖼️"
            self.listbox.insert(tk.END, f"{icon} {bn}")

        if self._files and (select_latest or not self.listbox.curselection()):
            self.listbox.selection_set(0)
            self._on_select()

    def _selected_path(self) -> Optional[str]:
        sel = self.listbox.curselection()
        if not sel or sel[0] >= len(self._files):
            return None
        return self._files[sel[0]]

    def _on_select(self, _e: Any = None) -> None:
        path = self._selected_path()
        if not path or not os.path.exists(path):
            return
        bn = os.path.basename(path)
        meta = self._vault.get(bn, {})
        seed_s = str(meta.get("seed", "未知"))
        mdl_s = str(meta.get("model") or meta.get("preset") or "本地产物")
        wh_s = f"{meta.get('width', '?')}×{meta.get('height', '?')}" if meta.get("width") else ""
        self.var_meta.set(f"模型: {mdl_s} | Seed: {seed_s} {wh_s}".strip())

        if path.lower().endswith(".mp4") or ImageTk is None:
            self._thumb_ref = None
            sz_mb = os.path.getsize(path) / (1024 * 1024)
            label_kind = "🎬 高清视频产物" if path.lower().endswith(".mp4") else "🖼️ 图像产物"
            self.preview_lbl.configure(
                image="",
                text=f"{label_kind}\n{bn}\n({sz_mb:.1f} MB · 双击打开)",
                width=28,
                height=11,
            )
            return

        try:
            im = Image.open(path).convert("RGB")
            w0, h0 = im.size
            im.thumbnail((236, 210), Image.Resampling.LANCZOS)
            canvas_im = Image.new("RGB", (236, 210), (241, 245, 249))
            canvas_im.paste(im, ((236 - im.width) // 2, (210 - im.height) // 2))
            self._thumb_ref = ImageTk.PhotoImage(canvas_im)
            self.preview_lbl.configure(image=self._thumb_ref, text="", width=236, height=210)
            if not wh_s:
                self.var_meta.set(f"模型: {mdl_s} | Seed: {seed_s} | {w0}×{h0}")
        except Exception:
            self._thumb_ref = None
            self.preview_lbl.configure(image="", text="无法预览缩略图", width=28, height=11)

    def open_selected_file(self) -> None:
        path = self._selected_path()
        if path and os.path.exists(path):
            open_path_cross_platform(path)

    def _act_restore(self) -> None:
        path = self._selected_path()
        if not path:
            return
        bn = os.path.basename(path)
        meta = self._vault.get(bn)
        if not meta or not meta.get("prompt"):
            messagebox.showinfo(
                "提示",
                "该早期产物未记录完整提示词配方（新产物以明文落盘，对应配方索引由本机 DPAPI/0600 保护）。",
            )
            return
        restored = dict(meta)
        restored["_is_image"] = not path.lower().endswith(".mp4")
        self.on_restore_recipe(restored)

    def _act_img2img(self) -> None:
        path = self._selected_path()
        if not path:
            return
        if path.lower().endswith(".mp4"):
            messagebox.showwarning("格式提示", "请选择静态图片文件作为垫图或局部重绘底图！")
            return
        self.on_send_to_img2img(path)

    def _act_i2v(self) -> None:
        path = self._selected_path()
        if not path:
            return
        if path.lower().endswith(".mp4"):
            messagebox.showwarning("格式提示", "请选择一张静态图片作为图生视频首帧！")
            return
        self.on_send_to_i2v(path)
