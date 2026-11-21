# -*- coding: utf-8 -*-
"""
零信任密码学原语、跨平台静态凭据保险箱与主流开源模型预设 (kiss_shot/crypto.py)

核心安全特性：
1. 密钥派生：遵循 OWASP 推荐标准，采用 PBKDF2-HMAC-SHA256 (210,000 次迭代) + 128-bit 随机盐。
2. 密码学域分离 (Domain Separation) 与 TTL 防重放：
   指令载荷 (AAD_PAYLOAD)、异步队列任务 (AAD_QUEUE)、握手票据 (AAD_TICKET)、二进制附件 (AAD_BLOB)
   与加密归档外层信封 (AAD_ARCHIVE) 各自绑定独立 AAD 标签，阻断同口令跨通道密文嫁接；
   结构化载荷与队列任务内置签发时间戳校验（默认 24h 过期）。
3. 流式会话隔离：每次启动远程网关自动生成随机 128-bit 会话盐与动态路径 (/v1/ks-<random>)，
   封装于 KISSSHOT_TICKET:... 握手票据中，消除固定路由与固定会话密钥特征。
4. 双层 AEAD 归档与反压缩炸弹：异步产物在内存中采用 256-bit WinZip AES (WZ_AES) + ZIP_STORED 无压缩封装，
   外层再施加完整 AES-256-GCM 整包信封抹除 ZIP 文件头；解包端强制拒绝任何压缩条目并实行流式总字节熔断。
5. 本机凭据与画廊配方静态保护：Windows 下采用系统级 DPAPI (CryptProtectData) 绑定当前登录账户加密落盘；
   Linux/macOS 下采用原子写入与严格 0600 属主读写权限隔离。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

import pyzipper
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KDF_ITERATIONS = 210_000
SALT_BYTES = 16
NONCE_BYTES = 12
AEAD_TAG_BYTES = 16

AAD_PAYLOAD = b"kissshot-payload-v2"
AAD_QUEUE = b"kissshot-queue-v2"
AAD_TICKET = b"kissshot-ticket-v2"
AAD_BLOB = b"kissshot-blob-v2"
AAD_ARCHIVE = b"kissshot-archive-v2"

MAX_PAYLOAD_TTL_SECONDS = 86_400
MAX_ARCHIVE_UNPACK_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB streaming fuse

DEFAULT_LOCAL_PORT = 18443
DEFAULT_MODEL_ALIAS = "kiss-shot-llm"
DEFAULT_MAILBOX_REPO_NAME = "kissshot-ephemeral-relay"
GALLERY_VAULT_FILENAME = ".kissshot_gallery_vault.json"
TICKET_PREFIX = "KISSSHOT_TICKET:"
TICKET_PATTERN = re.compile(r"KISSSHOT_TICKET:([0-9a-fA-F]{64,})")

_SAFE_INNER_RE = re.compile(r"^chunk_[0-9]{3,5}\.dat$")
_SAFE_EXT_RE = re.compile(r"^[A-Za-z0-9]{1,8}$")
_HF_REPO_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_DPAPI_ENTROPY = b"kiss-shot-dpapi-v2"

# 面向科研与开发的标准主流开源模型预设（中立合规基线）
MEDIA_PRESETS: Dict[str, Dict[str, Any]] = {
    "moss_image_sft": {
        "label": "OpenMOSS MOSS-Image-SFT (5B DiT + Qwen3.5 · 空间 BBox 构图与双语文字排版)",
        "category": "image_t2i",
        "src_repo": "OpenMOSS-Team/MOSS-Image-SFT",
        "arch": "moss",
        "variant": None,
        "skip_root_safetensors": False,
        "default_width": 1024,
        "default_height": 1344,
        "default_steps": 28,
        "default_cfg": 3.0,
        "default_frames": 1,
        "default_pos": "一张光影通透细腻的高清建筑与自然风景插画，清晨薄雾中的玻璃植物园，超高清细节",
        "default_neg": "",
    },
    "sdxl_base_1_0": {
        "label": "Stable Diffusion XL Base 1.0 (FP16 · 1024x1024 通用文生图 / 局部重绘)",
        "category": "image_t2i",
        "src_repo": "stabilityai/stable-diffusion-xl-base-1.0",
        "arch": "sdxl",
        "variant": "fp16",
        "skip_root_safetensors": False,
        "default_width": 1024,
        "default_height": 1024,
        "default_steps": 28,
        "default_cfg": 5.5,
        "default_frames": 1,
        "default_pos": "cinematic architectural photography, warm sunlight, ultra detailed, 8k resolution",
        "default_neg": "blurry, low quality, distorted, watermark, text, artifacts",
    },
    "flux_1_schnell": {
        "label": "FLUX.1-schnell (Apache-2.0 · 4步极速高保真文生图 / 垫图微调)",
        "category": "image_t2i",
        "src_repo": "black-forest-labs/FLUX.1-schnell",
        "arch": "flux",
        "variant": None,
        "skip_root_safetensors": False,
        "default_width": 1024,
        "default_height": 1024,
        "default_steps": 4,
        "default_cfg": 0.0,
        "default_frames": 1,
        "default_pos": "minimalist industrial product design render on studio backdrop, soft rim lighting",
        "default_neg": "",
    },
    "wan2_1_t2v_1_3b": {
        "label": "Wan 2.1 T2V 1.3B (Apache-2.0 · 轻量级 480P 文生视频)",
        "category": "video_t2v",
        "src_repo": "Wan-AI/Wan2.1-T2V-1.3B-Diffusers",
        "arch": "wan_t2v",
        "variant": None,
        "skip_root_safetensors": False,
        "default_width": 832,
        "default_height": 480,
        "default_steps": 30,
        "default_cfg": 5.0,
        "default_frames": 81,
        "default_pos": "aerial drone shot over misty pine forest at sunrise, smooth camera motion, natural lighting",
        "default_neg": "overexposed, static frame, blurry details, subtitles, compression artifacts",
    },
    "wan2_2_ti2v_5b": {
        "label": "Wan 2.2 TI2V 5B (Apache-2.0 · 720P 高清文生/图生视频双模)",
        "category": "video_ti2v",
        "src_repo": "Wan-AI/Wan2.2-TI2V-5B-Diffusers",
        "arch": "wan_ti2v_5b",
        "variant": None,
        "skip_root_safetensors": False,
        "default_width": 1280,
        "default_height": 704,
        "default_steps": 36,
        "default_cfg": 5.0,
        "default_frames": 81,
        "default_pos": "timelapse of ocean waves meeting basalt cliffs under golden hour clouds, crisp 720p detail",
        "default_neg": "overexposed, static, blurry, watermark, subtitles, deformed motion",
    },
    "hunyuan_video_1_5_t2v": {
        "label": "HunyuanVideo-1.5 720P T2V (Qwen2.5-VL 编码 · 720P 电影级文生视频)",
        "category": "video_t2v",
        "src_repo": "hunyuanvideo-community/HunyuanVideo-1.5-Diffusers-720p_t2v",
        "arch": "hunyuan15_t2v",
        "variant": None,
        "skip_root_safetensors": False,
        "default_width": 1280,
        "default_height": 720,
        "default_steps": 40,
        "default_cfg": 6.0,
        "default_frames": 81,
        "default_pos": "cinematic documentary footage of alpine glacier stream in morning sunlight, crisp 720p motion",
        "default_neg": "blurry, deformed motion, overexposed, flickering, subtitles, watermark",
    },
    "wan2_2_i2v_14b": {
        "label": "Wan 2.2 I2V A14B MoE (Apache-2.0 · 720P 旗舰图生视频 I2V)",
        "category": "video_i2v",
        "src_repo": "Wan-AI/Wan2.2-I2V-A14B-Diffusers",
        "arch": "wan_i2v",
        "variant": None,
        "skip_root_safetensors": False,
        "default_width": 1280,
        "default_height": 720,
        "default_steps": 30,
        "default_cfg": 5.0,
        "default_frames": 81,
        "default_pos": "natural subtle motion, gentle breeze moving foliage and reflections, smooth camera push-in",
        "default_neg": "overexposed, static frame, blurry details, subtitles, deformed structure",
    },
}

ARCH_PRESETS: Dict[str, Dict[str, Any]] = {
    "moss": {
        "label": "MOSS-Image 系生图 (OpenMOSS · 空间 BBox 构图与双语排版)",
        "category": "image_t2i",
        "default_width": 1024,
        "default_height": 1344,
        "default_steps": 28,
        "default_cfg": 3.0,
        "default_frames": 1,
        "default_pos": "high-detail architectural illustration in soft morning light, clean composition",
        "default_neg": "",
    },
    "sdxl": {
        "label": "SDXL 生图 (Diffusers 或单文件 .safetensors)",
        "category": "image_t2i",
        "default_width": 1024,
        "default_height": 1024,
        "default_steps": 28,
        "default_cfg": 5.5,
        "default_frames": 1,
        "default_pos": "cinematic landscape photography, crisp details, 8k resolution",
        "default_neg": "blurry, low quality, distorted, watermark, artifacts",
    },
    "flux": {
        "label": "FLUX 系生图 (FLUX.1-schnell / dev / Diffusers 衍生仓库)",
        "category": "image_t2i",
        "default_width": 1024,
        "default_height": 1024,
        "default_steps": 24,
        "default_cfg": 3.5,
        "default_frames": 1,
        "default_pos": "minimalist studio design photography, natural rim lighting, ultra detailed",
        "default_neg": "",
    },
    "wan_ti2v_5b": {
        "label": "Wan 2.2 TI2V 5B 双模视频 (T2V / I2V Diffusers · 24fps)",
        "category": "video_ti2v",
        "default_width": 1280,
        "default_height": 704,
        "default_steps": 36,
        "default_cfg": 5.0,
        "default_frames": 81,
        "default_pos": "timelapse of ocean waves meeting basalt cliffs under golden hour clouds, crisp 720p detail",
        "default_neg": "overexposed, static, blurry, watermark, subtitles, deformed motion",
    },
    "wan_t2v": {
        "label": "Wan 2.1 / 2.2 文生视频 (T2V Diffusers)",
        "category": "video_t2v",
        "default_width": 1280,
        "default_height": 704,
        "default_steps": 34,
        "default_cfg": 5.0,
        "default_frames": 81,
        "default_pos": "smooth aerial camera motion over mountain valley at sunrise, natural lighting",
        "default_neg": "overexposed, static, blurry, subtitles, compression artifacts",
    },
    "wan_i2v": {
        "label": "Wan 2.1 / 2.2 图生视频 (I2V Diffusers)",
        "category": "video_i2v",
        "default_width": 1280,
        "default_height": 720,
        "default_steps": 30,
        "default_cfg": 5.0,
        "default_frames": 81,
        "default_pos": "gentle natural camera motion, subtle atmospheric movement, crisp detail",
        "default_neg": "overexposed, static, blurry, deformed structure, watermark",
    },
    "cogvideox_i2v": {
        "label": "CogVideoX 图生视频 (CogVideoX-5B-I2V Diffusers)",
        "category": "video_i2v",
        "default_width": 1280,
        "default_height": 720,
        "default_steps": 40,
        "default_cfg": 6.0,
        "default_frames": 49,
        "default_pos": "smooth animated motion, gentle breeze, clean lines, steady camera push-in",
        "default_neg": "blurry, flickering, ghosting, deformed shapes, static",
    },
    "hunyuan15_t2v": {
        "label": "HunyuanVideo 1.5 文生视频 (720P T2V Diffusers)",
        "category": "video_t2v",
        "default_width": 1280,
        "default_height": 720,
        "default_steps": 40,
        "default_cfg": 6.0,
        "default_frames": 81,
        "default_pos": "cinematic natural scenery in soft golden light, smooth camera movement, 720p",
        "default_neg": "blurry, flickering, overexposed, watermark, subtitles",
    },
    "auto": {
        "label": "通用 Diffusers 自动识别管线 (DiffusionPipeline)",
        "category": "image_t2i",
        "default_width": 1024,
        "default_height": 1024,
        "default_steps": 28,
        "default_cfg": 5.0,
        "default_frames": 1,
        "default_pos": "high quality detailed digital illustration, soft lighting",
        "default_neg": "low quality, blurry, artifacts",
    },
}

LLM_PRESETS: Dict[str, Dict[str, Any]] = {
    "qwen2_5_vl_7b_q4km": {
        "label": "Qwen2.5-VL-7B-Instruct (GGUF Q4_K_M · 单卡 16GB+ 轻量多模态视觉推理)",
        "src_repo": "bartowski/Qwen2.5-VL-7B-Instruct-GGUF",
        "src_file": "Qwen2.5-VL-7B-Instruct-Q4_K_M.gguf",
        "mmproj_repo": "bartowski/Qwen2.5-VL-7B-Instruct-GGUF",
        "mmproj_file": "mmproj-Qwen2.5-VL-7B-Instruct-f16.gguf",
        "default_ctx": 16384,
        "default_img_tokens": 1280,
    },
    "qwen2_5_vl_72b_q4km": {
        "label": "Qwen2.5-VL-72B-Instruct (GGUF Q4_K_M · 48GB/80GB 旗舰多模态视觉推理)",
        "src_repo": "bartowski/Qwen2.5-VL-72B-Instruct-GGUF",
        "src_file": "Qwen2.5-VL-72B-Instruct-Q4_K_M.gguf",
        "mmproj_repo": "bartowski/Qwen2.5-VL-72B-Instruct-GGUF",
        "mmproj_file": "mmproj-Qwen2.5-VL-72B-Instruct-f16.gguf",
        "default_ctx": 16384,
        "default_img_tokens": 1280,
    },
    "llama_3_3_70b_q4km": {
        "label": "Llama-3.3-70B-Instruct (GGUF Q4_K_M · 纯文本代码与逻辑推理)",
        "src_repo": "bartowski/Llama-3.3-70B-Instruct-GGUF",
        "src_file": "Llama-3.3-70B-Instruct-Q4_K_M.gguf",
        "mmproj_repo": "",
        "mmproj_file": "",
        "default_ctx": 32768,
        "default_img_tokens": 0,
    },
}


def parse_hf_repo_id(raw: str) -> str:
    """支持直接输入 'author/model' 或完整 HuggingFace URL，清洗并校验为标准 repo_id"""
    s = (raw or "").strip()
    s = re.sub(r"^https?://(?:www\.)?(?:huggingface\.co|hf\.co)/", "", s, flags=re.IGNORECASE)
    s = re.sub(r"^models/", "", s, flags=re.IGNORECASE)
    s = s.split("?", 1)[0].split("#", 1)[0].strip("/")
    parts = [p for p in s.split("/") if p]
    if len(parts) >= 2:
        candidate = f"{parts[0]}/{parts[1]}"
        if _HF_REPO_ID_RE.fullmatch(candidate) and ".." not in candidate:
            return candidate
    raise ValueError("Invalid HuggingFace repository ID (expected 'owner/repo' or full https://huggingface.co/owner/repo URL)")


def build_custom_media_entry(item: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """将持久化的自定义生图/视频模型记录标准化为 MEDIA_PRESETS 兼容条目"""
    src_repo = parse_hf_repo_id(str(item["src_repo"]))
    arch = str(item.get("arch") or "sdxl").strip()
    if arch not in ARCH_PRESETS:
        arch = "auto"
    preset = ARCH_PRESETS[arch]
    key = str(item.get("key") or f"custom_{re.sub(r'[^a-z0-9]+', '_', src_repo.lower()).strip('_')[:40]}")
    if not key.startswith("custom_"):
        key = f"custom_{key}"
    note = str(item.get("note") or "").strip()
    disp_title = f"{note} ({src_repo})" if note else src_repo
    entry: Dict[str, Any] = {
        "label": f"[自定义 · {arch.upper()}] {disp_title}",
        "category": preset["category"],
        "src_repo": src_repo,
        "arch": arch,
        "variant": item.get("variant") or None,
        "skip_root_safetensors": bool(item.get("skip_root_safetensors", False)),
        "default_width": int(item.get("default_width", preset["default_width"])),
        "default_height": int(item.get("default_height", preset["default_height"])),
        "default_steps": int(item.get("default_steps", preset["default_steps"])),
        "default_cfg": float(item.get("default_cfg", preset["default_cfg"])),
        "default_frames": int(item.get("default_frames", preset["default_frames"])),
        "default_pos": str(item.get("default_pos", preset["default_pos"])),
        "default_neg": str(item.get("default_neg", preset["default_neg"])),
        "is_custom": True,
    }
    return key, entry


def get_merged_media_presets(custom_models: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = dict(MEDIA_PRESETS)
    for raw_item in custom_models or []:
        try:
            k, entry = build_custom_media_entry(raw_item)
            merged[k] = entry
        except Exception:
            continue
    return merged


def build_custom_llm_entry(item: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """将持久化的自定义 GGUF 大语言模型记录标准化为 LLM_PRESETS 兼容条目"""
    src_repo = parse_hf_repo_id(str(item["src_repo"]))
    src_file = str(item["src_file"]).strip().lstrip("/")
    if not src_file or ".." in src_file:
        raise ValueError("GGUF weight filename must not be empty")
    mmproj_repo_raw = str(item.get("mmproj_repo") or "").strip()
    mmproj_file = str(item.get("mmproj_file") or "").strip().lstrip("/")
    mmproj_repo = parse_hf_repo_id(mmproj_repo_raw) if (mmproj_repo_raw and mmproj_file) else (src_repo if mmproj_file else "")
    key = str(item.get("key") or f"custom_llm_{re.sub(r'[^a-z0-9]+', '_', (src_repo + '_' + src_file).lower()).strip('_')[:44]}")
    if not key.startswith("custom_llm_"):
        key = f"custom_llm_{key}"
    mode_tag = "VLM-GGUF" if mmproj_file else "GGUF"
    note = str(item.get("note") or "").strip()
    disp = f"{note} · {src_file}" if note else f"{src_repo} / {src_file}"
    entry: Dict[str, Any] = {
        "label": f"[自定义 · {mode_tag}] {disp}",
        "src_repo": src_repo,
        "src_file": src_file,
        "mmproj_repo": mmproj_repo,
        "mmproj_file": mmproj_file,
        "default_ctx": int(item.get("default_ctx", 16384)),
        "default_img_tokens": int(item.get("default_img_tokens", 1280 if mmproj_file else 0)),
        "is_custom": True,
    }
    return key, entry


def get_merged_llm_presets(custom_llms: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = dict(LLM_PRESETS)
    for raw_item in custom_llms or []:
        try:
            k, entry = build_custom_llm_entry(raw_item)
            merged[k] = entry
        except Exception:
            continue
    return merged


# ==================== Cross-Platform Local Vault (DPAPI / POSIX 0600) ====================
if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _CRYPTPROTECT_UI_FORBIDDEN = 0x01

    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    _crypt32.CryptProtectData.restype = wintypes.BOOL

    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    _kernel32.LocalFree.restype = wintypes.HLOCAL

    def _make_blob(raw: bytes) -> Tuple[_DATA_BLOB, Any]:
        buf = ctypes.create_string_buffer(raw, len(raw))
        blob = _DATA_BLOB(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        return blob, buf

    def _dpapi_seal(raw: bytes) -> bytes:
        in_blob, _in_ref = _make_blob(raw)
        ent_blob, _ent_ref = _make_blob(_DPAPI_ENTROPY)
        out_blob = _DATA_BLOB()
        if not _crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            "kiss-shot-vault",
            ctypes.byref(ent_blob),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        ):
            raise OSError(f"DPAPI CryptProtectData failed: {ctypes.get_last_error()}")
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            _kernel32.LocalFree(out_blob.pbData)

    def _dpapi_open(enc: bytes) -> bytes:
        in_blob, _in_ref = _make_blob(enc)
        ent_blob, _ent_ref = _make_blob(_DPAPI_ENTROPY)
        out_blob = _DATA_BLOB()
        if not _crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            ctypes.byref(ent_blob),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        ):
            raise OSError(f"DPAPI CryptUnprotectData failed: {ctypes.get_last_error()}")
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            _kernel32.LocalFree(out_blob.pbData)


def save_encrypted_secrets(file_path: str, data: Dict[str, Any]) -> None:
    """将本地敏感配置原子加密落盘（Windows 使用 DPAPI；Linux/macOS 强制 0600 属主权限）"""
    parent = os.path.dirname(os.path.abspath(file_path)) or "."
    os.makedirs(parent, exist_ok=True)
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")

    if sys.platform == "win32":
        envelope = {"_vault": "dpapi_v2", "blob": _dpapi_seal(raw).hex()}
    else:
        envelope = {"_vault": "posix_0600_v2", "blob": base64.b64encode(raw).decode("ascii")}

    fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".ks_vault_", suffix=".tmp")
    try:
        if sys.platform != "win32":
            os.chmod(tmp_path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(envelope, f, ensure_ascii=False)
        os.replace(tmp_path, file_path)
        if sys.platform != "win32":
            os.chmod(file_path, 0o600)
    except Exception:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        raise


def load_encrypted_secrets(file_path: str, defaults: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """读取并解密本地凭据保险箱；若遇旧版明文文件则自动原地升级为受保护格式"""
    base = dict(defaults or {})
    if not os.path.exists(file_path):
        return base
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            return base
        vault_kind = obj.get("_vault")
        if vault_kind == "dpapi_v2" and sys.platform == "win32":
            dec = json.loads(_dpapi_open(bytes.fromhex(str(obj["blob"]))).decode("utf-8"))
            if isinstance(dec, dict):
                base.update(dec)
            return base
        if vault_kind == "posix_0600_v2":
            dec = json.loads(base64.b64decode(str(obj["blob"])).decode("utf-8"))
            if isinstance(dec, dict):
                base.update(dec)
            return base
        # 旧版明文 JSON 自动原地迁移升级
        base.update(obj)
        try:
            save_encrypted_secrets(file_path, base)
        except Exception:
            pass
        return base
    except Exception:
        return base


def _read_encrypted_secrets_strict(file_path: str) -> Dict[str, Any]:
    """严格读取并解密本地保险箱；文件损坏、格式异常或解密失败直接抛错，绝不静默返回空字典。"""
    with open(file_path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise ValueError(f"Corrupted vault root structure in {file_path}")
    vault_kind = obj.get("_vault")
    if vault_kind == "dpapi_v2":
        if sys.platform != "win32":
            raise OSError("Cannot decrypt Windows DPAPI vault on a non-Windows platform")
        dec = json.loads(_dpapi_open(bytes.fromhex(str(obj["blob"]))).decode("utf-8"))
        if not isinstance(dec, dict):
            raise ValueError(f"Corrupted decrypted DPAPI vault payload in {file_path}")
        return dec
    if vault_kind == "posix_0600_v2":
        dec = json.loads(base64.b64decode(str(obj["blob"])).decode("utf-8"))
        if not isinstance(dec, dict):
            raise ValueError(f"Corrupted decoded POSIX vault payload in {file_path}")
        return dec
    if vault_kind is not None:
        raise ValueError(f"Unsupported vault format {vault_kind!r} in {file_path}")
    return obj


def load_gallery_vault(out_dir: str, for_update: bool = False) -> Dict[str, Dict[str, Any]]:
    """
    读取本地受保护的作品画廊配方索引（DPAPI / POSIX 0600）。
    - `for_update=True`（写入/迁移前）：若索引文件已存在但损坏、无法解密或结构异常，直接抛错拒绝覆盖写入，
      防止把用户历史配方索引静默清空；仅在索引文件不存在时返回空字典。
    - `for_update=False`（界面只读展示）：兼容容错返回空字典。
    """
    vault_p = os.path.join(os.path.abspath(out_dir), GALLERY_VAULT_FILENAME)
    if for_update:
        if not os.path.exists(vault_p):
            return {}
        raw = _read_encrypted_secrets_strict(vault_p)
        items = raw.get("items")
        if not isinstance(items, dict):
            raise ValueError(f"Corrupted gallery vault 'items' index in {vault_p}")
        return items
    raw = load_encrypted_secrets(vault_p, {"items": {}})
    items = raw.get("items")
    return items if isinstance(items, dict) else {}


def record_gallery_items(out_dir: str, paths: List[str], meta: Dict[str, Any]) -> None:
    """将新解密落盘的作品配方 (Seed/Prompt/模型参数) 写入本地受保护画廊索引（保留最近 500 条；坏索引拒写）"""
    if not paths:
        return
    abs_dir = os.path.abspath(out_dir)
    os.makedirs(abs_dir, exist_ok=True)
    vault_p = os.path.join(abs_dir, GALLERY_VAULT_FILENAME)
    items = load_gallery_vault(abs_dir, for_update=True)
    now_ts = int(time.time())
    for idx, p in enumerate(paths):
        bname = os.path.basename(p)
        rec = dict(meta or {})
        if isinstance(rec.get("seed"), int) and rec["seed"] >= 0 and len(paths) > 1:
            rec["seed"] = rec["seed"] + idx
        rec["saved_at"] = now_ts
        items[bname] = rec
    if len(items) > 500:
        sorted_keys = sorted(items.keys(), key=lambda k: int(items[k].get("saved_at", 0)), reverse=True)[:500]
        items = {k: items[k] for k in sorted_keys}
    save_encrypted_secrets(vault_p, {"items": items})


def migrate_output_vault(legacy_dir: str, target_dir: str) -> int:
    """无损迁移历史解密产物与加密画廊配方索引（自动防撞名重映射、坏索引拒写并在搬空后清理旧目录）"""
    src_abs = os.path.abspath(legacy_dir)
    dst_abs = os.path.abspath(target_dir)
    if os.path.normcase(src_abs) == os.path.normcase(dst_abs) or not os.path.isdir(src_abs):
        return 0
    entries = os.listdir(src_abs)
    if not entries:
        try:
            os.rmdir(src_abs)
        except OSError:
            pass
        return 0

    os.makedirs(dst_abs, exist_ok=True)
    src_vault = os.path.join(src_abs, GALLERY_VAULT_FILENAME)
    dst_vault = os.path.join(dst_abs, GALLERY_VAULT_FILENAME)
    legacy_items = load_gallery_vault(src_abs, for_update=True) if os.path.isfile(src_vault) else {}
    dst_items = load_gallery_vault(dst_abs, for_update=True) if os.path.isfile(dst_vault) else {}
    name_remap: Dict[str, str] = {}
    moved_media = 0

    for name in entries:
        if name == GALLERY_VAULT_FILENAME:
            continue
        sp = os.path.join(src_abs, name)
        if not os.path.isfile(sp):
            continue
        stem, ext = os.path.splitext(name)
        final_name = name
        dp = os.path.join(dst_abs, final_name)
        seq = 1
        while os.path.exists(dp):
            final_name = f"{stem}_m{seq}{ext}"
            dp = os.path.join(dst_abs, final_name)
            seq += 1
        shutil.move(sp, dp)
        name_remap[name] = final_name
        moved_media += 1

    if os.path.isfile(src_vault):
        if legacy_items:
            for old_k, rec in legacy_items.items():
                new_k = name_remap.get(old_k, old_k)
                dst_items.setdefault(new_k, rec)
            save_encrypted_secrets(dst_vault, {"items": dst_items})
        elif not os.path.isfile(dst_vault):
            shutil.move(src_vault, dst_vault)
        if os.path.isfile(src_vault):
            try:
                os.remove(src_vault)
            except OSError:
                pass

    if not os.listdir(src_abs):
        try:
            os.rmdir(src_abs)
        except OSError:
            pass
    return moved_media


# ==================== AEAD Primitives ====================
def derive_key(passphrase: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """使用 PBKDF2-HMAC-SHA256 从用户口令与随机盐派生 256-bit 密钥"""
    if not passphrase or not passphrase.strip():
        raise ValueError("Passphrase must not be empty / 加密口令不能为空")
    if len(salt) < SALT_BYTES:
        raise ValueError(f"Salt must be at least {SALT_BYTES} bytes")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def derive_session_cipher(passphrase: str, session_salt: bytes) -> AESGCM:
    """根据每次网关启动随机生成的 session_salt 派生独立会话 AES-256-GCM 密码器"""
    return AESGCM(derive_key(passphrase, session_salt))


def encrypt_payload_hex(
    data: Dict[str, Any],
    passphrase: str,
    aad: bytes = AAD_PAYLOAD,
    issued_at: Optional[int] = None,
) -> str:
    """将结构化字典附带签发时间戳用域分离 AES-256-GCM 认证加密并编码为十六进制"""
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    key = derive_key(passphrase, salt)
    wrapped = {
        "_ks_v": 2,
        "_ks_iat": int(time.time()) if issued_at is None else int(issued_at),
        "d": data,
    }
    plaintext = json.dumps(wrapped, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return (salt + nonce + ciphertext).hex()


def decrypt_payload_hex(
    hex_str: str,
    passphrase: str,
    aad: bytes = AAD_PAYLOAD,
    max_age_seconds: int = MAX_PAYLOAD_TTL_SECONDS,
) -> Dict[str, Any]:
    """校验域分离 AAD 与有效期限并解密十六进制 AES-256-GCM 载荷"""
    clean = "".join(hex_str.split())
    try:
        raw = bytes.fromhex(clean)
    except ValueError as exc:
        raise ValueError("Invalid hex payload / 密文不是合法的十六进制格式") from exc
    if len(raw) <= SALT_BYTES + NONCE_BYTES + AEAD_TAG_BYTES:
        raise ValueError("Truncated ciphertext / 密文长度不完整")
    salt = raw[:SALT_BYTES]
    nonce = raw[SALT_BYTES : SALT_BYTES + NONCE_BYTES]
    ciphertext = raw[SALT_BYTES + NONCE_BYTES :]
    key = derive_key(passphrase, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    parsed = json.loads(plaintext.decode("utf-8"))
    if isinstance(parsed, dict) and parsed.get("_ks_v") == 2 and "d" in parsed:
        iat = int(parsed.get("_ks_iat", 0) or 0)
        if max_age_seconds > 0 and (not iat or abs(time.time() - iat) > max_age_seconds):
            raise ValueError("Expired encrypted payload / 加密载荷已过期，请重新生成")
        inner = parsed["d"]
        if not isinstance(inner, dict):
            raise ValueError("Malformed inner payload")
        return inner
    return parsed


def encrypt_bytes_aes(
    raw_bytes: bytes,
    passphrase: str,
    aad: bytes = AAD_BLOB,
) -> bytes:
    """对任意二进制字节流执行带域分离 AAD 的纯内存 AES-256-GCM 认证加密"""
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    key = derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, raw_bytes, aad)
    return salt + nonce + ciphertext


def decrypt_bytes_aes(
    enc_bytes: bytes,
    passphrase: str,
    aad: bytes = AAD_BLOB,
) -> bytes:
    """校验域分离 AAD 并解密二进制字节流"""
    if len(enc_bytes) <= SALT_BYTES + NONCE_BYTES + AEAD_TAG_BYTES:
        raise ValueError("Truncated encrypted blob / 加密二进制数据不完整")
    salt = enc_bytes[:SALT_BYTES]
    nonce = enc_bytes[SALT_BYTES : SALT_BYTES + NONCE_BYTES]
    ciphertext = enc_bytes[SALT_BYTES + NONCE_BYTES :]
    key = derive_key(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def encrypt_queue_job(
    data: Dict[str, Any],
    passphrase: str,
    issued_at: Optional[int] = None,
) -> bytes:
    """封装异步密文信箱队列任务二进制密文（绑定独立 AAD_QUEUE 域标签与 24h TTL）"""
    wrapped = {
        "_ks_v": 2,
        "_ks_iat": int(time.time()) if issued_at is None else int(issued_at),
        "d": data,
    }
    pt = json.dumps(wrapped, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return encrypt_bytes_aes(pt, passphrase, aad=AAD_QUEUE)


def decrypt_queue_job(
    enc_bytes: bytes,
    passphrase: str,
    max_age_seconds: int = MAX_PAYLOAD_TTL_SECONDS,
) -> Dict[str, Any]:
    """校验 AAD_QUEUE 域分离与 24h TTL 并解封异步队列任务密文"""
    pt = decrypt_bytes_aes(enc_bytes, passphrase, aad=AAD_QUEUE)
    parsed = json.loads(pt.decode("utf-8"))
    if not isinstance(parsed, dict) or parsed.get("_ks_v") != 2 or "d" not in parsed:
        raise ValueError("Malformed queue job envelope / 队列任务信封结构异常")
    iat = int(parsed.get("_ks_iat", 0) or 0)
    if max_age_seconds > 0 and (not iat or abs(time.time() - iat) > max_age_seconds):
        raise ValueError("Expired queue job / 队列任务密文已过期")
    inner = parsed["d"]
    if not isinstance(inner, dict):
        raise ValueError("Malformed queue job payload")
    return inner


def aead_seal(cipher: AESGCM, plaintext: bytes, aad: bytes) -> bytes:
    """使用随机 96-bit Nonce 封装流式通信 AEAD 数据帧"""
    nonce = secrets.token_bytes(NONCE_BYTES)
    return nonce + cipher.encrypt(nonce, plaintext, aad)


def aead_open(cipher: AESGCM, wire: bytes, aad: bytes) -> bytes:
    """校验 AAD 与认证标签并解封流式通信 AEAD 数据帧"""
    if len(wire) < NONCE_BYTES + AEAD_TAG_BYTES:
        raise ValueError("Truncated AEAD frame / AEAD 数据帧长度不完整")
    return cipher.decrypt(wire[:NONCE_BYTES], wire[NONCE_BYTES:], aad)


def create_handshake_ticket(
    base_url: str,
    passphrase: str,
    route_path: str | None = None,
    session_salt: bytes | None = None,
) -> Tuple[str, str, bytes]:
    """
    生成包含动态路由路径与随机会话盐的端到端加密握手票据。
    返回: (ticket_string, route_path, session_salt_bytes)
    """
    clean_url = base_url.strip().rstrip("/")
    if not (
        clean_url.startswith("https://")
        or clean_url.startswith("http://127.0.0.1:")
        or clean_url.startswith("http://localhost:")
    ):
        raise ValueError("Endpoint must use https:// or localhost loopback")
    actual_route = route_path or f"/v1/ks-{secrets.token_hex(8)}"
    if not actual_route.startswith("/"):
        actual_route = "/" + actual_route
    actual_salt = session_salt or secrets.token_bytes(SALT_BYTES)
    ticket_obj = {
        "v": 2,
        "type": "kissshot_handshake",
        "url": clean_url,
        "route": actual_route,
        "salt": actual_salt.hex(),
        "ts": int(time.time()),
    }
    enc_hex = encrypt_payload_hex(ticket_obj, passphrase, aad=AAD_TICKET)
    return f"{TICKET_PREFIX}{enc_hex}", actual_route, actual_salt


def parse_handshake_ticket(
    raw_text: str,
    passphrase: str,
    max_age_seconds: int = MAX_PAYLOAD_TTL_SECONDS,
) -> Dict[str, Any]:
    """从文本或剪贴板内容中提取并验证 KISSSHOT_TICKET 握手票据"""
    text = (raw_text or "").strip()
    m = TICKET_PATTERN.search(text)
    hex_part = m.group(1) if m else text
    info = decrypt_payload_hex(hex_part, passphrase, aad=AAD_TICKET, max_age_seconds=max_age_seconds)
    if info.get("type") != "kissshot_handshake" or "url" not in info or "route" not in info or "salt" not in info:
        raise ValueError("Invalid handshake ticket structure / 握手票据结构无效")
    base_url = str(info["url"]).rstrip("/")
    if not (
        base_url.startswith("https://")
        or base_url.startswith("http://127.0.0.1:")
        or base_url.startswith("http://localhost:")
    ):
        raise ValueError("Unsafe endpoint URL in ticket")
    route = str(info["route"])
    if not route.startswith("/"):
        raise ValueError("Invalid route path in ticket")
    salt_bytes = bytes.fromhex(str(info["salt"]))
    if len(salt_bytes) < SALT_BYTES:
        raise ValueError("Invalid session salt in ticket")
    return {
        "endpoint_url": f"{base_url}{route}",
        "base_url": base_url,
        "route": route,
        "session_salt": salt_bytes,
        "created_at": int(info.get("ts", 0)),
    }


def pack_encrypted_zip(
    items: List[Tuple[str, bytes]],
    passphrase: str,
    extra_meta: Dict[str, Any] | None = None,
) -> bytes:
    """
    在纯内存 (BytesIO) 中将输出字节流封装为双层认证加密归档：
    - 内层：256-bit WinZip AES (WZ_AES) + ZIP_STORED 零压缩，防止压缩比侧信道泄露，文件名混淆为 chunk_XXX.dat。
    - 外层：绑定 AAD_ARCHIVE 的整包 AES-256-GCM 信封，抹除 PK 文件头、条目数与文件名元数据。
    """
    if not passphrase or not passphrase.strip():
        raise ValueError("Archive passphrase must not be empty")
    buf = io.BytesIO()
    pwd_bytes = passphrase.encode("utf-8")
    manifest: Dict[str, Any] = {
        "version": 2,
        "created_at": int(time.time()),
        "files": [],
        "meta": extra_meta or {},
    }
    with pyzipper.AESZipFile(
        buf,
        "w",
        compression=pyzipper.ZIP_STORED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(pwd_bytes)
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        for idx, (orig_ext, content) in enumerate(items):
            clean_ext = orig_ext.lstrip(".") or "bin"
            if not _SAFE_EXT_RE.fullmatch(clean_ext):
                clean_ext = "bin"
            inner_name = f"chunk_{idx:03d}.dat"
            zf.writestr(inner_name, content)
            manifest["files"].append({"inner": inner_name, "ext": clean_ext})
        zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False).encode("utf-8"))
    return encrypt_bytes_aes(buf.getvalue(), passphrase, aad=AAD_ARCHIVE)


def _file_sha256_hex(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            buf = f.read(1024 * 1024)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def unpack_encrypted_zip(
    archive_bytes: bytes,
    passphrase: str,
    out_dir: str,
    prefix: str = "artifact",
    max_total_bytes: int = MAX_ARCHIVE_UNPACK_BYTES,
    packet_id: Optional[str] = None,
) -> Tuple[List[str], Dict[str, Any]]:
    """
    校验外层 AAD_ARCHIVE 信封并安全流式解包内层 256-bit WZ_AES 归档：
    - 强制拒绝非 ZIP_STORED 压缩条目，免疫 ZIP_DEFLATED 解压炸弹攻击。
    - 1 MiB 流式分块写入 + 总字节上限熔断 + 异常半成品自动清理 + 严格路径穿越拦截。
    - 提供 `packet_id` 时使用确定性文件名实现幂等落盘：同名且内容哈希一致直接复用不重复生成；
      若目标文件已被用户编辑修改（哈希不一致）则拒覆并抛出 `FileExistsError`，且绝不删除已有用户文件。
    """
    os.makedirs(out_dir, exist_ok=True)
    real_out_dir = os.path.realpath(out_dir)
    inner_zip = decrypt_bytes_aes(archive_bytes, passphrase, aad=AAD_ARCHIVE)

    pwd_bytes = passphrase.encode("utf-8")
    saved_paths: List[str] = []
    newly_created: List[str] = []
    total_written = 0
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_prefix = re.sub(r"[^A-Za-z0-9_-]", "", prefix)[:24] or "artifact"
    safe_pkt = ""
    if packet_id is not None and str(packet_id).strip():
        cleaned = re.sub(r"[^A-Za-z0-9_-]", "", str(packet_id).strip())[:40]
        safe_pkt = cleaned if len(cleaned) >= 4 else hashlib.sha256(str(packet_id).encode("utf-8")).hexdigest()[:16]

    try:
        with pyzipper.AESZipFile(io.BytesIO(inner_zip), "r") as zf:
            zf.setpassword(pwd_bytes)
            for info in zf.infolist():
                if info.compress_type != pyzipper.ZIP_STORED:
                    raise ValueError("Compressed ZIP entries are forbidden (anti-decompression-bomb policy)")
                if info.file_size < 0 or info.file_size > max_total_bytes:
                    raise ValueError("Archive entry exceeds maximum allowed size")

            m_info = zf.getinfo("manifest.json")
            if m_info.file_size > 1024 * 1024:
                raise ValueError("Manifest exceeds 1 MiB limit")
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
            files_list = manifest.get("files", [])
            if not isinstance(files_list, list) or len(files_list) > 256:
                raise ValueError("Invalid manifest file list")

            for idx, item in enumerate(files_list):
                inner = str(item.get("inner", ""))
                raw_ext = str(item.get("ext", "bin")).lstrip(".")
                if not _SAFE_INNER_RE.fullmatch(inner):
                    raise ValueError(f"Unsafe inner archive member rejected: {inner!r}")
                if not _SAFE_EXT_RE.fullmatch(raw_ext):
                    raise ValueError(f"Unsafe file extension rejected: {raw_ext!r}")

                entry_info = zf.getinfo(inner)
                if total_written + entry_info.file_size > max_total_bytes:
                    raise ValueError("Total unpacked size exceeds safety limit")

                if safe_pkt:
                    fname = f"{safe_prefix}_{safe_pkt}_{idx + 1:02d}.{raw_ext}"
                else:
                    fname = f"{safe_prefix}_{ts}_{idx + 1:02d}_{secrets.token_hex(2)}.{raw_ext}"
                fpath = os.path.realpath(os.path.join(real_out_dir, fname))
                if os.path.commonpath([real_out_dir, fpath]) != real_out_dir or fpath == real_out_dir:
                    raise ValueError("Path traversal attempt rejected")

                fd, tmp_p = tempfile.mkstemp(dir=real_out_dir, prefix=".ks_unpack_", suffix=".tmp")
                entry_hasher = hashlib.sha256()
                try:
                    with zf.open(inner, "r") as src_f, os.fdopen(fd, "wb") as dst_f:
                        while True:
                            chunk = src_f.read(1024 * 1024)
                            if not chunk:
                                break
                            total_written += len(chunk)
                            if total_written > max_total_bytes:
                                raise ValueError("Streamed bytes exceeded safety limit")
                            entry_hasher.update(chunk)
                            dst_f.write(chunk)

                    if os.path.exists(fpath):
                        existing_hash = _file_sha256_hex(fpath)
                        if hmac.compare_digest(existing_hash, entry_hasher.hexdigest()):
                            os.remove(tmp_p)
                            saved_paths.append(fpath)
                            continue
                        os.remove(tmp_p)
                        raise FileExistsError(
                            f"Refusing to overwrite modified local file during idempotent unpack: {fpath}"
                        )

                    os.replace(tmp_p, fpath)
                    newly_created.append(fpath)
                    saved_paths.append(fpath)
                except Exception:
                    if os.path.exists(tmp_p):
                        try:
                            os.remove(tmp_p)
                        except OSError:
                            pass
                    raise
    except Exception:
        for p in newly_created:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
        raise

    return saved_paths, manifest.get("meta", {})
