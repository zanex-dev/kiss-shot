# -*- coding: utf-8 -*-
"""
零信任密码学原语与主流开源模型预设 (kiss_shot/crypto.py)

核心安全特性：
1. 密钥派生：遵循 OWASP 2023+ 推荐标准，采用 PBKDF2-HMAC-SHA256 (210,000 次迭代) + 128-bit 随机盐。
2. 流式会话隔离：每次启动远程网关自动生成随机 128-bit 会话盐 (session_salt) 与随机动态路径 (/v1/ks-<random>)，
   封装于加密握手票据 (KISSSHOT_TICKET:...) 中，彻底消除固定路由与固定会话密钥指纹。
3. 逐帧认证加密：请求与流式 SSE 响应分片均采用独立 96-bit 随机 Nonce + 上下文绑定 AAD（含请求 ID、方向与递增序号 seq），
   抵御中间人窥探、重放攻击、乱序注入与流截断攻击。
4. 纯内存归档封装：异步多模态产物在内存中采用 256-bit WinZip AES (WZ_AES) + ZIP_STORED 无压缩封装，
   消除压缩比侧信道特征，内层文件名统一混淆为 chunk_XXX.dat，真实元数据仅存于加密 manifest.json 内。
"""

from __future__ import annotations

import io
import json
import os
import re
import secrets
import time
from typing import Any, Dict, List, Tuple

import pyzipper
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# OWASP Password Storage Cheat Sheet 推荐的 PBKDF2-HMAC-SHA256 迭代基准
KDF_ITERATIONS = 210_000
SALT_BYTES = 16
NONCE_BYTES = 12
AEAD_TAG_BYTES = 16

DEFAULT_LOCAL_PORT = 18443
DEFAULT_MODEL_ALIAS = "kiss-shot-llm"
DEFAULT_MAILBOX_REPO_NAME = "kissshot-ephemeral-relay"
TICKET_PREFIX = "KISSSHOT_TICKET:"
TICKET_PATTERN = re.compile(r"KISSSHOT_TICKET:([0-9a-fA-F]{64,})")

# 面向科研与开发的标准主流开源模型预设（中立合规基线）
MEDIA_PRESETS: Dict[str, Dict[str, Any]] = {
    "sdxl_base_1_0": {
        "label": "Stable Diffusion XL Base 1.0 (FP16 · 1024x1024 通用文生图)",
        "category": "image_t2i",
        "src_repo": "stabilityai/stable-diffusion-xl-base-1.0",
        "arch": "sdxl",
        "variant": "fp16",
        "default_width": 1024,
        "default_height": 1024,
        "default_steps": 28,
        "default_cfg": 5.5,
        "default_frames": 1,
        "default_pos": "cinematic architectural photography, warm sunlight, ultra detailed, 8k resolution",
        "default_neg": "blurry, low quality, distorted, watermark, text, artifacts",
    },
    "flux_1_schnell": {
        "label": "FLUX.1-schnell (Apache-2.0 · 4步极速高保真文生图)",
        "category": "image_t2i",
        "src_repo": "black-forest-labs/FLUX.1-schnell",
        "arch": "flux",
        "variant": None,
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
        "default_width": 832,
        "default_height": 480,
        "default_steps": 30,
        "default_cfg": 5.0,
        "default_frames": 81,
        "default_pos": "aerial drone shot over misty pine forest at sunrise, smooth camera motion, natural lighting",
        "default_neg": "overexposed, static frame, blurry details, subtitles, compression artifacts",
    },
    "wan2_2_ti2v_5b": {
        "label": "Wan 2.2 TI2V 5B (Apache-2.0 · 720P 高清文生/图生视频)",
        "category": "video_ti2v",
        "src_repo": "Wan-AI/Wan2.2-TI2V-5B-Diffusers",
        "arch": "wan_ti2v",
        "variant": None,
        "default_width": 1280,
        "default_height": 704,
        "default_steps": 36,
        "default_cfg": 5.0,
        "default_frames": 81,
        "default_pos": "timelapse of ocean waves meeting basalt cliffs under golden hour clouds, crisp 720p detail",
        "default_neg": "overexposed, static, blurry, watermark, subtitles, deformed motion",
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
    aad: bytes = b"kissshot-payload-v1",
) -> str:
    """将结构化字典用 AES-256-GCM 认证加密并编码为纯十六进制文本"""
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    key = derive_key(passphrase, salt)
    plaintext = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return (salt + nonce + ciphertext).hex()


def decrypt_payload_hex(
    hex_str: str,
    passphrase: str,
    aad: bytes = b"kissshot-payload-v1",
) -> Dict[str, Any]:
    """校验并解密十六进制 AES-256-GCM 载荷"""
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
    return json.loads(plaintext.decode("utf-8"))


def encrypt_bytes_aes(
    raw_bytes: bytes,
    passphrase: str,
    aad: bytes = b"kissshot-blob-v1",
) -> bytes:
    """对任意二进制字节流（如参考图或附件）执行纯内存 AES-256-GCM 认证加密"""
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    key = derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, raw_bytes, aad)
    return salt + nonce + ciphertext


def decrypt_bytes_aes(
    enc_bytes: bytes,
    passphrase: str,
    aad: bytes = b"kissshot-blob-v1",
) -> bytes:
    """校验并解密二进制字节流"""
    if len(enc_bytes) <= SALT_BYTES + NONCE_BYTES + AEAD_TAG_BYTES:
        raise ValueError("Truncated encrypted blob / 加密二进制数据不完整")
    salt = enc_bytes[:SALT_BYTES]
    nonce = enc_bytes[SALT_BYTES : SALT_BYTES + NONCE_BYTES]
    ciphertext = enc_bytes[SALT_BYTES + NONCE_BYTES :]
    key = derive_key(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


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
    if not (clean_url.startswith("https://") or clean_url.startswith("http://127.0.0.1:") or clean_url.startswith("http://localhost:")):
        raise ValueError("Endpoint must use https:// or localhost loopback")
    actual_route = route_path or f"/v1/ks-{secrets.token_hex(8)}"
    if not actual_route.startswith("/"):
        actual_route = "/" + actual_route
    actual_salt = session_salt or secrets.token_bytes(SALT_BYTES)
    ticket_obj = {
        "v": 1,
        "type": "kissshot_handshake",
        "url": clean_url,
        "route": actual_route,
        "salt": actual_salt.hex(),
        "ts": int(time.time()),
    }
    enc_hex = encrypt_payload_hex(ticket_obj, passphrase, aad=b"kissshot-ticket-v1")
    return f"{TICKET_PREFIX}{enc_hex}", actual_route, actual_salt


def parse_handshake_ticket(raw_text: str, passphrase: str) -> Dict[str, Any]:
    """从文本或剪贴板内容中提取并验证 KISSSHOT_TICKET 握手票据"""
    text = (raw_text or "").strip()
    m = TICKET_PATTERN.search(text)
    hex_part = m.group(1) if m else text
    info = decrypt_payload_hex(hex_part, passphrase, aad=b"kissshot-ticket-v1")
    if info.get("type") != "kissshot_handshake" or "url" not in info or "route" not in info or "salt" not in info:
        raise ValueError("Invalid handshake ticket structure / 握手票据结构无效")
    salt_bytes = bytes.fromhex(info["salt"])
    if len(salt_bytes) < SALT_BYTES:
        raise ValueError("Invalid session salt in ticket")
    return {
        "endpoint_url": f"{str(info['url']).rstrip('/')}{info['route']}",
        "base_url": str(info["url"]).rstrip("/"),
        "route": str(info["route"]),
        "session_salt": salt_bytes,
        "created_at": int(info.get("ts", 0)),
    }


def pack_encrypted_zip(
    items: List[Tuple[str, bytes]],
    passphrase: str,
    extra_meta: Dict[str, Any] | None = None,
) -> bytes:
    """
    在纯内存 (BytesIO) 中将多个输出字节流打包为 256-bit WinZip AES 加密归档。
    采用 ZIP_STORED 无压缩模式防止压缩比侧信道泄露，内层文件名混淆为 chunk_XXX.dat。
    """
    if not passphrase or not passphrase.strip():
        raise ValueError("ZIP passphrase must not be empty")
    buf = io.BytesIO()
    pwd_bytes = passphrase.encode("utf-8")
    manifest: Dict[str, Any] = {
        "version": 1,
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
            inner_name = f"chunk_{idx:03d}.dat"
            zf.writestr(inner_name, content)
            manifest["files"].append({"inner": inner_name, "ext": orig_ext.lstrip(".") or "bin"})
        zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False).encode("utf-8"))
    return buf.getvalue()


def unpack_encrypted_zip(
    zip_bytes: bytes,
    passphrase: str,
    out_dir: str,
    prefix: str = "artifact",
) -> Tuple[List[str], Dict[str, Any]]:
    """解密 256-bit WZ_AES 归档包并将还原后的文件安全落盘（带路径穿越校验）"""
    os.makedirs(out_dir, exist_ok=True)
    real_out_dir = os.path.realpath(out_dir)
    pwd_bytes = passphrase.encode("utf-8")
    saved_paths: List[str] = []
    ts = time.strftime("%Y%m%d_%H%M%S")

    with pyzipper.AESZipFile(io.BytesIO(zip_bytes), "r") as zf:
        zf.setpassword(pwd_bytes)
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        for idx, item in enumerate(manifest.get("files", [])):
            inner = str(item["inner"])
            raw_ext = re.sub(r"[^a-zA-Z0-9]", "", str(item.get("ext", "bin")))[:10] or "bin"
            raw = zf.read(inner)
            fname = f"{prefix}_{ts}_{idx + 1:02d}_{secrets.token_hex(2)}.{raw_ext}"
            fpath = os.path.realpath(os.path.join(real_out_dir, fname))
            if not fpath.startswith(real_out_dir + os.sep) and fpath != real_out_dir:
                raise ValueError("Unsafe output path rejected")
            with open(fpath, "wb") as f:
                f.write(raw)
            saved_paths.append(fpath)
    return saved_paths, manifest.get("meta", {})
