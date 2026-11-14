# -*- coding: utf-8 -*-
"""
零信任密码学原语、跨平台静态凭据保险箱与主流开源模型预设 (kiss_shot/crypto.py)

核心安全特性：
1. 密钥派生：遵循 OWASP 推荐标准，采用 PBKDF2-HMAC-SHA256 (210,000 次迭代) + 128-bit 随机盐。
2. 密码学域分离 (Domain Separation) 与 TTL 防重放：
   指令载荷 (AAD_PAYLOAD)、握手票据 (AAD_TICKET)、二进制附件 (AAD_BLOB) 与加密归档外层信封 (AAD_ARCHIVE)
   各自绑定独立 AAD 标签，阻断同口令跨通道密文嫁接；结构化载荷内置签发时间戳校验（默认 24h 过期）。
3. 流式会话隔离：每次启动远程网关自动生成随机 128-bit 会话盐与动态路径 (/v1/ks-<random>)，
   封装于 KISSSHOT_TICKET:... 握手票据中，消除固定路由与固定会话密钥特征。
4. 双层 AEAD 归档与反压缩炸弹：异步产物在内存中采用 256-bit WinZip AES (WZ_AES) + ZIP_STORED 无压缩封装，
   外层再施加完整 AES-256-GCM 整包信封抹除 ZIP 文件头；解包端强制拒绝任何压缩条目并实行流式总字节熔断。
5. 本机凭据静态保护：Windows 下采用系统级 DPAPI (CryptProtectData) 绑定当前登录账户加密落盘；
   Linux/macOS 下采用原子写入与严格 0600 属主读写权限隔离。
"""

from __future__ import annotations

import base64
import io
import json
import os
import re
import secrets
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
AAD_TICKET = b"kissshot-ticket-v2"
AAD_BLOB = b"kissshot-blob-v2"
AAD_ARCHIVE = b"kissshot-archive-v2"

MAX_PAYLOAD_TTL_SECONDS = 86_400
MAX_ARCHIVE_UNPACK_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB streaming fuse

DEFAULT_LOCAL_PORT = 18443
DEFAULT_MODEL_ALIAS = "kiss-shot-llm"
DEFAULT_MAILBOX_REPO_NAME = "kissshot-ephemeral-relay"
TICKET_PREFIX = "KISSSHOT_TICKET:"
TICKET_PATTERN = re.compile(r"KISSSHOT_TICKET:([0-9a-fA-F]{64,})")

_SAFE_INNER_RE = re.compile(r"^chunk_[0-9]{3,5}\.dat$")
_SAFE_EXT_RE = re.compile(r"^[A-Za-z0-9]{1,8}$")
_DPAPI_ENTROPY = b"kiss-shot-dpapi-v2"

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


def unpack_encrypted_zip(
    archive_bytes: bytes,
    passphrase: str,
    out_dir: str,
    prefix: str = "artifact",
    max_total_bytes: int = MAX_ARCHIVE_UNPACK_BYTES,
) -> Tuple[List[str], Dict[str, Any]]:
    """
    校验外层 AAD_ARCHIVE 信封并安全流式解包内层 256-bit WZ_AES 归档：
    - 强制拒绝非 ZIP_STORED 压缩条目，免疫 ZIP_DEFLATED 解压炸弹攻击。
    - 1 MiB 流式分块写入 + 总字节上限熔断 + 异常半成品自动清理 + 严格路径穿越拦截。
    """
    os.makedirs(out_dir, exist_ok=True)
    real_out_dir = os.path.realpath(out_dir)
    inner_zip = decrypt_bytes_aes(archive_bytes, passphrase, aad=AAD_ARCHIVE)

    pwd_bytes = passphrase.encode("utf-8")
    saved_paths: List[str] = []
    total_written = 0
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_prefix = re.sub(r"[^A-Za-z0-9_-]", "", prefix)[:24] or "artifact"

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

                fname = f"{safe_prefix}_{ts}_{idx + 1:02d}_{secrets.token_hex(2)}.{raw_ext}"
                fpath = os.path.realpath(os.path.join(real_out_dir, fname))
                if os.path.commonpath([real_out_dir, fpath]) != real_out_dir or fpath == real_out_dir:
                    raise ValueError("Path traversal attempt rejected")

                with zf.open(inner, "r") as src_f, open(fpath, "wb") as dst_f:
                    while True:
                        chunk = src_f.read(1024 * 1024)
                        if not chunk:
                            break
                        total_written += len(chunk)
                        if total_written > max_total_bytes:
                            raise ValueError("Streamed bytes exceeded safety limit")
                        dst_f.write(chunk)
                saved_paths.append(fpath)
    except Exception:
        for p in saved_paths:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
        raise

    return saved_paths, manifest.get("meta", {})
