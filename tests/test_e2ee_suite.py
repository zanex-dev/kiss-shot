# -*- coding: utf-8 -*-
"""
端到端密码学、HTTP/SSE 环回网关、防重放/防截断与仓库脱敏审计测试套件
运行方式: python -m unittest discover -s tests -v
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile

from cryptography.exceptions import InvalidTag

from kiss_shot.crypto import (
    aead_open,
    aead_seal,
    create_handshake_ticket,
    decrypt_bytes_aes,
    decrypt_payload_hex,
    derive_session_cipher,
    encrypt_bytes_aes,
    encrypt_payload_hex,
    pack_encrypted_zip,
    parse_handshake_ticket,
    unpack_encrypted_zip,
)
from kiss_shot.local_bridge import LocalBridgeState, make_local_bridge_handler
from kiss_shot.remote_gateway import RemoteGatewayContext, make_gateway_handler


class _MockOpenAIBackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        if self.path == "/health":
            raw = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        body = json.loads(self.rfile.read(n).decode("utf-8")) if n > 0 else {}
        if self.path == "/v1/chat/completions":
            user_msg = body.get("messages", [{}])[-1].get("content", "")
            if body.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Connection", "close")
                self.end_headers()
                for token in ["零信任", "端到端", f"回显:{user_msg}"]:
                    chunk = {
                        "id": "chatcmpl-mock",
                        "object": "chat.completion.chunk",
                        "choices": [{"index": 0, "delta": {"content": token}, "finish_reason": None}],
                    }
                    self.wfile.write(f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode("utf-8"))
                    self.wfile.flush()
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            else:
                resp = {
                    "id": "chatcmpl-mock",
                    "object": "chat.completion",
                    "model": body.get("model", "kiss-shot-llm"),
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": f"Echo:{user_msg}"},
                            "finish_reason": "stop",
                        }
                    ],
                }
                raw = json.dumps(resp, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            return
        self.send_response(404)
        self.end_headers()


class TestCryptoPrimitives(unittest.TestCase):
    def test_payload_hex_roundtrip_and_tamper_rejection(self) -> None:
        pwd = "correct-horse-battery-staple-2026"
        data = {"prompt": "机密多模态指令 🚀", "steps": 28, "nested": [1, 2, 3]}
        enc_hex = encrypt_payload_hex(data, pwd)
        self.assertNotIn("机密", enc_hex)
        dec = decrypt_payload_hex(enc_hex, pwd)
        self.assertEqual(dec, data)

        with self.assertRaises(InvalidTag):
            decrypt_payload_hex(enc_hex, "wrong-passphrase")

        # 翻转密文末尾字节必须触发 GCM 认证失败
        flipped = enc_hex[:-2] + ("00" if enc_hex[-2:] != "00" else "ff")
        with self.assertRaises(InvalidTag):
            decrypt_payload_hex(flipped, pwd)

    def test_binary_aes_roundtrip(self) -> None:
        pwd = "binary-blob-secret-key"
        raw = secrets.token_bytes(8192)
        enc = encrypt_bytes_aes(raw, pwd)
        self.assertNotEqual(enc, raw)
        self.assertEqual(decrypt_bytes_aes(enc, pwd), raw)

    def test_wz_aes_zip_obfuscation_and_stored_mode(self) -> None:
        pwd = "zip-archive-passphrase"
        items = [("png", b"\x89PNG\r\n\x1a\nmock-image-1"), ("mp4", b"\x00\x00\x00\x18ftypmp42mock-video")]
        archive_bytes = pack_encrypted_zip(items, pwd, extra_meta={"seed": 42})

        # 校验 ZIP 目录头：不泄露 .png/.mp4 扩展名，且采用 WinZip AES (method=99) + ZIP_STORED 无压缩防侧信道
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf_inspect:
            names = zf_inspect.namelist()
            self.assertIn("chunk_000.dat", names)
            self.assertIn("chunk_001.dat", names)
            self.assertIn("manifest.json", names)
            for info in zf_inspect.infolist():
                self.assertEqual(info.compress_type, 99)  # 99 = WinZip AES (0x9901), 非脆弱传统 ZipCrypto
                self.assertTrue(info.flag_bits & 0x1)  # Encrypted flag set
                # ZIP_STORED 下密文长度 = 原始明文长度 + 16B Salt + 2B pwd_verify + 10B HMAC-SHA1 = 明文 + 28B
                if info.filename == "chunk_000.dat":
                    self.assertEqual(info.compress_size, len(items[0][1]) + 28)

        with tempfile.TemporaryDirectory() as tmpd:
            saved, meta = unpack_encrypted_zip(archive_bytes, pwd, tmpd, prefix="unit")
            self.assertEqual(meta.get("seed"), 42)
            self.assertEqual(len(saved), 2)
            self.assertTrue(saved[0].endswith(".png"))
            self.assertTrue(saved[1].endswith(".mp4"))
            with open(saved[0], "rb") as f0, open(saved[1], "rb") as f1:
                self.assertEqual(f0.read(), items[0][1])
                self.assertEqual(f1.read(), items[1][1])

    def test_dynamic_handshake_ticket(self) -> None:
        pwd = "session-handshake-secret"
        t1, r1, s1 = create_handshake_ticket("https://gpu-node.example.com/", pwd)
        t2, r2, s2 = create_handshake_ticket("https://gpu-node.example.com/", pwd)
        # 每次生成的动态路由和会话盐必须随机互异
        self.assertNotEqual(r1, r2)
        self.assertNotEqual(s1, s2)

        parsed = parse_handshake_ticket(f"Copied output:\n{t1}\n", pwd)
        self.assertEqual(parsed["base_url"], "https://gpu-node.example.com")
        self.assertEqual(parsed["route"], r1)
        self.assertEqual(parsed["session_salt"], s1)


class TestEndToEndBridgeAndSecurityDefenses(unittest.TestCase):
    def setUp(self) -> None:
        self.passphrase = "e2ee-loopback-test-passphrase"
        self.tmp_dir = tempfile.TemporaryDirectory()

        # 1. Mock OpenAI Engine
        self.mock_engine = ThreadingHTTPServer(("127.0.0.1", 0), _MockOpenAIBackendHandler)
        self.engine_port = self.mock_engine.server_address[1]
        threading.Thread(target=self.mock_engine.serve_forever, daemon=True).start()

        # 2. Remote AEAD Gateway
        self.rem_ctx = RemoteGatewayContext(
            passphrase=self.passphrase,
            upstream_base=f"http://127.0.0.1:{self.engine_port}",
        )
        self.rem_srv = ThreadingHTTPServer(("127.0.0.1", 0), make_gateway_handler(self.rem_ctx))
        self.rem_port = self.rem_srv.server_address[1]
        threading.Thread(target=self.rem_srv.serve_forever, daemon=True).start()

        # 3. Local OpenAI E2EE Bridge
        self.loc_state = LocalBridgeState(work_dir=self.tmp_dir.name)
        self.loc_srv = ThreadingHTTPServer(("127.0.0.1", 0), make_local_bridge_handler(self.loc_state))
        self.loc_port = self.loc_srv.server_address[1]
        threading.Thread(target=self.loc_srv.serve_forever, daemon=True).start()

        self.ticket = self.rem_ctx.export_ticket(f"http://127.0.0.1:{self.rem_port}")

    def tearDown(self) -> None:
        self.loc_srv.shutdown()
        self.loc_srv.server_close()
        self.rem_srv.shutdown()
        self.rem_srv.server_close()
        self.mock_engine.shutdown()
        self.mock_engine.server_close()
        self.tmp_dir.cleanup()

    def test_full_handshake_json_and_streaming_sse(self) -> None:
        ok, msg = self.loc_state.configure_with_ticket(self.ticket, passphrase_override=self.passphrase)
        self.assertTrue(ok, msg)

        # A. 非流式请求端到端加解密往返
        req_body = json.dumps(
            {
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "秘密多模态测试载荷"}],
                "stream": False,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.loc_port}/v1/chat/completions",
            data=req_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            out = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(out["choices"][0]["message"]["content"], "Echo:秘密多模态测试载荷")

        # B. 流式 SSE 逐帧序列校验与 EOF 认证标签验证
        stream_body = json.dumps(
            {
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "流式完整性验证"}],
                "stream": True,
            }
        ).encode("utf-8")
        s_req = urllib.request.Request(
            f"http://127.0.0.1:{self.loc_port}/v1/chat/completions",
            data=stream_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        collected = []
        with urllib.request.urlopen(s_req, timeout=5) as s_resp:
            for raw_ln in s_resp:
                ln = raw_ln.decode("utf-8").strip()
                if ln.startswith("data: ") and ln != "data: [DONE]":
                    obj = json.loads(ln[6:])
                    collected.append(obj["choices"][0]["delta"].get("content", ""))
        self.assertEqual("".join(collected), "零信任端到端回显:流式完整性验证")

    def test_scanner_403_and_anti_replay_defense(self) -> None:
        # 1. 未授权路径探测或 GET 扫描必须返回 403
        for bad_url, method in [
            (f"http://127.0.0.1:{self.rem_port}/v1/models", "GET"),
            (f"http://127.0.0.1:{self.rem_port}{self.rem_ctx.route_path}", "GET"),
            (f"http://127.0.0.1:{self.rem_port}/api/v1/sync", "POST"),
        ]:
            req = urllib.request.Request(bad_url, data=(b"probe" if method == "POST" else None), method=method)
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(req, timeout=3)
            self.assertEqual(cm.exception.code, 403)

        # 2. 抓包重放攻击验证：完全合法的加密请求帧第一次通过，第二次重放必须被 ReplayGuard 拦截返回 403
        cipher = derive_session_cipher(self.passphrase, self.rem_ctx.session_salt)
        meta = json.dumps({"id": "replay_test_id_0001", "method": "GET", "path": "/health", "ts": int(time.time())}).encode("utf-8")
        wire = aead_seal(cipher, meta + b"\n", f"kissshot-c2s-v1:{self.rem_ctx.route_path}".encode("utf-8"))

        url = f"http://127.0.0.1:{self.rem_port}{self.rem_ctx.route_path}"
        req1 = urllib.request.Request(url, data=wire, headers={"Content-Type": "application/octet-stream"}, method="POST")
        with urllib.request.urlopen(req1, timeout=3) as r1:
            self.assertEqual(r1.status, 200)

        req2 = urllib.request.Request(url, data=wire, headers={"Content-Type": "application/octet-stream"}, method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm_replay:
            urllib.request.urlopen(req2, timeout=3)
        self.assertEqual(cm_replay.exception.code, 403)

    def test_sse_truncation_without_eof_is_detected(self) -> None:
        # 模拟恶意反向代理在中途强行掐断 SSE 连接（缺失加密 EOF 认证帧）
        route = "/v1/ks-trunc-test"
        salt = secrets.token_bytes(16)
        cipher = derive_session_cipher(self.passphrase, salt)

        class _TruncatingGatewayHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                return

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0") or "0")
                plain = aead_open(cipher, self.rfile.read(n), f"kissshot-c2s-v1:{route}".encode("utf-8"))
                meta = json.loads(plain.split(b"\n", 1)[0].decode("utf-8"))
                req_id = meta["id"]
                if meta["path"] == "/health":
                    hdr = b'{"status":200,"ct":"application/json"}\n{"ok":true}'
                    enc = aead_seal(cipher, hdr, f"kissshot-s2c-body:{req_id}".encode("ascii"))
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(enc)))
                    self.end_headers()
                    self.wfile.write(enc)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Connection", "close")
                self.end_headers()
                c0 = aead_seal(cipher, b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n', f"kissshot-s2c:{req_id}:0".encode("ascii")).hex()
                self.wfile.write(f"data: {c0}\n\n".encode("ascii"))
                self.wfile.flush()
                # 故意不发送 data: EOF:... 直接关闭连接

        trunc_srv = ThreadingHTTPServer(("127.0.0.1", 0), _TruncatingGatewayHandler)
        t_port = trunc_srv.server_address[1]
        threading.Thread(target=trunc_srv.serve_forever, daemon=True).start()
        try:
            ticket, _, _ = create_handshake_ticket(f"http://127.0.0.1:{t_port}", self.passphrase, route_path=route, session_salt=salt)
            ok, _ = self.loc_state.configure_with_ticket(ticket, passphrase_override=self.passphrase)
            self.assertTrue(ok)

            s_req = urllib.request.Request(
                f"http://127.0.0.1:{self.loc_port}/v1/chat/completions",
                data=b'{"model":"x","messages":[{"role":"user","content":"hi"}],"stream":true}',
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(s_req, timeout=5) as resp:
                _ = resp.read()
            self.assertIn("Truncated SSE stream", self.loc_state.snapshot()["last_err"])
        finally:
            trunc_srv.shutdown()
            trunc_srv.server_close()


class TestRepositoryHygieneAndIsolation(unittest.TestCase):
    def test_zero_personal_paths_or_private_fingerprints(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        # 通过拼接构造敏感检测词，确保本测试文件自身亦不出现原始字面量
        forbidden_tokens = [
            "C:\\Users\\" + "shana",
            "C:/Users/" + "shana",
            "BRIDGE_" + "TICKET",
            "colab_gpu_" + "aes256",
            "proj-runtime-" + "cache",
            "tensor_" + "worker",
            "edge_" + "connector",
            "try" + "cloudflare",
            "vis-lab-" + "2d",
            "nlp-lab-" + "72b",
            "here" + "tic",
        ]
        checked_files = 0
        for p in repo_root.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(repo_root).as_posix()
            if any(rel.startswith(prefix) for prefix in (".git/", "__pycache__/", "outputs/", "build/", "dist/")):
                continue
            if p.suffix.lower() in (".pyc", ".pyo", ".pyd", ".egg", ".png", ".jpg", ".jpeg", ".webp", ".ico"):
                continue
            content = p.read_text(encoding="utf-8", errors="ignore")
            checked_files += 1
            for tok in forbidden_tokens:
                self.assertNotIn(
                    tok.lower(),
                    content.lower(),
                    f"Hygiene violation: forbidden token found in {rel}",
                )
        self.assertGreaterEqual(checked_files, 10)


if __name__ == "__main__":
    unittest.main()
