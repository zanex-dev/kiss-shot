# -*- coding: utf-8 -*-
"""
端到端密码学、域分离 AEAD、反压缩炸弹、DNS Rebinding 防御、HTTP/SSE 环回网关、
v1.3.0 持久化加密账本 / CAS 密文信箱 / 运行时依赖锁 / Notebook 安全边界与仓库脱敏测试套件 (v1.3.0)
运行方式: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import ast
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import inspect
import io
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile

from cryptography.exceptions import InvalidTag
from huggingface_hub import CommitOperationAdd, CommitOperationDelete
import pyzipper

from kiss_shot.crypto import (
    AAD_ARCHIVE,
    AAD_BLOB,
    AAD_PAYLOAD,
    AAD_QUEUE,
    AAD_TICKET,
    aead_open,
    aead_seal,
    create_handshake_ticket,
    decrypt_bytes_aes,
    decrypt_payload_hex,
    decrypt_queue_job,
    derive_session_cipher,
    encrypt_bytes_aes,
    encrypt_payload_hex,
    encrypt_queue_job,
    get_merged_llm_presets,
    get_merged_media_presets,
    load_encrypted_secrets,
    load_gallery_vault,
    migrate_output_vault,
    pack_encrypted_zip,
    parse_handshake_ticket,
    parse_hf_repo_id,
    record_gallery_items,
    save_encrypted_secrets,
    unpack_encrypted_zip,
)
from kiss_shot.job_ledger import JobLedger
from kiss_shot.local_bridge import (
    LocalBridgeState,
    bind_sillytavern_client,
    configure_local_bridge,
    make_local_bridge_handler,
    query_local_bridge_status,
    sillytavern_profiles,
)
from kiss_shot.mailbox_delivery import (
    MailboxPacketInfo,
    burn_packets_conditional,
    commit_with_parent_retry,
    compute_git_blob_id,
    compute_sha256_hex,
    download_verified_packet,
    enqueue_job_v2,
    extract_job_id_from_queue_path,
    is_queue_job_path,
    list_inbox_packets_with_revision,
    make_queue_v2_path,
    verify_packet_blob_id,
)
from kiss_shot.remote_gateway import RemoteGatewayContext, make_gateway_handler
from kiss_shot.runtime_lock import (
    RUNTIME_LOCK_SCHEMA,
    load_runtime_lock,
    save_runtime_lock,
    snapshot as snapshot_runtime_lock,
    verify_runtime_lock,
)


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
                # Simulate poisoned upstream sending text/html to verify local bridge XSS sanitization
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            return
        self.send_response(404)
        self.end_headers()


class TestCryptoPrimitivesAndVault(unittest.TestCase):
    def test_payload_hex_roundtrip_ttl_and_tamper_rejection(self) -> None:
        pwd = "correct-horse-battery-staple-2026"
        data = {"prompt": "机密多模态指令 🚀", "steps": 28, "nested": [1, 2, 3]}
        enc_hex = encrypt_payload_hex(data, pwd)
        self.assertNotIn("机密", enc_hex)
        dec = decrypt_payload_hex(enc_hex, pwd)
        self.assertEqual(dec, data)

        with self.assertRaises(InvalidTag):
            decrypt_payload_hex(enc_hex, "wrong-passphrase")

        flipped = enc_hex[:-2] + ("00" if enc_hex[-2:] != "00" else "ff")
        with self.assertRaises(InvalidTag):
            decrypt_payload_hex(flipped, pwd)

        # 签发超过 24 小时的过期密文必须被拒绝
        expired_hex = encrypt_payload_hex(data, pwd, issued_at=int(time.time()) - 90_000)
        with self.assertRaises(ValueError):
            decrypt_payload_hex(expired_hex, pwd)

    def test_local_secrets_vault_at_rest_protection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpd:
            vault_path = os.path.join(tmpd, ".kissshot_secrets.json")
            sample = {"passphrase": "VaultSuperSecret_99!", "hf_token": "hf_VaultWriteToken_ABC"}
            save_encrypted_secrets(vault_path, sample)
            raw_text = Path(vault_path).read_text(encoding="utf-8")
            self.assertNotIn("VaultSuperSecret_99!", raw_text)
            self.assertNotIn("hf_VaultWriteToken_ABC", raw_text)
            if sys.platform == "win32":
                self.assertIn("dpapi_v2", raw_text)
            else:
                mode = os.stat(vault_path).st_mode & 0o777
                self.assertEqual(mode, 0o600)
            loaded = load_encrypted_secrets(vault_path)
            self.assertEqual(loaded, sample)

            # 跨平台校验 posix_0600_v2 信封反序列化路径
            import base64
            posix_path = os.path.join(tmpd, ".kissshot_posix_test.json")
            Path(posix_path).write_text(
                json.dumps({"_vault": "posix_0600_v2", "blob": base64.b64encode(json.dumps(sample).encode("utf-8")).decode("ascii")}),
                encoding="utf-8",
            )
            self.assertEqual(load_encrypted_secrets(posix_path), sample)

    def test_binary_aes_roundtrip(self) -> None:
        pwd = "binary-blob-secret-key"
        raw = secrets.token_bytes(8192)
        enc = encrypt_bytes_aes(raw, pwd)
        self.assertNotEqual(enc, raw)
        self.assertEqual(decrypt_bytes_aes(enc, pwd), raw)

    def test_double_aead_zip_anti_grafting_and_anti_bomb(self) -> None:
        pwd = "zip-archive-passphrase"
        items = [("png", b"\x89PNG\r\n\x1a\nmock-image-1"), ("mp4", b"\x00\x00\x00\x18ftypmp42mock-video")]
        archive_bytes = pack_encrypted_zip(items, pwd, extra_meta={"seed": 42})

        # 外层必须是完整 AES-256-GCM 密文信封，绝不暴露 PK\x03\x04 头与 manifest.json 文件名
        self.assertFalse(archive_bytes.startswith(b"PK\x03\x04"))
        self.assertNotIn(b"manifest.json", archive_bytes)

        # 解开外层信封后校验内层 WZ_AES (method=99) + ZIP_STORED 无压缩防侧信道
        inner_zip = decrypt_bytes_aes(archive_bytes, pwd, aad=AAD_ARCHIVE)
        with zipfile.ZipFile(io.BytesIO(inner_zip), "r") as zf_inspect:
            names = zf_inspect.namelist()
            self.assertIn("chunk_000.dat", names)
            self.assertIn("chunk_001.dat", names)
            self.assertIn("manifest.json", names)
            for info in zf_inspect.infolist():
                self.assertEqual(info.compress_type, 99)
                self.assertTrue(info.flag_bits & 0x1)
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

            # 1. 跨域密文嫁接（把 AAD_BLOB 二进制密文伪造投递给归档解包器）必须触发 InvalidTag
            blob_ct = encrypt_bytes_aes(b"raw-image-blob", pwd, aad=AAD_BLOB)
            with self.assertRaises(InvalidTag):
                unpack_encrypted_zip(blob_ct, pwd, tmpd)

            # 2. 伪造 ZIP_DEFLATED 压缩炸弹必须被解包策略当场拒收
            bomb_buf = io.BytesIO()
            with pyzipper.AESZipFile(bomb_buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(pwd.encode("utf-8"))
                zf.setencryption(pyzipper.WZ_AES, nbits=256)
                zf.writestr("chunk_000.dat", b"\x00" * 65536)
                zf.writestr("manifest.json", json.dumps({"files": [{"inner": "chunk_000.dat", "ext": "bin"}]}).encode("utf-8"))
            wrapped_bomb = encrypt_bytes_aes(bomb_buf.getvalue(), pwd, aad=AAD_ARCHIVE)
            with self.assertRaises(ValueError):
                unpack_encrypted_zip(wrapped_bomb, pwd, tmpd)

            # 3. 伪造路径穿越扩展名必须被拦截
            trav_buf = io.BytesIO()
            with pyzipper.AESZipFile(trav_buf, "w", compression=pyzipper.ZIP_STORED, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(pwd.encode("utf-8"))
                zf.setencryption(pyzipper.WZ_AES, nbits=256)
                zf.writestr("chunk_000.dat", b"x")
                zf.writestr("manifest.json", json.dumps({"files": [{"inner": "chunk_000.dat", "ext": "../../pwn"}]}).encode("utf-8"))
            wrapped_trav = encrypt_bytes_aes(trav_buf.getvalue(), pwd, aad=AAD_ARCHIVE)
            with self.assertRaises(ValueError):
                unpack_encrypted_zip(wrapped_trav, pwd, tmpd)

    def test_dynamic_handshake_ticket_and_domain_separation(self) -> None:
        pwd = "session-handshake-secret"
        t1, r1, s1 = create_handshake_ticket("https://gpu-node.example.com/", pwd)
        t2, r2, s2 = create_handshake_ticket("https://gpu-node.example.com/", pwd)
        self.assertNotEqual(r1, r2)
        self.assertNotEqual(s1, s2)

        parsed = parse_handshake_ticket(f"Copied output:\n{t1}\n", pwd)
        self.assertEqual(parsed["base_url"], "https://gpu-node.example.com")
        self.assertEqual(parsed["route"], r1)
        self.assertEqual(parsed["session_salt"], s1)

        # 普通任务密文不能伪装成握手票据通过验证
        forged_task_hex = encrypt_payload_hex({"type": "kissshot_handshake", "url": "https://x.example.com", "route": "/v1/a", "salt": s1.hex()}, pwd)
        with self.assertRaises(InvalidTag):
            parse_handshake_ticket(forged_task_hex, pwd)

    def test_queue_job_aead_ttl_and_domain_separation(self) -> None:
        pwd = "queue-daemon-passphrase-2026"
        job = {"type": "kissshot_media_infer", "preset_key": "moss_image_sft", "prompt": "机密空间构图指令", "seed": 7}
        wire = encrypt_queue_job(job, pwd)
        self.assertNotIn(b"kissshot_media_infer", wire)
        self.assertEqual(decrypt_queue_job(wire, pwd), job)

        # 过期队列任务必须被拒绝
        stale_wire = encrypt_queue_job(job, pwd, issued_at=int(time.time()) - 95_000)
        with self.assertRaises(ValueError):
            decrypt_queue_job(stale_wire, pwd)

        # 跨通道密文嫁接（AAD_BLOB -> AAD_QUEUE 或 AAD_QUEUE -> AAD_BLOB）必须触发认证失败
        forged_blob = encrypt_bytes_aes(json.dumps({"_ks_v": 2, "_ks_iat": int(time.time()), "d": job}).encode("utf-8"), pwd, aad=AAD_BLOB)
        with self.assertRaises(InvalidTag):
            decrypt_queue_job(forged_blob, pwd)
        with self.assertRaises(InvalidTag):
            decrypt_bytes_aes(wire, pwd, aad=AAD_BLOB)
        self.assertNotEqual(AAD_QUEUE, AAD_BLOB)

    def test_gallery_vault_and_lossless_migration(self) -> None:
        with tempfile.TemporaryDirectory() as src_d, tempfile.TemporaryDirectory() as dst_d:
            p1 = os.path.join(src_d, "ks_01.png")
            p2 = os.path.join(src_d, "ks_02.png")
            Path(p1).write_bytes(b"img-a")
            Path(p2).write_bytes(b"img-b")
            # 在目标目录预先放一个同名文件验证防覆盖自动重映射 (_m1)
            Path(os.path.join(dst_d, "ks_01.png")).write_bytes(b"existing-dst")

            record_gallery_items(
                src_d,
                [p1, p2],
                {"seed": 100, "model": "moss_image_sft", "prompt": "TopSecretRecipePrompt"},
            )
            raw_vault = (Path(src_d) / ".kissshot_gallery_vault.json").read_text(encoding="utf-8")
            self.assertNotIn("TopSecretRecipePrompt", raw_vault)

            src_loaded = load_gallery_vault(src_d)
            self.assertEqual(src_loaded["ks_01.png"]["seed"], 100)
            self.assertEqual(src_loaded["ks_02.png"]["seed"], 101)

            moved = migrate_output_vault(src_d, dst_d)
            self.assertEqual(moved, 2)
            self.assertFalse(os.path.exists(src_d))
            self.assertEqual(Path(os.path.join(dst_d, "ks_01.png")).read_bytes(), b"existing-dst")
            self.assertEqual(Path(os.path.join(dst_d, "ks_01_m1.png")).read_bytes(), b"img-a")
            self.assertEqual(Path(os.path.join(dst_d, "ks_02.png")).read_bytes(), b"img-b")

            dst_loaded = load_gallery_vault(dst_d)
            self.assertEqual(dst_loaded["ks_01_m1.png"]["prompt"], "TopSecretRecipePrompt")
            self.assertEqual(dst_loaded["ks_02.png"]["seed"], 101)

    def test_studio_widgets_moss_layout_and_mask_helpers(self) -> None:
        from PIL import Image, ImageDraw
        from kiss_shot.studio_widgets import (
            canvas_pt_to_centered,
            centered_pt_to_canvas,
            compile_moss_layout_json,
            parse_moss_layout_json,
            render_binary_mask_png,
        )

        cx, cy = canvas_pt_to_centered(250, 250, 500, 500, 1024, 1024)
        self.assertEqual((cx, cy), (0, 0))
        rx, ry = centered_pt_to_canvas(0, 0, 500, 500, 1024, 1024)
        self.assertEqual((rx, ry), (250, 250))

        compiled = compile_moss_layout_json(
            "清晨玻璃温室海报",
            [
                {"label": "object", "caption": "热带植物玻璃穹顶", "bbox": [-400, -300, 200, 300]},
                {"label": "text", "caption": "顶部双语主标题", "text": "KISS-SHOT", "bbox": [-600, -400, -450, 400]},
            ],
        )
        obj = json.loads(compiled)
        self.assertEqual(obj["bbox_coord_space"], "abs_centralized")
        self.assertEqual(obj["bbox_format"], "yxyx")
        self.assertEqual(obj["summary"]["meta"], ["poster"])
        summary_back, boxes_back = parse_moss_layout_json(compiled)
        self.assertEqual(summary_back, "清晨玻璃温室海报")
        self.assertEqual(len(boxes_back), 2)
        self.assertEqual(boxes_back[1]["text"], "KISS-SHOT")

        blank = Image.new("L", (128, 128), 0)
        self.assertIsNone(render_binary_mask_png(blank))
        painted = Image.new("L", (128, 128), 0)
        ImageDraw.Draw(painted).rectangle([20, 20, 60, 60], fill=255)
        mask_png = render_binary_mask_png(painted)
        self.assertIsNotNone(mask_png)
        enc_mask = encrypt_bytes_aes(mask_png or b"", "mask-pass")
        dec_img = Image.open(io.BytesIO(decrypt_bytes_aes(enc_mask, "mask-pass"))).convert("L")
        self.assertEqual(dec_img.getpixel((40, 40)), 255)
        self.assertEqual(dec_img.getpixel((5, 5)), 0)

    def test_custom_hf_repo_parsing_and_preset_merging(self) -> None:
        self.assertEqual(
            parse_hf_repo_id("https://huggingface.co/OpenMOSS-Team/MOSS-Image-SFT/tree/main?tab=files"),
            "OpenMOSS-Team/MOSS-Image-SFT",
        )
        with self.assertRaises(ValueError):
            parse_hf_repo_id("invalid_single_segment")

        merged_m = get_merged_media_presets([{"src_repo": "black-forest-labs/FLUX.1-dev", "arch": "flux", "note": "Dev"}])
        self.assertTrue(any(v.get("src_repo") == "black-forest-labs/FLUX.1-dev" for v in merged_m.values()))
        merged_l = get_merged_llm_presets([{"src_repo": "bartowski/Qwen2.5-14B-Instruct-GGUF", "src_file": "Qwen2.5-14B-Q4_K_M.gguf"}])
        self.assertTrue(any(v.get("src_file") == "Qwen2.5-14B-Q4_K_M.gguf" for v in merged_l.values()))


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
        self.loc_srv = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_local_bridge_handler(self.loc_state),
        )
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

    def test_full_handshake_json_streaming_and_xss_sanitization(self) -> None:
        ok, msg = configure_local_bridge(
            self.ticket,
            passphrase=self.passphrase,
            port=self.loc_port,
            work_dir=self.tmp_dir.name,
        )
        self.assertTrue(ok, msg)

        st = query_local_bridge_status(port=self.loc_port, work_dir=self.tmp_dir.name)
        self.assertIsNotNone(st)
        self.assertTrue(st["connected"])

        # A. 非流式请求端到端加解密往返 + 上游 text/html XSS 响应头强制清洗校验
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
            self.assertIn("application/json", (resp.headers.get("Content-Type") or "").lower())
            self.assertEqual((resp.headers.get("X-Content-Type-Options") or "").lower(), "nosniff")
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

    def test_local_bridge_dns_rebinding_cross_site_and_admin_ipc_auth(self) -> None:
        # 1. DNS Rebinding 伪造 Host 头必须返回 403
        rebind_req = urllib.request.Request(
            f"http://127.0.0.1:{self.loc_port}/v1/models",
            headers={"Host": f"rebind.attacker.example:{self.loc_port}"},
            method="GET",
        )
        with self.assertRaises(urllib.error.HTTPError) as cm_host:
            urllib.request.urlopen(rebind_req, timeout=3)
        self.assertEqual(cm_host.exception.code, 403)

        # 2. Sec-Fetch-Site: cross-site 跨站请求必须返回 403
        sfs_req = urllib.request.Request(
            f"http://127.0.0.1:{self.loc_port}/v1/models",
            headers={"Sec-Fetch-Site": "cross-site"},
            method="GET",
        )
        with self.assertRaises(urllib.error.HTTPError) as cm_sfs:
            urllib.request.urlopen(sfs_req, timeout=3)
        self.assertEqual(cm_sfs.exception.code, 403)

        # 3. 外部网页 Origin 必须返回 403
        origin_req = urllib.request.Request(
            f"http://127.0.0.1:{self.loc_port}/v1/models",
            headers={"Origin": "https://malicious.example"},
            method="GET",
        )
        with self.assertRaises(urllib.error.HTTPError) as cm_orig:
            urllib.request.urlopen(origin_req, timeout=3)
        self.assertEqual(cm_orig.exception.code, 403)

        # 4. 未携带 X-KissShot-Admin-Token 的管理接口调用必须返回 403
        unauth_cfg = urllib.request.Request(
            f"http://127.0.0.1:{self.loc_port}/__kissshot/configure",
            data=b'{"ticket":"x"}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as cm_adm:
            urllib.request.urlopen(unauth_cfg, timeout=3)
        self.assertEqual(cm_adm.exception.code, 403)

    def test_scanner_403_ssrf_allowlist_and_anti_replay_defense(self) -> None:
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

        cipher = derive_session_cipher(self.passphrase, self.rem_ctx.session_salt)
        url = f"http://127.0.0.1:{self.rem_port}{self.rem_ctx.route_path}"

        # 2. 即使通过认证，尝试访问非白名单内部管理路径 (/admin/internal) 也必须被 SSRF 白名单拦截返回 403
        ssrf_meta = json.dumps({"id": "ssrf_probe_id_0001", "method": "GET", "path": "/admin/internal", "ts": int(time.time())}).encode("utf-8")
        ssrf_wire = aead_seal(cipher, ssrf_meta + b"\n", f"kissshot-c2s-v1:{self.rem_ctx.route_path}".encode("utf-8"))
        ssrf_req = urllib.request.Request(url, data=ssrf_wire, headers={"Content-Type": "application/octet-stream"}, method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm_ssrf:
            urllib.request.urlopen(ssrf_req, timeout=3)
        self.assertEqual(cm_ssrf.exception.code, 403)

        # 3. 抓包重放攻击验证：第一次通过，第二次重放必须返回 403
        meta = json.dumps({"id": "replay_test_id_0001", "method": "GET", "path": "/health", "ts": int(time.time())}).encode("utf-8")
        wire = aead_seal(cipher, meta + b"\n", f"kissshot-c2s-v1:{self.rem_ctx.route_path}".encode("utf-8"))
        req1 = urllib.request.Request(url, data=wire, headers={"Content-Type": "application/octet-stream"}, method="POST")
        with urllib.request.urlopen(req1, timeout=3) as r1:
            self.assertEqual(r1.status, 200)

        req2 = urllib.request.Request(url, data=wire, headers={"Content-Type": "application/octet-stream"}, method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm_replay:
            urllib.request.urlopen(req2, timeout=3)
        self.assertEqual(cm_replay.exception.code, 403)

    def test_sse_truncation_without_eof_is_detected(self) -> None:
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
    def test_notebooks_ast_valid(self) -> None:
        import kiss_shot

        self.assertEqual(kiss_shot.__version__, "1.3.0")
        self.assertEqual(
            (AAD_PAYLOAD, AAD_TICKET, AAD_BLOB, AAD_ARCHIVE, AAD_QUEUE),
            (
                b"kissshot-payload-v2",
                b"kissshot-ticket-v2",
                b"kissshot-blob-v2",
                b"kissshot-archive-v2",
                b"kissshot-queue-v2",
            ),
        )
        repo_root = Path(__file__).resolve().parent.parent
        for nb_path in (repo_root / "notebooks").glob("*.ipynb"):
            nb = json.loads(nb_path.read_text(encoding="utf-8"))
            for cell in nb.get("cells", []):
                if cell.get("cell_type") == "code":
                    ast.parse("".join(cell.get("source", [])))

    def test_win32_tray_and_shortcut_helpers(self) -> None:
        from kiss_shot import __main__ as cli_mod
        from kiss_shot import panel as panel_mod
        from kiss_shot import win_tray

        ico = panel_mod._get_icon_path()
        self.assertTrue(ico.is_file())
        svg = ico.with_name("logo.svg")
        self.assertTrue(svg.is_file())

        if sys.platform == "win32":
            woke: list[int] = []
            cls_name = f"KissShotTrayUnit_{os.getpid()}_{time.time_ns()}"
            tray = win_tray.Win32TrayController(
                class_name=cls_name,
                tooltip="Kiss-Shot Unit Test",
                ico_path=ico,
                on_open=lambda: woke.append(1),
                menu_builder=lambda: [("Open", lambda: None)],
                dispatch_ui=lambda cb: cb(),
            )
            try:
                tray.start()
                self.assertNotEqual(tray._hwnd, 0)
                self.assertTrue(win_tray.signal_existing_instance(cls_name))
                for _ in range(30):
                    if woke:
                        break
                    time.sleep(0.02)
                self.assertEqual(woke, [1])
            finally:
                tray.stop()

            with tempfile.TemporaryDirectory() as tmp:
                res = win_tray.install_start_menu_shortcut(
                    shortcut_name="KissShotUnitTest",
                    arguments="-m kiss_shot panel",
                    working_dir=tmp,
                    icon_path=ico,
                    app_id=panel_mod.APP_USER_MODEL_ID,
                    description="Kiss-Shot unit test shortcut",
                    target_dir=tmp,
                )
                self.assertTrue(res["ok"])
                self.assertTrue(Path(str(res["path"])).is_file())
                rem = win_tray.remove_start_menu_shortcut("KissShotUnitTest", target_dir=tmp)
                self.assertTrue(rem["ok"])
                self.assertTrue(rem["removed"])
        self.assertTrue(hasattr(cli_mod, "_cmd_shortcut"))

    def test_zero_personal_paths_or_private_fingerprints(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        forbidden_tokens = [
            "C:\\Users\\" + "shana",
            "C:/Users/" + "shana",
            "BRIDGE_" + "TICKET",
            "colab_gpu_" + "aes256",
            "colab-" + "gpu:",
            "proj-runtime-" + "cache",
            "tensor_" + "worker",
            "edge_" + "connector",
            "try" + "cloudflare",
            "vis-lab-" + "2d",
            "vis-lab-" + "ext",
            "nlp-lab-" + "72b",
            "nlp-lab-" + "ext",
            "KissShot-" + "Vault",
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


def _extract_notebook_symbols(
    nb_rel_path: str,
    cell_index: int,
    names: set[str],
    base_ns: dict,
) -> dict:
    """Safely parse and execute only the requested top-level defs/classes/assignments from a notebook cell."""
    repo_root = Path(__file__).resolve().parent.parent
    nb = json.loads((repo_root / nb_rel_path).read_text(encoding="utf-8"))
    src = "".join(nb["cells"][cell_index].get("source", []))
    tree = ast.parse(src)
    selected: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in names:
                selected.append(node)
        elif isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if any(t in names for t in targets):
                selected.append(node)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id in names:
                selected.append(node)
    mod = ast.Module(body=selected, type_ignores=[])
    ast.fix_missing_locations(mod)
    ns = dict(base_ns)
    exec(compile(mod, f"{nb_rel_path}#cell{cell_index}", "exec"), ns)
    return ns


class _MockCASConflict(RuntimeError):
    def __init__(self, msg: str = "412 Precondition Failed: parent_commit outdated") -> None:
        super().__init__(msg)
        self.response = type("Resp", (), {"status_code": 412})()


class _InMemoryHFRepoApi:
    """Deterministic in-memory mock of HuggingFace HfApi with parent_commit CAS & blob_id tracking."""

    def __init__(self, initial_files: dict[str, bytes] | None = None) -> None:
        self._lock = threading.RLock()
        self.files: dict[str, bytes] = dict(initial_files or {})
        self.history: dict[str, dict[str, bytes]] = {}
        self._rev_seq = 0
        self.head = self._record_snapshot()
        self.fail_next_conflicts = 0
        self.commit_log: list[dict] = []

    def _record_snapshot(self) -> str:
        self._rev_seq += 1
        sha = hashlib.sha1(f"rev-{self._rev_seq}-{sorted(self.files.keys())}".encode("utf-8")).hexdigest()
        self.history[sha] = dict(self.files)
        return sha

    def repo_info(self, repo_id: str, repo_type: str = "model"):
        with self._lock:
            return type("RepoInfo", (), {"sha": self.head})()

    def list_repo_files(self, repo_id: str, repo_type: str = "model", revision: str | None = None):
        with self._lock:
            snap = self.history.get(revision, self.files) if revision else self.files
            return sorted(snap.keys())

    def list_repo_tree(
        self,
        repo_id: str,
        path_in_repo: str = "",
        repo_type: str = "model",
        revision: str | None = None,
        recursive: bool = False,
    ):
        with self._lock:
            snap = self.history.get(revision, self.files) if revision else self.files
            prefix = f"{path_in_repo.rstrip('/')}/" if path_in_repo else ""
            out = []
            for p, data in sorted(snap.items()):
                if prefix and not p.startswith(prefix):
                    continue
                out.append(
                    {
                        "path": p,
                        "blob_id": compute_git_blob_id(data),
                        "size": len(data),
                    }
                )
            return out

    def create_commit(
        self,
        *,
        repo_id: str,
        repo_type: str = "model",
        operations: list,
        commit_message: str = "",
        parent_commit: str | None = None,
    ):
        with self._lock:
            if self.fail_next_conflicts > 0:
                self.fail_next_conflicts -= 1
                self.head = self._record_snapshot()
                raise _MockCASConflict()
            if parent_commit and parent_commit != self.head:
                raise _MockCASConflict(f"412 Precondition Failed: expected {self.head}, got {parent_commit}")
            for op in operations:
                if isinstance(op, CommitOperationAdd):
                    raw = op.path_or_fileobj
                    if isinstance(raw, (bytes, bytearray)):
                        self.files[op.path_in_repo] = bytes(raw)
                    elif hasattr(raw, "read"):
                        self.files[op.path_in_repo] = raw.read()
                    else:
                        self.files[op.path_in_repo] = Path(str(raw)).read_bytes()
                elif isinstance(op, CommitOperationDelete):
                    self.files.pop(op.path_in_repo, None)
            self.head = self._record_snapshot()
            self.commit_log.append(
                {
                    "message": commit_message,
                    "parent_commit": parent_commit,
                    "new_head": self.head,
                    "ops": len(operations),
                }
            )
            return type("CommitInfo", (), {"oid": self.head})()

    def make_downloader(self):
        def _dl(repo_id: str, filename: str, repo_type: str = "model", token=False, local_dir: str = "", revision: str | None = None):
            with self._lock:
                snap = self.history.get(revision, self.files) if revision else self.files
                if filename not in snap:
                    raise FileNotFoundError(f"Missing {filename} at revision={revision}")
                raw = snap[filename]
            dst = Path(local_dir) / filename
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(raw)
            return str(dst)

        return _dl


class TestV130LedgerDeliveryRuntimeLockAndHelpers(unittest.TestCase):
    def test_job_ledger_persistence_outbox_failures_and_receipts(self) -> None:
        pwd = "ledger-unit-test-secret"
        with tempfile.TemporaryDirectory() as tmpd:
            db_path = os.path.join(tmpd, ".kissshot_jobs.sqlite3")
            q_ct = encrypt_queue_job({"type": "kissshot_media_infer", "prompt": "secret-prompt"}, pwd)
            ref_ct = encrypt_bytes_aes(b"fake-ref-img", pwd, aad=AAD_BLOB)
            q_rel = make_queue_v2_path("job_alpha_01", ts=1700000100)

            with JobLedger(db_path) as ledger:
                created = ledger.create_job(
                    "job_alpha_01",
                    "owner/mailbox",
                    q_rel,
                    preset_key="moss_image_sft",
                    arch="moss",
                    ref_rel="_staging/ref_0123456789ab.bin",
                    outbox_blobs=[
                        (q_rel, "queue", q_ct),
                        ("_staging/ref_0123456789ab.bin", "ref", ref_ct),
                    ],
                )
                self.assertEqual(created["state"], "pending_upload")
                self.assertEqual(len(ledger.list_pending_uploads("owner/mailbox")), 1)
                self.assertEqual(len(ledger.get_outbox_blobs("job_alpha_01")), 2)

                # Ciphertext only in SQLite, never plaintext prompts
                raw_db = Path(db_path).read_bytes()
                self.assertNotIn(b"secret-prompt", raw_db)

                self.assertEqual(ledger.mark_outbox_uploaded("job_alpha_01"), 2)
                self.assertEqual(ledger.get_outbox_blobs("job_alpha_01"), [])
                self.assertEqual(len(ledger.get_outbox_blobs("job_alpha_01", include_uploaded=True)), 2)

                ledger.update_job_state("job_alpha_01", "queued", increment_attempts=True)
                self.assertEqual(ledger.purge_outbox_blobs("job_alpha_01"), 2)
                ledger.record_failure("job_alpha_01", "upload", "transient 412", error_code="412", retryable=True)
                self.assertEqual(len(ledger.list_failures("job_alpha_01")), 1)

                pkt_rel = "_inbox/pkt_1700000200_abcd1234.bin"
                ledger.record_receipt(
                    pkt_rel,
                    job_id="job_alpha_01",
                    packet_blob_id="a" * 40,
                    packet_revision="b" * 40,
                    status="unpacked",
                    saved_paths=["out_01.png"],
                )
                self.assertTrue(ledger.is_packet_processed(pkt_rel, "a" * 40))
                self.assertFalse(ledger.is_packet_processed(pkt_rel, "c" * 40))
                ledger.mark_receipt_burned(pkt_rel)
                ledger.update_job_state("job_alpha_01", "completed", packet_rel=pkt_rel, saved_paths=["out_01.png"])

            # Restart recovery: reopen the same SQLite ledger
            with JobLedger(db_path) as reopened:
                job = reopened.get_job("job_alpha_01")
                self.assertIsNotNone(job)
                assert job is not None
                self.assertEqual(job["state"], "completed")
                self.assertEqual(job["attempts"], 1)
                self.assertEqual(job["saved_paths"], ["out_01.png"])
                rec = reopened.get_receipt("_inbox/pkt_1700000200_abcd1234.bin")
                self.assertIsNotNone(rec)
                assert rec is not None
                self.assertEqual(rec["status"], "burned")
                self.assertGreater(rec["burned_at"], 0)
                summary = reopened.summary()
                self.assertEqual(summary["completed"], 1)
                self.assertEqual(summary["receipts"], 1)
                self.assertEqual(summary["failures"], 1)

    def test_mailbox_delivery_cas_revision_blob_id_and_conditional_burn(self) -> None:
        q_v2 = make_queue_v2_path("abc12345", ts=1700000500)
        self.assertTrue(is_queue_job_path(q_v2))
        self.assertTrue(is_queue_job_path("_queue/job_1700000500_deadbeef.bin"))
        self.assertFalse(is_queue_job_path("_queue/../escape.bin"))
        self.assertEqual(extract_job_id_from_queue_path(q_v2), "abc12345")

        payload_a = b"cipher-packet-alpha"
        payload_b = b"cipher-packet-beta"
        git_sha_a = compute_git_blob_id(payload_a)
        lfs_sha_a = compute_sha256_hex(payload_a)
        self.assertTrue(verify_packet_blob_id(payload_a, git_sha_a))
        self.assertTrue(verify_packet_blob_id(payload_a, lfs_sha_a))
        self.assertFalse(verify_packet_blob_id(payload_b, git_sha_a))
        self.assertFalse(verify_packet_blob_id(payload_a, "not-a-valid-hex"))

        api = _InMemoryHFRepoApi()
        api.fail_next_conflicts = 1
        enq = enqueue_job_v2(
            api,
            "owner/mailbox",
            q_v2,
            b"enc-queue-job",
            staging_ops=[CommitOperationAdd(path_in_repo="_staging/ref_0123456789ab.bin", path_or_fileobj=b"enc-ref")],
            max_retries=3,
        )
        self.assertTrue(enq["committed"])
        self.assertEqual(enq["attempts"], 2)
        self.assertIn(q_v2, api.files)

        # Put two inbox packets and verify revision-locked + blob_id-verified download
        pkt1 = "_inbox/pkt_1700000600_1111aaaa.bin"
        pkt2 = "_inbox/pkt_1700000601_2222bbbb.bin"
        commit_with_parent_retry(
            api,
            "owner/mailbox",
            [
                CommitOperationAdd(path_in_repo=pkt1, path_or_fileobj=payload_a),
                CommitOperationAdd(path_in_repo=pkt2, path_or_fileobj=payload_b),
            ],
            "publish inbox",
        )
        rev, pkts = list_inbox_packets_with_revision(api, "owner/mailbox")
        self.assertIsNotNone(rev)
        self.assertEqual([p.path for p in pkts], [pkt1, pkt2])

        with tempfile.TemporaryDirectory() as td:
            raw1 = download_verified_packet(
                "owner/mailbox",
                pkts[0],
                token="hf_tok",
                local_dir=td,
                downloader=api.make_downloader(),
            )
            self.assertEqual(raw1, payload_a)

            tampered_info = MailboxPacketInfo(path=pkt1, blob_id="0" * 40, size=len(payload_a), revision=rev)
            with self.assertRaises(ValueError):
                download_verified_packet(
                    "owner/mailbox",
                    tampered_info,
                    token="hf_tok",
                    local_dir=td,
                    downloader=api.make_downloader(),
                )

        # Simulate concurrent overwrite of pkt2 before conditional burn -> stale parent_commit triggers 412,
        # conflict handler refreshes tree and burns ONLY unchanged pkt1 while skipping mutated pkt2!
        stale_parent = rev
        commit_with_parent_retry(
            api,
            "owner/mailbox",
            [CommitOperationAdd(path_in_repo=pkt2, path_or_fileobj=b"mutated-newer-packet")],
            "concurrent overwrite of pkt2",
        )
        burn_res = burn_packets_conditional(api, "owner/mailbox", pkts, parent_commit=stale_parent, max_retries=3)
        self.assertEqual(burn_res["removed_count"], 1)
        self.assertEqual(burn_res["removed_paths"], [pkt1])
        self.assertEqual(burn_res["skipped_paths"], [pkt2])
        self.assertNotIn(pkt1, api.files)
        self.assertEqual(api.files[pkt2], b"mutated-newer-packet")

    def test_runtime_lock_snapshot_verify_strict_and_compat_modes(self) -> None:
        unlocked = verify_runtime_lock(None, strict=False)
        self.assertTrue(unlocked["ok"])
        self.assertTrue(unlocked["allowed"])
        self.assertEqual(unlocked["mode"], "unlocked")

        with self.assertRaises(RuntimeError):
            verify_runtime_lock(None, strict=True)

        versions = {"cryptography": "43.0.1", "huggingface_hub": "0.26.2"}
        manifest = snapshot_runtime_lock("llm", installed_overrides=versions)
        self.assertEqual(manifest["schema"], RUNTIME_LOCK_SCHEMA)
        self.assertEqual(manifest["profile"], "llm")

        ok_res = verify_runtime_lock(manifest, profile="llm", strict=True, installed_versions=versions)
        self.assertTrue(ok_res["ok"])
        self.assertEqual(ok_res["mode"], "verified")

        # Drift under strict=False warns and allows; under strict=True raises RuntimeError
        drifted_versions = {"cryptography": "44.0.0", "huggingface_hub": "0.26.2"}
        warn_res = verify_runtime_lock(manifest, profile="llm", strict=False, installed_versions=drifted_versions)
        self.assertFalse(warn_res["ok"])
        self.assertTrue(warn_res["allowed"])
        self.assertEqual(warn_res["mode"], "warn")
        self.assertEqual(len(warn_res["mismatches"]), 1)
        with self.assertRaises(RuntimeError):
            verify_runtime_lock(manifest, profile="llm", strict=True, installed_versions=drifted_versions)

        # Tampered manifest_sha256 detection
        tampered = json.loads(json.dumps(manifest))
        tampered["packages"]["cryptography"]["version"] = "99.9.9"
        with self.assertRaises(RuntimeError):
            verify_runtime_lock(tampered, profile="llm", strict=True, installed_versions={"cryptography": "99.9.9", "huggingface_hub": "0.26.2"})

        with tempfile.TemporaryDirectory() as tmpd:
            lp = Path(tmpd) / "runtime_lock.json"
            save_runtime_lock(lp, manifest)
            loaded = load_runtime_lock(lp)
            self.assertEqual(loaded, manifest)

    def test_single_profile_sillytavern_binding_and_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpd:
            root = Path(tmpd)
            p_def = root / "data" / "default-user"
            p_alt = root / "data" / "alt-user"
            p_def.mkdir(parents=True)
            p_alt.mkdir(parents=True)
            orig_def = {"main_api": "kobold", "oai_settings": {"custom_url": "https://old-def"}}
            orig_alt = {"main_api": "textgenerationwebui", "oai_settings": {"custom_url": "https://old-alt"}}
            (p_def / "settings.json").write_text(json.dumps(orig_def), encoding="utf-8")
            (p_alt / "settings.json").write_text(json.dumps(orig_alt), encoding="utf-8")

            self.assertEqual(sillytavern_profiles(root), ["alt-user", "default-user"])

            # Multi-profile without explicit profile MUST refuse rather than bulk-overwrite
            with self.assertRaises(ValueError):
                bind_sillytavern_client(root, port=18443, st_server="")
            self.assertEqual(json.loads((p_def / "settings.json").read_text(encoding="utf-8")), orig_def)
            self.assertEqual(json.loads((p_alt / "settings.json").read_text(encoding="utf-8")), orig_alt)

            # Invalid / traversal profile rejected
            with self.assertRaises(ValueError):
                bind_sillytavern_client(root, port=18443, st_server="", profile="../default-user")

            # Explicit single profile binds ONLY alt-user and backs up original once
            cnt, _ = bind_sillytavern_client(root, port=18443, st_server="", profile="alt-user")
            self.assertEqual(cnt, 1)
            self.assertEqual(json.loads((p_def / "settings.json").read_text(encoding="utf-8")), orig_def)
            self.assertFalse((p_def / "settings.before-kiss-shot.json").exists())

            updated_alt = json.loads((p_alt / "settings.json").read_text(encoding="utf-8"))
            self.assertEqual(updated_alt["oai_settings"]["custom_url"], "http://127.0.0.1:18443/v1")
            bak_alt = json.loads((p_alt / "settings.before-kiss-shot.json").read_text(encoding="utf-8"))
            self.assertEqual(bak_alt, orig_alt)

            # Second re-bind to a different port preserves the original pre-kiss-shot backup
            cnt2, _ = bind_sillytavern_client(root, port=19443, st_server="", profile="alt-user")
            self.assertEqual(cnt2, 1)
            self.assertEqual(json.loads((p_alt / "settings.before-kiss-shot.json").read_text(encoding="utf-8")), orig_alt)

    def test_idempotent_packet_id_unpack_and_user_edit_protection(self) -> None:
        pwd = "idempotent-unpack-secret"
        payload = b"\x89PNG\r\n\x1a\nidempotent-artifact-bytes"
        arc = pack_encrypted_zip([("png", payload)], pwd, extra_meta={"seed": 77})
        with tempfile.TemporaryDirectory() as tmpd:
            paths1, meta1 = unpack_encrypted_zip(arc, pwd, tmpd, prefix="ks", packet_id="pkt_1700001111_a1b2")
            self.assertEqual(meta1.get("seed"), 77)
            self.assertEqual(len(paths1), 1)
            self.assertTrue(os.path.basename(paths1[0]).startswith("ks_pkt_1700001111_a1b2_01"))

            # Re-unpacking identical archive with same packet_id reuses the exact file without duplicates
            paths2, _ = unpack_encrypted_zip(arc, pwd, tmpd, prefix="ks", packet_id="pkt_1700001111_a1b2")
            self.assertEqual(paths2, paths1)
            self.assertEqual(len(list(Path(tmpd).glob("*.png"))), 1)

            # If user edited the existing file, re-unpacking MUST raise FileExistsError and preserve user edits
            user_edited = b"user-retouched-artwork"
            Path(paths1[0]).write_bytes(user_edited)
            with self.assertRaises(FileExistsError):
                unpack_encrypted_zip(arc, pwd, tmpd, prefix="ks", packet_id="pkt_1700001111_a1b2")
            self.assertEqual(Path(paths1[0]).read_bytes(), user_edited)

    def test_panel_v130_helper_functions(self) -> None:
        from kiss_shot.panel import (
            format_burn_report,
            resolve_recipe_restore_values,
            strip_queue_job_secrets,
            validate_media_batch,
        )

        self.assertEqual(validate_media_batch("image", 4), 4)
        self.assertEqual(validate_media_batch("video_t2v", 1), 1)
        with self.assertRaises(ValueError):
            validate_media_batch("video_t2v", 2)
        with self.assertRaises(ValueError):
            validate_media_batch("video_i2v", 3)
        with self.assertRaises(ValueError):
            validate_media_batch("image", 0)

        raw_job = {"type": "kissshot_media_infer", "prompt": "hi", "hf_token": "hf_secret_123"}
        cleaned = strip_queue_job_secrets(raw_job)
        self.assertNotIn("hf_token", cleaned)
        self.assertIn("hf_token", raw_job)
        self.assertEqual(cleaned["prompt"], "hi")

        # Recipe restore prefers base_width/base_height and clears stale LoRA fields
        restored_new = resolve_recipe_restore_values(
            {"base_width": 1024, "base_height": 768, "width": 2048, "height": 1536, "upscale_2x": True}
        )
        self.assertEqual(restored_new["width"], 1024)
        self.assertEqual(restored_new["height"], 768)
        self.assertEqual(restored_new["lora_repo"], "")
        self.assertEqual(restored_new["lora_weight"], "")
        self.assertEqual(restored_new["lora_strength"], "0.8")

        restored_legacy = resolve_recipe_restore_values(
            {"width": 2048, "height": 1024, "upscale_2x": True, "lora_repo": "org/lora", "lora_strength": 0.65}
        )
        self.assertEqual(restored_legacy["width"], 1024)
        self.assertEqual(restored_legacy["height"], 512)
        self.assertEqual(restored_legacy["lora_repo"], "org/lora")
        self.assertEqual(restored_legacy["lora_strength"], "0.65")

        rep_clean = format_burn_report(2, {"removed_count": 1, "skipped_paths": []})
        self.assertIn("2", rep_clean)
        self.assertIn("1", rep_clean)
        rep_skip = format_burn_report(2, {"removed_count": 1, "skipped_paths": ["_inbox/pkt_x.bin"]})
        self.assertIn("跳过 1", rep_skip)


class TestNotebookV130SecurityRegressions(unittest.TestCase):
    def _load_media_cell1(self) -> dict:
        return _extract_notebook_symbols(
            "notebooks/remote_media_worker.ipynb",
            1,
            {
                "_SENSITIVE_HISTORY_PATTERNS",
                "_SENSITIVE_MEM_TOKENS",
                "_scrub_sqlite_history_file",
                "RUNTIME_LOCK_STRICT",
                "_SAFE_STAGING_RE",
                "_SAFE_QUEUE_V2_RE",
                "_SAFE_QUEUE_LEGACY_RE",
                "_COMMIT_SHA_RE",
                "_HF_REPO_ID_RE",
                "PINNED_MODEL_REVISIONS",
                "PINNED_FILE_SHA256",
                "APPROVED_MOSS_SOURCES",
                "_EXECUTABLE_SUFFIXES",
                "_EXECUTABLE_IGNORE_PATTERNS",
                "_PIPE_CACHE",
                "_sha256_file",
                "_job_arch",
                "_is_executable_repo_file",
                "_strip_repo_executables",
                "verified_model_file",
                "_approved_moss_source",
                "_set_lora_strength",
            },
            {
                "os": os,
                "re": re,
                "hashlib": hashlib,
                "hmac": hmac,
                "inspect": inspect,
                "sqlite3": sqlite3,
                "hf_hub_download": None,
            },
        )

    def _load_media_cell2(self, c1: dict) -> dict:
        return _extract_notebook_symbols(
            "notebooks/remote_media_worker.ipynb",
            2,
            {
                "CLAIM_LEASE_TTL_SEC",
                "CLAIM_HEARTBEAT_SEC",
                "WORKER_ID",
                "_is_queue_job_path",
                "_extract_job_id",
                "_claim_path",
                "_receipt_path",
                "_is_cas_conflict",
                "_repo_head_sha",
                "_commit_cas",
                "_try_claim_job",
                "_ClaimHeartbeat",
                "_finish_job",
            },
            {
                "os": os,
                "re": re,
                "json": json,
                "time": time,
                "secrets": secrets,
                "tempfile": tempfile,
                "threading": threading,
                "inspect": inspect,
                "CommitOperationAdd": CommitOperationAdd,
                "CommitOperationDelete": CommitOperationDelete,
                "hf_hub_download": None,
                "_SAFE_STAGING_RE": c1["_SAFE_STAGING_RE"],
                "_SAFE_QUEUE_V2_RE": c1["_SAFE_QUEUE_V2_RE"],
                "_SAFE_QUEUE_LEGACY_RE": c1["_SAFE_QUEUE_LEGACY_RE"],
            },
        )

    def test_k01_k02_k08_k15_media_worker_notebook(self) -> None:
        c1 = self._load_media_cell1()
        self.assertFalse(c1["RUNTIME_LOCK_STRICT"])

        # K01: _job_arch preserves wan_ti2v_5b (and normalizes legacy wan_ti2v)
        job_arch = c1["_job_arch"]
        self.assertEqual(job_arch("wan_ti2v_5b"), "wan_ti2v_5b")
        self.assertEqual(job_arch({"arch": "wan_ti2v"}), "wan_ti2v_5b")
        self.assertEqual(job_arch({"arch": "MOSS"}), "moss")

        # K02: All 8 pinned repos have valid 40-char commit SHAs and verified_model_file enforces pin + SHA-256
        pinned_revs = c1["PINNED_MODEL_REVISIONS"]
        self.assertEqual(len(pinned_revs), 8)
        for repo, sha in pinned_revs.items():
            self.assertRegex(sha, r"^[0-9a-f]{40}$", f"Unpinned or invalid SHA for {repo}")

        verified_model_file = c1["verified_model_file"]
        good_bytes = b"verified-model-weights-v130"
        good_sha = hashlib.sha256(good_bytes).hexdigest()

        def _fake_dl(repo_id, filename, revision, local_dir, token=False):
            p = Path(local_dir) / filename
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(good_bytes)
            return str(p)

        with tempfile.TemporaryDirectory() as tmpd:
            with self.assertRaises(ValueError):
                verified_model_file("unpinned/repo", "model.bin", local_dir=tmpd, downloader=_fake_dl)

            ok_path = verified_model_file(
                "ai-forever/Real-ESRGAN",
                "RealESRGAN_x2.pth",
                local_dir=tmpd,
                expected_sha256=good_sha,
                downloader=_fake_dl,
            )
            self.assertTrue(os.path.isfile(ok_path))

            with self.assertRaises(RuntimeError):
                verified_model_file(
                    "ai-forever/Real-ESRGAN",
                    "RealESRGAN_x2.pth",
                    local_dir=tmpd,
                    expected_sha256="f" * 64,
                    downloader=_fake_dl,
                )
            self.assertFalse(os.path.exists(ok_path))

        # K08: _approved_moss_source & _strip_repo_executables
        approved_moss = c1["_approved_moss_source"]
        moss_spec = c1["APPROVED_MOSS_SOURCES"]["OpenMOSS-Team/MOSS-Image-SFT"]
        with tempfile.TemporaryDirectory() as tmpd:
            with self.assertRaises(PermissionError):
                approved_moss("evil/MOSS-Fork", tmpd, downloader=_fake_dl)
            with self.assertRaises(PermissionError):
                approved_moss("OpenMOSS-Team/MOSS-Image-SFT", tmpd, revision="0" * 40, downloader=_fake_dl)
            with self.assertRaises(RuntimeError):
                approved_moss("OpenMOSS-Team/MOSS-Image-SFT", tmpd, revision=moss_spec["revision"], downloader=_fake_dl)

            ok_moss = approved_moss(
                "OpenMOSS-Team/MOSS-Image-SFT",
                tmpd,
                approved_sources={
                    "OpenMOSS-Team/MOSS-Image-SFT": {
                        "revision": moss_spec["revision"],
                        "filename": "pipeline_moss_image.py",
                        "sha256": good_sha,
                    }
                },
                downloader=_fake_dl,
            )
            self.assertTrue(os.path.isfile(ok_moss))

            # Strip executables while keeping safetensors/json
            repo_dir = Path(tmpd) / "ckpt"
            (repo_dir / "sub").mkdir(parents=True)
            (repo_dir / "model.safetensors").write_bytes(b"weights")
            (repo_dir / "config.json").write_text("{}", encoding="utf-8")
            (repo_dir / "evil.py").write_text("import os", encoding="utf-8")
            (repo_dir / "sub" / "run.sh").write_text("echo pwn", encoding="utf-8")
            removed = c1["_strip_repo_executables"](str(repo_dir))
            self.assertEqual(sorted(removed), ["evil.py", "sub/run.sh"])
            self.assertTrue((repo_dir / "model.safetensors").is_file())
            self.assertTrue((repo_dir / "config.json").is_file())

        # K15: _set_lora_strength load, scale, no-op cache hit, unload, and validation
        class _MockLoraPipe:
            def __init__(self) -> None:
                self.loads: list[tuple] = []
                self.unloads = 0
                self.adapter_calls: list[tuple] = []

            def load_lora_weights(self, repo, weight_name=None, adapter_name=None, token=None):
                self.loads.append((repo, weight_name, adapter_name, token))

            def unload_lora_weights(self):
                self.unloads += 1

            def set_adapters(self, names, adapter_weights=None):
                self.adapter_calls.append((list(names), list(adapter_weights or [])))

        pipe = _MockLoraPipe()
        state = {"lora_sig": None, "lora_adapter": "ks_lora"}
        set_lora = c1["_set_lora_strength"]

        st1 = set_lora(pipe, "org/style-lora", "style.safetensors", 0.75, current_state=state)
        self.assertTrue(st1["active"])
        self.assertEqual(len(pipe.loads), 1)
        self.assertEqual(pipe.adapter_calls[-1], (["ks_lora"], [0.75]))

        # Same repo/weight only adjusts strength without reloading weights
        st2 = set_lora(pipe, "org/style-lora", "style.safetensors", 1.25, current_state=state)
        self.assertEqual(len(pipe.loads), 1)
        self.assertEqual(pipe.adapter_calls[-1], (["ks_lora"], [1.25]))
        self.assertEqual(st2["strength"], 1.25)

        # Empty repo or 0 strength cleanly unloads stale LoRA
        st3 = set_lora(pipe, "", "", 0.8, current_state=state)
        self.assertFalse(st3["active"])
        self.assertEqual(pipe.unloads, 1)
        self.assertIsNone(state["lora_sig"])

        with self.assertRaises(ValueError):
            set_lora(pipe, "../invalid", "", 0.8, current_state=state)

    def test_k07_media_worker_lease_claims_heartbeat_and_atomic_finish(self) -> None:
        c1 = self._load_media_cell1()
        c2 = self._load_media_cell2(c1)

        job_id = "jobk07test"
        q_rel = f"_queue/v2/job_1700002000_{job_id}.bin"
        ref_rel = "_staging/ref_0123456789ab.bin"
        api = _InMemoryHFRepoApi({q_rel: b"enc-job", ref_rel: b"enc-ref"})
        dl = api.make_downloader()

        # Worker A acquires lease claim
        claim_a = c2["_try_claim_job"](
            api, "owner/mailbox", job_id, q_rel, worker_id="w-alpha", lease_ttl=180, downloader=dl
        )
        self.assertIsNotNone(claim_a)
        self.assertIn(f"_claims/{job_id}.json", api.files)

        # Worker B cannot steal an active unexpired lease
        claim_b = c2["_try_claim_job"](
            api, "owner/mailbox", job_id, q_rel, worker_id="w-beta", lease_ttl=180, downloader=dl
        )
        self.assertIsNone(claim_b)

        # Heartbeat renews lease cleanly
        hb = c2["_ClaimHeartbeat"](api, "owner/mailbox", claim_a, interval_sec=10.0, lease_ttl=180)
        self.assertTrue(hb.beat_once())
        self.assertEqual(hb.beats, 1)
        renewed = json.loads(api.files[f"_claims/{job_id}.json"].decode("utf-8"))
        self.assertEqual(renewed["status"], "running")

        # Expired lease can be taken over by Worker B
        expired_doc = dict(renewed)
        expired_doc["expires_at"] = int(time.time()) - 10
        api.files[f"_claims/{job_id}.json"] = json.dumps(expired_doc).encode("utf-8")
        claim_b2 = c2["_try_claim_job"](
            api, "owner/mailbox", job_id, q_rel, worker_id="w-beta", lease_ttl=180, downloader=dl
        )
        self.assertIsNotNone(claim_b2)
        self.assertEqual(claim_b2["worker_id"], "w-beta")

        # Atomic _finish_job writes _inbox + _receipts and cleans _queue/_claims/_staging even across a 412 CAS retry
        api.fail_next_conflicts = 1
        pkt_rel = "_inbox/pkt_1700002050_cafe1234.bin"
        fin = c2["_finish_job"](
            api,
            "owner/mailbox",
            job_id=job_id,
            queue_rel=q_rel,
            status="completed",
            packet_rel=pkt_rel,
            packet_bytes=b"double-aead-archive",
            staging_rels=[ref_rel],
            worker_id="w-beta",
            max_retries=3,
        )
        self.assertTrue(fin["committed"])
        self.assertIn(pkt_rel, api.files)
        self.assertIn(f"_receipts/{job_id}.json", api.files)
        self.assertNotIn(q_rel, api.files)
        self.assertNotIn(f"_claims/{job_id}.json", api.files)
        self.assertNotIn(ref_rel, api.files)

    def test_k12_k13_selective_history_scrub_and_llm_gateway_engine_verify(self) -> None:
        # Verify K12 selective history scrubbing in BOTH notebooks
        for nb_rel in ("notebooks/remote_llm_gateway.ipynb", "notebooks/remote_media_worker.ipynb"):
            ns = _extract_notebook_symbols(
                nb_rel,
                1,
                {"_SENSITIVE_HISTORY_PATTERNS", "_SENSITIVE_MEM_TOKENS", "_scrub_sqlite_history_file", "RUNTIME_LOCK_STRICT"},
                {"os": os, "sqlite3": sqlite3},
            )
            self.assertFalse(ns["RUNTIME_LOCK_STRICT"])
            with tempfile.TemporaryDirectory() as tmpd:
                dbp = os.path.join(tmpd, "history.sqlite")
                con = sqlite3.connect(dbp)
                con.execute("CREATE TABLE history (session integer, line integer, source text, source_raw text)")
                con.execute("CREATE TABLE output_history (session integer, line integer, output text)")
                con.execute("INSERT INTO history VALUES (1, 1, 'KISSSHOT_TASK_HEX = \"deadbeef\"', 'KISSSHOT_TASK_HEX = \"deadbeef\"')")
                con.execute("INSERT INTO history VALUES (1, 2, 'SESSION_PASSPHRASE = \"secret\"', 'SESSION_PASSPHRASE = \"secret\"')")
                con.execute("INSERT INTO history VALUES (1, 3, 'print(\"unrelated user experiment\")', 'print(\"unrelated user experiment\")')")
                con.execute("INSERT INTO output_history VALUES (1, 1, 'KISSSHOT_TICKET:abc123')")
                con.execute("INSERT INTO output_history VALUES (1, 2, 'normal notebook output')")
                con.commit()
                con.close()

                removed = ns["_scrub_sqlite_history_file"](dbp)
                self.assertEqual(removed, 2, f"Expected 2 sensitive rows removed for {nb_rel}")

                con2 = sqlite3.connect(dbp)
                rem_hist = [r[0] for r in con2.execute("SELECT source FROM history").fetchall()]
                rem_out = [r[0] for r in con2.execute("SELECT output FROM output_history").fetchall()]
                con2.close()
                self.assertEqual(rem_hist, ['print("unrelated user experiment")'])
                self.assertEqual(rem_out, ["normal notebook output"])

        # Verify K13 loopback listen host default + verified_engine SHA-256 verification in LLM notebook
        llm_c2 = _extract_notebook_symbols(
            "notebooks/remote_llm_gateway.ipynb",
            2,
            {"GATEWAY_LISTEN_HOST", "verified_engine"},
            {"os": os, "hashlib": hashlib, "hmac": hmac},
        )
        self.assertEqual(llm_c2["GATEWAY_LISTEN_HOST"], "127.0.0.1")
        ve = llm_c2["verified_engine"]
        with tempfile.TemporaryDirectory() as tmpd:
            eng = Path(tmpd) / "llama-server"
            eng.write_bytes(b"ELF-mock-llama-server-binary")
            good_sha = hashlib.sha256(b"ELF-mock-llama-server-binary").hexdigest()

            r_ok = ve(str(eng), good_sha, strict=True)
            self.assertTrue(r_ok["ok"])
            self.assertTrue(r_ok["verified"])
            self.assertEqual(r_ok["sha256"], good_sha)

            r_unpinned = ve(str(eng), "", strict=False)
            self.assertTrue(r_unpinned["ok"])
            self.assertFalse(r_unpinned["verified"])

            with self.assertRaises(RuntimeError):
                ve(str(eng), "", strict=True)
            with self.assertRaises(RuntimeError):
                ve(str(eng), "0" * 64, strict=False)
            with self.assertRaises(FileNotFoundError):
                ve(os.path.join(tmpd, "nonexistent-bin"), good_sha, strict=True)


if __name__ == "__main__":
    unittest.main()
