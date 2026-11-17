# -*- coding: utf-8 -*-
"""
端到端密码学、域分离 AEAD、反压缩炸弹、DNS Rebinding 防御、HTTP/SSE 环回网关与仓库脱敏测试套件 (v1.0.0)
运行方式: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import ast
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile

from cryptography.exceptions import InvalidTag
import pyzipper

from kiss_shot.crypto import (
    AAD_ARCHIVE,
    AAD_BLOB,
    AAD_QUEUE,
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
from kiss_shot.local_bridge import (
    LocalBridgeState,
    configure_local_bridge,
    make_local_bridge_handler,
    query_local_bridge_status,
)
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

        self.assertEqual(kiss_shot.__version__, "1.2.0")
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


if __name__ == "__main__":
    unittest.main()
