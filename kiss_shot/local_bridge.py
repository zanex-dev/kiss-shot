# -*- coding: utf-8 -*-
"""
本地端到端 AES-256-GCM OpenAI 兼容透明加密网桥 (kiss_shot/local_bridge.py)

职责：
- 在用户工作站本地监听 127.0.0.1:18443/v1，向任意 OpenAI SDK / LangChain / OpenWebUI / SillyTavern 暴露标准接口。
- 所有请求（含多模态 Base64 图像与系统提示词）在离开本机前封装为高熵 AEAD 帧发送至远端动态路由。
- 流式 SSE 响应逐块校验递增序号 (seq) 与认证结束帧 (EOF:...)，如果中途被代理截断或丢包将立即抛出完整性异常。
- 支持后台监听剪贴板 KISSSHOT_TICKET:... 握手票据并自动完成密钥派生与热重连。
"""

from __future__ import annotations

import http.cookiejar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import tempfile
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .clipboard import read_clipboard_text
from .crypto import (
    DEFAULT_LOCAL_PORT,
    DEFAULT_MODEL_ALIAS,
    TICKET_PATTERN,
    TICKET_PREFIX,
    aead_open,
    aead_seal,
    derive_session_cipher,
    parse_handshake_ticket,
)

USER_AGENT = "kiss-shot/0.1"


def default_secrets_path(work_dir: Optional[str] = None) -> str:
    base = work_dir or os.getcwd()
    return os.path.join(base, ".kissshot_secrets.json")


def default_state_path(work_dir: Optional[str] = None) -> str:
    base = work_dir or os.getcwd()
    return os.path.join(base, ".kissshot_bridge_state.json")


def _load_saved_passphrase(secrets_file: str) -> str:
    if os.path.exists(secrets_file):
        try:
            with open(secrets_file, "r", encoding="utf-8") as f:
                return str(json.load(f).get("passphrase", "")).strip()
        except Exception:
            pass
    return ""


class LocalBridgeState:
    def __init__(self, work_dir: Optional[str] = None, model_alias: str = DEFAULT_MODEL_ALIAS) -> None:
        self.lock = threading.RLock()
        self.work_dir = work_dir or os.getcwd()
        self.secrets_file = default_secrets_path(self.work_dir)
        self.state_file = default_state_path(self.work_dir)
        self.model_alias = model_alias

        self.passphrase: str = ""
        self.session_salt: bytes = b""
        self.cipher: Optional[AESGCM] = None
        self.base_url: str = ""
        self.route_path: str = ""
        self.req_count: int = 0
        self.last_ok_ts: int = 0
        self.last_err: str = ""
        self.on_status_change: Optional[Callable[[Dict[str, Any]], None]] = None
        self.reload_from_disk()

    @property
    def endpoint_url(self) -> str:
        if self.base_url and self.route_path:
            return f"{self.base_url}{self.route_path}"
        return ""

    def reload_from_disk(self) -> None:
        with self.lock:
            pwd = _load_saved_passphrase(self.secrets_file)
            if pwd:
                self.passphrase = pwd
            if os.path.exists(self.state_file) and self.passphrase:
                try:
                    with open(self.state_file, "r", encoding="utf-8") as f:
                        st = json.load(f)
                    ticket_saved = str(st.get("ticket", "")).strip()
                    if ticket_saved:
                        parsed = parse_handshake_ticket(ticket_saved, self.passphrase)
                        self.base_url = parsed["base_url"]
                        self.route_path = parsed["route"]
                        self.session_salt = parsed["session_salt"]
                        self.cipher = derive_session_cipher(self.passphrase, self.session_salt)
                except Exception:
                    pass

    def configure_with_ticket(
        self,
        raw_ticket: str,
        passphrase_override: str = "",
        persist: bool = True,
    ) -> Tuple[bool, str]:
        with self.lock:
            pwd = passphrase_override.strip() or self.passphrase or _load_saved_passphrase(self.secrets_file)
            if not pwd:
                return False, "Passphrase not configured / 尚未设置加密口令"
            try:
                parsed = parse_handshake_ticket(raw_ticket, pwd)
            except Exception as exc:
                return False, f"Ticket decryption failed / 票据解密校验未通过: {exc}"

            self.passphrase = pwd
            self.base_url = parsed["base_url"]
            self.route_path = parsed["route"]
            self.session_salt = parsed["session_salt"]
            self.cipher = derive_session_cipher(pwd, self.session_salt)

            if persist:
                try:
                    clean_m = TICKET_PATTERN.search(raw_ticket)
                    canonical = f"{TICKET_PREFIX}{clean_m.group(1)}" if clean_m else raw_ticket.strip()
                    with open(self.state_file, "w", encoding="utf-8") as f:
                        json.dump({"ticket": canonical, "updated_at": int(time.time())}, f)
                except Exception:
                    pass

        ok, msg = self.ping_remote()
        self._notify()
        return ok, msg

    def ping_remote(self) -> Tuple[bool, str]:
        with self.lock:
            cipher = self.cipher
            endpoint = self.endpoint_url
            route = self.route_path
        if not cipher or not endpoint:
            return False, "Bridge not bound / 尚未绑定远端票据"

        t0 = time.time()
        try:
            req_id = secrets.token_hex(12)
            env = json.dumps({"id": req_id, "method": "GET", "path": "/health", "ts": int(time.time())}).encode("utf-8") + b"\n"
            wire = aead_seal(cipher, env, f"kissshot-c2s-v1:{route}".encode("utf-8"))
            req = urllib.request.Request(
                endpoint,
                data=wire,
                headers={"Content-Type": "application/octet-stream", "User-Agent": USER_AGENT},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                raw_out = resp.read()
            plain = aead_open(cipher, raw_out, f"kissshot-s2c-body:{req_id}".encode("ascii"))
            hdr_line, body = plain.split(b"\n", 1)
            hdr = json.loads(hdr_line.decode("utf-8"))
            ms = int((time.time() - t0) * 1000)
            if int(hdr.get("status", 0)) == 200:
                with self.lock:
                    self.last_ok_ts = int(time.time())
                    self.last_err = ""
                return True, f"E2EE AES-256-GCM handshake OK ({ms} ms)"
            return False, f"Upstream status={hdr.get('status')}: {body.decode('utf-8', 'ignore')[:80]}"
        except Exception as exc:
            with self.lock:
                self.last_err = str(exc)
            return False, f"Handshake failed: {exc}"

    def snapshot(self, listen_port: int = DEFAULT_LOCAL_PORT) -> Dict[str, Any]:
        with self.lock:
            masked = ""
            if self.base_url:
                masked = (
                    self.base_url[:18] + "..." + self.base_url[-12:]
                    if len(self.base_url) > 34
                    else self.base_url
                )
            return {
                "ok": True,
                "connected": bool(self.endpoint_url and self.cipher),
                "endpoint_masked": masked,
                "route_masked": (self.route_path[:8] + "...") if self.route_path else "",
                "model": self.model_alias,
                "port": listen_port,
                "req_count": self.req_count,
                "last_ok_ts": self.last_ok_ts,
                "last_err": self.last_err,
            }

    def _notify(self) -> None:
        cb = self.on_status_change
        if cb:
            try:
                cb(self.snapshot())
            except Exception:
                pass


def make_local_bridge_handler(state: LocalBridgeState, listen_port: int = DEFAULT_LOCAL_PORT):
    class LocalOpenAIBridgeHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _send_cors(self) -> None:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

        def _send_json(self, status: int, obj: Dict[str, Any]) -> None:
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self._send_cors()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self._send_cors()
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        def do_GET(self) -> None:
            if self.path == "/__kissshot/status":
                self._send_json(200, state.snapshot(listen_port))
                return

            if self.path.rstrip("/") in ("/v1/models", "/models"):
                self._send_json(
                    200,
                    {
                        "object": "list",
                        "data": [
                            {
                                "id": state.model_alias,
                                "object": "model",
                                "created": 1735689600,
                                "owned_by": "kiss-shot",
                            }
                        ],
                    },
                )
                return

            self._proxy_encrypted("GET", b"")

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length > 0 else b""

            if self.path == "/__kissshot/configure":
                try:
                    req_obj = json.loads(body.decode("utf-8")) if body else {}
                    ok, msg = state.configure_with_ticket(
                        raw_ticket=str(req_obj.get("ticket", "")),
                        passphrase_override=str(req_obj.get("passphrase", "")),
                    )
                    self._send_json(200 if ok else 400, {"ok": ok, "message": msg, "state": state.snapshot(listen_port)})
                except Exception as exc:
                    self._send_json(400, {"ok": False, "message": str(exc)})
                return

            self._proxy_encrypted("POST", body)

        def _reply_offline_hint(self, body: bytes) -> None:
            hint = (
                "🔒 [Kiss-Shot Standby] No remote KISSSHOT_TICKET bound yet.\n"
                "Start the remote AEAD gateway and copy the printed `KISSSHOT_TICKET:...` line — "
                "the local bridge will handshake automatically."
            )
            is_stream = False
            try:
                parsed = json.loads(body.decode("utf-8"))
                is_stream = bool(parsed.get("stream", False))
            except Exception:
                pass

            if is_stream:
                chunk = {
                    "id": "chatcmpl-ztgb-standby",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": state.model_alias,
                    "choices": [{"index": 0, "delta": {"role": "assistant", "content": hint}, "finish_reason": "stop"}],
                }
                sse = f"data: {json.dumps(chunk, ensure_ascii=False)}\n\ndata: [DONE]\n\n".encode("utf-8")
                self.send_response(200)
                self._send_cors()
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(sse)
                self.wfile.flush()
            else:
                self._send_json(
                    200,
                    {
                        "id": "chatcmpl-ztgb-standby",
                        "object": "chat.completion",
                        "created": int(time.time()),
                        "model": state.model_alias,
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": hint},
                                "finish_reason": "stop",
                            }
                        ],
                    },
                )

        def _proxy_encrypted(self, method: str, body: bytes) -> None:
            with state.lock:
                cipher = state.cipher
                endpoint = state.endpoint_url
                route = state.route_path

            if not cipher or not endpoint:
                if "completions" in self.path:
                    self._reply_offline_hint(body)
                else:
                    self._send_json(503, {"error": "bridge_not_connected"})
                return

            if method == "POST" and body and ("completions" in self.path):
                try:
                    jbody = json.loads(body.decode("utf-8"))
                    if isinstance(jbody, dict) and "model" in jbody:
                        jbody["model"] = state.model_alias
                        body = json.dumps(jbody, ensure_ascii=False).encode("utf-8")
                except Exception:
                    pass

            req_id = secrets.token_hex(12)
            meta = json.dumps({"id": req_id, "method": method, "path": self.path, "ts": int(time.time())}).encode("utf-8")
            wire_req = aead_seal(cipher, meta + b"\n" + body, f"kissshot-c2s-v1:{route}".encode("utf-8"))

            req = urllib.request.Request(
                endpoint,
                data=wire_req,
                headers={
                    "Content-Type": "application/octet-stream",
                    "Accept": "text/event-stream, application/octet-stream",
                    "User-Agent": USER_AGENT,
                },
                method="POST",
            )

            try:
                with urllib.request.urlopen(req, timeout=300) as up_resp:
                    up_ct = (up_resp.headers.get("Content-Type") or "").lower()
                    with state.lock:
                        state.req_count += 1
                        state.last_ok_ts = int(time.time())
                        state.last_err = ""
                    state._notify()

                    if "text/event-stream" in up_ct:
                        self.send_response(200)
                        self._send_cors()
                        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                        self.send_header("Cache-Control", "no-cache")
                        self.send_header("X-Accel-Buffering", "no")
                        self.send_header("Connection", "close")
                        self.end_headers()

                        seq = 0
                        verified_eof = False
                        while True:
                            raw_line = up_resp.readline()
                            if not raw_line:
                                break
                            line = raw_line.decode("ascii", errors="ignore").strip()
                            if not line or not line.startswith("data:"):
                                continue
                            payload = line[5:].strip()
                            if payload.startswith("EOF:"):
                                aead_open(cipher, bytes.fromhex(payload[4:]), f"kissshot-eof:{req_id}:{seq}".encode("ascii"))
                                verified_eof = True
                                break
                            plain_chunk = aead_open(
                                cipher,
                                bytes.fromhex(payload),
                                f"kissshot-s2c:{req_id}:{seq}".encode("ascii"),
                            )
                            seq += 1
                            self.wfile.write(plain_chunk)
                            self.wfile.flush()

                        if not verified_eof:
                            raise ValueError("Truncated SSE stream: missing authenticated EOF tag")
                    else:
                        raw_out = up_resp.read()
                        plain_out = aead_open(cipher, raw_out, f"kissshot-s2c-body:{req_id}".encode("ascii"))
                        hdr_line, resp_body = plain_out.split(b"\n", 1)
                        hdr = json.loads(hdr_line.decode("utf-8"))
                        self.send_response(int(hdr.get("status", 200)))
                        self._send_cors()
                        self.send_header("Content-Type", hdr.get("ct", "application/json; charset=utf-8"))
                        self.send_header("Content-Length", str(len(resp_body)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(resp_body)
            except Exception as exc:
                with state.lock:
                    state.last_err = str(exc)
                state._notify()
                try:
                    self._send_json(502, {"error": {"message": f"E2EE tunnel error: {exc}"}})
                except Exception:
                    pass

    return LocalOpenAIBridgeHandler


def is_port_listening(port: int = DEFAULT_LOCAL_PORT) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.35)
        return s.connect_ex(("127.0.0.1", port)) == 0


def query_local_bridge_status(port: int = DEFAULT_LOCAL_PORT) -> Optional[Dict[str, Any]]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/__kissshot/status", timeout=1.5) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def configure_local_bridge(
    ticket: str,
    passphrase: str = "",
    port: int = DEFAULT_LOCAL_PORT,
) -> Tuple[bool, str]:
    payload = json.dumps({"ticket": ticket, "passphrase": passphrase}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/__kissshot/configure",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
            return bool(data.get("ok")), str(data.get("message", ""))
    except urllib.error.HTTPError as he:
        try:
            data = json.loads(he.read().decode("utf-8"))
            return False, str(data.get("message", str(he)))
        except Exception:
            return False, str(he)
    except Exception as exc:
        return False, str(exc)


def bind_sillytavern_client(
    st_root: Path,
    port: int = DEFAULT_LOCAL_PORT,
    model_alias: str = DEFAULT_MODEL_ALIAS,
    st_server: str = "http://127.0.0.1:8000",
) -> Tuple[int, bool]:
    """可选辅助工具：将用户显式指定的本地 SillyTavern 目录指向本地加密网桥"""
    if not st_root or not st_root.exists():
        return 0, False

    bridge_v1 = f"http://127.0.0.1:{port}/v1"

    def _patch(settings: dict) -> dict:
        settings["main_api"] = "openai"
        oai = settings.setdefault("oai_settings", {})
        oai["chat_completion_source"] = "custom"
        oai["custom_url"] = bridge_v1
        oai["custom_model"] = model_alias
        oai["media_inlining"] = True
        oai["stream_openai"] = True
        return settings

    updated_cnt = 0
    data_dir = st_root / "data"
    if data_dir.exists():
        for sp in data_dir.glob("*/settings.json"):
            try:
                d = json.loads(sp.read_text(encoding="utf-8"))
                _patch(d)
                fd, tmp_p = tempfile.mkstemp(dir=str(sp.parent), prefix=".ztgb_st_", suffix=".tmp")
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(d, f, ensure_ascii=False, indent=4)
                os.replace(tmp_p, sp)
                updated_cnt += 1
            except Exception:
                pass

    api_ok = False
    try:
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        with opener.open(urllib.request.Request(f"{st_server}/csrf-token", method="GET"), timeout=1.5) as r:
            csrf = json.loads(r.read().decode("utf-8")).get("token", "")
        hdrs = {"Content-Type": "application/json", "X-CSRF-Token": csrf}
        with opener.open(urllib.request.Request(f"{st_server}/api/settings/get", data=b"{}", headers=hdrs, method="POST"), timeout=2) as r:
            raw_s = json.loads(r.read().decode("utf-8")).get("settings")
            s_dict = json.loads(raw_s) if isinstance(raw_s, str) else raw_s
        if isinstance(s_dict, dict):
            _patch(s_dict)
            body = json.dumps(s_dict, ensure_ascii=False, indent=4).encode("utf-8")
            with opener.open(urllib.request.Request(f"{st_server}/api/settings/save", data=body, headers=hdrs, method="POST"), timeout=2) as r:
                api_ok = json.loads(r.read().decode("utf-8")).get("result") == "ok"
    except Exception:
        pass

    return updated_cnt, api_ok


def _clipboard_watcher_loop(state: LocalBridgeState) -> None:
    last_seen = ""
    while True:
        try:
            txt = read_clipboard_text()
            if txt and TICKET_PREFIX in txt:
                m = TICKET_PATTERN.search(txt)
                if m and m.group(1) != last_seen:
                    last_seen = m.group(1)
                    ok, msg = state.configure_with_ticket(f"{TICKET_PREFIX}{last_seen}")
                    print(f"[Kiss-Shot] Clipboard ticket detected -> {'OK' if ok else 'PENDING'}: {msg}", flush=True)
        except Exception:
            pass
        time.sleep(1.2)


def start_local_bridge_background(
    port: int = DEFAULT_LOCAL_PORT,
    work_dir: Optional[str] = None,
    watch_clipboard: bool = True,
    on_status_change: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Tuple[Optional[ThreadingHTTPServer], LocalBridgeState]:
    """启动本地 OpenAI 兼容加密网桥后台线程（若端口已监听则复用状态查询）"""
    state = LocalBridgeState(work_dir=work_dir)
    if on_status_change:
        state.on_status_change = on_status_change

    if is_port_listening(port):
        return None, state

    srv = ThreadingHTTPServer(("127.0.0.1", port), make_local_bridge_handler(state, listen_port=port))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    if watch_clipboard:
        threading.Thread(target=_clipboard_watcher_loop, args=(state,), daemon=True).start()
    return srv, state
