# -*- coding: utf-8 -*-
"""
远端 GPU 节点纯内存 AES-256-GCM 认证网关 (kiss_shot/remote_gateway.py)

职责与纵深防御：
- 在远端算力节点内部将本地回环推理引擎（如 llama-server / vLLM / Ollama，仅绑定 127.0.0.1）包装为端到端 AEAD 网关。
- 每次启动随机生成一次性动态路由 (/v1/ks-<hex>) 与 128-bit 会话盐，签发 KISSSHOT_TICKET 握手票据。
- 内置时间戳窗口校验 (±300s) + 请求 ID 有界防重放守卫 (ReplayGuard) + 上游 API 路径白名单（防容器内部 SSRF）。
- 内置慢连接超时熔断 (timeout=15) 与并发信号量限制，任何未授权扫描、错误路径、篡改密文一律静默返回 403。
"""

from __future__ import annotations

from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import threading
import time
from typing import Any, Deque, Dict, Optional, Set, Tuple
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import (
    SALT_BYTES,
    aead_open,
    aead_seal,
    create_handshake_ticket,
    derive_session_cipher,
)

MAX_CLOCK_SKEW_SECONDS = 300
REPLAY_CACHE_SIZE = 4096
MAX_CONCURRENT_REQUESTS = 16
MAX_SSE_LINE_BYTES = 4 * 1024 * 1024
MAX_UPSTREAM_BODY_BYTES = 32 * 1024 * 1024

ALLOWED_UPSTREAM_PATHS = frozenset(
    {
        "/health",
        "/models",
        "/v1/models",
        "/v1/chat/completions",
        "/v1/completions",
        "/v1/embeddings",
        "/tokenize",
        "/detokenize",
    }
)


class ReplayGuard:
    """线程安全的有界请求 ID 防重放过滤器"""

    def __init__(self, max_size: int = REPLAY_CACHE_SIZE) -> None:
        self._lock = threading.Lock()
        self._queue: Deque[str] = deque()
        self._seen: Set[str] = set()
        self._max_size = max_size

    def check_and_record(self, req_id: str) -> bool:
        if not req_id or len(req_id) < 8 or len(req_id) > 64:
            return False
        with self._lock:
            if req_id in self._seen:
                return False
            if len(self._queue) >= self._max_size:
                oldest = self._queue.popleft()
                self._seen.discard(oldest)
            self._queue.append(req_id)
            self._seen.add(req_id)
            return True


class RemoteGatewayContext:
    def __init__(
        self,
        passphrase: str,
        upstream_base: str = "http://127.0.0.1:8080",
        route_path: Optional[str] = None,
        session_salt: Optional[bytes] = None,
        max_concurrency: int = MAX_CONCURRENT_REQUESTS,
    ) -> None:
        self.passphrase = passphrase
        self.upstream_base = upstream_base.rstrip("/")
        self.route_path = route_path or f"/v1/ks-{secrets.token_hex(8)}"
        if not self.route_path.startswith("/"):
            self.route_path = "/" + self.route_path
        self.session_salt = session_salt or secrets.token_bytes(SALT_BYTES)
        self.cipher: AESGCM = derive_session_cipher(passphrase, self.session_salt)
        self.replay_guard = ReplayGuard()
        self.concurrency_sem = threading.BoundedSemaphore(max_concurrency)
        self.stats_lock = threading.Lock()
        self.ok_requests = 0
        self.blocked_requests = 0

    def export_ticket(self, public_url: str) -> str:
        ticket, _, _ = create_handshake_ticket(
            base_url=public_url,
            passphrase=self.passphrase,
            route_path=self.route_path,
            session_salt=self.session_salt,
        )
        return ticket

    def record_ok(self) -> None:
        with self.stats_lock:
            self.ok_requests += 1

    def record_blocked(self) -> None:
        with self.stats_lock:
            self.blocked_requests += 1

    def stats(self) -> Dict[str, int]:
        with self.stats_lock:
            return {"ok_requests": self.ok_requests, "blocked_requests": self.blocked_requests}


def make_gateway_handler(ctx: RemoteGatewayContext):
    class RemoteAEADHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 15

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _deny(self, status: int = 403) -> None:
            ctx.record_blocked()
            raw = b'{"error":"forbidden"}'
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            self._deny()

        def do_HEAD(self) -> None:
            self._deny()

        def do_POST(self) -> None:
            if self.path != ctx.route_path:
                self._deny()
                return
            if not ctx.concurrency_sem.acquire(timeout=3.0):
                self._deny(503)
                return

            try:
                try:
                    content_len = int(self.headers.get("Content-Length", "0") or "0")
                    if content_len <= 0 or content_len > 64 * 1024 * 1024:
                        self._deny()
                        return
                    wire = self.rfile.read(content_len)
                    aad_req = f"kissshot-c2s-v1:{ctx.route_path}".encode("utf-8")
                    plain = aead_open(ctx.cipher, wire, aad_req)
                    meta_b, req_body = plain.split(b"\n", 1)
                    meta = json.loads(meta_b.decode("utf-8"))

                    req_ts = int(meta.get("ts", 0))
                    if abs(time.time() - req_ts) > MAX_CLOCK_SKEW_SECONDS:
                        self._deny()
                        return

                    req_id = str(meta.get("id", ""))
                    if not ctx.replay_guard.check_and_record(req_id):
                        self._deny()
                        return

                    method = str(meta.get("method", "POST")).upper()
                    clean_path = str(meta.get("path", "")).split("?", 1)[0].rstrip("/") or "/"
                    if method not in ("GET", "POST") or clean_path not in ALLOWED_UPSTREAM_PATHS:
                        self._deny()
                        return
                except Exception:
                    self._deny()
                    return

                ctx.record_ok()
                up_url = f"{ctx.upstream_base}{clean_path}"
                up_headers = {"Content-Type": "application/json"} if req_body else {}
                up_req = urllib.request.Request(
                    up_url,
                    data=(req_body if method == "POST" else None),
                    headers=up_headers,
                    method=method,
                )

                try:
                    with urllib.request.urlopen(up_req, timeout=300) as resp:
                        ct = (resp.headers.get("Content-Type") or "").lower()
                        if "text/event-stream" in ct:
                            self.send_response(200)
                            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                            self.send_header("Cache-Control", "no-cache")
                            self.send_header("X-Accel-Buffering", "no")
                            self.send_header("Connection", "close")
                            self.end_headers()

                            seq = 0
                            while True:
                                ln = resp.readline(MAX_SSE_LINE_BYTES)
                                if not ln:
                                    break
                                enc_chunk = aead_seal(
                                    ctx.cipher,
                                    ln,
                                    f"kissshot-s2c:{req_id}:{seq}".encode("ascii"),
                                ).hex()
                                seq += 1
                                self.wfile.write(f"data: {enc_chunk}\n\n".encode("ascii"))
                                self.wfile.flush()

                            eof_tag = aead_seal(
                                ctx.cipher,
                                b"",
                                f"kissshot-eof:{req_id}:{seq}".encode("ascii"),
                            ).hex()
                            self.wfile.write(f"data: EOF:{eof_tag}\n\n".encode("ascii"))
                            self.wfile.flush()
                        else:
                            out_b = resp.read(MAX_UPSTREAM_BODY_BYTES)
                            hdr_b = json.dumps(
                                {
                                    "status": resp.status,
                                    "ct": "application/json; charset=utf-8",
                                }
                            ).encode("utf-8")
                            enc_all = aead_seal(
                                ctx.cipher,
                                hdr_b + b"\n" + out_b,
                                f"kissshot-s2c-body:{req_id}".encode("ascii"),
                            )
                            self.send_response(200)
                            self.send_header("Content-Type", "application/octet-stream")
                            self.send_header("Content-Length", str(len(enc_all)))
                            self.send_header("Connection", "close")
                            self.end_headers()
                            self.wfile.write(enc_all)
                except urllib.error.HTTPError as he:
                    err_b = he.read(MAX_SSE_LINE_BYTES)
                    hdr_b = json.dumps({"status": he.code, "ct": "application/json; charset=utf-8"}).encode("utf-8")
                    enc_err = aead_seal(
                        ctx.cipher,
                        hdr_b + b"\n" + err_b,
                        f"kissshot-s2c-body:{req_id}".encode("ascii"),
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(enc_err)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(enc_err)
                except Exception as exc:
                    err_payload = json.dumps({"error": {"message": f"Upstream engine unreachable: {exc}"}}).encode("utf-8")
                    hdr_b = json.dumps({"status": 502, "ct": "application/json; charset=utf-8"}).encode("utf-8")
                    enc_err = aead_seal(
                        ctx.cipher,
                        hdr_b + b"\n" + err_payload,
                        f"kissshot-s2c-body:{req_id}".encode("ascii"),
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(enc_err)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(enc_err)
            finally:
                ctx.concurrency_sem.release()

    return RemoteAEADHandler


def start_remote_gateway_server(
    passphrase: str,
    listen_host: str = "127.0.0.1",
    listen_port: int = 8081,
    upstream_base: str = "http://127.0.0.1:8080",
    route_path: Optional[str] = None,
) -> Tuple[ThreadingHTTPServer, RemoteGatewayContext]:
    """实例化并在后台守护线程启动远端 AEAD 网关，返回 (server, context)"""
    ctx = RemoteGatewayContext(
        passphrase=passphrase,
        upstream_base=upstream_base,
        route_path=route_path,
    )
    srv = ThreadingHTTPServer((listen_host, listen_port), make_gateway_handler(ctx))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, ctx
