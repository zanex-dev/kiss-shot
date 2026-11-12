# -*- coding: utf-8 -*-
"""
统一命令行入口 (kiss_shot/__main__.py)

子命令：
  panel           启动本地跨平台桌面图形控制台
  bridge          启动本地无头 OpenAI 兼容 E2EE 代理服务 (127.0.0.1:18443/v1)
  remote-gateway  在远端 GPU 服务器启动纯内存 AEAD 反向代理并输出 KISSSHOT_TICKET 握手票据
"""

from __future__ import annotations

import argparse
import getpass
from http.server import ThreadingHTTPServer
import os
import sys
import threading
import time

from .crypto import DEFAULT_LOCAL_PORT
from .local_bridge import (
    LocalBridgeState,
    _clipboard_watcher_loop,
    is_port_listening,
    make_local_bridge_handler,
)
from .remote_gateway import RemoteGatewayContext, make_gateway_handler


def _cmd_panel(args: argparse.Namespace) -> int:
    from .panel import run_panel

    run_panel(work_dir=args.work_dir, port=args.port)
    return 0


def _cmd_bridge(args: argparse.Namespace) -> int:
    if is_port_listening(args.port):
        print(f"[Kiss-Shot] Port 127.0.0.1:{args.port} is already listening.", file=sys.stderr)
        return 1

    state = LocalBridgeState(work_dir=args.work_dir, model_alias=args.model_alias)
    passphrase = args.passphrase or os.environ.get("KISSSHOT_PASSPHRASE", "").strip()
    if passphrase:
        state.passphrase = passphrase

    if args.ticket:
        if not state.passphrase:
            state.passphrase = getpass.getpass("Passphrase: ").strip()
        ok, msg = state.configure_with_ticket(args.ticket, passphrase_override=state.passphrase)
        print(f"[Kiss-Shot] Initial handshake: {'OK' if ok else 'FAILED'} — {msg}")

    if not args.no_clipboard:
        threading.Thread(target=_clipboard_watcher_loop, args=(state,), daemon=True).start()

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), make_local_bridge_handler(state, listen_port=args.port))
    print("=" * 72)
    print(f" 🔒 Zero-Trust Local OpenAI Bridge listening on http://127.0.0.1:{args.port}/v1")
    print(" 📋 Watching clipboard for KISSSHOT_TICKET:... (Ctrl+C to stop)")
    print("=" * 72, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[Kiss-Shot] Shutting down local bridge.")
    finally:
        srv.server_close()
    return 0


def _cmd_remote_gateway(args: argparse.Namespace) -> int:
    passphrase = args.passphrase or os.environ.get("KISSSHOT_PASSPHRASE", "").strip()
    if not passphrase:
        passphrase = getpass.getpass("Enter session passphrase (in-memory only): ").strip()
    if not passphrase:
        print("Error: Passphrase cannot be empty.", file=sys.stderr)
        return 1

    ctx = RemoteGatewayContext(
        passphrase=passphrase,
        upstream_base=args.upstream,
        route_path=args.route,
    )
    ticket = ctx.export_ticket(args.public_url)
    srv = ThreadingHTTPServer((args.listen_host, args.listen_port), make_gateway_handler(ctx))

    print("\n" + "=" * 76)
    print(f" 🛡️ Remote Zero-Trust AEAD Gateway bound to {args.listen_host}:{args.listen_port}")
    print(f" 🔀 Dynamic authenticated route : {ctx.route_path}")
    print(f" 🎯 Upstream local engine       : {args.upstream}")
    print(" 📋 Copy the entire handshake ticket line below to your local workstation:\n")
    print(ticket)
    print("\n" + "=" * 76, flush=True)

    try:
        while True:
            srv.handle_request()
    except KeyboardInterrupt:
        print("\n[Kiss-Shot] Stopping remote gateway.")
    finally:
        srv.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kiss-shot",
        description="Zero-Trust End-to-End Encrypted Inference Bridge & Ephemeral Ciphertext Mailbox.",
    )
    sub = parser.add_subparsers(dest="subcommand")

    p_panel = sub.add_parser("panel", help="Launch local desktop GUI console")
    p_panel.add_argument("--port", type=int, default=DEFAULT_LOCAL_PORT, help="Local OpenAI proxy port")
    p_panel.add_argument("--work-dir", default=None, help="Working directory for local config and outputs")
    p_panel.set_defaults(func=_cmd_panel)

    p_bridge = sub.add_parser("bridge", help="Run headless local OpenAI E2EE proxy")
    p_bridge.add_argument("--port", type=int, default=DEFAULT_LOCAL_PORT, help="Local listen port (127.0.0.1)")
    p_bridge.add_argument("--work-dir", default=None, help="Working directory")
    p_bridge.add_argument("--model-alias", default="kiss-shot-llm", help="Model ID exposed on /v1/models")
    p_bridge.add_argument("--ticket", default="", help="Optional KISSSHOT_TICKET:... string to bind at startup")
    p_bridge.add_argument("--passphrase", default="", help="Passphrase (prefer KISSSHOT_PASSPHRASE env or prompt)")
    p_bridge.add_argument("--no-clipboard", action="store_true", help="Disable background clipboard ticket watcher")
    p_bridge.set_defaults(func=_cmd_bridge)

    p_rem = sub.add_parser("remote-gateway", help="Run in-memory AEAD gateway on a remote GPU server")
    p_rem.add_argument(
        "--public-url",
        required=True,
        help="Externally reachable HTTPS ingress URL pointing to --listen-port (e.g. https://pod-8081.proxy.runpod.net)",
    )
    p_rem.add_argument("--listen-host", default="0.0.0.0", help="Bind address on remote container (default: 0.0.0.0)")
    p_rem.add_argument("--listen-port", type=int, default=8081, help="Bind port for AEAD gateway (default: 8081)")
    p_rem.add_argument("--upstream", default="http://127.0.0.1:8080", help="Local loopback inference server URL")
    p_rem.add_argument("--route", default=None, help="Custom route path (default: random /v1/ks-<hex>)")
    p_rem.add_argument("--passphrase", default="", help="Passphrase (prefer interactive prompt or KISSSHOT_PASSPHRASE)")
    p_rem.set_defaults(func=_cmd_remote_gateway)

    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
