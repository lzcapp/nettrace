#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nettrace 本地代理服务：让浏览器 GUI 能执行本机 traceroute。

浏览器受沙箱限制无法直接发 raw socket，本服务在本机执行 tracert/traceroute，
供 nettrace_gui.html 通过 http://127.0.0.1:8765 调用（预览面板 CSP 放行该地址）。

启动:
    python nettrace_server.py
    # 自定义端口: python nettrace_server.py --port 9000

接口:
    GET /api/health              -> {"ok": true, "platform": "..."}
    GET /api/trace?target=X&mode=tcp|icmp|udp&port=443&max=30&resolve=0
        -> {"ok": bool, "target": X, "raw": "...", "hops": [...], "error": "..."}

只监听 127.0.0.1，不对外暴露。无第三方依赖。
"""

import argparse
import json
import platform
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import nettrace

IS_WIN = platform.system() == "Windows"
MAX_CONCURRENT = 4
_sema = threading.Semaphore(MAX_CONCURRENT)
_cache = {}
_CACHE_TTL = 120


def build_cmd(target, mode, port, max_hops, resolve):
    """构造平台对应的 traceroute 命令。"""
    if IS_WIN:
        # Windows tracert 只支持 ICMP，忽略 mode/port
        cmd = ["tracert", "-h", str(max_hops)]
        if not resolve:
            cmd.append("-d")
        cmd.append(target)
        return cmd
    # macOS / Linux
    import os
    need_root = mode in ("tcp", "icmp") and hasattr(os, "geteuid") and os.geteuid() != 0
    if mode == "tcp":
        cmd = ["traceroute", "-T", "-p", str(port)]
        if not resolve:
            cmd.append("-n")
        cmd += ["-m", str(max_hops), target]
        if need_root:
            cmd.insert(0, "sudo", "-n")
    elif mode == "icmp":
        cmd = ["traceroute", "-I"]
        if not resolve:
            cmd.append("-n")
        cmd += ["-m", str(max_hops), target]
        if need_root:
            cmd.insert(0, "sudo", "-n")
    else:  # udp（默认，无需 root）
        cmd = ["traceroute"]
        if not resolve:
            cmd.append("-n")
        cmd += ["-m", str(max_hops), target]
    return cmd


def run_trace(target, mode, port, max_hops, resolve):
    """执行 traceroute，返回 (raw_text, error)。"""
    cmd = build_cmd(target, mode, port, max_hops, resolve)
    timeout = max(60, max_hops * 6)
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return "", "找不到 traceroute/tracert 命令"
    except subprocess.TimeoutExpired:
        return "", "traceroute 超时（超过 %ds）" % timeout
    raw = p.stdout
    if not raw and p.stderr:
        raw = p.stderr
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("gbk", errors="replace")
    err = ""
    if p.returncode != 0 and not text.strip():
        err = p.stderr.decode("utf-8", errors="replace").strip()[:300] or ("退出码 %d" % p.returncode)
    return text, err


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("[http] " + (fmt % args), file=sys.stderr)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/health":
            return self._json({"ok": True, "platform": platform.system(), "service": "nettrace"})
        if u.path != "/api/trace":
            return self._json({"ok": False, "error": "not found"}, 404)

        q = parse_qs(u.query)
        target = (q.get("target") or [""])[0].strip()
        mode = (q.get("mode") or ["udp"])[0].strip().lower()
        if mode not in ("tcp", "icmp", "udp"):
            mode = "udp"
        try:
            port = int((q.get("port") or ["443"])[0])
        except ValueError:
            port = 443
        try:
            max_hops = min(30, max(1, int((q.get("max") or ["30"])[0])))
        except ValueError:
            max_hops = 30
        resolve = (q.get("resolve") or ["0"])[0] == "1"

        if not target:
            return self._json({"ok": False, "error": "缺少 target 参数"}, 400)
        # 基本校验，防止命令注入（只允许域名/IP 字符）
        import re
        if not re.fullmatch(r"[A-Za-z0-9.\-:]+", target):
            return self._json({"ok": False, "error": "target 含非法字符"}, 400)

        key = (target, mode, port, max_hops, resolve)
        cached = _cache.get(key)
        if cached and time.time() - cached[0] < _CACHE_TTL:
            raw, err = cached[1], cached[2]
            hit = True
        else:
            hit = False
            if not _sema.acquire(blocking=False):
                return self._json({"ok": False, "error": "探测任务已满，请稍后重试"}, 429)
            try:
                raw, err = run_trace(target, mode, port, max_hops, resolve)
            finally:
                _sema.release()
            if not err:
                _cache[key] = (time.time(), raw, err)

        hops = nettrace.parse_hops(raw) if raw else []
        # 只回传必要字段，减小体积
        hops_out = [
            {"hop": h["hop"], "ips": h["ips"], "lat": h["lat"]}
            for h in hops
        ]
        return self._json({
            "ok": bool(raw or not err),
            "target": target,
            "mode": mode,
            "raw": raw,
            "hops": hops_out,
            "error": err,
            "cached": hit,
        })


def main():
    ap = argparse.ArgumentParser(description="nettrace 本地 traceroute 代理服务")
    ap.add_argument("--port", type=int, default=8765, help="监听端口（默认 8765）")
    args = ap.parse_args()

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print("nettrace 本地服务已启动: http://127.0.0.1:%d" % args.port, flush=True)
    print("平台: %s | 按 Ctrl+C 停止" % platform.system(), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止", flush=True)
        srv.shutdown()


if __name__ == "__main__":
    main()
