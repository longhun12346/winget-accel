"""winget-accel 原型：PAC 服务 + 白名单 MITM 改写代理。

用途：验证"不改清单、只在下载层改写"的架构是否成立。
定位：实验原型，不是交付代码；目标是让它的行为可被观测、可被证伪。

用法：
    python wgaccel.py --port 8443 --accel gh-proxy.com
    python wgaccel.py --port 8443 --mitm-extra example.com   # 测 Name Constraints
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import threading
import time
from pathlib import Path

from ca import WHITELIST, CertAuthority

ACCEL_DEFAULT = "gh-proxy.com"
STATS_LOCK = threading.Lock()
STATS: dict[str, int] = {"connects": 0, "mitm": 0, "tunnel": 0, "rewrites": 0, "bytes": 0, "errors": 0}


class Cfg:
    def __init__(self, args: argparse.Namespace) -> None:
        self.port: int = args.port
        self.listen: str = args.listen
        self.accel: str = args.accel
        self.log_path = Path(args.log)
        self.ca = CertAuthority(Path(args.cert_dir))
        self.mitm_extra: tuple[str, ...] = tuple(args.mitm_extra)

    # ---------------------------------------------------------------- logging
    def log(self, msg: str) -> None:
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        print(line, flush=True)
        try:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass


def bump(key: str, n: int = 1) -> None:
    with STATS_LOCK:
        STATS[key] = STATS.get(key, 0) + n


class Conn:
    """带缓冲的读写封装；避免把 TLS 记录切碎或丢失。"""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = b""

    def read_until_atomic(self, delim: bytes, limit: int = 16384) -> bytes:
        """逐字节读，保证不越过分隔符（CONNECT 头后面紧跟 ClientHello）。"""
        out = b""
        while len(out) < limit:
            b = self.sock.recv(1)
            if not b:
                break
            out += b
            if out.endswith(delim):
                break
        return out

    def read_until(self, delim: bytes, limit: int = 1 << 16) -> bytes:
        while delim not in self.buf:
            if len(self.buf) > limit:
                break
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            self.buf += chunk
        idx = self.buf.find(delim)
        if idx < 0:
            out, self.buf = self.buf, b""
            return out
        out = self.buf[: idx + len(delim)]
        self.buf = self.buf[idx + len(delim) :]
        return out

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(min(65536, n - len(self.buf)) or 1)
            if not chunk:
                break
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def stream_to(self, dst: socket.socket, limit: int | None = None) -> int:
        total = 0
        if self.buf:
            dst.sendall(self.buf)
            total += len(self.buf)
            self.buf = b""
        while limit is None or total < limit:
            want = 65536 if limit is None else min(65536, limit - total)
            if want <= 0:
                break
            data = self.sock.recv(want)
            if not data:
                break
            dst.sendall(data)
            total += len(data)
        return total


# ---------------------------------------------------------------- PAC
def pac_text(port: int) -> str:
    exact = " || ".join(f'host == "{h}"' for h in WHITELIST)
    return (
        "function FindProxyForURL(url, host) {\n"
        "  host = host.toLowerCase();\n"
        f"  if ({exact} || shExpMatch(host, \"*.github.com\")) {{\n"
        f'    return "PROXY 127.0.0.1:{port}";\n'
        "  }\n"
        '  return "DIRECT";\n'
        "}\n"
    )


# ---------------------------------------------------------------- 处理逻辑
def do_tunnel(client: socket.socket, host: str, port: int, cfg: Cfg) -> None:
    try:
        upstream = socket.create_connection((host, port), timeout=15)
    except OSError as exc:
        cfg.log(f"TUNNEL-FAIL {host}:{port} {exc}")
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        return
    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    def pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=pump, args=(client, upstream), daemon=True)
    t.start()
    pump(upstream, client)
    t.join(timeout=30)
    upstream.close()


def do_mitm(client: socket.socket, host: str, port: int, cfg: Cfg) -> None:
    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    try:
        ctx = cfg.ca.leaf_context(host)
        tls = ctx.wrap_socket(client, server_side=True)
    except (ssl.SSLError, OSError) as exc:
        bump("errors")
        cfg.log(f"MITM-HANDSHAKE-FAIL {host} {exc}")
        return

    src = Conn(tls)
    head = src.read_until(b"\r\n\r\n")
    if not head:
        tls.close()
        return

    lines = head.decode("latin-1").split("\r\n")
    try:
        method, target, _ver = lines[0].split(" ", 2)
    except ValueError:
        cfg.log(f"BAD-REQUEST {host} {lines[0][:80]}")
        tls.close()
        return

    rewrite = host in WHITELIST
    if rewrite:
        up_host = cfg.accel
        up_target = f"/https://{host}{target}"
        bump("rewrites")
    else:
        up_host = host
        up_target = target

    skip = {"host", "proxy-connection", "connection", "keep-alive", "te", "trailer", "upgrade"}
    fwd = [f"{method} {up_target} HTTP/1.1", f"Host: {up_host}"]
    for line in lines[1:]:
        if not line:
            break
        name = line.split(":", 1)[0].strip().lower()
        if name in skip:
            continue
        fwd.append(line)
    fwd.append("Connection: close")
    payload = ("\r\n".join(fwd) + "\r\n\r\n").encode("latin-1")

    started = time.time()
    try:
        raw = socket.create_connection((up_host, 443), timeout=15)
        up_tls = ssl.create_default_context().wrap_socket(raw, server_hostname=up_host)
    except (OSError, ssl.SSLError) as exc:
        bump("errors")
        cfg.log(f"UPSTREAM-FAIL {host} -> {up_host} {exc}")
        try:
            tls.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
        tls.close()
        return

    up_tls.sendall(payload)
    up = Conn(up_tls)
    status, size = relay_response(up, tls, host, cfg)
    elapsed = time.time() - started
    bump("bytes", size)
    tag = "REWRITE" if rewrite else "PASS"
    cfg.log(f"{tag} {host}{target[:90]} -> {status} {size}B {elapsed:.2f}s")

    up_tls.close()
    tls.close()


def relay_response(up: Conn, dst: socket.socket, host: str, cfg: Cfg) -> tuple[int, int]:
    head = up.read_until(b"\r\n\r\n")
    if not head:
        dst.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        return 502, 0
    dst.sendall(head)

    text = head.decode("latin-1")
    status = 0
    try:
        status = int(text.split(" ")[1])
    except (IndexError, ValueError):
        pass

    content_length: int | None = None
    chunked = False
    for line in text.split("\r\n")[1:]:
        if not line:
            break
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip().lower()
        if name == "content-length":
            try:
                content_length = int(value)
            except ValueError:
                pass
        elif name == "transfer-encoding" and "chunked" in value:
            chunked = True

    total = 0
    try:
        if chunked:
            while True:
                line = up.read_until(b"\r\n")
                if not line:
                    break
                dst.sendall(line)
                try:
                    size = int(line.strip().split(b";")[0], 16)
                except ValueError:
                    break
                if size == 0:
                    while True:
                        trailer = up.read_until(b"\r\n")
                        if not trailer:
                            break
                        dst.sendall(trailer)
                        if trailer in (b"\r\n", b"\n"):
                            break
                    break
                data = up.read_exact(size)
                dst.sendall(data)
                total += len(data)
                dst.sendall(up.read_exact(2))
        elif content_length is not None:
            total = up.stream_to(dst, limit=content_length)
        else:
            total = up.stream_to(dst)
    except OSError as exc:
        bump("errors")
        cfg.log(f"RELAY-ERR {host} {exc}")

    return status, total


def handle_plain(client: socket.socket, target: str, head: bytes, cfg: Cfg) -> None:
    path = target
    if path.startswith("http://") or path.startswith("https://"):
        after = path.split("://", 1)[1]
        path = "/" + after.split("/", 1)[1] if "/" in after else "/"

    if "proxy.pac" in path:
        body = pac_text(cfg.port).encode()
        resp = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/x-ns-proxy-autoconfig\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode() + body
        client.sendall(resp)
        cfg.log("PAC-SERVED")
        return

    if path.rstrip("/") in ("/health", "/status"):
        with STATS_LOCK:
            body = json.dumps(STATS, ensure_ascii=False).encode()
        resp = (
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode() + body
        client.sendall(resp)
        return

    client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
    cfg.log(f"PLAIN-405 {path[:80]}")


def handle_client(client: socket.socket, cfg: Cfg) -> None:
    try:
        client.settimeout(30)
        conn = Conn(client)
        head = conn.read_until_atomic(b"\r\n\r\n")
        if not head:
            return
        first = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = first.split(" ")
        if len(parts) < 2:
            return
        method, target = parts[0], parts[1]
        if method.upper() == "CONNECT":
            host, _, port_s = target.rpartition(":")
            port = int(port_s) if port_s.isdigit() else 443
            bump("connects")
            host_l = host.lower()
            if host_l in WHITELIST or host_l in cfg.mitm_extra:
                bump("mitm")
                do_mitm(client, host_l, port, cfg)
            else:
                bump("tunnel")
                do_tunnel(client, host_l, port, cfg)
        else:
            handle_plain(client, target, head, cfg)
    except (OSError, ssl.SSLError) as exc:
        bump("errors")
        cfg.log(f"CLIENT-ERR {exc}")
    finally:
        try:
            client.close()
        except OSError:
            pass


def main() -> None:
    ap = argparse.ArgumentParser(description="winget-accel prototype")
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--accel", default=ACCEL_DEFAULT)
    ap.add_argument("--cert-dir", default="certs")
    ap.add_argument("--log", default="proxy.log")
    ap.add_argument("--mitm-extra", action="append", default=[],
                    help="额外拦截但不改写的 host（用于验证 Name Constraints）")
    args = ap.parse_args()

    cfg = Cfg(args)
    cfg.log(f"CA thumbprint = {cfg.ca.thumbprint}")
    cfg.log(f"PAC  = http://{cfg.listen}:{cfg.port}/proxy.pac")
    cfg.log(f"ACCEL= https://{cfg.accel}/<原始 URL>")
    cfg.log(f"改写范围 = {', '.join(WHITELIST)}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        # Windows 上 SO_REUSEADDR 允许"抢占"已占用端口，会导致两个实例同时绑定
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((cfg.listen, cfg.port))
    srv.listen(128)
    cfg.log(f"LISTEN {cfg.listen}:{cfg.port}")
    try:
        while True:
            client, _addr = srv.accept()
            threading.Thread(target=handle_client, args=(client, cfg), daemon=True).start()
    except KeyboardInterrupt:
        cfg.log("SHUTDOWN")


if __name__ == "__main__":
    main()
