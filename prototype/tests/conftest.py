"""测试夹具：本地假上游、临时 CA、可控的代理进程。

设计原则：
- 默认**不碰系统状态**（不装根证书、不改 PAC），CA 通过 curl --cacert 显式信任
- 默认**不依赖外网**：改写/分片/错误路径都用本地假上游验证
- 需要真实网络的用例标 `@pytest.mark.network`，默认跳过
"""

from __future__ import annotations

import datetime as dt
import http.server
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

PROTO_DIR = Path(__file__).resolve().parents[1]
if str(PROTO_DIR) not in sys.path:
    sys.path.insert(0, str(PROTO_DIR))

CURL = "curl.exe"


# --------------------------------------------------------------------- 工具


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http(url: str, timeout: float = 20.0) -> None:
    """轮询直到 HTTP 服务可用，否则抛错。"""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):
                return
        except (urllib.error.URLError, ConnectionError, OSError) as exc:
            last = exc
            time.sleep(0.15)
    raise RuntimeError(f"服务未就绪: {url} ({last})")


def curl(
    port: int,
    url: str,
    *,
    ca_path: Path | None = None,
    extra: tuple[str, ...] = (),
    timeout: int = 60,
) -> subprocess.CompletedProcess:
    """经代理发一次请求。ca_path 给定时显式信任该 CA（不动系统存储）。"""
    cmd = [CURL, "-sS", "--max-time", str(timeout), "-x", f"http://127.0.0.1:{port}"]
    if ca_path is not None:
        # schannel 对自签 CA 查不到吊销信息，必须关掉；winget/WinHTTP 不受影响
        cmd += ["--ssl-no-revoke", "--cacert", str(ca_path)]
    cmd += list(extra)
    cmd += [url]
    return subprocess.run(cmd, capture_output=True)


# ------------------------------------------------------------------ 代理句柄


@dataclass
class ProxyHandle:
    proc: subprocess.Popen
    port: int
    log: Path
    cert_dir: Path

    @property
    def ca_path(self) -> Path:
        return self.cert_dir / "ca-cert.pem"

    def log_text(self) -> str:
        return self.log.read_text(encoding="utf-8", errors="replace")

    def health(self) -> dict:
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=5) as r:
            import json

            return json.loads(r.read().decode())


@pytest.fixture
def build_command(request):
    """构造"启动一个代理实例"的命令行。

    默认跑 Python 原型；传 `--target-binary <path>` 时改跑该可执行文件
    （用于让同一套协议用例驱动 Rust 版）。两者的 CLI 参数刻意保持一致。
    """

    def _build(port, cert_dir, log, accel=None, extra=()):
        target = request.config.getoption("--target-binary")
        if target:
            base = [target]
        else:
            base = [sys.executable, "-u", str(PROTO_DIR / "wgaccel.py")]
        cmd = base + [
            "--port", str(port),
            "--cert-dir", str(cert_dir),
            "--log", str(log),
            # 二进制默认会接管系统环境（装 CA / 设 PAC）。测试必须显式关掉，
            # 否则会污染测试机——这也是 --no-env 存在的原因。
            "--no-env",
        ]
        if accel is not None:
            cmd += ["--accel", accel]
        cmd += list(extra)
        return cmd

    return _build


@pytest.fixture
def start_proxy(tmp_path, build_command):
    """启动一个代理实例；可多次调用（不同端口/不同加速器）。"""
    procs: list[tuple[subprocess.Popen, object, object]] = []

    def _start(
        *,
        accel: str = "gh-proxy.com",
        cert_dir: Path | None = None,
        extra: tuple[str, ...] = (),
    ) -> ProxyHandle:
        port = free_port()
        cd = Path(cert_dir) if cert_dir else tmp_path / f"certs-{port}"
        cd.mkdir(parents=True, exist_ok=True)
        log = tmp_path / f"proxy-{port}.log"
        out = (tmp_path / f"proxy-{port}.out").open("wb")
        err = (tmp_path / f"proxy-{port}.err").open("wb")
        cmd = build_command(port, cd, log, accel, extra)
        proc = subprocess.Popen(cmd, cwd=str(PROTO_DIR), stdout=out, stderr=err)
        procs.append((proc, out, err))
        wait_http(f"http://127.0.0.1:{port}/health")
        return ProxyHandle(proc=proc, port=port, log=log, cert_dir=cd)

    yield _start

    for proc, out, err in procs:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        out.close()
        err.close()


# ---------------------------------------------------------------- 假上游（HTTP）


def make_upstream_handler(requests: list[dict]):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):  # noqa: N802
            headers = {k.lower(): v for k, v in self.headers.items()}

            # 内部探测不属于被测流量，不能进 requests，否则会挤掉真实请求的断言位置：
            # - winget-accel-health：定期探 origin 根路径（判可达）
            # - winget-accel-probe：启动粗筛取固定资产的量（测吞吐）
            if "winget-accel-" in headers.get("user-agent", ""):
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            requests.append({"path": self.path, "headers": headers})

            if "boom" in self.path:
                self.send_response(502)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if "chunked" in self.path:
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for part in (b"abc", b"defg", b"h"):
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
                self.wfile.write(b"0\r\n\r\n")
                return

            if "nolength" in self.path:
                self.send_response(200)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"no-length-body")
                self.close_connection = True
                return

            if "big" in self.path:
                body = b"x" * (8 * 1024 * 1024)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if "range" in self.path:
                body = bytes(range(256)) * 4  # 1024 B
                rng = headers.get("range", "")
                if rng.startswith("bytes="):
                    spec = rng[6:].split(",")[0]
                    a, _, b = spec.partition("-")
                    start = int(a)
                    end = int(b) if b else len(body) - 1
                    end = min(end, len(body) - 1)
                    part = body[start : end + 1]
                    self.send_response(206)
                    self.send_header("Content-Range", f"bytes {start}-{end}/{len(body)}")
                    self.send_header("Content-Length", str(len(part)))
                    self.end_headers()
                    self.wfile.write(part)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            body = b"hello-through-proxy"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # 静音
            pass

    return Handler


@pytest.fixture
def fake_upstream():
    """本地明文假上游，记录收到的请求，按路径给出不同响应。"""
    servers = []

    def _start() -> SimpleNamespace:
        requests: list[dict] = []
        srv = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), make_upstream_handler(requests)
        )
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        port = srv.server_address[1]
        handle = SimpleNamespace(
            port=port,
            requests=requests,
            accel=f"http://127.0.0.1:{port}",
            close=lambda: (srv.shutdown(), srv.server_close()),
        )
        servers.append(handle)
        return handle

    yield _start
    for h in servers:
        h.close()


# --------------------------------------------------------------- 假上游（TLS）


def _self_signed_for_ip(ip: str, cert_dir: Path) -> tuple[Path, Path]:
    """生成仅用于测试的自签证书（IP SAN）；与产品 CA 无关。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake-tls-upstream")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address(ip))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "fake-tls-cert.pem"
    key_path = cert_dir / "fake-tls-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def ip_address(value: str):
    import ipaddress

    return ipaddress.ip_address(value)


@pytest.fixture
def tls_upstream(tmp_path):
    """本地 TLS 假上游，用于验证"非白名单 host 走隧道"这条路径。"""

    def _start() -> SimpleNamespace:
        requests: list[dict] = []
        cert_path, key_path = _self_signed_for_ip("127.0.0.1", tmp_path / "fake-tls")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path))

        class TlsServer(http.server.ThreadingHTTPServer):
            def get_request(self):
                sock, addr = super().get_request()
                return ctx.wrap_socket(sock, server_side=True), addr

        srv = TlsServer(("127.0.0.1", 0), make_upstream_handler(requests))
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        port = srv.server_address[1]
        return SimpleNamespace(
            port=port,
            requests=requests,
            cert_path=cert_path,
            close=lambda: (srv.shutdown(), srv.server_close()),
        )

    server = _start()
    yield server
    server.close()


# ------------------------------------------------------------------ CA 夹具


@pytest.fixture
def cert_dir(tmp_path) -> Path:
    return tmp_path / "certs"


@pytest.fixture
def ca(cert_dir):
    from ca import CertAuthority

    return CertAuthority(cert_dir)


# ---------------------------------------------------------------- 网络开关


# 命令行选项（--network / --target-binary）与收集钩子在 prototype/conftest.py：
# pytest 解析参数时就要注册，放这里太晚。



