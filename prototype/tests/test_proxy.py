"""集成测试：真实启动代理进程 + 本地假上游，不需要外网、不改系统状态。

覆盖的是"协议行为"这一层：改写是否正确、响应是否逐字节保真、
错误是否透传、非白名单 host 是否真的被隧道而不是被改写。
"""

from __future__ import annotations

import hashlib
import socket
import subprocess
import sys
import time
import urllib.request

import pytest
from conftest import PROTO_DIR, curl, free_port

STATUS_MARK = "\nHTTP_STATUS:"


def call(proxy, url, *, ca=True, extra=(), timeout=60):
    """经代理请求，返回 (CompletedProcess, body_bytes, http_status)。"""
    proc = curl(
        proxy.port,
        url,
        ca_path=proxy.ca_path if ca else None,
        extra=("-w", STATUS_MARK + "%{http_code}", *extra),
        timeout=timeout,
    )
    body, sep, status = proc.stdout.rpartition(STATUS_MARK.encode())
    if not sep:
        return proc, proc.stdout, 0
    try:
        return proc, body, int(status)
    except ValueError:
        return proc, body, 0


# --------------------------------------------------------------- 改写与转发


def test_rewrite_forwards_prefixed_url_and_accel_host(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    proc, body, status = call(proxy, "https://github.com/ok")

    assert proc.returncode == 0, proc.stderr
    assert status == 200
    assert body == b"hello-through-proxy"

    assert len(up.requests) == 1
    seen = up.requests[0]
    assert seen["path"] == "/https://github.com/ok"
    assert seen["headers"]["host"] == f"127.0.0.1:{up.port}"


def test_rewrite_drops_hop_by_hop_and_forces_close(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    call(proxy, "https://github.com/ok", extra=("-H", "X-Custom: 1"))

    headers = up.requests[0]["headers"]
    assert headers["connection"] == "close"
    assert "proxy-connection" not in headers
    assert headers["x-custom"] == "1"  # 端到端头必须保留


def test_every_whitelisted_host_gets_rewritten(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    import wgaccel as w

    for host in w.WHITELIST:
        up.requests.clear()
        proc, _, status = call(proxy, f"https://{host}/probe")
        assert proc.returncode == 0, (host, proc.stderr)
        assert status == 200, host
        assert up.requests[0]["path"] == f"/https://{host}/probe"


# ------------------------------------------------------------- Range / 分片


def test_range_is_forwarded_and_status_206_preserved(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    proc, body, status = call(proxy, "https://github.com/range", extra=("-r", "10-109"))

    assert proc.returncode == 0, proc.stderr
    assert status == 206
    assert len(body) == 100
    assert up.requests[0]["headers"]["range"] == "bytes=10-109"


def test_content_range_header_survives_rewrite(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    proc = curl(
        proxy.port,
        "https://github.com/range",
        ca_path=proxy.ca_path,
        extra=("-r", "0-9", "-D", "-", "-o", "NUL"),
    )
    text = proc.stdout.decode("latin-1").lower()
    assert "206" in text
    assert "content-range: bytes 0-9/1024" in text


# --------------------------------------------------------- 响应体的三种定界


def test_chunked_response_is_relayed(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    proc, body, status = call(proxy, "https://github.com/chunked")

    assert proc.returncode == 0, proc.stderr
    assert status == 200
    assert body == b"abcdefgh"  # abc + defg + h


def test_response_without_content_length_is_relayed(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    proc, body, status = call(proxy, "https://github.com/nolength")

    assert proc.returncode == 0, proc.stderr
    assert status == 200
    assert body == b"no-length-body"


def test_large_response_is_byte_exact(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    proc, body, status = call(proxy, "https://github.com/big", timeout=120)

    assert proc.returncode == 0, proc.stderr
    assert status == 200
    assert len(body) == 8 * 1024 * 1024
    assert hashlib.sha256(body).hexdigest() == hashlib.sha256(b"x" * (8 * 1024 * 1024)).hexdigest()


# ------------------------------------------------------------------ 错误路径


def test_upstream_error_status_is_passed_through(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    proc, body, status = call(proxy, "https://github.com/boom")

    assert proc.returncode == 0
    assert status == 502
    assert body == b""


def test_range_request_upstream_200_is_rejected(request, start_proxy, fake_upstream):
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制的 Range 契约")

    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)
    proc, body, status = call(
        proxy, "https://github.com/range-ignored", extra=("-r", "0-1")
    )

    assert proc.returncode == 0, proc.stderr
    assert status == 502
    assert body == b""

def test_truncated_upstream_body_closes_client_and_clears_pin(
    request, start_proxy, fake_upstream
):
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制的中途失败契约")

    up = fake_upstream(truncate=True)
    proxy = start_proxy(accel=up.accel)
    proc = curl(
        proxy.port,
        "https://github.com/truncated",
        ca_path=proxy.ca_path,
        extra=("-r", "0-99"),
        timeout=20,
    )

    assert proc.returncode != 0
    time.sleep(0.2)
    log = proxy.log_text()
    assert "RELAY-ERR" in log
    assert "pin_cleared=true" in log

def test_unreachable_tunnel_returns_502(request, start_proxy):
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制的隧道失败契约")

    closed = free_port()
    proxy = start_proxy(accel="gh-proxy.com")
    proc = curl(proxy.port, f"https://127.0.0.1:{closed}/", timeout=10)

    assert proc.returncode != 0
    assert b"response 502" in proc.stderr.lower()

def test_unreachable_accel_returns_502_quickly(start_proxy):
    closed = free_port()  # 拿到就释放，保证没人监听
    proxy = start_proxy(accel=f"http://127.0.0.1:{closed}")

    proc, _, status = call(proxy, "https://github.com/x", timeout=20)

    assert status == 502
    assert proxy.health()["errors"] >= 1


# --------------------------------------------------------------- 隧道路径


def test_non_whitelisted_host_is_tunneled_not_rewritten(start_proxy, tls_upstream):
    proxy = start_proxy(accel="gh-proxy.com")

    proc = curl(
        proxy.port,
        f"https://127.0.0.1:{tls_upstream.port}/plain",
        ca_path=tls_upstream.cert_path,  # 信任的是目标站自己的证书，不是我们的 CA
    )

    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == b"hello-through-proxy"
    assert tls_upstream.requests[0]["path"] == "/plain"  # 未被加前缀


# ------------------------------------------------------------- 本地端点


def test_pac_is_served_on_own_port(request, start_proxy):
    if not request.config.getoption("--target-binary"):
        pytest.skip("Python 原型未实现 PAC 本地端点")
    proxy = start_proxy(accel="gh-proxy.com")

    with urllib.request.urlopen(f"http://127.0.0.1:{proxy.port}/winget-accel.pac", timeout=10) as r:
        text = r.read().decode()
        ctype = r.headers.get("Content-Type", "")

    assert "application/x-ns-proxy-autoconfig" in ctype
    assert "function FindProxyForURL" in text
    assert f"PROXY 127.0.0.1:{proxy.port}" in text


def test_health_reports_counters(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    before = proxy.health()
    call(proxy, "https://github.com/ok")
    after = proxy.health()

    assert after["rewrites"] == before["rewrites"] + 1
    assert after["bytes"] > before["bytes"]
    assert after["mitm"] >= 1


def test_unknown_plain_request_gets_405(start_proxy):
    proxy = start_proxy(accel="gh-proxy.com")
    proc = subprocess.run(
        ["curl.exe", "-sS", "-o", "NUL", "-w", "%{http_code}",
         f"http://127.0.0.1:{proxy.port}/nope"],
        capture_output=True,
    )
    assert proc.stdout.strip() == b"405"


# ------------------------------------------------------- 端口与稳定性的边界


def test_second_instance_on_same_port_fails_fast(start_proxy, build_command, tmp_path):
    proxy = start_proxy(accel="gh-proxy.com")
    other_certs = tmp_path / "other-certs"
    other_certs.mkdir()

    cmd = build_command(
        proxy.port, other_certs, tmp_path / "second.log", accel="gh-proxy.com"
    )
    proc = subprocess.run(cmd, cwd=str(PROTO_DIR), capture_output=True, timeout=30)

    # Windows 上若用 SO_REUSEADDR 会静默抢占；必须是非零退出
    assert proc.returncode != 0


def test_name_constraints_reject_host_outside_whitelist(start_proxy):
    """同一张 CA 签 example.com 必须被客户端拒绝（H1 的回归用例）。"""
    proxy = start_proxy(accel="gh-proxy.com", mitm_extra=("example.com",))

    proc = curl(proxy.port, "https://example.com/", ca_path=proxy.ca_path, timeout=20)

    assert proc.returncode != 0, "Name Constraints 未生效：约束外的 host 竟然握手成功"
    assert b"certificate" in proc.stderr.lower() or b"ssl" in proc.stderr.lower()


def test_concurrent_first_connections_all_succeed(start_proxy, fake_upstream):
    """并发首连同一 host：叶证书只生成一次，任何一个连接都不该被重置。

    回归：叶证书生成与加载不是原子操作，并发时会读到半截 PEM。
    """
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    procs = [
        subprocess.Popen(
            ["curl.exe", "-sS", "--max-time", "60", "-x", f"http://127.0.0.1:{proxy.port}",
             "--ssl-no-revoke", "--cacert", str(proxy.ca_path),
             "https://github.com/ok"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        for _ in range(5)
    ]
    results = [proc.communicate(timeout=90) for proc in procs]

    for proc, (out, err) in zip(procs, results):
        assert proc.returncode == 0, err
        assert out == b"hello-through-proxy"
    assert proxy.health()["rewrites"] >= 5
