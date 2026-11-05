"""集成测试：真实启动代理进程 + 本地假上游，不需要外网、不改系统状态。

覆盖的是"协议行为"这一层：改写是否正确、响应是否逐字节保真、
错误是否透传、非白名单 host 是否真的被隧道而不是被改写。
"""

from __future__ import annotations

import hashlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import pytest
from conftest import PROTO_DIR, curl, free_port

STATUS_MARK = "\nHTTP_STATUS:"


def github_asset(name: str) -> str:
    """返回一个会触发 Rust 代理改写的本地测试资产 URL。"""
    return f"https://github.com/test/repo/releases/download/v1/{name}"


def test_homepage_cannot_promote_a_candidate_that_failed_asset_probe(
    request, start_proxy, fake_upstream
):
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制的候选验证")
    upstream = fake_upstream(reject_probe=True)
    proxy = start_proxy(accel=upstream.accel)
    # 启动后后台会立即巡检；要等待它确实完成第二次资产校验。
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if proxy.log_text().count("实测失败（非 206 或数据不足）") >= 2:
            break
        time.sleep(0.05)
    assert proxy.log_text().count("实测失败（非 206 或数据不足）") >= 2
    assert sum("winget-accel-probe" in ua for ua in upstream.probes) >= 2
    proc, body, status = call(proxy, github_asset("must-not-reach-upstream"))
    assert proc.returncode == 0, proc.stderr
    assert status == 502
    assert not upstream.requests


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

    proc, body, status = call(proxy, github_asset("ok"))

    assert proc.returncode == 0, proc.stderr
    assert status == 200
    assert body == b"hello-through-proxy"

    assert len(up.requests) == 1
    seen = up.requests[0]
    assert seen["path"] == f"/{github_asset('ok')}"
    assert seen["headers"]["host"] == f"127.0.0.1:{up.port}"


def test_rewrite_drops_hop_by_hop_and_forces_close(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    call(proxy, github_asset("ok"), extra=("-H", "X-Custom: 1"))

    headers = up.requests[0]["headers"]
    assert headers["connection"] == "close"
    assert "proxy-connection" not in headers
    assert headers["x-custom"] == "1"  # 端到端头必须保留


def test_mixed_case_configuration_rewrites_instead_of_connecting_directly(
    request, start_proxy, fake_upstream
):
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 配置规范化")
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel, rewrite_hosts=[" GITHUB.COM ", "github.com"])
    proc, body, status = call(proxy, github_asset("ok"))
    assert proc.returncode == 0, proc.stderr
    assert status == 200
    assert body == b"hello-through-proxy"
    assert up.requests[0]["path"] == f"/{github_asset('ok')}"


def test_connection_named_headers_and_proxy_credentials_are_not_leaked(
    request, start_proxy, fake_upstream
):
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 逐跳头过滤")
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)
    proc, _, status = call(
        proxy,
        github_asset("ok"),
        extra=(
            "-H", "Connection: X-Internal-Token",
            "-H", "X-Internal-Token: secret",
            "-H", "Proxy-Authorization: Basic secret",
            "-H", "X-End-To-End: keep",
        ),
    )
    assert proc.returncode == 0, proc.stderr
    assert status == 200
    headers = up.requests[0]["headers"]
    assert "x-internal-token" not in headers
    assert "proxy-authorization" not in headers
    assert headers["connection"] == "close"
    assert headers["x-end-to-end"] == "keep"


def test_expect_continue_without_body_is_rejected_promptly(
    request, start_proxy, fake_upstream
):
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 请求体拒绝路径")
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)
    context = ssl.create_default_context(cafile=str(proxy.ca_path))
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=3) as raw:
        raw.sendall(b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
        response = b""
        while not response.endswith(b"\r\n\r\n"):
            response += raw.recv(1)
        assert response.startswith(b"HTTP/1.1 200")
        with context.wrap_socket(raw, server_hostname="github.com") as tls:
            started = time.monotonic()
            tls.sendall(
                b"POST /ok HTTP/1.1\r\nHost: github.com\r\n"
                b"Content-Length: 10\r\nExpect: 100-continue\r\n\r\n"
            )
            response = tls.recv(4096)
            assert response.startswith(b"HTTP/1.1 501"), response
            assert time.monotonic() - started < 2
    assert not up.requests


def test_every_whitelisted_host_gets_rewritten(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    import wgaccel as w

    for host in w.WHITELIST:
        up.requests.clear()
        url = github_asset("probe") if host == "github.com" else f"https://{host}/probe"
        proc, _, status = call(proxy, url)
        assert proc.returncode == 0, (host, proc.stderr)
        assert status == 200, host
        assert up.requests[0]["path"] == f"/{url}"


# ------------------------------------------------------------- Range / 分片


def test_range_is_forwarded_and_status_206_preserved(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    proc, body, status = call(proxy, github_asset("range"), extra=("-r", "10-109"))

    assert proc.returncode == 0, proc.stderr
    assert status == 206
    assert len(body) == 100
    assert up.requests[0]["headers"]["range"] == "bytes=10-109"


def test_content_range_header_survives_rewrite(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    proc = curl(
        proxy.port,
        github_asset("range"),
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

    proc, body, status = call(proxy, github_asset("chunked"))

    assert proc.returncode == 0, proc.stderr
    assert status == 200
    assert body == b"abcdefgh"  # abc + defg + h


def test_chunked_with_bogus_content_length_is_relayed_to_eof(start_proxy, fake_upstream):
    """`Transfer-Encoding` 与 `Content-Length` 同时出现时按 TE 读到 EOF。

    回归：此前按 `Content-Length` 读固定字节数，分块流被截断在 chunk 中间，
    客户端（curl/winget 的分块解析）直接失败。
    """
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    proc, body, status = call(proxy, github_asset("chunkedboth"))

    assert proc.returncode == 0, proc.stderr
    assert status == 200
    assert body == b"abcdefgh"


def test_resume_with_two_range_requests_reassembles_exactly(start_proxy, fake_upstream):
    """断点续传的线上形态：两次相邻 Range 请求拼起来必须与整包逐字节一致。

    此前 README 把"断点续传"列为未验证。这里覆盖的是代理侧的责任——
    分片偏移不被篡改、pin 复用不会把两段接到不同的内容上；
    真实 winget 中断重试的行为不在本用例范围内。
    """
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    full = bytes(range(256)) * 4  # 与 conftest 里 "range" 分支的一致：1024 B

    _, head_part, status1 = call(proxy, github_asset("range"), extra=("-r", "0-511"))
    _, tail_part, status2 = call(proxy, github_asset("range"), extra=("-r", "512-1023"))

    assert status1 == 206 and status2 == 206
    assert len(head_part) == 512, len(head_part)
    assert len(tail_part) == 512, len(tail_part)

    joined = head_part + tail_part
    assert len(joined) == len(full)
    assert hashlib.sha256(joined).hexdigest() == hashlib.sha256(full).hexdigest(), (
        "两段拼接后必须与整包一致（偏移或内容被改动都会在这里暴露）"
    )
    # 两次请求都命中同一个候选（pin）：同一个文件不该被摊到不同加速器上
    assert len(up.requests) == 2
    assert all(r["path"] == f"/{github_asset('range')}" for r in up.requests)


def test_response_without_content_length_is_relayed(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    proc, body, status = call(proxy, github_asset("nolength"))

    assert proc.returncode == 0, proc.stderr
    assert status == 200
    assert body == b"no-length-body"


def test_large_response_is_byte_exact(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    proc, body, status = call(proxy, github_asset("big"), timeout=120)

    assert proc.returncode == 0, proc.stderr
    assert status == 200
    assert len(body) == 8 * 1024 * 1024
    assert hashlib.sha256(body).hexdigest() == hashlib.sha256(b"x" * (8 * 1024 * 1024)).hexdigest()


# ------------------------------------------------------------------ 错误路径


def test_upstream_error_status_is_passed_through(start_proxy, fake_upstream):
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    proc, body, status = call(proxy, github_asset("boom"))

    assert proc.returncode == 0
    assert status == 502
    assert body == b""


def test_range_request_upstream_200_is_rejected(request, start_proxy, fake_upstream):
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制的 Range 契约")

    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)
    proc, body, status = call(
        proxy, github_asset("range-ignored"), extra=("-r", "0-1")
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
        github_asset("truncated"),
        ca_path=proxy.ca_path,
        extra=("-r", "0-99"),
        timeout=20,
    )

    assert proc.returncode != 0
    time.sleep(0.2)
    log = proxy.log_text()
    assert "RELAY-ERR" in log
    assert "pin_cleared=true" in log
    # 上游声明 100 字节却只给 10 字节 → 这是"真的不完整"，不是"上游不发数据了"
    assert "kind=early-eof" in log, "截断必须归类为 early-eof，不能和超时混为一谈"

def test_unreachable_tunnel_returns_502(request, start_proxy):
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制的隧道失败契约")

    closed = free_port()
    proxy = start_proxy(accel="gh-proxy.com")
    proc = curl(proxy.port, f"https://127.0.0.1:{closed}/", timeout=10)

    assert proc.returncode != 0
    assert b"response 502" in proc.stderr.lower()

def test_request_body_is_rejected_fast(request, start_proxy, fake_upstream):
    """带请求体的请求必须立刻 501，而不是让上游等 body、客户端卡到读超时。

    回归：本代理只转发响应体。此前既没有转发请求体、也没有拒绝带体的请求。
    对真实上游（按 Content-Length 等 body）会一直等到 60 秒读超时；
    对本地的假上游则表现为"上游回 5xx → 换候选重试 → 合成 502"。
    修复后两种情况都变成：立刻 501、不碰上游。
    """
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制的「不转发请求体」契约")

    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    started = time.time()
    proc = curl(
        proxy.port,
        "https://github.com/upload",
        ca_path=proxy.ca_path,
        extra=("-X", "POST", "-d", "0123456789abcdef", "-w", STATUS_MARK + "%{http_code}"),
        timeout=30,
    )
    elapsed = time.time() - started
    _, _, status = proc.stdout.rpartition(STATUS_MARK.encode())

    assert proc.returncode == 0, proc.stderr
    assert status == b"501", proc.stdout
    assert elapsed < 15, f"应当立刻失败，实际 {elapsed:.1f}s（旧行为是卡满 60 秒）"
    assert up.requests == [], "带体的请求不该被转发到上游"

    time.sleep(0.2)
    log = proxy.log_text()
    assert "REQ-BODY-UNSUPPORTED" in log
    assert "method=POST" in log


def test_connect_host_is_case_insensitive(request, start_proxy):
    """`CONNECT GitHub.COM:443` 必须照样走 MITM。

    回归（实测复现过）：PAC 内部做了 `host.toLowerCase()`，所以大写 host 也会被导到代理；
    而分流判断曾用 `==` 精确比较，于是判成 TUNNEL——那条下载根本没有被加速，
    日志里还只写 `mode=TUNNEL`，看着一切正常。
    DNS 名字大小写不敏感（RFC 4343），这里用裸 socket 发一条大写 CONNECT 来钉住。
    """
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制的分流契约")

    proxy = start_proxy(accel="gh-proxy.com")
    sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
    sock.sendall(b"CONNECT GitHub.COM:443 HTTP/1.1\r\nHost: GitHub.COM:443\r\n\r\n")
    time.sleep(0.2)
    head = sock.recv(200)
    sock.close()

    assert b"200" in head, head
    time.sleep(0.2)
    log = proxy.log_text()
    assert "CONNECT github.com:443 mode=MITM" in log, f"大写 host 应仍走 MITM：\n{log[-600:]}"


def test_tunnels_cannot_starve_downloads(request, start_proxy):
    """隧道占满时，下载仍必须能用（名额有独立上限）。

    隧道来自 `*.github.com` 这类子域：浏览器开着若干 GitHub 标签页时，每条连接
    都可能长期占着名额。实测过：64 条隧道把名额占满后，winget 的下载 CONNECT
    直接拿到 503 —— 用户会看到"装了反而下载不了"。
    下载是本工具存在的唯一理由，所以隧道上限 48，其余名额留给 MITM。
    """
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制的名额契约")

    proxy = start_proxy(accel="gh-proxy.com")
    tunnels, rejected = [], 0
    try:
        for _ in range(56):
            s = socket.create_connection(("127.0.0.1", proxy.port), timeout=8)
            s.sendall(
                b"CONNECT gist.github.com:443 HTTP/1.1\r\nHost: gist.github.com:443\r\n\r\n"
            )
            s.settimeout(8)
            try:
                resp = s.recv(120)
            except OSError:
                resp = b""
            if resp.startswith(b"HTTP/1.1 200"):
                tunnels.append(s)
            else:
                rejected += 1
                s.close()

        assert len(tunnels) == 48, f"隧道上限应为 48，实际 {len(tunnels)}（被拒 {rejected}）"
        assert rejected > 0, "超过上限的隧道应被拒"

        # 关键：此时下载仍能建立 MITM 连接（修复前这里是 503）
        # 注意用 ca_path=（它会自动加 --ssl-no-revoke）；手写 --cacert 会漏掉它，
        # schannel 查不到吊销信息就直接失败——第一版就是这么写错的。
        proc = curl(
            proxy.port,
            "https://github.com/git-for-windows/git/releases/download/"
            "v2.43.0.windows.1/Git-2.43.0-64-bit.exe",
            ca_path=proxy.cert_dir / "ca-cert.pem",
            extra=("-r", "0-1023"),
        )
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    finally:
        for s in tunnels:
            s.close()

def test_pac_and_health_still_served_when_connection_slots_are_full(
    request, start_proxy
):
    """名额占满时，PAC 与 /health 仍必须能取到。

    Windows 会定期重新取 PAC，而把 64 个名额占满的正是下载本身。
    若 PAC 请求也被 503，浏览器可能退回直连——"下载越多、加速越容易失效"，
    而且失败是静默的。实测过：修复前 64 个连接占满后 `GET /winget-accel.pac`
    返回 503；修复后 PAC 与 /health 仍 200，其它路径仍 503。
    """
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制的并发上限契约")

    proxy = start_proxy(accel="gh-proxy.com")
    held = []
    try:
        for _ in range(64):
            held.append(socket.create_connection(("127.0.0.1", proxy.port), timeout=5))
        time.sleep(0.5)

        def get(path):
            s = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
                return s.recv(400)
            finally:
                s.close()

        pac = get("/winget-accel.pac")
        assert pac.startswith(b"HTTP/1.1 200"), f"占满后 PAC 应仍可用: {pac[:80]!r}"
        assert b"FindProxyForURL" in pac or b"function" in pac, pac[:120]

        health = get("/health")
        assert health.startswith(b"HTTP/1.1 200"), f"占满后 /health 应仍可用: {health[:80]!r}"

        # 其它路径仍按"满"拒绝，别把兜底变成绕过上限
        other = get("/something-else")
        assert other.startswith(b"HTTP/1.1 503"), f"非本地端点仍应 503: {other[:80]!r}"
    finally:
        for s in held:
            s.close()

def test_connection_limit_returns_503(request, start_proxy):
    """并发连接超过上限（64）时必须回 503，而不是无限建线程。

    连接在被 accept 时就占一个名额；空闲连接会停在"读请求头"，所以这里
    只要开满 64 个不发数据的连接，第 65 个就该被拒。
    """
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制的并发上限契约")

    proxy = start_proxy(accel="gh-proxy.com")
    held = []
    try:
        for _ in range(64):
            s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            held.append(s)
        time.sleep(0.5)  # 等服务端把这 64 个都 accept 掉

        extra = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        try:
            extra.settimeout(5)
            resp = extra.recv(200)
        finally:
            extra.close()

        assert b"503" in resp, f"第 65 个连接应被拒（503），实际: {resp[:60]!r}"
        assert proxy.log_text().count("CONN-LIMIT") >= 1
    finally:
        for s in held:
            s.close()


def test_unreachable_accel_returns_502_quickly(start_proxy):
    closed = free_port()  # 拿到就释放，保证没人监听
    proxy = start_proxy(accel=f"http://127.0.0.1:{closed}")

    proc, _, status = call(proxy, github_asset("x"), timeout=20)

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
    call(proxy, github_asset("ok"))
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
             github_asset("ok")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        for _ in range(5)
    ]
    results = [proc.communicate(timeout=90) for proc in procs]

    for proc, (out, err) in zip(procs, results):
        assert proc.returncode == 0, err
        assert out == b"hello-through-proxy"
    assert proxy.health()["rewrites"] >= 5

def test_conditional_headers_reach_the_accel(start_proxy, fake_upstream):
    """If-Range / If-None-Match / User-Agent 必须原样到达加速器。

    design.md §5 承诺这四个头透传；winget 用 Range+If-Range 续传、
    用 If-None-Match 做条件请求。此前没有用例覆盖这两个头。
    """
    up = fake_upstream()
    proxy = start_proxy(accel=up.accel)

    call(
        proxy,
        github_asset("range"),
        extra=("-r", "1024-2047", "-H", 'If-Range: "etag-abc"',
               "-H", 'If-None-Match: "etag-abc"'),
    )

    headers = up.requests[-1]["headers"]
    assert headers["range"] == "bytes=1024-2047", headers
    assert headers["if-range"] == '"etag-abc"', headers
    assert headers["if-none-match"] == '"etag-abc"', headers
    assert headers["user-agent"].startswith("curl/"), headers

# --------------------------------------------------------------- PAC 语义（真执行）

PAC_EVAL_JS = r"""
var fso = new ActiveXObject("Scripting.FileSystemObject");
function readAll(p) { var f = fso.OpenTextFile(p, 1), s = f.ReadAll(); f.Close(); return s; }
// PAC 标准函数：* 匹配任意字符，其余字面量
function shExpMatch(str, shexp) {
    var re = "^" + shexp.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$";
    return new RegExp(re).test(str);
}
eval(readAll(WScript.Arguments(0)));
var cases = readAll(WScript.Arguments(1)).split(/\r?\n/), fail = 0;
for (var i = 0; i < cases.length; i++) {
    var line = cases[i]; if (!line) continue;
    var p = line.split("\t"), want = p[0], url = p[1];
    var host = url.replace(/^[a-z]+:\/\/([^\/:]+).*$/i, "$1");
    var got = FindProxyForURL(url, host).indexOf("PROXY") === 0 ? "PROXY" : "DIRECT";
    if (got !== want) { fail++; WScript.Echo("FAIL " + want + " <- " + url + " (got " + got + ")"); }
}
WScript.Quit(fail === 0 ? 0 : 1);
"""

# PAC 的分流语义要**真正执行**才验得出来：字符串包含只能证明"文本里有这几个词"。
# 这里用 Windows 自带 JScript（cscript）执行代理实际吐出的 PAC，逐条比对期望。
PAC_CASES = [
    ("PROXY",  "https://github.com/o/r/releases/download/v1/x.exe"),
    ("PROXY",  "https://github.com/o/r/releases/latest/download/y.zip"),
    ("PROXY",  "https://github.com/o/r/archive/refs/heads/main.zip"),
    ("PROXY",  "https://github.com/o/r/raw/main/README.md"),
    ("PROXY",  "https://github.com/o/r/blob/main/a.txt"),
    ("PROXY",  "https://github.com/o/r"),                      # PAC 整域代理，代理层再决定是否改写
    ("PROXY",  "https://github.com/o/r.git/info/refs?service=git-upload-pack"),  # PAC 整域代理，代理层走隧道
    ("PROXY",  "https://github.com/o/r.git/git-upload-pack"),
    ("DIRECT", "http://github.com/o/r/releases/download/v1/x"),  # 非 https
    ("PROXY",  "https://api.github.com/repos/o/r"),             # 子域 → 隧道
    ("PROXY",  "https://objects.githubusercontent.com/a/b"),
    ("PROXY",  "https://codeload.github.com/o/r/zip/main"),
    ("PROXY",  "https://release-assets.githubusercontent.com/x/y"),
    ("DIRECT", "https://example.com/"),
    ("DIRECT", "https://evilgithub.com/github.com/x"),          # 别被 *.github.com 误伤
    ("PROXY",  "https://evil.github.com/x"),                    # 真子域
    ("DIRECT", "https://microsoft.com/"),
    ("DIRECT", "https://cdn.winget.microsoft.com/cache"),
]


def test_pac_routing_semantics(request, start_proxy):
    """用真实 JS 引擎执行生成的 PAC，验证分流语义（含克隆/子域/非 https 的负例）。"""
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制生成的 PAC")
    if not shutil.which("cscript"):
        pytest.skip("没有 cscript（Windows Script Host）")

    proxy = start_proxy(accel="gh-proxy.com")
    pac = urllib.request.urlopen(
        f"http://127.0.0.1:{proxy.port}/winget-accel.pac", timeout=5
    ).read().decode("utf-8")

    tmp = Path(tempfile.mkdtemp(prefix="pac-"))
    try:
        (tmp / "p.pac").write_text(pac, encoding="utf-8")
        (tmp / "c.txt").write_text(
            "\n".join(f"{want}\t{url}" for want, url in PAC_CASES), encoding="utf-8"
        )
        (tmp / "e.js").write_text(PAC_EVAL_JS, encoding="utf-8")
        proc = subprocess.run(
            ["cscript", "//nologo", str(tmp / "e.js"), str(tmp / "p.pac"), str(tmp / "c.txt")],
            capture_output=True,
        )
        out = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
        assert proc.returncode == 0, f"有路由与预期不符：\n{out}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_oversized_request_head_gets_431(start_proxy):
    """请求头超过上限时要回 431，而不是直接断线。

    实测过：此前客户端只看到连接被重置/超时，完全看不出是"请求头太大"。
    本地代理不是对外服务，但报错能指对方向对排查仍有价值。
    注意：随机二进制打进来**不该**收到 HTTP 响应（对端读不懂），所以只测 HTTP 形态的超限。
    """
    proxy = start_proxy(accel="gh-proxy.com")

    # 只写到刚好超过上限（32 KiB）就停手：继续灌数据会在服务端关闭后触发 RST，
    # 把已经到达的 431 响应冲掉（第一次写这个用例就踩到了）。
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=10) as s:
        s.sendall(b"GET / HTTP/1.1\r\nX: " + b"a" * 33000)
        data = s.recv(200)

    assert data.startswith(b"HTTP/1.1 431"), data[:80]


def test_normal_request_still_works_after_oversized_one(start_proxy):
    """一个畸形请求不该影响后续正常请求（何况它们跑在不同线程里）。"""
    proxy = start_proxy(accel="gh-proxy.com")

    with socket.create_connection(("127.0.0.1", proxy.port), timeout=10) as s:
        s.sendall(b"GET /" + b"b" * 33000)
        first = s.recv(200)
    assert first.startswith(b"HTTP/1.1 431"), first[:80]

    with socket.create_connection(("127.0.0.1", proxy.port), timeout=10) as s:
        s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        second = s.recv(400)
    assert second.startswith(b"HTTP/1.1 200"), second[:80]
    assert b'"status"' in second


def test_range_ignoring_candidate_fails_over_to_a_good_one(
    request, start_proxy, fake_upstream
):
    """候选忽略 Range（回 200）时，客户端最终必须拿到**分片**，绝不能拿到整包。

    回归防线：把"Range 请求拿到 200"透传给 winget，会让它把**整包**当成某个分片，
    哈希必然不符——而且是静默的。

    注意本用例的**局限**：候选是加权随机选的，所以"先试坏的那个"不是必然。
    稳定覆盖"200 绝不被透传"的是 `test_all_candidates_ignoring_range_yields_502`；
    这条负责"有好的候选时能拿到 206"，并在恰好先试了坏候选时额外验证换候选发生。
    """
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制的 Range 契约")

    bad = fake_upstream(ignore_range=True)
    good = fake_upstream()
    proxy = start_proxy(accels=[bad.accel, good.accel])

    proc, body, status = call(
        proxy, github_asset("failover-range"), extra=("-r", "0-65535")
    )

    assert proc.returncode == 0, proc.stderr
    # 关键断言：客户端拿到的是**分片**（206），不是坏候选那个 200 整包。
    # 候选选择是加权随机的，所以"先试坏的"不是必然——
    # 只断言结果正确，并把"是否真的发生后换"作为条件性证据。
    assert status == 206, f"应拿到分片，实际 {status}"
    # 夹具里路径含 "range" 的默认响应是 1024 B（bytes(range(256)) * 4）。
    assert len(body) == 1024, f"应拿到正常候选的分片，实际 {len(body)} B"
    assert good.requests, "正常候选应该收到请求"
    if bad.requests:
        # 坏候选被先试过 → 说明确实发生了"发现 200 后换候选"
        assert len(bad.requests) >= 1


def test_all_candidates_ignoring_range_yields_502(request, start_proxy, fake_upstream):
    """所有候选都忽略 Range 时必须回 502，绝不能把 200 整包透给客户端。"""
    if not request.config.getoption("--target-binary"):
        pytest.skip("Rust 二进制的 Range 契约")

    a = fake_upstream(ignore_range=True)
    b = fake_upstream(ignore_range=True)
    proxy = start_proxy(accels=[a.accel, b.accel])

    proc, body, status = call(
        proxy, github_asset("all-bad-range"), extra=("-r", "0-65535")
    )

    assert proc.returncode == 0, proc.stderr
    assert status == 502, f"整包不能被当成 200 透传，实际 {status}"
    assert body == b""


def test_no_alpn_so_http2_cannot_be_negotiated(start_proxy):
    """服务端不得协商 ALPN：客户端 offer h2 时结果必须是 None（强制 HTTP/1.1）。

    文档承诺"不实现 HTTP/2（不协商 ALPN）"。此前只有代码注释，没有实测。
    Windows 自带的 curl 是 Schannel 构建、不支持 h2，验证不了这件事——
    所以这里用 Python 的 ssl 模块显式 set_alpn_protocols(["h2", "http/1.1"])。
    服务端若不发 ALPN，`selected_alpn_protocol()` 返回 None，客户端只能走 HTTP/1.1。
    """
    proxy = start_proxy(accel="gh-proxy.com")

    ctx = ssl.create_default_context()
    # 只信任本代理刚生成的那张 CA，避免受系统根存储影响
    ctx.load_verify_locations(cafile=str(proxy.cert_dir / "ca-cert.pem"))
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    with socket.create_connection(("127.0.0.1", proxy.port), timeout=15) as raw:
        raw.sendall(b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
        head = raw.recv(200)
        assert b"200" in head, head

        with ctx.wrap_socket(raw, server_hostname="github.com") as tls:
            negotiated = tls.selected_alpn_protocol()
            assert negotiated is None, (
                f"代理协商了 ALPN={negotiated!r}；本代理只支持 HTTP/1.1，必须不发 ALPN"
            )
