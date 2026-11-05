"""需要真实外网与可用加速器的用例（默认跳过，用 --network 开启）。

这些用例的价值是"钉住加速器的真实行为"：Range 是否被支持、字节是否保真。
它们会随加速器失效而失败——这正是我们想尽早知道的。
"""

from __future__ import annotations

import hashlib
import subprocess

import pytest

pytestmark = pytest.mark.network

# 固定版本与已知摘要，避免"上游发新版导致测试漂移"
ASSET = (
    "https://github.com/sharkdp/fd/releases/download/v10.5.0/"
    "fd-v10.5.0-x86_64-pc-windows-msvc.zip"
)
ASSET_SIZE = 1_535_063
ASSET_SHA256 = "a227701b8551c35a9931d9f6da75503cf86d88e182d71fb849a70864c5d57cd7"


def _curl(proxy, extra, timeout=180):
    return subprocess.run(
        [
            "curl.exe", "-sS", "--max-time", str(timeout),
            "--ssl-no-revoke", "--cacert", str(proxy.ca_path),
            "-x", f"http://127.0.0.1:{proxy.port}",
            *extra,
        ],
        capture_output=True,
    )


def test_real_asset_downloads_byte_exact(start_proxy):
    proxy = start_proxy(accel="gh-proxy.com")

    proc = _curl(proxy, [ASSET])

    assert proc.returncode == 0, proc.stderr
    assert len(proc.stdout) == ASSET_SIZE
    assert hashlib.sha256(proc.stdout).hexdigest() == ASSET_SHA256


def test_real_accel_supports_range(start_proxy):
    proxy = start_proxy(accel="gh-proxy.com")

    proc = _curl(proxy, ["-r", "0-1023", "-w", "%{http_code}", ASSET])

    assert proc.returncode == 0, proc.stderr
    body, _, status = proc.stdout.rpartition(b"206")
    assert status == b"", "加速器未返回 206，说明不支持 Range"
    assert len(body) == 1024


def test_three_concurrent_ranges_reassemble_to_full_file(start_proxy):
    proxy = start_proxy(accel="gh-proxy.com")
    third = ASSET_SIZE // 3

    ranges = [f"0-{third - 1}", f"{third}-{2 * third - 1}", f"{2 * third}-"]
    procs = [
        subprocess.Popen(
            [
                "curl.exe", "-sS", "--max-time", "180",
                "--ssl-no-revoke", "--cacert", str(proxy.ca_path),
                "-x", f"http://127.0.0.1:{proxy.port}",
                "-r", rng, ASSET,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for rng in ranges
    ]
    parts = []
    for proc in procs:
        out, err = proc.communicate(timeout=200)
        assert proc.returncode == 0, err
        parts.append(out)

    merged = b"".join(parts)
    assert len(merged) == ASSET_SIZE
    assert hashlib.sha256(merged).hexdigest() == ASSET_SHA256


def test_relay_preserves_bytes_exactly_vs_accelerator(start_proxy):
    """经我们代理取到的字节，必须与**直接向加速器**取到的字节完全相同。

    `test_real_asset_downloads_byte_exact` 比对的是硬编码摘要——它验证"内容对不对"，
    但如果加速器本身返回了不同内容（换版本、被投毒），那个用例会失败，
    却分不清是"我们改坏了"还是"上游变了"。
    这一条把**同一时刻**的两条路径放在一起比：只盯"我们这层有没有动过字节"。
    """
    proxy = start_proxy(accel="gh-proxy.com")
    rng = ["-r", "0-65535"]

    via_proxy = _curl(proxy, [*rng, ASSET])
    assert via_proxy.returncode == 0, via_proxy.stderr
    assert len(via_proxy.stdout) == 65536

    direct = subprocess.run(
        ["curl.exe", "-sS", "--max-time", "180", *rng, f"https://gh-proxy.com/{ASSET}"],
        capture_output=True,
    )
    assert direct.returncode == 0, direct.stderr
    assert len(direct.stdout) == 65536

    assert hashlib.sha256(via_proxy.stdout).hexdigest() == hashlib.sha256(
        direct.stdout
    ).hexdigest(), "代理转发改变了字节：这一层必须逐字节透传"
