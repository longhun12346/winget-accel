"""单元测试：不碰网络、不碰 socket 的纯逻辑与证书属性。

这些用例是 Rust 版必须逐条对齐的行为契约。
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

import ca as ca_mod
import wgaccel as w


# ------------------------------------------------------------------ PAC 文本
# 说明：PAC 是 JScript，这里不做 JS 求值，只锁定"生成文本的结构"。
# 真实路由行为由 tests/test_proxy.py 的端到端用例覆盖。


def test_pac_declares_entry_function():
    text = w.pac_text(8443)
    assert "function FindProxyForURL(url, host)" in text


def test_pac_covers_all_whitelist_hosts():
    text = w.pac_text(8443)
    for host in w.WHITELIST:
        assert f'host == "{host}"' in text, host


def test_pac_routes_github_subdomains_but_not_other_wildcards():
    """`*.github.com` 是唯一的通配，且只用于 github.com。

    PAC 范围比 MITM 范围宽是有意的：子域会被圈进代理但只做隧道，
    避免其流量被系统直连卡住（design.md §4）。
    """
    text = w.pac_text(8443)
    assert 'shExpMatch(host, "*.github.com")' in text
    assert '*.com"' not in text  # 不允许过宽的通配
    assert text.count("shExpMatch") == 1


def test_pac_uses_given_port_and_defaults_to_direct():
    text = w.pac_text(9123)
    assert 'PROXY 127.0.0.1:9123' in text
    assert 'return "DIRECT";' in text


def test_pac_lowercases_host():
    assert "host.toLowerCase()" in w.pac_text(8443)


# -------------------------------------------------------------- 加速器地址


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("gh-proxy.com", ("https", "gh-proxy.com", 443)),
        ("ghfast.top", ("https", "ghfast.top", 443)),
        ("127.0.0.1:9999", ("https", "127.0.0.1", 9999)),
        ("http://127.0.0.1:9999", ("http", "127.0.0.1", 9999)),
        ("https://gh-proxy.com", ("https", "gh-proxy.com", 443)),
        ("HTTP://LocalHost:8080", ("http", "LocalHost", 8080)),
        ("http://example.com", ("http", "example.com", 80)),
    ],
)
def test_parse_accel_accepts_supported_forms(value, expected):
    assert w.parse_accel(value) == expected


@pytest.mark.parametrize("value", ["ftp://x", "http://", ":8080", "host:notaport"])
def test_parse_accel_rejects_bad_input(value):
    with pytest.raises(ValueError):
        w.parse_accel(value)


# ----------------------------------------------------------------- 改写决策


ACCEL = ("https", "gh-proxy.com", 443)


def test_rewrite_path_prefixes_original_url():
    assert w.rewrite_path("github.com", "/a/b.zip?x=1&y=2") == "/https://github.com/a/b.zip?x=1&y=2"


def test_rewrite_keeps_query_string_untouched():
    target = "/releases/download/v1/x.zip?download=1&foo=%E4%B8%AD"
    plan = w.plan_upstream("GET", "github.com", 443, target, ["Host: github.com"], ACCEL)
    assert plan.path.endswith(target)
    # 已百分号编码的字符不得二次编码
    assert "%E4%B8%AD" in plan.path


def test_plan_rewrite_targets_accel_and_replaces_host_header():
    plan = w.plan_upstream(
        "GET", "github.com", 443, "/a.zip", ["Host: github.com", "User-Agent: winget"], ACCEL
    )
    assert plan.rewritten is True
    assert (plan.scheme, plan.host, plan.port) == ("https", "gh-proxy.com", 443)
    assert plan.path == "/https://github.com/a.zip"
    head = plan.head.decode()
    assert head.startswith("GET /https://github.com/a.zip HTTP/1.1\r\n")
    assert "Host: gh-proxy.com\r\n" in head
    assert "Host: github.com\r\n" not in head


def test_plan_rewrite_drops_hop_by_hop_headers_and_keeps_range():
    plan = w.plan_upstream(
        "GET",
        "github.com",
        443,
        "/a.zip",
        [
            "Host: github.com",
            "Range: bytes=0-1023",
            "Connection: keep-alive",
            "Proxy-Connection: keep-alive",
            "Keep-Alive: timeout=5",
            "TE: trailers",
            "Trailer: X",
            "Upgrade: h2c",
            "Accept: */*",
        ],
        ACCEL,
    )
    head = plan.head.decode().lower()
    assert "range: bytes=0-1023" in head
    assert "accept: */*" in head
    for gone in ("proxy-connection", "keep-alive:", "te:", "trailer:", "upgrade:"):
        assert gone not in head, gone
    # 统一以 close 结束，简化响应定界
    assert "connection: close" in head


def test_plan_passthrough_keeps_host_and_path():
    plan = w.plan_upstream(
        "GET", "example.com", 443, "/index.html", ["Host: example.com"], ACCEL
    )
    assert plan.rewritten is False
    assert (plan.scheme, plan.host, plan.port) == ("https", "example.com", 443)
    assert plan.path == "/index.html"
    head = plan.head.decode()
    assert "Host: example.com\r\n" in head
    assert "gh-proxy.com" not in head


def test_plan_passthrough_keeps_nonstandard_port():
    plan = w.plan_upstream("GET", "127.0.0.1", 9443, "/", ["Host: 127.0.0.1:9443"], ACCEL)
    assert (plan.host, plan.port) == ("127.0.0.1", 9443)


def test_plan_rewrite_applies_to_every_whitelisted_host():
    for host in w.WHITELIST:
        plan = w.plan_upstream("GET", host, 443, "/x", [f"Host: {host}"], ACCEL)
        assert plan.rewritten is True, host
        assert plan.path == f"/https://{host}/x"


def test_plan_non_whitelisted_host_is_not_rewritten():
    for host in ("api.github.com", "example.com", "cdn.winget.microsoft.com"):
        plan = w.plan_upstream("GET", host, 443, "/x", [f"Host: {host}"], ACCEL)
        assert plan.rewritten is False, host
        assert plan.path == "/x"


# --------------------------------------------------------------- CA 与叶证书


def test_ca_has_name_constraints_limited_to_whitelist(ca):
    ext = ca.ca_cert.extensions.get_extension_for_class(x509.NameConstraints)
    assert ext.critical is True
    dns = sorted(name.value for name in ext.value.permitted_subtrees)
    assert dns == sorted(ca_mod.WHITELIST)
    assert ext.value.excluded_subtrees is None


def test_ca_cannot_sign_subordinate_ca(ca):
    bc = ca.ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length == 0


def test_ca_key_usage_allows_cert_signing(ca):
    ku = ca.ca_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is True
    assert ku.crl_sign is True


def test_ca_is_stable_across_restarts(cert_dir):
    """同一 cert-dir 必须复用原 CA，否则每次重启都要重新信任。"""
    first = ca_mod.CertAuthority(cert_dir)
    second = ca_mod.CertAuthority(cert_dir)
    assert first.thumbprint == second.thumbprint


def test_leaf_certificate_is_valid_for_host(ca, cert_dir):
    ca.leaf_context("github.com")
    leaf = x509.load_pem_x509_certificate((ca.leaf_dir / "github.com.pem").read_bytes())

    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [str(n) for n in san.get_values_for_type(x509.DNSName)] == ["github.com"]

    bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False

    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku

    assert leaf.issuer == ca.ca_cert.subject
    # 签名确实由 CA 私钥生成
    ca.ca_cert.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        ec.ECDSA(leaf.signature_hash_algorithm),
    )


def test_leaf_is_cached_per_host(ca):
    ctx1 = ca.leaf_context("github.com")
    ctx2 = ca.leaf_context("github.com")
    assert ctx1 is ctx2


def test_leaf_certificates_are_distinct_per_host(ca):
    ca.leaf_context("github.com")
    ca.leaf_context("codeload.github.com")
    a = (ca.leaf_dir / "github.com.pem").read_bytes()
    b = (ca.leaf_dir / "codeload.github.com.pem").read_bytes()
    assert a != b


def test_concurrent_first_use_builds_one_valid_leaf(ca):
    """并发首连同一 host 时，叶证书只能生成一次且必须可解析。

    回归：不加锁时两个线程会同时写同一个 .pem，后一个 load_cert_chain
    可能读到写了一半的内容，表现为 TLS 握手被重置。
    """
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        contexts = list(pool.map(lambda _: ca.leaf_context("github.com"), range(16)))

    assert all(ctx is contexts[0] for ctx in contexts)

    leaf = x509.load_pem_x509_certificate((ca.leaf_dir / "github.com.pem").read_bytes())
    cn = leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == "github.com"
