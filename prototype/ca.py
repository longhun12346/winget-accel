"""原型用 CA 与叶证书生成。

关键设计：CA 带 Name Constraints，只允许签发白名单内的域名。
这样即使私钥泄露，也无法用于劫持其他站点——对应 ADR-007 的收窄。
"""

from __future__ import annotations

import datetime as dt
import ssl
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# 只改写着四个 host。github.com 覆盖其子域（RFC 5280 的 DNS 约束语义）。
WHITELIST = (
    "github.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "release-assets.githubusercontent.com",
)

CA_CERT_NAME = "ca-cert.pem"
CA_KEY_NAME = "ca-key.pem"


class CertAuthority:
    """自签 CA + 按需签发叶证书。"""

    def __init__(
        self,
        cert_dir: Path,
        permitted_hosts: tuple[str, ...] = WHITELIST,
        ca_days: int = 365,
        leaf_days: int = 30,
    ) -> None:
        self.cert_dir = Path(cert_dir)
        self.leaf_dir = self.cert_dir / "leaves"
        self.leaf_dir.mkdir(parents=True, exist_ok=True)
        self.permitted_hosts = tuple(permitted_hosts)
        self.ca_days = ca_days
        self.leaf_days = leaf_days
        self._contexts: dict[str, ssl.SSLContext] = {}
        # 叶证书是"生成文件 + 加载文件"两步；并发首连同一 host 时若不加锁，
        # 后一个线程可能读到写了一半的 PEM，表现为 TLS 握手被重置（实测过）。
        self._leaf_lock = threading.Lock()
        self._load_or_create()

    # ------------------------------------------------------------------ CA
    def _load_or_create(self) -> None:
        cert_path = self.cert_dir / CA_CERT_NAME
        key_path = self.cert_dir / CA_KEY_NAME
        if cert_path.exists() and key_path.exists():
            self.ca_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            self.ca_key = serialization.load_pem_private_key(
                key_path.read_bytes(), password=None
            )
            return

        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.timezone.utc)
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "winget-accel prototype"),
                x509.NameAttribute(NameOID.COMMON_NAME, "winget-accel prototype CA"),
            ]
        )
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=self.ca_days))
            # path_length=0：只能签终端证书，不能签下级 CA
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            # 核心约束：只允许签发白名单域名
            .add_extension(
                x509.NameConstraints(
                    permitted_subtrees=[x509.DNSName(h) for h in self.permitted_hosts],
                    excluded_subtrees=None,
                ),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )
        cert_path.write_bytes(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            self.ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    @property
    def thumbprint(self) -> str:
        return self.ca_cert.fingerprint(hashes.SHA256()).hex().upper()

    def permit_host(self, host: str) -> None:
        """把额外 host 加入许可集（仅用于测试 Name Constraints 是否生效）。"""
        if host in self.permitted_hosts:
            return
        self.permitted_hosts = self.permitted_hosts + (host,)
        # 重建 CA 以带上新约束
        for stale in (self.cert_dir / CA_CERT_NAME, self.cert_dir / CA_KEY_NAME):
            stale.unlink(missing_ok=True)
        self._contexts.clear()
        for leaf in self.leaf_dir.glob("*.pem"):
            leaf.unlink(missing_ok=True)
        self._load_or_create()

    # ---------------------------------------------------------------- leaf
    def leaf_context(self, host: str) -> ssl.SSLContext:
        ctx = self._contexts.get(host)
        if ctx is not None:
            return ctx
        with self._leaf_lock:
            # 等锁期间可能已被其它线程建好
            ctx = self._contexts.get(host)
            if ctx is not None:
                return ctx
            return self._build_leaf_context(host)

    def _build_leaf_context(self, host: str) -> ssl.SSLContext:
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.timezone.utc)
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self.ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=self.leaf_days))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        cert_path = self.leaf_dir / f"{host}.pem"
        key_path = self.leaf_dir / f"{host}.key.pem"
        cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        self._contexts[host] = ctx
        return ctx
