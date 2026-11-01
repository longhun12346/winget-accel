//! 本地 CA 与叶证书。
//!
//! 三重约束（ADR-014）里的第 1 条就落在这里：
//! - CA 带 `NameConstraints`，permitted 恰为改写白名单
//! - CA 的 `path_length = 0`，不能签下级 CA
//!
//! 这两条**由 Windows 强制校验**（实测见 docs/verification-proxy-2026-11-01.md §9.4），
//! 所以即使代理被攻破，也无法用这张 CA 冒充白名单以外的站点。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, NameConstraints,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// CA 有效期（天）。短一些是为了降低私钥泄露后的窗口期。
const CA_VALIDITY_DAYS: i64 = 365; // 1 年：与 Charles Proxy 的本地 CA 保持一致
/// 叶证书有效期（天）。只在内存里，重启即重建。
const LEAF_VALIDITY_DAYS: i64 = 30;

const CA_CERT_FILE: &str = "ca-cert.pem";
const CA_KEY_FILE: &str = "ca-key.pem";
const CA_META_FILE: &str = "ca-meta.json";

pub struct CertAuthority {
    /// CA 证书 PEM。单测用它验证"重启后仍是同一张 CA"；doctor 后续也会用到。
    #[allow(dead_code)]
    ca_pem: String,
    /// rcgen 的签发者：持有 CA 私钥，可按需签叶证书。
    issuer: Issuer<'static, KeyPair>,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertAuthority {
    /// 读取既有 CA；不存在则生成一张。
    ///
    /// `permitted` 必须与配置里的改写白名单一致：改了白名单却沿用旧 CA，
    /// 新 host 会签不出证书（Name Constraints 会拒绝），所以这里直接报错。
    pub fn load_or_create(dir: &Path, permitted: &[String]) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("建不了证书目录: {}", dir.display()))?;

        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        let meta_path = dir.join(CA_META_FILE);

        // 到期前自动轮换：清掉旧证书与旧文件，随后走"创建新 CA"分支
        if cert_path.exists() {
            let info = expiry_info(&cert_path);
            if info.is_none() {
                println!("⚠ 无法读取 CA 有效期（Get-PfxCertificate 未返回结果），跳过到期检查。");
            }
            if let Some((thumb, days)) = info {
                if days <= RENEW_BEFORE_DAYS {
                    println!(
                        "本机 CA 有效期剩余 {days} 天（阈值 {RENEW_BEFORE_DAYS} 天），自动轮换：\
                         移除旧证书并重新生成，需要重新信任一次。"
                    );
                    remove_trusted_ca(&thumb);
                    let _ = std::fs::remove_file(&cert_path);
                    let _ = std::fs::remove_file(&key_path);
                    let _ = std::fs::remove_file(&meta_path);
                }
            }
        }
        if cert_path.exists() && key_path.exists() {
            let ca_pem = std::fs::read_to_string(&cert_path)
                .with_context(|| format!("读不到 {}", cert_path.display()))?;
            let key_pem = std::fs::read_to_string(&key_path)
                .with_context(|| format!("读不到 {}", key_path.display()))?;

            if let Ok(meta) = std::fs::read_to_string(&meta_path) {
                let recorded: Vec<String> = serde_json::from_str(&meta).unwrap_or_default();
                if recorded != permitted {
                    bail!(
                        "已存在的 CA 的授权域名与当前配置不一致。\n\
                         旧: {recorded:?}\n新: {permitted:?}\n\
                         请删除 {} 后重试（会生成新 CA，需要重新信任一次）",
                        dir.display()
                    );
                }
            }

            let key = KeyPair::from_pem(&key_pem).context("CA 私钥无法解析")?;
            let issuer = Issuer::from_ca_cert_pem(&ca_pem, key).context("CA 证书无法解析")?;
            return Ok(Self {
                ca_pem,
                issuer,
                cache: Mutex::new(HashMap::new()),
            });
        }

        let ca_pem = Self::create(dir, permitted, &cert_path, &key_path, &meta_path)?;
        let key_pem = std::fs::read_to_string(&key_path)?;
        let key = KeyPair::from_pem(&key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, key)?;
        Ok(Self {
            ca_pem,
            issuer,
            cache: Mutex::new(HashMap::new()),
        })
    }

    fn create(
        dir: &Path,
        permitted: &[String],
        cert_path: &Path,
        key_path: &Path,
        meta_path: &Path,
    ) -> Result<String> {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "winget-accel local CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "winget-accel");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: permitted
                .iter()
                .map(|host| GeneralSubtree::DnsName(host.clone()))
                .collect(),
            excluded_subtrees: Vec::new(),
        });
        set_validity(&mut params, CA_VALIDITY_DAYS);

        let key = KeyPair::generate().context("生成 CA 私钥失败")?;
        let key_pem = key.serialize_pem();
        let cert = params.self_signed(&key).context("自签 CA 失败")?;
        let ca_pem = cert.pem();

        std::fs::write(cert_path, &ca_pem)
            .with_context(|| format!("写不了 {}", cert_path.display()))?;
        std::fs::write(key_path, &key_pem)
            .with_context(|| format!("写不了 {}", key_path.display()))?;
        // 记下授权域名，配置变化时能立刻发现
        std::fs::write(meta_path, serde_json::to_string(permitted)?)
            .with_context(|| format!("写不了 {}", meta_path.display()))?;
        restrict_permissions(dir);

        Ok(ca_pem)
    }

    #[allow(dead_code)]
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn ca_pem_path(dir: &Path) -> PathBuf {
        dir.join(CA_CERT_FILE)
    }

    /// 取（必要时生成）该 host 的服务端 TLS 配置。
    ///
    /// 加锁是必须的：生成与加载不是原子操作，并发首连同 host 会互相踩。
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let mut cache = self.cache.lock().expect("证书缓存锁中毒");
        if let Some(cfg) = cache.get(host) {
            return Ok(Arc::clone(cfg));
        }

        let mut params = CertificateParams::new(vec![host.to_string()])
            .with_context(|| format!("叶证书 SAN 非法: {host}"))?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.is_ca = IsCa::NoCa;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        set_validity(&mut params, LEAF_VALIDITY_DAYS);

        let leaf_key = KeyPair::generate().context("生成叶证书私钥失败")?;
        let cert = params
            .signed_by(&leaf_key, &self.issuer)
            .with_context(|| format!("签发叶证书失败: {host}"))?;

        let cert_der: CertificateDer<'static> = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .context("构造 TLS 服务端配置失败")?;
        let cfg = Arc::new(cfg);
        cache.insert(host.to_string(), Arc::clone(&cfg));
        Ok(cfg)
    }
}

/// 上游（加速器）证书校验用的客户端配置。
///
/// 用 webpki-roots 的静态根证书，避免读取系统存储（那需要额外依赖，
/// 且会让"信任谁"变得不可控）。ALPN 不发：只支持 HTTP/1.1。
pub fn upstream_client_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// 就地设置有效期，避免在签名里写出 `time::OffsetDateTime` 的路径
/// （rcgen 对 `time` 的再导出方式在不同版本间变过）。
fn set_validity(params: &mut CertificateParams, days: i64) {
    let today = days_since_unix_epoch();
    let (y, m, d) = civil_from_days(today - 1);
    params.not_before = rcgen::date_time_ymd(y, m, d);
    let (y, m, d) = civil_from_days(today + days);
    params.not_after = rcgen::date_time_ymd(y, m, d);
}

fn days_since_unix_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64 / 86_400)
        .unwrap_or(0)
}

/// 天数转 (年, 月, 日)。Howard Hinnant 的 civil_from_days，避免引入 chrono。
fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u8, d as u8)
}

/// 收紧证书目录权限：去掉继承，只保留当前用户与 SYSTEM。
///
/// CA 私钥是明文存放的，默认从父目录继承的 ACL 可能允许同机其他用户读取。
/// 失败不致命（最多保持原状），所以只吞掉错误，不中断启动。
fn restrict_permissions(dir: &Path) {
    let user = std::env::var("USERNAME").unwrap_or_default();
    let mut cmd = std::process::Command::new("icacls");
    cmd.arg(dir).arg("/inheritance:r");
    if !user.is_empty() {
        cmd.arg("/grant:r").arg(format!("{user}:(OI)(CI)F"));
    }
    cmd.arg("/grant:r").arg("SYSTEM:(OI)(CI)F");
    let _ = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

// ---------------------------------------------------------------- 自动轮换
//
// CA 有效期 1 年。到期后叶证书会验签失败，而 WinINet 报的是
// TRUST_E_CERT_SIGNATURE（0x96004）——完全指不到"证书过期"，用户无从下手。
// 所以到期前主动轮换：自动移除旧证书、删掉旧文件、重新生成。
// 唯一无法自动化的是导入时的确认框（Windows 装根证书必然交互）。

/// 提前多少天开始轮换。留一点余量，避免"今天能用明天突然坏"。
const RENEW_BEFORE_DAYS: i32 = 7;

/// 读证书指纹与剩余天数（走 Win32 API，不依赖 PowerShell）。
fn expiry_info(ca_pem: &Path) -> Option<(String, i32)> {
    crate::certinfo::info(ca_pem).map(|info| (info.thumbprint, info.days_left as i32))
}
/// 从用户根存储移除指定指纹的证书。
///
/// 用注册表键而非 `certutil -delstore`：后者在部分机器上返回
/// ERROR_NOT_SUPPORTED（实测过，见 README 卸载章节）。
fn remove_trusted_ca(thumbprint: &str) {
    let key = format!(
        "HKCU\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\{thumbprint}"
    );
    let _ = std::process::Command::new("reg")
        .args(["delete", &key, "/f"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        // 闰日
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }

    #[test]
    fn reuses_existing_ca_across_loads() {
        let dir = std::env::temp_dir().join(format!("wgaccel-ca-{}", std::process::id()));
        let hosts = vec!["github.com".to_string()];
        let first = CertAuthority::load_or_create(&dir, &hosts).unwrap();
        let second = CertAuthority::load_or_create(&dir, &hosts).unwrap();
        assert_eq!(first.ca_pem(), second.ca_pem());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_ca_when_permitted_hosts_change() {
        let dir = std::env::temp_dir().join(format!("wgaccel-ca-meta-{}", std::process::id()));
        CertAuthority::load_or_create(&dir, &["github.com".to_string()]).unwrap();
        // 白名单变了却沿用旧 CA：新 host 签不出证书，必须显式报错而不是静默继续
        let err = CertAuthority::load_or_create(&dir, &["example.com".to_string()])
            .err()
            .expect("应当报错");
        assert!(err.to_string().contains("不一致"), "实际错误: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}