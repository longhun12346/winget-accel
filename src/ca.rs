//! 本地 CA 与叶证书。
//!
//! 三重约束（ADR-014）里的第 1 条就落在这里：
//! - 中间 CA 带 `NameConstraints`，permitted 恰为改写白名单
//! - 中间 CA 的 `path_length = 0`，不能签下级 CA
//!
//! 这两条**由 Windows 强制校验**（实测：签 `example.com` 的链被拒，
//! `HasNotPermittedNameConstraint`），所以即使代理被攻破，
//! 也无法用这张 CA 冒充白名单以外的站点。
//!
//! **范围的准确表述是"4 个域及其子域"**：dNSName 子树按 RFC 5280 §4.2.1.10
//! 覆盖"往左侧加任意标签"，所以 permitted `github.com` 同时也允许
//! `api.github.com`、`evil.github.com`（实测 Windows 链校验通过）。
//! 这不是缺陷（约束本来就按域表达），但文档不能写成"只能签 4 个主机名"。
//! 本工具自己不做这些子域的 MITM：PAC 只把 4 个 host 交过来，子域走隧道。

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
const ROOT_CERT_FILE: &str = "root-cert.pem";
const ROOT_KEY_FILE: &str = "root-key.pem";
const CA_META_FILE: &str = "ca-meta.json";

pub struct CertAuthority {
    /// 受 Name Constraints 约束的中间 CA 证书 PEM。
    #[allow(dead_code)]
    ca_pem: String,
    /// 中间 CA 的签发者：持有中间 CA 私钥，可按需签叶证书。
    issuer: Issuer<'static, KeyPair>,
    /// 发送给客户端的中间 CA 证书，组成 leaf → constrained CA → trusted root 链。
    intermediate_der: CertificateDer<'static>,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertAuthority {
    /// 读取既有 CA；不存在则生成一张。
    ///
    /// `permitted` 必须与配置里的改写白名单一致：改了白名单却沿用旧 CA，
    /// 新 host 会签不出证书（Name Constraints 会拒绝），所以这里直接报错。
    pub fn load_or_create(dir: &Path, permitted: &[String], manage_trust: bool) -> Result<Self> {
        Self::load_with_remover(dir, permitted, manage_trust, remove_trusted_ca)
    }

    fn load_with_remover(
        dir: &Path,
        permitted: &[String],
        manage_trust: bool,
        remove_trust: impl Fn(&str),
    ) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("建不了证书目录: {}", dir.display()))?;

        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        let root_cert_path = dir.join(ROOT_CERT_FILE);
        let root_key_path = dir.join(ROOT_KEY_FILE);
        let meta_path = dir.join(CA_META_FILE);

        // 旧版本只有一张自签、带 NameConstraints 的 CA。Windows 不会把这种
        // 证书稳定地接受为 CurrentUser\Root 信任锚，因此升级时必须换成
        // “无约束根 CA + 受约束中间 CA”链。只在旧版四件套完整、且新根文件
        // 完全不存在时迁移；新链只生成了一半时仍然保守失败，避免覆盖未知状态。
        let legacy_single_ca = cert_path.exists()
            && key_path.exists()
            && !root_cert_path.exists()
            && !root_key_path.exists();
        let legacy_thumb = if legacy_single_ca {
            expiry_info(&cert_path).map(|(thumb, _)| thumb)
        } else {
            None
        };
        let legacy_backup = if legacy_single_ca {
            Some((
                std::fs::read(&cert_path)
                    .with_context(|| format!("读不了旧版 {}", cert_path.display()))?,
                std::fs::read(&key_path)
                    .with_context(|| format!("读不了旧版 {}", key_path.display()))?,
                std::fs::read(&meta_path).ok(),
            ))
        } else {
            None
        };
        if legacy_single_ca {
            crate::log::warn(&format!(
                "检测到旧版单 CA，正在迁移为根 CA + 受约束中间 CA：{}",
                dir.display()
            ));
            remove_ca_files(
                &cert_path,
                &key_path,
                &root_cert_path,
                &root_key_path,
                &meta_path,
            );
        }

        // 到期前自动轮换：清掉根、中间 CA 与元数据，随后走"创建新链"分支。
        if root_cert_path.exists() || cert_path.exists() {
            let info = expiry_info(if root_cert_path.exists() {
                &root_cert_path
            } else {
                &cert_path
            });
            if info.is_none() {
                crate::log::warn("无法读取 CA 有效期（Win32 证书 API 未返回结果），跳过到期检查。");
            }
            if let Some((thumb, days)) = info {
                if days <= RENEW_BEFORE_DAYS {
                    crate::log::warn(&format!(
                        "本机根 CA 有效期剩余 {days} 天（阈值 {RENEW_BEFORE_DAYS} 天），自动轮换：\
                         移除旧根证书并重新生成，需要重新信任一次。"
                    ));
                    if manage_trust {
                        remove_trust(&thumb);
                    }
                    let _ = std::fs::remove_file(&cert_path);
                    let _ = std::fs::remove_file(&key_path);
                    let _ = std::fs::remove_file(&root_cert_path);
                    let _ = std::fs::remove_file(&root_key_path);
                    let _ = std::fs::remove_file(&meta_path);
                }
            }
        }
        // Versions before 0.1.8 generated an ECDSA self-signed root. On
        // Windows that certificate can appear in ProtectedRoots while never
        // becoming a persistent CurrentUser\Root certificate. Rotate it
        // before the environment manager asks the user to trust it.
        if root_cert_path.exists() && !Self::root_uses_rsa(&root_cert_path) {
            crate::log::warn(
                "检测到旧版 ECDSA 根 CA；Windows 当前用户根存储无法稳定持久化它，\
                 正在轮换为 RSA 根 CA。",
            );
            if manage_trust {
                if let Some((thumb, _)) = expiry_info(&root_cert_path) {
                    remove_trust(&thumb);
                }
            }
            remove_ca_files(
                &cert_path,
                &key_path,
                &root_cert_path,
                &root_key_path,
                &meta_path,
            );
        }
        let complete = cert_path.exists()
            && key_path.exists()
            && root_cert_path.exists()
            && root_key_path.exists();
        let partial = cert_path.exists()
            || key_path.exists()
            || root_cert_path.exists()
            || root_key_path.exists();
        if partial && !complete {
            bail!(
                "{} 里的 CA 链文件不完整（需要 ca-cert.pem、ca-key.pem、root-cert.pem、root-key.pem）。\
                 请删除证书目录后重新启动。",
                dir.display()
            );
        }
        if complete {
            let ca_pem = std::fs::read_to_string(&cert_path)
                .with_context(|| format!("读不到 {}", cert_path.display()))?;
            let key_pem = std::fs::read_to_string(&key_path)
                .with_context(|| format!("读不到 {}", key_path.display()))?;

            // 元数据只是旁注；必须核对 Windows 实际执行的证书约束。
            let normalize = |hosts: &[String]| {
                let mut hosts: Vec<_> = hosts
                    .iter()
                    .map(|h| h.trim().to_ascii_lowercase())
                    .collect();
                hosts.sort();
                hosts.dedup();
                hosts
            };
            let actual = Self::permitted_dns_names(&cert_path)
                .context("已有 CA 缺少有效的 NameConstraints，请删除证书目录后重新生成并信任")?;
            if normalize(&actual) != normalize(permitted) {
                bail!("已存在的 CA 的实际授权域名与当前配置不一致。旧: {actual:?} 新: {permitted:?}；请删除 {} 后重新生成并信任", dir.display());
            }
            Self::validate_chain_paths(&cert_path, &root_cert_path)?;
            let der = crate::certinfo::read_ca_der(&cert_path).context("中间 CA 证书无法解析")?;

            // 私钥与证书必须是一对。rcgen 不校验这一点（见 `key_matches_cert` 的说明），
            // 不配对时程序能正常启动、签得出叶证书，但每个 MITM 握手都会被客户端拒绝——
            // 与其让用户对着 `MITM-HANDSHAKE-FAIL` 猜，不如在这里直接失败并说清怎么修。
            if Self::key_matches_cert_at(&cert_path, &key_path) == Some(false)
                || Self::key_matches_cert_at(&root_cert_path, &root_key_path) == Some(false)
            {
                bail!(
                    "{} 里的 CA 私钥与证书不配对（文件被改动或覆盖过？）。\
                     这样签出的叶证书会被所有客户端拒绝（表现为每处都 MITM-HANDSHAKE-FAIL）。\
                     请删除 {} 后重新启动（会生成新 CA，需要重新信任一次）",
                    dir.display(),
                    dir.display()
                );
            }

            let key = KeyPair::from_pem(&key_pem).context("CA 私钥无法解析")?;
            let issuer = Issuer::from_ca_cert_pem(&ca_pem, key).context("CA 证书无法解析")?;
            return Ok(Self {
                ca_pem,
                issuer,
                intermediate_der: CertificateDer::from(der),
                cache: Mutex::new(HashMap::new()),
            });
        }

        let generated = (|| -> Result<Self> {
            let ca_pem = Self::create(
                dir,
                permitted,
                &cert_path,
                &key_path,
                &root_cert_path,
                &root_key_path,
                &meta_path,
            )?;
            let key_pem = std::fs::read_to_string(&key_path)?;
            let key = KeyPair::from_pem(&key_pem)?;
            let issuer = Issuer::from_ca_cert_pem(&ca_pem, key)?;
            let intermediate_der = CertificateDer::from(
                crate::certinfo::read_ca_der(&cert_path).context("中间 CA 证书无法解析")?,
            );
            Ok(Self {
                ca_pem,
                issuer,
                intermediate_der,
                cache: Mutex::new(HashMap::new()),
            })
        })();
        match generated {
            Ok(ca) => {
                // Keep the old trust anchor until the replacement chain has
                // been generated and parsed successfully, avoiding a trust
                // gap during a successful upgrade.
                if manage_trust {
                    if let Some(thumb) = legacy_thumb.as_deref() {
                        remove_trust(thumb);
                    }
                }
                Ok(ca)
            }
            Err(err) => {
                if let Some((cert, key, meta)) = legacy_backup {
                    restore_legacy_files(dir, &cert, &key, meta.as_deref());
                }
                Err(err)
            }
        }
    }

    fn create(
        dir: &Path,
        permitted: &[String],
        cert_path: &Path,
        key_path: &Path,
        root_cert_path: &Path,
        root_key_path: &Path,
        meta_path: &Path,
    ) -> Result<String> {
        let mut root_params = CertificateParams::default();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "winget-accel local root CA");
        root_params
            .distinguished_name
            .push(DnType::OrganizationName, "winget-accel");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        root_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        set_validity(&mut root_params, CA_VALIDITY_DAYS);

        // Windows 当前用户 Root 对 ECDSA 自签根的持久化并不稳定：
        // 向导可能报告成功，但证书只进入 ProtectedRoots，重新打开 Root
        // 后没有可用的 Certificates 条目。使用 RSA 根兼容该存储路径；
        // 中间 CA 和叶证书仍沿用默认的 ECDSA，保持运行时性能。
        let root_key = crate::windowsrsa::generate_rsa_key_pair()?;
        let root_key_pem = root_key.serialize_pem();
        let root_cert = root_params
            .self_signed(&root_key)
            .context("自签根 CA 失败")?;
        let root_pem = root_cert.pem();
        let root_issuer =
            Issuer::from_ca_cert_pem(&root_pem, root_key).context("构造根 CA 签发者失败")?;

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

        let key = KeyPair::generate().context("生成中间 CA 私钥失败")?;
        let key_pem = key.serialize_pem();
        let cert = params
            .signed_by(&key, &root_issuer)
            .context("签发中间 CA 失败")?;
        let ca_pem = cert.pem();

        let write_result = (|| -> Result<()> {
            std::fs::write(root_cert_path, &root_pem)
                .with_context(|| format!("写不了 {}", root_cert_path.display()))?;
            std::fs::write(root_key_path, &root_key_pem)
                .with_context(|| format!("写不了 {}", root_key_path.display()))?;
            std::fs::write(cert_path, &ca_pem)
                .with_context(|| format!("写不了 {}", cert_path.display()))?;
            std::fs::write(key_path, &key_pem)
                .with_context(|| format!("写不了 {}", key_path.display()))?;
            // 记下授权域名，配置变化时能立刻发现
            std::fs::write(meta_path, serde_json::to_string(permitted)?)
                .with_context(|| format!("写不了 {}", meta_path.display()))?;
            Ok(())
        })();
        if let Err(error) = write_result {
            // This function is only called when no complete chain exists.
            // Remove every file written by this attempt so the next launch
            // can retry instead of being trapped by a misleading partial chain.
            remove_ca_files(
                cert_path,
                key_path,
                root_cert_path,
                root_key_path,
                meta_path,
            );
            return Err(error);
        }
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

    /// Windows 信任的无约束根 CA。Name Constraints 放在中间 CA，避免
    /// Windows 把带关键 Name Constraints 的自签根证书拒绝出 CurrentUser\Root。
    pub fn root_pem_path(dir: &Path) -> PathBuf {
        dir.join(ROOT_CERT_FILE)
    }

    /// Windows 当前用户 Root 需要能持久化该信任锚。
    ///
    /// 只检查 SubjectPublicKeyInfo 的算法，不按文件名或元数据猜测；
    /// 这样旧版 ECDSA 根会在启动时自动轮换，手工替换过的文件也不会
    /// 继续进入必然失败的导入流程。
    fn root_uses_rsa(path: &Path) -> bool {
        let Some(der) = crate::certinfo::read_ca_der(path) else {
            return false;
        };
        let Ok((_, cert)) = x509_parser::parse_x509_certificate(&der) else {
            return false;
        };
        cert.subject_pki.algorithm.oid() == &x509_parser::oid_registry::OID_PKCS1_RSAENCRYPTION
    }

    /// 校验现有中间 CA 与根 CA 的层级约束和签名关系，不修改磁盘或系统存储。
    ///
    /// doctor 使用同一套规则，避免“启动时会拒绝、doctor 却显示证书正常”的诊断分歧。
    pub fn validate_chain(dir: &Path) -> Result<()> {
        Self::validate_chain_paths(&dir.join(CA_CERT_FILE), &dir.join(ROOT_CERT_FILE))
    }

    fn validate_chain_paths(cert_path: &Path, root_cert_path: &Path) -> Result<()> {
        let der = crate::certinfo::read_ca_der(cert_path).context("中间 CA 证书无法解析")?;
        let (_, parsed) = x509_parser::parse_x509_certificate(&der)
            .map_err(|e| anyhow::anyhow!("中间 CA 证书无法解析: {e}"))?;
        let basic = parsed
            .basic_constraints()?
            .context("中间 CA 缺少 BasicConstraints")?;
        if !basic.value.ca || basic.value.path_len_constraint != Some(0) {
            bail!("中间 CA 必须禁止签发下级 CA（path_length = 0），请重新生成并信任");
        }

        let root_der =
            crate::certinfo::read_ca_der(root_cert_path).context("根 CA 证书无法解析")?;
        let (_, root_parsed) = x509_parser::parse_x509_certificate(&root_der)
            .map_err(|e| anyhow::anyhow!("根 CA 证书无法解析: {e}"))?;
        let root_basic = root_parsed
            .basic_constraints()?
            .context("根 CA 缺少 BasicConstraints")?;
        if !root_basic.value.ca || root_basic.value.path_len_constraint != Some(1) {
            bail!("根 CA 必须允许签发一个中间 CA（path_length = 1）");
        }
        parsed
            .verify_signature(Some(&root_parsed.tbs_certificate.subject_pki))
            .map_err(|e| anyhow::anyhow!("中间 CA 不是由当前根 CA 签发: {e}"))?;
        Ok(())
    }

    /// 从磁盘上的 CA 证书里读出**实际的** dNSName 授权列表（permitted subtrees）。
    ///
    /// 为什么读证书而不是读 `ca-meta.json`：
    /// - meta 是我们自己写的旁注，可能缺失（旧版本升级、手工删过）或与证书不同步；
    /// - 证书里的 `NameConstraints` 才是 **Windows 真正执行的那一份**。
    ///
    /// 返回 `None` 表示读不出来或证书里没有该扩展（例如文件损坏、被换成别的 CA）。
    pub fn permitted_dns_names(cert_pem: &Path) -> Option<Vec<String>> {
        let der = crate::certinfo::read_ca_der(cert_pem)?;
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).ok()?;
        let constraints = parsed.name_constraints().ok().flatten()?;
        let permitted = constraints.value.permitted_subtrees.as_ref()?;
        let mut names: Vec<String> = permitted
            .iter()
            .filter_map(|subtree| match &subtree.base {
                x509_parser::extensions::GeneralName::DNSName(name) => Some(name.to_string()),
                _ => None,
            })
            .collect();
        names.sort();
        Some(names)
    }

    /// 磁盘上的 CA 私钥与证书是不是**一对**。
    ///
    /// 为什么必须自己查：**rcgen 不校验这一点**。实测（2026-11-04）：把 `ca-key.pem`
    /// 换成另一把私钥后，`Issuer::from_ca_cert_pem` 仍返回 Ok，`build_leaf` 也照样"成功"——
    /// 只是签出来的叶证书用的是与证书不配对的密钥。后果是所有 MITM 握手都被客户端拒绝
    /// （日志里只有 `MITM-HANDSHAKE-FAIL`），而 `--doctor` 的 `ca` 一项却是全绿。
    ///
    /// 做法：直接比公钥字节（证书 SPKI 里的公钥 vs 私钥导出的公钥），不做签名运算。
    /// `None` 表示文件读不出/解析不了，与"确定不配对"区分开。
    pub fn key_matches_cert(dir: &Path) -> Option<bool> {
        Self::key_matches_cert_at(&dir.join(CA_CERT_FILE), &dir.join(CA_KEY_FILE))
    }

    /// 根 CA 私钥与根证书是不是一对。
    pub fn root_key_matches_cert(dir: &Path) -> Option<bool> {
        Self::key_matches_cert_at(&dir.join(ROOT_CERT_FILE), &dir.join(ROOT_KEY_FILE))
    }

    fn key_matches_cert_at(cert_path: &Path, key_path: &Path) -> Option<bool> {
        let der = crate::certinfo::read_ca_der(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path).ok()?;
        let key = KeyPair::from_pem(&key_pem).ok()?;
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).ok()?;
        // 注意两边的形态不同（实测）：
        // - `public_key().raw` 是整段 SubjectPublicKeyInfo 的 DER（含 AlgorithmIdentifier）
        // - `KeyPair::public_key_raw()` 是裸公钥（ECDSA 下是 0x04||X||Y，65 字节）
        // 所以要取 SPKI 里 BIT STRING 的内容来比，否则永远不相等。
        let cert_key: &[u8] = parsed.public_key().subject_public_key.as_ref();
        let signer_key: &[u8] = key.public_key_raw();
        Some(cert_key == signer_key)
    }

    /// 取（必要时生成）该 host 的服务端 TLS 配置。
    ///
    /// 加锁是必须的：生成与加载不是原子操作，并发首连同 host 会互相踩。
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let mut cache = self.cache.lock().expect("证书缓存锁中毒");
        if let Some(cfg) = cache.get(host) {
            return Ok(Arc::clone(cfg));
        }

        let (cert_der, key_der) = self.build_leaf(host)?;
        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der, self.intermediate_der.clone()], key_der)
            .context("构造 TLS 服务端配置失败")?;
        let cfg = Arc::new(cfg);
        cache.insert(host.to_string(), Arc::clone(&cfg));
        Ok(cfg)
    }

    /// 签发一张 host 对应的叶证书；抽出来便于单测检查 SAN/EKU。
    fn build_leaf(&self, host: &str) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
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
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        Ok((cert_der, key_der))
    }
}

/// 上游（加速器）证书校验用的客户端配置。
///
/// 用 webpki-roots 的静态根证书，避免读取系统存储（那需要额外依赖，
/// 且会让"信任谁"变得不可控）。ALPN 不发：只支持 HTTP/1.1。
///
/// **缓存一份**：这个配置原本在每次上游连接（含每次健康/测速探测）时重建，
/// 每次都要把 ~150 张根证书搬进新的 `RootCertStore`。配置本身不可变，
/// 用 `OnceLock` 复用即可，省掉的是每连接的分配与拷贝。
pub fn upstream_client_config() -> Arc<ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }))
}

/// 就地设置有效期，避免在签名里写出 `time::OffsetDateTime` 的路径
/// （rcgen 对 `time` 的再导出方式在不同版本间变过）。
/// 就地设置有效期。
///
/// 早先用自实现的 Howard Hinnant 公历换算（`civil_from_days`）算日期，
/// 还要 1 个单测护着——典型的手搓日期运算。rcgen 本身依赖 `time` crate，直接用它。
fn set_validity(params: &mut CertificateParams, days: i64) {
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(days);
}

/// 收紧证书目录权限：去掉继承，只保留当前用户与 SYSTEM。
///
/// CA 私钥是明文存放的，默认从父目录继承的 ACL 可能允许同机其他用户读取。
/// 失败不致命（最多保持原状），所以不中断启动——但**必须留下痕迹**：
/// 早先这里把 icacls 的退出码整个吞掉，于是"收紧失败"既没告警也没日志，
/// 而文档写的是"失败只记日志"。
///
/// 现在做三件事：跑 icacls、看退出码、再读回 ACL 确认没有宽泛的组（`Users`/`Everyone`）。
fn restrict_permissions(dir: &Path) {
    let user = std::env::var("USERNAME").unwrap_or_default();
    let mut cmd = std::process::Command::new("icacls");
    cmd.arg(dir).arg("/inheritance:r");
    if !user.is_empty() {
        cmd.arg("/grant:r").arg(format!("{user}:(OI)(CI)F"));
    }
    cmd.arg("/grant:r").arg("SYSTEM:(OI)(CI)F");
    let status = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match status {
        Ok(status) if status.success() => {}
        Ok(status) => crate::log::warn(&format!(
            "无法收紧证书目录权限（icacls 退出码 {}）：{} 下的 CA 私钥可能对本机其他用户可读。\
             建议手工执行：icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:(OI)(CI)F\" /grant:r \"SYSTEM:(OI)(CI)F\"",
            status.code().unwrap_or(-1),
            dir.display(),
            dir.display()
        )),
        Err(err) => crate::log::warn(&format!(
            "无法调用 icacls 收紧证书目录权限（{err}）：{} 下的 CA 私钥可能对本机其他用户可读",
            dir.display()
        )),
    }

    // 读回实际 ACL 再确认一次：icacls 返回 0 也可能因为继承/父目录策略而留下宽泛条目。
    if let Some(text) = read_acl(dir) {
        if acl_is_broad(&text) {
            crate::log::warn(&format!(
                "证书目录的 ACL 里仍有宽泛授权（Users/Everyone 之类）：{}。\
                 CA 私钥是明文存放的，建议手工收紧到当前用户与 SYSTEM",
                dir.display()
            ));
        }
    }
}

/// 读回目录的 ACL 文本（`icacls <dir>`）；失败返回 `None`。
fn read_acl(dir: &Path) -> Option<String> {
    let out = std::process::Command::new("icacls")
        .arg(dir)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

/// ACL 文本里是否有**宽泛**的授权（同机其他用户也能读）。
///
/// 判据用组名而不是权限字母：`icacls` 输出的身份名不随界面语言翻译
/// （实测中文 Windows 上仍打印 `NT AUTHORITY\SYSTEM`、`BUILTIN\Users`）。
/// 只看这几类"任何本机用户都算成员"的主体；`Administrators` 不在此列——
/// 管理员本来就能拿到机器上的一切。
fn acl_is_broad(text: &str) -> bool {
    const BROAD: [&str; 4] = [
        "BUILTIN\\Users",
        "Everyone",
        "NT AUTHORITY\\Authenticated Users",
        "NT AUTHORITY\\INTERACTIVE",
    ];
    BROAD.iter().any(|needle| text.contains(needle))
}

// ---------------------------------------------------------------- 自动轮换
//
// CA 有效期 1 年。到期后叶证书会验签失败，而 WinINet 报的是
// TRUST_E_CERT_SIGNATURE（0x96004）——完全指不到"证书过期"，用户无从下手。
// 所以到期前主动轮换：自动移除旧证书、删掉旧文件、重新生成。
// 唯一无法自动化的是导入时的确认框（Windows 装根证书必然交互）。

/// 提前多少天开始轮换。
///
/// 不写死成魔法数字：按有效期的 2% 推导并夹在 7–30 天之间。
/// 目的只是"避免今天能用、明天突然坏"，不需要精确值；
/// 用比例表达的好处是改了 `CA_VALIDITY_DAYS` 之后阈值仍然自动合理。
const RENEW_BEFORE_DAYS: i32 = {
    let derived = (CA_VALIDITY_DAYS / 50) as i32; // 2%
    if derived < 7 {
        7
    } else if derived > 30 {
        30
    } else {
        derived
    }
};

/// 读证书指纹与剩余天数（走 Win32 API，不依赖 PowerShell）。
fn expiry_info(ca_pem: &Path) -> Option<(String, i32)> {
    crate::certinfo::info(ca_pem).map(|info| (info.thumbprint, info.days_left as i32))
}

fn remove_ca_files(
    cert_path: &Path,
    key_path: &Path,
    root_cert_path: &Path,
    root_key_path: &Path,
    meta_path: &Path,
) {
    for path in [
        cert_path,
        key_path,
        root_cert_path,
        root_key_path,
        meta_path,
    ] {
        let _ = std::fs::remove_file(path);
    }
}

fn restore_legacy_files(dir: &Path, cert: &[u8], key: &[u8], meta: Option<&[u8]>) {
    let cert_path = dir.join(CA_CERT_FILE);
    let key_path = dir.join(CA_KEY_FILE);
    let root_cert_path = dir.join(ROOT_CERT_FILE);
    let root_key_path = dir.join(ROOT_KEY_FILE);
    let meta_path = dir.join(CA_META_FILE);
    let _ = std::fs::remove_file(root_cert_path);
    let _ = std::fs::remove_file(root_key_path);
    if let Err(err) = std::fs::write(&cert_path, cert) {
        crate::log::warn(&format!(
            "旧版 CA 证书恢复失败（{}）：{err}",
            cert_path.display()
        ));
    }
    if let Err(err) = std::fs::write(&key_path, key) {
        crate::log::warn(&format!(
            "旧版 CA 私钥恢复失败（{}）：{err}",
            key_path.display()
        ));
    }
    match meta {
        Some(meta) => {
            if let Err(err) = std::fs::write(&meta_path, meta) {
                crate::log::warn(&format!(
                    "旧版 CA 元数据恢复失败（{}）：{err}",
                    meta_path.display()
                ));
            }
        }
        None => {
            let _ = std::fs::remove_file(meta_path);
        }
    }
}

/// 从用户根存储移除指定指纹的证书。
///
/// 走 `certutil -user -delstore`；首次安装由 Windows 原生证书导入向导完成。
/// 删除失败时只记日志，
/// 不换别的路径（写注册表属于实现细节，不该作为常规手段）。
fn remove_trusted_ca(thumbprint: &str) {
    let ok = std::process::Command::new("certutil")
        .args(["-user", "-delstore", "Root", thumbprint])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        crate::log::warn(
            "移除旧 CA 失败（certutil -delstore 返回非零）。\
             若该环境不支持，请用 certmgr.msc 手工删除后再启动。",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_only_changes_trust_when_environment_management_is_enabled() {
        for manage_trust in [false, true] {
            let dir = std::env::temp_dir().join(format!(
                "wg-ca-renew-{}-{}",
                std::process::id(),
                manage_trust
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let mut params = CertificateParams::default();
            params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(10);
            params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
            let key = KeyPair::generate().unwrap();
            let expired = params.self_signed(&key).unwrap().pem();
            std::fs::write(dir.join(CA_CERT_FILE), &expired).unwrap();
            std::fs::write(dir.join(CA_KEY_FILE), key.serialize_pem()).unwrap();
            let removed = std::cell::Cell::new(0);
            let ca = CertAuthority::load_with_remover(
                &dir,
                &["github.com".into()],
                manage_trust,
                |_| removed.set(removed.get() + 1),
            )
            .unwrap();
            assert_ne!(ca.ca_pem(), expired);
            assert_eq!(removed.get(), usize::from(manage_trust));
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn migrates_legacy_single_ca_to_two_level_chain() {
        let dir = std::env::temp_dir().join(format!("wg-ca-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "legacy winget-accel CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName("github.com".to_string())],
            excluded_subtrees: Vec::new(),
        });
        let key = KeyPair::generate().unwrap();
        let legacy = params.self_signed(&key).unwrap().pem();
        std::fs::write(dir.join(CA_CERT_FILE), &legacy).unwrap();
        std::fs::write(dir.join(CA_KEY_FILE), key.serialize_pem()).unwrap();
        std::fs::write(dir.join(CA_META_FILE), r#"["github.com"]"#).unwrap();

        let removed = std::cell::Cell::new(0);
        let ca = CertAuthority::load_with_remover(&dir, &["github.com".to_string()], true, |_| {
            removed.set(removed.get() + 1)
        })
        .unwrap();

        assert_eq!(removed.get(), 1, "迁移时应移除旧版信任锚");
        assert_ne!(ca.ca_pem(), legacy);
        assert!(dir.join(CA_CERT_FILE).is_file());
        assert!(dir.join(CA_KEY_FILE).is_file());
        assert!(dir.join(ROOT_CERT_FILE).is_file());
        assert!(dir.join(ROOT_KEY_FILE).is_file());
        assert!(CertAuthority::permitted_dns_names(&dir.join(CA_CERT_FILE)).is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_chain_creation_does_not_leave_partial_files() {
        let dir = std::env::temp_dir().join(format!("wg-ca-partial-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(CA_META_FILE)).unwrap();

        let error = CertAuthority::load_or_create(&dir, &["github.com".to_string()], false)
            .err()
            .expect("元数据路径是目录时创建必须失败");
        assert!(error.to_string().contains("写不了"), "实际错误: {error}");
        for file in [CA_CERT_FILE, CA_KEY_FILE, ROOT_CERT_FILE, ROOT_KEY_FILE] {
            assert!(
                !dir.join(file).exists(),
                "失败创建不应留下半套证书文件: {file}"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reuses_existing_ca_across_loads() {
        let dir = std::env::temp_dir().join(format!("wgaccel-ca-{}", std::process::id()));
        let hosts = vec!["github.com".to_string()];
        let first = CertAuthority::load_or_create(&dir, &hosts, false).unwrap();
        let second = CertAuthority::load_or_create(&dir, &hosts, false).unwrap();
        assert_eq!(first.ca_pem(), second.ca_pem());
        let equivalent = vec![" GITHUB.COM ".to_string(), "github.com".to_string()];
        let normalized = CertAuthority::load_or_create(&dir, &equivalent, false).unwrap();
        assert_eq!(first.ca_pem(), normalized.ca_pem());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_ca_when_permitted_hosts_change() {
        let dir = std::env::temp_dir().join(format!("wgaccel-ca-meta-{}", std::process::id()));
        CertAuthority::load_or_create(&dir, &["github.com".to_string()], false).unwrap();
        // 即使旁注伪装成新白名单，也必须依据真实证书拒绝启动。
        std::fs::write(dir.join(CA_META_FILE), r#"["example.com"]"#).unwrap();
        let err = CertAuthority::load_or_create(&dir, &["example.com".to_string()], false)
            .err()
            .expect("应当报错");
        assert!(err.to_string().contains("不一致"), "实际错误: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 缺失旁注时，实际证书约束匹配仍能加载。
    #[test]
    fn matching_certificate_loads_without_meta() {
        let dir = std::env::temp_dir().join(format!("wgaccel-ca-nometa-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        CertAuthority::load_or_create(&dir, &["github.com".to_string()], false).unwrap();
        std::fs::remove_file(dir.join(CA_META_FILE)).expect("应能删掉 meta");

        let ca = CertAuthority::load_or_create(&dir, &["github.com".to_string()], false);
        assert!(ca.is_ok(), "缺 meta 不该拒绝启动");
        assert_eq!(ca.unwrap().ca_pem(), {
            CertAuthority::load_or_create(&dir, &["github.com".to_string()], false)
                .unwrap()
                .ca_pem()
                .to_string()
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leaf_config_is_cached_per_host() {
        let dir = std::env::temp_dir().join(format!("wgaccel-ca-cache-{}", std::process::id()));
        let hosts = vec!["github.com".to_string()];
        let ca = CertAuthority::load_or_create(&dir, &hosts, false).unwrap();
        let first = ca.server_config("github.com").unwrap();
        let second = ca.server_config("github.com").unwrap();
        assert!(Arc::ptr_eq(&first, &second), "同 host 应复用同一 TLS 配置");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_first_use_reuses_one_leaf_config() {
        let dir =
            std::env::temp_dir().join(format!("wgaccel-ca-concurrent-{}", std::process::id()));
        let hosts = vec!["github.com".to_string()];
        let ca = Arc::new(CertAuthority::load_or_create(&dir, &hosts, false).unwrap());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let ca = Arc::clone(&ca);
            handles.push(std::thread::spawn(move || {
                ca.server_config("github.com").unwrap()
            }));
        }
        let configs: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        for cfg in &configs {
            assert!(Arc::ptr_eq(&configs[0], cfg), "并发首连应只生成一份配置");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn leaf_certificate_has_exact_san_and_server_auth() {
        use x509_parser::extensions::GeneralName;
        let dir = std::env::temp_dir().join(format!("wgaccel-ca-leaf-{}", std::process::id()));
        let hosts = vec!["github.com".to_string()];
        let ca = CertAuthority::load_or_create(&dir, &hosts, false).unwrap();
        let (cert, _) = ca.build_leaf("github.com").unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();

        let san = parsed.subject_alternative_name().unwrap().unwrap();
        let mut names = Vec::new();
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                names.push(dns.to_string());
            }
        }
        assert_eq!(names, vec!["github.com".to_string()]);

        let eku = parsed.extended_key_usage().unwrap().unwrap();
        assert!(eku.value.server_auth, "叶证书必须带 serverAuth EKU");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 私钥与证书是否配对：**rcgen 不校验**，所以必须自己判。
    ///
    /// 实测（2026-11-04）：换一把私钥后 `Issuer::from_ca_cert_pem` 仍 Ok、
    /// `build_leaf` 也"成功"，但签出的叶证书会被客户端拒绝——而 doctor 的
    /// 信任/有效期/约束检查全都正常。这个用例把"能判出来"钉住。
    #[test]
    fn detects_mismatched_key_pair() {
        let dir = std::env::temp_dir().join(format!("wgaccel-ca-kp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        CertAuthority::load_or_create(&dir, &["github.com".to_string()], false).unwrap();

        assert_eq!(
            CertAuthority::key_matches_cert(&dir),
            Some(true),
            "刚生成的 CA 私钥与证书必须配对"
        );

        // 换成另一把私钥
        let other = KeyPair::generate().unwrap();
        std::fs::write(dir.join(CA_KEY_FILE), other.serialize_pem()).unwrap();
        assert_eq!(
            CertAuthority::key_matches_cert(&dir),
            Some(false),
            "换过私钥后必须判出不配对"
        );

        // 换了私钥就不该还能启动：与其让用户对着 MITM-HANDSHAKE-FAIL 猜，不如启动即失败
        let err = CertAuthority::load_or_create(&dir, &["github.com".to_string()], false)
            .err()
            .expect("不配对时必须拒绝启动");
        assert!(err.to_string().contains("不配对"), "实际错误: {err}");

        // 文件缺失 → None（与"确定不配对"区分）
        let empty = std::env::temp_dir().join(format!("wgaccel-ca-kp-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&empty);
        assert_eq!(CertAuthority::key_matches_cert(&empty), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_mismatched_root_key_pair() {
        let dir = std::env::temp_dir().join(format!("wgaccel-ca-root-kp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        CertAuthority::load_or_create(&dir, &["github.com".to_string()], false).unwrap();
        assert_eq!(CertAuthority::root_key_matches_cert(&dir), Some(true));

        let other = KeyPair::generate().unwrap();
        std::fs::write(dir.join(ROOT_KEY_FILE), other.serialize_pem()).unwrap();
        assert_eq!(CertAuthority::root_key_matches_cert(&dir), Some(false));

        let err = CertAuthority::load_or_create(&dir, &["github.com".to_string()], false)
            .err()
            .expect("根 CA 私钥不配对时必须拒绝启动");
        assert!(err.to_string().contains("不配对"), "实际错误: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `doctor` 用它核对"这张 CA 到底能签哪些域"——读证书本身，而不是 meta 旁注。
    #[test]
    fn permitted_dns_names_reads_the_certificate_itself() {
        let dir = std::env::temp_dir().join(format!("wgaccel-ca-nc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hosts = vec![
            "github.com".to_string(),
            "objects.githubusercontent.com".to_string(),
            "codeload.github.com".to_string(),
            "release-assets.githubusercontent.com".to_string(),
        ];
        CertAuthority::load_or_create(&dir, &hosts, false).unwrap();

        let mut got = CertAuthority::permitted_dns_names(&CertAuthority::ca_pem_path(&dir))
            .expect("应能读出");
        got.sort();
        let mut want = hosts.clone();
        want.sort();
        assert_eq!(got, want, "证书里的 dNSName 约束应等于生成时的白名单");

        // 删掉 meta 也不影响：读的是证书
        let _ = std::fs::remove_file(dir.join(CA_META_FILE));
        let after = CertAuthority::permitted_dns_names(&CertAuthority::ca_pem_path(&dir));
        assert_eq!(after.expect("删 meta 后仍应读得出"), want);

        // 文件不存在 → None（doctor 会据此报"读不出 NameConstraints"）
        assert!(CertAuthority::permitted_dns_names(&dir.join("nope.pem")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ca_has_basic_constraints_and_authorized_name_constraints() {
        use x509_parser::extensions::GeneralName;
        let dir =
            std::env::temp_dir().join(format!("wgaccel-ca-constraints-{}", std::process::id()));
        let hosts = vec![
            "github.com".to_string(),
            "objects.githubusercontent.com".to_string(),
            "codeload.github.com".to_string(),
            "release-assets.githubusercontent.com".to_string(),
        ];
        let ca = CertAuthority::load_or_create(&dir, &hosts, false).unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(ca.ca_pem().as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();

        let bc = cert.basic_constraints().unwrap().unwrap();
        assert!(bc.value.ca);
        assert_eq!(bc.value.path_len_constraint, Some(0));

        let nc = cert.name_constraints().unwrap().unwrap();
        let permitted = nc.value.permitted_subtrees.as_ref().unwrap();
        let mut names: Vec<String> = permitted
            .iter()
            .filter_map(|subtree| match &subtree.base {
                GeneralName::DNSName(name) => Some((*name).to_string()),
                _ => None,
            })
            .collect();
        names.sort();
        let mut expected = hosts.clone();
        expected.sort();
        assert_eq!(names, expected);
        assert!(nc
            .value
            .excluded_subtrees
            .as_ref()
            .map(|v| v.is_empty())
            .unwrap_or(true));

        let root_der = crate::certinfo::read_ca_der(&CertAuthority::root_pem_path(&dir)).unwrap();
        let (_, root) = x509_parser::parse_x509_certificate(&root_der).unwrap();
        let root_bc = root.basic_constraints().unwrap().unwrap();
        assert!(root_bc.value.ca);
        assert_eq!(root_bc.value.path_len_constraint, Some(1));
        assert!(
            root.name_constraints().unwrap().is_none(),
            "Windows 信任锚不应携带 NameConstraints"
        );
        assert!(CertAuthority::validate_chain(&dir).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `restrict_permissions` 之后要能判断"这个 ACL 是否还对其他本机用户开放"。
    ///
    /// 判据用身份名（`icacls` 不翻译这些名字，实测中文 Windows 上仍打印
    /// `NT AUTHORITY\SYSTEM`），而不是权限字母。
    #[test]
    fn broad_acl_detection_matches_real_icacls_output() {
        // 真实输出（本机收紧成功后的样子）：只有 SYSTEM 与当前用户
        let tightened = "\
C:\\tmp\\wg-acl-certs NT AUTHORITY\\SYSTEM:(OI)(CI)(F)
                    DESKTOP-4EGASL0\\lijianhua02:(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
";
        assert!(
            !acl_is_broad(tightened),
            "只授权 SYSTEM 与本机用户时不该报警"
        );

        // 未收紧（从父目录继承了 Users）——这是要抓的情形
        let broad = "\
C:\\tmp\\certs BUILTIN\\Users:(I)(RX)
            NT AUTHORITY\\SYSTEM:(OI)(CI)(F)
            DESKTOP-4EGASL0\\lijianhua02:(OI)(CI)(F)
";
        assert!(acl_is_broad(broad), "继承来的 BUILTIN\\Users 必须被识别");

        // 其它几种"任何本机用户都在内"的主体
        for text in [
            "C:\\x Everyone:(OI)(CI)(F)",
            "C:\\x NT AUTHORITY\\Authenticated Users:(I)(RX)",
            "C:\\x NT AUTHORITY\\INTERACTIVE:(I)(RX)",
        ] {
            assert!(acl_is_broad(text), "应识别: {text}");
        }

        // 管理员组不算"宽泛"：管理员本来就能拿到机器上的一切
        assert!(!acl_is_broad("C:\\x BUILTIN\\Administrators:(OI)(CI)(F)"));
    }
}
