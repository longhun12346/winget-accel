//! 用 Win32 证书 API 读取本机 CA 的信息与信任状态。
//!
//! 为什么不用 PowerShell：原先靠 `powershell.exe` + `Get-PfxCertificate` 取指纹与有效期，
//! 实测在 `-NonInteractive` 下会静默不返回结果，导致"到期自动轮换"从未触发过。
//! 而且 PowerShell 可能被组策略禁用，多一个不必要的隐性依赖。
//!
//! 这里全部用 `windows-sys` 提供的 Win32 API，不手写 crypto、不解析 ASN.1：
//! - 从 PEM 取 DER：`rustls-pemfile`（已是直接依赖）
//! - 建证书上下文：`CertCreateCertificateContext`
//! - 指纹 / 有效期：`CertGetCertificateContextProperty`（SHA-1 指纹、NotAfter FILETIME）
//! - 是否受信任：枚举 `CurrentUser\Root` 逐张比较编码字节（无需哈希，避免"同名不同证书"误判）

use std::io::BufReader;
use std::path::Path;

use windows_sys::Win32::Security::Cryptography as C;




pub struct CertInfo {
    /// 大写十六进制 SHA-1，与 Windows 里显示的"指纹"一致。
    pub thumbprint: String,
    /// 距到期还有多少天（已过期则为负）。
    pub days_left: i64,
}

/// 读 PEM 里的第一张证书，返回 DER。
pub fn read_ca_der(pem: &Path) -> Option<Vec<u8>> {
    let data = std::fs::read(pem).ok()?;
    let mut reader = BufReader::new(&data[..]);
    let first = rustls_pemfile::certs(&mut reader).next()?.ok()?;
    Some(first.as_ref().to_vec())
}

/// 从 PEM 读证书信息；失败返回 None（调用方应打印告警，不要静默）。
///
/// 有效期用 `x509-parser` 从 DER 解析：
/// windows-sys 0.60 **没有导出** `CERT_NOT_AFTER_FILETIME_PROP_ID`
/// （127 实际是 `CERT_NOT_BEFORE_ENHKEY_USAGE_PROP_ID`），
/// 此前按"官方值 127"补常量是错的，导致读取永远失败、到期轮换从未生效。
/// 指纹仍走 Win32（`CERT_SHA1_HASH_PROP_ID` 是真实存在的常量）。
pub fn info(pem: &Path) -> Option<CertInfo> {
    let der = read_ca_der(pem)?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).ok()?;
    let not_after = parsed.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let ctx = create_context(&der)?;
    let thumbprint = property_bytes(ctx, C::CERT_SHA1_HASH_PROP_ID)
        .map(|b| b.iter().map(|x| format!("{x:02X}")).collect::<String>());
    unsafe { C::CertFreeCertificateContext(ctx) };

    Some(CertInfo {
        thumbprint: thumbprint?,
        days_left: (not_after - now) / 86_400,
    })
}
/// 这张证书是否已在「当前用户受信任的根」里。
///
/// 按**编码字节**逐一比较：不能按 Subject 比（同名不同证书合法且常见，
/// 踩过——旧 CA 还在存储里、Subject 相同，导致误判"已信任"、
/// 跳过导入，客户端随后报 TRUST_E_CERT_SIGNATURE / 0x80096004）。
pub fn is_trusted(der: &[u8]) -> bool {
    unsafe {
        let store = C::CertOpenStore(
            C::CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            C::CERT_SYSTEM_STORE_CURRENT_USER,
            wide("ROOT").as_ptr() as *const core::ffi::c_void,
        );
        if store.is_null() {
            return false;
        }
        let mut cursor: *const C::CERT_CONTEXT = std::ptr::null();
        let mut found = false;
        loop {
            cursor = C::CertEnumCertificatesInStore(store, cursor);
            if cursor.is_null() {
                break;
            }
            let ctx = &*cursor;
            if ctx.cbCertEncoded as usize == der.len() && !ctx.pbCertEncoded.is_null() {
                let encoded = std::slice::from_raw_parts(ctx.pbCertEncoded, der.len());
                if encoded == der {
                    found = true;
                    break;
                }
            }
        }
        C::CertCloseStore(store, 0);
        found
    }
}

fn create_context(der: &[u8]) -> Option<*const C::CERT_CONTEXT> {
    unsafe {
        let ctx = C::CertCreateCertificateContext(
            C::X509_ASN_ENCODING | C::PKCS_7_ASN_ENCODING,
            der.as_ptr(),
            der.len() as u32,
        );
        if ctx.is_null() {
            None
        } else {
            Some(ctx)
        }
    }
}

/// 读某个证书属性的原始字节（先问长度再取值）。
fn property_bytes(ctx: *const C::CERT_CONTEXT, prop: u32) -> Option<Vec<u8>> {
    unsafe {
        let mut len: u32 = 0;
        if C::CertGetCertificateContextProperty(ctx, prop, std::ptr::null_mut(), &mut len) == 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        if C::CertGetCertificateContextProperty(
            ctx,
            prop,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut len,
        ) == 0
        {
            return None;
        }
        buf.truncate(len as usize);
        Some(buf)
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

// ------------------------------------------------------------ 移除本工具证书
//
// 供 `--remove-ca` 使用。不依赖 certs 目录是否还在：
// 直接枚举「当前用户受信任的根」，按 Subject 认出本工具的 CA 并删除。
//
// 删除走注册表项而不是 `certutil -delstore` / `CertDeleteCertificateFromStore`：
// 实测前者在部分机器返回 ERROR_NOT_SUPPORTED（后者是同一底层操作，风险相同），
// 而删注册表项有效。

/// 本工具 CA 的 Subject 关键字。
const OUR_CA_SUBJECT: &str = "winget-accel local CA";

/// 移除所有属于本工具的受信任根证书，返回（成功数, 失败数）。
///
/// **只用 `certutil -user -delstore`**，与安装（`certutil -user -addstore`）完全对称。
/// 不写注册表：失败就如实报错，由调用方提示用户手工处理，
/// 而不是偷偷换一条未文档化的路径把问题掩盖掉。
pub fn remove_our_ca() -> (usize, usize) {
    let mut removed = 0;
    let mut failed = 0usize;
    unsafe {
        let store = C::CertOpenStore(
            C::CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            C::CERT_SYSTEM_STORE_CURRENT_USER,
            wide("ROOT").as_ptr() as *const core::ffi::c_void,
        );
        if store.is_null() {
            return (0, 0);
        }

        // 先收集指纹（不能在枚举过程中删，会让枚举游标失效）
        let mut thumbprints: Vec<String> = Vec::new();
        let mut cursor: *const C::CERT_CONTEXT = std::ptr::null();
        loop {
            cursor = C::CertEnumCertificatesInStore(store, cursor);
            if cursor.is_null() {
                break;
            }
            if let Some(subject) = subject_of(cursor) {
                if subject.contains(OUR_CA_SUBJECT) {
                    if let Some(hash) = property_bytes(cursor, C::CERT_SHA1_HASH_PROP_ID) {
                        thumbprints.push(hash.iter().map(|b| format!("{b:02X}")).collect());
                    }
                }
            }
        }
        C::CertCloseStore(store, 0);

        for thumbprint in thumbprints {
            let ok = std::process::Command::new("certutil")
                .args(["-user", "-delstore", "Root", &thumbprint])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                removed += 1;
            } else {
                failed += 1;
            }
        }
    }
    (removed, failed)
}

/// 取证书的简单显示名（通常是 Subject）。
fn subject_of(ctx: *const C::CERT_CONTEXT) -> Option<String> {
    unsafe {
        let needed = C::CertGetNameStringW(
            ctx,
            C::CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
        );
        if needed <= 1 {
            return None;
        }
        let mut buf = vec![0u16; needed as usize];
        let written = C::CertGetNameStringW(
            ctx,
            C::CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            std::ptr::null(),
            buf.as_mut_ptr(),
            needed,
        );
        if written <= 1 {
            return None;
        }
        buf.truncate((written - 1) as usize);
        Some(String::from_utf16_lossy(&buf))
    }
}





