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

use std::io::{self, BufReader};
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
/// 这是证书存储查询，不代表完整的客户端 TLS 证书链校验。
/// 读取失败必须返回错误，不能当成「未找到」。
///
/// 按**编码字节**逐一比较：不能按 Subject 比（同名不同证书合法且常见，
/// 踩过——旧 CA 还在存储里、Subject 相同，导致误判"已信任"、
/// 跳过导入，客户端随后报 TRUST_E_CERT_SIGNATURE / 0x80096004）。
pub fn is_trusted(der: &[u8]) -> io::Result<bool> {
    let store = open_user_store("ROOT")?;
    unsafe {
        let found = store_contains(store, der);
        C::CertCloseStore(store, 0);
        found
    }
}

/// Diagnostics must neither request write access nor create missing stores.
fn open_user_store(name: &str) -> io::Result<C::HCERTSTORE> {
    let store = unsafe {
        C::CertOpenStore(
            C::CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            C::CERT_SYSTEM_STORE_CURRENT_USER
                | C::CERT_STORE_READONLY_FLAG
                | C::CERT_STORE_OPEN_EXISTING_FLAG,
            wide(name).as_ptr() as *const core::ffi::c_void,
        )
    };
    if store.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(store)
    }
}

/// Open the current user's root store with write access for the Windows
/// certificate import wizard.
///
/// Diagnostics use [`open_user_store`] with read-only and existing-store flags.
/// Import is intentionally separate so a read-only doctor check can never
/// create or mutate a certificate store.
pub fn open_user_root_for_import() -> io::Result<C::HCERTSTORE> {
    let store = unsafe {
        C::CertOpenStore(
            // The logical CurrentUser\Root store is a protected collection.
            // Importing into that collection can update ProtectedRoots while
            // dropping the certificate from its writable physical store.
            // CryptUIWizImport is reliable when it receives the user's
            // physical default store directly.
            C::CERT_STORE_PROV_PHYSICAL_W,
            0,
            0,
            C::CERT_SYSTEM_STORE_CURRENT_USER
                | C::CERT_STORE_OPEN_EXISTING_FLAG
                | C::CERT_STORE_SET_LOCALIZED_NAME_FLAG,
            wide(r"Root\.Default").as_ptr() as *const core::ffi::c_void,
        )
    };
    if store.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(store)
    }
}

/// Close a store opened by [`open_user_root_for_import`].
///
/// The import wizard is synchronous and does not retain the handle after it
/// returns, so closing it here is sufficient.
pub fn close_import_store(store: C::HCERTSTORE) {
    unsafe {
        C::CertCloseStore(store, 0);
    }
}

fn enumeration_end(error: io::Error) -> io::Result<()> {
    if error.raw_os_error().map(|code| code as u32)
        == Some(windows_sys::Win32::Foundation::CRYPT_E_NOT_FOUND as u32)
    {
        Ok(())
    } else {
        Err(error)
    }
}

/// Borrow a store; the caller retains responsibility for closing it.
fn store_contains(store: C::HCERTSTORE, der: &[u8]) -> io::Result<bool> {
    unsafe {
        let mut cursor: *const C::CERT_CONTEXT = std::ptr::null();
        loop {
            cursor = C::CertEnumCertificatesInStore(store, cursor);
            if cursor.is_null() {
                return enumeration_end(io::Error::last_os_error()).map(|()| false);
            }
            let ctx = &*cursor;
            if ctx.cbCertEncoded as usize == der.len() && !ctx.pbCertEncoded.is_null() {
                let encoded = std::slice::from_raw_parts(ctx.pbCertEncoded, der.len());
                if encoded == der {
                    // Enum frees the preceding context only on its next call.
                    // Early return must release this final reference explicitly.
                    C::CertFreeCertificateContext(cursor);
                    return Ok(true);
                }
            }
        }
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
// 删除走 `certutil -user -delstore`；首次安装由 Windows 原生证书导入向导完成。
// 实测部分环境会返回 ERROR_NOT_SUPPORTED（0x80070032）；此时**不偷偷改走写注册表**
// 这种未文档化的路径，而是如实报错并给出手工方式（certmgr.msc）。
// 早期版本的注释曾写成"已改用删注册表项"，与实现相反，已按实际行为改正。

/// 本工具 CA 的 Subject 关键字。
///
/// 新版两级链会把根证书和中间证书分别放进用户存储/服务端链；
/// 旧版只有 `winget-accel local CA`。两者都必须被 `--remove-ca`
/// 和 doctor 的残留检查识别。
const OUR_CA_SUBJECTS: [&str; 2] = ["winget-accel local CA", "winget-accel local root CA"];

fn is_our_ca_subject(subject: &str) -> bool {
    OUR_CA_SUBJECTS
        .iter()
        .any(|needle| subject.contains(needle))
}

/// 列出「当前用户受信任的根」里所有属于本工具的 CA 指纹（SHA-1 大写十六进制）。
///
/// 抽出来是为了让 `doctor` 也能查"残留了几张"——只枚举、不修改任何东西。
pub fn our_ca_thumbprints() -> io::Result<Vec<String>> {
    let mut thumbprints: Vec<String> = Vec::new();
    let store = open_user_store("ROOT")?;
    unsafe {
        let mut cursor: *const C::CERT_CONTEXT = std::ptr::null();
        loop {
            cursor = C::CertEnumCertificatesInStore(store, cursor);
            if cursor.is_null() {
                // Capture GetLastError before closing the store.
                let result = enumeration_end(io::Error::last_os_error()).map(|()| thumbprints);
                C::CertCloseStore(store, 0);
                return result;
            }
            if let Some(subject) = subject_of(cursor) {
                if is_our_ca_subject(&subject) {
                    if let Some(hash) = property_bytes(cursor, C::CERT_SHA1_HASH_PROP_ID) {
                        thumbprints.push(hash.iter().map(|b| format!("{b:02X}")).collect());
                    }
                }
            }
        }
    }
}

/// 移除所有属于本工具的受信任根证书，返回（成功数, 失败数）。
///
/// **只用 `certutil -user -delstore`**，不写注册表。
/// 删除失败就如实报错，由调用方提示用户手工处理，
/// 而不是偷偷换一条未文档化的路径把问题掩盖掉。
pub fn remove_our_ca() -> io::Result<(usize, usize)> {
    let mut removed = 0;
    let mut failed = 0usize;
    // 先收集指纹（不能在枚举过程中删，会让枚举游标失效）
    let thumbprints = our_ca_thumbprints()?;
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
    Ok((removed, failed))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_both_legacy_and_two_level_ca_subjects() {
        assert!(is_our_ca_subject("CN=winget-accel local CA"));
        assert!(is_our_ca_subject("CN=winget-accel local root CA"));
        assert!(!is_our_ca_subject("CN=some other local CA"));
    }

    #[test]
    fn certificate_lookup_releases_contexts_on_match_and_miss() {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
        let der = certificate.cert.der().as_ref();
        for matched in [false, true] {
            // A private memory store exercises native ownership without adding
            // anything to the user's trusted roots.
            unsafe {
                let store = C::CertOpenStore(
                    C::CERT_STORE_PROV_MEMORY,
                    0,
                    0,
                    C::CERT_STORE_CREATE_NEW_FLAG,
                    std::ptr::null(),
                );
                assert!(!store.is_null());
                assert_ne!(
                    C::CertAddEncodedCertificateToStore(
                        store,
                        C::X509_ASN_ENCODING,
                        der.as_ptr(),
                        der.len() as u32,
                        C::CERT_STORE_ADD_NEW,
                        std::ptr::null_mut(),
                    ),
                    0
                );
                let found = store_contains(store, if matched { der } else { &[] });
                let closed = C::CertCloseStore(store, C::CERT_CLOSE_STORE_CHECK_FLAG);
                assert_eq!(found.unwrap(), matched);
                assert_ne!(
                    closed, 0,
                    "certificate lookup leaked an enumeration context"
                );
            }
        }
    }

    #[test]
    fn certificate_store_errors_are_not_reported_as_absence() {
        use windows_sys::Win32::Foundation::{CRYPT_E_NOT_FOUND, ERROR_ACCESS_DENIED};
        assert!(enumeration_end(io::Error::from_raw_os_error(CRYPT_E_NOT_FOUND)).is_ok());
        let error =
            enumeration_end(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32)).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));

        // OPEN_EXISTING + READONLY must fail, without creating a user store.
        let missing = format!(
            "winget-accel-missing-store-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        );
        assert!(open_user_store(&missing).is_err());
        assert!(open_user_store(&missing).is_err());
    }
}
