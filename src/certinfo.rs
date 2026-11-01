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

/// 1601-01-01 到 1970-01-01 的秒数差（FILETIME 纪元换算用）。
const FILETIME_UNIX_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;

/// `CERT_NOT_AFTER_FILETIME_PROP_ID`。
///
/// windows-sys 0.60 没有导出这个常量（只导出了 NOT_BEFORE=126；
/// 值 127 被生成为 `CERT_NOT_BEFORE_ENHKEY_USAGE_PROP_ID`，属 SDK 里的别名冲突）。
/// 官方值是 127，见 wincrypt.h。
const CERT_NOT_AFTER_FILETIME_PROP_ID: u32 = 127;

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
pub fn info(pem: &Path) -> Option<CertInfo> {
    let der = read_ca_der(pem)?;
    let ctx = create_context(&der)?;
    let result = (|| {
        let thumbprint = property_bytes(ctx, C::CERT_SHA1_HASH_PROP_ID)
            .map(|b| b.iter().map(|x| format!("{x:02X}")).collect::<String>())?;
        let not_after = property_bytes(ctx, CERT_NOT_AFTER_FILETIME_PROP_ID)?;
        if not_after.len() < 8 {
            return None;
        }
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&not_after[..8]);
        let filetime = u64::from_le_bytes(raw);
        let unix_secs = (filetime / 10_000_000) as i64 - FILETIME_UNIX_EPOCH_OFFSET_SECS;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Some(CertInfo {
            thumbprint,
            days_left: (unix_secs - now) / 86_400,
        })
    })();
    unsafe { C::CertFreeCertificateContext(ctx) };
    result
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
