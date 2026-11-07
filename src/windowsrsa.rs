//! Generate an RSA private key with Windows' built-in CryptoAPI.
//!
//! `rcgen` can sign RSA certificates with ring when it is given an existing
//! PKCS#8 key, but ring deliberately does not generate RSA keys. Windows
//! CurrentUser\Root is also the one place where an RSA trust anchor is
//! required for reliable persistence on supported machines. This small
//! adapter uses the OS key generator and converts its documented
//! PRIVATEKEYBLOB to PKCS#8 DER; it avoids adding a second crypto backend.

use anyhow::{bail, Context, Result};
use rcgen::{KeyPair, PKCS_RSA_SHA256};
use rustls::pki_types::PrivatePkcs8KeyDer;
use windows_sys::Win32::Security::Cryptography as C;

const RSA_BITS: u32 = 2048;
const BLOB_HEADER_LEN: usize = 20;

/// Generate an exportable RSA-2048 key and load it into rcgen.
pub fn generate_rsa_key_pair() -> Result<KeyPair> {
    let mut provider = 0usize;
    let acquired = unsafe {
        C::CryptAcquireContextW(
            &mut provider,
            std::ptr::null(),
            std::ptr::null(),
            C::PROV_RSA_AES,
            C::CRYPT_VERIFYCONTEXT,
        )
    };
    if acquired == 0 {
        return Err(std::io::Error::last_os_error()).context("Windows CryptoAPI 初始化失败");
    }

    let result = (|| {
        let mut key = 0usize;
        let generated = unsafe {
            C::CryptGenKey(
                provider,
                C::CALG_RSA_SIGN,
                (RSA_BITS << 16) | C::CRYPT_EXPORTABLE,
                &mut key,
            )
        };
        if generated == 0 {
            return Err(std::io::Error::last_os_error())
                .context("Windows CryptoAPI 生成 RSA 根密钥失败");
        }

        let result = export_pkcs8(key).and_then(|der| {
            KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(der), &PKCS_RSA_SHA256)
                .context("rcgen 无法读取 Windows CryptoAPI 生成的 RSA 私钥")
        });
        unsafe {
            C::CryptDestroyKey(key);
        }
        result
    })();

    unsafe {
        C::CryptReleaseContext(provider, 0);
    }
    result
}

fn export_pkcs8(key: usize) -> Result<Vec<u8>> {
    let mut size = 0u32;
    let queried = unsafe {
        C::CryptExportKey(
            key,
            0,
            C::PRIVATEKEYBLOB,
            0,
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if queried == 0 {
        return Err(std::io::Error::last_os_error()).context("读取 RSA 私钥长度失败");
    }
    let mut blob = vec![0u8; size as usize];
    let exported =
        unsafe { C::CryptExportKey(key, 0, C::PRIVATEKEYBLOB, 0, blob.as_mut_ptr(), &mut size) };
    if exported == 0 {
        return Err(std::io::Error::last_os_error()).context("导出 RSA 私钥失败");
    }
    blob.truncate(size as usize);
    private_blob_to_pkcs8(&blob)
}

/// Convert the documented CryptoAPI PRIVATEKEYBLOB layout to PKCS#8.
fn private_blob_to_pkcs8(blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < BLOB_HEADER_LEN || blob[0] != 0x07 || &blob[8..12] != b"RSA2" {
        bail!("Windows CryptoAPI 返回了无法识别的 RSA 私钥格式");
    }
    let bits = u32::from_le_bytes(blob[12..16].try_into().unwrap());
    if bits != RSA_BITS {
        bail!("Windows CryptoAPI 返回了非 RSA-2048 私钥（{bits} 位）");
    }
    let bytes = (bits / 8) as usize;
    let half = bytes / 2;
    let expected = BLOB_HEADER_LEN + bytes + half * 5 + bytes;
    if blob.len() < expected {
        bail!("Windows CryptoAPI 返回的 RSA 私钥不完整");
    }

    let modulus = integer_from_little_endian(&blob[20..20 + bytes]);
    let prime1 = integer_from_little_endian(&blob[20 + bytes..20 + bytes + half]);
    let prime2 = integer_from_little_endian(&blob[20 + bytes + half..20 + bytes + half * 2]);
    let exponent1 = integer_from_little_endian(&blob[20 + bytes + half * 2..20 + bytes + half * 3]);
    let exponent2 = integer_from_little_endian(&blob[20 + bytes + half * 3..20 + bytes + half * 4]);
    let coefficient =
        integer_from_little_endian(&blob[20 + bytes + half * 4..20 + bytes + half * 5]);
    let private_exponent =
        integer_from_little_endian(&blob[20 + bytes + half * 5..20 + bytes + half * 5 + bytes]);
    let public_exponent = integer_from_little_endian(&blob[16..20]);

    let mut pkcs1 = Vec::new();
    for value in [
        integer_zero(),
        modulus,
        public_exponent,
        private_exponent,
        prime1,
        prime2,
        exponent1,
        exponent2,
        coefficient,
    ] {
        der_integer(&mut pkcs1, &value);
    }
    let pkcs1 = der_sequence(&pkcs1);

    let mut algorithm = Vec::new();
    algorithm.extend_from_slice(&[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    ]);
    algorithm.extend_from_slice(&[0x05, 0x00]);
    let algorithm = der_sequence(&algorithm);

    let mut pkcs8 = Vec::new();
    der_integer(&mut pkcs8, &integer_zero());
    pkcs8.extend_from_slice(&algorithm);
    pkcs8.push(0x04);
    der_length(&mut pkcs8, pkcs1.len());
    pkcs8.extend_from_slice(&pkcs1);
    Ok(der_sequence(&pkcs8))
}

fn integer_zero() -> Vec<u8> {
    vec![0]
}

fn integer_from_little_endian(value: &[u8]) -> Vec<u8> {
    let mut result = value.to_vec();
    result.reverse();
    while result.len() > 1 && result[0] == 0 {
        result.remove(0);
    }
    if result.first().is_some_and(|byte| byte & 0x80 != 0) {
        result.insert(0, 0);
    }
    result
}

fn der_integer(out: &mut Vec<u8>, value: &[u8]) {
    out.push(0x02);
    der_length(out, value.len());
    out.extend_from_slice(value);
}

fn der_sequence(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    der_length(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

fn der_length(out: &mut Vec<u8>, length: usize) {
    if length < 128 {
        out.push(length as u8);
    } else {
        let bytes = (length as u64).to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_length_uses_short_and_long_forms() {
        let mut short = Vec::new();
        der_length(&mut short, 127);
        assert_eq!(short, [127]);
        let mut long = Vec::new();
        der_length(&mut long, 256);
        assert_eq!(long, [0x82, 0x01, 0x00]);
    }

    #[test]
    fn little_endian_integer_is_positive_der_integer() {
        assert_eq!(integer_from_little_endian(&[0x01, 0x00]), [1]);
        assert_eq!(integer_from_little_endian(&[0x80]), [0, 0x80]);
    }
}
