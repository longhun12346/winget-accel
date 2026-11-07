//! Effective LAN connection options. AutoConfigURL alone does not enable PAC.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::GlobalFree;
use windows_sys::Win32::Networking::WinInet::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Connection {
    pub flags: u32,
    // Explicit null is valid; a missing backup field is corrupt, not absent.
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub url: Option<String>,
}

impl Connection {
    pub fn with_pac(&self, url: String) -> Self {
        Self {
            flags: self.flags | PROXY_TYPE_AUTO_PROXY_URL,
            url: Some(url),
        }
    }

    pub fn pac_enabled(&self) -> bool {
        self.flags & PROXY_TYPE_AUTO_PROXY_URL != 0
    }

    /// Restore only our PAC bit; preserve changes to manual proxy/WPAD flags.
    pub fn restore_pac(&self, prior: &Self) -> Self {
        Self {
            flags: (self.flags & !PROXY_TYPE_AUTO_PROXY_URL)
                | (prior.flags & PROXY_TYPE_AUTO_PROXY_URL),
            url: prior.url.clone(),
        }
    }
}

/// Write-ahead recovery intent: the native setter can also rewrite AutoConfigURL.
/// Keep its two independent original values recoverable across that crash window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Restore {
    pub before: Connection,
    pub after: Connection,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub registry_before: Option<String>,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub registry_after: Option<String>,
}

fn options() -> [INTERNET_PER_CONN_OPTIONW; 2] {
    [
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_FLAGS,
            ..Default::default()
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_AUTOCONFIG_URL,
            ..Default::default()
        },
    ]
}

fn list(options: &mut [INTERNET_PER_CONN_OPTIONW; 2]) -> INTERNET_PER_CONN_OPTION_LISTW {
    INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        // Null means the LAN/default connection, rather than a named RAS entry.
        dwOptionCount: options.len() as u32,
        pOptions: options.as_mut_ptr(),
        ..Default::default()
    }
}

pub fn query() -> Result<Connection> {
    let mut options = options();
    let mut list = list(&mut options);
    let mut size = list.dwSize;
    // SAFETY: typed option/list buffers live throughout the call.
    if unsafe {
        InternetQueryOptionW(
            std::ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&mut list as *mut INTERNET_PER_CONN_OPTION_LISTW).cast(),
            &mut size,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("读取 WinINet 有效 PAC 配置失败");
    }
    // SAFETY: a successful query initializes the requested union members. The
    // returned URL is NUL terminated and allocated by WinINet with GlobalAlloc.
    unsafe {
        let ptr = options[1].Value.pszValue;
        let url = if ptr.is_null() {
            Ok(None)
        } else {
            let mut len = 0;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let value = String::from_utf16(std::slice::from_raw_parts(ptr, len));
            GlobalFree(ptr.cast());
            value.map(|value| (!value.is_empty()).then_some(value))
        };
        Ok(Connection {
            flags: options[0].Value.dwValue,
            url: url.context("WinINet PAC URL 不是合法 UTF-16")?,
        })
    }
}

pub fn apply(connection: &Connection) -> Result<()> {
    let mut url: Vec<u16> = connection
        .url
        .as_deref()
        .unwrap_or("")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut options = options();
    options[0].Value.dwValue = connection.flags;
    options[1].Value.pszValue = url.as_mut_ptr();
    let list = list(&mut options);
    // SAFETY: the list, options and UTF-16 URL all live throughout the call.
    if unsafe {
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&list as *const INTERNET_PER_CONN_OPTION_LISTW).cast(),
            list.dwSize,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("写入 WinINet 有效 PAC 配置失败");
    }
    Ok(())
}
