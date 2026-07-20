// sysproxy.rs - Windows system proxy management via HKCU registry
// Uses WinINet Internet Settings registry keys directly.
// Notifies Windows via InternetSetOption (raw wininet.dll FFI).

use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows::Win32::Foundation::*;
use windows::Win32::System::Registry::*;

const INTERNET_SETTINGS: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";

// INTERNET_OPTION constants
const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
const INTERNET_OPTION_REFRESH: u32 = 37;

// ── helpers ────────────────────────────────────────────────────────

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

unsafe fn open_key(
    access: u32,
) -> Result<HKEY> {
    let path = to_wide(INTERNET_SETTINGS);
    let mut hkey = HKEY::default();
    RegOpenKeyExW(HKEY_CURRENT_USER, &path, 0, access, &mut hkey)
        .context("failed to open Internet Settings registry key")?;
    Ok(hkey)
}

unsafe fn read_dword(hkey: HKEY, name: &str) -> Option<u32> {
    let name_w = to_wide(name);
    let mut data: u32 = 0;
    let mut size = size_of::<u32>() as u32;
    RegQueryValueExW(
        hkey,
        &name_w,
        None,
        None,
        Some(&mut data as *mut u32 as *mut u8),
        &mut size,
    )
    .ok()?;
    Some(data)
}

unsafe fn read_string(hkey: HKEY, name: &str) -> Option<String> {
    let name_w = to_wide(name);

    // get required buffer size
    let mut size: u32 = 0;
    if RegQueryValueExW(hkey, &name_w, None, None, None, &mut size).is_err() {
        return None;
    }
    if size == 0 {
        return Some(String::new());
    }

    let mut buf = vec![0u8; size as usize];
    RegQueryValueExW(
        hkey,
        &name_w,
        None,
        None,
        Some(buf.as_mut_ptr()),
        &mut size,
    )
    .ok()?;

    // REG_SZ is null-terminated UTF-16LE
    let len = size as usize / 2;
    let wide_slice =
        std::slice::from_raw_parts(buf.as_ptr() as *const u16, len);
    // trim trailing null
    let actual_len = wide_slice
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(wide_slice.len());
    Some(String::from_utf16_lossy(&wide_slice[..actual_len]))
}

unsafe fn write_dword(hkey: HKEY, name: &str, value: u32) -> Result<()> {
    let name_w = to_wide(name);
    let data = value as u32;
    RegSetValueExW(
        hkey,
        &name_w,
        0,
        REG_DWORD,
        Some(&data as *const u32 as *const u8),
        size_of::<u32>() as u32,
    )
    .context(format!("failed to write DWORD registry value '{name}'"))?;
    Ok(())
}

unsafe fn write_string(hkey: HKEY, name: &str, value: &str) -> Result<()> {
    let name_w = to_wide(name);
    // REG_SZ must be null-terminated UTF-16LE
    let value_w = to_wide(value);
    let byte_len = (value_w.len() * 2) as u32; // includes null from to_wide
    RegSetValueExW(
        hkey,
        &name_w,
        0,
        REG_SZ,
        Some(value_w.as_ptr() as *const u8),
        byte_len,
    )
    .context(format!("failed to write STRING registry value '{name}'"))?;
    Ok(())
}

unsafe fn delete_value(hkey: HKEY, name: &str) -> Result<()> {
    let name_w = to_wide(name);
    RegDeleteValueW(hkey, &name_w)
        .context(format!("failed to delete registry value '{name}'"))?;
    Ok(())
}

#[link(name = "wininet")]
extern "system" {
    fn InternetSetOptionW(
        hInternet: *mut std::ffi::c_void,
        dwOption: u32,
        lpBuffer: *mut std::ffi::c_void,
        dwBufferLength: u32,
    ) -> i32;
}

unsafe fn notify_settings_changed() {
    // Notify WinINet that settings changed
    InternetSetOptionW(
        ptr::null_mut(),
        INTERNET_OPTION_SETTINGS_CHANGED,
        ptr::null_mut(),
        0,
    );
    InternetSetOptionW(
        ptr::null_mut(),
        INTERNET_OPTION_REFRESH,
        ptr::null_mut(),
        0,
    );
}

// ── public API ─────────────────────────────────────────────────────

/// Snapshot of the current Windows proxy settings.
/// Used to restore exactly what the user had before we touched it.
#[derive(Debug, Clone, Default)]
pub struct SavedProxyState {
    pub proxy_enable: Option<u32>,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
    pub auto_config_url: Option<String>,
    pub auto_detect: Option<u32>,
}

/// Take a snapshot of every proxy-related value in Internet Settings.
pub fn take_snapshot() -> SavedProxyState {
    unsafe {
        match open_key(KEY_QUERY_VALUE) {
            Ok(hkey) => {
                let s = SavedProxyState {
                    proxy_enable: read_dword(hkey, "ProxyEnable"),
                    proxy_server: read_string(hkey, "ProxyServer"),
                    proxy_override: read_string(hkey, "ProxyOverride"),
                    auto_config_url: read_string(hkey, "AutoConfigURL"),
                    auto_detect: read_dword(hkey, "AutoDetect"),
                };
                let _ = RegCloseKey(hkey);
                s
            }
            Err(_) => SavedProxyState::default(),
        }
    }
}

/// Enable system proxy — set ProxyEnable=1, ProxyServer=`host:port`.
/// Keeps existing ProxyOverride and AutoDetect values intact.
pub fn enable(host: &str, port: u16) -> Result<()> {
    unsafe {
        let hkey = open_key(KEY_SET_VALUE | KEY_QUERY_VALUE)?;
        write_dword(hkey, "ProxyEnable", 1)?;
        write_string(hkey, "ProxyServer", &format!("{host}:{port}"))?;
        // preserve ProxyOverride (don't wipe it)
        // preserve AutoDetect
        let _ = RegCloseKey(hkey);
        notify_settings_changed();
    }
    Ok(())
}

/// Restore a previously-saved snapshot.
/// For each key: if snapshot has a value, restore it; otherwise delete it
/// (so stale values don't linger).
pub fn restore(saved: &SavedProxyState) -> Result<()> {
    unsafe {
        let hkey = open_key(KEY_SET_VALUE | KEY_QUERY_VALUE)?;

        match &saved.proxy_enable {
            Some(v) => write_dword(hkey, "ProxyEnable", *v)?,
            None => {
                let _ = delete_value(hkey, "ProxyEnable");
            }
        }
        match &saved.proxy_server {
            Some(v) => write_string(hkey, "ProxyServer", v)?,
            None => {
                let _ = delete_value(hkey, "ProxyServer");
            }
        }
        match &saved.proxy_override {
            Some(v) => write_string(hkey, "ProxyOverride", v)?,
            None => {
                let _ = delete_value(hkey, "ProxyOverride");
            }
        }
        match &saved.auto_config_url {
            Some(v) => write_string(hkey, "AutoConfigURL", v)?,
            None => {
                let _ = delete_value(hkey, "AutoConfigURL");
            }
        }
        match &saved.auto_detect {
            Some(v) => write_dword(hkey, "AutoDetect", *v)?,
            None => {
                let _ = delete_value(hkey, "AutoDetect");
            }
        }

        let _ = RegCloseKey(hkey);
        notify_settings_changed();
    }
    Ok(())
}
