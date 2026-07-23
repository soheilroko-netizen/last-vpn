// proxy.rs - Proxy manager (sing-box + WinDivert engine)
use anyhow::{bail, Context, Result};
use crate::config::Config;
use crate::sysdns;
use crate::sysproxy;
use crate::wd;
use crate::wd_engine::WdEngine;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

#[derive(Clone, Serialize, Deserialize)]
pub struct Profile {
    pub ss_method: String,
    pub ss_password: String,
    pub ss_server: String,
    pub ss_port: u16,
    pub stls_server: String,
    pub stls_port: u16,
    pub stls_password: String,
    pub stls_sni: String,
    pub local_addr: String,
    pub local_port: u16,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            ss_method: "2022-blake3-chacha20-poly1305".into(),
            ss_password: "tE+3/qlN/orCZRVUutWouysZ8BQs4RWzq46WK6CDGG4=".into(),
            ss_server: "ns.baft.uk".into(),
            ss_port: 8380,
            stls_server: "ns.baft.uk".into(),
            stls_port: 8553,
            stls_password: "y2lachetore".into(),
            stls_sni: "dl.google.com".into(),
            local_addr: "127.0.0.1".into(),
            local_port: 1080,
        }
    }
}

// ── sing-box config structures ─────────────────────────────────────

#[derive(Serialize)]
struct SbConfig {
    log: SbLog,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<SbDns>,
    inbounds: Vec<SbInbound>,
    outbounds: Vec<SbOutbound>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route: Option<SbRoute>,
}

#[derive(Serialize)]
struct SbLog {
    disabled: bool,
    level: String,
    timestamp: bool,
}

#[derive(Serialize)]
struct SbDns {
    servers: Vec<SbDnsServer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rules: Option<Vec<SbDnsRule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    strategy: Option<String>,
}

#[derive(Serialize)]
struct SbDnsServer {
    #[serde(rename = "type")]
    typ: String,
    tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detour: Option<String>,
}

#[derive(Serialize)]
struct SbDnsRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
}

#[derive(Serialize)]
struct SbRoute {
    #[serde(skip_serializing_if = "Option::is_none")]
    rules: Option<Vec<SbRouteRule>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "final")]
    final_outbound: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_detect_interface: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_domain_resolver: Option<String>,
}

#[derive(Serialize)]
struct SbRouteRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_cidr: Option<Vec<String>>,
    outbound: String,
}

#[derive(Serialize)]
struct SbInbound {
    #[serde(rename = "type")]
    typ: String,
    tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    listen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listen_port: Option<u16>,
    // remnant TUN fields (unused now, keep for transition)
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_route: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    strict_route: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stack: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sniff: Option<bool>,
}

#[derive(Serialize)]
struct SbOutbound {
    #[serde(rename = "type")]
    typ: String,
    tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<SbTls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detour: Option<String>,
}

#[derive(Serialize)]
struct SbTls {
    enabled: bool,
    server_name: String,
    insecure: bool,
}

// ── ProxyManager ───────────────────────────────────────────────────

pub struct ProxyManager {
    // sing-box child process
    child: Arc<Mutex<Option<Child>>>,
    config_dir: PathBuf,
    config: Config,
    saved_proxy: Arc<Mutex<Option<sysproxy::SavedProxyState>>>,
    saved_dns: Arc<Mutex<Option<sysdns::SavedDnsState>>>,
    active_mode: Arc<Mutex<Option<String>>>,
    // WinDivert engine for VPN mode
    wd_engine: Arc<Mutex<Option<WdEngine>>>,
}

impl ProxyManager {
    pub fn new() -> Result<Self> {
        let config = Config::load()?;
        let config_dir = ProjectDirs::from("", "", "stls")
            .map(|d| d.config_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        fs::create_dir_all(&config_dir)?;

        Ok(ProxyManager {
            child: Arc::new(Mutex::new(None)),
            config_dir,
            config,
            saved_proxy: Arc::new(Mutex::new(None)),
            saved_dns: Arc::new(Mutex::new(None)),
            active_mode: Arc::new(Mutex::new(None)),
            wd_engine: Arc::new(Mutex::new(None)),
        })
    }

    pub fn is_running(&self) -> bool {
        // Check sing-box
        let mut guard = self.child.lock().unwrap();
        if let Some(child) = guard.as_mut() {
            match child.try_wait() {
                Ok(Some(_)) => { *guard = None; false }
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    pub fn start(&mut self) -> Result<String> {
        if self.is_running() {
            bail!("Already running");
        }

        #[cfg(target_os = "windows")]
        {
            extern "system" { fn IsUserAnAdmin() -> i32; }
            let is_admin = unsafe { IsUserAnAdmin() != 0 };
            if !is_admin {
                bail!("Admin required. Right-click stls.exe → 'Run as administrator'.");
            }
        }

        self.config = Config::load()?;
        let mode = self.config.mode.clone();

        match mode.as_str() {
            "proxy" => self.start_proxy_mode()?,
            "vpn" => self.start_vpn_mode()?,
            _ => bail!("Unknown mode: {mode}"),
        }

        *self.active_mode.lock().unwrap() = Some(mode.clone());
        Ok(format!("{} mode started", mode.to_uppercase()))
    }

    pub fn stop(&mut self) -> Result<String> {
        let mode = self.active_mode.lock().unwrap().take();

        // Stop WdEngine if running (VPN mode)
        if let Some(engine) = self.wd_engine.lock().unwrap().take() {
            engine.stop();
            // Give threads a moment to exit
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        // Stop sing-box
        let mut guard = self.child.lock().unwrap();
        let was_running = guard.is_some();
        if let Some(mut child) = guard.take() {
            child.kill()?;
            child.wait()?;
        }
        drop(guard);

        // Restore system proxy (proxy mode)
        if mode.as_deref() == Some("proxy") {
            let snapshot = self.saved_proxy.lock().unwrap().take();
            if let Some(ref saved) = snapshot {
                let _ = sysproxy::restore(saved);
            }
        }

        // Restore DNS (VPN mode)
        if mode.as_deref() == Some("vpn") {
            let snapshot = self.saved_dns.lock().unwrap().take();
            if let Some(ref saved) = snapshot {
                let _ = sysdns::restore(saved);
            }
        }

        if !was_running {
            bail!("Not running");
        }

        Ok("Stopped".into())
    }

    // ── PROXY MODE (unchanged) ──────────────────────────────────────

    fn start_proxy_mode(&mut self) -> Result<()> {
        let cfg = self.build_plain_proxy_config();
        self.launch_sing_box(&cfg)?;

        // Set system proxy
        let snapshot = sysproxy::take_snapshot();
        sysproxy::enable("127.0.0.1", self.config.socks5_port)?;
        *self.saved_proxy.lock().unwrap() = Some(snapshot);

        Ok(())
    }

    fn build_plain_proxy_config(&self) -> SbConfig {
        let c = &self.config;
        SbConfig {
            log: SbLog { disabled: false, level: "info".into(), timestamp: true },
            dns: None,
            inbounds: vec![SbInbound {
                typ: "mixed".into(),
                tag: "mixed-in".into(),
                listen: Some("127.0.0.1".into()),
                listen_port: Some(c.socks5_port),
                interface_name: None, address: None, mtu: None,
                auto_route: None, strict_route: None, stack: None, sniff: None,
            }],
            outbounds: self.common_outbounds(),
            route: None,
        }
    }

    // ── VPN MODE (WinDivert + sing-box proxy) ───────────────────────

    fn start_vpn_mode(&mut self) -> Result<()> {
        // 1. Resolve VPS server IP (for WinDivert filter exclusion)
        let vps_ips = resolve_hostname(&self.config.server_address)
            .context("Failed to resolve VPS address")?;
        let vps_ip = vps_ips.first()
            .ok_or_else(|| anyhow::anyhow!("No VPS IP resolved"))?
            .clone();

        // 2. Start sing-box as a local proxy (SOCKS5+HTTP on :1080)
        let cfg = self.build_vpn_proxy_config(&vps_ip);
        self.launch_sing_box(&cfg)?;

        // 3. Find and bundle WinDivert.dll next to config/exe
        let wd_dll = self.bundle_windivert()?;

        // 4. Build filter and start WinDivert engine
        let filter = build_wd_filter(&vps_ip);
        let engine = WdEngine::new(&wd_dll);
        engine.start(&filter)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .context("WinDivert engine failed to start")?;
        *self.wd_engine.lock().unwrap() = Some(engine);

        // 5. Override system DNS
        match sysdns::take_snapshot() {
            Ok(snap) => {
                sysdns::set_dns(&snap.interface, "8.8.8.8")
                    .context("DNS override failed")?;
                *self.saved_dns.lock().unwrap() = Some(snap);
            }
            Err(e) => {
                eprintln!("[stls] DNS snapshot failed: {e}");
            }
        }

        Ok(())
    }

    /// VPN mode: sing-box runs as local proxy (no TUN).
    /// Outbounds go through SS→STLS; DNS uses 8.8.8.8 direct.
    fn build_vpn_proxy_config(&self, vps_ip: &str) -> SbConfig {
        let mut outbounds = self.common_outbounds();
        // Pin server IP to avoid DNS in proxy chain
        for ob in &mut outbounds {
            if ob.tag == "ss-out" || ob.tag == "shadowtls-out" {
                ob.server = Some(vps_ip.to_string());
            }
        }

        SbConfig {
            log: SbLog { disabled: false, level: "info".into(), timestamp: true },
            dns: None,
            inbounds: vec![SbInbound {
                typ: "mixed".into(),
                tag: "mixed-in".into(),
                listen: Some("127.0.0.1".into()),
                listen_port: Some(self.config.socks5_port),
                interface_name: None, address: None, mtu: None,
                auto_route: None, strict_route: None, stack: None, sniff: None,
            }],
            outbounds,
            route: None,
        }
    }

    // ── Sing-box lifecycle ──────────────────────────────────────────

    fn launch_sing_box(&self, cfg: &SbConfig) -> Result<()> {
        let exe = self.get_bundled_or_download()?;
        let cfg_json = serde_json::to_string_pretty(cfg)?;
        let cfg_path = self.config_dir.join("config.json");
        fs::write(&cfg_path, &cfg_json)?;

        // Validate
        let check = Command::new(&exe)
            .arg("check").arg("-c").arg(&cfg_path)
            .output().context("sing-box check failed")?;
        if !check.status.success() {
            bail!("Config invalid:\n{}\n{}",
                String::from_utf8_lossy(&check.stderr).trim(),
                String::from_utf8_lossy(&check.stdout).trim());
        }

        let log_path = self.config_dir.join("sing-box.log");
        let log_file = fs::File::create(&log_path)?;

        #[cfg(target_os = "windows")]
        let child = {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            Command::new(&exe)
                .arg("run").arg("-c").arg(&cfg_path)
                .creation_flags(CREATE_NO_WINDOW)
                .stdout(Stdio::from(log_file.try_clone()?))
                .stderr(Stdio::from(log_file))
                .spawn()?
        };

        #[cfg(not(target_os = "windows"))]
        let child = Command::new(&exe)
            .arg("run").arg("-c").arg(&cfg_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        *self.child.lock().unwrap() = Some(child);

        // Check liveness
        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut guard = self.child.lock().unwrap();
        if let Some(ref mut c) = *guard {
            match c.try_wait() {
                Ok(Some(status)) => {
                    let log = fs::read_to_string(&log_path).unwrap_or_default();
                    guard.take();
                    *self.active_mode.lock().unwrap() = None;
                    bail!("sing-box exited (code={:?}):\n{}", status.code(), log.trim());
                }
                Ok(None) => {} // running
                Err(e) => {
                    guard.take();
                    *self.active_mode.lock().unwrap() = None;
                    bail!("sing-box crash: {e}");
                }
            }
        }
        drop(guard);

        Ok(())
    }

    fn common_outbounds(&self) -> Vec<SbOutbound> {
        let c = &self.config;
        vec![
            SbOutbound {
                typ: "shadowsocks".into(), tag: "ss-out".into(),
                server: Some(c.server_address.clone()),
                server_port: Some(c.ss_port),
                method: Some("2022-blake3-chacha20-poly1305".into()),
                password: Some(c.ss_password.clone()),
                version: None, tls: None,
                detour: Some("shadowtls-out".into()),
            },
            SbOutbound {
                typ: "shadowtls".into(), tag: "shadowtls-out".into(),
                server: Some(c.server_address.clone()),
                server_port: Some(c.stls_port),
                version: Some(3),
                password: Some(c.stls_password.clone()),
                tls: Some(SbTls {
                    enabled: true,
                    server_name: c.stls_sni.clone(),
                    insecure: false,
                }),
                detour: None, method: None,
            },
            SbOutbound {
                typ: "direct".into(), tag: "direct".into(),
                server: None, server_port: None,
                method: None, password: None,
                version: None, tls: None, detour: None,
            },
        ]
    }

    // ── Sing-box binary management ──────────────────────────────────

    fn sing_box_exe(&self) -> PathBuf { self.config_dir.join("sing-box.exe") }

    fn get_bundled_or_download(&self) -> Result<PathBuf> {
        // Check next to exe
        if let Ok(exe_path) = std::env::current_exe() {
            let bundled = exe_path.parent().unwrap_or(Path::new(".")).join("sing-box.exe");
            if bundled.exists() {
                return Ok(bundled);
            }
        }
        let paths = [
            PathBuf::from("bin").join("sing-box.exe"),
            PathBuf::from("sing-box.exe"),
            self.sing_box_exe(),
        ];
        for p in &paths {
            if p.exists() { return Ok(p.clone()); }
        }
        self.download_sing_box()
    }

    fn download_sing_box(&self) -> Result<PathBuf> {
        let exe = self.sing_box_exe();
        if exe.exists() { return Ok(exe); }

        let client = reqwest::blocking::Client::builder()
            .user_agent("stls").build()?;

        let rel: serde_json::Value = client
            .get("https://api.github.com/repos/SagerNet/sing-box/releases/latest")
            .send()?.json()?;

        let tag = rel["tag_name"].as_str()
            .ok_or_else(|| anyhow::anyhow!("no tag"))?;
        let version = tag.trim_start_matches('v');

        let zip_name = format!("sing-box-{version}-windows-amd64.zip");
        let url = format!("https://github.com/SagerNet/sing-box/releases/download/{tag}/{zip_name}");

        let bytes = client.get(&url).send()?.error_for_status()?.bytes()?;
        let reader = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader)?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            if file.name().ends_with("sing-box.exe") {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;
                fs::write(&exe, &buf)?;
                return Ok(exe);
            }
        }
        bail!("sing-box.exe not found in release zip")
    }

    // ── WinDivert bundling ──────────────────────────────────────────

    /// Find WinDivert.dll — checks alongside exe, bin/, resources/, config dir, current dir.
    fn bundle_windivert(&self) -> Result<String> {
        let candidates = {
            let mut v = Vec::new();
            if let Ok(exe) = std::env::current_exe() {
                if let Some(parent) = exe.parent() {
                    v.push(parent.join("WinDivert.dll"));
                    v.push(parent.join("bin").join("WinDivert.dll"));
                    v.push(parent.join("resources").join("bin").join("WinDivert.dll"));
                }
            }
            v.push(self.config_dir.join("WinDivert.dll"));
            v.push(self.config_dir.join("bin").join("WinDivert.dll"));
            v.push(PathBuf::from("WinDivert.dll"));
            v.push(PathBuf::from("bin").join("WinDivert.dll"));
            v
        };
        for c in &candidates {
            if c.exists() {
                return Ok(c.to_string_lossy().to_string());
            }
        }
        // Download if not found
        eprintln!("[stls] WinDivert.dll not bundled — download not implemented yet");
        bail!("WinDivert.dll not found. Bundle WinDivert.dll and WinDivert64.sys in the installer.");
    }
}

// ── Helper ──────────────────────────────────────────────────────────

fn resolve_hostname(host: &str) -> Result<Vec<String>> {
    let addr_str = format!("{host}:0");
    let addrs = addr_str.to_socket_addrs().context("DNS resolution failed")?;
    let mut ips: Vec<String> = Vec::new();
    for addr in addrs {
        let ip = addr.ip().to_string();
        if !ips.contains(&ip) { ips.push(ip); }
    }
    Ok(ips)
}

/// Build WinDivert filter string for VPN mode.
/// Intercepts all outbound TCP except: VPS IP, relay port, proxy port, LAN.
fn build_wd_filter(vps_ip: &str) -> String {
    format!(
        concat!(
            "not impostor and ",
            "tcp and (outbound) and ",
            "not ip.DstAddr == {} and ",
            "not tcp.DstPort == 34010 and ",
            "not tcp.DstPort == 1080 and ",
            "not tcp.SrcPort == 1080 and ",
            "not (ip.DstAddr >= 10.0.0.0 and ip.DstAddr <= 10.255.255.255) and ",
            "not (ip.DstAddr >= 172.16.0.0 and ip.DstAddr <= 172.31.255.255) and ",
            "not (ip.DstAddr >= 192.168.0.0 and ip.DstAddr <= 192.168.255.255) and ",
            "not (ip.DstAddr >= 127.0.0.0 and ip.DstAddr <= 127.255.255.255) and ",
            "not (ip.DstAddr >= 169.254.0.0 and ip.DstAddr <= 169.254.255.255) and ",
            "not (ip.DstAddr >= 224.0.0.0 and ip.DstAddr <= 239.255.255.255)",
        ),
        vps_ip,
    )
}
