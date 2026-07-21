// proxy.rs - sing-box proxy manager
use anyhow::{bail, Context, Result};
use crate::config::Config;
use crate::sysproxy;
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
    // SOCKS5 fields
    #[serde(skip_serializing_if = "Option::is_none")]
    listen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listen_port: Option<u16>,
    // TUN fields
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

pub struct ProxyManager {
    child: Arc<Mutex<Option<Child>>>,
    config_dir: PathBuf,
    config: Config,
    saved_proxy: Arc<Mutex<Option<sysproxy::SavedProxyState>>>,
    active_mode: Arc<Mutex<Option<String>>>, // records mode when started
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
            active_mode: Arc::new(Mutex::new(None)),
        })
    }

    pub fn is_running(&self) -> bool {
        let mut guard = self.child.lock().unwrap();
        if let Some(child) = guard.as_mut() {
            match child.try_wait() {
                Ok(Some(_)) => {
                    *guard = None;
                    false
                }
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    pub fn start(&mut self) -> Result<String> {
        if self.is_running() {
            bail!("Proxy already running");
        }

        // Check admin on Windows (needed for TUN + sysproxy)
        #[cfg(target_os = "windows")]
        {
            extern "system" {
                fn IsUserAnAdmin() -> i32;
            }
            // SAFETY: IsUserAnAdmin() from shell32.dll
            let is_admin = unsafe { IsUserAnAdmin() != 0 };
            if !is_admin {
                bail!("Admin required. Right-click stls.exe → 'Run as administrator'.");
            }
        }

        // Re-read config in case user changed mode/settings
        self.config = Config::load()?;

        let exe = self.get_bundled_or_download()?;

        let mode = self.config.mode.clone();
        let cfg = match mode.as_str() {
            "proxy" => self.build_proxy_config(),
            "vpn" => self.build_vpn_config()?,
            _ => bail!("Unknown mode: {mode}"),
        };

        let cfg_json = serde_json::to_string_pretty(&cfg)?;
        let cfg_path = self.config_dir.join("config.json");
        fs::write(&cfg_path, &cfg_json)?;

        // Validate config before launch
        let check_output = Command::new(&exe)
            .arg("check")
            .arg("-c")
            .arg(&cfg_path)
            .output()
            .context("failed to run sing-box check")?;
        if !check_output.status.success() {
            let err_text = String::from_utf8_lossy(&check_output.stderr);
            let out_text = String::from_utf8_lossy(&check_output.stdout);
            bail!(
                "Config validation failed:\n{}{}\nConfig: {}",
                err_text.trim(),
                out_text.trim(),
                cfg_path.display()
            );
        }

        let log_path = self.config_dir.join("sing-box.log");
        let log_file = fs::File::create(&log_path)?;

        // Start sing-box with hidden window on Windows
        #[cfg(target_os = "windows")]
        let child = {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            Command::new(&exe)
                .arg("run")
                .arg("-c")
                .arg(&cfg_path)
                .creation_flags(CREATE_NO_WINDOW)
                .stdout(Stdio::from(log_file.try_clone()?))
                .stderr(Stdio::from(log_file))
                .spawn()?
        };

        #[cfg(not(target_os = "windows"))]
        let child = Command::new(&exe)
            .arg("run")
            .arg("-c")
            .arg(&cfg_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // Enable system proxy BEFORE marking running
        if mode == "proxy" {
            let snapshot = sysproxy::take_snapshot();
            sysproxy::enable("127.0.0.1", self.config.socks5_port)?;
            *self.saved_proxy.lock().unwrap() = Some(snapshot);
        }

        *self.child.lock().unwrap() = Some(child);
        *self.active_mode.lock().unwrap() = Some(mode.clone());

        // Check liveness — if sing-box died instantly, report why
        let mut guard = self.child.lock().unwrap();
        if let Some(ref mut c) = *guard {
            std::thread::sleep(std::time::Duration::from_millis(500));
            match c.try_wait() {
                Ok(Some(status)) => {
                    // Child exited already — read log
                    let log = fs::read_to_string(&log_path).unwrap_or_default();
                    guard.take();
                    *self.active_mode.lock().unwrap() = None;
                    bail!("sing-box exited (code={:?}):\n{}", status.code(), log.trim());
                }
                Err(e) => {
                    // try_wait error means child gone
                    guard.take();
                    *self.active_mode.lock().unwrap() = None;
                    bail!("sing-box check failed: {e}");
                }
                Ok(None) => {} // still running — good
            }
        }
        drop(guard);

        Ok(format!("{} mode started", mode.to_uppercase()))
    }

    pub fn stop(&mut self) -> Result<String> {
        let mode = self.active_mode.lock().unwrap().take();

        let mut guard = self.child.lock().unwrap();
        let was_running = guard.is_some();
        if let Some(mut child) = guard.take() {
            child.kill()?;
            child.wait()?;
        }
        drop(guard);

        if !was_running {
            bail!("Not running");
        }

        // Restore system proxy unconditionally
        if mode.as_deref() == Some("proxy") {
            let snapshot = self.saved_proxy.lock().unwrap().take();
            if let Some(ref saved) = snapshot {
                let _ = sysproxy::restore(saved);
            }
        }

        Ok("Stopped".into())
    }

    // ── proxy mode config (existing behaviour) ────────────────────

    fn build_proxy_config(&self) -> SbConfig {
        let c = &self.config;
        SbConfig {
            log: SbLog {
                disabled: false,
                level: "info".into(),
                timestamp: true,
            },
            dns: None,
            inbounds: vec![SbInbound {
                typ: "socks".into(),
                tag: "socks-in".into(),
                listen: Some("127.0.0.1".into()),
                listen_port: Some(c.socks5_port),
                interface_name: None,
                address: None,
                mtu: None,
                auto_route: None,
                strict_route: None,
                stack: None,
            }],
            outbounds: self.common_outbounds(),
            route: None,
        }
    }

    // ── VPN / TUN mode config ─────────────────────────────────────

    fn build_vpn_config(&self) -> Result<SbConfig> {
        let c = &self.config;

        // Resolve STLS server IP so we can bypass it from the TUN (prevents loop)
        let stls_ips: Vec<String> = resolve_hostname(&c.server_address)
            .context("failed to resolve ShadowTLS server address")?;

        let bypass_cidrs: Vec<String> = if stls_ips.is_empty() {
            vec!["198.18.0.0/15".into()] // fallback: sing-box reserved
        } else {
            stls_ips.iter().map(|ip| format!("{ip}/32")).collect()
        };

        // Use resolved IP in outbound server fields to avoid circular DNS
        let stls_ip = stls_ips.first()
            .map(|s| s.clone())
            .unwrap_or_else(|| "198.18.0.0".into());

        let mut outbounds = self.common_outbounds();
        for ob in &mut outbounds {
            if ob.tag == "ss-out" || ob.tag == "shadowtls-out" {
                ob.server = Some(stls_ip.clone());
            }
        }

        Ok(SbConfig {
            log: SbLog {
                disabled: false,
                level: "info".into(),
                timestamp: true,
            },
            dns: Some(SbDns {
                servers: vec![
                    SbDnsServer {
                        typ: "tcp".into(),
                        tag: "dns-remote".into(),
                        server: Some("8.8.8.8".into()),
                        server_port: Some(53),
                        detour: None,
                    },
                ],
                rules: Some(vec![
                    SbDnsRule {
                        server: Some("dns-remote".into()),
                    },
                ]),
                strategy: Some("prefer_ipv4".into()),
            }),
            inbounds: vec![SbInbound {
                typ: "tun".into(),
                tag: "tun-in".into(),
                listen: None,
                listen_port: None,
                interface_name: Some("stls-tun".into()),
                address: Some(vec!["172.19.0.1/30".into()]),
                mtu: Some(1400),
                auto_route: Some(true),
                strict_route: Some(true),
                stack: Some("system".into()),
            }],
            outbounds,
            route: Some(SbRoute {
                rules: Some(vec![
                    SbRouteRule {
                        protocol: None,
                        ip_cidr: Some(bypass_cidrs),
                        outbound: "direct".into(),
                    },
                ]),
                final_outbound: Some("ss-out".into()),
                auto_detect_interface: Some(true),
                default_domain_resolver: Some("dns-remote".into()),
            }),
        })
    }

    // ── shared outbounds (SS + STLS + direct) ─────────────────────

    fn common_outbounds(&self) -> Vec<SbOutbound> {
        let c = &self.config;
        vec![
            SbOutbound {
                typ: "shadowsocks".into(),
                tag: "ss-out".into(),
                server: Some(c.server_address.clone()),
                server_port: Some(c.ss_port),
                method: Some("2022-blake3-chacha20-poly1305".into()),
                password: Some(c.ss_password.clone()),
                version: None,
                tls: None,
                detour: Some("shadowtls-out".into()),
            },
            SbOutbound {
                typ: "shadowtls".into(),
                tag: "shadowtls-out".into(),
                server: Some(c.server_address.clone()),
                server_port: Some(c.stls_port),
                version: Some(3),
                password: Some(c.stls_password.clone()),
                tls: Some(SbTls {
                    enabled: true,
                    server_name: c.stls_sni.clone(),
                    insecure: false,
                }),
                detour: None,
                method: None,
            },
            SbOutbound {
                typ: "direct".into(),
                tag: "direct".into(),
                server: None,
                server_port: None,
                method: None,
                password: None,
                version: None,
                tls: None,
                detour: None,
            },
        ]
    }

    // ── sing-box binary management ─────────────────────────────────

    fn sing_box_exe(&self) -> PathBuf {
        self.config_dir.join("sing-box.exe")
    }

    fn get_bundled_or_download(&self) -> Result<PathBuf> {
        if let Ok(exe_path) = std::env::current_exe() {
            let bundled = exe_path.parent().unwrap_or(Path::new(".")).join("sing-box.exe");
            if bundled.exists() {
                println!("[stls] using bundled sing-box: {}", bundled.display());
                return Ok(bundled);
            }
        }
        let bundled = PathBuf::from("bin").join("sing-box.exe");
        if bundled.exists() {
            println!("[stls] using bundled sing-box: {}", bundled.display());
            return Ok(bundled);
        }
        let bundled = PathBuf::from("sing-box.exe");
        if bundled.exists() {
            println!("[stls] using bundled sing-box: {}", bundled.display());
            return Ok(bundled);
        }
        let cached = self.sing_box_exe();
        if cached.exists() {
            println!("[stls] using cached sing-box: {}", cached.display());
            return Ok(cached);
        }
        println!("[stls] no bundled sing-box found, downloading...");
        self.download_sing_box()
    }

    fn download_sing_box(&self) -> Result<PathBuf> {
        let exe = self.sing_box_exe();
        if exe.exists() {
            return Ok(exe);
        }

        println!("[stls] resolving latest sing-box release...");
        let client = reqwest::blocking::Client::builder()
            .user_agent("stls")
            .build()?;

        let rel: serde_json::Value = client
            .get("https://api.github.com/repos/SagerNet/sing-box/releases/latest")
            .send()?
            .json()?;

        let tag = rel["tag_name"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no tag"))?;
        let version = tag.trim_start_matches('v');

        println!("[stls] downloading sing-box {version}...");
        let zip_name = format!("sing-box-{version}-windows-amd64.zip");
        let url =
            format!("https://github.com/SagerNet/sing-box/releases/download/{tag}/{zip_name}");

        let bytes = client.get(&url).send()?.error_for_status()?.bytes()?;

        println!("[stls] extracting...");
        let reader = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader)?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let name = file.name().to_string();
            if name.ends_with("sing-box.exe") {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;
                let mut out = fs::File::create(&exe)?;
                out.write_all(&buf)?;
                println!("[stls] sing-box ready");
                return Ok(exe);
            }
        }

        bail!("sing-box.exe not found in release")
    }
}

// ── DNS resolver for STLS server IP (used to build TUN bypass) ────

fn resolve_hostname(host: &str) -> Result<Vec<String>> {
    let addr_str = format!("{host}:0");
    let addrs = addr_str
        .to_socket_addrs()
        .context("DNS resolution failed")?;
    let mut ips: Vec<String> = Vec::new();
    for addr in addrs {
        let ip = addr.ip().to_string();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    if ips.is_empty() {
        bail!("no IPs resolved for {host}");
    }
    println!("[stls] resolved {host} -> {:?}", ips);
    Ok(ips)
}

// ── tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify VPN DNS config uses modern schema (type field, no legacy address).
    #[test]
    fn vpn_dns_uses_modern_schema() {
        // Build minimal config to test serialization
        let cfg = SbConfig {
            log: SbLog { disabled: false, level: "info".into(), timestamp: true },
            dns: Some(SbDns {
                servers: vec![
                    SbDnsServer {
                        typ: "tcp".into(),
                        tag: "dns-remote".into(),
                        server: Some("8.8.8.8".into()),
                        server_port: Some(53),
                        detour: None,
                    },
                ],
                rules: Some(vec![SbDnsRule {
                    server: Some("dns-remote".into()),
                }]),
                strategy: Some("prefer_ipv4".into()),
            }),
            inbounds: vec![],
            outbounds: vec![],
            route: None,
        };

        let json = serde_json::to_value(&cfg).unwrap();
        let dns = json["dns"].as_object().unwrap();

        // Must NOT have deprecated fields
        assert!(!dns.contains_key("independent_cache"));

        let servers = dns["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 1);

        for server in servers {
            let typ = server["type"].as_str().unwrap();
            assert!(!server.contains_key("address"));
            assert!(!server.contains_key("transport"));
            assert!(!server.contains_key("detour"));

            match typ {
                "tcp" => {
                    assert!(server["server"].is_string());
                    assert!(server["server_port"].is_u64());
                }
                other => panic!("unexpected DNS server type: {other}"),
            }
        }
    }
}
