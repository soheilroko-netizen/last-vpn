// proxy.rs - sing-box proxy manager
use anyhow::{bail, Result};
use crate::config::Config;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
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

#[derive(Serialize)]
struct SbConfig {
    log: SbLog,
    inbounds: Vec<SbInbound>,
    outbounds: Vec<SbOutbound>,
}

#[derive(Serialize)]
struct SbLog {
    disabled: bool,
    level: String,
    timestamp: bool,
}

#[derive(Serialize)]
struct SbInbound {
    #[serde(rename = "type")]
    typ: String,
    tag: String,
    listen: String,
    listen_port: u16,
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
        })
    }

    pub fn is_running(&self) -> bool {
        self.child.lock().unwrap().is_some()
    }

    pub fn start(&mut self) -> Result<String> {
        if self.is_running() {
            bail!("Proxy already running");
        }

        // Ensure sing-box exists
        let exe = self.download_sing_box()?;

        // Write config
        let cfg = self.build_config();
        let cfg_json = serde_json::to_string_pretty(&cfg)?;
        let cfg_path = self.config_dir.join("config.json");
        fs::write(&cfg_path, &cfg_json)?;

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
                .stdout(Stdio::null())
                .stderr(Stdio::null())
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

        *self.child.lock().unwrap() = Some(child);
        
        Ok(format!("Proxy started: SOCKS5 127.0.0.1:{}", self.config.socks5_port))
    }

    pub fn stop(&mut self) -> Result<String> {
        let mut guard = self.child.lock().unwrap();
        if let Some(mut child) = guard.take() {
            child.kill()?;
            Ok("Proxy stopped".into())
        } else {
            bail!("Proxy not running")
        }
    }

    fn build_config(&self) -> SbConfig {
        let c = &self.config;
        SbConfig {
            log: SbLog {
                disabled: false,
                level: "info".into(),
                timestamp: true,
            },
            inbounds: vec![SbInbound {
                typ: "socks".into(),
                tag: "socks-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: c.socks5_port,
            }],
            outbounds: vec![
                SbOutbound {
                    typ: "shadowsocks".into(),
                    tag: "ss-out".into(),
                    server: Some(c.server_address.clone()),
                    server_port: Some(c.server_port),
                    method: Some("2022-blake3-chacha20-poly1305".into()),
                    password: Some(c.password.clone()),
                    version: None,
                    tls: None,
                    detour: Some("shadowtls-out".into()),
                },
                SbOutbound {
                    typ: "shadowtls".into(),
                    tag: "shadowtls-out".into(),
                    server: Some(c.server_address.clone()),
                    server_port: Some(c.server_port),
                    version: Some(3),
                    password: Some(c.shadowtls_password.clone()),
                    tls: Some(SbTls {
                        enabled: true,
                        server_name: c.server_address.clone(),
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
            ],
        }
    }

    fn sing_box_exe(&self) -> PathBuf {
        self.config_dir.join("sing-box.exe")
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
        
        let tag = rel["tag_name"].as_str().ok_or_else(|| anyhow::anyhow!("no tag"))?;
        let version = tag.trim_start_matches('v');
        
        println!("[stls] downloading sing-box {version}...");
        let zip_name = format!("sing-box-{version}-windows-amd64.zip");
        let url = format!("https://github.com/SagerNet/sing-box/releases/download/{tag}/{zip_name}");
        
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
