// stls v4 — minimal ShadowTLS + Shadowsocks chain proxy client (CLI)
//
// What it does:
//   1. Downloads sing-box (if missing) into the config dir.
//   2. Writes a sing-box config that chains:
//        SOCKS5 listener 127.0.0.1:1080
//          -> Shadowsocks 2022 (ns.baft.uk:8380)
//            -> ShadowTLS v3  (ns.baft.uk:8553, fake TLS to dl.google.com)
//   3. Launches sing-box and stays alive until you press Ctrl+C.
//
// Config values come from the nekoray export you provided. Edit the
// DEFAULT_CONFIG block below to change servers/passwords.

use directories::ProjectDirs;
use serde::Serialize;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Default connection profile (extracted from your nekoray links)
// ---------------------------------------------------------------------------
#[derive(Clone)]
struct Profile {
    // Shadowsocks 2022
    ss_method: String,
    ss_password: String,
    ss_server: String,
    ss_port: u16,
    // ShadowTLS v3 (wraps the Shadowsocks connection)
    stls_server: String,
    stls_port: u16,
    stls_password: String,
    stls_sni: String,
    // Local SOCKS5 listen address
    local_addr: String,
    local_port: u16,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            ss_method: "2022-blake3-chacha20-poly1305".into(),
            // from ss:// link: 2022-blake3-chacha20-poly1305:tE+3/qlN/orCZRVUutWouysZ8BQs4RWzq46WK6CDGG4=@ns.baft.uk:8380
            ss_password: "tE+3/qlN/orCZRVUutWouysZ8BQs4RWzq46WK6CDGG4=".into(),
            ss_server: "ns.baft.uk".into(),
            ss_port: 8380,
            // from nekoray custom: shadowtls ns.baft.uk:8553 v3 pw=y2lachetore sni=dl.google.com
            stls_server: "ns.baft.uk".into(),
            stls_port: 8553,
            stls_password: "y2lachetore".into(),
            stls_sni: "dl.google.com".into(),
            // nekoray listen port
            local_addr: "127.0.0.1".into(),
            local_port: 1080,
        }
    }
}

// ---------------------------------------------------------------------------
// sing-box JSON config (subset of the schema we need)
// ---------------------------------------------------------------------------
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
    outbounds: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detour: Option<String>,
}

#[derive(Serialize)]
struct SbTls {
    enabled: bool,
    server_name: String,
    insecure: bool,
}

fn build_config(p: &Profile) -> SbConfig {
    SbConfig {
        log: SbLog {
            disabled: false,
            level: "info".into(),
            timestamp: true,
        },
        inbounds: vec![SbInbound {
            typ: "socks".into(),
            tag: "socks-in".into(),
            listen: p.local_addr.clone(),
            listen_port: p.local_port,
        }],
        outbounds: vec![
            // 1) Outer outbound the SOCKS listener uses: Shadowsocks 2022 encrypts
            //    app traffic, then detours through ShadowTLS for fake-TLS wrapping.
            SbOutbound {
                typ: "shadowsocks".into(),
                tag: "ss-out".into(),
                server: Some(p.ss_server.clone()),
                server_port: Some(p.ss_port),
                method: Some(p.ss_method.clone()),
                password: Some(p.ss_password.clone()),
                version: None,
                tls: None,
                // wrap the SS connection inside ShadowTLS
                detour: Some("shadowtls-out".into()),
                outbounds: None,
            },
            // 2) Inner outbound: ShadowTLS v3 connects to the remote STLS port.
            SbOutbound {
                typ: "shadowtls".into(),
                tag: "shadowtls-out".into(),
                server: Some(p.stls_server.clone()),
                server_port: Some(p.stls_port),
                version: Some(3),
                password: Some(p.stls_password.clone()),
                tls: Some(SbTls {
                    enabled: true,
                    server_name: p.stls_sni.clone(),
                    insecure: false,
                }),
                outbounds: None,
                detour: None,
                method: None,
            },
            // 3) Direct (kept for safety)
            SbOutbound {
                typ: "direct".into(),
                tag: "direct".into(),
                server: None,
                server_port: None,
                method: None,
                password: None,
                version: None,
                tls: None,
                outbounds: None,
                detour: None,
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// sing-box downloader (Windows x86_64)
// ---------------------------------------------------------------------------
fn config_dir() -> PathBuf {
    ProjectDirs::from("", "", "stls")
        .map(|d| d.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn sing_box_exe(dir: &Path) -> PathBuf {
    dir.join("sing-box.exe")
}

fn download_sing_box(dir: &Path) -> Result<PathBuf, String> {
    let exe = sing_box_exe(dir);
    if exe.exists() {
        return Ok(exe);
    }
    fs::create_dir_all(dir).map_err(|e| format!("create config dir: {e}"))?;

    // Resolve latest stable version tag from GitHub API.
    println!("[stls] resolving latest sing-box release...");
    let client = reqwest::blocking::Client::builder()
        .user_agent("stls")
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let rel: serde_json::Value = client
        .get("https://api.github.com/repos/SagerNet/sing-box/releases/latest")
        .send()
        .map_err(|e| format!("github api: {e}"))?
        .json()
        .map_err(|e| format!("github api json: {e}"))?;
    let tag = rel["tag_name"]
        .as_str()
        .ok_or_else(|| "no tag_name in release".to_string())?;
    let version = tag.trim_start_matches('v');
    println!("[stls] latest sing-box = {version}");

    // Asset name pattern: sing-box-{version}-windows-amd64.zip
    let zip_name = format!("sing-box-{version}-windows-amd64.zip");
    let url = format!("https://github.com/SagerNet/sing-box/releases/download/{tag}/{zip_name}");
    println!("[stls] downloading {url}");
    let bytes = client
        .get(&url)
        .send()
        .map_err(|e| format!("download: {e}"))?
        .error_for_status()
        .map_err(|e| format!("download status: {e}"))?
        .bytes()
        .map_err(|e| format!("body: {e}"))?;

    // Extract sing-box.exe from the zip.
    println!("[stls] extracting...");
    let reader = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| format!("zip: {e}"))?;
    let mut found = false;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| format!("zip entry: {e}"))?;
        let name = file.name().to_string();
        if name.ends_with("sing-box.exe") {
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).map_err(|e| format!("read zip: {e}"))?;
            let mut out = fs::File::create(&exe).map_err(|e| format!("write exe: {e}"))?;
            out.write_all(&buf).map_err(|e| format!("write exe: {e}"))?;
            found = true;
            break;
        }
    }
    if !found {
        return Err("sing-box.exe not found in release zip".into());
    }
    println!("[stls] sing-box ready at {}", exe.display());
    Ok(exe)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
fn main() {
    println!("stls v{VERSION} — ShadowTLS + Shadowsocks chain proxy");
    let p = Profile::default();

    let dir = config_dir();
    println!("[stls] config dir: {}", dir.display());

    // Ensure sing-box binary.
    let exe = match download_sing_box(&dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[stls] ERROR: could not obtain sing-box: {e}");
            eprintln!("[stls] Install it manually: https://sing-box.sagernet.org/");
            std::process::exit(1);
        }
    };

    // Write sing-box config.
    let cfg = build_config(&p);
    let cfg_json = serde_json::to_string_pretty(&cfg).expect("serialize config");
    let cfg_path = dir.join("config.json");
    fs::write(&cfg_path, &cfg_json).expect("write config");
    println!("[stls] wrote sing-box config: {}", cfg_path.display());

    println!(
        "[stls] starting proxy: SOCKS5 {}:{} -> SS {}:{} -> ShadowTLS {}:{} (SNI {})",
        p.local_addr, p.local_port, p.ss_server, p.ss_port, p.stls_server, p.stls_port, p.stls_sni
    );
    println!("[stls] press Ctrl+C to stop.");

    let child = Command::new(&exe)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn();

    let child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[stls] ERROR: failed to launch sing-box: {e}");
            std::process::exit(1);
        }
    };

    // Share the child handle so the Ctrl+C handler can kill it.
    let child = std::sync::Arc::new(std::sync::Mutex::new(Some(child)));
    let child_for_signal = child.clone();
    let _ = ctrlc::set_handler(move || {
        if let Ok(mut guard) = child_for_signal.lock() {
            if let Some(mut c) = guard.take() {
                let _ = c.kill();
            }
        }
        std::process::exit(0);
    });

    // Wait for sing-box; if it exits on its own, we exit too.
    let code = {
        let mut guard = child.lock().unwrap();
        guard.take().unwrap().wait().expect("wait for sing-box")
    };
    println!("[stls] sing-box exited with {code}");
    std::process::exit(code.code().unwrap_or(0));
}
