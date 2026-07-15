use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose, Engine as _};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub profiles: Vec<Profile>,
    pub settings: Settings,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Settings {
    pub auto_start: bool,
    pub minimize_to_tray: bool,
    pub log_level: String,
    pub local_socks_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub shadowsocks: ShadowsocksConfig,
    pub shadowtls: ShadowTLSConfig,
    pub local_socks_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksConfig {
    pub cipher: String,
    pub password: String,
    pub server: String,
    pub port: u16,
    pub plugin: Option<String>,
    pub plugin_opts: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowTLSConfig {
    pub server: String,
    pub server_port: u16,
    pub version: u8,
    pub password: String,
    pub tls: ShadowTLSConfigTLS,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowTLSConfigTLS {
    pub enabled: bool,
    pub server_name: String,
    pub insecure: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            name: "Default".to_string(),
            shadowsocks: ShadowsocksConfig {
                cipher: "2022-blake3-chacha20-poly1305".to_string(),
                password: "".to_string(),
                server: "auto".to_string(),
                port: 0,
                plugin: None,
                plugin_opts: None,
            },
            shadowtls: ShadowTLSConfig {
                server: "".to_string(),
                server_port: 443,
                version: 3,
                password: "".to_string(),
                tls: ShadowTLSConfigTLS {
                    enabled: true,
                    server_name: "dl.google.com".to_string(),
                    insecure: false,
                },
            },
            local_socks_port: 1080,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyStatus {
    #[serde(rename = "Stopped")]
    Stopped,
    #[serde(rename = "Starting")]
    Starting,
    #[serde(rename = "Running")]
    Running { profile: String, local_port: u16 },
    #[serde(rename = "Error")]
    Error { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

pub mod socks5 {
    pub const VERSION: u8 = 0x05;
    pub const CMD_CONNECT: u8 = 0x01;
    pub const CMD_BIND: u8 = 0x02;
    pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
    pub const ATYP_IPV4: u8 = 0x01;
    pub const ATYP_DOMAIN: u8 = 0x03;
    pub const ATYP_IPV6: u8 = 0x04;
    pub const AUTH_NONE: u8 = 0x00;
    pub const AUTH_GSSAPI: u8 = 0x01;
    pub const AUTH_USERPASS: u8 = 0x02;
    pub const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

    pub const REP_SUCCESS: u8 = 0x00;
    pub const REP_GENERAL_FAILURE: u8 = 0x01;
    pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
    pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
    pub const REP_HOST_UNREACHABLE: u8 = 0x04;
    pub const REP_CONNECTION_REFUSED: u8 = 0x05;
    pub const REP_TTL_EXPIRED: u8 = 0x06;
    pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsUriParts {
    pub method: String,
    pub password: String,
    pub server: String,
    pub port: u16,
    pub name: String,
}

pub fn decode_ss_uri(uri: &str) -> Result<(String, String, String, u16), anyhow::Error> {
    if !uri.starts_with("ss://") {
        bail!("Invalid Shadowsocks URI: must start with ss://");
    }

    let uri = &uri[5..];
    let (main_part, name) = if let Some(idx) = uri.find('#') {
        (&uri[..idx], percent_decode(&uri[idx + 1..])?)
    } else {
        (uri, String::new())
    };

    let decoded = if main_part.contains('@') && !main_part.contains(':') {
        let parts: Vec<&str> = main_part.split('@').collect();
        if parts.len() != 2 {
            bail!("Invalid URI format");
        }
        let userinfo = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0])?;
        let userinfo = String::from_utf8(userinfo)?;
        format!("{}@{}", userinfo, parts[1])
    } else {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(main_part)?;
        String::from_utf8(decoded)?
    };

    let (auth_part, server_part) = decoded.split_once('@')
        .ok_or_else(|| anyhow::anyhow!("Missing @ separator"))?;
    
    let (method, password) = auth_part.split_once(':')
        .ok_or_else(|| anyhow::anyhow!("Missing : in auth part"))?;
    
    let (server, port_str) = server_part.rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("Missing : in server part"))?;
    let port = port_str.parse::<u16>()?;

    Ok((method.to_string(), password.to_string(), server.to_string(), port))
}

pub fn encode_ss_uri(method: &str, password: &str, server: &str, port: u16, name: &str) -> String {
    let userinfo = format!("{}:{}", method, password);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(userinfo.as_bytes());
    let uri = format!("ss://{}@{}:{}", encoded, server, port);
    if !name.is_empty() {
        format!("{}#{}", uri, percent_encode(name))
    } else {
        uri
    }
}

fn percent_decode(s: &str) -> Result<String, anyhow::Error> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|e| anyhow::anyhow!("Percent decode error: {}", e))
}

fn percent_encode(s: &str) -> String {
    percent_encoding::percent_encode(s.as_bytes(), percent_encoding::NON_ALPHANUMERIC).to_string()
}