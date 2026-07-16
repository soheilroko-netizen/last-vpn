// config.rs - App configuration management
use anyhow::Result;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_address: String,
    pub server_port: u16,
    pub password: String,
    pub shadowtls_password: String,
    pub shadowtls_sni: String,
    pub socks5_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_address: "ns.baft.uk".to_string(),
            server_port: 5353,
            password: "baft123".to_string(),
            shadowtls_password: "shahabshahab".to_string(),
            shadowtls_sni: "dl.google.com".to_string(),
            socks5_port: 1080,
        }
    }
}

impl Config {
    pub fn config_path() -> Result<PathBuf> {
        let proj_dirs = ProjectDirs::from("com", "stls", "stls")
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?;
        let config_dir = proj_dirs.config_dir();
        fs::create_dir_all(config_dir)?;
        Ok(config_dir.join("config.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&path, content)?;
        Ok(())
    }
}
