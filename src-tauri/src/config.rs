// config.rs - App configuration management
use anyhow::Result;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_address: String,
    pub ss_port: u16,
    pub ss_password: String,
    pub stls_port: u16,
    pub stls_password: String,
    pub stls_sni: String,
    pub socks5_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub config: Config,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileStore {
    pub profiles: Vec<Profile>,
    pub active_profile: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_address: "ns.baft.uk".to_string(),
            ss_port: 8380,
            ss_password: "tE+3/qlN/orCZRVUutWouysZ8BQs4RWzq46WK6CDGG4=".to_string(),
            stls_port: 8553,
            stls_password: "y2lachetore".to_string(),
            stls_sni: "dl.google.com".to_string(),
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

impl ProfileStore {
    fn profiles_path() -> Result<PathBuf> {
        let proj_dirs = ProjectDirs::from("com", "stls", "stls")
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?;
        let config_dir = proj_dirs.config_dir();
        fs::create_dir_all(config_dir)?;
        Ok(config_dir.join("profiles.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::profiles_path()?;
        if !path.exists() {
            // Create default profile from current config
            let default_config = Config::load().unwrap_or_default();
            return Ok(Self {
                profiles: vec![Profile {
                    name: "Default".to_string(),
                    config: default_config,
                }],
                active_profile: "Default".to_string(),
            });
        }
        let content = fs::read_to_string(&path)?;
        let store: ProfileStore = serde_json::from_str(&content)?;
        Ok(store)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::profiles_path()?;
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&path, content)?;
        Ok(())
    }

    pub fn get_active_config(&self) -> Result<Config> {
        self.profiles
            .iter()
            .find(|p| p.name == self.active_profile)
            .map(|p| p.config.clone())
            .ok_or_else(|| anyhow::anyhow!("Active profile not found"))
    }

    pub fn add_profile(&mut self, name: String, config: Config) -> Result<()> {
        if self.profiles.iter().any(|p| p.name == name) {
            anyhow::bail!("Profile '{}' already exists", name);
        }
        self.profiles.push(Profile { name, config });
        self.save()
    }

    pub fn delete_profile(&mut self, name: &str) -> Result<()> {
        if name == "Default" {
            anyhow::bail!("Cannot delete Default profile");
        }
        if self.active_profile == name {
            anyhow::bail!("Cannot delete active profile");
        }
        self.profiles.retain(|p| p.name != name);
        self.save()
    }

    pub fn switch_profile(&mut self, name: &str) -> Result<()> {
        if !self.profiles.iter().any(|p| p.name == name) {
            anyhow::bail!("Profile '{}' not found", name);
        }
        self.active_profile = name.to_string();
        self.save()
    }
}
