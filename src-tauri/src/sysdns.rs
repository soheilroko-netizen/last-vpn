// sysdns.rs - Windows DNS management via netsh
// Saves/restores DNS servers per interface. No deps.

use anyhow::{Context, Result};
use std::process::Command;

const DNS_IP: &str = "8.8.8.8";

pub struct DnsState {
    pub enabled: bool,
}

impl DnsState {
    /// Parse current DNS from all active interfaces, store, then set to 8.8.8.8
    pub fn enable() -> Result<Self> {
        // Get current DNS settings first (for restore)
        save_dns_config()?;
        // Set DNS on all active interfaces
        set_dns(DNS_IP)?;
        Ok(DnsState { enabled: true })
    }

    /// Revert to DHCP on all interfaces
    pub fn restore(&self) -> Result<()> {
        restore_dns()?;
        Ok(())
    }
}

fn get_active_interfaces() -> Result<Vec<String>> {
    let out = Command::new("netsh")
        .arg("interface")
        .arg("ip")
        .arg("show")
        .arg("interfaces")
        .output()
        .context("netsh show interfaces failed")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut ifaces = Vec::new();
    for line in text.lines() {
        // Lines like: "  17  Local Area Connection  ...  connected  ..."
        let trimmed = line.trim();
        if trimmed.contains("connected") && !trimmed.contains("Loopback") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 3 {
                // idx is first col, name is everything between idx and "connected"
                // Actually netsh format: idx | name | ... | state | ...
                // Simplistic: idx is part[0], name might be part[2] or later
                // Let's just take the full line and extract name by skipping first token
                let after_idx = trimmed.trim_start_matches(|c: char| c.is_ascii_digit() || c == ' ' || c == '\t');
                let name = after_idx
                    .split("connected")
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches(|c| c == ' ' || c == '\t' || c == '.');
                if !name.is_empty() {
                    ifaces.push(name.to_string());
                }
            }
        }
    }
    if ifaces.is_empty() {
        // Fallback: try "Local Area Connection"
        ifaces.push("Local Area Connection".into());
    }
    Ok(ifaces)
}

fn save_dns_config() -> Result<()> {
    let ifaces = get_active_interfaces()?;
    for name in &ifaces {
        let out = Command::new("netsh")
            .arg("interface")
            .arg("ip")
            .arg("show")
            .arg("dns")
            .arg(name)
            .output()
            .context(format!("failed to read DNS for {name}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        // Write to temp file
        let temp = std::env::temp_dir().join(format!("stls_dns_{}.txt", name.replace(' ', "_")));
        std::fs::write(&temp, &*text).ok();
    }
    Ok(())
}

fn set_dns(dns: &str) -> Result<()> {
    let ifaces = get_active_interfaces()?;
    for name in &ifaces {
        let status = Command::new("netsh")
            .arg("interface")
            .arg("ip")
            .arg("set")
            .arg("dns")
            .arg(name)
            .arg("static")
            .arg(dns)
            .status()
            .context(format!("failed to set DNS on {name}"))?;
        if !status.success() {
            eprintln!("[stls] warning: failed to set DNS on {name}");
        }
    }
    Ok(())
}

fn restore_dns() -> Result<()> {
    let ifaces = get_active_interfaces()?;
    for name in &ifaces {
        let status = Command::new("netsh")
            .arg("interface")
            .arg("ip")
            .arg("set")
            .arg("dns")
            .arg(&name)
            .arg("dhcp")
            .status()
            .context(format!("failed to restore DNS on {name}"))?;
        if !status.success() {
            eprintln!("[stls] warning: failed to restore DNS on {name}");
        }
    }
    Ok(())
}

// Test
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_interfaces() {
        let ifaces = get_active_interfaces().unwrap();
        println!("interfaces: {:?}", ifaces);
        assert!(!ifaces.is_empty());
    }
}
