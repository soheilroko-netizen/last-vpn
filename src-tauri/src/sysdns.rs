// sysdns.rs - Windows system DNS management via netsh
// Saves/restores DNS settings on the default internet-facing interface.
// Used by VPN mode to set DNS to 8.8.8.8 (which has a TUN bypass rule).

use anyhow::{Context, Result};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct SavedDnsState {
    pub interface: String,
    pub servers: Vec<String>,
    pub was_dhcp: bool,
}

/// Detect the first non-loopback interface with a DNS server set.
fn find_default_interface() -> Result<String> {
    let out = Command::new("netsh")
        .args(["interface", "ip", "show", "dns"])
        .output()
        .context("failed to run netsh interface ip show dns")?;
    if !out.status.success() {
        anyhow::bail!(
            "netsh dns query failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);

    // Parse blocks like:
    //   Configuration for interface "Ethernet":
    //       DNS servers configured through DHCP:  8.8.8.8
    //   Configuration for interface "Wi-Fi":
    //       Statically Configured DNS Servers:    1.1.1.1
    let mut current_iface: Option<String> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(r#"Configuration for interface ""#) {
            if let Some(name) = rest.strip_suffix('"') {
                current_iface = Some(name.to_string());
            } else if let Some(name) = rest.strip_suffix("\":") {
                current_iface = Some(name.to_string());
            }
            continue;
        }

        // If this line has a DNS server and we know the interface, return it
        if current_iface.is_some()
            && (trimmed.contains("DNS server") || trimmed.contains("DNS Servers"))
            && trimmed.contains(':')
        {
            // Check if there's an IP after the colon
            let after_colon = trimmed.split(':').last().unwrap_or("").trim();
            if !after_colon.is_empty() && after_colon != "None" {
                return Ok(current_iface.unwrap());
            }
        }
    }

    anyhow::bail!("no internet-facing interface with DNS found")
}

/// Snapshot current DNS settings for the default interface.
///
/// Returns the interface name, current DNS servers, and whether they came from DHCP.
pub fn take_snapshot() -> Result<SavedDnsState> {
    let iface = find_default_interface()?;
    let out = Command::new("netsh")
        .args(["interface", "ip", "show", "dns", &iface])
        .output()
        .context("failed to query DNS for interface")?;

    let text = String::from_utf8_lossy(&out.stdout);
    let mut servers: Vec<String> = Vec::new();
    let mut was_dhcp = false;

    for line in text.lines() {
        let trimmed = line.trim();
        // DHCP-sourced
        if trimmed.contains("DNS servers configured through DHCP") {
            was_dhcp = true;
        }
        // Static
        if trimmed.contains("Statically Configured DNS Servers") {
            was_dhcp = false;
        }
        // Extract IP addresses (lines ending or containing IPs after colon)
        if (trimmed.contains("DHCP") || trimmed.contains("Servers")) && trimmed.contains(':') {
            let after = trimmed.split(':').last().unwrap_or("").trim();
            for part in after.split_whitespace() {
                let part = part.trim_end_matches(',');
                if is_ipv4(part) {
                    servers.push(part.to_string());
                }
            }
        }
    }

    Ok(SavedDnsState {
        interface: iface,
        servers,
        was_dhcp,
    })
}

/// Set DNS server for the given interface to a static IP.
pub fn set_dns(interface: &str, server: &str) -> Result<()> {
    let status = Command::new("netsh")
        .args(["interface", "ip", "set", "dns", "name", interface, "static", server])
        .status()
        .context("failed to set DNS via netsh")?;

    if !status.success() {
        anyhow::bail!("netsh set dns {interface} {server} failed");
    }
    println!("[stls] DNS {interface} -> {server}");
    Ok(())
}

/// Restore saved DNS state: either revert to original static servers or return to DHCP.
pub fn restore(saved: &SavedDnsState) -> Result<()> {
    if saved.was_dhcp {
        // Revert to DHCP
        let status = Command::new("netsh")
            .args(["interface", "ip", "set", "dns", "name", &saved.interface, "dhcp"])
            .status()
            .context("failed to restore DHCP DNS")?;
        if !status.success() {
            anyhow::bail!("netsh set dns {} dhcp failed", saved.interface);
        }
        println!("[stls] DNS {} -> DHCP (restored)", saved.interface);
    } else if let Some(original) = saved.servers.first() {
        let status = Command::new("netsh")
            .args([
                "interface", "ip", "set", "dns",
                "name", &saved.interface,
                "static", original,
            ])
            .status()
            .context("failed to restore static DNS")?;
        if !status.success() {
            anyhow::bail!("netsh set dns {} {} failed", saved.interface, original);
        }
        println!("[stls] DNS {} -> {} (restored)", saved.interface, original);
    }
    Ok(())
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

// ── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ipv4() {
        assert!(is_ipv4("8.8.8.8"));
        assert!(is_ipv4("192.168.1.1"));
        assert!(!is_ipv4("dns.google"));
        assert!(!is_ipv4(""));
        assert!(!is_ipv4("256.1.1.1"));
    }

    #[test]
    fn test_find_default_interface_runs() {
        // This will only pass on Windows with netsh available
        let result = find_default_interface();
        // On non-Windows, skip assertions
        #[cfg(not(target_os = "windows"))]
        let _ = result;
        #[cfg(target_os = "windows")]
        assert!(result.is_ok(), "find_default_interface failed: {:?}", result.err());
    }
}
