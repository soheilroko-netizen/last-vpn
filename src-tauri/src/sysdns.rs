// sysdns.rs - Windows system DNS management via netsh
// Finds the default internet-facing interface dynamically (no hardcoded names).
// Saves/restores DNS settings so VPN mode can use 8.8.8.8 (bypasses TUN).

use anyhow::{Context, Result};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct SavedDnsState {
    pub interface: String,
    pub servers: Vec<String>,
    pub was_dhcp: bool,
}

/// Get the name of the interface that has a default gateway (internet-facing).
/// Uses `route print 0.0.0.0` and picks the first interface with metric >0.
fn find_default_interface() -> Result<String> {
    eprintln!("[stls] DNS: find_default_interface() — route print 0.0.0.0");
    // Method: parse `route print 0.0.0.0` which shows the default route with interface name.
    // Output format:
    //   IPv4 Route Table
    //   ===================
    //   Active Routes:
    //   Network Destination        Netmask          Gateway       Interface  Metric
    //   0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.100    25
    let out = Command::new("route")
        .args(["print", "0.0.0.0"])
        .output()
        .context("failed to run route print")?;
    if !out.status.success() {
        anyhow::bail!("route print failed");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    eprintln!("[stls] DNS: route print output:\n{}", text.lines().take(20).collect::<Vec<_>>().join("\n"));

    // Find the line starting with "0.0.0.0" after "Active Routes:"
    let mut in_active = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "Active Routes:" {
            in_active = true;
            continue;
        }
        if !in_active {
            continue;
        }
        if trimmed.starts_with("0.0.0.0") {
            // Columns: dest, netmask, gateway, interface, metric
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 5 {
                let iface_ip = parts[3];
                eprintln!("[stls] DNS: found default route via IP {iface_ip}");
                // Now resolve interface name from IP using `netsh interface ip show config`
                return resolve_interface_name(iface_ip);
            }
        }
    }

    // Fallback: parse `netsh interface ip show dns` for any interface with a real DNS server
    let out2 = Command::new("netsh")
        .args(["interface", "ip", "show", "dns"])
        .output()
        .context("failed to run netsh interface ip show dns")?;
    let text2 = String::from_utf8_lossy(&out2.stdout);
    let mut current_iface: Option<String> = None;
    for line in text2.lines() {
        let trimmed = line.trim();
        if let Some(name) = parse_iface_header(trimmed) {
            current_iface = Some(name);
            continue;
        }
        if let Some(ref iface) = current_iface {
            if has_dns_entry(trimmed) {
                return Ok(iface.clone());
            }
        }
    }

    anyhow::bail!("no default-route interface with DNS found")
}

/// Given an interface IP, find the interface name from `netsh interface ip show config`.
fn resolve_interface_name(ip: &str) -> Result<String> {
    eprintln!("[stls] DNS: resolve_interface_name(ip=\"{ip}\")");
    let out = Command::new("netsh")
        .args(["interface", "ip", "show", "config"])
        .output()
        .context("failed to run netsh interface ip show config")?;
    let text = String::from_utf8_lossy(&out.stdout);
    eprintln!("[stls] DNS: netsh ip show config:\n{}", text.lines().take(30).collect::<Vec<_>>().join("\n"));

    // Format:
    //   Configuration for interface "Ethernet":
    //       DHCP enabled:        Yes
    //       IP Address:          192.168.1.100
    let mut current_iface: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(name) = parse_iface_header(trimmed) {
            current_iface = Some(name);
            continue;
        }
        if let Some(ref iface) = current_iface {
            if trimmed.starts_with("IP Address:") || trimmed.starts_with("IPv4 Address:") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 3 && parts.last().map(|p| p.trim()) == Some(ip) {
                    eprintln!("[stls] DNS: resolved interface \"{iface}\" via IP {ip}");
                    return Ok(iface.clone());
                }
                // Also check if it's "IP Address: 192.168.1.100(preferred)" etc.
                for part in &parts {
                    if part.trim_end_matches("(preferred)") == ip {
                        eprintln!("[stls] DNS: resolved interface \"{iface}\" via IP {ip} (preferred)");
                        return Ok(iface.clone());
                    }
                }
            }
        }
    }

    anyhow::bail!("could not resolve IP {ip} to interface name")
}

fn parse_iface_header(line: &str) -> Option<String> {
    let line = line.trim();
    // "Configuration for interface "Ethernet":"
    // "Configuration for interface "Wi-Fi":"
    if let Some(rest) = line.strip_prefix(r#"Configuration for interface ""#) {
        if let Some(name) = rest.strip_suffix('"') {
            return Some(name.to_string());
        }
        if let Some(name) = rest.strip_suffix("\":") {
            return Some(name.to_string());
        }
        // Try splitting at last quote
        if let Some(idx) = rest.rfind('"') {
            return Some(rest[..idx].to_string());
        }
    }
    None
}

fn has_dns_entry(line: &str) -> bool {
    let trimmed = line.trim();
    let has_dns_keyword =
        trimmed.contains("DNS server") || trimmed.contains("DNS Servers") || trimmed.contains("DHCP");
    if !has_dns_keyword || !trimmed.contains(':') {
        return false;
    }
    let after_colon = trimmed.split(':').last().unwrap_or("").trim();
    !after_colon.is_empty() && after_colon != "None"
}

/// Snapshot current DNS settings for the default interface.
pub fn take_snapshot() -> Result<SavedDnsState> {
    let iface = find_default_interface()?;
    eprintln!("[stls] DNS: take_snapshot() for interface \"{iface}\"");
    let out = Command::new("netsh")
        .args(["interface", "ip", "show", "dns", &iface])
        .output()
        .context("failed to query DNS for interface")?;

    let text = String::from_utf8_lossy(&out.stdout);
    eprintln!("[stls] DNS: netsh ip show dns \"{iface}\":\n{}", text.lines().take(20).collect::<Vec<_>>().join("\n"));
    let mut servers: Vec<String> = Vec::new();
    let mut was_dhcp = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.contains("DHCP") && trimmed.contains("DNS") {
            was_dhcp = true;
        }
        if trimmed.contains("Statically Configured DNS Servers") {
            // If this line shows "None", it means no static DNS - but we treat as static
            // (the DHCP flag was set earlier if appropriate)
        }
        // Extract IPs after colon
        if (trimmed.contains("DHCP") || trimmed.contains("Servers")) && trimmed.contains(':') {
            let after = trimmed.split(':').last().unwrap_or("").trim();
            for part in after.split_whitespace() {
                let part = part.trim_end_matches(',').trim_end_matches(')');
                if is_ipv4(part) {
                    servers.push(part.to_string());
                }
            }
        }
    }

    eprintln!("[stls] DNS: snapshot — was_dhcp={was_dhcp}, servers={:?}", servers);
    Ok(SavedDnsState {
        interface: iface,
        servers,
        was_dhcp,
    })
}

/// Set DNS server for the given interface to a static IP.
pub fn set_dns(interface: &str, server: &str) -> Result<()> {
    eprintln!("[stls] DNS: set_dns(interface=\"{interface}\", server=\"{server}\")");
    let out = Command::new("netsh")
        .args(["interface", "ip", "set", "dns", "name", interface, "static", server])
        .output()
        .context("failed to run netsh set dns")?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("[stls] DNS: netsh exit={:?} stdout={:?} stderr={:?}",
        out.status.code(), stdout.trim(), stderr.trim());

    if !out.status.success() {
        anyhow::bail!(
            "netsh set dns name \"{interface}\" static {server} failed (exit={:?}): {stderr}",
            out.status.code()
        );
    }
    println!("[stls] DNS {interface} -> {server}");
    Ok(())
}

/// Restore saved DNS state: either revert to original static servers or return to DHCP.
pub fn restore(saved: &SavedDnsState) -> Result<()> {
    eprintln!("[stls] DNS: restore() — interface=\"{}\" was_dhcp={} servers={:?}",
        saved.interface, saved.was_dhcp, saved.servers);
    if saved.was_dhcp {
        let out = Command::new("netsh")
            .args(["interface", "ip", "set", "dns", "name", &saved.interface, "dhcp"])
            .output()
            .context("failed to restore DHCP DNS")?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!("[stls] DNS: restore DHCP exit={:?} stderr={:?}", out.status.code(), stderr.trim());
        if !out.status.success() {
            anyhow::bail!("netsh set dns {} dhcp failed (exit={:?}): {stderr}", saved.interface, out.status.code());
        }
        println!("[stls] DNS {} -> DHCP (restored)", saved.interface);
    } else if let Some(original) = saved.servers.first() {
        let out = Command::new("netsh")
            .args(["interface", "ip", "set", "dns", "name", &saved.interface, "static", original])
            .output()
            .context("failed to restore static DNS")?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!("[stls] DNS: restore static exit={:?} stderr={:?}", out.status.code(), stderr.trim());
        if !out.status.success() {
            anyhow::bail!("netsh set dns {} {} failed (exit={:?}): {stderr}", saved.interface, original, out.status.code());
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
    fn test_parse_iface_header() {
        assert_eq!(
            parse_iface_header(r#"Configuration for interface "Ethernet":"#).as_deref(),
            Some("Ethernet")
        );
        assert_eq!(
            parse_iface_header(r#"Configuration for interface "Wi-Fi":"#).as_deref(),
            Some("Wi-Fi")
        );
        assert_eq!(
            parse_iface_header(r#"Configuration for interface "Local Area Connection* 10":"#).as_deref(),
            Some("Local Area Connection* 10")
        );
        assert!(parse_iface_header("   something else:").is_none());
    }

    #[test]
    fn test_has_dns_entry() {
        assert!(has_dns_entry("    DNS servers configured through DHCP:  8.8.8.8"));
        assert!(has_dns_entry("    Statically Configured DNS Servers:    1.1.1.1"));
        assert!(!has_dns_entry("    Register with which suffix:           Primary only"));
        assert!(!has_dns_entry("    Statically Configured DNS Servers:     None"));
    }
}
