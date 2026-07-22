// wd_engine.rs — WinDivert TCP intercept engine (reflection pattern)
//
// Architecture (ProxyBridge/streamdump):
// 1. App outbound SYN → reflect INBOUND (swap src↔dst, dst_port=RELAY_PORT, impostor=TRUE)
// 2. Relay accepts connection from google.com:app_port → SOCKS5 → proxy → VPS
// 3. Relay writes response to accepted socket → OUTBOUND with SrcPort=RELAY_PORT
// 4. packet_loop catches relay response → un-reflect → INBOUND with impostor=TRUE
// 5. App receives data matching its socket 4-tuple
//
// Two WinDivert handles would be cleaner but we can do it with one:
// - Filter: not impostor and tcp and (outbound) → catches both app outbound AND relay responses
// - Distinguish by SrcPort: app uses ephemeral ports, relay uses RELAY_PORT

use crate::wd::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::thread;

const RELAY_PORT: u16 = 34010;
const MAXBUF: usize = 0xFFFF;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const CONN_TTL: Duration = Duration::from_secs(3600);
const PROXY_PORT: u16 = 1080;

// ── Connection table ───────────────────────────────────────────────

struct ConnEntry {
    dst_ip: [u8; 4],   // net byte order
    dst_port: u16,     // host byte order
    last_seen: Instant,
}

struct ConnTable {
    by_app_port: HashMap<u16, ConnEntry>,
}

impl ConnTable {
    fn new() -> Self {
        ConnTable { by_app_port: HashMap::new() }
    }

    fn insert(&mut self, app_port: u16, dst_ip: [u8; 4], dst_port: u16) {
        self.by_app_port.insert(app_port, ConnEntry {
            dst_ip, dst_port,
            last_seen: Instant::now(),
        });
    }

    fn lookup(&mut self, app_port: u16) -> Option<ConnEntry> {
        if let Some(e) = self.by_app_port.get_mut(&app_port) {
            e.last_seen = Instant::now();
            Some(ConnEntry { dst_ip: e.dst_ip, dst_port: e.dst_port, last_seen: e.last_seen })
        } else {
            None
        }
    }

    fn remove(&mut self, app_port: u16) {
        self.by_app_port.remove(&app_port);
    }

    fn cleanup(&mut self) {
        let cutoff = Instant::now() - CONN_TTL;
        self.by_app_port.retain(|_, v| v.last_seen > cutoff);
    }

    fn len(&self) -> usize { self.by_app_port.len() }
}

unsafe impl Send for WinDivert {}
unsafe impl Sync for WinDivert {}

// ── Engine ─────────────────────────────────────────────────────────

pub struct WdEngine {
    running: Arc<AtomicBool>,
    conn_table: Arc<Mutex<ConnTable>>,
    _dll_path: String,
}

impl WdEngine {
    pub fn new(dll_path: &str) -> Self {
        WdEngine {
            running: Arc::new(AtomicBool::new(false)),
            conn_table: Arc::new(Mutex::new(ConnTable::new())),
            _dll_path: dll_path.to_string(),
        }
    }

    pub fn start(&self, filter: &str) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            return Err("Already running".into());
        }
        self.running.store(true, Ordering::SeqCst);

        let mut wd = WinDivert::load(std::path::Path::new(&self._dll_path))
            .ok_or_else(|| format!("Load WinDivert.dll failed from {}", self._dll_path))?;
        wd.open(filter, WINDIVERT_LAYER_NETWORK, 123, 0)?;
        wd.set_param(WINDIVERT_PARAM_QUEUE_LENGTH, 16384).ok();
        wd.set_param(WINDIVERT_PARAM_QUEUE_TIME, 2000).ok();
        wd.set_param(WINDIVERT_PARAM_QUEUE_SIZE, 33553920).ok();

        let wd = Arc::new(wd);

        // Thread 1: packet loop
        {
            let wd = wd.clone();
            let running = self.running.clone();
            let ct = self.conn_table.clone();
            thread::spawn(move || packet_loop(wd, running, ct));
        }

        // Thread 2: relay listener
        {
            let ct = self.conn_table.clone();
            let running = self.running.clone();
            thread::spawn(move || relay_listener(RELAY_PORT, PROXY_PORT, ct, running));
        }

        // Thread 3: cleanup
        {
            let ct = self.conn_table.clone();
            let running = self.running.clone();
            thread::spawn(move || cleanup_loop(ct, running));
        }

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

// ═════════════════════════════════════════════════════════════════════
// PACKET LOOP
// ═════════════════════════════════════════════════════════════════════

fn packet_loop(wd: Arc<WinDivert>, running: Arc<AtomicBool>, ct: Arc<Mutex<ConnTable>>) {
    let mut buf = [0u8; MAXBUF];

    while running.load(Ordering::SeqCst) {
        match wd.recv(&mut buf) {
            Ok((pkt_len, addr)) => {
                let pkt = &buf[..pkt_len as usize];
                // Determine direction by checking SrcPort
                let ip_hl = if pkt.len() >= 20 { (pkt[0] & 0x0F) as usize * 4 } else { 20 };
                if pkt.len() < ip_hl + 20 { continue; }
                let src_port = u16::from_be_bytes([pkt[ip_hl], pkt[ip_hl + 1]]);

                if src_port == RELAY_PORT {
                    // Relay response → un-reflect back to app
                    handle_relay_response(&wd, pkt, &addr, &ct);
                } else if addr.is_outbound() {
                    // App outbound → reflect to relay (if TCP SYN or tracked)
                    handle_app_outbound(&wd, pkt, &addr, &ct);
                } else {
                    let _ = wd.send(pkt, &addr);
                }
            }
            Err(e) => {
                eprintln!("[wd] recv: {e}");
                thread::sleep(Duration::from_millis(100));
                if !running.load(Ordering::SeqCst) { break; }
            }
        }
    }
    eprintln!("[wd] packet loop ended");
}

/// App outbound: capture SYN or tracked-connection data, reflect to relay
fn handle_app_outbound(wd: &WinDivert, pkt: &[u8], addr: &WINDIVERT_ADDRESS, ct: &Arc<Mutex<ConnTable>>) {
    let ip_hl = (pkt[0] & 0x0F) as usize * 4;
    let tcp_off = ip_hl;
    if pkt.len() < tcp_off + 20 { let _ = wd.send(pkt, addr); return; }

    let src_port = u16::from_be_bytes([pkt[tcp_off], pkt[tcp_off + 1]]);
    let dst_port = u16::from_be_bytes([pkt[tcp_off + 2], pkt[tcp_off + 3]]);
    let flags = pkt[tcp_off + 13];
    let is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0;
    let is_fin = (flags & 0x01) != 0;
    let is_rst = (flags & 0x04) != 0;

    // Capture SYN or data on tracked connection
    let mut tracked = false;
    if is_syn {
        let mut dst_ip = [0u8; 4];
        dst_ip.copy_from_slice(&pkt[16..20]);
        ct.lock().unwrap().insert(src_port, dst_ip, dst_port);
        tracked = true;
    } else {
        tracked = ct.lock().unwrap().lookup(src_port).is_some();
    }

    if !tracked {
        let _ = wd.send(pkt, addr);
        return;
    }

    if is_fin || is_rst {
        ct.lock().unwrap().remove(src_port);
    }

    // Reflect: swap src↔dst, set dst_port=RELAY_PORT, inject inbound with impostor
    let mut mod_pkt = pkt.to_vec();
    // Swap IP src↔dst (bytes 12-15 ↔ 16-19)
    let old_src = [mod_pkt[12], mod_pkt[13], mod_pkt[14], mod_pkt[15]];
    let old_dst = [mod_pkt[16], mod_pkt[17], mod_pkt[18], mod_pkt[19]];
    mod_pkt[12..16].copy_from_slice(&old_dst); // Src = old Dst
    mod_pkt[16..20].copy_from_slice(&old_src); // Dst = old Src
    // Change TCP dst port to relay
    let relay_be = RELAY_PORT.to_be_bytes();
    mod_pkt[tcp_off + 2] = relay_be[0];
    mod_pkt[tcp_off + 3] = relay_be[1];

    // Build modified address: set inbound + impostor + recalc
    let mut mod_addr = *addr;
    mod_addr.set_outbound(false);
    mod_addr.set_impostor(true);

    if let Err(e) = wd.calc_checksums(&mut mod_pkt, &mod_addr) {
        eprintln!("[wd] reflect chksum err: {e}");
        // Send anyway, might still work
    }
    let _ = wd.send(&mod_pkt, &mod_addr);
}

/// Relay response: un-reflect back to app's original 4-tuple
fn handle_relay_response(wd: &WinDivert, pkt: &[u8], addr: &WINDIVERT_ADDRESS, ct: &Arc<Mutex<ConnTable>>) {
    let ip_hl = (pkt[0] & 0x0F) as usize * 4;
    let tcp_off = ip_hl;
    if pkt.len() < tcp_off + 20 { let _ = wd.send(pkt, addr); return; }

    // SrcPort == RELAY_PORT, DstPort is the app's ephemeral port
    let app_port = u16::from_be_bytes([pkt[tcp_off + 2], pkt[tcp_off + 3]]);

    let entry = match ct.lock().unwrap().lookup(app_port) {
        Some(e) => e,
        None => {
            // Unknown → let it pass (will go nowhere useful)
            let _ = wd.send(pkt, addr);
            return;
        }
    };

    // Un-reflect: restore original 4-tuple
    // Current: SrcIP=local_ip:34010, DstIP=original_dst_ip:app_port
    // Want:    SrcIP=original_dst_ip:original_dst_port, DstIP=local_ip:app_port
    let mut mod_pkt = pkt.to_vec();

    // DstIP (bytes 16-19) is currently the original dst_ip (from reflection).
    // We need:
    //   SrcIP ← DstIP (currently original_dst_ip, restore)
    //   DstIP ← SrcIP (currently local_ip, restore)
    //   SrcPort ← original_dst_port
    //   DstPort ← app_port (already correct)

    // Swap IP src↔dst
    let old_src = [mod_pkt[12], mod_pkt[13], mod_pkt[14], mod_pkt[15]];
    let old_dst = [mod_pkt[16], mod_pkt[17], mod_pkt[18], mod_pkt[19]];
    mod_pkt[12..16].copy_from_slice(&old_dst); // SrcIP = DstIP (original dst)
    mod_pkt[16..20].copy_from_slice(&old_src); // DstIP = SrcIP (local ip)

    // Restore original dst port as src port
    let dst_port_be = entry.dst_port.to_be_bytes();
    mod_pkt[tcp_off] = dst_port_be[0];     // SrcPort = original dst
    mod_pkt[tcp_off + 1] = dst_port_be[1];

    // DstPort stays as app_port (already correct)

    // Build modified address: inbound + impostor
    let mut mod_addr = *addr;
    mod_addr.set_outbound(false);
    mod_addr.set_impostor(true);

    if let Err(e) = wd.calc_checksums(&mut mod_pkt, &mod_addr) {
        eprintln!("[wd] unreflect chksum err: {e}");
    }
    let _ = wd.send(&mod_pkt, &mod_addr);
}

// ═════════════════════════════════════════════════════════════════════
// RELAY LISTENER
// ═════════════════════════════════════════════════════════════════════
// Each reflected SYN arrives as an INBOUND connection to :RELAY_PORT.
// The relay accept() sees peer = (original_dst_ip, app_eph_port).
// Look up app_port to get original dst_port, then SOCKS5 connect to proxy.

fn relay_listener(
    relay_port: u16,
    proxy_port: u16,
    ct: Arc<Mutex<ConnTable>>,
    running: Arc<AtomicBool>,
) {
    let listener = match TcpListener::bind(format!("0.0.0.0:{relay_port}")) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[relay] bind :{relay_port}: {e}");
            return;
        }
    };
    listener.set_nonblocking(true).ok();
    eprintln!("[relay] listening on :{relay_port}");

    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let app_port = peer.port();
                let entry = ct.lock().unwrap().lookup(app_port);
                match entry {
                    Some(e) => {
                        let orig_ip = std::net::Ipv4Addr::new(
                            e.dst_ip[0], e.dst_ip[1], e.dst_ip[2], e.dst_ip[3]
                        );
                        eprintln!("[relay] accept app:{app_port} → {orig_ip}:{}", e.dst_port);
                        let proxy_addr = format!("127.0.0.1:{proxy_port}");
                        let ct = ct.clone();
                        thread::spawn(move || {
                            handle_relay(stream, &proxy_addr, orig_ip, e.dst_port, app_port, ct);
                        });
                    }
                    None => {
                        eprintln!("[relay] no table entry for port {app_port}, close");
                        drop(stream);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("[relay] accept err: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn handle_relay(
    mut app: TcpStream,
    proxy_addr: &str,
    orig_ip: std::net::Ipv4Addr,
    orig_port: u16,
    app_port: u16,
    ct: Arc<Mutex<ConnTable>>,
) {
    let mut proxy = match TcpStream::connect(proxy_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[relay] proxy connect '{proxy_addr}': {e}");
            return;
        }
    };

    if let Err(e) = socks5_connect(&mut proxy, &std::net::IpAddr::V4(orig_ip), orig_port) {
        eprintln!("[relay] socks5 {orig_ip}:{orig_port}: {e}");
        return;
    }

    eprintln!("[relay] proxying {orig_ip}:{orig_port}");

    let (mut ar, mut aw) = (app.try_clone().unwrap(), app.try_clone().unwrap());
    let (mut pr, mut pw) = (proxy.try_clone().unwrap(), proxy.try_clone().unwrap());

    let a2p = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match ar.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => { let _ = pw.write_all(&buf[..n]); }
            }
        }
    });

    let p2a = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match pr.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => { let _ = aw.write_all(&buf[..n]); }
            }
        }
    });

    a2p.join().ok();
    p2a.join().ok();

    ct.lock().unwrap().remove(app_port);
}

// ═════════════════════════════════════════════════════════════════════
// SOCKS5 CLIENT (RFC 1928)
// ═════════════════════════════════════════════════════════════════════

fn socks5_connect(stream: &mut TcpStream, addr: &std::net::IpAddr, port: u16) -> Result<(), String> {
    let mut buf = [0u8; 260];
    buf[0] = 5; buf[1] = 1; buf[2] = 0;
    stream.write_all(&buf[..3]).map_err(|e| format!("w auth: {e}"))?;
    stream.read_exact(&mut buf[..2]).map_err(|e| format!("r auth: {e}"))?;
    if buf[0] != 5 || buf[1] != 0 {
        return Err(format!("auth fail: {buf:02x?}"));
    }
    buf[0] = 5; buf[1] = 1; buf[2] = 0;
    let off;
    match addr {
        std::net::IpAddr::V4(v4) => { buf[3] = 1; buf[4..8].copy_from_slice(&v4.octets()); off = 8; }
        std::net::IpAddr::V6(v6) => { buf[3] = 4; buf[4..20].copy_from_slice(&v6.octets()); off = 20; }
    }
    buf[off] = (port >> 8) as u8;
    buf[off + 1] = (port & 0xFF) as u8;
    stream.write_all(&buf[..off + 2]).map_err(|e| format!("w conn: {e}"))?;
    stream.read_exact(&mut buf[..4]).map_err(|e| format!("r conn: {e}"))?;
    if buf[0] != 5 || buf[1] != 0 {
        return Err(format!("conn rejected: reply={}", buf[1]));
    }
    let drain_size = match buf[3] {
        1 => 6,
        4 => 18,
        3 => {
            let _ = stream.read_exact(&mut buf[..1]);
            buf[0] as usize + 2
        }
        _ => 0,
    };
    if drain_size > 0 { let _ = stream.read_exact(&mut buf[..drain_size.min(260)]); }
    Ok(())
}

// ═════════════════════════════════════════════════════════════════════
// CLEANUP
// ═════════════════════════════════════════════════════════════════════

fn cleanup_loop(ct: Arc<Mutex<ConnTable>>, running: Arc<AtomicBool>) {
    while running.load(Ordering::SeqCst) {
        thread::sleep(CLEANUP_INTERVAL);
        let mut t = ct.lock().unwrap();
        let before = t.len();
        t.cleanup();
        let after = t.len();
        if before != after {
            eprintln!("[wd] cleanup: {before} → {after}");
        }
    }
}
