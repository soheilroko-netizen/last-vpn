// wd_engine.rs — WinDivert TCP intercept engine
//
// Architecture (from ProxyBridge/streamdump):
// 1. App outbound SYN → reflected INBOUND to relay (swap src↔dst, dst_port=RELAY)
// 2. Relay accepts connection → lookup original dest from connection table
// 3. Relay SOCKS5 CONNECTs to local proxy → SS→STLS→VPS
// 4. Bidirectional byte shuttle
// 5. Relay response packets are un-reflected back to app

use crate::wd::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::thread;

// ── Constants ──────────────────────────────────────────────────────

const RELAY_PORT: u16 = 34010;
const MAXBUF: usize = 0xFFFF;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const CONN_TTL: Duration = Duration::from_secs(3600);
const PROXY_PORT: u16 = 1080;

// ── Connection table ───────────────────────────────────────────────
// Stores raw network-byte-order IPs + ports as stored in packets

#[derive(Clone)]
struct ConnEntry {
    app_ip: [u8; 4],     // apps own IP (nbo)
    app_port: u16,        // app ephemeral port (nbo)
    dst_ip: [u8; 4],      // original destination IP (nbo)
    dst_port: u16,         // original destination port (nbo)
    last_seen: Instant,
}

struct ConnTable {
    by_app_port: HashMap<u16, ConnEntry>, // keyed by app_port (nbo)
}

impl ConnTable {
    fn new() -> Self {
        ConnTable { by_app_port: HashMap::new() }
    }

    fn insert(&mut self, app_port_nbo: u16, app_ip: [u8; 4], dst_ip: [u8; 4], dst_port_nbo: u16) {
        self.by_app_port.insert(app_port_nbo, ConnEntry {
            app_ip, app_port: app_port_nbo, dst_ip, dst_port: dst_port_nbo,
            last_seen: Instant::now(),
        });
    }

    fn lookup_by_app_port(&mut self, app_port_nbo: u16) -> Option<ConnEntry> {
        if let Some(e) = self.by_app_port.get_mut(&app_port_nbo) {
            e.last_seen = Instant::now();
            Some(e.clone())
        } else {
            None
        }
    }

    fn remove(&mut self, app_port_nbo: u16) {
        self.by_app_port.remove(&app_port_nbo);
    }

    fn cleanup(&mut self) {
        let cutoff = Instant::now() - CONN_TTL;
        self.by_app_port.retain(|_, v| v.last_seen > cutoff);
    }
}

// ── Thread safety for our WinDivert handle ─────────────────────────

unsafe impl Send for WinDivert {}
unsafe impl Sync for WinDivert {}

// ── Build filter string ────────────────────────────────────────────

fn build_filter(vps_ip: &str) -> String {
    format!(
        "not impostor and " \
        "tcp and (outbound) and " \
        "not ip.DstAddr == {vps_ip} and " \
        "not tcp.DstPort == {relay} and " \
        "not tcp.SrcPort == {relay} and " \
        "not tcp.DstPort == {proxy} and " \
        "not tcp.SrcPort == {proxy} and " \
        "not (ip.DstAddr >= 10.0.0.0 and ip.DstAddr <= 10.255.255.255) and " \
        "not (ip.DstAddr >= 172.16.0.0 and ip.DstAddr <= 172.31.255.255) and " \
        "not (ip.DstAddr >= 192.168.0.0 and ip.DstAddr <= 192.168.255.255) and " \
        "not (ip.DstAddr >= 127.0.0.0 and ip.DstAddr <= 127.255.255.255)",
        vps_ip = vps_ip, relay = RELAY_PORT, proxy = PROXY_PORT,
    )
}

// ── Engine ─────────────────────────────────────────────────────────

pub struct WdEngine {
    running: Arc<AtomicBool>,
    conn_table: Arc<Mutex<ConnTable>>,
    dll_path: String,
    filter: String,
    proxy_addr: String,
    proxy_port: u16,
}

impl WdEngine {
    pub fn new(dll_path: &str, vps_ip: &str) -> Self {
        let filter = build_filter(vps_ip);
        WdEngine {
            running: Arc::new(AtomicBool::new(false)),
            conn_table: Arc::new(Mutex::new(ConnTable::new())),
            dll_path: dll_path.to_string(),
            filter,
            proxy_addr: "127.0.0.1".to_string(),
            proxy_port: PROXY_PORT,
        }
    }

    pub fn start(&self) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            return Err("Already running".into());
        }
        self.running.store(true, Ordering::SeqCst);

        let mut wd = WinDivert::load(std::path::Path::new(&self.dll_path))
            .ok_or_else(|| format!("Load WinDivert.dll failed from {}", self.dll_path))?;
        wd.open(&self.filter, WINDIVERT_LAYER_NETWORK, 123, 0)?;
        wd.set_param(WINDIVERT_PARAM_QUEUE_LENGTH, 16384)?;
        wd.set_param(WINDIVERT_PARAM_QUEUE_TIME, 2000)?;
        wd.set_param(WINDIVERT_PARAM_QUEUE_SIZE, 33553920)?;

        let wd = Arc::new(Mutex::new(wd));

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
            let proxy = self.proxy_addr.clone();
            let port = self.proxy_port;
            thread::spawn(move || relay_listener(RELAY_PORT, proxy, port, ct, running));
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

fn packet_loop(wd: Arc<Mutex<WinDivert>>, running: Arc<AtomicBool>, ct: Arc<Mutex<ConnTable>>) {
    let mut buf = [0u8; MAXBUF];

    while running.load(Ordering::SeqCst) {
        // Receive packet
        let (pkt_len, addr) = {
            let wd = wd.lock().unwrap();
            match wd.recv(&mut buf) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[wd] recv: {e}");
                    break;
                }
            }
        };

        let pkt = &buf[..pkt_len as usize];
        let wd = wd.lock().unwrap();

        // Parse
        let pp = wd.parse_packet(pkt);
        let (ip, tcp) = match (pp.ip, pp.tcp) {
            (Some(ip), Some(tcp)) => (ip, tcp),
            _ => { let _ = wd.send(pkt, &addr); continue; }
        };

        // All IP/TCP values in the parsed struct are in NETWORK byte order.
        // Raw buffer at [12..16] = SrcAddr, [16..20] = DstAddr.
        let ip_hl = (ip.HdrLength & 0x0F) as usize * 4; // IP header length in bytes
        let tcp_off = ip_hl;

        if addr.is_outbound() {
            // ═══ OUTBOUND PACKET ═══

            // Is this the relay responding to the app? (src_port = RELAY_PORT)
            let raw_src_port = u16::from_ne_bytes([pkt[tcp_off], pkt[tcp_off + 1]]);

            if raw_src_port == RELAY_PORT.to_be_bytes() {
                // YES — response from relay back to app.
                // Need to "un-reflect": restore original src IP/port
                let raw_dst_port = u16::from_ne_bytes([pkt[tcp_off + 2], pkt[tcp_off + 3]]);

                let entry = ct.lock().unwrap().lookup_by_app_port(raw_dst_port);
                if let Some(entry) = entry {
                    let mut mod_pkt = pkt.to_vec();

                    // Current:  SrcIP = relay_ip, DstIP = app_ip
                    //           SrcPort = RELAY_PORT, DstPort = app_ephemeral
                    // Wanted:   SrcIP = original_dst_ip, DstIP = app_ip
                    //           SrcPort = original_dst_port, DstPort = app_ephemeral

                    // IP SrcAddr = original dst
                    mod_pkt[12..16].copy_from_slice(&entry.dst_ip);
                    // IP DstAddr = app IP (unchanged, but already there from reflection)
                    mod_pkt[16..20].copy_from_slice(&entry.app_ip);

                    // TCP SrcPort = original dst port
                    mod_pkt[tcp_off] = (entry.dst_port >> 8) as u8;
                    mod_pkt[tcp_off + 1] = (entry.dst_port & 0xFF) as u8;

                    // Mark as inbound so app receives it as a foreign response
                    let mut in_addr = addr;
                    in_addr.set_outbound(false);
                    wd.calc_checksums(&mut mod_pkt, &in_addr).ok();
                    let _ = wd.send(&mod_pkt, &in_addr);

                    if pkt[tcp_off + 13] & 0x01 != 0 || pkt[tcp_off + 13] & 0x04 != 0 {
                        ct.lock().unwrap().remove(raw_dst_port);
                    }
                } else {
                    let _ = wd.send(pkt, &addr);
                }
                continue;
            }

            // Outbound app packet
            let raw_dst_port = u16::from_ne_bytes([pkt[tcp_off + 2], pkt[tcp_off + 3]]);

            // Skip known non-proxied traffic (these should be excluded by filter anyway)
            if raw_dst_port == RELAY_PORT.to_be_bytes() || raw_dst_port == PROXY_PORT.to_be_bytes() {
                let _ = wd.send(pkt, &addr);
                continue;
            }

            // Check if this is a new SYN
            let flags = pkt[tcp_off + 13];
            let is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0;

            let raw_src_port = u16::from_ne_bytes([pkt[tcp_off], pkt[tcp_off + 1]]);

            if is_syn {
                // Record new connection
                let mut src_ip = [0u8; 4];
                let mut dst_ip = [0u8; 4];
                src_ip.copy_from_slice(&pkt[12..16]);
                dst_ip.copy_from_slice(&pkt[16..20]);

                ct.lock().unwrap().insert(
                    raw_src_port,
                    src_ip,
                    dst_ip,
                    raw_dst_port,
                );
            }

            // If tracked, reflect to relay
            let tracked = ct.lock().unwrap().lookup_by_app_port(raw_src_port);
            if let Some(entry) = tracked {
                let mut mod_pkt = pkt.to_vec();

                // Swap src/dst IP
                let src = mod_pkt[12..16].to_vec();
                let dst = mod_pkt[16..20].to_vec();
                mod_pkt[12..16].copy_from_slice(&dst);
                mod_pkt[16..20].copy_from_slice(&src);

                // Change dst port to RELAY_PORT
                mod_pkt[tcp_off + 2] = (RELAY_PORT >> 8) as u8;
                mod_pkt[tcp_off + 3] = (RELAY_PORT & 0xFF) as u8;

                // Inject as inbound (to our relay listener)
                let mut in_addr = addr;
                in_addr.set_outbound(false);
                wd.calc_checksums(&mut mod_pkt, &in_addr).ok();

                if flags & 0x01 != 0 || flags & 0x04 != 0 {
                    ct.lock().unwrap().remove(raw_src_port);
                }

                let _ = wd.send(&mod_pkt, &in_addr);
            } else {
                let _ = wd.send(pkt, &addr);
            }
        } else {
            // ═══ INBOUND PACKET ═══
            // Pass through (responses go to relay via its TCP connection, not via WinDivert)
            let _ = wd.send(pkt, &addr);
        }
    }

    eprintln!("[wd] packet loop ended");
}

// ═════════════════════════════════════════════════════════════════════
// RELAY LISTENER
// ═════════════════════════════════════════════════════════════════════

fn relay_listener(
    relay_port: u16,
    proxy_addr: String,
    proxy_port: u16,
    ct: Arc<Mutex<ConnTable>>,
    running: Arc<AtomicBool>,
) {
    let listener = match TcpListener::bind("0.0.0.0:34010") {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[relay] bind 0.0.0.0:{relay_port}: {e}");
            return;
        }
    };
    listener.set_nonblocking(true).ok();
    eprintln!("[relay] listening on :{relay_port}");

    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, peer)) => {
                eprintln!("[relay] accept {peer}");

                let proxy = proxy_addr.clone();
                let ct = ct.clone();
                let run = running.clone();
                thread::spawn(move || {
                    handle_relay(stream, &proxy, proxy_port, ct, run);
                });
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
    proxy_port: u16,
    ct: Arc<Mutex<ConnTable>>,
    running: Arc<AtomicBool>,
) {
    // Get the original destination from the reflected connection
    // The peer address on the reflected connection was [original_dst_ip]:[original_dst_port]
    // because we swapped src/dst IP on reflection, so the "peer" is the original destination
    let dst = app.peer_addr().unwrap();
    let orig_ip = dst.ip();
    let orig_port = dst.port();

    eprintln!("[relay] orig dest = {orig_ip}:{orig_port}");

    // Connect to local proxy
    let mut proxy = match TcpStream::connect(format!("{proxy_addr}:{proxy_port}")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[relay] proxy connect fail: {e}");
            return;
        }
    };

    // SOCKS5 CONNECT
    if let Err(e) = socks5_connect(&mut proxy, &orig_ip, orig_port) {
        eprintln!("[relay] socks5 {orig_ip}:{orig_port}: {e}");
        return;
    }

    eprintln!("[relay] proxying {orig_ip}:{orig_port}");

    // Bidirectional copy
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
}

// ═════════════════════════════════════════════════════════════════════
// SOCKS5 CLIENT (RFC 1928)
// ═════════════════════════════════════════════════════════════════════

fn socks5_connect(stream: &mut TcpStream, addr: &std::net::IpAddr, port: u16) -> Result<(), String> {
    let mut buf = [0u8; 260];

    // ── Auth negotiation ──
    buf[0] = 5; buf[1] = 1; buf[2] = 0; // 1 method = no auth
    stream.write_all(&buf[..3]).map_err(|e| format!("w auth: {e}"))?;
    stream.read_exact(&mut buf[..2]).map_err(|e| format!("r auth: {e}"))?;
    if buf[0] != 5 || buf[1] != 0 {
        return Err(format!("auth fail: {buf:02x?}"));
    }

    // ── CONNECT ──
    buf[0] = 5; buf[1] = 1; buf[2] = 0;
    let off;
    match addr {
        std::net::IpAddr::V4(v4) => {
            buf[3] = 1; // ATYP IPv4
            buf[4..8].copy_from_slice(&v4.octets());
            off = 8;
        }
        std::net::IpAddr::V6(v6) => {
            buf[3] = 4; // ATYP IPv6
            buf[4..20].copy_from_slice(&v6.octets());
            off = 20;
        }
    }
    buf[off] = (port >> 8) as u8;
    buf[off + 1] = (port & 0xFF) as u8;
    let req_len = off + 2;

    stream.write_all(&buf[..req_len]).map_err(|e| format!("w conn: {e}"))?;
    stream.read_exact(&mut buf[..4]).map_err(|e| format!("r conn: {e}"))?;
    if buf[0] != 5 || buf[1] != 0 {
        return Err(format!("conn rejected: reply={}", buf[1]));
    }

    // Drain BND.ADDR + PORT
    let drain = match buf[3] {
        1 => 6,
        4 => 18,
        3 => {
            stream.read_exact(&mut buf[..1]).ok();
            buf[0] as usize + 2
        }
        _ => 0,
    };
    if drain > 0 && drain <= 260 {
        let _ = stream.read_exact(&mut buf[..drain]);
    }

    Ok(())
}

// ═════════════════════════════════════════════════════════════════════
// CLEANUP
// ═════════════════════════════════════════════════════════════════════

fn cleanup_loop(ct: Arc<Mutex<ConnTable>>, running: Arc<AtomicBool>) {
    while running.load(Ordering::SeqCst) {
        thread::sleep(CLEANUP_INTERVAL);
        let mut t = ct.lock().unwrap();
        let before = t.by_app_port.len();
        t.cleanup();
        let after = t.by_app_port.len();
        if before != after {
            eprintln!("[wd] cleanup: {before} → {after}");
        }
    }
}
