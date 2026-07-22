// wd_engine.rs — WinDivert TCP redirect engine
//
// Based on Tallow/streamdump approach:
// 1. Intercept outbound TCP SYN
// 2. Record original dest (IP:port)
// 3. Rewrite dst to local machine:RELAY_PORT
// 4. Send as outbound — OS establishes TCP with our relay
// 5. Relay accepts connection, looks up original dest
// 6. Relay SOCKS5 CONNECTs to local proxy → SS→STLS→VPS
// 7. Bidirectional byte shuttle (normal TCP, no more WinDivert involvement)

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

struct ConnEntry {
    dst_ip: [u8; 4],
    dst_port: u16,
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
                process_outbound(wd.as_ref(), pkt, &addr, &ct);
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

fn process_outbound(
    wd: &WinDivert,
    pkt: &[u8],
    addr: &WINDIVERT_ADDRESS,
    ct: &Arc<Mutex<ConnTable>>,
) {
    // Parse
    let pp = wd.parse_packet(pkt);
    let (ip, tcp) = match (pp.ip, pp.tcp) {
        (Some(ip), Some(tcp)) => (ip, tcp),
        _ => { let _ = wd.send(pkt, addr); return; }
    };

    let ip_hl = (ip.HdrLength & 0x0F) as usize * 4;
    let tcp_off = ip_hl;

    // Read ports from raw buffer (network byte order)
    let src_port = u16::from_be_bytes([pkt[tcp_off], pkt[tcp_off + 1]]);
    let dst_port = u16::from_be_bytes([pkt[tcp_off + 2], pkt[tcp_off + 3]]);
    let flags = pkt[tcp_off + 13];

    // Skip if not outbound
    if !addr.is_outbound() {
        let _ = wd.send(pkt, addr);
        return;
    }

    // Only intercept TCP SYN (new connections)
    let is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0;
    if !is_syn {
        // Non-SYN: if this is a tracked connection, redirect to relay
        // (covers subsequent packets on the same connection)
        let tracked = ct.lock().unwrap().lookup(src_port);
        if tracked.is_some() {
            let mut mod_pkt = pkt.to_vec();
            // Overwrite dst IP with local machine IP (the original src IP)
            mod_pkt[16..20].copy_from_slice(&mod_pkt[12..16]); // DstIP = SrcIP
            let relay_be = RELAY_PORT.to_be_bytes();
            mod_pkt[tcp_off + 2] = relay_be[0];
            mod_pkt[tcp_off + 3] = relay_be[1];
            wd.calc_checksums(&mut mod_pkt, addr).ok();

            if flags & 0x01 != 0 || flags & 0x04 != 0 {
                ct.lock().unwrap().remove(src_port);
            }
            let _ = wd.send(&mod_pkt, addr);
        } else {
            let _ = wd.send(pkt, addr);
        }
        return;
    }

    // ── SYN handling ──
    let mut dst_ip = [0u8; 4];
    dst_ip.copy_from_slice(&pkt[16..20]);

    // Record original destination
    ct.lock().unwrap().insert(src_port, dst_ip, dst_port);

    // Modify packet: redirect to local relay
    let mut mod_pkt = pkt.to_vec();
    mod_pkt[16..20].copy_from_slice(&mod_pkt[12..16]); // DstIP = SrcIP (local machine)
    let relay_be = RELAY_PORT.to_be_bytes();
    mod_pkt[tcp_off + 2] = relay_be[0]; // DstPort = RELAY_PORT
    mod_pkt[tcp_off + 3] = relay_be[1];

    // Recalc and send
    wd.calc_checksums(&mut mod_pkt, addr).ok();
    let _ = wd.send(&mod_pkt, addr);
}

// ═════════════════════════════════════════════════════════════════════
// RELAY LISTENER
// ═════════════════════════════════════════════════════════════════════
// Accepts redirected connections from the app (via modified SYN).
// peer_addr = (app_ip, app_eph_port).
// Look up original dest from conn table.

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
                        let orig_dst = Ipv4Addr::new(e.dst_ip[0], e.dst_ip[1], e.dst_ip[2], e.dst_ip[3]);
                        let orig_port = e.dst_port;
                        eprintln!("[relay] accept app:{app_port} → {orig_dst}:{orig_port}");

                        let proxy_addr = format!("127.0.0.1:{proxy_port}");
                        let ct = ct.clone();
                        thread::spawn(move || {
                            handle_relay(stream, &proxy_addr, orig_dst, orig_port, app_port, ct);
                        });
                    }
                    None => {
                        eprintln!("[relay] no entry for port {app_port}, closing");
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
    orig_ip: Ipv4Addr,
    orig_port: u16,
    app_port: u16,
    ct: Arc<Mutex<ConnTable>>,
) {
    let mut proxy = match TcpStream::connect(proxy_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[relay] proxy connect fail '{proxy_addr}': {e}");
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
    let drain = match buf[3] { 1 => 6, 4 => 18, 3 => { let _ = stream.read_exact(&mut buf[..1]); buf[0] as usize + 2 } _ => 0 };
    if drain > 0 { let _ = stream.read_exact(&mut buf[..drain.min(260)]); }
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
