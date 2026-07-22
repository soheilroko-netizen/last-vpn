// wd_engine.rs — WinDivert TCP intercept engine
//
// Architecture (from ProxyBridge/streamdump):
// 1. App outbound SYN → reflected INBOUND to relay (swap src↔dst, dst_port=RELAY)
// 2. Relay accepts connection from reflected peer (src=original_dst_ip, port=app_eph)
// 3. Relay looks up original dst port via conn table (keyed by app_eph)
// 4. Relay SOCKS5 CONNECTs to local proxy → SS→STLS→VPS
// 5. Bidirectional byte shuttle
// 6. Relay response (from relay:app_eph) is un-reflected back to app

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
const RECV_TIMEOUT_MS: u64 = 500;

// ── Connection table ───────────────────────────────────────────────
// All values stored in HOST byte order (as Rust native u16/u32).

#[derive(Clone)]
struct ConnEntry {
    app_port: u16,    // app ephemeral port (HBO)
    dst_ip: [u8; 4],  // original destination IP (net byte order, as in packet)
    dst_port: u16,     // original destination port (HBO)
    last_seen: Instant,
}

struct ConnTable {
    by_app_port: HashMap<u16, ConnEntry>, // keyed by app_port (HBO)
}

impl ConnTable {
    fn new() -> Self {
        ConnTable { by_app_port: HashMap::new() }
    }

    fn insert(&mut self, app_port_hbo: u16, dst_ip: [u8; 4], dst_port_hbo: u16) {
        self.by_app_port.insert(app_port_hbo, ConnEntry {
            app_port: app_port_hbo, dst_ip, dst_port: dst_port_hbo,
            last_seen: Instant::now(),
        });
    }

    fn lookup(&mut self, app_port_hbo: u16) -> Option<ConnEntry> {
        if let Some(e) = self.by_app_port.get_mut(&app_port_hbo) {
            e.last_seen = Instant::now();
            Some(e.clone())
        } else {
            None
        }
    }

    fn remove(&mut self, app_port_hbo: u16) {
        self.by_app_port.remove(&app_port_hbo);
    }

    fn cleanup(&mut self) {
        let cutoff = Instant::now() - CONN_TTL;
        self.by_app_port.retain(|_, v| v.last_seen > cutoff);
    }
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
    pub fn new(dll_path: &str, _filter: &str) -> Self {
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

        // Wrap in Arc so the packet loop can use it.
        // We don't use a Mutex over the handle — only the packet thread touches it.
        // Stop is done by setting running=false; recv will timeout and exit.
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
// HELPERS: read port/IP from packet buffer (big-endian / network order)
// ═════════════════════════════════════════════════════════════════════

/// Read u16 from network byte order bytes in the packet buffer, return host-order.
fn ntohs(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

// ═════════════════════════════════════════════════════════════════════
// PACKET LOOP
// ═════════════════════════════════════════════════════════════════════

fn packet_loop(wd: Arc<WinDivert>, running: Arc<AtomicBool>, ct: Arc<Mutex<ConnTable>>) {
    let mut buf = [0u8; MAXBUF];

    wd.set_nonblocking(true);

    while running.load(Ordering::SeqCst) {
        // Recv with timeout loop (non-blocking)
        match wd.recv(&mut buf) {
            Ok((pkt_len, addr)) => {
                let pkt = &buf[..pkt_len as usize];
                process_packet(wd.as_ref(), pkt, &addr, &running, &ct);
            }
            Err(ref e) if is_blocking_err(e) => {
                thread::sleep(Duration::from_millis(RECV_TIMEOUT_MS));
                continue;
            }
            Err(e) => {
                eprintln!("[wd] recv: {e}");
                break;
            }
        }
    }
    eprintln!("[wd] packet loop ended");
}

fn is_blocking_err(e: &str) -> bool {
    // WinDivert sets last error to ERROR_NO_DATA or WSAEWOULDBLOCK when in nonblocking mode
    e.contains("NO_DATA") || e.contains("WOULDBLOCK") || e.contains("would block")
}

fn process_packet(
    wd: &WinDivert,
    pkt: &[u8],
    addr: &WINDIVERT_ADDRESS,
    running: &AtomicBool,
    ct: &Arc<Mutex<ConnTable>>,
) {
    if !running.load(Ordering::SeqCst) { return; }

    let pp = wd.parse_packet(pkt);

    if pp.ip.is_none() || pp.tcp.is_none() {
        let _ = wd.send(pkt, addr);
        return;
    }

    let ip = pp.ip.unwrap();
    let tcp = pp.tcp.unwrap();
    let ip_hl = (ip.HdrLength & 0x0F) as usize * 4;
    let tcp_off = ip_hl;

    // Read raw port values from packet buffer (network byte order)
    let tcp_src_port = ntohs(pkt, tcp_off);
    let tcp_dst_port = ntohs(pkt, tcp_off + 2);

    if addr.is_outbound() {
        handle_outbound(wd, pkt, addr, tcp_src_port, tcp_dst_port, tcp_off, ip_hl, ct, running);
    } else {
        // inbound — pass through (responses go to relay via its TCP socket)
        let _ = wd.send(pkt, addr);
    }
}

fn handle_outbound(
    wd: &WinDivert,
    pkt: &[u8],
    addr: &WINDIVERT_ADDRESS,
    tcp_src: u16,
    tcp_dst: u16,
    tcp_off: usize,
    _ip_hl: usize,
    ct: &Arc<Mutex<ConnTable>>,
    _running: &AtomicBool,
) {
    // ── Case 1: Relay responding to app (src_port == RELAY_PORT) → un-reflect ──
    if tcp_src == RELAY_PORT {
        // Packet is from relay → app.
        // Need to restore: src_ip→original_dst_ip, src_port→original_dst_port
        // and inject as inbound so app receives it as server response.
        let entry = ct.lock().unwrap().lookup(tcp_dst); // dst_port = app_eph
        if let Some(entry) = entry {
            let mut mod_pkt = pkt.to_vec();

            // Current:  SrcIP=relay_ip, DstIP=app_ip, SrcPort=RELAY, DstPort=app_eph
            // Wanted:   SrcIP=orig_dst_ip, DstIP=app_ip, SrcPort=orig_dst_port, DstPort=app_eph

            // Set IP SrcAddr = original destination IP
            mod_pkt[12..16].copy_from_slice(&entry.dst_ip);
            // IP DstAddr stays as app_ip (already correct)
            // TCP SrcPort becomes original destination port
            let dst_port_be = entry.dst_port.to_be_bytes();
            mod_pkt[tcp_off] = dst_port_be[0];
            mod_pkt[tcp_off + 1] = dst_port_be[1];
            // TCP DstPort stays as app_eph (already correct)

            // Mark as inbound
            let mut in_addr = *addr;
            in_addr.set_outbound(false);
            wd.calc_checksums(&mut mod_pkt, &in_addr).ok();
            let _ = wd.send(&mod_pkt, &in_addr);

            let flags = pkt[tcp_off + 13];
            if flags & 0x01 != 0 || flags & 0x04 != 0 {
                ct.lock().unwrap().remove(tcp_dst);
            }
        } else {
            let _ = wd.send(pkt, addr);
        }
        return;
    }

    // ── Case 2: App → internet, check if we should intercept ──
    // Skip relay/proxy port traffic (should be excluded by filter, but defensive)
    if tcp_dst == RELAY_PORT || tcp_dst == PROXY_PORT || tcp_src == PROXY_PORT {
        let _ = wd.send(pkt, addr);
        return;
    }

    let flags = pkt[tcp_off + 13];
    let is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0; // SYN not ACK

    // Record new connection on SYN
    if is_syn {
        let mut dst_ip = [0u8; 4];
        dst_ip.copy_from_slice(&pkt[16..20]);
        ct.lock().unwrap().insert(tcp_src, dst_ip, tcp_dst);
    }

    // If tracked, reflect to relay
    let tracked = ct.lock().unwrap().lookup(tcp_src);
    if let Some(_) = tracked {
        let mut mod_pkt = pkt.to_vec();

        // Swap src/dst IP
        let src_ip = mod_pkt[12..16].to_vec();
        mod_pkt[12..16].copy_from_slice(&mod_pkt[16..20]);
        mod_pkt[16..20].copy_from_slice(&src_ip);

        // Change TCP dst port to RELAY_PORT
        let relay_be = RELAY_PORT.to_be_bytes();
        mod_pkt[tcp_off + 2] = relay_be[0];
        mod_pkt[tcp_off + 3] = relay_be[1];

        // Inject as inbound (to our relay)
        let mut in_addr = *addr;
        in_addr.set_outbound(false);
        wd.calc_checksums(&mut mod_pkt, &in_addr).ok();

        if flags & 0x01 != 0 || flags & 0x04 != 0 {
            ct.lock().unwrap().remove(tcp_src);
        }

        let _ = wd.send(&mod_pkt, &in_addr);
    } else {
        // Not tracked, pass through (shouldn't happen for non-SYN of tracked conns,
        // but happens for non-proxied traffic)
        let _ = wd.send(pkt, addr);
    }
}

// ═════════════════════════════════════════════════════════════════════
// RELAY LISTENER
// ═════════════════════════════════════════════════════════════════════
// The relay receives TCP connections from reflected packets.
// The reflected packet has: SrcIP=original_dst_ip, SrcPort=app_eph.
// So peer_addr() gives us: ip=original_dst_ip, port=app_eph.
// We look up app_eph in the conn table to get original dst_port,
// then SOCKS5 CONNECT to original_dst_ip:original_dst_port.

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
                let reflected_ip = peer.ip();
                let app_eph_port = peer.port();

                // Look up original dest port from conn table
                let orig_dst_port = {
                    let mut ct = ct.lock().unwrap();
                    ct.lookup(app_eph_port).map(|e| e.dst_port)
                };

                match orig_dst_port {
                    Some(orig_port) => {
                        eprintln!("[relay] accept → {reflected_ip}:{orig_port} (app_eph={app_eph_port})");
                        let ct = ct.clone();
                        let run = running.clone();
                        thread::spawn(move || {
                            handle_relay(stream, &format!("127.0.0.1:{proxy_port}"), &reflected_ip, orig_port, app_eph_port, ct, run);
                        });
                    }
                    None => {
                        eprintln!("[relay] no conn entry for port {app_eph_port}, closing");
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
    orig_ip: &std::net::IpAddr,
    orig_port: u16,
    app_eph_port: u16,
    ct: Arc<Mutex<ConnTable>>,
    _running: Arc<AtomicBool>,
) {
    let mut proxy = match TcpStream::connect(proxy_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[relay] proxy connect fail '{proxy_addr}': {e}");
            return;
        }
    };

    if let Err(e) = socks5_connect(&mut proxy, orig_ip, orig_port) {
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

    ct.lock().unwrap().remove(app_eph_port);
}

// ═════════════════════════════════════════════════════════════════════
// SOCKS5 CLIENT (RFC 1928)
// ═════════════════════════════════════════════════════════════════════

fn socks5_connect(stream: &mut TcpStream, addr: &std::net::IpAddr, port: u16) -> Result<(), String> {
    let mut buf = [0u8; 260];

    // Auth negotiation
    buf[0] = 5; buf[1] = 1; buf[2] = 0;
    stream.write_all(&buf[..3]).map_err(|e| format!("w auth: {e}"))?;
    stream.read_exact(&mut buf[..2]).map_err(|e| format!("r auth: {e}"))?;
    if buf[0] != 5 || buf[1] != 0 {
        return Err(format!("auth fail: {buf:02x?}"));
    }

    // CONNECT
    buf[0] = 5; buf[1] = 1; buf[2] = 0;
    let off;
    match addr {
        std::net::IpAddr::V4(v4) => {
            buf[3] = 1;
            buf[4..8].copy_from_slice(&v4.octets());
            off = 8;
        }
        std::net::IpAddr::V6(v6) => {
            buf[3] = 4;
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
            let _ = stream.read_exact(&mut buf[..1]);
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
