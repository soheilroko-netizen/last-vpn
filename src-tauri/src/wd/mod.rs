// wd/mod.rs — WinDivert raw FFI bindings
// WinDivert 2.2 API via dynamic link to WinDivert.dll bundled at runtime

#![allow(non_camel_case_types, dead_code)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

// ── Types ──────────────────────────────────────────────────────────

pub type BOOL = i32;
pub type UINT8 = u8;
pub type UINT16 = u16;
pub type UINT32 = u32;
pub type UINT64 = u64;
pub type INT16 = i16;
pub type INT32 = i32;
pub type HANDLE = *mut c_void;
pub type DWORD = u32;
pub type LPVOID = *mut c_void;
pub type LPCSTR = *const u8;
pub type LPSTR = *mut u8;

pub const INVALID_HANDLE_VALUE: HANDLE = !0 as HANDLE;
pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

// ── WinDivert constants ────────────────────────────────────────────

pub const WINDIVERT_LAYER_NETWORK: i32 = 0;
pub const WINDIVERT_LAYER_NETWORK_FORWARD: i32 = 1;
pub const WINDIVERT_LAYER_FLOW: i32 = 2;
pub const WINDIVERT_LAYER_SOCKET: i32 = 3;
pub const WINDIVERT_LAYER_REFLECT: i32 = 4;

pub const WINDIVERT_PARAM_QUEUE_LENGTH: u32 = 0;
pub const WINDIVERT_PARAM_QUEUE_TIME: u32 = 1;
pub const WINDIVERT_PARAM_QUEUE_SIZE: u32 = 2;
pub const WINDIVERT_PARAM_VERSION_MAJOR: u32 = 3;
pub const WINDIVERT_PARAM_VERSION_MINOR: u32 = 4;

pub const WINDIVERT_FLAG_SNIFF: u64 = 0x0001;
pub const WINDIVERT_FLAG_DROP: u64 = 0x0002;
pub const WINDIVERT_FLAG_NO_INSTALL: u64 = 0x0004;
pub const WINDIVERT_FLAG_FRAGMENTS: u64 = 0x0008;
pub const WINDIVERT_FLAG_RECV_ONLY: u64 = 0x0010;

// ── WINDIVERT_ADDRESS ──────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WINDIVERT_ADDRESS {
    pub IfIdx: UINT32,
    pub SubIfIdx: UINT32,
    pub Direction: UINT8,
    pub Impostor: UINT8,
    _pad: [u8; 2],
}

impl WINDIVERT_ADDRESS {
    pub fn is_outbound(&self) -> bool {
        self.Direction == 0
    }
    pub fn set_outbound(&mut self, out: bool) {
        self.Direction = if out { 0 } else { 1 };
    }
    pub fn set_impostor(&mut self, impostor: bool) {
        self.Impostor = if impostor { 1 } else { 0 };
    }
}

// ── IP header ──────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WINDIVERT_IPHDR {
    pub HdrLength: UINT8,   // 4 bits (×4) upper 4 bits = Version
    pub Version: UINT8,     // 4 bits lower
    pub Tos: UINT8,
    pub Length: UINT16,
    pub Id: UINT16,
    pub FragOff0: UINT16,
    pub Ttl: UINT8,
    pub Protocol: UINT8,
    pub Checksum: UINT16,
    pub SrcAddr: UINT32,
    pub DstAddr: UINT32,
}

// ── TCP header ─────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WINDIVERT_TCPHDR {
    pub SrcPort: UINT16,
    pub DstPort: UINT16,
    pub SeqNum: UINT32,
    pub AckNum: UINT32,
    pub Reserved1: UINT8,   // 4 bits
    pub HdrLength: UINT8,   // 4 bits (×4)
    pub Fin: UINT8,         // 1 bit
    pub Syn: UINT8,         // 1 bit
    pub Rst: UINT8,         // 1 bit
    pub Psh: UINT8,         // 1 bit
    pub Ack: UINT8,         // 1 bit
    pub Urg: UINT8,         // 1 bit
    pub Reserved2: UINT8,   // 2 bits
    pub Window: UINT16,
    pub Checksum: UINT16,
    pub UrgPtr: UINT16,
}

// ── Helper structs for FillPacket ──────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WINDIVERT_IPV6HDR {
    pub VersionClassFlow: UINT32,
    pub PayloadLength: UINT16,
    pub NextHdr: UINT8,
    pub HopLimit: UINT8,
    pub SrcAddr: [UINT8; 16],
    pub DstAddr: [UINT8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WINDIVERT_ICMPHDR {
    pub Type: UINT8,
    pub Code: UINT8,
    pub Checksum: UINT16,
    pub Body: UINT32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WINDIVERT_UDPHDR {
    pub SrcPort: UINT16,
    pub DstPort: UINT16,
    pub Length: UINT16,
    pub Checksum: UINT16,
}

// ── DLL function type definitions ───────────────────────────────────

pub type WinDivertOpenType = unsafe extern "system" fn(
    filter: LPCSTR,
    layer: i32,
    priority: INT16,
    flags: UINT64,
) -> HANDLE;

pub type WinDivertCloseType = unsafe extern "system" fn(handle: HANDLE) -> BOOL;

pub type WinDivertRecvType = unsafe extern "system" fn(
    handle: HANDLE,
    pPacket: *mut u8,
    packetLen: UINT32,
    readLen: *mut UINT32,
    pAddr: *mut WINDIVERT_ADDRESS,
) -> BOOL;

pub type WinDivertSendType = unsafe extern "system" fn(
    handle: HANDLE,
    pPacket: *const u8,
    packetLen: UINT32,
    writeLen: *mut UINT32,
    pAddr: *const WINDIVERT_ADDRESS,
) -> BOOL;

pub type WinDivertSetParamType = unsafe extern "system" fn(
    handle: HANDLE,
    param: UINT32,
    value: UINT64,
) -> BOOL;

pub type WinDivertHelperCalcChecksumsType = unsafe extern "system" fn(
    pPacket: *mut u8,
    packetLen: UINT32,
    pAddr: *const WINDIVERT_ADDRESS,
    flags: UINT64,
) -> BOOL;

pub type WinDivertHelperParsePacketType = unsafe extern "system" fn(
    pPacket: *const u8,
    packetLen: UINT32,
    ppIpHdr: *mut *mut WINDIVERT_IPHDR,
    ppIpv6Hdr: *mut *mut WINDIVERT_IPV6HDR,
    ppIcmpHdr: *mut *mut WINDIVERT_ICMPHDR,
    ppIcmpv6Hdr: *mut *mut WINDIVERT_ICMPHDR,
    ppUdpHdr: *mut *mut WINDIVERT_UDPHDR,
    ppTcpHdr: *mut *mut WINDIVERT_TCPHDR,
    ppData: *mut *mut u8,
    pDataLen: *mut UINT32,
) -> BOOL;

// ── WinDivert handle wrapper ───────────────────────────────────────

pub struct WinDivert {
    handle: HANDLE,
    dll: *mut c_void, // HMODULE
    // Function pointers — loaded on init
    pub raw_open: unsafe extern "system" fn(LPCSTR, i32, INT16, UINT64) -> HANDLE,
    pub raw_close: unsafe extern "system" fn(HANDLE) -> BOOL,
    pub raw_recv: unsafe extern "system" fn(HANDLE, *mut u8, UINT32, *mut UINT32, *mut WINDIVERT_ADDRESS) -> BOOL,
    pub raw_send: unsafe extern "system" fn(HANDLE, *const u8, UINT32, *mut UINT32, *const WINDIVERT_ADDRESS) -> BOOL,
    pub raw_set_param: unsafe extern "system" fn(HANDLE, UINT32, UINT64) -> BOOL,
    pub raw_calc_checksums: unsafe extern "system" fn(*mut u8, UINT32, *const WINDIVERT_ADDRESS, UINT64) -> BOOL,
    pub raw_parse_packet: unsafe extern "system" fn(*const u8, UINT32, *mut *mut WINDIVERT_IPHDR, *mut *mut WINDIVERT_IPV6HDR, *mut *mut WINDIVERT_ICMPHDR, *mut *mut WINDIVERT_ICMPHDR, *mut *mut WINDIVERT_UDPHDR, *mut *mut WINDIVERT_TCPHDR, *mut *mut u8, *mut UINT32) -> BOOL,
}

impl WinDivert {
    /// Load WinDivert.dll from the given path and bind all functions.
    /// Returns None if the DLL couldn't be loaded.
    pub fn load(dll_path: &std::path::Path) -> Option<Self> {
        // We load the DLL manually
        let dll_path_c = dll_path.as_os_str().to_str()?;
        let dll_path_bytes = std::ffi::CString::new(dll_path_c).ok()?;

        // Use LoadLibraryW for proper path handling
        let dll_wide: Vec<u16> = dll_path_c.encode_utf16().chain(std::iter::once(0)).collect();

        let dll: *mut c_void;
        unsafe {
            dll = LoadLibraryW(dll_wide.as_ptr()) as *mut c_void;
        }
        if dll.is_null() {
            return None;
        }

        macro_rules! get_fn {
            ($name:expr) => {{
                let name_c = std::ffi::CString::new($name).ok()?;
                unsafe {
                    let ptr = GetProcAddress(dll as _, name_c.as_ptr() as *const u8);
                    std::mem::transmute::<*mut c_void, _>(ptr)
                }
            }};
        }

        Some(WinDivert {
            handle: INVALID_HANDLE_VALUE,
            dll,
            raw_open: get_fn!("WinDivertOpen")?,
            raw_close: get_fn!("WinDivertClose")?,
            raw_recv: get_fn!("WinDivertRecv")?,
            raw_send: get_fn!("WinDivertSend")?,
            raw_set_param: get_fn!("WinDivertSetParam")?,
            raw_calc_checksums: get_fn!("WinDivertHelperCalcChecksums")?,
            raw_parse_packet: get_fn!("WinDivertHelperParsePacket")?,
        })
    }

    /// Open a WinDivert handle with the given filter string.
    pub fn open(&mut self, filter: &str, layer: i32, priority: INT16, flags: UINT64) -> Result<(), String> {
        if self.handle != INVALID_HANDLE_VALUE {
            self.close();
        }
        let filter_c = std::ffi::CString::new(filter).map_err(|e| e.to_string())?;
        let handle = unsafe {
            (self.raw_open)(filter_c.as_ptr() as *const u8, layer, priority, flags)
        };
        if handle == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            return Err(format!("WinDivertOpen failed (err={err})"));
        }
        self.handle = handle;
        Ok(())
    }

    /// Set a WinDivert parameter.
    pub fn set_param(&self, param: UINT32, value: UINT64) -> Result<(), String> {
        if self.handle == INVALID_HANDLE_VALUE {
            return Err("WinDivert not open".into());
        }
        let ret = unsafe { (self.raw_set_param)(self.handle, param, value) };
        if ret == 0 {
            return Err(format!("WinDivertSetParam failed (err={})", unsafe { GetLastError() }));
        }
        Ok(())
    }

    /// Receive a packet.
    pub fn recv(&self, buf: &mut [u8]) -> Result<(u32, WINDIVERT_ADDRESS), String> {
        if self.handle == INVALID_HANDLE_VALUE {
            return Err("WinDivert not open".into());
        }
        let mut read_len: UINT32 = 0;
        let mut addr: WINDIVERT_ADDRESS = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            (self.raw_recv)(self.handle, buf.as_mut_ptr(), buf.len() as UINT32, &mut read_len, &mut addr)
        };
        if ret == 0 {
            return Err(format!("WinDivertRecv failed (err={})", unsafe { GetLastError() }));
        }
        Ok((read_len, addr))
    }

    /// Send a packet.
    pub fn send(&self, buf: &[u8], addr: &WINDIVERT_ADDRESS) -> Result<u32, String> {
        if self.handle == INVALID_HANDLE_VALUE {
            return Err("WinDivert not open".into());
        }
        let mut written: UINT32 = 0;
        let ret = unsafe {
            (self.raw_send)(self.handle, buf.as_ptr(), buf.len() as UINT32, &mut written, addr as *const _)
        };
        if ret == 0 {
            return Err(format!("WinDivertSend failed (err={})", unsafe { GetLastError() }));
        }
        Ok(written)
    }

    /// Calculate checksums for a modified packet.
    pub fn calc_checksums(&self, buf: &mut [u8], addr: &WINDIVERT_ADDRESS) -> Result<(), String> {
        let ret = unsafe {
            (self.raw_calc_checksums)(buf.as_mut_ptr(), buf.len() as UINT32, addr as *const _, 0)
        };
        if ret == 0 {
            return Err("WinDivertHelperCalcChecksums failed".into());
        }
        Ok(())
    }

    /// Parse a packet into headers.
    pub fn parse_packet<'a>(
        &self,
        buf: &'a [u8],
    ) -> ParsedPacket<'a> {
        let mut ip_hdr: *mut WINDIVERT_IPHDR = std::ptr::null_mut();
        let mut ipv6_hdr: *mut WINDIVERT_IPV6HDR = std::ptr::null_mut();
        let mut icmp_hdr: *mut WINDIVERT_ICMPHDR = std::ptr::null_mut();
        let mut icmpv6_hdr: *mut WINDIVERT_ICMPHDR = std::ptr::null_mut();
        let mut udp_hdr: *mut WINDIVERT_UDPHDR = std::ptr::null_mut();
        let mut tcp_hdr: *mut WINDIVERT_TCPHDR = std::ptr::null_mut();
        let mut data: *mut u8 = std::ptr::null_mut();
        let mut data_len: UINT32 = 0;

        let ret = unsafe {
            (self.raw_parse_packet)(
                buf.as_ptr(),
                buf.len() as UINT32,
                &mut ip_hdr,
                &mut ipv6_hdr,
                &mut icmp_hdr,
                &mut icmpv6_hdr,
                &mut udp_hdr,
                &mut tcp_hdr,
                &mut data,
                &mut data_len,
            )
        };
        if ret == 0 {
            return ParsedPacket { ip: None, tcp: None, udp: None, ipv6: None, data: &[] };
        }

        ParsedPacket {
            ip: if ip_hdr.is_null() { None } else { Some(unsafe { &*ip_hdr }) },
            tcp: if tcp_hdr.is_null() { None } else { Some(unsafe { &*tcp_hdr }) },
            udp: if udp_hdr.is_null() { None } else { Some(unsafe { &*udp_hdr }) },
            ipv6: if ipv6_hdr.is_null() { None } else { Some(unsafe { &*ipv6_hdr }) },
            data: if data.is_null() { &[] } else { unsafe { std::slice::from_raw_parts(data, data_len as usize) } },
        }
    }

    /// Close the WinDivert handle. Used from any thread to wake up a blocking recv.
    pub fn close(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                (self.raw_close)(self.handle);
            }
            self.handle = INVALID_HANDLE_VALUE;
        }
    }

    /// WinDivert 2.2 doesn't have native non-blocking recv.
    /// Instead, closing the handle from another thread wakes up recv.
    /// This method is a no-op for API compatibility.
    pub fn set_nonblocking(&self, _enable: bool) {}

    pub fn is_open(&self) -> bool {
        self.handle != INVALID_HANDLE_VALUE
    }
}

impl Drop for WinDivert {
    fn drop(&mut self) {
        self.close();
        if !self.dll.is_null() {
            unsafe {
                FreeLibrary(self.dll as _);
            }
        }
    }
}

// ── ParsedPacket ───────────────────────────────────────────────────

pub struct ParsedPacket<'a> {
    pub ip: Option<&'a WINDIVERT_IPHDR>,
    pub tcp: Option<&'a WINDIVERT_TCPHDR>,
    pub udp: Option<&'a WINDIVERT_UDPHDR>,
    pub ipv6: Option<&'a WINDIVERT_IPV6HDR>,
    pub data: &'a [u8],
}

// ── Windows FFI helpers (used at runtime) ──────────────────────────

#[cfg(windows)]
extern "system" {
    fn LoadLibraryW(lpFileName: *const u16) -> *mut c_void;
    fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
    fn FreeLibrary(hModule: *mut c_void) -> BOOL;
    fn GetLastError() -> DWORD;
}
