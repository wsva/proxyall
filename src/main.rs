//! proxyall — redirect ALL outbound TCP (IPv4 + IPv6) through one proxy, EXCEPT
//! traffic from a hardcoded process name (Veee.exe), resolved to PID(s) at runtime.
//!
//! Single-file build: WinDivert FFI, packet loop, connection tracking, process
//! resolution, upstream proxy handshakes (SOCKS5/HTTP CONNECT), and the local
//! relay all live in the inline modules below.

use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::{c_char, c_void};
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
    ToSocketAddrs,
};
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use libloading::Library;
use windows::core::PWSTR;
use windows::Win32::Foundation::{BOOL, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::System::Console::SetConsoleCtrlHandler;
use windows::Win32::System::SystemInformation::GetLocalTime;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Runtime configuration is loaded from `proxyall.config.json`, looked up next to
/// the executable and then in the current working directory. The constants below
/// are only a fallback used when no config file is present.
const CONFIG_FILE: &str = "proxyall.config.json";
/// Default upstream proxy URL when no config file is found. Accepted schemes are
/// `socks5://host:port` and `http://host:port`.
const DEFAULT_PROXY_URL: &str = "socks5://127.0.0.1:1080";
/// Default process names whose traffic bypasses the proxy (VPN / overlay daemons
/// that must reach the internet directly: proxying one VPN's traffic through
/// another breaks it, e.g. Tailscale's DERP control plane). Overridden by the
/// config file's `except` array.
const DEFAULT_EXCEPT: &[&str] = &["vpn.exe", "tailscaled.exe", "tailscale-ipn.exe"];
/// Like ProxyBridge's "send domain to proxy": hand the proxy the hostname the app
/// resolved (learned by sniffing DNS replies) instead of a bare IP, so the proxy
/// resolves it itself. Falls back to the IP when no mapping is known.
const SEND_DOMAIN_TO_PROXY: bool = true;
const RELAY_PORT: u16 = 34010;
const VPN_REFRESH: Duration = Duration::from_secs(5);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const CONN_STALE: Duration = Duration::from_secs(30 * 60);

static STOP: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// WinDivert FFI.
//
// The DLL is loaded at runtime (no build-time `.lib` needed). Struct layouts
// mirror `windivert.h` exactly (WinDivert 2.x): `WINDIVERT_ADDRESS` is 80 bytes
// with the bitfield word at offset 8, where `Outbound` is bit 17.
// ---------------------------------------------------------------------------

mod windivert {
    use super::*;

    pub const MAXBUF: usize = 0xFFFF;

    pub const LAYER_NETWORK: i32 = 0;
    pub const PARAM_QUEUE_LENGTH: i32 = 0;
    pub const PARAM_QUEUE_TIME: i32 = 1;
    pub const PARAM_QUEUE_SIZE: i32 = 2;
    pub const SHUTDOWN_BOTH: i32 = 3;

    pub type Handle = *mut c_void;
    pub const INVALID_HANDLE: Handle = -1isize as *mut c_void;

    /// Bit position of `Outbound` in the flags word (Layer:8, Event:8, Sniffed:1,
    /// Outbound:1 => bit 17).
    const OUTBOUND_BIT: u32 = 1 << 17;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Address {
        pub timestamp: i64,
        pub flags: u32,
        pub reserved2: u32,
        pub data: [u8; 64],
    }
    const _: () = assert!(std::mem::size_of::<Address>() == 80);

    impl Address {
        #[inline]
        pub fn outbound(&self) -> bool {
            self.flags & OUTBOUND_BIT != 0
        }
        #[inline]
        pub fn set_outbound(&mut self, v: bool) {
            if v {
                self.flags |= OUTBOUND_BIT;
            } else {
                self.flags &= !OUTBOUND_BIT;
            }
        }
    }

    /// IPv4 header. `ver_ihl` low nibble = header length in 32-bit words.
    /// `src_addr`/`dst_addr` are the raw in-memory (network-order) words, matching
    /// `dwLocalAddr` from the TCP owner-PID table.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct IpHdr {
        pub ver_ihl: u8,
        pub tos: u8,
        pub length: u16,
        pub id: u16,
        pub frag_off0: u16,
        pub ttl: u8,
        pub protocol: u8,
        pub checksum: u16,
        pub src_addr: u32,
        pub dst_addr: u32,
    }

    /// IPv6 header (40 bytes). Addresses are kept as raw network-order bytes.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Ipv6Hdr {
        pub ver_tc_flow: u32,
        pub length: u16,
        pub next_hdr: u8,
        pub hop_limit: u8,
        pub src_addr: [u8; 16],
        pub dst_addr: [u8; 16],
    }
    const _: () = assert!(std::mem::size_of::<Ipv6Hdr>() == 40);

    /// TCP header. `off_flags` is the 16-bit word at offset 12 (data offset +
    /// flags) read natively; the flag bits map as in `windivert.h`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct TcpHdr {
        pub src_port: u16,
        pub dst_port: u16,
        pub seq_num: u32,
        pub ack_num: u32,
        pub off_flags: u16,
        pub window: u16,
        pub checksum: u16,
        pub urg_ptr: u16,
    }

    impl TcpHdr {
        #[inline]
        pub fn fin(&self) -> bool {
            self.off_flags & (1 << 8) != 0
        }
        #[inline]
        pub fn syn(&self) -> bool {
            self.off_flags & (1 << 9) != 0
        }
        #[inline]
        pub fn rst(&self) -> bool {
            self.off_flags & (1 << 10) != 0
        }
        #[inline]
        pub fn ack(&self) -> bool {
            self.off_flags & (1 << 12) != 0
        }
        #[inline]
        pub fn src_port_host(&self) -> u16 {
            u16::from_be(self.src_port)
        }
        #[inline]
        pub fn dst_port_host(&self) -> u16 {
            u16::from_be(self.dst_port)
        }
        #[inline]
        pub fn set_dst_port_host(&mut self, port: u16) {
            self.dst_port = port.to_be();
        }
        #[inline]
        pub fn set_src_port_host(&mut self, port: u16) {
            self.src_port = port.to_be();
        }
    }

    type FnOpen = unsafe extern "system" fn(*const c_char, i32, i16, u64) -> Handle;
    type FnRecv = unsafe extern "system" fn(Handle, *mut u8, u32, *mut u32, *mut Address) -> i32;
    type FnSend = unsafe extern "system" fn(Handle, *const u8, u32, *mut u32, *const Address) -> i32;
    type FnCalc = unsafe extern "system" fn(*mut u8, u32, *mut Address, u64) -> i32;
    type FnSetParam = unsafe extern "system" fn(Handle, i32, u64) -> i32;
    type FnShutdown = unsafe extern "system" fn(Handle, i32) -> i32;
    type FnClose = unsafe extern "system" fn(Handle) -> i32;
    #[allow(clippy::type_complexity)]
    type FnParse = unsafe extern "system" fn(
        *const u8,
        u32,
        *mut *mut IpHdr,
        *mut *mut c_void,
        *mut u8,
        *mut *mut c_void,
        *mut *mut c_void,
        *mut *mut TcpHdr,
        *mut *mut c_void,
        *mut *mut c_void,
        *mut u32,
        *mut *mut c_void,
        *mut u32,
    ) -> i32;

    pub struct Parsed {
        pub ip: Option<*mut IpHdr>,
        pub ip6: Option<*mut Ipv6Hdr>,
        pub tcp: Option<*mut TcpHdr>,
        pub is_udp: bool,
        /// Transport payload (pointer into the packet buffer, length).
        pub data: Option<(*const u8, usize)>,
    }

    pub struct WinDivert {
        _lib: Library,
        handle: AtomicUsize,
        f_open: FnOpen,
        f_recv: FnRecv,
        f_send: FnSend,
        f_calc: FnCalc,
        f_setparam: FnSetParam,
        f_shutdown: FnShutdown,
        f_close: FnClose,
        f_parse: FnParse,
    }

    impl WinDivert {
        /// Load WinDivert.dll from `dll_path` and resolve the symbols we need.
        pub fn load(dll_path: &str) -> Result<Self, String> {
            unsafe {
                let lib = Library::new(dll_path)
                    .map_err(|e| format!("cannot load {} ({}). Put WinDivert.dll next to the executable.", dll_path, e))?;

                let f_open: FnOpen = *lib.get(b"WinDivertOpen\0").map_err(|e| e.to_string())?;
                let f_recv: FnRecv = *lib.get(b"WinDivertRecv\0").map_err(|e| e.to_string())?;
                let f_send: FnSend = *lib.get(b"WinDivertSend\0").map_err(|e| e.to_string())?;
                let f_calc: FnCalc = *lib.get(b"WinDivertHelperCalcChecksums\0").map_err(|e| e.to_string())?;
                let f_setparam: FnSetParam = *lib.get(b"WinDivertSetParam\0").map_err(|e| e.to_string())?;
                let f_shutdown: FnShutdown = *lib.get(b"WinDivertShutdown\0").map_err(|e| e.to_string())?;
                let f_close: FnClose = *lib.get(b"WinDivertClose\0").map_err(|e| e.to_string())?;
                let f_parse: FnParse = *lib.get(b"WinDivertHelperParsePacket\0").map_err(|e| e.to_string())?;

                Ok(Self {
                    _lib: lib,
                    handle: AtomicUsize::new(INVALID_HANDLE as usize),
                    f_open,
                    f_recv,
                    f_send,
                    f_calc,
                    f_setparam,
                    f_shutdown,
                    f_close,
                    f_parse,
                })
            }
        }

        pub fn open(&self, filter: &str, priority: i16) -> Result<(), String> {
            let cstr = std::ffi::CString::new(filter).map_err(|_| "invalid filter".to_string())?;
            let h = unsafe { (self.f_open)(cstr.as_ptr(), LAYER_NETWORK, priority, 0) };
            if h == INVALID_HANDLE || h.is_null() {
                return Err(format!("WinDivertOpen failed (os error {}). Run as Administrator and ensure WinDivert64.sys is present and not blocked by antivirus.", std::io::Error::last_os_error().raw_os_error().unwrap_or(0)));
            }
            self.handle.store(h as usize, Ordering::Relaxed);
            // Large, patient kernel queue so bursts are not dropped.
            unsafe {
                (self.f_setparam)(h, PARAM_QUEUE_LENGTH, 16384);
                (self.f_setparam)(h, PARAM_QUEUE_TIME, 2000);
                (self.f_setparam)(h, PARAM_QUEUE_SIZE, 33_553_920);
            }
            Ok(())
        }

        #[inline]
        fn h(&self) -> Handle {
            self.handle.load(Ordering::Relaxed) as Handle
        }

        /// Receive one packet. Returns false when the handle was closed/shutdown.
        pub fn recv(&self, buf: &mut [u8], len: &mut u32, addr: &mut Address) -> bool {
            unsafe { (self.f_recv)(self.h(), buf.as_mut_ptr(), buf.len() as u32, len, addr) != 0 }
        }

        pub fn send(&self, buf: &[u8], len: u32, addr: &Address) -> bool {
            unsafe { (self.f_send)(self.h(), buf.as_ptr(), len, std::ptr::null_mut(), addr) != 0 }
        }

        pub fn calc_checksums(&self, buf: &mut [u8], len: u32, addr: &mut Address) {
            unsafe { (self.f_calc)(buf.as_mut_ptr(), len, addr, 0) };
        }

        /// Parse IPv4 / IPv6 / TCP / UDP-payload out of a raw packet.
        pub fn parse(&self, buf: &[u8], len: u32) -> Parsed {
            let mut ip: *mut IpHdr = std::ptr::null_mut();
            let mut ip6: *mut c_void = std::ptr::null_mut();
            let mut tcp: *mut TcpHdr = std::ptr::null_mut();
            let mut udp: *mut c_void = std::ptr::null_mut();
            let mut data: *mut c_void = std::ptr::null_mut();
            let mut data_len: u32 = 0;
            unsafe {
                (self.f_parse)(
                    buf.as_ptr(),
                    len,
                    &mut ip,
                    &mut ip6,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut tcp,
                    &mut udp,
                    &mut data,
                    &mut data_len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
            }
            Parsed {
                ip: if ip.is_null() { None } else { Some(ip) },
                ip6: if ip6.is_null() { None } else { Some(ip6 as *mut Ipv6Hdr) },
                tcp: if tcp.is_null() { None } else { Some(tcp) },
                is_udp: !udp.is_null(),
                data: if data.is_null() { None } else { Some((data as *const u8, data_len as usize)) },
            }
        }

        pub fn shutdown_and_close(&self) {
            let h = self.handle.swap(INVALID_HANDLE as usize, Ordering::Relaxed) as Handle;
            if h != INVALID_HANDLE && !h.is_null() {
                unsafe {
                    (self.f_shutdown)(h, SHUTDOWN_BOTH);
                    (self.f_close)(h);
                }
            }
        }
    }
}

use windivert::{Address, IpHdr, Ipv6Hdr, WinDivert, MAXBUF};

// ---------------------------------------------------------------------------
// Connection tracking: source port -> original destination.
//
// Populated when a new connection is decided PROXY; read by the relay (to dial
// the real server) and by the packet loop (to rewrite relay responses back).
// ---------------------------------------------------------------------------

mod conntrack {
    use super::*;

    pub struct ConnInfo {
        pub dest_ip: IpAddr,
        pub dest_port: u16,
        pub last: Instant,
    }

    /// Keyed by (source port, is_ipv6): the IPv4 and IPv6 stacks have separate
    /// port spaces, so the same number can be live in both at once.
    #[derive(Default)]
    pub struct ConnTrack {
        map: RwLock<HashMap<(u16, bool), ConnInfo>>,
    }

    impl ConnTrack {
        pub fn insert(&self, src_port: u16, v6: bool, dest_ip: IpAddr, dest_port: u16) {
            if let Ok(mut m) = self.map.write() {
                m.insert((src_port, v6), ConnInfo { dest_ip, dest_port, last: Instant::now() });
            }
        }

        /// Original destination for a source port, refreshing its activity time.
        pub fn get_dest(&self, src_port: u16, v6: bool) -> Option<(IpAddr, u16)> {
            let mut m = self.map.write().ok()?;
            if let Some(info) = m.get_mut(&(src_port, v6)) {
                info.last = Instant::now();
                Some((info.dest_ip, info.dest_port))
            } else {
                None
            }
        }

        pub fn remove(&self, src_port: u16, v6: bool) {
            if let Ok(mut m) = self.map.write() {
                m.remove(&(src_port, v6));
            }
        }

        /// Drop entries idle for longer than `timeout` (sweeps connections whose
        /// FIN/RST was missed; clean closes are removed immediately).
        pub fn cleanup(&self, timeout: Duration) {
            let now = Instant::now();
            if let Ok(mut m) = self.map.write() {
                m.retain(|_, info| now.duration_since(info.last) <= timeout);
            }
        }
    }
}

use conntrack::ConnTrack;

// ---------------------------------------------------------------------------
// DNS snoop cache (same idea as ProxyBridge's pb_dns.c): inbound UDP/53 replies
// are parsed and every A answer is stored as ip -> queried hostname, so the relay
// can send `CONNECT host:port` / SOCKS5 domain requests instead of a bare IP.
// Both A (IPv4) and AAAA (IPv6) answers are recorded.
// ---------------------------------------------------------------------------

mod dns {
    use super::*;

    const DNS_TTL: Duration = Duration::from_secs(300);

    #[derive(Default)]
    pub struct DnsCache {
        map: RwLock<HashMap<IpAddr, (String, Instant)>>,
    }

    impl DnsCache {
        pub fn lookup(&self, ip: IpAddr) -> Option<String> {
            let m = self.map.read().ok()?;
            match m.get(&ip) {
                Some((name, exp)) if *exp > Instant::now() => Some(name.clone()),
                _ => None,
            }
        }

        pub fn cleanup(&self) {
            let now = Instant::now();
            if let Ok(mut m) = self.map.write() {
                m.retain(|_, (_, exp)| *exp > now);
            }
        }

        fn store(&self, ip: IpAddr, name: &str) {
            if let Ok(mut m) = self.map.write() {
                m.insert(ip, (name.to_string(), Instant::now() + DNS_TTL));
            }
        }

        /// Snoop one inbound DNS response (UDP payload, starting at the DNS header).
        /// Returns the hostname and number of A/AAAA records stored, for logging.
        pub fn snoop(&self, p: &[u8]) -> Option<(String, usize)> {
            if p.len() < 12 {
                return None;
            }
            let flags = u16::from_be_bytes([p[2], p[3]]);
            if flags & 0x8000 == 0 || flags & 0x000F != 0 {
                return None; // not a response, or RCODE != NOERROR
            }
            let qd = u16::from_be_bytes([p[4], p[5]]) as usize;
            let an = u16::from_be_bytes([p[6], p[7]]) as usize;
            if qd == 0 || an == 0 {
                return None;
            }

            let mut off = 12;
            // The first question's name is the canonical hostname for every answer
            // (so CNAME chains still map the final IPs back to what the app asked for).
            let qname = parse_name(p, &mut off)?;
            off += 4; // QTYPE + QCLASS
            for _ in 1..qd {
                parse_name(p, &mut off)?;
                off += 4;
            }
            if !valid_hostname(&qname) {
                return None;
            }

            let mut stored = 0;
            for _ in 0..an {
                if off >= p.len() {
                    break;
                }
                parse_name(p, &mut off)?; // owner name
                if off + 10 > p.len() {
                    break;
                }
                let rtype = u16::from_be_bytes([p[off], p[off + 1]]);
                let rclass = u16::from_be_bytes([p[off + 2], p[off + 3]]);
                let rdlen = u16::from_be_bytes([p[off + 8], p[off + 9]]) as usize;
                off += 10;
                if off + rdlen > p.len() {
                    break;
                }
                if rtype == 1 && rclass == 1 && rdlen == 4 {
                    // A record
                    self.store(IpAddr::V4(Ipv4Addr::new(p[off], p[off + 1], p[off + 2], p[off + 3])), &qname);
                    stored += 1;
                } else if rtype == 28 && rclass == 1 && rdlen == 16 {
                    // AAAA record
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&p[off..off + 16]);
                    self.store(IpAddr::V6(Ipv6Addr::from(b)), &qname);
                    stored += 1;
                }
                off += rdlen;
            }
            if stored > 0 { Some((qname, stored)) } else { None }
        }
    }

    /// Parse a (possibly compressed) DNS name at `*offset`, advancing past it.
    fn parse_name(msg: &[u8], offset: &mut usize) -> Option<String> {
        let mut pos = *offset;
        let mut out = String::new();
        let mut jumped = false;
        let mut end = 0usize;
        let mut jumps = 0;
        loop {
            let b = *msg.get(pos)?;
            if b == 0 {
                *offset = if jumped { end } else { pos + 1 };
                return Some(out);
            }
            if b & 0xC0 == 0xC0 {
                let b2 = *msg.get(pos + 1)?;
                if !jumped {
                    end = pos + 2;
                    jumped = true;
                }
                pos = (((b & 0x3F) as usize) << 8) | b2 as usize;
                jumps += 1;
                if jumps > 10 {
                    return None;
                }
                continue;
            }
            if b & 0xC0 != 0 {
                return None; // reserved label type
            }
            let l = b as usize;
            pos += 1;
            let label = msg.get(pos..pos + l)?;
            if !out.is_empty() {
                out.push('.');
            }
            if out.len() + l > 253 {
                return None;
            }
            out.extend(label.iter().map(|&c| c as char));
            pos += l;
        }
    }

    /// The name ends up inside a `CONNECT` request line, so accept only plain
    /// hostname characters (never CR/LF/space) and fall back to the IP otherwise.
    fn valid_hostname(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 253
            && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_')
    }
}

use dns::DnsCache;

// ---------------------------------------------------------------------------
// Upstream proxy handshakes: SOCKS5 CONNECT (RFC 1928, no-auth) and HTTP
// CONNECT. Operates on an already-connected `TcpStream` to the proxy.
// ---------------------------------------------------------------------------

mod proxy {
    use super::*;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum ProxyKind {
        Socks5,
        Http,
    }

    #[derive(Clone, Debug)]
    pub struct ProxyConfig {
        pub kind: ProxyKind,
        pub host: String,
        pub port: u16,
        /// Resolved once at startup so no DNS is paid per connection.
        pub addr: Ipv4Addr,
    }

    impl ProxyConfig {
        pub fn describe(&self) -> String {
            format!(
                "{} {}:{}",
                match self.kind {
                    ProxyKind::Socks5 => "SOCKS5",
                    ProxyKind::Http => "HTTP",
                },
                self.host,
                self.port
            )
        }

        /// Establish a tunnel to `dest_ip:dest_port` over `stream`.
        pub fn connect(
            &self,
            stream: &mut TcpStream,
            dest_ip: IpAddr,
            dest_port: u16,
            domain: Option<&str>,
        ) -> io::Result<()> {
            match self.kind {
                ProxyKind::Socks5 => socks5_connect(stream, dest_ip, dest_port, domain),
                ProxyKind::Http => http_connect(stream, dest_ip, dest_port, domain),
            }
        }
    }

    fn socks5_connect(s: &mut TcpStream, dest_ip: IpAddr, dest_port: u16, domain: Option<&str>) -> io::Result<()> {
        // Greeting: offer "no authentication" only.
        s.write_all(&[0x05, 0x01, 0x00])?;

        let mut reply = [0u8; 2];
        s.read_exact(&mut reply)?;
        if reply[0] != 0x05 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad SOCKS version"));
        }
        if reply[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "proxy requires authentication (not supported)",
            ));
        }

        // CONNECT to a domain name (atyp 0x03) when known, else an IPv4/IPv6 address.
        let mut req: Vec<u8> = vec![0x05, 0x01, 0x00]; // ver, cmd connect, rsv
        match domain {
            Some(d) if d.len() <= 255 => {
                req.push(0x03);
                req.push(d.len() as u8);
                req.extend_from_slice(d.as_bytes());
            }
            _ => match dest_ip {
                IpAddr::V4(a) => {
                    req.push(0x01);
                    req.extend_from_slice(&a.octets());
                }
                IpAddr::V6(a) => {
                    req.push(0x04);
                    req.extend_from_slice(&a.octets());
                }
            },
        }
        req.extend_from_slice(&dest_port.to_be_bytes());
        s.write_all(&req)?;

        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr)?;
        if hdr[0] != 0x05 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad SOCKS reply version"));
        }
        if hdr[1] != 0x00 {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("SOCKS5 reply {:#04}", hdr[1])));
        }
        // Consume the bound address (atyp-dependent) so the stream is positioned at data.
        match hdr[3] {
            0x01 => {
                let mut skip = [0u8; 4 + 2];
                s.read_exact(&mut skip)?;
            }
            0x04 => {
                let mut skip = [0u8; 16 + 2];
                s.read_exact(&mut skip)?;
            }
            0x03 => {
                let mut n = [0u8; 1];
                s.read_exact(&mut n)?;
                let mut skip = vec![0u8; n[0] as usize + 2];
                s.read_exact(&mut skip)?;
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad SOCKS5 atyp")),
        }
        Ok(())
    }

    fn http_connect(s: &mut TcpStream, dest_ip: IpAddr, dest_port: u16, domain: Option<&str>) -> io::Result<()> {
        let host = match domain {
            Some(d) => d.to_string(),
            None => match dest_ip {
                IpAddr::V4(a) => a.to_string(),
                IpAddr::V6(a) => format!("[{}]", a), // literals need brackets in authority form
            },
        };
        let req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
            host, dest_port, host, dest_port
        );
        s.write_all(req.as_bytes())?;

        // Read the status line + headers up to the blank line.
        let mut buf = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        loop {
            s.read_exact(&mut byte)?;
            buf.push(byte[0]);
            let n = buf.len();
            if n >= 4 && buf[n - 4..] == *b"\r\n\r\n" {
                break;
            }
            if n > 65536 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP CONNECT response too large"));
            }
        }

        let head = String::from_utf8_lossy(&buf);
        // Expect "HTTP/1.x 200 ...".
        let ok = head.split_whitespace().nth(1).map(|code| code == "200").unwrap_or(false);
        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("HTTP CONNECT rejected: {}", head.lines().next().unwrap_or("")),
            ));
        }
        Ok(())
    }
}

use proxy::ProxyConfig;

// ---------------------------------------------------------------------------
// Process resolution:
//   * source (ip, port) -> owning PID, via the TCP owner-PID table (+ a TTL cache)
//   * process *names* ("Veee.exe", "tailscaled.exe", ...) -> the set of matching
//     PIDs, via a toolhelp snapshot. Resolved live so a VPN restart (new PID) is
//     picked up.
// ---------------------------------------------------------------------------

mod process {
    use super::*;

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const PID_CACHE_TTL: Duration = Duration::from_secs(30);

    pub fn self_pid() -> u32 {
        unsafe { GetCurrentProcessId() }
    }

    /// All PIDs whose image name matches any of `names` (case-insensitive). A
    /// program may run more than one process, so we except every match. The
    /// toolhelp snapshot is walked once for the whole list.
    pub fn pids_by_names(names: &[&str]) -> HashSet<u32> {
        let mut out = HashSet::new();
        unsafe {
            let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return out,
            };
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snap, &mut entry).is_ok() {
                loop {
                    if names.iter().any(|n| exe_name_matches(&entry.szExeFile, n)) {
                        out.insert(entry.th32ProcessID);
                    }
                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snap);
        }
        out
    }

    fn exe_name_matches(sz: &[u16; 260], name: &str) -> bool {
        let len = sz.iter().position(|&c| c == 0).unwrap_or(sz.len());
        let s = String::from_utf16_lossy(&sz[..len]);
        s.eq_ignore_ascii_case(name)
    }

    /// Image name ("foo.exe") of the process behind `pid`, via its full module
    /// path. Requires only query-limited access, so it works for other users'
    /// and elevated processes without debug privilege. "?" when unresolvable
    /// (exited, or access denied).
    pub fn exe_name_by_pid(pid: u32) -> String {
        if pid == 0 {
            return "?".to_string();
        }
        unsafe {
            let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return "?".to_string(),
            };
            let mut buf = [0u16; 260];
            let mut len = buf.len() as u32;
            let ok =
                QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
                    .is_ok();
            let _ = windows::Win32::Foundation::CloseHandle(h);
            if !ok || len == 0 {
                return "?".to_string();
            }
            let path = String::from_utf16_lossy(&buf[..len as usize]);
            match path.rsplit(['\\', '/']).next() {
                Some(name) if !name.is_empty() => name.to_string(),
                _ => "?".to_string(),
            }
        }
    }

    /// Owning PID for a TCP connection (IPv4 or IPv6) identified by its local
    /// address and port, plus the owner's image name. Results are cached briefly
    /// so a burst of new connections does not each pay a full table walk.
    pub struct PidResolver {
        cache: RwLock<HashMap<(IpAddr, u16), (u32, String, Instant)>>,
    }

    impl Default for PidResolver {
        fn default() -> Self {
            Self { cache: RwLock::new(HashMap::new()) }
        }
    }

    impl PidResolver {
        pub fn lookup(&self, src: IpAddr, src_port: u16) -> (u32, String) {
            if let Some((pid, name)) = self.cached(src, src_port) {
                return (pid, name);
            }
            let pid = query_tcp_owner(src, src_port);
            if pid != 0 {
                // Resolve once per connection decision; the name is stable for a
                // given PID (barring reuse within the TTL, which is cosmetic).
                let name = exe_name_by_pid(pid);
                if let Ok(mut c) = self.cache.write() {
                    c.insert((src, src_port), (pid, name.clone(), Instant::now()));
                }
                return (pid, name);
            }
            (0, "?".to_string())
        }

        /// Evict a cached PID when a fresh SYN reuses an ephemeral port, so the
        /// decision is re-derived against the current owner.
        pub fn evict(&self, src: IpAddr, src_port: u16) {
            if let Ok(mut c) = self.cache.write() {
                c.remove(&(src, src_port));
            }
        }

        pub fn cleanup(&self) {
            let now = Instant::now();
            if let Ok(mut c) = self.cache.write() {
                c.retain(|_, (_, _, t)| now.duration_since(*t) < PID_CACHE_TTL);
            }
        }

        fn cached(&self, src: IpAddr, src_port: u16) -> Option<(u32, String)> {
            let c = self.cache.read().ok()?;
            match c.get(&(src, src_port)) {
                Some((pid, name, t)) if t.elapsed() < PID_CACHE_TTL => Some((*pid, name.clone())),
                _ => None,
            }
        }
    }

    /// Fetch the TCP owner-PID table for an address family as a raw buffer.
    unsafe fn tcp_table(af: u32) -> Option<Vec<u8>> {
        unsafe {
            let mut size: u32 = 0;
            // First call sizes the buffer (returns ERROR_INSUFFICIENT_BUFFER).
            let _ = GetExtendedTcpTable(None, &mut size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
            if size == 0 {
                return None;
            }
            // The table can grow between the two calls, so retry a few times.
            for _ in 0..4 {
                let mut buf: Vec<u8> = vec![0u8; size as usize];
                let rc = GetExtendedTcpTable(
                    Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                    &mut size,
                    false,
                    af,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );
                if rc == NO_ERROR.0 {
                    return Some(buf);
                }
                if rc != ERROR_INSUFFICIENT_BUFFER.0 {
                    return None;
                }
            }
            None
        }
    }

    /// Number of rows that actually fit in `buf` (guards against a bad header).
    fn row_count<T>(buf: &[u8]) -> usize {
        if buf.len() < 4 {
            return 0;
        }
        let num = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        num.min((buf.len() - 4) / std::mem::size_of::<T>())
    }

    fn query_tcp_owner(ip: IpAddr, port: u16) -> u32 {
        unsafe {
            // MIB_TCP(6)TABLE_OWNER_PID = { DWORD dwNumEntries; ROW table[..] }
            match ip {
                IpAddr::V4(a) => {
                    let Some(buf) = tcp_table(AF_INET) else { return 0 };
                    let raw = u32::from_le_bytes(a.octets()); // in-memory network-order word
                    let rows = buf.as_ptr().add(4) as *const MIB_TCPROW_OWNER_PID;
                    let mut found = 0u32;
                    for i in 0..row_count::<MIB_TCPROW_OWNER_PID>(&buf) {
                        let row = std::ptr::read_unaligned(rows.add(i));
                        let row_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                        if row.dwLocalAddr == raw && row_port == port {
                            if row.dwState == 3 {
                                return row.dwOwningPid; // SYN_SENT: the connection being opened
                            }
                            if found == 0 {
                                found = row.dwOwningPid; // skip stale pid-0 rows (TIME_WAIT...)
                            }
                        }
                    }
                    found
                }
                IpAddr::V6(a) => {
                    let Some(buf) = tcp_table(AF_INET6) else { return 0 };
                    let want = a.octets();
                    let rows = buf.as_ptr().add(4) as *const MIB_TCP6ROW_OWNER_PID;
                    let mut found = 0u32;
                    for i in 0..row_count::<MIB_TCP6ROW_OWNER_PID>(&buf) {
                        let row = std::ptr::read_unaligned(rows.add(i));
                        let row_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                        if row.ucLocalAddr == want && row_port == port {
                            if row.dwState == 3 {
                                return row.dwOwningPid;
                            }
                            if found == 0 {
                                found = row.dwOwningPid;
                            }
                        }
                    }
                    found
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared runtime state handed to every worker thread.
// ---------------------------------------------------------------------------

mod state {
    use super::*;

    /// Two 2048-word bitmaps (8 KB each) per address family cache the
    /// DIRECT/PROXY decision per source port, so only a connection's first packet
    /// pays for the PID lookup. Writes use atomics; aligned 32-bit reads are atomic, so no lock
    /// is taken on the hot path.
    const BITMAP_WORDS: usize = 2048;

    /// Local wall-clock stamp prefixed on every verbose log line, e.g.
    /// `2026-10-03 12:38:30.512`. Uses Win32 GetLocalTime to stay dependency-free.
    pub fn now_stamp() -> String {
        let t = unsafe { GetLocalTime() };
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds
        )
    }

    pub struct Shared {
        pub conntrack: ConnTrack,
        pub dns: DnsCache,
        pub pids: process::PidResolver,
        pub proxy: ProxyConfig,
        pub relay_port: u16,
        pub self_pid: u32,
        /// PIDs of the excepted process (resolved by name, refreshed live).
        pub vpn_pids: RwLock<HashSet<u32>>,
        /// Process names to keep in `vpn_pids` (from the config file); the
        /// refresher re-resolves these by name every few seconds.
        pub except_names: Vec<String>,
        pub running: AtomicBool,
        pub verbose: AtomicBool,
        /// Set once the IPv6 relay listener is bound; until then IPv6 flows go DIRECT.
        pub relay6_ok: AtomicBool,
        // Index 0 = IPv4, 1 = IPv6 (separate port spaces).
        decided: [[AtomicU32; BITMAP_WORDS]; 2],
        direct: [[AtomicU32; BITMAP_WORDS]; 2],
    }

    impl Shared {
        pub fn new(proxy: ProxyConfig, relay_port: u16, self_pid: u32, vpn_pids: HashSet<u32>, except_names: Vec<String>, verbose: bool) -> Self {
            Self {
                conntrack: ConnTrack::default(),
                dns: DnsCache::default(),
                pids: process::PidResolver::default(),
                proxy,
                relay_port,
                self_pid,
                vpn_pids: RwLock::new(vpn_pids),
                except_names,
                running: AtomicBool::new(true),
                verbose: AtomicBool::new(verbose),
                relay6_ok: AtomicBool::new(false),
                decided: [const { [const { AtomicU32::new(0) }; BITMAP_WORDS] }; 2],
                direct: [const { [const { AtomicU32::new(0) }; BITMAP_WORDS] }; 2],
            }
        }

        #[inline]
        pub fn is_decided(&self, port: u16, v6: bool) -> bool {
            let (f, p) = (v6 as usize, port as usize);
            self.decided[f][p >> 5].load(Ordering::Relaxed) & (1 << (p & 31)) != 0
        }
        #[inline]
        pub fn is_direct(&self, port: u16, v6: bool) -> bool {
            let (f, p) = (v6 as usize, port as usize);
            self.direct[f][p >> 5].load(Ordering::Relaxed) & (1 << (p & 31)) != 0
        }
        #[inline]
        pub fn set_direct(&self, port: u16, v6: bool) {
            let (f, p) = (v6 as usize, port as usize);
            let bit = 1u32 << (p & 31);
            self.decided[f][p >> 5].fetch_or(bit, Ordering::Relaxed);
            self.direct[f][p >> 5].fetch_or(bit, Ordering::Relaxed);
        }
        #[inline]
        pub fn set_proxy(&self, port: u16, v6: bool) {
            let (f, p) = (v6 as usize, port as usize);
            self.decided[f][p >> 5].fetch_or(1u32 << (p & 31), Ordering::Relaxed);
            // direct bit stays 0
        }
        #[inline]
        pub fn clear_port(&self, port: u16, v6: bool) {
            let (f, p) = (v6 as usize, port as usize);
            let mask = !(1u32 << (p & 31));
            self.decided[f][p >> 5].fetch_and(mask, Ordering::Relaxed);
            self.direct[f][p >> 5].fetch_and(mask, Ordering::Relaxed);
        }

        pub fn is_excepted(&self, pid: u32) -> bool {
            if pid == self.self_pid {
                return true;
            }
            self.vpn_pids.read().map(|s| s.contains(&pid)).unwrap_or(false)
        }

        pub fn log(&self, msg: &str) {
            if self.verbose.load(Ordering::Relaxed) {
                println!("{} {}", now_stamp(), msg);
            }
        }
    }
}

use state::Shared;

// ---------------------------------------------------------------------------
// Local relay: accepts redirected connections, tunnels each through the
// upstream proxy, and pumps bytes both ways. `std::thread` + `io::copy` replace
// the hand-rolled thread/ref-count machinery of the C version.
// ---------------------------------------------------------------------------

mod relay {
    use super::*;

    /// Bound the upstream connect+handshake so a stalled proxy fails fast (and
    /// is logged) instead of hanging the handler thread forever.
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

    pub fn run(shared: Arc<Shared>) {
        // IPv6 listener on its own thread. On Windows a [::] socket is v6-only by
        // default, so it coexists with the 0.0.0.0 listener on the same port.
        let s6 = shared.clone();
        thread::spawn(move || {
            let bind = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, s6.relay_port, 0, 0));
            accept_loop(s6, bind, true);
        });

        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, shared.relay_port));
        accept_loop(shared, bind, false);
    }

    fn accept_loop(shared: Arc<Shared>, bind: SocketAddr, v6: bool) {
        let listener = match TcpListener::bind(bind) {
            Ok(l) => l,
            Err(e) => {
                if v6 {
                    eprintln!(
                        "WARNING: IPv6 relay bind on {} failed: {} (IPv6 traffic will bypass the proxy)",
                        bind, e
                    );
                } else {
                    eprintln!("ERROR: relay bind on {} failed: {}", bind, e);
                }
                return;
            }
        };
        let _ = listener.set_nonblocking(true);
        if v6 {
            shared.relay6_ok.store(true, Ordering::Relaxed);
        }
        shared.log(&format!("relay listening on {}", bind));

        while shared.running.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((client, peer)) => {
                    let shared = shared.clone();
                    thread::spawn(move || handle(client, peer, shared));
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    }

    fn handle(client: TcpStream, peer: SocketAddr, shared: Arc<Shared>) {
        // CRITICAL: on Windows an accepted socket INHERITS the listener's
        // non-blocking mode (the accept loop above sets it). A non-blocking
        // client makes the upload io::copy fail on its very first empty recv
        // with WSAEWOULDBLOCK (os error 10035), killing the app->proxy
        // direction instantly: the tunnel only ever carries the first queued
        // burst, the upstream eventually FINs, and the app sees EOF/reset
        // mid-handshake. The C version never hit this (select + blocking
        // accept). Put the socket back into blocking mode immediately.
        if let Err(e) = client.set_nonblocking(false) {
            shared.log(&format!("relay: set_nonblocking(false) on :{} failed: {}", peer.port(), e));
        }

        // The redirected SYN preserved the client's original source port; that
        // (plus the address family) is the key we recorded the real destination under.
        let client_port = peer.port();
        let (dest_ip, dest_port) = match shared.conntrack.get_dest(client_port, peer.is_ipv6()) {
            Some(d) => d,
            None => {
                shared.log(&format!("relay: no conntrack entry for :{}", client_port));
                return;
            }
        };

        let domain = if SEND_DOMAIN_TO_PROXY { shared.dns.lookup(dest_ip) } else { None };
        shared.log(&format!(
            "relay :{} -> {}:{} host={} (dialing proxy)",
            client_port,
            dest_ip,
            dest_port,
            domain.as_deref().unwrap_or("<none, sending IP>")
        ));

        let proxy_addr = SocketAddr::V4(SocketAddrV4::new(shared.proxy.addr, shared.proxy.port));
        let mut proxy = match TcpStream::connect(proxy_addr) {
            Ok(s) => s,
            Err(e) => {
                shared.log(&format!("proxy connect failed ({}): {}", proxy_addr, e));
                return;
            }
        };
        let _ = client.set_nodelay(true);
        let _ = proxy.set_nodelay(true);
        // 4 MB kernel socket buffers on both legs (same as the C relay): pulls
        // stream multi-MB layer blobs; small buffers stall the pump on every
        // window update and slow tunnels to a crawl.
        set_big_buffers(&client);
        set_big_buffers(&proxy);

        // Time-box the handshake: a proxy that accepts TCP but stalls on CONNECT
        // would otherwise hang this thread forever while the caller silently
        // retries.
        let _ = proxy.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
        let _ = proxy.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
        if let Err(e) = shared.proxy.connect(&mut proxy, dest_ip, dest_port, domain.as_deref()) {
            shared.log(&format!("proxy handshake failed ({}:{}): {}", dest_ip, dest_port, e));
            return;
        }
        // Clear timeouts so an established (possibly idle) tunnel is not torn down.
        let _ = proxy.set_read_timeout(None);
        let _ = proxy.set_write_timeout(None);

        shared.log(&format!("tunnel :{} -> {}:{}", client_port, dest_ip, dest_port));
        pump(client, proxy, client_port, &shared);
    }

    /// Bidirectional copy with graceful (FIN-only) teardown toward the app.
    ///
    /// We must never shutdown(Both) the client socket when the proxy side
    /// EOFs: that aborts with an RST, and on Windows an arriving RST discards
    /// response bytes still unread in the app's receive buffer. A fully
    /// successful transfer then surfaces as "connection reset by peer" (the
    /// wslc pull signature: tunnel logged a clean EOF with ~4.5 KB down while
    /// the engine reported a reset). Instead: forward the EOF as a FIN, let
    /// the app drain its buffer and close; the upload copy ends on that FIN,
    /// and by then the receive queue is drained so closing cannot RST.
    fn pump(client: TcpStream, proxy: TcpStream, client_port: u16, shared: &Shared) {
        let (mut up_c, mut up_p) = match (client.try_clone(), proxy.try_clone()) {
            (Ok(c), Ok(p)) => (c, p),
            _ => return,
        };

        // Upload result comes back over a channel: JoinHandle cannot be waited
        // on with a deadline, but recv_timeout can.
        let (tx, rx) = std::sync::mpsc::channel();
        let upload = thread::spawn(move || {
            let r = io::copy(&mut up_c, &mut up_p);
            // App's request stream ended: half-close the proxy side too.
            let _ = up_p.shutdown(Shutdown::Write);
            let _ = tx.send(r);
        });

        let (mut dn_client, mut dn_proxy) = (client, proxy);
        let down = io::copy(&mut dn_proxy, &mut dn_client);

        // Download ended: FIN toward the app (receive path stays intact so the
        // app can still drain everything we already sent it). Do NOT half-close
        // the proxy leg here: registries close after a 401/Connection: close
        // response while the app still has bytes in flight (next request, TLS
        // records); shutting the proxy send side at this instant makes the
        // upload copy fail with WSAESHUTDOWN (os error 10058) and silently
        // drops those bytes - the intermittent "EOF" failures. The proxy side
        // is half-closed only when the app's own FIN ends the upload copy.
        let _ = dn_client.shutdown(Shutdown::Write);

        // Wait for the app to read its buffer and close (its FIN ends the
        // upload copy). Well-behaved clients do this promptly; the deadline
        // only guards against a peer that holds the socket shut forever, and
        // must be generous enough for the app to drain a multi-MB tail.
        let up = match rx.recv_timeout(Duration::from_secs(120)) {
            Ok(r) => r,
            Err(_) => {
                shared.log(&format!(
                    "tunnel :{}: app did not close 120s after FIN, aborting",
                    client_port
                ));
                // Unblock the upload thread; the app forfeited graceful close.
                let _ = dn_client.shutdown(Shutdown::Both);
                let _ = dn_proxy.shutdown(Shutdown::Both);
                rx.recv().unwrap_or_else(|_| Err(io::Error::other("upload thread gone")))
            }
        };
        let _ = upload.join();

        shared.log(&format!(
            "tunnel :{} closed (down: {}; up: {})",
            client_port,
            end_kind(down),
            end_kind(up)
        ));
    }

    fn end_kind(r: io::Result<u64>) -> String {
        match r {
            Ok(n) => format!("clean EOF, {} bytes", n),
            Err(e) => format!("ERROR {} (raw {:?})", e, e.raw_os_error()),
        }
    }

    /// Best-effort SO_SNDBUF/SO_RCVBUF of 4 MB (mirrors the C relay's
    /// configure_tcp_socket; std's equivalents are unstable on this toolchain).
    fn set_big_buffers(sock: &TcpStream) {
        use std::os::windows::io::AsRawSocket;
        use windows::Win32::Networking::WinSock::{
            setsockopt, SO_RCVBUF, SO_SNDBUF, SOCKET, SOL_SOCKET,
        };
        let raw = SOCKET(sock.as_raw_socket() as usize);
        let val = (4 * 1024 * 1024i32).to_ne_bytes();
        unsafe {
            let _ = setsockopt(raw, SOL_SOCKET, SO_RCVBUF, Some(&val));
            let _ = setsockopt(raw, SOL_SOCKET, SO_SNDBUF, Some(&val));
        }
    }
}

// ---------------------------------------------------------------------------
// WinDivert packet loop: TCP/IPv4 only. Every new outbound connection is
// decided DIRECT or PROXY once (by owning PID); the decision is cached per
// source port so data packets take a straight-line path.
// ---------------------------------------------------------------------------

mod packet {
    use super::*;

    /// Destinations that must never be handed to the upstream (internet) proxy:
    /// loopback, private LAN, link-local, CGNAT/overlay, multicast/broadcast and
    /// other reserved ranges. Docker's bridge (172.17/16), Tailscale (100.64/10,
    /// fd7a:115c:a1e0::/48) and LAN services fall in here and break if proxied.
    fn is_non_routable_v4(ip: Ipv4Addr) -> bool {
        let o = ip.octets();
        ip.is_loopback()          // 127.0.0.0/8
            || ip.is_unspecified()    // 0.0.0.0
            || ip.is_private()        // 10/8, 172.16/12, 192.168/16
            || ip.is_link_local()     // 169.254/16
            || ip.is_multicast()      // 224/4
            || o[0] >= 240            // 240/4 reserved (incl. 255.255.255.255)
            // 100.64.0.0/10 (RFC 6598 shared/CGNAT): Tailscale & other overlay nets
            // live here and are reachable only via their own local interface.
            || (o[0] == 100 && (64..=127).contains(&o[1]))
    }

    fn is_non_routable_v6(ip: Ipv6Addr) -> bool {
        // ::ffff:a.b.c.d is just an IPv4 address in disguise.
        if let Some(v4) = ip.to_ipv4_mapped() {
            return is_non_routable_v4(v4);
        }
        let s0 = ip.segments()[0];
        ip.is_loopback()                  // ::1
            || ip.is_unspecified()        // ::
            || ip.is_multicast()          // ff00::/8
            || (s0 & 0xfe00) == 0xfc00    // fc00::/7 unique-local (LAN, Tailscale ULA)
            || (s0 & 0xffc0) == 0xfe80    // fe80::/10 link-local
            || (s0 & 0xffc0) == 0xfec0    // fec0::/10 site-local (deprecated)
    }

    fn is_non_routable(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => is_non_routable_v4(a),
            IpAddr::V6(a) => is_non_routable_v6(a),
        }
    }

    /// The packet's network header, IPv4 or IPv6.
    #[derive(Clone, Copy)]
    enum L3 {
        V4(*mut IpHdr),
        V6(*mut Ipv6Hdr),
    }

    impl L3 {
        #[inline]
        fn is_v6(self) -> bool {
            matches!(self, L3::V6(_))
        }
        #[inline]
        unsafe fn src(self) -> IpAddr {
            unsafe {
                match self {
                    L3::V4(p) => IpAddr::V4(Ipv4Addr::from((*p).src_addr.to_le_bytes())),
                    L3::V6(p) => IpAddr::V6(Ipv6Addr::from((*p).src_addr)),
                }
            }
        }
        #[inline]
        unsafe fn dst(self) -> IpAddr {
            unsafe {
                match self {
                    L3::V4(p) => IpAddr::V4(Ipv4Addr::from((*p).dst_addr.to_le_bytes())),
                    L3::V6(p) => IpAddr::V6(Ipv6Addr::from((*p).dst_addr)),
                }
            }
        }
        /// Swap source/destination addresses in place (used when redirecting a
        /// packet to the relay and when un-redirecting a relay response).
        #[inline]
        unsafe fn swap(self) {
            unsafe {
                match self {
                    L3::V4(p) => std::mem::swap(&mut (*p).src_addr, &mut (*p).dst_addr),
                    L3::V6(p) => std::mem::swap(&mut (*p).src_addr, &mut (*p).dst_addr),
                }
            }
        }
    }

    pub fn run(wd: Arc<WinDivert>, shared: Arc<Shared>) {
        let mut packet = vec![0u8; MAXBUF];
        let mut addr: Address = unsafe { std::mem::zeroed() };
        let relay_be = shared.relay_port.to_be();

        while shared.running.load(Ordering::Relaxed) {
            let mut len: u32 = 0;
            if !wd.recv(&mut packet, &mut len, &mut addr) {
                break; // handle closed / shutdown
            }

            let parsed = wd.parse(&packet, len);

            // Inbound UDP/53 replies (the only UDP the filter captures): learn
            // ip -> hostname (A and AAAA), then pass the packet on untouched.
            if parsed.is_udp {
                if let Some((ptr, n)) = parsed.data {
                    let payload = unsafe { std::slice::from_raw_parts(ptr, n) };
                    if let Some((name, count)) = shared.dns.snoop(payload) {
                        shared.log(&format!("[DNS] {} ({} address record(s))", name, count));
                    }
                }
                wd.send(&packet, len, &addr);
                continue;
            }

            let (l3, tcp) = match (parsed.ip, parsed.ip6, parsed.tcp) {
                (Some(i), _, Some(t)) => (L3::V4(i), t),
                (None, Some(i), Some(t)) => (L3::V6(i), t),
                // Non-first fragment or unexpected: pass through untouched.
                _ => {
                    wd.send(&packet, len, &addr);
                    continue;
                }
            };
            let v6 = l3.is_v6();

            unsafe {
                if addr.outbound() {
                    if (*tcp).src_port == relay_be {
                        // Response from our relay back to the client: restore the
                        // real server port and swap addresses so it looks
                        // server-originated.
                        let dst_port = (*tcp).dst_port_host();
                        match shared.conntrack.get_dest(dst_port, v6) {
                            Some((_, orig_port)) => (*tcp).set_src_port_host(orig_port),
                            None => {
                                // Cannot be un-redirected. Leaking it would hand the
                                // app a packet from :RELAY_PORT and make it send RST.
                                // Silent: after an app RST this fires for every
                                // in-flight packet of the dying tunnel (90+ line floods
                                // observed); the [app rst] line already told the story.
                                continue;
                            }
                        }
                        if (*tcp).syn() && (*tcp).ack() {
                            shared.log(&format!("[relay syn-ack] :{}{}", dst_port, if v6 { " (v6)" } else { "" }));
                        }
                        if !(l3.src().is_loopback() && l3.dst().is_loopback()) {
                            l3.swap();
                            addr.set_outbound(false);
                        }
                        // A FIN is only a half-close: the final ACKs of the close
                        // handshake still need the mapping. Only RST is terminal.
                        if (*tcp).rst() {
                            // Visible teardown: covers a proxy/server reset flowing
                            // back to the app AND our own pump() shutdown Both-RST.
                            shared.log(&format!("[tunnel rst] -> :{} (conntrack dropped)", dst_port));
                            shared.conntrack.remove(dst_port, v6);
                        }
                    } else {
                        let sp = (*tcp).src_port_host();
                        let is_new_syn = (*tcp).syn() && !(*tcp).ack();

                        // A fresh SYN always starts a new connection, so any cached
                        // decision for this port is stale (port reuse / missed FIN).
                        if is_new_syn {
                            shared.clear_port(sp, v6);
                            shared.pids.evict(l3.src(), sp);
                        }

                        if shared.is_decided(sp, v6) {
                            if shared.is_direct(sp, v6) {
                                if (*tcp).fin() || (*tcp).rst() {
                                    shared.clear_port(sp, v6);
                                }
                                wd.send(&packet, len, &addr);
                                continue;
                            }
                            // PROXY fast path: bitmap is authoritative, no table
                            // lookup. Proxied destinations are never loopback, so
                            // swap unconditionally.
                            if (*tcp).rst() {
                                shared.log(&format!("[app rst] proxied conn :{} reset before/while tunneled", sp));
                            }
                            // Only RST ends the flow. After the app's FIN the
                            // server may still be sending, and the app's later ACKs
                            // must keep going to the relay, not out to the real server.
                            if (*tcp).rst() {
                                shared.conntrack.remove(sp, v6);
                                shared.clear_port(sp, v6);
                            }
                            (*tcp).set_dst_port_host(shared.relay_port);
                            l3.swap();
                            addr.set_outbound(false);
                        } else if !is_new_syn {
                            // Mid-stream packet of a connection we never saw start
                            // (pre-existing, or a local server's reply): leave it
                            // alone, but mark the port DIRECT so the leak is logged
                            // exactly once per connection. Without this, a dropped
                            // or pre-start SYN means the flow runs unredirected in
                            // total silence (the wslc failure signature).
                            if !shared.is_decided(sp, v6) {
                                shared.set_direct(sp, v6);
                                shared.log(&format!(
                                    "[PASS] mid-stream :{} -> {}:{} (SYN never seen)",
                                    sp,
                                    l3.dst(),
                                    (*tcp).dst_port_host()
                                ));
                            }
                            wd.send(&packet, len, &addr);
                            continue;
                        } else {
                            let src_ip = l3.src();
                            let dest_ip = l3.dst();
                            let orig_dest_port = (*tcp).dst_port_host();
                            let (pid, pname) = shared.pids.lookup(src_ip, sp);

                            let non_routable = is_non_routable(dest_ip);
                            // Same rule set as the original C `check_process_rule`, which
                            // only ever hands traffic to the "*" -> PROXY wildcard rule if
                            // its owner is fully attributable. Anything else short-circuits
                            // to DIRECT *before* rule matching:
                            //   pid == 0  -> no TCP-table owner (forwarded VM/WSL
                            //              traffic, lookup race)
                            //   pid == 4  -> System; C's get_process_name_from_pid() also
                            //              refuses it
                            //   name "?"  -> image name unqueryable (protected, pico, or
                            //              already-exited process); C returns DIRECT
                            // Only after those does C fall through to the process-name
                            // rules, which for proxyall are self + the except list.
                            let unattributed = pid == 0 || pid == 4 || pname == "?";
                            let excepted = unattributed || shared.is_excepted(pid);
                            // No IPv6 relay listener => nothing to redirect v6 flows to.
                            let relay_down = v6 && !shared.relay6_ok.load(Ordering::Relaxed);

                            if non_routable || excepted || relay_down {
                                shared.log(&format!(
                                    "[DIRECT] {} (pid {}) :{} -> {}:{} ({})",
                                    pname, pid, sp, dest_ip, orig_dest_port,
                                    if non_routable {
                                        "non-routable dest"
                                    } else if pid == 0 {
                                        "unknown owner (pid 0)"
                                    } else if unattributed {
                                        "unattributable owner (C: direct)"
                                    } else if excepted {
                                        "excepted process"
                                    } else {
                                        "IPv6 relay unavailable"
                                    }
                                ));
                                shared.set_direct(sp, v6);
                                wd.send(&packet, len, &addr);
                                continue;
                            }

                            shared.log(&format!(
                                "[PROXY] {} (pid {}) :{} -> {}:{}",
                                pname, pid, sp, dest_ip, orig_dest_port
                            ));
                            shared.conntrack.insert(sp, v6, dest_ip, orig_dest_port);
                            shared.set_proxy(sp, v6);
                            (*tcp).set_dst_port_host(shared.relay_port);
                            l3.swap();
                            addr.set_outbound(false);
                        }
                    }
                } else if (*tcp).dst_port != relay_be {
                    // Inbound and not for the relay: pass through untouched.
                    wd.send(&packet, len, &addr);
                    continue;
                }
            }

            wd.calc_checksums(&mut packet, len, &mut addr);
            if !wd.send(&packet, len, &addr) {
                shared.log("WinDivertSend failed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point and background threads.
// ---------------------------------------------------------------------------

unsafe extern "system" fn ctrl_handler(_ctrl: u32) -> BOOL {
    STOP.store(true, Ordering::SeqCst);
    BOOL(1)
}

// ---------------------------------------------------------------------------
// Runtime configuration (proxyall.config.json)
// ---------------------------------------------------------------------------

mod config {
    use super::*;
    use serde::Deserialize;

    /// Shape of `proxyall.config.json`. `proxy` is a URL string; `except` lists
    /// process names whose traffic bypasses the proxy (absent = except nothing).
    #[derive(Deserialize)]
    struct RawConfig {
        proxy: String,
        #[serde(default)]
        except: Vec<String>,
    }

    /// Fully-resolved runtime configuration.
    pub struct AppConfig {
        pub proxy_url: String,
        pub except: Vec<String>,
    }

    impl Default for AppConfig {
        fn default() -> Self {
            Self {
                proxy_url: DEFAULT_PROXY_URL.to_string(),
                except: DEFAULT_EXCEPT.iter().map(|s| s.to_string()).collect(),
            }
        }
    }

    /// Parse a proxy URL like `socks5://127.0.0.1:15235` or `http://127.0.0.1:15236`
    /// into (kind, host, port). Tolerates an optional `user:pass@` prefix (auth is
    /// not performed by the handshake and will simply fail there if the proxy
    /// demands it) and bracketed IPv6 literals like `[::1]:1080`.
    pub fn parse_proxy_url(url: &str) -> Result<(proxy::ProxyKind, String, u16), String> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| "must look like socks5://host:port or http://host:port".to_string())?;
        let kind = match scheme.to_ascii_lowercase().as_str() {
            "socks5" | "socks5h" => proxy::ProxyKind::Socks5,
            "http" => proxy::ProxyKind::Http,
            other => return Err(format!("unsupported scheme '{other}' (use socks5:// or http://)")),
        };
        // Drop any userinfo; only the authority part matters here.
        let authority = rest.rsplit('@').next().unwrap_or(rest);
        let (host, port_str) = if authority.starts_with('[') {
            let (h, p) = authority
                .split_once("]:")
                .ok_or_else(|| "malformed IPv6 endpoint, expected [addr]:port".to_string())?;
            (h.trim_start_matches('['), p)
        } else {
            authority
                .rsplit_once(':')
                .ok_or_else(|| "endpoint must include :port".to_string())?
        };
        let port: u16 = port_str.trim().parse().map_err(|_| format!("invalid port '{port_str}'"))?;
        let host = host.trim();
        if host.is_empty() {
            return Err("empty proxy host".to_string());
        }
        Ok((kind, host.to_string(), port))
    }

    /// Locate and read `proxyall.config.json` (next to the exe, then the current
    /// directory), returning it plus a human-readable source description. A
    /// missing file falls back to defaults; a present-but-malformed file is fatal
    /// so the user sees the mistake instead of silently running on the wrong proxy.
    pub fn load_or_default() -> (AppConfig, String) {
        let candidates = [exe_dir(), env::current_dir().unwrap_or_else(|_| PathBuf::from("."))];
        let mut found: Option<PathBuf> = None;
        for dir in candidates.iter() {
            let p = dir.join(CONFIG_FILE);
            if p.is_file() {
                found = Some(p);
                break;
            }
        }
        match found {
            Some(path) => {
                let text = match std::fs::read_to_string(&path) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("ERROR: cannot read {}: {}", path.display(), e);
                        exit(1);
                    }
                };
                match serde_json::from_str::<RawConfig>(&text) {
                    Ok(raw) => (
                        AppConfig { proxy_url: raw.proxy, except: raw.except },
                        path.display().to_string(),
                    ),
                    Err(e) => {
                        eprintln!("ERROR: cannot parse {}: {}", path.display(), e);
                        exit(1);
                    }
                }
            }
            None => (AppConfig::default(), "built-in defaults (no config file found)".to_string()),
        }
    }
}

fn main() {
    let verbose = env::args().any(|a| a == "--verbose");

    // Load the proxy URL and except list from proxyall.config.json (or fall back
    // to built-in defaults when the file is absent).
    let (cfg, cfg_source) = config::load_or_default();
    let (kind, phost, pport) = match config::parse_proxy_url(&cfg.proxy_url) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: invalid proxy URL '{}' in config: {}", cfg.proxy_url, e);
            exit(1);
        }
    };
    let addr = match resolve_v4(&phost) {
        Some(a) => a,
        None => {
            eprintln!("ERROR: cannot resolve proxy host '{}' to an IPv4 address.", phost);
            exit(1);
        }
    };
    let proxy = ProxyConfig { kind, host: phost, port: pport, addr };

    // Resolve the excepted processes by name (may be empty if none are running
    // yet; the refresher thread below keeps the set up to date).
    let self_pid = process::self_pid();
    let except_refs: Vec<&str> = cfg.except.iter().map(|s| s.as_str()).collect();
    let vpn_pids = process::pids_by_names(&except_refs);

    let shared = Arc::new(Shared::new(
        proxy.clone(),
        RELAY_PORT,
        self_pid,
        vpn_pids,
        cfg.except.clone(),
        verbose,
    ));

    unsafe {
        let _ = SetConsoleCtrlHandler(Some(ctrl_handler), true);
    }

    // Load WinDivert from the executable's directory.
    let dll_path = exe_dir().join("WinDivert.dll");
    let wd = match WinDivert::load(dll_path.to_string_lossy().as_ref()) {
        Ok(w) => Arc::new(w),
        Err(e) => {
            eprintln!("ERROR: {}", e);
            exit(1);
        }
    };
    let filter = format!(
        "not impostor and ((tcp and (outbound or loopback or tcp.DstPort == {} or tcp.SrcPort == {})) \
         or (udp and not outbound and udp.SrcPort == 53))",
        RELAY_PORT, RELAY_PORT
    );
    if let Err(e) = wd.open(&filter, 123) {
        eprintln!("ERROR: {}", e);
        exit(1);
    }

    print_banner(&proxy, &shared, &cfg_source);

    // Worker threads.
    let s = shared.clone();
    thread::spawn(move || relay::run(s));

    let s = shared.clone();
    thread::spawn(move || vpn_refresher(s));

    let s = shared.clone();
    thread::spawn(move || cleanup(s));

    let wd_pkt = wd.clone();
    let s = shared.clone();
    let pkt_thread = thread::spawn(move || packet::run(wd_pkt, s));

    // Make apps re-resolve on the wire so the DNS sniffer can see the answers
    // (names cached by Windows before startup would otherwise have no mapping).
    if SEND_DOMAIN_TO_PROXY {
        flush_dns_resolver_cache();
    }

    // Wait for Ctrl+C.
    while !STOP.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(200));
    }

    println!("\nstopping proxyall...");
    shared.running.store(false, Ordering::Relaxed);
    wd.shutdown_and_close(); // unblocks the packet thread's recv
    let _ = pkt_thread.join();
    println!("proxyall stopped.");
}

fn vpn_refresher(shared: Arc<Shared>) {
    loop {
        thread::sleep(VPN_REFRESH);
        if !shared.running.load(Ordering::Relaxed) {
            break;
        }
        let refs: Vec<&str> = shared.except_names.iter().map(|s| s.as_str()).collect();
        let pids = process::pids_by_names(&refs);
        if let Ok(mut set) = shared.vpn_pids.write() {
            if *set != pids {
                shared.log(&format!("excepted PIDs now {:?} ({:?})", pids, shared.except_names));
            }
            *set = pids;
        }
    }
}

fn cleanup(shared: Arc<Shared>) {
    loop {
        thread::sleep(CLEANUP_INTERVAL);
        if !shared.running.load(Ordering::Relaxed) {
            break;
        }
        shared.conntrack.cleanup(CONN_STALE);
        shared.pids.cleanup();
        shared.dns.cleanup();
    }
}

/// Flush the Windows DNS client cache (dnsapi!DnsFlushResolverCache), loaded
/// dynamically so there is no link-time dependency.
fn flush_dns_resolver_cache() {
    unsafe {
        if let Ok(lib) = Library::new("dnsapi.dll") {
            if let Ok(f) = lib.get::<unsafe extern "system" fn() -> i32>(b"DnsFlushResolverCache\0") {
                (*f)();
            }
        }
    }
}

fn exe_dir() -> PathBuf {
    match env::current_exe() {
        Ok(p) => p.parent().map(|d| d.to_path_buf()).unwrap_or_else(|| PathBuf::from(".")),
        Err(_) => PathBuf::from("."),
    }
}

fn resolve_v4(host: &str) -> Option<Ipv4Addr> {
    // Accept a literal IPv4 first, otherwise resolve via the system resolver.
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    let addrs = (host, 0u16).to_socket_addrs().ok()?;
    for a in addrs {
        if let std::net::SocketAddr::V4(v4) = a {
            return Some(*v4.ip());
        }
    }
    None
}

fn print_banner(proxy: &ProxyConfig, shared: &Shared, cfg_source: &str) {
    println!();
    println!("  proxyall");
    println!("  Redirect all TCP (IPv4 + IPv6) through a proxy, except listed processes");
    println!();
    println!("  Config     : {}", cfg_source);
    println!("  Proxy      : {}", proxy.describe());
    println!("  Local relay: 0.0.0.0:{} and [::]:{}", shared.relay_port, shared.relay_port);
    println!("  Hostnames  : {}", if SEND_DOMAIN_TO_PROXY { "sent to proxy (DNS sniffing)" } else { "off (IP only)" });
    println!("  Except     : {}", shared.except_names.join(", "));
    let pids = shared.vpn_pids.read().map(|s| s.clone()).unwrap_or_default();
    if pids.is_empty() {
        println!("                 (none running yet - watching for them)");
    } else {
        println!("                 (PID {:?})", pids);
    }
    println!("  Press Ctrl+C to stop.");
    println!();
}