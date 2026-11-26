//! Darwin `libproc` socket owner lookup and short-lived image-path cache.

use std::collections::HashMap;
use std::ffi::{OsStr, c_int, c_void};
use std::fmt;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rosetun_config::ConnectionNetwork;

use super::{ProcessLookup, TcpFlow};

const MAX_PIDS: usize = 16_384;
const MAX_FDS_PER_PID: usize = 8_192;
const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDFDSOCKETINFO: c_int = 3;
const SOCKINFO_IN: c_int = 1;
const SOCKINFO_TCP: c_int = 2;
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;
const SOI_PROTO_BYTES: usize = 528;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
const CACHE_SIZE: usize = 512;
const IMAGE_TTL: Duration = Duration::from_secs(1);
const UDP_TABLE_TTL: Duration = Duration::from_millis(250);
const TCP_TABLE_TTL: Duration = Duration::from_millis(50);

type Images = HashMap<i32, (Instant, Option<String>)>;
type TcpSnapshot = Option<(Instant, HashMap<TcpFlow, i32>)>;
type UdpEntries = HashMap<u16, Vec<(IpAddr, i32)>>;
type UdpSnapshot = Option<(Instant, UdpEntries)>;

/// XNU `struct proc_fileinfo` (`<sys/proc_info.h>`).
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

/// XNU `struct vinfo_stat` (`<sys/proc_info.h>`).
#[repr(C)]
#[derive(Clone, Copy)]
struct VinfoStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: u32,
    vst_gid: u32,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: i64,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

/// XNU `struct sockbuf_info` (`<sys/proc_info.h>`).
#[repr(C)]
#[derive(Clone, Copy)]
struct SockBufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

/// 16-byte address union (`in4in6_addr` / `in6_addr`) aligned to 4 bytes.
#[repr(C, align(4))]
#[derive(Clone, Copy)]
struct InAddrStorage([u8; 16]);

/// XNU `struct in_sockinfo` (`<sys/proc_info.h>`), placed at offset 0 of
/// `soi_proto` for both `SOCKINFO_IN` (`pri_in`) and `SOCKINFO_TCP` (`pri_tcp.tcpsi_ini`).
#[repr(C)]
#[derive(Clone, Copy)]
struct InSockInfo {
    insi_fport: c_int,
    insi_lport: c_int,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    _pad: [u8; 2],
    rfu_1: u32,
    insi_faddr: InAddrStorage,
    insi_laddr: InAddrStorage,
    insi_v4: [u8; 4],
    insi_v6: [u8; 12],
}

/// XNU `struct socket_info` (`<sys/proc_info.h>`).
#[repr(C)]
#[derive(Clone, Copy)]
struct SocketInfo {
    soi_stat: VinfoStat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: c_int,
    soi_protocol: c_int,
    soi_family: c_int,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: SockBufInfo,
    soi_snd: SockBufInfo,
    soi_kind: c_int,
    rfu_1: u32,
    insi: InSockInfo,
    _proto_tail: [u8; SOI_PROTO_BYTES - size_of::<InSockInfo>()],
}

/// XNU `struct socket_fdinfo` (`PROC_PIDFDSOCKETINFO_SIZE == 792` on 64-bit Darwin).
#[repr(C)]
#[derive(Clone, Copy)]
struct SocketFdInfo {
    pfi: ProcFileInfo,
    psi: SocketInfo,
}

const _: () = assert!(size_of::<ProcFileInfo>() == 24);
const _: () = assert!(size_of::<VinfoStat>() == 136);
const _: () = assert!(size_of::<SockBufInfo>() == 24);
const _: () = assert!(size_of::<InSockInfo>() == 80);
const _: () = assert!(size_of::<SocketInfo>() == 768);
const _: () = assert!(size_of::<SocketFdInfo>() == 792);

unsafe extern "C" {
    fn proc_listpids(kind: u32, typeinfo: u32, buffer: *mut c_void, buffersize: c_int) -> c_int;
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
}

#[derive(Default)]
pub struct MacosProcessLookup {
    images: Mutex<Images>,
    tcp: Mutex<TcpSnapshot>,
    udp: Mutex<UdpSnapshot>,
}

impl fmt::Debug for MacosProcessLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacosProcessLookup").finish_non_exhaustive()
    }
}

impl ProcessLookup for MacosProcessLookup {
    fn image(&self, flow: &TcpFlow, network: ConnectionNetwork) -> Option<String> {
        let now = Instant::now();
        let pid = match network {
            ConnectionNetwork::Tcp => self.tcp_owner_cached(flow, now)?,
            ConnectionNetwork::Udp => self.udp_owner_cached(flow.source, now)?,
        };
        if let Some((at, path)) = self.images.lock().ok()?.get(&pid)
            && now.saturating_duration_since(*at) < IMAGE_TTL
        {
            return path.clone();
        }
        let image = process_image(pid);
        let mut images = self.images.lock().ok()?;
        images.retain(|_, (at, _)| now.saturating_duration_since(*at) < IMAGE_TTL);
        if images.len() < CACHE_SIZE {
            images.insert(pid, (now, image.clone()));
        }
        image
    }
}

impl MacosProcessLookup {
    fn tcp_owner_cached(&self, flow: &TcpFlow, now: Instant) -> Option<i32> {
        let canonical = canonical_flow(flow);
        if let Ok(guard) = self.tcp.lock()
            && let Some((captured_at, map)) = guard.as_ref()
            && now.saturating_duration_since(*captured_at) < TCP_TABLE_TTL
            && let Some(&pid) = map.get(&canonical)
        {
            return Some(pid);
        }
        let fresh = build_tcp_snapshot()?;
        let pid = fresh.get(&canonical).copied();
        if let Ok(mut guard) = self.tcp.lock() {
            *guard = Some((now, fresh));
        }
        pid
    }

    fn udp_owner_cached(&self, source: SocketAddr, now: Instant) -> Option<i32> {
        let source = SocketAddr::new(source.ip().to_canonical(), source.port());
        if let Ok(guard) = self.udp.lock()
            && let Some((captured_at, map)) = guard.as_ref()
            && now.saturating_duration_since(*captured_at) < UDP_TABLE_TTL
            && let Some(pid) = match_udp_owner(map, source)
        {
            return Some(pid);
        }
        let fresh = build_udp_snapshot()?;
        let pid = match_udp_owner(&fresh, source);
        if let Ok(mut guard) = self.udp.lock() {
            *guard = Some((now, fresh));
        }
        pid
    }
}

fn canonical_flow(flow: &TcpFlow) -> TcpFlow {
    TcpFlow {
        source: SocketAddr::new(flow.source.ip().to_canonical(), flow.source.port()),
        destination: SocketAddr::new(
            flow.destination.ip().to_canonical(),
            flow.destination.port(),
        ),
    }
}

fn match_udp_owner(entries: &UdpEntries, source: SocketAddr) -> Option<i32> {
    let candidates = entries.get(&source.port())?;
    let mut wildcard = None;
    for &(local_ip, pid) in candidates {
        if local_ip == source.ip() {
            return Some(pid);
        }
        if local_ip.is_unspecified() && wildcard.is_none() {
            wildcard = Some(pid);
        }
    }
    wildcard
}

fn list_pids() -> Option<Vec<i32>> {
    // SAFETY: Null buffer queries the byte count needed for active PIDs.
    let estimated = unsafe { proc_listpids(PROC_ALL_PIDS, 0, ptr::null_mut(), 0) };
    if estimated <= 0 {
        return None;
    }
    let count = ((estimated as usize) / size_of::<i32>())
        .saturating_add(64)
        .min(MAX_PIDS);
    let mut pids = vec![0i32; count];
    let byte_len = c_int::try_from(pids.len() * size_of::<i32>()).ok()?;
    // SAFETY: `pids` is writable for `byte_len` bytes.
    let actual = unsafe { proc_listpids(PROC_ALL_PIDS, 0, pids.as_mut_ptr().cast(), byte_len) };
    if actual <= 0 {
        return None;
    }
    pids.truncate((actual as usize) / size_of::<i32>());
    // SAFETY: `getpid` is always safe and side-effect free.
    let own_pid = unsafe { libc::getpid() };
    pids.retain(|&pid| pid > 0 && pid != own_pid);
    Some(pids)
}

fn visit_process_sockets(mut visit: impl FnMut(i32, &SocketInfo)) -> Option<()> {
    let pids = list_pids()?;
    let fd_size = size_of::<libc::proc_fdinfo>();
    let sock_size = c_int::try_from(size_of::<SocketFdInfo>()).ok()?;
    let mut fds = Vec::new();
    for pid in pids {
        // SAFETY: Null buffer queries the required byte size for `pid`'s fd table.
        let needed = unsafe { proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, ptr::null_mut(), 0) };
        if needed <= 0 {
            continue;
        }
        let count = ((needed as usize) / fd_size)
            .saturating_add(16)
            .min(MAX_FDS_PER_PID);
        fds.resize(
            count,
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            },
        );
        let byte_len = match c_int::try_from(fds.len() * fd_size) {
            Ok(len) => len,
            Err(_) => continue,
        };
        // SAFETY: `fds` is writable for `byte_len` bytes.
        let actual = unsafe {
            proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr().cast(),
                byte_len,
            )
        };
        if actual <= 0 {
            continue;
        }
        let fd_count = (actual as usize) / fd_size;
        for entry in &fds[..fd_count] {
            if entry.proc_fdtype != libc::PROX_FDTYPE_SOCKET as u32 {
                continue;
            }
            // SAFETY: `SocketFdInfo` is plain #[repr(C)] integer/byte data zeroed before kernel fill.
            let mut info: SocketFdInfo = unsafe { std::mem::zeroed() };
            // SAFETY: `info` is writable for `sock_size` (792) bytes.
            let read = unsafe {
                proc_pidfdinfo(
                    pid,
                    entry.proc_fd,
                    PROC_PIDFDSOCKETINFO,
                    (&raw mut info).cast(),
                    sock_size,
                )
            };
            if read == sock_size {
                visit(pid, &info.psi);
            }
        }
    }
    Some(())
}

fn decode_network_port(raw: c_int) -> u16 {
    u16::from_be((raw & 0xffff) as u16)
}

fn decode_in_sockinfo_local(insi: &InSockInfo) -> Option<SocketAddr> {
    let port = decode_network_port(insi.insi_lport);
    if port == 0 {
        return None;
    }
    let ip = decode_in_addr(insi.insi_vflag, &insi.insi_laddr)?;
    Some(SocketAddr::new(ip.to_canonical(), port))
}

fn decode_in_sockinfo_flow(insi: &InSockInfo) -> Option<TcpFlow> {
    let local_port = decode_network_port(insi.insi_lport);
    let remote_port = decode_network_port(insi.insi_fport);
    if local_port == 0 || remote_port == 0 {
        return None;
    }
    let local_ip = decode_in_addr(insi.insi_vflag, &insi.insi_laddr)?.to_canonical();
    let remote_ip = decode_in_addr(insi.insi_vflag, &insi.insi_faddr)?.to_canonical();
    Some(TcpFlow {
        source: SocketAddr::new(local_ip, local_port),
        destination: SocketAddr::new(remote_ip, remote_port),
    })
}

fn decode_in_addr(vflag: u8, addr: &InAddrStorage) -> Option<IpAddr> {
    let bytes = addr.0;
    if (vflag & INI_IPV4) != 0 {
        Some(IpAddr::V4(Ipv4Addr::new(
            bytes[12], bytes[13], bytes[14], bytes[15],
        )))
    } else if (vflag & INI_IPV6) != 0 {
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        None
    }
}

fn build_tcp_snapshot() -> Option<HashMap<TcpFlow, i32>> {
    let mut map = HashMap::new();
    visit_process_sockets(|pid, psi| {
        if psi.soi_kind != SOCKINFO_TCP {
            return;
        }
        if let Some(flow) = decode_in_sockinfo_flow(&psi.insi) {
            map.entry(flow).or_insert(pid);
        }
    })?;
    Some(map)
}

fn build_udp_snapshot() -> Option<UdpEntries> {
    let mut map: UdpEntries = HashMap::new();
    visit_process_sockets(|pid, psi| {
        if psi.soi_kind != SOCKINFO_IN || psi.soi_protocol != libc::IPPROTO_UDP {
            return;
        }
        if let Some(local) = decode_in_sockinfo_local(&psi.insi) {
            map.entry(local.port()).or_default().push((local.ip(), pid));
        }
    })?;
    Some(map)
}

fn process_image(pid: i32) -> Option<String> {
    let mut buffer = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: `buffer` is writable for `PROC_PIDPATHINFO_MAXSIZE` bytes.
    let len = unsafe {
        proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast(),
            PROC_PIDPATHINFO_MAXSIZE as u32,
        )
    };
    if len <= 0 {
        return None;
    }
    let path = PathBuf::from(OsStr::from_bytes(&buffer[..len as usize]));
    let text = path.to_str()?;
    (!text.is_empty()).then(|| text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_addresses_ports_and_matches_exact_before_wildcard_udp() {
        let port = 53_210u16;
        assert_eq!(decode_network_port(c_int::from(port.to_be())), port);

        let mut v4_storage = [0u8; 16];
        v4_storage[12..16].copy_from_slice(&[198, 51, 100, 7]);
        assert_eq!(
            decode_in_addr(INI_IPV4, &InAddrStorage(v4_storage)),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );

        let v6_addr: Ipv6Addr = "2001:db8::42".parse().unwrap();
        assert_eq!(
            decode_in_addr(INI_IPV6, &InAddrStorage(v6_addr.octets())),
            Some(IpAddr::V6(v6_addr))
        );

        let mut entries = UdpEntries::new();
        entries.insert(
            port,
            vec![
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 100),
                (IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 200),
            ],
        );
        assert_eq!(
            match_udp_owner(
                &entries,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), port)
            ),
            Some(200)
        );
        assert_eq!(
            match_udp_owner(
                &entries,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), port)
            ),
            Some(100)
        );
    }
}
