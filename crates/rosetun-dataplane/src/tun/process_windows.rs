//! Windows owner-PID table lookup and short-lived image-name cache.

use std::collections::HashMap;
use std::ffi::c_void;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rosetun_config::ConnectionNetwork;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use super::{ProcessLookup, TcpFlow};

const MAX_TABLE_BYTES: u32 = 4 * 1024 * 1024;
const CACHE_SIZE: usize = 512;
const IMAGE_TTL: Duration = Duration::from_secs(1);
const UDP_OWNER_TTL: Duration = Duration::from_millis(250);

type OwnerTable = unsafe extern "system" fn(*mut c_void, *mut u32, i32, u32, i32, u32) -> u32;
type Images = HashMap<u32, (Instant, Option<String>)>;
type UdpOwners = HashMap<SocketAddr, (Instant, Option<u32>)>;

#[derive(Default)]
pub struct WindowsProcessLookup {
    images: Mutex<Images>,
    udp_owners: Mutex<UdpOwners>,
}

impl fmt::Debug for WindowsProcessLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsProcessLookup")
            .finish_non_exhaustive()
    }
}

impl ProcessLookup for WindowsProcessLookup {
    fn image(&self, flow: &TcpFlow, network: ConnectionNetwork) -> Option<String> {
        let now = Instant::now();
        let pid = match network {
            ConnectionNetwork::Tcp => owner(flow, network)?,
            ConnectionNetwork::Udp => self.udp_owner_cached(flow, now)?,
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

impl WindowsProcessLookup {
    fn udp_owner_cached(&self, flow: &TcpFlow, now: Instant) -> Option<u32> {
        if let Some((at, pid)) = self.udp_owners.lock().ok()?.get(&flow.source)
            && now.saturating_duration_since(*at) < UDP_OWNER_TTL
        {
            return *pid;
        }
        let pid = owner(flow, ConnectionNetwork::Udp);
        if let Ok(mut cache) = self.udp_owners.lock() {
            cache.retain(|_, (at, _)| now.saturating_duration_since(*at) < UDP_OWNER_TTL);
            if cache.len() < CACHE_SIZE {
                cache.insert(flow.source, (now, pid));
            }
        }
        pid
    }
}

fn owner(flow: &TcpFlow, network: ConnectionNetwork) -> Option<u32> {
    let family = if flow.source.is_ipv4() {
        AF_INET
    } else {
        AF_INET6
    };
    match network {
        ConnectionNetwork::Tcp => {
            let table = read_table(
                GetExtendedTcpTable,
                u32::from(family),
                TCP_TABLE_OWNER_PID_ALL,
            )?;
            if flow.source.is_ipv4() {
                unique(table_rows::<6>(&table)?.iter().filter_map(|row| {
                    (endpoint(v4(row[1]), row[2]) == flow.source
                        && endpoint(v4(row[3]), row[4]) == flow.destination)
                        .then_some(row[5])
                }))
            } else {
                unique(table_rows::<14>(&table)?.iter().filter_map(|row| {
                    (endpoint(v6(&row[..4]), row[5]) == flow.source
                        && endpoint(v6(&row[6..10]), row[11]) == flow.destination)
                        .then_some(row[13])
                }))
            }
        }
        ConnectionNetwork::Udp => {
            let table = read_table(GetExtendedUdpTable, u32::from(family), UDP_TABLE_OWNER_PID)?;
            if flow.source.is_ipv4() {
                udp_owner(
                    flow.source,
                    table_rows::<3>(&table)?
                        .iter()
                        .map(|row| (endpoint(v4(row[0]), row[1]), row[2])),
                )
            } else {
                udp_owner(
                    flow.source,
                    table_rows::<7>(&table)?
                        .iter()
                        .map(|row| (endpoint(v6(&row[..4]), row[5]), row[6])),
                )
            }
        }
    }
}

fn udp_owner(
    local: SocketAddr,
    rows: impl Iterator<Item = (SocketAddr, u32)> + Clone,
) -> Option<u32> {
    let exact = rows
        .clone()
        .filter_map(|(address, pid)| (address == local).then_some(pid));
    if exact.clone().next().is_some() {
        return unique(exact);
    }
    unique(rows.filter_map(|(addr, pid)| {
        (addr.ip().is_unspecified() && addr.port() == local.port()).then_some(pid)
    }))
}

fn unique(mut candidates: impl Iterator<Item = u32>) -> Option<u32> {
    let owner = candidates.next()?;
    (owner != 0 && candidates.all(|pid| pid == owner)).then_some(owner)
}

fn v4(value: u32) -> IpAddr {
    Ipv4Addr::from(value.to_ne_bytes()).into()
}

fn v6(words: &[u32]) -> IpAddr {
    let mut octets = [0u8; 16];
    for (bytes, word) in octets.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *bytes = word.to_ne_bytes();
    }
    Ipv6Addr::from(octets).into()
}

fn endpoint(ip: IpAddr, port: u32) -> SocketAddr {
    SocketAddr::new(ip, u16::from_be(port as u16))
}

fn read_table(api: OwnerTable, family: u32, class: i32) -> Option<Vec<u32>> {
    let mut bytes = 0;
    let mut buffer: Vec<u32> = Vec::new();
    for _ in 0..4 {
        let ptr = if buffer.is_empty() {
            std::ptr::null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        };
        // SAFETY: The probe passes a null buffer with size zero. Subsequent calls
        // have a writable, DWORD-aligned allocation at least as large as bytes.
        // This IP Helper call does not retain the pointer after it returns.
        let result = unsafe { api(ptr, &mut bytes, 0, family, class, 0) };
        match result {
            NO_ERROR if !buffer.is_empty() && bytes as usize <= buffer.len() * size_of::<u32>() => {
                buffer.truncate(bytes as usize / size_of::<u32>());
                return Some(buffer);
            }
            ERROR_INSUFFICIENT_BUFFER if (4..=MAX_TABLE_BYTES).contains(&bytes) => {
                buffer.resize((bytes as usize).div_ceil(size_of::<u32>()), 0);
            }
            _ => return None,
        }
    }
    None
}

fn table_rows<const WIDTH: usize>(table: &[u32]) -> Option<&[[u32; WIDTH]]> {
    let (&count, data) = table.split_first()?;
    data.as_chunks::<WIDTH>().0.get(..count as usize)
}

fn process_image(pid: u32) -> Option<String> {
    // SAFETY: The handle returned by OpenProcess is uniquely owned by the
    // caller. Only the limited image-query right is requested.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return None;
    }
    // SAFETY: raw is a non-null owned process handle and is closed by OwnedHandle.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut stack = [0u16; 512];
    let mut length = stack.len() as u32;
    // SAFETY: The borrowed handle and UTF-16 output buffer stay valid throughout
    // this synchronous call. QueryFullProcessImageNameW writes at most length units.
    let success = unsafe {
        QueryFullProcessImageNameW(handle.as_raw_handle(), 0, stack.as_mut_ptr(), &mut length)
    };
    if success != 0 {
        return String::from_utf16(stack.get(..length as usize)?).ok();
    }
    // SAFETY: GetLastError reads the calling thread's last Win32 error code.
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }
    let mut path = vec![0u16; 32768];
    let mut length = path.len() as u32;
    // SAFETY: The borrowed handle and UTF-16 output buffer stay valid throughout
    // this synchronous call. QueryFullProcessImageNameW writes at most length units.
    let success = unsafe {
        QueryFullProcessImageNameW(handle.as_raw_handle(), 0, path.as_mut_ptr(), &mut length)
    };
    if success == 0 {
        return None;
    }
    String::from_utf16(path.get(..length as usize)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_prefers_the_exact_bind_and_refuses_an_ambiguous_owner() {
        let local = "192.0.2.1:5000".parse().unwrap();
        let wildcard = "0.0.0.0:5000".parse().unwrap();
        assert_eq!(
            udp_owner(local, [(wildcard, 3), (local, 7)].into_iter()),
            Some(7)
        );
        assert_eq!(
            udp_owner(local, [(wildcard, 3), (local, 7), (local, 8)].into_iter()),
            None
        );
        assert_eq!(udp_owner(local, [(wildcard, 3)].into_iter()), Some(3));
    }

    #[test]
    fn native_rows_are_checked_against_the_buffer_length() {
        assert_eq!(table_rows::<3>(&[1, 0, 0, 1]).unwrap(), &[[0, 0, 1]]);
        assert!(table_rows::<3>(&[2, 0, 0, 1]).is_none());
    }

    #[test]
    fn the_snapshot_finds_the_current_process_for_a_connected_loopback_socket() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let connection = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        let flow = TcpFlow {
            source: connection.local_addr().unwrap(),
            destination: connection.peer_addr().unwrap(),
        };
        assert_eq!(
            owner(&flow, ConnectionNetwork::Tcp),
            Some(std::process::id())
        );
        assert!(
            WindowsProcessLookup::default()
                .image(&flow, ConnectionNetwork::Tcp)
                .is_some()
        );
    }
}
