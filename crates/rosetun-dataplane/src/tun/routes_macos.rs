//! Physical route preservation and `utun` capture routes on macOS.

use std::ffi::CStr;
use std::fmt;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::process::{Command, Stdio};
use std::ptr;

use rosetun_config::IpPrefix;

use super::{CaptureRoutes, PhysicalEgress, RouteBackend, RouteLease};

const RTAX_DST: usize = 0;
const RTAX_GATEWAY: usize = 1;
const RTAX_NETMASK: usize = 2;
const RTAX_MAX: usize = 8;
/// XNU `RTF_IFSCOPE` (`<net/route.h>`).
const RTF_IFSCOPE: i32 = 0x0100_0000;

#[derive(Clone)]
struct UtunBackend {
    interface: String,
}

impl UtunBackend {
    fn new(interface: &str) -> io::Result<Self> {
        if interface
            .strip_prefix("utun")
            .is_none_or(|index| index.parse::<u16>().is_err())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid utun interface",
            ));
        }
        Ok(Self {
            interface: interface.to_owned(),
        })
    }

    fn change(&self, operation: &str, prefix: IpPrefix) -> io::Result<()> {
        let family = family_flag(prefix.is_ipv4());
        let destination = prefix.to_string();
        run_route(&[
            "-n",
            operation,
            family,
            "-net",
            &destination,
            "-interface",
            &self.interface,
        ])
    }
}

impl RouteBackend for UtunBackend {
    fn add(&mut self, prefix: IpPrefix) -> io::Result<()> {
        self.change("add", prefix)
    }

    fn delete(&mut self, prefix: IpPrefix) -> io::Result<()> {
        self.change("delete", prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PhysicalRoute {
    index: NonZeroU32,
    interface: String,
    gateway: Option<IpAddr>,
    scoped: bool,
}

/// Physical default routes captured before tunnel setup, owned `utun` capture
/// routes, and exact physical host routes for VPN worker endpoints.
pub struct MacosRoutes {
    physical: PhysicalEgress,
    ipv4: PhysicalRoute,
    ipv6: Option<PhysicalRoute>,
    capture: Option<RouteLease<UtunBackend>>,
    endpoints: Vec<IpAddr>,
}

impl fmt::Debug for MacosRoutes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacosRoutes")
            .field("endpoints", &self.endpoints.len())
            .finish_non_exhaustive()
    }
}

impl MacosRoutes {
    /// Captures the active physical IPv4 (and optional IPv6) default route
    /// before any `utun` capture routes are installed.
    pub fn before_capture() -> io::Result<Self> {
        let dump = dump_routing_table()?;
        let (ipv4, ipv6) = select_physical_routes(&dump, interface_name)?;
        let physical =
            PhysicalEgress::new(Some(ipv4.index), ipv6.as_ref().map(|route| route.index));
        Ok(Self {
            physical,
            ipv4,
            ipv6,
            capture: None,
            endpoints: Vec::new(),
        })
    }

    pub fn physical(&self) -> PhysicalEgress {
        self.physical
    }

    pub fn capture(
        &mut self,
        interface: &str,
        plan: &CaptureRoutes,
        endpoints: &[IpAddr],
    ) -> io::Result<()> {
        let backend = UtunBackend::new(interface)?;
        if self.capture.is_some()
            || self.ipv4.interface == interface
            || self
                .ipv6
                .as_ref()
                .is_some_and(|route| route.interface == interface)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid native utun interface",
            ));
        }
        self.ensure_endpoints(endpoints)?;
        self.capture = Some(RouteLease::install(backend, plan)?);
        Ok(())
    }

    pub fn ensure_endpoints(&mut self, endpoints: &[IpAddr]) -> io::Result<()> {
        let existing_hosts = dump_routing_table()
            .map(|dump| collect_existing_host_routes(&dump, interface_name))
            .unwrap_or_default();
        for &address in endpoints {
            if address.is_loopback()
                || address.is_unspecified()
                || self.endpoints.contains(&address)
            {
                continue;
            }
            // Leave pre-existing non-tunnel exact host routes to their owner.
            if existing_hosts.iter().any(|(host, iface)| {
                *host == address && !iface.starts_with("utun") && iface != "lo0"
            }) {
                continue;
            }
            let route = if address.is_ipv4() {
                Some(&self.ipv4)
            } else {
                self.ipv6.as_ref()
            }
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NetworkUnreachable,
                    "no physical route for server address family",
                )
            })?;
            let args = host_route_args("add", address, Some(route));
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            run_route(&arg_refs)?;
            self.endpoints.push(address);
        }
        Ok(())
    }

    pub fn retain_endpoints(&mut self, endpoints: &[IpAddr]) -> io::Result<()> {
        let mut index = 0;
        while index < self.endpoints.len() {
            let address = self.endpoints[index];
            if endpoints.contains(&address) {
                index += 1;
            } else {
                let args = host_route_args("delete", address, None);
                let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
                run_route(&arg_refs)?;
                self.endpoints.remove(index);
            }
        }
        Ok(())
    }

    pub fn close(&mut self) -> io::Result<()> {
        let mut first_error = None;
        if let Some(capture) = self.capture.as_mut()
            && let Err(error) = capture.close()
        {
            first_error.get_or_insert(error);
        }
        if first_error.is_none() {
            self.capture = None;
        }
        let mut retained = Vec::new();
        while let Some(address) = self.endpoints.pop() {
            let args = host_route_args("delete", address, None);
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Err(error) = run_route(&arg_refs) {
                retained.push(address);
                first_error.get_or_insert(error);
            }
        }
        self.endpoints.extend(retained.into_iter().rev());
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for MacosRoutes {
    fn drop(&mut self) {
        if self.close().is_err() {
            tracing::error!("could not remove all native macOS routes");
        }
    }
}

fn family_flag(ipv4: bool) -> &'static str {
    if ipv4 { "-inet" } else { "-inet6" }
}

fn host_route_args(operation: &str, address: IpAddr, route: Option<&PhysicalRoute>) -> Vec<String> {
    let mut args = vec![
        "-n".to_owned(),
        operation.to_owned(),
        family_flag(address.is_ipv4()).to_owned(),
        "-host".to_owned(),
        address.to_string(),
    ];
    if let Some(route) = route {
        match route.gateway {
            Some(IpAddr::V6(v6)) if v6.is_unicast_link_local() => {
                args.push(format!("{v6}%{}", route.interface));
            }
            Some(gateway) => {
                args.push(gateway.to_string());
            }
            None => {
                args.push("-interface".to_owned());
                args.push(route.interface.clone());
            }
        }
    }
    args
}

fn run_route(args: &[&str]) -> io::Result<()> {
    let status = Command::new("/sbin/route")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("could not update native macOS route"))
    }
}

const fn roundup(len: usize) -> usize {
    if len == 0 { 4 } else { (len + 3) & !3 }
}

fn parse_route_addrs(buf: &[u8], addrs_mask: i32) -> [Option<&[u8]>; RTAX_MAX] {
    let mut slots = [None; RTAX_MAX];
    let mut offset = 0usize;
    for (index, slot) in slots.iter_mut().enumerate() {
        if (addrs_mask & (1 << index)) == 0 {
            continue;
        }
        if offset >= buf.len() {
            break;
        }
        let sa_len = usize::from(buf[offset]);
        let step = roundup(sa_len);
        let end = offset.saturating_add(sa_len.max(1));
        if end <= buf.len() {
            *slot = Some(&buf[offset..offset + sa_len.min(buf.len() - offset)]);
        }
        offset = offset.saturating_add(step);
    }
    slots
}

fn parse_sockaddr_ip(sa: &[u8]) -> Option<IpAddr> {
    if sa.len() < 2 {
        return None;
    }
    let family = i32::from(sa[1]);
    if family == libc::AF_INET {
        let bytes: [u8; 4] = sa.get(4..8)?.try_into().ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(bytes)))
    } else if family == libc::AF_INET6 {
        let mut bytes: [u8; 16] = sa.get(8..24)?.try_into().ok()?;
        // XNU stores the embedded 16-bit scope index in `s6_addr[2..4]` for
        // link-local gateways (`fe80::/10`) inside kernel route records.
        if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 {
            bytes[2] = 0;
            bytes[3] = 0;
        }
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        None
    }
}

fn is_zero_netmask(mask: Option<&[u8]>) -> bool {
    let Some(mask) = mask else {
        return false;
    };
    if mask.is_empty() {
        return true;
    }
    if mask.len() < 2 {
        return false;
    }
    let family = i32::from(mask[1]);
    if family == libc::AF_INET {
        let end = mask.len().min(8);
        return mask
            .get(4..end)
            .is_none_or(|bytes| bytes.iter().all(|&b| b == 0));
    }
    if family == libc::AF_INET6 {
        let end = mask.len().min(24);
        return mask
            .get(8..end)
            .is_none_or(|bytes| bytes.iter().all(|&b| b == 0));
    }
    mask[2..].iter().all(|&byte| byte == 0)
}

fn dump_routing_table() -> io::Result<Vec<u8>> {
    let mut mib: [libc::c_int; 6] = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_DUMP, 0];
    for _ in 0..3 {
        let mut needed: libc::size_t = 0;
        // SAFETY: `mib` has 6 elements; a null output buffer queries required length.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                ptr::null_mut(),
                &raw mut needed,
                ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if needed == 0 {
            return Ok(Vec::new());
        }
        let mut buffer = vec![0u8; needed];
        let mut actual = needed;
        // SAFETY: `buffer` is writable for `actual` bytes.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buffer.as_mut_ptr().cast(),
                &raw mut actual,
                ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            buffer.truncate(actual);
            return Ok(buffer);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOMEM) {
            return Err(error);
        }
    }
    Err(io::Error::from_raw_os_error(libc::ENOMEM))
}

fn interface_name(index: u16) -> Option<String> {
    if index == 0 {
        return None;
    }
    let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
    // SAFETY: `name` is writable for `IFNAMSIZ` bytes; `if_indextoname` writes a C string.
    let ptr = unsafe { libc::if_indextoname(u32::from(index), name.as_mut_ptr()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: Non-null return points to a NUL-terminated string inside `name`.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let text = cstr.to_str().ok()?;
    (!text.is_empty()).then(|| text.to_owned())
}

fn usable_physical(interface: &str) -> bool {
    !interface.is_empty() && interface != "lo0" && !interface.starts_with("utun")
}

fn collect_existing_host_routes(
    dump: &[u8],
    resolve_name: impl Fn(u16) -> Option<String>,
) -> Vec<(IpAddr, String)> {
    let header_len = size_of::<libc::rt_msghdr>();
    let mut hosts = Vec::new();
    let mut offset = 0usize;
    while offset + header_len <= dump.len() {
        // SAFETY: Checked `offset + size_of::<rt_msghdr>() <= dump.len()`.
        let header: libc::rt_msghdr =
            unsafe { ptr::read_unaligned(dump.as_ptr().add(offset).cast()) };
        let msglen = usize::from(header.rtm_msglen);
        if msglen < header_len || offset + msglen > dump.len() {
            break;
        }
        let payload = &dump[offset + header_len..offset + msglen];
        offset += msglen;

        if i32::from(header.rtm_version) != libc::RTM_VERSION
            || (header.rtm_flags & libc::RTF_UP) == 0
            || (header.rtm_flags & libc::RTF_HOST) == 0
            || (header.rtm_flags & (libc::RTF_REJECT | libc::RTF_BLACKHOLE | RTF_IFSCOPE)) != 0
        {
            continue;
        }
        let slots = parse_route_addrs(payload, header.rtm_addrs);
        let Some(dst) = slots[RTAX_DST].and_then(parse_sockaddr_ip) else {
            continue;
        };
        let Some(iface) = resolve_name(header.rtm_index) else {
            continue;
        };
        hosts.push((dst, iface));
    }
    hosts
}

fn select_physical_routes(
    dump: &[u8],
    resolve_name: impl Fn(u16) -> Option<String>,
) -> io::Result<(PhysicalRoute, Option<PhysicalRoute>)> {
    let header_len = size_of::<libc::rt_msghdr>();
    let mut v4_candidates = Vec::new();
    let mut v6_candidates = Vec::new();
    let mut offset = 0usize;

    while offset + header_len <= dump.len() {
        // SAFETY: Checked `offset + size_of::<rt_msghdr>() <= dump.len()`.
        let header: libc::rt_msghdr =
            unsafe { ptr::read_unaligned(dump.as_ptr().add(offset).cast()) };
        let msglen = usize::from(header.rtm_msglen);
        if msglen < header_len || offset + msglen > dump.len() {
            break;
        }
        let payload = &dump[offset + header_len..offset + msglen];
        offset += msglen;

        if i32::from(header.rtm_version) != libc::RTM_VERSION
            || (header.rtm_flags & libc::RTF_UP) == 0
            || (header.rtm_flags & (libc::RTF_HOST | libc::RTF_REJECT | libc::RTF_BLACKHOLE)) != 0
        {
            continue;
        }
        let slots = parse_route_addrs(payload, header.rtm_addrs);
        let Some(dst) = slots[RTAX_DST].and_then(parse_sockaddr_ip) else {
            continue;
        };
        if !dst.is_unspecified() || !is_zero_netmask(slots[RTAX_NETMASK]) {
            continue;
        }
        let Some(index) = NonZeroU32::new(u32::from(header.rtm_index)) else {
            continue;
        };
        let Some(interface) = resolve_name(header.rtm_index) else {
            continue;
        };
        if !usable_physical(&interface) {
            continue;
        }
        let gateway = if (header.rtm_flags & libc::RTF_GATEWAY) != 0 {
            slots[RTAX_GATEWAY].and_then(parse_sockaddr_ip)
        } else {
            None
        };
        let candidate = PhysicalRoute {
            index,
            interface,
            gateway,
            scoped: (header.rtm_flags & RTF_IFSCOPE) != 0,
        };
        if dst.is_ipv4() {
            v4_candidates.push(candidate);
        } else {
            v6_candidates.push(candidate);
        }
    }

    let pick = |candidates: Vec<PhysicalRoute>| {
        candidates
            .iter()
            .find(|route| !route.scoped)
            .cloned()
            .or_else(|| candidates.into_iter().next())
    };
    let ipv4 = pick(v4_candidates).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NetworkUnreachable,
            "physical IPv4 default route is unavailable",
        )
    })?;
    let ipv6 = pick(v6_candidates);
    Ok((ipv4, ipv6))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_routes_and_clears_embedded_link_local_scope() {
        let mut dump = Vec::new();

        // IPv4 unscoped default route via 192.168.1.1 on en0 (index 4).
        let mut hdr4: libc::rt_msghdr = unsafe { std::mem::zeroed() };
        let mut dst4 = [0u8; 16];
        dst4[0] = 16;
        dst4[1] = libc::AF_INET as u8;
        let mut gw4 = [0u8; 16];
        gw4[0] = 16;
        gw4[1] = libc::AF_INET as u8;
        gw4[4..8].copy_from_slice(&[192, 168, 1, 1]);
        let mask4 = [0u8; 4];
        hdr4.rtm_version = libc::RTM_VERSION as u8;
        hdr4.rtm_index = 4;
        hdr4.rtm_flags = libc::RTF_UP | libc::RTF_GATEWAY;
        hdr4.rtm_addrs = libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK;
        hdr4.rtm_msglen =
            (size_of::<libc::rt_msghdr>() + dst4.len() + gw4.len() + mask4.len()) as u16;
        // SAFETY: `hdr4` is initialized POD.
        dump.extend_from_slice(unsafe {
            std::slice::from_raw_parts((&raw const hdr4).cast::<u8>(), size_of::<libc::rt_msghdr>())
        });
        dump.extend_from_slice(&dst4);
        dump.extend_from_slice(&gw4);
        dump.extend_from_slice(&mask4);

        // IPv6 default route via embedded-scope link-local fe80:0004::1 on en0 (index 4).
        let mut hdr6: libc::rt_msghdr = unsafe { std::mem::zeroed() };
        let mut dst6 = [0u8; 28];
        dst6[0] = 28;
        dst6[1] = libc::AF_INET6 as u8;
        let mut gw6 = [0u8; 28];
        gw6[0] = 28;
        gw6[1] = libc::AF_INET6 as u8;
        gw6[8..12].copy_from_slice(&[0xfe, 0x80, 0x00, 0x04]);
        gw6[23] = 1;
        let mask6 = [0u8; 4];
        hdr6.rtm_version = libc::RTM_VERSION as u8;
        hdr6.rtm_index = 4;
        hdr6.rtm_flags = libc::RTF_UP | libc::RTF_GATEWAY;
        hdr6.rtm_addrs = libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK;
        hdr6.rtm_msglen =
            (size_of::<libc::rt_msghdr>() + dst6.len() + gw6.len() + mask6.len()) as u16;
        // SAFETY: `hdr6` is initialized POD.
        dump.extend_from_slice(unsafe {
            std::slice::from_raw_parts((&raw const hdr6).cast::<u8>(), size_of::<libc::rt_msghdr>())
        });
        dump.extend_from_slice(&dst6);
        dump.extend_from_slice(&gw6);
        dump.extend_from_slice(&mask6);

        let (v4, v6) = select_physical_routes(&dump, |idx| (idx == 4).then(|| "en0".to_owned()))
            .expect("select physical routes");
        assert_eq!(v4.interface, "en0");
        assert_eq!(v4.gateway, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        let v6 = v6.expect("IPv6 route");
        assert_eq!(v6.gateway, Some("fe80::1".parse().unwrap()));
        assert_eq!(
            host_route_args("add", "2001:db8::10".parse().unwrap(), Some(&v6)),
            vec![
                "-n",
                "add",
                "-inet6",
                "-host",
                "2001:db8::10",
                "fe80::1%en0"
            ]
        );
    }
}
