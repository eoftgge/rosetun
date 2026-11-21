//! Default-route discovery on macOS via `sysctl(NET_RT_DUMP)`.

use std::io;
use std::mem::size_of;
use std::ptr;

use super::rtmsg::{
    RTAX_DST, RTAX_NETMASK, RTF_IFSCOPE, default_destination_family, interface_name,
    is_zero_netmask, parse_route_addrs,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct DefaultRoute {
    interface: String,
    family: i32,
    scoped: bool,
}

fn usable(interface: &str, exclude_alias: &str) -> bool {
    !interface.is_empty() && interface != "lo0" && interface != exclude_alias
}

/// Dumps the Darwin routing table without opening a raw socket or sending any
/// traffic. Retries up to 3 times if the table grows between size query and read.
fn dump_routing_table() -> io::Result<Vec<u8>> {
    let mut mib: [libc::c_int; 6] = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_DUMP, 0];
    for _ in 0..3 {
        let mut needed: libc::size_t = 0;
        // SAFETY: `mib` has 6 valid elements; passing a null output buffer asks
        // `sysctl` for the required byte length.
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
        // SAFETY: `buffer` is writable for `actual` bytes and `mib` has 6 elements.
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

fn collect_default_routes(
    dump: &[u8],
    resolve_name: impl Fn(u16) -> Option<String>,
) -> Vec<DefaultRoute> {
    let header_len = size_of::<libc::rt_msghdr>();
    let mut routes = Vec::new();
    let mut offset = 0usize;
    while offset + header_len <= dump.len() {
        // SAFETY: We checked `offset + size_of::<rt_msghdr>() <= dump.len()`,
        // and `read_unaligned` handles arbitrary buffer alignment.
        let header: libc::rt_msghdr =
            unsafe { ptr::read_unaligned(dump.as_ptr().add(offset).cast()) };
        let msglen = usize::from(header.rtm_msglen);
        if msglen < header_len || offset + msglen > dump.len() {
            break;
        }
        let payload = &dump[offset + header_len..offset + msglen];
        offset += msglen;

        if i32::from(header.rtm_version) != libc::RTM_VERSION {
            continue;
        }
        if (header.rtm_flags & libc::RTF_UP) == 0 {
            continue;
        }
        if (header.rtm_flags & (libc::RTF_HOST | libc::RTF_REJECT | libc::RTF_BLACKHOLE)) != 0 {
            continue;
        }

        let slots = parse_route_addrs(payload, header.rtm_addrs);
        let Some(dst) = slots[RTAX_DST] else {
            continue;
        };
        let Some(family) = default_destination_family(dst) else {
            continue;
        };
        if !is_zero_netmask(slots[RTAX_NETMASK]) {
            continue;
        }
        let Some(interface) = resolve_name(header.rtm_index) else {
            continue;
        };
        routes.push(DefaultRoute {
            interface,
            family,
            scoped: (header.rtm_flags & RTF_IFSCOPE) != 0,
        });
    }
    routes
}

fn select_primary_interface(routes: &[DefaultRoute], exclude_alias: &str) -> Option<String> {
    // Prefer unscoped (global) default routes over interface-scoped routes, and
    // IPv4 over IPv6 to match Windows and Linux behavior.
    for (scoped, family) in [
        (false, libc::AF_INET),
        (false, libc::AF_INET6),
        (true, libc::AF_INET),
        (true, libc::AF_INET6),
    ] {
        if let Some(route) = routes.iter().find(|route| {
            route.scoped == scoped
                && route.family == family
                && usable(&route.interface, exclude_alias)
        }) {
            return Some(route.interface.clone());
        }
    }
    None
}

/// Primary physical default-route interface, excluding loopback and the active
/// tunnel interface.
pub(in crate::platform) fn physical_default_interface(exclude_alias: &str) -> Option<String> {
    let dump = dump_routing_table().ok()?;
    let routes = collect_default_routes(&dump, interface_name);
    select_primary_interface(&routes, exclude_alias)
}

/// Every non-loopback interface carrying an IPv4 or IPv6 default route
/// (including interface-scoped default routes), excluding `exclude_alias`.
pub(super) fn interfaces_with_default_route(exclude_alias: &str) -> Vec<String> {
    let Ok(dump) = dump_routing_table() else {
        return Vec::new();
    };
    let mut interfaces: Vec<String> = collect_default_routes(&dump, interface_name)
        .into_iter()
        .map(|route| route.interface)
        .filter(|name| usable(name, exclude_alias))
        .collect();
    interfaces.sort_unstable();
    interfaces.dedup();
    interfaces
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(interface: &str, family: i32, scoped: bool) -> DefaultRoute {
        DefaultRoute {
            interface: interface.to_owned(),
            family,
            scoped,
        }
    }

    #[test]
    fn prefers_unscoped_ipv4_then_unscoped_ipv6_then_scoped_and_excludes_tunnel() {
        let routes = vec![
            route("lo0", libc::AF_INET, false),
            route("utun6", libc::AF_INET, false),
            route("en1", libc::AF_INET, true),
            route("en0", libc::AF_INET6, false),
        ];
        assert_eq!(
            select_primary_interface(&routes, "utun6").as_deref(),
            Some("en0")
        );

        let mut with_v4 = routes.clone();
        with_v4.push(route("en2", libc::AF_INET, false));
        assert_eq!(
            select_primary_interface(&with_v4, "utun6").as_deref(),
            Some("en2")
        );

        let scoped_only = vec![route("en1", libc::AF_INET, true)];
        assert_eq!(
            select_primary_interface(&scoped_only, "utun6").as_deref(),
            Some("en1")
        );
    }

    #[test]
    fn parses_synthetic_rt_msghdr_dump_record() {
        let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
        let dst = [
            16u8,
            libc::AF_INET as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mask = [0u8; 4];
        header.rtm_version = libc::RTM_VERSION as u8;
        header.rtm_type = libc::RTM_GET as u8;
        header.rtm_index = 7;
        header.rtm_flags = libc::RTF_UP | libc::RTF_GATEWAY;
        header.rtm_addrs = libc::RTA_DST | libc::RTA_NETMASK;
        header.rtm_msglen = (size_of::<libc::rt_msghdr>() + dst.len() + mask.len()) as u16;

        let mut dump = Vec::new();
        // SAFETY: `header` is initialized and POD; copying its raw bytes builds
        // a valid wire message for the parser unit test.
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const header).cast::<u8>(),
                size_of::<libc::rt_msghdr>(),
            )
        };
        dump.extend_from_slice(header_bytes);
        dump.extend_from_slice(&dst);
        dump.extend_from_slice(&mask);

        let parsed = collect_default_routes(&dump, |index| (index == 7).then(|| "en0".to_owned()));
        assert_eq!(parsed, vec![route("en0", libc::AF_INET, false)]);
    }
}
