//! Darwin `PF_ROUTE` message parsing helpers.
//!
//! XNU aligns routing-socket `sockaddr` records to 4 bytes (`sizeof(uint32_t)`)
//! on both 32-bit and 64-bit architectures (including `arm64`), NOT `sizeof(long)`.

use std::ffi::CStr;

pub(crate) const RTAX_DST: usize = 0;
pub(crate) const RTAX_NETMASK: usize = 2;
pub(crate) const RTAX_MAX: usize = 8;

/// XNU `RTF_IFSCOPE` (`<net/route.h>`): interface-scoped route ignored by
/// unscoped lookups unless the socket binds to the interface.
pub(crate) const RTF_IFSCOPE: i32 = 0x0100_0000;

/// XNU `ROUNDUP32`: rounds a `sockaddr` length up to a 4-byte boundary, with
/// zero-length addresses still occupying 4 bytes on the wire.
pub(crate) const fn roundup(len: usize) -> usize {
    if len == 0 { 4 } else { (len + 3) & !3 }
}

/// Splits the trailing `sockaddr` array of a Darwin routing message into slots
/// indexed by `RTAX_*`, advancing by 4-byte `ROUNDUP32` steps.
pub(crate) fn parse_route_addrs(buf: &[u8], addrs_mask: i32) -> [Option<&[u8]>; RTAX_MAX] {
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

/// Returns the address family of a Darwin `sockaddr` slice (`AF_INET` or
/// `AF_INET6`) when the destination is the all-zeros default address (`0.0.0.0`
/// or `::`).
pub(crate) fn default_destination_family(sa: &[u8]) -> Option<i32> {
    if sa.len() < 2 {
        return None;
    }
    let family = i32::from(sa[1]);
    if family == libc::AF_INET {
        let addr_bytes = sa.get(4..8)?;
        if addr_bytes == [0, 0, 0, 0] {
            return Some(libc::AF_INET);
        }
    } else if family == libc::AF_INET6 {
        let addr_bytes = sa.get(8..24)?;
        if addr_bytes.iter().all(|&byte| byte == 0) {
            return Some(libc::AF_INET6);
        }
    }
    None
}

/// Whether `RTA_NETMASK` represents a `/0` (default-route) netmask.
///
/// XNU encodes a `/0` mask as either a zero-length `sockaddr` (`sa_len == 0`)
/// or an address family mask whose address bytes are all zero.
pub(crate) fn is_zero_netmask(mask: Option<&[u8]>) -> bool {
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
    // Compact AF_UNSPEC zero mask (e.g. [4, 0, 0, 0]).
    mask[2..].iter().all(|&byte| byte == 0)
}

/// Resolves a Darwin interface index to its interface name (e.g. `en0`, `utun6`).
pub(crate) fn interface_name(index: u16) -> Option<String> {
    if index == 0 {
        return None;
    }
    let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
    // SAFETY: `name` is writable for `IFNAMSIZ` bytes as required by
    // `if_indextoname`, which writes a NUL-terminated string on success.
    let ptr = unsafe { libc::if_indextoname(u32::from(index), name.as_mut_ptr()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `if_indextoname` returned a non-null pointer into `name` holding
    // a valid NUL-terminated C string.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let text = cstr.to_str().ok()?;
    (!text.is_empty()).then(|| text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundup_matches_darwin_four_byte_alignment() {
        assert_eq!(roundup(0), 4);
        assert_eq!(roundup(1), 4);
        assert_eq!(roundup(4), 4);
        assert_eq!(roundup(5), 8);
        assert_eq!(roundup(16), 16);
        assert_eq!(roundup(20), 20);
        assert_eq!(roundup(28), 28);
    }

    #[test]
    fn parses_ipv6_default_route_with_28_byte_sockaddr_and_zero_netmask() {
        let mut payload = Vec::new();
        // RTAX_DST: 28-byte sockaddr_in6 for ::
        let mut dst = [0u8; 28];
        dst[0] = 28;
        dst[1] = libc::AF_INET6 as u8;
        payload.extend_from_slice(&dst);
        // RTAX_GATEWAY: 28-byte sockaddr_in6 for fe80::1
        let mut gw = [0u8; 28];
        gw[0] = 28;
        gw[1] = libc::AF_INET6 as u8;
        gw[8] = 0xfe;
        gw[9] = 0x80;
        gw[23] = 1;
        payload.extend_from_slice(&gw);
        // RTAX_NETMASK: zero-length sockaddr (4 bytes on wire)
        payload.extend_from_slice(&[0u8; 4]);

        let mask = libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK;
        let slots = parse_route_addrs(&payload, mask);
        assert_eq!(
            default_destination_family(slots[RTAX_DST].unwrap()),
            Some(libc::AF_INET6)
        );
        assert!(is_zero_netmask(slots[RTAX_NETMASK]));
    }

    #[test]
    fn rejects_non_default_ipv4_destination_and_non_zero_netmask() {
        let mut dst = [0u8; 16];
        dst[0] = 16;
        dst[1] = libc::AF_INET as u8;
        dst[4..8].copy_from_slice(&[192, 168, 1, 0]);
        assert_eq!(default_destination_family(&dst), None);

        let mut mask = [0u8; 16];
        mask[0] = 16;
        mask[1] = libc::AF_INET as u8;
        mask[4..8].copy_from_slice(&[255, 255, 255, 0]);
        assert!(!is_zero_netmask(Some(&mask)));
        assert!(!is_zero_netmask(None));
        // Compact /1 split route (128.0.0.0).
        assert!(!is_zero_netmask(Some(&[5, libc::AF_INET as u8, 0, 0, 128])));
    }

    #[test]
    fn accepts_compact_and_full_zero_netmasks() {
        assert!(is_zero_netmask(Some(&[])));
        assert!(is_zero_netmask(Some(&[4, 0, 0, 0])));
        assert!(is_zero_netmask(Some(&[2, libc::AF_INET as u8])));
        assert!(is_zero_netmask(Some(&[4, libc::AF_INET6 as u8, 0, 0])));
        let mut v4_zero = [0u8; 16];
        v4_zero[0] = 16;
        v4_zero[1] = libc::AF_INET as u8;
        assert!(is_zero_netmask(Some(&v4_zero)));
    }
}
