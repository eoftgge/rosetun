use std::io;
use std::net::IpAddr;
use std::ptr;

use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToAlias, GetBestRoute2, MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_INET,
};

pub(super) fn route_interface(address: IpAddr) -> io::Result<String> {
    let destination = match address {
        IpAddr::V4(address) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(address.octets()),
                    },
                },
                ..Default::default()
            },
        },
        IpAddr::V6(address) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: address.octets(),
                    },
                },
                ..Default::default()
            },
        },
    };
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: the destination is a matching initialized sockaddr union; both output
    // objects are writable for this synchronous lookup. Null inputs request OS selection.
    let result = unsafe {
        GetBestRoute2(
            ptr::null(),
            0,
            ptr::null(),
            &destination,
            0,
            &mut route,
            &mut source,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let mut name = [0u16; 257];
    // SAFETY: the route supplies the LUID and name is a writable UTF-16 buffer.
    let result =
        unsafe { ConvertInterfaceLuidToAlias(&route.InterfaceLuid, name.as_mut_ptr(), name.len()) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let end = name
        .iter()
        .position(|&unit| unit == 0)
        .ok_or(io::ErrorKind::InvalidData)?;
    String::from_utf16(&name[..end]).map_err(|_| io::ErrorKind::InvalidData.into())
}
