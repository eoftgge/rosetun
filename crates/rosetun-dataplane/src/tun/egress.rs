use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::num::NonZeroU32;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

/// Physical egress selected before the system routes are changed.
#[derive(Clone, Copy)]
pub struct PhysicalEgress {
    ipv4: Option<NonZeroU32>,
    ipv6: Option<NonZeroU32>,
    #[cfg(target_os = "linux")]
    mark: NonZeroU32,
}

impl fmt::Debug for PhysicalEgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhysicalEgress")
            .field("ipv4", &self.ipv4.is_some())
            .field("ipv6", &self.ipv6.is_some())
            .finish_non_exhaustive()
    }
}

impl PhysicalEgress {
    #[cfg(target_os = "linux")]
    pub fn new(ipv4: Option<NonZeroU32>, ipv6: Option<NonZeroU32>, mark: NonZeroU32) -> Self {
        Self { ipv4, ipv6, mark }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new(ipv4: Option<NonZeroU32>, ipv6: Option<NonZeroU32>) -> Self {
        Self { ipv4, ipv6 }
    }

    pub(crate) fn connect(self, addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        let socket = self.socket(addr, Type::STREAM, Protocol::TCP)?;
        socket.connect_timeout(&addr.into(), timeout)?;
        Ok(socket.into())
    }

    pub(crate) fn bind_udp(self, addr: SocketAddr) -> io::Result<UdpSocket> {
        let socket = self.socket(addr, Type::DGRAM, Protocol::UDP)?;
        socket.bind(&addr.into())?;
        Ok(socket.into())
    }

    fn socket(self, addr: SocketAddr, socket_type: Type, protocol: Protocol) -> io::Result<Socket> {
        let ipv4 = addr.is_ipv4();
        let interface = if ipv4 { self.ipv4 } else { self.ipv6 }.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "no physical egress for this address family",
            )
        })?;
        let socket = Socket::new(Domain::for_address(addr), socket_type, Some(protocol))?;
        if !ipv4 {
            socket.set_only_v6(true)?;
        }
        self.bind_interface(&socket, interface, ipv4)?;
        Ok(socket)
    }

    #[cfg(target_os = "linux")]
    fn bind_interface(self, socket: &Socket, _: NonZeroU32, _: bool) -> io::Result<()> {
        socket.set_mark(self.mark.get())
    }

    #[cfg(target_os = "macos")]
    fn bind_interface(self, socket: &Socket, interface: NonZeroU32, ipv4: bool) -> io::Result<()> {
        if ipv4 {
            socket.bind_device_by_index_v4(Some(interface))
        } else {
            socket.bind_device_by_index_v6(Some(interface))
        }
    }

    #[cfg(windows)]
    fn bind_interface(self, socket: &Socket, interface: NonZeroU32, ipv4: bool) -> io::Result<()> {
        windows::bind(socket, interface, ipv4)
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    fn bind_interface(self, _: &Socket, _: NonZeroU32, _: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "physical egress binding is unavailable",
        ))
    }
}

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Windows socket2 has no wrapper for the unicast interface options"
)]
mod windows {
    use std::io;
    use std::num::NonZeroU32;
    use std::os::windows::io::AsRawSocket;

    use socket2::Socket;
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET_ERROR, WSAGetLastError,
        setsockopt,
    };

    pub(super) fn bind(socket: &Socket, interface: NonZeroU32, ipv4: bool) -> io::Result<()> {
        let (level, option, bytes) = if ipv4 {
            (IPPROTO_IP, IP_UNICAST_IF, interface.get().to_be_bytes())
        } else {
            (IPPROTO_IPV6, IPV6_UNICAST_IF, interface.get().to_ne_bytes())
        };
        // SAFETY: The socket remains borrowed and the option is a four-byte
        // input WinSock reads synchronously. Nothing changes socket ownership.
        let error = unsafe {
            if setsockopt(
                socket.as_raw_socket() as usize,
                level,
                option,
                bytes.as_ptr(),
                4,
            ) == SOCKET_ERROR
            {
                Some(WSAGetLastError())
            } else {
                None
            }
        };
        error.map_or(Ok(()), |code| Err(io::Error::from_raw_os_error(code)))
    }
}
