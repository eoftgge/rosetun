use std::io;
#[cfg(windows)]
use std::net::TcpStream;
use std::net::UdpSocket;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::time::Duration;

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    POLLRDNORM, POLLWRNORM, SOCKET_ERROR, WSAGetLastError, WSAPOLLFD, WSAPoll,
};

#[cfg(windows)]
pub(crate) fn readable(stream: &TcpStream, timeout: Duration) -> io::Result<bool> {
    wait(stream, POLLRDNORM, timeout)
}

#[cfg(windows)]
pub(crate) fn writable(stream: &TcpStream, timeout: Duration) -> io::Result<bool> {
    wait(stream, POLLWRNORM, timeout)
}

fn timeout_millis(timeout: Duration) -> i32 {
    if timeout.is_zero() {
        0
    } else {
        i32::try_from(timeout.as_millis().max(1)).unwrap_or(i32::MAX)
    }
}

#[cfg(windows)]
fn wait(stream: &TcpStream, events: i16, timeout: Duration) -> io::Result<bool> {
    let mut fd = WSAPOLLFD {
        fd: stream.as_raw_socket() as usize,
        events,
        revents: 0,
    };
    let millis = timeout_millis(timeout);
    // SAFETY: The socket remains borrowed while WSAPoll writes to the single
    // descriptor. This readiness test does not consume any socket data.
    let result = unsafe { WSAPoll(&raw mut fd, 1, millis) };
    if result == SOCKET_ERROR {
        // SAFETY: WinSock returns the error value for the calling thread.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    // An error/hangup event is also readiness: the I/O operation reports it.
    Ok(result > 0)
}

/// Waits until at least one UDP socket in `sockets` is readable (or reports an
/// error/hangup), clearing and populating `ready` with the ready indices.
#[cfg(windows)]
pub(crate) fn poll_udp_readable(
    sockets: &[&UdpSocket],
    timeout: Duration,
    ready: &mut Vec<usize>,
) -> io::Result<()> {
    ready.clear();
    if sockets.is_empty() {
        return Ok(());
    }
    let mut fds: Vec<WSAPOLLFD> = sockets
        .iter()
        .map(|socket| WSAPOLLFD {
            fd: socket.as_raw_socket() as usize,
            events: POLLRDNORM,
            revents: 0,
        })
        .collect();
    let count = u32::try_from(fds.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many UDP sockets to poll"))?;
    let millis = timeout_millis(timeout);
    // SAFETY: Every UdpSocket in `sockets` remains borrowed for the duration of
    // WSAPoll, and `fds` has exactly `count` initialized entries.
    let result = unsafe { WSAPoll(fds.as_mut_ptr(), count, millis) };
    if result == SOCKET_ERROR {
        // SAFETY: WinSock returns the error value for the calling thread.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    if result > 0 {
        for (index, fd) in fds.iter().enumerate() {
            if fd.revents != 0 {
                ready.push(index);
            }
        }
    }
    Ok(())
}

/// Waits until at least one UDP socket in `sockets` is readable (or reports an
/// error/hangup), clearing and populating `ready` with the ready indices.
#[cfg(target_os = "linux")]
pub(crate) fn poll_udp_readable(
    sockets: &[&UdpSocket],
    timeout: Duration,
    ready: &mut Vec<usize>,
) -> io::Result<()> {
    ready.clear();
    if sockets.is_empty() {
        return Ok(());
    }
    let mut fds: Vec<libc::pollfd> = sockets
        .iter()
        .map(|socket| libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let count = libc::nfds_t::try_from(fds.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many UDP sockets to poll"))?;
    let millis = timeout_millis(timeout);
    // SAFETY: Every UdpSocket in `sockets` remains borrowed for the duration of
    // poll, and `fds` has exactly `count` initialized entries.
    let result = unsafe { libc::poll(fds.as_mut_ptr(), count, millis) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result > 0 {
        for (index, fd) in fds.iter().enumerate() {
            if fd.revents != 0 {
                ready.push(index);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use std::io::{Read, Write};
    #[cfg(windows)]
    use std::net::TcpListener;

    use super::*;

    #[cfg(windows)]
    #[test]
    fn an_expired_readiness_wait_leaves_the_socket_usable() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server.set_nonblocking(true).unwrap();
        assert!(!readable(&server, Duration::from_millis(10)).unwrap());
        client.write_all(b"ok").unwrap();
        assert!(readable(&server, Duration::from_secs(1)).unwrap());
        let mut data = [0; 2];
        server.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"ok");
    }

    #[test]
    fn poll_udp_readable_reports_the_ready_socket_index() {
        let first = UdpSocket::bind("127.0.0.1:0").unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        first.set_nonblocking(true).unwrap();
        second.set_nonblocking(true).unwrap();
        let mut ready = Vec::new();
        poll_udp_readable(&[&first, &second], Duration::from_millis(5), &mut ready).unwrap();
        assert!(ready.is_empty());
        sender.send_to(b"hi", second.local_addr().unwrap()).unwrap();
        poll_udp_readable(&[&first, &second], Duration::from_secs(1), &mut ready).unwrap();
        assert_eq!(ready, vec![1]);
    }
}
