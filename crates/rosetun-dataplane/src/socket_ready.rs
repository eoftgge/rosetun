use std::io;
use std::net::TcpStream;
use std::os::windows::io::AsRawSocket;
use std::time::Duration;

use windows_sys::Win32::Networking::WinSock::{
    POLLRDNORM, POLLWRNORM, SOCKET_ERROR, WSAGetLastError, WSAPOLLFD, WSAPoll,
};

pub(crate) fn readable(stream: &TcpStream, timeout: Duration) -> io::Result<bool> {
    wait(stream, POLLRDNORM, timeout)
}

pub(crate) fn writable(stream: &TcpStream, timeout: Duration) -> io::Result<bool> {
    wait(stream, POLLWRNORM, timeout)
}

fn wait(stream: &TcpStream, events: i16, timeout: Duration) -> io::Result<bool> {
    let mut fd = WSAPOLLFD {
        fd: stream.as_raw_socket() as usize,
        events,
        revents: 0,
    };
    let millis = if timeout.is_zero() {
        0
    } else {
        i32::try_from(timeout.as_millis().max(1)).unwrap_or(i32::MAX)
    };
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

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::*;

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
}
