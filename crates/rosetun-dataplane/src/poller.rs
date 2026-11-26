//! Safe RAII wrappers around [`polling::Poller`] (`epoll` on Linux, `kqueue`
//! on macOS, `wepoll`/AFD IOCP on Windows).
//!
//! `polling` requires every registered socket to be deleted from the poller
//! before its underlying OS descriptor is closed. [`PolledStream`] and
//! [`PolledUdpPath`] own the socket (or `Arc<UdpPath>`) and delete it in
//! `Drop` before the owned descriptor is dropped.

use std::io;
use std::net::{TcpStream, UdpSocket};
use std::sync::Arc;

use polling::{Event, Poller};

use crate::net::UdpPath;

pub(crate) struct PolledStream {
    poller: Arc<Poller>,
    stream: TcpStream,
    key: usize,
}

impl PolledStream {
    pub(crate) fn new(
        poller: Arc<Poller>,
        stream: TcpStream,
        key: usize,
        readable: bool,
        writable: bool,
    ) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        // SAFETY: `Self` owns `stream` and deletes it from `poller` in `Drop`
        // before `stream` is dropped and its OS handle is closed.
        unsafe {
            poller.add(&stream, Event::new(key, readable, writable))?;
        }
        Ok(Self {
            poller,
            stream,
            key,
        })
    }

    pub(crate) fn get(&self) -> &TcpStream {
        &self.stream
    }

    pub(crate) fn rearm(&self, readable: bool, writable: bool) -> io::Result<()> {
        self.poller
            .modify(&self.stream, Event::new(self.key, readable, writable))
    }
}

impl Drop for PolledStream {
    fn drop(&mut self) {
        let _ = self.poller.delete(&self.stream);
    }
}

pub(crate) struct PolledUdpPath {
    poller: Arc<Poller>,
    path: Arc<UdpPath>,
    key_v4: Option<usize>,
    key_v6: Option<usize>,
}

impl PolledUdpPath {
    pub(crate) fn new(
        poller: Arc<Poller>,
        path: Arc<UdpPath>,
        key_v4: usize,
        key_v6: usize,
    ) -> io::Result<Option<Self>> {
        path.set_nonblocking(true)?;
        let (v4, v6) = path.recv_sockets();
        if v4.is_none() && v6.is_none() {
            return Ok(None);
        }
        let mut registered_v4 = None;
        if let Some(sock) = v4 {
            // SAFETY: `path` keeps `sock` alive until after `Self::drop`
            // removes every registered socket from `poller`.
            unsafe {
                poller.add(sock, Event::readable(key_v4))?;
            }
            registered_v4 = Some(key_v4);
        }
        let mut registered_v6 = None;
        if let Some(sock) = v6 {
            // SAFETY: Same ownership guarantee; if adding `v6` fails, clean up
            // `v4` immediately before returning.
            let added = unsafe { poller.add(sock, Event::readable(key_v6)) };
            if let Err(err) = added {
                if registered_v4.is_some()
                    && let Some(sock_v4) = v4
                {
                    let _ = poller.delete(sock_v4);
                }
                return Err(err);
            }
            registered_v6 = Some(key_v6);
        }
        Ok(Some(Self {
            poller,
            path,
            key_v4: registered_v4,
            key_v6: registered_v6,
        }))
    }

    pub(crate) fn path(&self) -> &Arc<UdpPath> {
        &self.path
    }

    pub(crate) fn rearm(&self, is_v6: bool) -> io::Result<()> {
        let (v4, v6) = self.path.recv_sockets();
        if is_v6 {
            if let (Some(key), Some(sock)) = (self.key_v6, v6) {
                self.poller.modify(sock, Event::readable(key))?;
            }
        } else if let (Some(key), Some(sock)) = (self.key_v4, v4) {
            self.poller.modify(sock, Event::readable(key))?;
        }
        Ok(())
    }

    fn delete_one(poller: &Poller, sock: Option<&UdpSocket>, registered: Option<usize>) {
        if registered.is_some()
            && let Some(sock) = sock
        {
            let _ = poller.delete(sock);
        }
    }
}

impl Drop for PolledUdpPath {
    fn drop(&mut self) {
        let (v4, v6) = self.path.recv_sockets();
        Self::delete_one(&self.poller, v4, self.key_v4);
        Self::delete_one(&self.poller, v6, self.key_v6);
    }
}
