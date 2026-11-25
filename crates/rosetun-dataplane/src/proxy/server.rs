//! Local mixed proxy listener: accepts TCP connections on one or more
//! addresses, peeks the first byte to separate SOCKS5 (`0x05`) from HTTP,
//! and dispatches each connection to a bounded worker thread.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::{http, router::Router, socks};

pub(super) const ACCEPT_POLL: Duration = Duration::from_millis(10);

/// Why binding the local proxy failed.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("no listen addresses given")]
    NoAddresses,
    #[error("could not bind local proxy listener")]
    Bind {
        #[source]
        source: io::Error,
    },
    #[error("could not start listener thread")]
    Thread {
        #[source]
        source: io::Error,
    },
}

/// Running local mixed proxy (HTTP + SOCKS5 on the same port).
pub struct ProxyServer {
    router: Arc<Router>,
    addresses: Vec<SocketAddr>,
    shutdown: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    clients: Arc<Clients>,
}

impl fmt::Debug for ProxyServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyServer")
            .field("listeners", &self.addresses.len())
            .field("stopped", &self.shutdown.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl ProxyServer {
    /// Binds every address in `addresses` and starts accepting connections.
    pub fn bind(router: Arc<Router>, addresses: &[SocketAddr]) -> Result<Self, ServerError> {
        if addresses.is_empty() {
            return Err(ServerError::NoAddresses);
        }
        let mut bound = Vec::with_capacity(addresses.len());
        let mut local_addrs = Vec::with_capacity(addresses.len());
        for &address in addresses {
            let listener =
                TcpListener::bind(address).map_err(|source| ServerError::Bind { source })?;
            listener
                .set_nonblocking(true)
                .map_err(|source| ServerError::Bind { source })?;
            let local = listener
                .local_addr()
                .map_err(|source| ServerError::Bind { source })?;
            bound.push(listener);
            local_addrs.push(local);
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let mut server = Self {
            router,
            addresses: local_addrs,
            shutdown,
            workers: Vec::with_capacity(bound.len()),
            clients: Arc::new(Clients::default()),
        };

        for listener in bound {
            let router = Arc::clone(&server.router);
            let shutdown = Arc::clone(&server.shutdown);
            let clients = Arc::clone(&server.clients);
            let handle = thread::Builder::new()
                .name("dataplane-proxy".to_owned())
                .spawn(move || accept_loop(listener, router, shutdown, clients))
                .map_err(|source| ServerError::Thread { source })?;
            server.workers.push(handle);
        }

        Ok(server)
    }

    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.addresses
    }

    /// Stops accepting new connections, closes active connections, and waits
    /// for the listener threads to exit. Idempotent.
    pub fn shutdown(&mut self) {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }
        self.router.table().shutdown();
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
        self.clients.close_and_wait();
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Default)]
pub(crate) struct Clients {
    next: AtomicUsize,
    sockets: Mutex<HashMap<usize, TcpStream>>,
    finished: Condvar,
}

impl Clients {
    pub(crate) fn track(self: &Arc<Self>, stream: &TcpStream, limit: usize) -> Option<Client> {
        let mut sockets = self.sockets.lock().unwrap_or_else(PoisonError::into_inner);
        if sockets.len() >= limit {
            return None;
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        sockets.insert(id, stream.try_clone().ok()?);
        Some(Client {
            id,
            clients: Arc::clone(self),
        })
    }

    pub(crate) fn close_and_wait(&self) {
        let sockets = self.sockets.lock().unwrap_or_else(PoisonError::into_inner);
        for stream in sockets.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        drop(
            self.finished
                .wait_while(sockets, |sockets| !sockets.is_empty()),
        );
    }
}

pub(crate) struct Client {
    id: usize,
    clients: Arc<Clients>,
}

impl Drop for Client {
    fn drop(&mut self) {
        let mut sockets = self
            .clients
            .sockets
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        sockets.remove(&self.id);
        if sockets.is_empty() {
            self.clients.finished.notify_all();
        }
    }
}

fn accept_loop(
    listener: TcpListener,
    router: Arc<Router>,
    shutdown: Arc<AtomicBool>,
    clients: Arc<Clients>,
) {
    let limit = router.config().max_connections;
    while !shutdown.load(Ordering::Acquire) {
        let Ok((stream, _)) = listener.accept() else {
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(ACCEPT_POLL);
            continue;
        };
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        if stream.set_nonblocking(false).is_err() {
            continue;
        }
        let Some(client) = clients.track(&stream, limit) else {
            continue;
        };
        let router = Arc::clone(&router);
        let shutdown = Arc::clone(&shutdown);
        let _ = thread::Builder::new()
            .name("dataplane-conn".to_owned())
            .spawn(move || {
                let _client = client;
                handle_client(router, stream, &shutdown);
            });
    }
}

fn handle_client(router: Arc<Router>, stream: TcpStream, shutdown: &AtomicBool) {
    stream.set_nodelay(true).ok();
    stream
        .set_read_timeout(Some(router.config().handshake_timeout))
        .ok();
    let mut first = [0u8; 1];
    let Ok(read) = stream.peek(&mut first) else {
        return;
    };
    if read == 0 {
        return;
    }
    if first[0] == 0x05 {
        let _ = socks::serve(
            &router,
            stream,
            &socks::Access::Open,
            router.table(),
            shutdown,
        );
    } else {
        let _ = http::serve(&router, stream);
    }
}
