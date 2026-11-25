//! Local mixed proxy listener: accepts TCP connections on one or more
//! addresses, peeks the first byte to separate SOCKS5 (`0x05`) from HTTP,
//! and dispatches each connection to a bounded worker thread.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::{http, router::Router, socks};

const WAKE_TIMEOUT: Duration = Duration::from_millis(200);

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
            let local = listener
                .local_addr()
                .map_err(|source| ServerError::Bind { source })?;
            bound.push(listener);
            local_addrs.push(local);
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::with_capacity(bound.len());

        for listener in bound {
            let router = Arc::clone(&router);
            let shutdown = Arc::clone(&shutdown);
            let active = Arc::clone(&active);
            let handle = thread::Builder::new()
                .name("dataplane-proxy".to_owned())
                .spawn(move || accept_loop(listener, router, shutdown, active))
                .map_err(|source| ServerError::Thread { source })?;
            workers.push(handle);
        }

        Ok(Self {
            router,
            addresses: local_addrs,
            shutdown,
            workers,
        })
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
        self.router.table().close_all();
        for &address in &self.addresses {
            wake_listener(address);
        }
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct SlotGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn accept_loop(
    listener: TcpListener,
    router: Arc<Router>,
    shutdown: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
) {
    let limit = router.config().max_connections;
    while !shutdown.load(Ordering::Acquire) {
        let Ok((stream, _)) = listener.accept() else {
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
            continue;
        };
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        if !try_acquire_slot(&active, limit) {
            continue;
        }
        let guard = SlotGuard {
            active: Arc::clone(&active),
        };
        let router = Arc::clone(&router);
        let shutdown = Arc::clone(&shutdown);
        let spawned = thread::Builder::new()
            .name("dataplane-conn".to_owned())
            .spawn(move || {
                let _guard = guard;
                handle_client(router, stream, &shutdown);
            });
        if spawned.is_err() {
            // Guard drops on spawn error if not moved; here it moved into the closure.
        }
    }
}

fn try_acquire_slot(active: &AtomicUsize, limit: usize) -> bool {
    let mut current = active.load(Ordering::Acquire);
    while current < limit {
        match active.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
    false
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

/// Connects to the listening socket so a blocking `accept()` wakes up and
/// observes the shutdown flag.
pub(crate) fn wake_listener(address: SocketAddr) {
    let target = match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), address.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), address.port())
        }
        _ => address,
    };
    let _ = TcpStream::connect_timeout(&target, WAKE_TIMEOUT);
}
