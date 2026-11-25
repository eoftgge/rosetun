//! The live connection table and traffic counters: what the engine's local
//! control API gave the helper, kept by the data plane itself.
//!
//! A registered connection counts its bytes into its own counters and into
//! the table's totals. The table can close a connection by id: it shuts down
//! the sockets attached to the connection and flags UDP flows, whose relay
//! loops poll the flag. A finished connection moves into a bounded ring.
//!
//! A connection is the user's browsing history: nothing here logs one and no
//! `Debug` shows a destination, address, program or id.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use rosetun_config::ConnectionNetwork;
use rosetun_engine::errors::EngineError;
use rosetun_engine::{EngineConnection, EngineRoute, TrafficProbe, TrafficSample, TrafficTotals};

/// Most connections the table holds at once.
pub const MAX_ACTIVE_CONNECTIONS: usize = 8192;
/// Finished connections kept for the client's list.
pub const MAX_CLOSED_CONNECTIONS: usize = 300;

/// What is known about a connection when it starts.
#[derive(Clone)]
pub struct ConnectionMeta {
    pub process: Option<String>,
    /// The sniffed or requested domain, otherwise the IP address.
    pub host: String,
    /// The destination address when `host` is a name.
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub network: ConnectionNetwork,
    pub route: EngineRoute,
}

impl fmt::Debug for ConnectionMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionMeta")
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

/// A finished connection with the time it ended.
#[derive(Clone, PartialEq, Eq)]
pub struct ClosedConnection {
    pub connection: EngineConnection,
    pub end_unix_ms: u64,
}

impl fmt::Debug for ClosedConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClosedConnection")
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

/// The table is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("too many connections")]
pub struct TableFull;

#[derive(Default)]
struct Totals {
    up: AtomicU64,
    down: AtomicU64,
}

struct Entry {
    meta: ConnectionMeta,
    start_unix_ms: u64,
    shared: Arc<Shared>,
}

/// State a registration and the table both reach.
struct Shared {
    up: AtomicU64,
    down: AtomicU64,
    closed: AtomicBool,
    sockets: Mutex<Vec<TcpStream>>,
}

struct Inner {
    totals: Totals,
    active: Mutex<HashMap<String, Entry>>,
    closed: Mutex<VecDeque<ClosedConnection>>,
    max_active: usize,
    max_closed: usize,
}

/// The registry. Cheap to clone; every clone is the same table.
#[derive(Clone)]
pub struct ConnectionTable {
    inner: Arc<Inner>,
}

impl fmt::Debug for ConnectionTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionTable")
            .field("active", &lock(&self.inner.active).len())
            .finish_non_exhaustive()
    }
}

impl Default for ConnectionTable {
    fn default() -> Self {
        Self::with_limits(MAX_ACTIVE_CONNECTIONS, MAX_CLOSED_CONNECTIONS)
    }
}

impl ConnectionTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(max_active: usize, max_closed: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                totals: Totals::default(),
                active: Mutex::new(HashMap::new()),
                closed: Mutex::new(VecDeque::new()),
                max_active,
                max_closed,
            }),
        }
    }

    /// Adds a connection. It stays in the table until the returned
    /// [`Registration`] is dropped.
    pub fn register(&self, meta: ConnectionMeta) -> Result<Registration, TableFull> {
        let shared = Arc::new(Shared {
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            sockets: Mutex::new(Vec::new()),
        });
        let mut active = lock(&self.inner.active);
        if active.len() >= self.inner.max_active {
            return Err(TableFull);
        }
        let mut id = new_id();
        while active.contains_key(&id) {
            id = new_id();
        }
        active.insert(
            id.clone(),
            Entry {
                meta,
                start_unix_ms: now_unix_ms(),
                shared: Arc::clone(&shared),
            },
        );
        Ok(Registration {
            table: Arc::clone(&self.inner),
            id,
            shared,
        })
    }

    /// Bytes carried since the table was created, finished connections
    /// included.
    pub fn totals(&self) -> TrafficTotals {
        TrafficTotals {
            up: self.inner.totals.up.load(Ordering::Relaxed),
            down: self.inner.totals.down.load(Ordering::Relaxed),
        }
    }

    pub fn active_count(&self) -> usize {
        lock(&self.inner.active).len()
    }

    /// The connections carried now, oldest first.
    pub fn active(&self) -> Vec<EngineConnection> {
        let active = lock(&self.inner.active);
        let mut list: Vec<EngineConnection> = active
            .iter()
            .map(|(id, entry)| snapshot(id, entry))
            .collect();
        list.sort_by(|a, b| a.start_unix_ms.cmp(&b.start_unix_ms).then(a.id.cmp(&b.id)));
        list
    }

    /// The most recently finished connections, newest last.
    pub fn closed(&self) -> Vec<ClosedConnection> {
        lock(&self.inner.closed).iter().cloned().collect()
    }

    /// Shuts down the connection with `id`. `false` when no active
    /// connection has it (an unknown id is not an error).
    pub fn close_connection(&self, id: &str) -> bool {
        if !rosetun_engine::valid_connection_id(id) {
            return false;
        }
        let shared = lock(&self.inner.active)
            .get(id)
            .map(|entry| Arc::clone(&entry.shared));
        match shared {
            Some(shared) => {
                shared.close();
                true
            }
            None => false,
        }
    }

    /// Shuts down every active connection.
    pub fn close_all(&self) {
        let all: Vec<Arc<Shared>> = lock(&self.inner.active)
            .values()
            .map(|entry| Arc::clone(&entry.shared))
            .collect();
        for shared in all {
            shared.close();
        }
    }

    /// A probe that reads this table the way the helper reads the engine's
    /// control API.
    pub fn probe(&self) -> TableProbe {
        TableProbe {
            table: self.clone(),
        }
    }
}

/// [`TrafficProbe`] over a [`ConnectionTable`]; it cannot fail.
#[derive(Clone)]
pub struct TableProbe {
    table: ConnectionTable,
}

impl fmt::Debug for TableProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TableProbe").finish_non_exhaustive()
    }
}

impl TrafficProbe for TableProbe {
    fn sample(&mut self, connections: bool) -> Result<TrafficSample, EngineError> {
        Ok(TrafficSample {
            totals: self.table.totals(),
            connections: connections.then(|| self.table.active()),
        })
    }
}

/// One connection's membership in the table; dropping it ends the
/// connection and moves it into the closed ring.
pub struct Registration {
    table: Arc<Inner>,
    id: String,
    shared: Arc<Shared>,
}

impl fmt::Debug for Registration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registration")
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl Registration {
    /// The id the client sees; never log it.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Hands a socket of the connection to the table, so closing the
    /// connection shuts it down. If the connection is already closed the
    /// socket is shut down at once.
    pub fn attach(&self, stream: &TcpStream) {
        if self.is_closed() {
            stream.shutdown(Shutdown::Both).ok();
            return;
        }
        if let Ok(clone) = stream.try_clone() {
            lock(&self.shared.sockets).push(clone);
            // A close that raced the push must not miss this socket.
            if self.is_closed() {
                stream.shutdown(Shutdown::Both).ok();
            }
        }
    }

    /// Whether the table closed this connection; relay loops that cannot
    /// be woken by a socket shutdown (UDP) poll this.
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }

    /// A handle for counting bytes from another thread.
    pub fn counters(&self) -> Counters {
        Counters {
            shared: Arc::clone(&self.shared),
            table: Arc::clone(&self.table),
        }
    }

    pub fn add_up(&self, bytes: u64) {
        self.counters().add_up(bytes);
    }

    pub fn add_down(&self, bytes: u64) {
        self.counters().add_down(bytes);
    }

    /// Uploaded and downloaded bytes so far.
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.shared.up.load(Ordering::Relaxed),
            self.shared.down.load(Ordering::Relaxed),
        )
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let Some(entry) = lock(&self.table.active).remove(&self.id) else {
            return;
        };
        let connection = snapshot(&self.id, &entry);
        let mut closed = lock(&self.table.closed);
        closed.push_back(ClosedConnection {
            connection,
            end_unix_ms: now_unix_ms(),
        });
        while closed.len() > self.table.max_closed {
            closed.pop_front();
        }
    }
}

/// Byte counters of one connection, usable from relay threads.
#[derive(Clone)]
pub struct Counters {
    shared: Arc<Shared>,
    table: Arc<Inner>,
}

impl fmt::Debug for Counters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Counters").finish_non_exhaustive()
    }
}

impl Counters {
    /// Client to server.
    pub fn add_up(&self, bytes: u64) {
        self.shared.up.fetch_add(bytes, Ordering::Relaxed);
        self.table.totals.up.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Server to client.
    pub fn add_down(&self, bytes: u64) {
        self.shared.down.fetch_add(bytes, Ordering::Relaxed);
        self.table.totals.down.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }
}

impl Shared {
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        for socket in lock(&self.sockets).iter() {
            socket.shutdown(Shutdown::Both).ok();
        }
    }
}

fn snapshot(id: &str, entry: &Entry) -> EngineConnection {
    EngineConnection {
        id: id.to_owned(),
        start_unix_ms: entry.start_unix_ms,
        process: entry.meta.process.clone(),
        host: entry.meta.host.clone(),
        ip: entry.meta.ip.map(|ip| ip.to_string()),
        port: entry.meta.port,
        network: entry.meta.network,
        route: entry.meta.route.clone(),
        upload: entry.shared.up.load(Ordering::Relaxed),
        download: entry.shared.down.load(Ordering::Relaxed),
    }
}

/// A random 128-bit id as 32 hexadecimal digits.
fn new_id() -> String {
    static FALLBACK: AtomicU64 = AtomicU64::new(1);
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        bytes[..8].copy_from_slice(&now_unix_ms().to_be_bytes());
        bytes[8..].copy_from_slice(&FALLBACK.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    }
    let mut id = String::with_capacity(32);
    for byte in bytes {
        id.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        id.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    id
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// A poisoned table lock only means a thread panicked while counting; the
/// data is plain and worth serving.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::*;

    fn meta(host: &str) -> ConnectionMeta {
        ConnectionMeta {
            process: None,
            host: host.to_owned(),
            ip: Some("192.0.2.10".parse().unwrap()),
            port: 443,
            network: ConnectionNetwork::Tcp,
            route: EngineRoute::Direct,
        }
    }

    #[test]
    fn counters_feed_the_connection_and_the_totals() {
        let table = ConnectionTable::new();
        let first = table.register(meta("a.example.com")).unwrap();
        let second = table.register(meta("b.example.com")).unwrap();
        first.add_up(10);
        first.add_down(20);
        second.counters().add_up(5);
        assert_eq!(table.totals(), TrafficTotals { up: 15, down: 20 });
        let active = table.active();
        assert_eq!(active.len(), 2);
        let found = active.iter().find(|c| c.id == first.id()).unwrap();
        assert_eq!((found.upload, found.download), (10, 20));
        assert_eq!(found.ip.as_deref(), Some("192.0.2.10"));
    }

    #[test]
    fn a_dropped_registration_moves_to_the_bounded_closed_ring() {
        let table = ConnectionTable::with_limits(8, 2);
        for name in ["a", "b", "c"] {
            let registration = table.register(meta(name)).unwrap();
            registration.add_down(7);
        }
        assert_eq!(table.active_count(), 0);
        let closed = table.closed();
        assert_eq!(closed.len(), 2);
        assert_eq!(closed[0].connection.host, "b");
        assert_eq!(closed[1].connection.host, "c");
        assert_eq!(closed[1].connection.download, 7);
        assert_eq!(table.totals().down, 21);
    }

    #[test]
    fn the_active_table_is_bounded() {
        let table = ConnectionTable::with_limits(1, 1);
        let _kept = table.register(meta("a")).unwrap();
        assert_eq!(table.register(meta("b")).unwrap_err(), TableFull);
    }

    #[test]
    fn closing_by_id_shuts_the_attached_socket_down() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let table = ConnectionTable::new();
        let registration = table.register(meta("a")).unwrap();
        registration.attach(&server);
        assert!(!table.close_connection("unknown"));
        assert!(table.close_connection(registration.id()));
        assert!(registration.is_closed());
        let mut buffer = [0u8; 8];
        assert_eq!(client.read(&mut buffer).unwrap_or(0), 0);
        assert!(server.write_all(b"x").is_err() || server.write_all(b"y").is_err());
    }

    #[test]
    fn attaching_to_a_closed_connection_shuts_the_socket_at_once() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let table = ConnectionTable::new();
        let registration = table.register(meta("a")).unwrap();
        table.close_all();
        registration.attach(&server);
        let mut buffer = [0u8; 8];
        assert_eq!(client.read(&mut buffer).unwrap_or(0), 0);
    }

    #[test]
    fn the_probe_reports_totals_and_connections_on_request() {
        let table = ConnectionTable::new();
        let registration = table.register(meta("a")).unwrap();
        registration.add_up(3);
        let mut probe = table.probe();
        let bare = probe.sample(false).unwrap();
        assert_eq!(bare.totals.up, 3);
        assert!(bare.connections.is_none());
        let full = probe.sample(true).unwrap();
        assert_eq!(full.connections.unwrap().len(), 1);
    }

    #[test]
    fn debug_output_shows_no_destination_or_id() {
        let table = ConnectionTable::new();
        let registration = table.register(meta("secret.example.com")).unwrap();
        let id = registration.id().to_owned();
        let text = format!(
            "{table:?} {registration:?} {:?} {:?}",
            meta("secret.example.com"),
            table.active()
        );
        assert!(!text.contains("secret"));
        assert!(!text.contains("192.0.2"));
        assert!(!text.contains(&id));
    }

    #[test]
    fn an_over_long_or_empty_id_closes_nothing() {
        let table = ConnectionTable::new();
        let _registration = table.register(meta("a")).unwrap();
        assert!(!table.close_connection(""));
        assert!(!table.close_connection(&"x".repeat(65)));
    }
}
