//! Live connections of the running session for the Traffic tab.
//!
//! The list is the user's browsing history: it lives only in this memory, is
//! never written to disk, a log or a report, and is cleared whenever the
//! engine stops. It is collected only while its owner reads it.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rosetun_config::{ConnectionRoute, ExitId, LiveConnection};
use rosetun_engine::{EngineConnection, EngineRoute, MAX_CONNECTION_ID_CHARS};
use rosetun_ipc::{
    MAX_ACTIVE_CONNECTIONS, MAX_CLOSED_CONNECTIONS, MAX_CONNECTION_HOST_CHARS,
    MAX_CONNECTION_PROCESS_CHARS,
};

/// Exit identifiers come from the client and are not otherwise bounded; a
/// longer one is shown as an unnamed route so the answer always fits a frame.
const MAX_EXIT_ID_BYTES: usize = 64;

/// Without a request for this long the list is no longer collected.
pub(super) const WATCH_WINDOW: Duration = Duration::from_secs(3);

#[derive(Default)]
pub(super) struct ConnectionBook {
    watched_at: Option<Instant>,
    /// Every connection of the last poll by engine id, to notice which closed.
    previous: HashMap<String, LiveConnection>,
    /// Newest first, at most [`MAX_ACTIVE_CONNECTIONS`].
    active: Vec<LiveConnection>,
    /// Newest first, at most [`MAX_CLOSED_CONNECTIONS`].
    closed: VecDeque<LiveConnection>,
}

impl std::fmt::Debug for ConnectionBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionBook")
            .field("watched", &self.watched_at.is_some())
            .field("active", &self.active.len())
            .field("closed", &self.closed.len())
            .finish()
    }
}

impl ConnectionBook {
    pub(super) fn watch(&mut self, now: Instant) {
        self.watched_at = Some(now);
    }

    pub(super) fn watched(&self, now: Instant) -> bool {
        self.watched_at
            .is_some_and(|at| now.saturating_duration_since(at) < WATCH_WINDOW)
    }

    /// Drops every connection but keeps whether someone is reading the list.
    pub(super) fn forget(&mut self) {
        self.previous = HashMap::new();
        self.active = Vec::new();
        self.closed = VecDeque::new();
    }

    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }

    pub(super) fn is_empty(&self) -> bool {
        self.previous.is_empty() && self.closed.is_empty()
    }

    /// Takes one poll of the engine. Connections of the previous poll that are
    /// missing now closed between the two polls.
    pub(super) fn record(&mut self, current: Vec<(String, LiveConnection)>, now_unix_ms: u64) {
        let current: HashMap<_, _> = current.into_iter().collect();
        let mut ended: Vec<_> = self
            .previous
            .drain()
            .filter(|(id, _)| !current.contains_key(id))
            .map(|(_, mut connection)| {
                connection.end_unix_ms = Some(now_unix_ms.max(connection.start_unix_ms));
                connection
            })
            .collect();
        ended.sort_by_key(|connection| connection.start_unix_ms);
        for connection in ended {
            self.closed.push_front(connection);
        }
        self.closed.truncate(MAX_CLOSED_CONNECTIONS);

        let mut active: Vec<_> = current.values().cloned().collect();
        active.sort_by_key(|connection| std::cmp::Reverse(connection.start_unix_ms));
        active.truncate(MAX_ACTIVE_CONNECTIONS);
        self.active = active;
        self.previous = current;
    }

    pub(super) fn snapshot(&self) -> (Vec<LiveConnection>, Vec<LiveConnection>) {
        (self.active.clone(), self.closed.iter().cloned().collect())
    }
}

/// What the monitor needs to turn engine entries into list entries.
#[derive(Default)]
pub(super) struct Translation {
    /// Each exit's outbound tag in the running config.
    pub(super) exit_tags: Vec<(ExitId, Option<String>)>,
    /// Programs of the service itself (its DNS and path checks, Xray), which
    /// are not the user's traffic.
    pub(super) hidden: Vec<PathBuf>,
}

impl std::fmt::Debug for Translation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Translation")
            .field("exits", &self.exit_tags.len())
            .field("hidden", &self.hidden.len())
            .finish()
    }
}

impl Translation {
    pub(super) fn translate(
        &self,
        connections: Vec<EngineConnection>,
    ) -> Vec<(String, LiveConnection)> {
        connections
            .into_iter()
            .filter(|connection| {
                !connection
                    .process
                    .as_deref()
                    .is_some_and(|process| self.is_hidden(Path::new(process)))
            })
            .map(|connection| {
                let route = match connection.route {
                    EngineRoute::Proxy => ConnectionRoute::Proxy,
                    EngineRoute::Direct => ConnectionRoute::Direct,
                    EngineRoute::Exit(tag) => self
                        .exit_tags
                        .iter()
                        .find(|(exit, exit_tag)| {
                            exit_tag.as_deref() == Some(tag.as_str())
                                && exit.as_str().len() <= MAX_EXIT_ID_BYTES
                        })
                        .map_or(ConnectionRoute::Other, |(exit, _)| {
                            ConnectionRoute::Exit(exit.clone())
                        }),
                    EngineRoute::Other => ConnectionRoute::Other,
                };
                let id = if connection.id.chars().count() <= MAX_CONNECTION_ID_CHARS {
                    connection.id.clone()
                } else {
                    String::new()
                };
                let entry = LiveConnection {
                    id,
                    start_unix_ms: connection.start_unix_ms,
                    end_unix_ms: None,
                    process: connection
                        .process
                        .map(|process| bounded(&process, MAX_CONNECTION_PROCESS_CHARS)),
                    host: bounded(&connection.host, MAX_CONNECTION_HOST_CHARS),
                    port: connection.port,
                    network: connection.network,
                    route,
                    download: connection.download,
                    upload: connection.upload,
                };
                (connection.id, entry)
            })
            .collect()
    }

    fn is_hidden(&self, process: &Path) -> bool {
        self.hidden.iter().any(|hidden| same_path(hidden, process))
    }
}

/// Windows paths ignore letter case.
fn same_path(left: &Path, right: &Path) -> bool {
    if cfg!(windows) {
        left.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
    } else {
        left == right
    }
}

/// Control characters dropped (a sniffed host is whatever the program sent),
/// cut to `limit` characters.
fn bounded(text: &str, limit: usize) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .take(limit)
        .collect()
}

pub(super) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosetun_config::ConnectionNetwork;
    use rosetun_ipc::{Frame, MAX_FRAME_BYTES, Response, read_frame, write_frame};

    fn engine(id: &str, start: u64) -> EngineConnection {
        EngineConnection {
            id: id.to_owned(),
            start_unix_ms: start,
            process: Some(r"C:\Program Files\Example\app.exe".to_owned()),
            host: "example.com".to_owned(),
            port: 443,
            network: ConnectionNetwork::Tcp,
            route: EngineRoute::Proxy,
            upload: 1,
            download: 2,
        }
    }

    fn entries(ids: &[(&str, u64)]) -> Vec<(String, LiveConnection)> {
        Translation::default().translate(ids.iter().map(|(id, start)| engine(id, *start)).collect())
    }

    #[test]
    fn closed_connections_are_found_by_id_and_kept_newest_first() {
        let mut book = ConnectionBook::default();
        book.record(entries(&[("a", 1), ("b", 2), ("c", 3)]), 10);
        book.record(entries(&[("b", 2)]), 20);
        book.record(entries(&[]), 30);

        let (active, closed) = book.snapshot();
        assert!(active.is_empty());
        let closed: Vec<_> = closed
            .iter()
            .map(|connection| (connection.start_unix_ms, connection.end_unix_ms))
            .collect();
        assert_eq!(closed, [(2, Some(30)), (3, Some(20)), (1, Some(20))]);
    }

    #[test]
    fn a_closed_connection_keeps_the_engine_id() {
        let mut book = ConnectionBook::default();
        book.record(entries(&[("0d5c1f2e-7a3b-4c9d-8e1f-2a3b4c5d6e7f", 1)]), 10);
        let (active, _) = book.snapshot();
        assert_eq!(active[0].id, "0d5c1f2e-7a3b-4c9d-8e1f-2a3b4c5d6e7f");

        book.record(entries(&[]), 20);
        let (_, closed) = book.snapshot();
        assert_eq!(closed[0].id, "0d5c1f2e-7a3b-4c9d-8e1f-2a3b4c5d6e7f");
    }

    #[test]
    fn an_id_too_long_to_close_is_not_passed_on() {
        let long = "i".repeat(MAX_CONNECTION_ID_CHARS + 1);
        let translated = entries(&[(&long, 1), (&long[1..], 2)]);
        assert_eq!(translated[0].0, long, "the book still tells it apart");
        assert_eq!(translated[0].1.id, "");
        assert_eq!(translated[1].1.id, long[1..]);
    }

    #[test]
    fn the_closed_ring_and_the_active_list_are_bounded() {
        let mut book = ConnectionBook::default();
        let many: Vec<_> = (0..MAX_ACTIVE_CONNECTIONS as u64 + 100)
            .map(|start| (start.to_string(), start))
            .collect();
        let many: Vec<_> = many
            .iter()
            .map(|(id, start)| (id.as_str(), *start))
            .collect();
        book.record(entries(&many), 1_000);

        let (active, _) = book.snapshot();
        assert_eq!(active.len(), MAX_ACTIVE_CONNECTIONS);
        assert_eq!(active[0].start_unix_ms, MAX_ACTIVE_CONNECTIONS as u64 + 99);

        book.record(entries(&[]), 2_000);
        let (active, closed) = book.snapshot();
        assert!(active.is_empty());
        assert_eq!(closed.len(), MAX_CLOSED_CONNECTIONS);
        assert_eq!(closed[0].start_unix_ms, MAX_ACTIVE_CONNECTIONS as u64 + 99);
    }

    #[test]
    fn the_watch_ends_without_requests() {
        let mut book = ConnectionBook::default();
        let start = Instant::now();
        assert!(!book.watched(start));

        book.watch(start);
        assert!(book.watched(start + WATCH_WINDOW - Duration::from_millis(1)));
        assert!(!book.watched(start + WATCH_WINDOW));

        book.record(entries(&[("a", 1)]), 2);
        book.forget();
        assert!(book.is_empty());
        assert!(book.watched(start));
        book.clear();
        assert!(!book.watched(start));
    }

    #[test]
    fn routes_name_the_exit_and_service_programs_are_hidden() {
        let translation = Translation {
            exit_tags: vec![
                (ExitId::new("no-address"), None),
                (ExitId::new("work"), Some("exit-0".to_owned())),
                (ExitId::new("e".repeat(65)), Some("exit-1".to_owned())),
            ],
            hidden: vec![PathBuf::from(
                r"C:\Program Files\Rosetun\rosetun-helper-privileged.exe",
            )],
        };
        let mut service = engine("service", 1);
        service.process =
            Some(r"c:\program files\rosetun\ROSETUN-HELPER-PRIVILEGED.EXE".to_owned());
        let routed = |route| EngineConnection {
            route,
            ..engine("x", 1)
        };
        let routes: Vec<_> = translation
            .translate(vec![
                service,
                routed(EngineRoute::Direct),
                routed(EngineRoute::Exit("exit-0".to_owned())),
                routed(EngineRoute::Exit("exit-1".to_owned())),
                routed(EngineRoute::Other),
            ])
            .into_iter()
            .map(|(_, connection)| connection.route)
            .collect();

        let mut expected = vec![
            ConnectionRoute::Direct,
            ConnectionRoute::Exit(ExitId::new("work")),
            ConnectionRoute::Other,
            ConnectionRoute::Other,
        ];
        if !cfg!(windows) {
            expected.insert(0, ConnectionRoute::Proxy);
        }
        assert_eq!(routes, expected);
    }

    #[test]
    fn hosts_and_programs_are_bounded_and_the_frame_fits() {
        // Four-byte characters and escaped quotes are the worst case for JSON size.
        let mut connection = engine("a", 1);
        connection.host = format!("\u{1}{}", "\u{10348}\"".repeat(400));
        connection.process = Some("\\\u{10348}".repeat(400));
        let translated = Translation::default().translate(vec![connection]);
        let entry = &translated[0].1;
        assert_eq!(entry.host.chars().count(), MAX_CONNECTION_HOST_CHARS);
        assert!(!entry.host.starts_with('\u{1}'));
        assert_eq!(
            entry.process.as_ref().unwrap().chars().count(),
            MAX_CONNECTION_PROCESS_CHARS
        );

        let mut largest = entry.clone();
        largest.id = "\u{10348}".repeat(MAX_CONNECTION_ID_CHARS);
        largest.route = ConnectionRoute::Exit(ExitId::new("e".repeat(MAX_EXIT_ID_BYTES)));
        largest.start_unix_ms = u64::MAX;
        largest.end_unix_ms = Some(u64::MAX);
        largest.download = u64::MAX;
        largest.upload = u64::MAX;
        let frame = Frame::Response {
            id: u64::MAX,
            body: Response::Connections {
                active: vec![largest.clone(); MAX_ACTIVE_CONNECTIONS],
                closed: vec![largest; MAX_CLOSED_CONNECTIONS],
            },
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).expect("frame serializes");
        assert!(
            (bytes.len() as u64) < MAX_FRAME_BYTES,
            "{} bytes",
            bytes.len()
        );
        let read = read_frame(&mut bytes.as_slice()).expect("frame reads back");
        assert_eq!(read, Some(frame));
    }
}
