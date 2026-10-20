//! `rosetun connections`: the running session's connections, for the account
//! that connected it. The list is a browsing history: it is printed, never logged.

use std::process::ExitCode;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rosetun_config::{ConnectionNetwork, ConnectionRoute, ConnectionState, LiveConnection};
use rosetun_core::terminal_text;
use rosetun_ipc::{ClientError, ErrorCode, HelperClient};

/// The service collects the list only after it was asked for it; its next
/// poll of the engine follows within a quarter of a second.
const FIRST_POLL: Duration = Duration::from_millis(1500);

/// Characters of the id shown in the table; `close` accepts them when they
/// name one active connection.
const SHORT_ID_CHARS: usize = 8;

pub(crate) fn run(client: &mut HelperClient) -> ExitCode {
    if let Err(code) = require_connected(client, "see") {
        return code;
    }
    match read(client) {
        Ok((active, closed)) => {
            let now = now_unix_ms();
            println!("active: {}, closed: {}", active.len(), closed.len());
            println!("STATE\tID\tNET\tROUTE\tDOWN\tUP\tSECONDS\tDESTINATION\tPROGRAM");
            for connection in &active {
                println!("{}", line("active", connection, now));
            }
            for connection in &closed {
                println!("{}", line("closed", connection, now));
            }
            ExitCode::SUCCESS
        }
        Err(error) => report(&error, "read"),
    }
}

/// `rosetun connections close <id>`: a full id goes to the service as typed,
/// a shown short id is first matched against the active connections.
pub(crate) fn close(client: &mut HelperClient, id: &str) -> ExitCode {
    if id.is_empty() {
        eprintln!("the connection ID is empty");
        return ExitCode::FAILURE;
    }
    if let Err(code) = require_connected(client, "close") {
        return code;
    }
    let full = if id.chars().count() > SHORT_ID_CHARS {
        id.to_owned()
    } else {
        let active = match read(client) {
            Ok((active, _)) => active,
            Err(error) => return report(&error, "close"),
        };
        match matching(&active, id).as_slice() {
            [one] => (*one).to_owned(),
            [] => {
                eprintln!("no active connection has the ID {}", terminal_text(id));
                return ExitCode::FAILURE;
            }
            several => {
                eprintln!("the ID {} is ambiguous; use one of:", terminal_text(id));
                for full in several {
                    eprintln!("  {}", terminal_text(full));
                }
                return ExitCode::FAILURE;
            }
        }
    };
    match client.close_connection(&full) {
        Ok(()) => {
            println!("closed");
            ExitCode::SUCCESS
        }
        Err(error) => report(&error, "close"),
    }
}

fn require_connected(client: &mut HelperClient, verb: &str) -> Result<(), ExitCode> {
    match client.status() {
        Ok(status)
            if matches!(
                status.state,
                ConnectionState::Connected | ConnectionState::Reconnecting
            ) =>
        {
            Ok(())
        }
        Ok(_) => {
            eprintln!("not connected; connect to {verb} the tunnel's connections");
            Err(ExitCode::FAILURE)
        }
        Err(error) => Err(report(&error, verb)),
    }
}

fn read(
    client: &mut HelperClient,
) -> Result<(Vec<LiveConnection>, Vec<LiveConnection>), ClientError> {
    client.connections().and_then(|_| {
        thread::sleep(FIRST_POLL);
        client.connections()
    })
}

/// Full ids of active connections that `id` names: exactly, or else as the
/// start of each.
fn matching<'a>(active: &'a [LiveConnection], id: &str) -> Vec<&'a str> {
    let ids = active
        .iter()
        .map(|connection| connection.id.as_str())
        .filter(|full| !full.is_empty());
    if let Some(exact) = ids.clone().find(|full| *full == id) {
        return vec![exact];
    }
    let mut found: Vec<_> = ids.filter(|full| full.starts_with(id)).collect();
    found.sort_unstable();
    found.dedup();
    found
}

fn report(error: &ClientError, verb: &str) -> ExitCode {
    match error {
        ClientError::Helper(helper) if helper.code == ErrorCode::AccessDenied => eprintln!(
            "the tunnel is connected from another Windows account; only that account can {verb} its connections"
        ),
        ClientError::Helper(helper) if helper.code == ErrorCode::Busy => {
            eprintln!("the service is busy; try again in a moment");
        }
        _ if verb == "close" => tracing::error!(%error, "failed to close the connection"),
        _ => tracing::error!(%error, "failed to get connections"),
    }
    ExitCode::FAILURE
}

fn line(state: &str, connection: &LiveConnection, now_unix_ms: u64) -> String {
    let network = match connection.network {
        ConnectionNetwork::Tcp => "tcp",
        ConnectionNetwork::Udp => "udp",
    };
    let route = match &connection.route {
        ConnectionRoute::Proxy => "proxy".to_owned(),
        ConnectionRoute::Direct => "direct".to_owned(),
        ConnectionRoute::Exit(exit) => format!("exit:{}", terminal_text(exit.as_str())),
        ConnectionRoute::Other => "other".to_owned(),
    };
    let end = connection.end_unix_ms.unwrap_or(now_unix_ms);
    let seconds = end.saturating_sub(connection.start_unix_ms) / 1000;
    let program = connection.process.as_deref().unwrap_or("-");
    let id: String = connection.id.chars().take(SHORT_ID_CHARS).collect();
    let id = if id.is_empty() {
        "-".to_owned()
    } else {
        terminal_text(&id).replace('\t', " ")
    };
    format!(
        "{state}\t{id}\t{network}\t{route}\t{}\t{}\t{seconds}\t{}:{}\t{}",
        connection.download,
        connection.upload,
        terminal_text(&connection.host).replace('\t', " "),
        connection.port,
        terminal_text(program).replace('\t', " "),
    )
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::{line, matching};
    use rosetun_config::{ConnectionNetwork, ConnectionRoute, ExitId, LiveConnection};

    #[test]
    fn a_line_has_every_column_and_no_control_characters() {
        let connection = LiveConnection {
            id: "0d5c1f2e-7a3b-4c9d-8e1f-2a3b4c5d6e7f".to_owned(),
            start_unix_ms: 1_000,
            end_unix_ms: Some(6_500),
            process: Some("C:\\Program Files\\Example\\app.exe".to_owned()),
            host: "example.com\u{1b}[2J".to_owned(),
            port: 443,
            network: ConnectionNetwork::Udp,
            route: ConnectionRoute::Exit(ExitId::new("work")),
            download: 7,
            upload: 5,
        };

        let text = line("closed", &connection, 99_000);
        assert!(!text.contains('\u{1b}'));
        let columns: Vec<_> = text.split('\t').collect();
        assert_eq!(
            columns[..7],
            ["closed", "0d5c1f2e", "udp", "exit:work", "7", "5", "5"]
        );
        assert!(columns[7].starts_with("example.com"));
        assert!(columns[7].ends_with(":443"));
        assert_eq!(columns[8], "C:\\Program Files\\Example\\app.exe");

        let active = LiveConnection {
            id: String::new(),
            end_unix_ms: None,
            process: None,
            route: ConnectionRoute::Direct,
            ..connection
        };
        let columns: Vec<_> = line("active", &active, 11_000)
            .split('\t')
            .map(str::to_owned)
            .collect();
        assert_eq!(columns[1], "-");
        assert_eq!(columns[3], "direct");
        assert_eq!(columns[6], "10");
        assert_eq!(columns[8], "-");
    }

    #[test]
    fn a_short_id_closes_only_when_it_names_one_connection() {
        let with_id = |id: &str| LiveConnection {
            id: id.to_owned(),
            start_unix_ms: 1,
            end_unix_ms: None,
            process: None,
            host: "example.com".to_owned(),
            port: 443,
            network: ConnectionNetwork::Tcp,
            route: ConnectionRoute::Proxy,
            download: 0,
            upload: 0,
        };
        let active = [
            with_id("0d5c1f2e-7a3b-4c9d-8e1f-2a3b4c5d6e7f"),
            with_id("0d5c1f2e-0000-4c9d-8e1f-2a3b4c5d6e7f"),
            with_id("9b1e4d2a-7a3b-4c9d-8e1f-2a3b4c5d6e7f"),
            with_id("short"),
            with_id("shorter"),
            with_id(""),
        ];
        assert_eq!(
            matching(&active, "9b1e4d2a"),
            ["9b1e4d2a-7a3b-4c9d-8e1f-2a3b4c5d6e7f"]
        );
        assert_eq!(matching(&active, "0d5c1f2e").len(), 2);
        assert_eq!(matching(&active, "short"), ["short"]);
        assert!(matching(&active, "ffffffff").is_empty());
    }
}
