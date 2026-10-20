//! `rosetun connections`: the running session's connections, for the account
//! that connected it. The list is a browsing history: it is printed, never logged.

use std::process::ExitCode;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rosetun_config::{ConnectionNetwork, ConnectionRoute, ConnectionState, LiveConnection};
use rosetun_core::terminal_text;
use rosetun_ipc::{ClientError, ErrorCode, HelperClient};

/// The service collects the list only after it was asked for it, and polls the
/// engine once a second.
const FIRST_POLL: Duration = Duration::from_millis(1500);

pub(crate) fn run(client: &mut HelperClient) -> ExitCode {
    match client.status() {
        Ok(status)
            if matches!(
                status.state,
                ConnectionState::Connected | ConnectionState::Reconnecting
            ) => {}
        Ok(_) => {
            eprintln!("not connected; connect to see the tunnel's connections");
            return ExitCode::FAILURE;
        }
        Err(error) => return report(&error),
    }
    let result = client.connections().and_then(|_| {
        thread::sleep(FIRST_POLL);
        client.connections()
    });
    match result {
        Ok((active, closed)) => {
            let now = now_unix_ms();
            println!("active: {}, closed: {}", active.len(), closed.len());
            println!("STATE\tNET\tROUTE\tDOWN\tUP\tSECONDS\tDESTINATION\tPROGRAM");
            for connection in &active {
                println!("{}", line("active", connection, now));
            }
            for connection in &closed {
                println!("{}", line("closed", connection, now));
            }
            ExitCode::SUCCESS
        }
        Err(error) => report(&error),
    }
}

fn report(error: &ClientError) -> ExitCode {
    match error {
        ClientError::Helper(helper) if helper.code == ErrorCode::AccessDenied => eprintln!(
            "the tunnel is connected from another Windows account; only that account can read its connections"
        ),
        ClientError::Helper(helper) if helper.code == ErrorCode::Busy => {
            eprintln!("the service is busy; try again in a moment");
        }
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
    format!(
        "{state}\t{network}\t{route}\t{}\t{}\t{seconds}\t{}:{}\t{}",
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
    use super::line;
    use rosetun_config::{ConnectionNetwork, ConnectionRoute, ExitId, LiveConnection};

    #[test]
    fn a_line_has_every_column_and_no_control_characters() {
        let connection = LiveConnection {
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
            columns[..6],
            ["closed", "udp", "exit:work", "7", "5", "5"]
        );
        assert!(columns[6].starts_with("example.com"));
        assert!(columns[6].ends_with(":443"));
        assert_eq!(columns[7], "C:\\Program Files\\Example\\app.exe");

        let active = LiveConnection {
            end_unix_ms: None,
            process: None,
            route: ConnectionRoute::Direct,
            ..connection
        };
        let columns: Vec<_> = line("active", &active, 11_000).split('\t').map(str::to_owned).collect();
        assert_eq!(columns[2], "direct");
        assert_eq!(columns[5], "10");
        assert_eq!(columns[7], "-");
    }
}
