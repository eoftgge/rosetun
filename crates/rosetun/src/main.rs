#![allow(unreachable_pub)]

mod client;

use std::path::Path;

use client::HelperClient;
use rosetun_ipc::ConnectRequest;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Status,
    Connect { request_path: String },
    Disconnect,
    Shutdown,
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("ROSETUN_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let command = match parse_command() {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{message}");
            print_usage();
            return std::process::ExitCode::FAILURE;
        }
    };

    let endpoint = rosetun_ipc::default_endpoint();
    let mut client = match HelperClient::connect(&endpoint) {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(endpoint = %endpoint.display(), %error, "helper unavailable");
            return std::process::ExitCode::FAILURE;
        }
    };

    tracing::info!(helper = client.helper_version(), "connection established");

    match command {
        Command::Status => match client.status() {
            Ok(status) => {
                println!("state: {:?}", status.state);
                println!("engine:      {:?}", status.engine);
                println!(
                    "traffic: up {} B/s down {} B/s",
                    status.traffic.up_bps, status.traffic.down_bps
                );
                std::process::ExitCode::SUCCESS
            }
            Err(error) => {
                tracing::error!(%error, "failed to get status");
                std::process::ExitCode::FAILURE
            }
        },
        Command::Connect { request_path } => {
            let request = match read_connect_request(Path::new(&request_path)) {
                Ok(request) => request,
                Err(message) => {
                    tracing::error!(path = %request_path, %message, "invalid connect request");
                    return std::process::ExitCode::FAILURE;
                }
            };

            match client.connect_tunnel(request) {
                Ok(()) => {
                    println!("tunnel connection started");
                    std::process::ExitCode::SUCCESS
                }
                Err(error) => {
                    tracing::error!(%error, "failed to connect tunnel");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Command::Disconnect => match client.disconnect_tunnel() {
            Ok(()) => {
                println!("tunnel disconnected");
                std::process::ExitCode::SUCCESS
            }
            Err(error) => {
                tracing::error!(%error, "failed to disconnect tunnel");
                std::process::ExitCode::FAILURE
            }
        },
        Command::Shutdown => match client.shutdown() {
            Ok(()) => {
                println!("helper shut down");
                std::process::ExitCode::SUCCESS
            }
            Err(error) => {
                tracing::error!(%error, "failed to shut down helper");
                std::process::ExitCode::FAILURE
            }
        },
    }
}

fn parse_command() -> Result<Command, String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    parse_command_arguments(&arguments)
}

fn parse_command_arguments(arguments: &[String]) -> Result<Command, String> {
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();

    match arguments.as_slice() {
        [] | ["status"] => Ok(Command::Status),
        ["connect", path] => Ok(Command::Connect {
            request_path: (*path).to_owned(),
        }),
        ["disconnect"] => Ok(Command::Disconnect),
        ["shutdown"] => Ok(Command::Shutdown),
        ["connect"] => Err("missing path to connect request JSON".to_owned()),
        ["connect", ..] => Err("connect accepts exactly one request JSON path".to_owned()),
        ["status", ..] => Err("status does not accept arguments".to_owned()),
        ["disconnect", ..] => Err("disconnect does not accept arguments".to_owned()),
        ["shutdown", ..] => Err("shutdown does not accept arguments".to_owned()),
        [command, ..] => Err(format!("unknown command: {command}")),
    }
}

fn read_connect_request(path: &Path) -> Result<ConnectRequest, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;

    serde_json::from_str(&contents)
        .map_err(|error| format!("could not parse {}: {error}", path.display()))
}

fn print_usage() {
    eprintln!(
        "Usage:\n  rosetun [status]\n  rosetun connect <request.json>\n  rosetun disconnect\n  rosetun shutdown"
    );
}

#[cfg(test)]
mod tests {
    use super::{Command, parse_command_arguments};

    fn parse(arguments: &[&str]) -> Result<Command, String> {
        let arguments: Vec<String> = arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect();
        parse_command_arguments(&arguments)
    }

    #[test]
    fn valid_commands_are_parsed() {
        assert_eq!(parse(&[]), Ok(Command::Status));
        assert_eq!(parse(&["status"]), Ok(Command::Status));
        assert_eq!(
            parse(&["connect", "request.json"]),
            Ok(Command::Connect {
                request_path: "request.json".to_owned(),
            })
        );
        assert_eq!(parse(&["disconnect"]), Ok(Command::Disconnect));
        assert_eq!(parse(&["shutdown"]), Ok(Command::Shutdown));
    }

    #[test]
    fn connect_requires_exactly_one_path() {
        assert_eq!(
            parse(&["connect"]),
            Err("missing path to connect request JSON".to_owned())
        );

        for arguments in [
            vec!["connect", "request.json", "extra"],
            vec!["connect", "request.json", "extra", "another"],
        ] {
            assert_eq!(
                parse(&arguments),
                Err("connect accepts exactly one request JSON path".to_owned())
            );
        }
    }

    #[test]
    fn commands_without_parameters_reject_extra_arguments() {
        for command in ["status", "disconnect", "shutdown"] {
            for arguments in [vec![command, "extra"], vec![command, "extra", "another"]] {
                assert_eq!(
                    parse(&arguments),
                    Err(format!("{command} does not accept arguments"))
                );
            }
        }
    }

    #[test]
    fn unknown_commands_are_rejected() {
        assert_eq!(
            parse(&["unknown"]),
            Err("unknown command: unknown".to_owned())
        );
        assert_eq!(
            parse(&["unknown", "extra"]),
            Err("unknown command: unknown".to_owned())
        );
    }
}
