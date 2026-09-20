#![allow(unreachable_pub)]

mod client;

use std::path::Path;

use client::HelperClient;
use rosetun_ipc::ConnectRequest;

#[derive(Debug)]
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
    let mut arguments = std::env::args().skip(1);

    match arguments.next().as_deref() {
        None | Some("status") if arguments.next().is_none() => Ok(Command::Status),
        Some("connect") => {
            let request_path = arguments
                .next()
                .ok_or_else(|| "missing path to connect request JSON".to_owned())?;

            if arguments.next().is_some() {
                return Err("connect accepts exactly one request JSON path".to_owned());
            }

            Ok(Command::Connect { request_path })
        }
        Some("disconnect") if arguments.next().is_none() => Ok(Command::Disconnect),
        Some("shutdown") if arguments.next().is_none() => Ok(Command::Shutdown),
        Some(command) => Err(format!("unknown or invalid command: {command}")),
        command => Err(format!("unknown or invalid command: {command:?}")),
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
