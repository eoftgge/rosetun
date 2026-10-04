#![allow(unreachable_pub)]

mod client;
mod store;

use std::path::Path;
use std::process::ExitCode;

use client::HelperClient;
use rosetun_config::{NodeId, Selection, SubscriptionId};
use rosetun_ipc::ConnectRequest;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Status,
    Connect {
        request_path: Option<String>,
    },
    Select {
        subscription_id: String,
        node_id: String,
    },
    Config,
    Disconnect,
    Shutdown,
}

fn main() -> ExitCode {
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
            return ExitCode::FAILURE;
        }
    };

    match &command {
        Command::Select {
            subscription_id,
            node_id,
        } => return local_result(select_node(subscription_id, node_id)),
        Command::Config => return local_result(print_config()),
        _ => {}
    }

    let request = match &command {
        Command::Connect { request_path } => {
            match prepare_connect_request(request_path.as_deref()) {
                Ok(request) => Some(request),
                Err(message) => {
                    eprintln!("{message}");
                    return ExitCode::FAILURE;
                }
            }
        }
        _ => None,
    };

    let endpoint = rosetun_ipc::default_endpoint();
    let mut client = match HelperClient::connect(&endpoint) {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(endpoint = %endpoint.display(), %error, "helper unavailable");
            return ExitCode::FAILURE;
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
                ExitCode::SUCCESS
            }
            Err(error) => {
                tracing::error!(%error, "failed to get status");
                ExitCode::FAILURE
            }
        },
        Command::Connect { .. } => {
            let Some(request) = request else {
                eprintln!("connect request was not prepared");
                return ExitCode::FAILURE;
            };

            match client.connect_tunnel(request) {
                Ok(()) => {
                    println!("tunnel connection started");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    tracing::error!(%error, "failed to connect tunnel");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Disconnect => match client.disconnect_tunnel() {
            Ok(()) => {
                println!("tunnel disconnected");
                ExitCode::SUCCESS
            }
            Err(error) => {
                tracing::error!(%error, "failed to disconnect tunnel");
                ExitCode::FAILURE
            }
        },
        Command::Shutdown => match client.shutdown() {
            Ok(()) => {
                println!("helper shut down");
                ExitCode::SUCCESS
            }
            Err(error) => {
                tracing::error!(%error, "failed to shut down helper");
                ExitCode::FAILURE
            }
        },
        Command::Select { .. } | Command::Config => {
            eprintln!("local command was not handled");
            ExitCode::FAILURE
        }
    }
}

fn local_result(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn prepare_connect_request(request_path: Option<&str>) -> Result<ConnectRequest, String> {
    if let Some(path) = request_path {
        return read_connect_request(Path::new(path));
    }

    let path = store::config_path().map_err(|error| error.to_string())?;
    let config = store::load(&path).map_err(|error| error.to_string())?;
    store::connect_request(&config)
}

fn select_node(subscription_id: &str, node_id: &str) -> Result<(), String> {
    let path = store::config_path().map_err(|error| error.to_string())?;
    let mut config = store::load(&path).map_err(|error| error.to_string())?;

    let subscription_id = SubscriptionId::new(subscription_id);
    let node_id = NodeId::new(node_id);
    let subscription = config
        .subscriptions
        .iter()
        .find(|subscription| subscription.id == subscription_id)
        .ok_or_else(|| format!("subscription {subscription_id} does not exist"))?;
    let node_name = subscription
        .node(&node_id)
        .ok_or_else(|| format!("node {node_id} is not in subscription {subscription_id}"))?
        .name
        .clone();

    config.active = Some(Selection {
        subscription: subscription_id,
        node: node_id,
    });

    store::save(&path, &config).map_err(|error| error.to_string())?;
    println!("selected node: {node_name}");

    Ok(())
}

fn print_config() -> Result<(), String> {
    let path = store::config_path().map_err(|error| error.to_string())?;
    println!("configuration path: {}", path.display());

    match std::fs::metadata(&path) {
        Ok(_) => println!("file exists: yes"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("file exists: no");
        }
        Err(error) => {
            println!("file exists: unknown");
            return Err(format!("could not inspect {}: {error}", path.display()));
        }
    }

    let config = match store::load(&path) {
        Ok(config) => config,
        Err(error) => {
            println!("validation: failed");
            println!("active node: unavailable");
            println!("active rule set: unavailable");

            let reason = match error {
                store::StoreError::Parse { .. } => "invalid JSON",
                store::StoreError::Invalid { .. } => "invalid configuration",
                store::StoreError::Io { .. } => "could not read configuration",
                store::StoreError::NoConfigDir => "configuration directory unavailable",
            };

            // Parser diagnostics can contain input values, including credentials.
            return Err(format!("{reason} in {}", path.display()));
        }
    };

    println!("validation: passed");

    match config.active_node() {
        Some((subscription, node)) => {
            println!("active subscription: {}", subscription.id);
            println!("active node id: {}", node.id);
            println!("active node name: {}", node.name);
        }
        None => println!("active node: none"),
    }

    match config.active_rules() {
        Some(rule_set) => {
            println!("active rule set id: {}", rule_set.id);
            println!("active rule set name: {}", rule_set.name);
        }
        None => println!("active rule set: none (connect uses Default, proxy)"),
    }

    Ok(())
}

fn parse_command() -> Result<Command, String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    parse_command_arguments(&arguments)
}

fn parse_command_arguments(arguments: &[String]) -> Result<Command, String> {
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();

    match arguments.as_slice() {
        [] | ["status"] => Ok(Command::Status),
        ["connect"] => Ok(Command::Connect { request_path: None }),
        ["connect", path] => Ok(Command::Connect {
            request_path: Some((*path).to_owned()),
        }),
        ["select", subscription_id, node_id] => Ok(Command::Select {
            subscription_id: (*subscription_id).to_owned(),
            node_id: (*node_id).to_owned(),
        }),
        ["config"] => Ok(Command::Config),
        ["disconnect"] => Ok(Command::Disconnect),
        ["shutdown"] => Ok(Command::Shutdown),
        ["connect", ..] => Err("connect accepts zero or one request JSON path".to_owned()),
        ["select", ..] => Err("select requires exactly a subscription ID and a node ID".to_owned()),
        ["config", ..] => Err("config does not accept arguments".to_owned()),
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
        "Usage:\n  rosetun [status]\n  rosetun connect [request.json]\n  rosetun select <subscription-id> <node-id>\n  rosetun config\n  rosetun disconnect\n  rosetun shutdown"
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
            parse(&["connect"]),
            Ok(Command::Connect { request_path: None })
        );
        assert_eq!(
            parse(&["connect", "request.json"]),
            Ok(Command::Connect {
                request_path: Some("request.json".to_owned()),
            })
        );
        assert_eq!(
            parse(&["select", "subscription", "node"]),
            Ok(Command::Select {
                subscription_id: "subscription".to_owned(),
                node_id: "node".to_owned(),
            })
        );
        assert_eq!(parse(&["config"]), Ok(Command::Config));
        assert_eq!(parse(&["disconnect"]), Ok(Command::Disconnect));
        assert_eq!(parse(&["shutdown"]), Ok(Command::Shutdown));
    }

    #[test]
    fn connect_rejects_more_than_one_path() {
        for arguments in [
            vec!["connect", "a", "b"],
            vec!["connect", "request.json", "extra", "another"],
        ] {
            assert_eq!(
                parse(&arguments),
                Err("connect accepts zero or one request JSON path".to_owned())
            );
        }
    }

    #[test]
    fn select_requires_exactly_two_arguments() {
        for arguments in [
            vec!["select"],
            vec!["select", "subscription"],
            vec!["select", "subscription", "node", "extra"],
        ] {
            assert_eq!(
                parse(&arguments),
                Err("select requires exactly a subscription ID and a node ID".to_owned())
            );
        }
    }

    #[test]
    fn commands_without_parameters_reject_extra_arguments() {
        for command in ["status", "config", "disconnect", "shutdown"] {
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
