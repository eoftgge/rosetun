#![allow(unreachable_pub)]

mod client;

use client::HelperClient;

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("ROSETUN_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let endpoint = rosetun_ipc::default_endpoint();
    let mut client = match HelperClient::connect(&endpoint) {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(endpoint = %endpoint.display(), %error, "helper unavailable");
            return std::process::ExitCode::FAILURE;
        }
    };

    tracing::info!(helper = client.helper_version(), "connection established");

    match client.status() {
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
            tracing::error!(%error, "failed to get state");
            std::process::ExitCode::FAILURE
        }
    }
}