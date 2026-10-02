#![allow(unreachable_pub)]

#[cfg(windows)]
mod process_job;

mod server;
mod state;

use crate::server::Helper;
use std::sync::Arc;

use rosetun_engine::EngineRegistry;
use rosetun_engine_singbox::SingBoxBackend;
use rosetun_ipc::Listener;

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("ROSETUN_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    #[cfg(windows)]
    if let Err(error) = process_job::install() {
        tracing::error!(%error, "failed to install helper process-lifetime job");
        return std::process::ExitCode::FAILURE;
    }

    let work_dir = work_dir();
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(SingBoxBackend::new(work_dir.join("sing-box"))));

    let helper = Arc::new(Helper::new(engines, rosetun_routing::backend()));
    let endpoint = rosetun_ipc::default_endpoint();
    let listener = match Listener::bind(&endpoint) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(endpoint = %endpoint.display(), %error, "failed to bind socket");
            return std::process::ExitCode::FAILURE;
        }
    };

    if let Err(error) = server::serve(listener, helper) {
        tracing::error!(%error, "helper stopped");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

fn work_dir() -> std::path::PathBuf {
    if let Some(custom) = std::env::var_os("ROSETUN_WORK_DIR") {
        return std::path::PathBuf::from(custom);
    }
    #[cfg(unix)]
    {
        std::path::PathBuf::from("/run/rosetun")
    }
    #[cfg(windows)]
    {
        std::path::PathBuf::from(r"C:\ProgramData\Rosetun\run")
    }
}
