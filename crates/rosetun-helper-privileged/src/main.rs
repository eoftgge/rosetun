#![allow(unreachable_pub)]

#[cfg(windows)]
mod data_dir;
#[cfg(windows)]
mod log_file;
mod log_gate;
#[cfg(windows)]
mod process_job;
mod server;
#[cfg(windows)]
mod service;
mod state;

use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;

use rosetun_engine::{EngineBackend, EngineRegistry};
use rosetun_engine_singbox::SingBoxBackend;
use rosetun_ipc::Listener;
use tracing_subscriber::prelude::*;

use crate::log_gate::VerboseGate;
use crate::server::{Helper, Server};

const USAGE: &str =
    "usage: rosetun-helper-privileged [--service | --install-service | --uninstall-service]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Console,
    Service,
    InstallService,
    UninstallService,
}

fn parse_mode(args: impl IntoIterator<Item = OsString>) -> Result<Mode, String> {
    let args: Vec<_> = args.into_iter().collect();
    match args.as_slice() {
        [] => Ok(Mode::Console),
        [arg] if arg == "--service" => Ok(Mode::Service),
        [arg] if arg == "--install-service" => Ok(Mode::InstallService),
        [arg] if arg == "--uninstall-service" => Ok(Mode::UninstallService),
        _ => Err(USAGE.to_owned()),
    }
}

fn log_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_env("ROSETUN_LOG").unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(format!(
            "info,{}=trace",
            rosetun_engine::ENGINE_OUTPUT_TARGET
        ))
    })
}

fn main() -> std::process::ExitCode {
    let mode = match parse_mode(std::env::args_os().skip(1)) {
        Ok(mode) => mode,
        Err(message) => {
            eprintln!("{message}");
            return std::process::ExitCode::from(2);
        }
    };

    #[cfg(not(windows))]
    if mode != Mode::Console {
        eprintln!("--service and its install flags are Windows only");
        return std::process::ExitCode::from(2);
    }

    match mode {
        Mode::Console => run_console(),
        #[cfg(windows)]
        Mode::Service => run_service(),
        #[cfg(windows)]
        Mode::InstallService => service_command(service::install()),
        #[cfg(windows)]
        Mode::UninstallService => service_command(service::uninstall()),
        #[cfg(not(windows))]
        _ => unreachable!("non-Windows modes were rejected above"),
    }
}

#[cfg(windows)]
fn service_command(result: std::io::Result<()>) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run_console() -> std::process::ExitCode {
    let gate = VerboseGate::default();
    let log_gate = gate.clone();
    tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .finish()
        .with(tracing_subscriber::filter::filter_fn(move |metadata| {
            log_gate.allows(metadata)
        }))
        .init();

    #[cfg(windows)]
    let run_dir = match data_dir::data_dir().and_then(|dir| {
        data_dir::secure(&dir)?;
        Ok(dir.join("run"))
    }) {
        Ok(dir) => dir,
        Err(error) => {
            tracing::error!(%error, "failed to secure helper data directory");
            return std::process::ExitCode::FAILURE;
        }
    };
    #[cfg(not(windows))]
    let run_dir = std::path::PathBuf::from("/run/rosetun");

    let (listener, helper) = match start(&run_dir, gate) {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, "failed to start helper");
            return std::process::ExitCode::FAILURE;
        }
    };
    if let Err(error) = Server::new(true).serve(listener, helper) {
        tracing::error!(%error, "helper stopped");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(windows)]
fn run_service() -> std::process::ExitCode {
    let result = data_dir::data_dir().and_then(|dir| {
        data_dir::secure(&dir)?;
        log_file::RotatingFile::open(&dir.join("logs"), log_file::LOG_LIMIT)
    });
    let file = match result {
        Ok(file) => file,
        Err(error) => {
            eprintln!("failed to initialize Rosetun service data and log: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let gate = VerboseGate::default();
    let log_gate = gate.clone();
    tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .with_writer(std::sync::Mutex::new(file))
        .with_ansi(false)
        .finish()
        .with(tracing_subscriber::filter::filter_fn(move |metadata| {
            log_gate.allows(metadata)
        }))
        .init();
    service::run(gate)
}

#[derive(Debug)]
struct StartError(String);

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn start(run_dir: &Path, gate: VerboseGate) -> Result<(Listener, Arc<Helper>), StartError> {
    #[cfg(windows)]
    process_job::install().map_err(|error| {
        StartError(format!(
            "failed to install helper process-lifetime job: {error}"
        ))
    })?;

    let mut engines = EngineRegistry::new();
    let singbox = SingBoxBackend::new(run_dir.join("sing-box"));
    let warmup = singbox.clone();
    std::thread::Builder::new()
        .name("engine-warmup".to_owned())
        .spawn(move || match warmup.locate_binary() {
            Ok(binary) => tracing::info!(binary = %binary.display(), "sing-box is ready"),
            Err(error) => tracing::warn!(%error, "sing-box check at start failed"),
        })
        .map_err(|error| StartError(format!("failed to start engine warmup thread: {error}")))?;
    engines.register(Box::new(singbox));

    let helper = Arc::new(Helper::new(engines, rosetun_routing::backend(), gate));
    state::spawn_supervisor(Arc::clone(&helper)).map_err(|error| {
        StartError(format!("failed to start engine supervisor thread: {error}"))
    })?;
    let endpoint = rosetun_ipc::default_endpoint();
    let listener = Listener::bind(&endpoint).map_err(|error| {
        StartError(format!(
            "failed to bind socket {}: {error}",
            endpoint.display()
        ))
    })?;
    Ok((listener, helper))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_accept_only_one_known_flag() {
        let mode = |args: &[&str]| parse_mode(args.iter().map(OsString::from));
        assert_eq!(mode(&[]), Ok(Mode::Console));
        assert_eq!(mode(&["--service"]), Ok(Mode::Service));
        assert_eq!(mode(&["--install-service"]), Ok(Mode::InstallService));
        assert_eq!(mode(&["--uninstall-service"]), Ok(Mode::UninstallService));
        assert_eq!(mode(&["--unknown"]), Err(USAGE.to_owned()));
        assert_eq!(
            mode(&["--service", "--install-service"]),
            Err(USAGE.to_owned())
        );
    }
}
