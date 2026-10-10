#![allow(unreachable_pub)]

#[cfg(windows)]
mod data_dir;
#[cfg(windows)]
mod install_dir;
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

const USAGE: &str = "usage: rosetun-helper-privileged [--service | --install-service | --uninstall-service | --verify-install-dir <path> | --secure-install-dir <path> | --finalize-install-dir <path>]";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    Console,
    Service,
    InstallService,
    UninstallService,
    VerifyInstallDir(std::path::PathBuf),
    SecureInstallDir(std::path::PathBuf),
    FinalizeInstallDir(std::path::PathBuf),
}

fn parse_mode(args: impl IntoIterator<Item = OsString>) -> Result<Mode, String> {
    let args: Vec<_> = args.into_iter().collect();
    match args.as_slice() {
        [] => Ok(Mode::Console),
        [arg] if arg == "--service" => Ok(Mode::Service),
        [arg] if arg == "--install-service" => Ok(Mode::InstallService),
        [arg] if arg == "--uninstall-service" => Ok(Mode::UninstallService),
        [arg, path] if arg == "--verify-install-dir" => Ok(Mode::VerifyInstallDir(path.into())),
        [arg, path] if arg == "--secure-install-dir" => Ok(Mode::SecureInstallDir(path.into())),
        [arg, path] if arg == "--finalize-install-dir" => Ok(Mode::FinalizeInstallDir(path.into())),
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
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("non-string panic payload");
        let location = info
            .location()
            .map(|location| format!("{}:{}", location.file(), location.line()))
            .unwrap_or_else(|| "unknown".to_owned());
        tracing::error!(%location, message, "helper panicked");
        default_hook(info);
    }));

    let mode = match parse_mode(std::env::args_os().skip(1)) {
        Ok(mode) => mode,
        Err(message) => {
            eprintln!("{message}");
            return std::process::ExitCode::from(2);
        }
    };

    #[cfg(not(windows))]
    if mode != Mode::Console {
        eprintln!("service and install-directory commands are Windows only");
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
        #[cfg(windows)]
        Mode::VerifyInstallDir(path) => {
            install_command(&path, "safe", install_dir::verify(&path, true))
        }
        #[cfg(windows)]
        Mode::SecureInstallDir(path) => {
            install_command(&path, "secured", install_dir::secure(&path))
        }
        #[cfg(windows)]
        Mode::FinalizeInstallDir(path) => {
            install_command(&path, "finalized", install_dir::finalize(&path))
        }
        #[cfg(not(windows))]
        _ => unreachable!("non-Windows modes were rejected above"),
    }
}

#[cfg(windows)]
fn install_failure_output(error: &install_dir::Failure) -> String {
    format!(
        "path={}\n{}",
        install_dir::one_line(&error.path.to_string_lossy()),
        error.message()
    )
}

#[cfg(windows)]
fn install_command(
    path: &Path,
    action: &str,
    result: Result<(), install_dir::Failure>,
) -> std::process::ExitCode {
    match result {
        Ok(()) => {
            println!(
                "install directory {action}: {}",
                install_dir::one_line(&path.to_string_lossy())
            );
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            println!("{}", install_failure_output(&error));
            std::process::ExitCode::from(error.reason as u8)
        }
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
    let install_dir = std::env::current_exe().and_then(|exe| {
        let parent = exe
            .parent()
            .ok_or_else(|| std::io::Error::other("service executable has no parent"))?;
        // Windows can return the executable's trusted path in verbatim form.
        // Installer-supplied verbatim paths remain invalid at the CLI boundary.
        Ok(parent
            .to_str()
            .and_then(|path| path.strip_prefix(r"\\?\"))
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| parent.to_owned()))
    });
    match install_dir {
        Ok(dir) => {
            if let Err(error) = install_dir::verify(&dir, false) {
                tracing::warn!(reason = error.reason as u8, "{}", error.message());
            }
        }
        Err(error) => tracing::warn!(%error, "cannot inspect service install directory"),
    }
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

    #[cfg(windows)]
    #[test]
    fn install_failure_has_one_escaped_path_line() {
        let error = install_dir::verify(Path::new("D:\\Example\\Ro\nsetun"), true).unwrap_err();
        let output = install_failure_output(&error);
        assert_eq!(output.lines().count(), 2);
        assert_eq!(
            output
                .lines()
                .filter(|line| line.starts_with("path="))
                .count(),
            1
        );
        assert_eq!(output.lines().next(), Some(r"path=D:\Example\Ro\nsetun"));
    }

    #[test]
    fn modes_accept_only_one_known_flag() {
        let mode = |args: &[&str]| parse_mode(args.iter().map(OsString::from));
        assert_eq!(mode(&[]), Ok(Mode::Console));
        assert_eq!(mode(&["--service"]), Ok(Mode::Service));
        assert_eq!(mode(&["--install-service"]), Ok(Mode::InstallService));
        assert_eq!(mode(&["--uninstall-service"]), Ok(Mode::UninstallService));
        assert_eq!(
            mode(&["--verify-install-dir", r"D:\Example\Rosetun"]),
            Ok(Mode::VerifyInstallDir(r"D:\Example\Rosetun".into()))
        );
        assert_eq!(
            mode(&["--secure-install-dir", r"D:\Example\Rosetun"]),
            Ok(Mode::SecureInstallDir(r"D:\Example\Rosetun".into()))
        );
        assert_eq!(
            mode(&["--finalize-install-dir", r"D:\Example\Rosetun"]),
            Ok(Mode::FinalizeInstallDir(r"D:\Example\Rosetun".into()))
        );
        assert_eq!(mode(&["--verify-install-dir"]), Err(USAGE.to_owned()));
        assert_eq!(mode(&["--unknown"]), Err(USAGE.to_owned()));
        assert_eq!(
            mode(&["--service", "--install-service"]),
            Err(USAGE.to_owned())
        );
    }
}
