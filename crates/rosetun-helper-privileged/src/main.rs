#![expect(
    unreachable_pub,
    reason = "a binary has no public API; `pub` only shares items between its modules"
)]

#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(windows)]
mod data_dir;
#[cfg(windows)]
mod engine_copy;
#[cfg(windows)]
mod install_dir;
mod list_store;
#[cfg(target_os = "linux")]
mod lockdown_linux;
#[cfg(windows)]
mod log_file;
mod log_gate;
#[cfg(windows)]
mod process_job;
#[cfg(target_os = "linux")]
mod restart_linux;
#[cfg(target_os = "linux")]
mod sd_notify;
mod server;
#[cfg(windows)]
mod service;
#[cfg(target_os = "linux")]
mod signals;
mod state;
#[cfg(windows)]
mod upgrade_hold;

use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rosetun_engine::{EngineBackend, EngineRegistry};
use rosetun_engine_singbox::SingBoxBackend;
use rosetun_engine_xray::XrayHelper;
use rosetun_ipc::Listener;
use tracing_subscriber::prelude::*;

use crate::log_gate::VerboseGate;
use crate::server::{Helper, Server};

#[cfg(target_os = "linux")]
use crate::restart_linux::UPGRADE_MARKER;
const USAGE: &str = "usage: rosetun-helper-privileged [--service | --install-service | --uninstall-service | --reset-firewall | --verify-install-dir <path> | --secure-install-dir <path> | --finalize-install-dir <path> | --hold-for-upgrade <path> | --restore-lockdown | --restart-for-upgrade]";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    Console,
    Service,
    InstallService,
    UninstallService,
    /// Removes Lockdown (administrator): exit codes in `service::reset_exit`.
    ResetFirewall,
    VerifyInstallDir(std::path::PathBuf),
    SecureInstallDir(std::path::PathBuf),
    FinalizeInstallDir(std::path::PathBuf),
    /// Holds the network closed for an upgrade (administrator): exit codes
    /// in `upgrade_hold::hold_exit`.
    HoldForUpgrade(std::path::PathBuf),
    /// Linux, at boot: Lockdown's set from its record, before any network.
    RestoreLockdown,
    RestartForUpgrade,
}

fn parse_mode(args: impl IntoIterator<Item = OsString>) -> Result<Mode, String> {
    let args: Vec<_> = args.into_iter().collect();
    match args.as_slice() {
        [] => Ok(Mode::Console),
        [arg] if arg == "--service" => Ok(Mode::Service),
        [arg] if arg == "--install-service" => Ok(Mode::InstallService),
        [arg] if arg == "--uninstall-service" => Ok(Mode::UninstallService),
        [arg] if arg == "--reset-firewall" => Ok(Mode::ResetFirewall),
        [arg] if arg == "--restart-for-upgrade" => Ok(Mode::RestartForUpgrade),
        [arg] if arg == "--restore-lockdown" => Ok(Mode::RestoreLockdown),
        [arg, path] if arg == "--verify-install-dir" => Ok(Mode::VerifyInstallDir(path.into())),
        [arg, path] if arg == "--secure-install-dir" => Ok(Mode::SecureInstallDir(path.into())),
        [arg, path] if arg == "--finalize-install-dir" => Ok(Mode::FinalizeInstallDir(path.into())),
        [arg, path] if arg == "--hold-for-upgrade" => Ok(Mode::HoldForUpgrade(path.into())),
        _ => Err(USAGE.to_owned()),
    }
}

/// The console helper, the systemd service and Lockdown's commands; the rest
/// manage the Windows service and install directory.
#[cfg(target_os = "linux")]
fn runs_on_linux(mode: &Mode) -> bool {
    matches!(
        mode,
        Mode::Console
            | Mode::Service
            | Mode::ResetFirewall
            | Mode::RestoreLockdown
            | Mode::RestartForUpgrade
    )
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
    // First, while the process has one thread: every thread started later
    // inherits the mask, so only the waiter takes SIGTERM, SIGINT or SIGHUP.
    #[cfg(target_os = "linux")]
    let signals = match signals::block() {
        Ok(signals) => signals,
        Err(error) => {
            eprintln!("cannot block termination signals: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("non-string panic payload");
        let location = info.location().map_or_else(
            || "unknown".to_owned(),
            |location| format!("{}:{}", location.file(), location.line()),
        );
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

    #[cfg(target_os = "linux")]
    if !runs_on_linux(&mode) {
        eprintln!(
            "this command is Windows only; on Linux run the helper without arguments, with --service, --reset-firewall --restore-lockdown or --restart-for-upgrade"
        );
        return std::process::ExitCode::from(2);
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    if mode != Mode::Console {
        eprintln!("service and install-directory commands are Windows only");
        return std::process::ExitCode::from(2);
    }

    match mode {
        #[cfg(target_os = "linux")]
        Mode::RestartForUpgrade => restart_linux::restart(),
        #[cfg(windows)]
        Mode::RestartForUpgrade => {
            eprintln!("--restart-for-upgrade is Linux only");
            std::process::ExitCode::from(2)
        }
        #[cfg(target_os = "linux")]
        Mode::Console => run_linux(signals, false),
        #[cfg(target_os = "linux")]
        Mode::Service => run_linux(signals, true),
        #[cfg(target_os = "linux")]
        Mode::ResetFirewall => lockdown_linux::reset_firewall(),
        #[cfg(target_os = "linux")]
        Mode::RestoreLockdown => {
            // To the journal through stderr; the routing crate's warnings too.
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .without_time()
                .init();
            lockdown_linux::restore_at_boot()
        }
        #[cfg(windows)]
        Mode::RestoreLockdown => {
            eprintln!("--restore-lockdown is Linux only");
            std::process::ExitCode::from(2)
        }
        #[cfg(not(target_os = "linux"))]
        Mode::Console => run_console(),
        #[cfg(windows)]
        Mode::Service => run_service(),
        #[cfg(windows)]
        Mode::InstallService => service_command(service::install()),
        #[cfg(windows)]
        Mode::UninstallService => service_command(service::uninstall()),
        #[cfg(windows)]
        Mode::ResetFirewall => {
            // Only Lockdown's own warnings, such as a failed flush, on stderr.
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
                .with_writer(std::io::stderr)
                .init();
            service::reset_firewall()
        }
        #[cfg(windows)]
        Mode::HoldForUpgrade(path) => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
                .with_writer(std::io::stderr)
                .init();
            upgrade_hold::hold_for_upgrade(&path)
        }
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
        _ => unreachable!("Windows-only modes were rejected above"),
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

/// Dynamic: `filter_fn` asks once per log statement and remembers the answer, so
/// an engine line first seen with the verbose log off would stay away after it
/// goes on, and one first seen with it on would stay after it goes off.
fn log_gate_layer<S: tracing::Subscriber>(
    gate: &VerboseGate,
) -> impl tracing_subscriber::Layer<S> + use<S> {
    let gate = gate.clone();
    tracing_subscriber::filter::dynamic_filter_fn(move |metadata, _| {
        gate.allows(metadata) && !rosetun_config::is_sensitive_log_target(metadata.target())
    })
}

fn init_console_log(gate: &VerboseGate) {
    tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .finish()
        .with(log_gate_layer(gate))
        .init();
}

#[cfg(not(target_os = "linux"))]
fn run_console() -> std::process::ExitCode {
    let gate = VerboseGate::default();
    init_console_log(&gate);

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

    let (listener, helper) = match start(&run_dir, gate, rosetun_routing::backend()) {
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

/// The console helper and the systemd service on Linux. Both stop on
/// SIGTERM, SIGINT or SIGHUP through the same path as an IPC shutdown;
/// only the console honours that request (as on Windows). The service logs
/// to stderr for journald, which adds its own timestamps, and tells systemd
/// when it is ready and when it starts stopping.
#[cfg(target_os = "linux")]
fn run_linux(signals: signals::Blocked, service: bool) -> std::process::ExitCode {
    let gate = VerboseGate::default();
    if service {
        tracing_subscriber::fmt()
            .with_env_filter(log_filter())
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .without_time()
            .finish()
            .with(log_gate_layer(&gate))
            .init();
    } else {
        init_console_log(&gate);
    }

    let notifier = if service {
        match sd_notify::Notifier::from_env().transpose() {
            Ok(notifier) => notifier.map(Arc::new),
            Err(error) => {
                tracing::error!(%error, "cannot reach systemd");
                return std::process::ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    rosetun_engine::process::run_engines_as(engine_identity(
        rosetun_engine::process::engine_account(),
        service,
    ));
    // Before anything else starts: the helper moves into its own leaf and
    // engines go into theirs, or protection stays off with the reason.
    let routing = if service {
        rosetun_routing::backend_with_cgroups(cgroup::prepare())
    } else {
        rosetun_routing::backend()
    };
    let (listener, helper) = match start(Path::new("/run/rosetun"), gate, routing) {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, "failed to start helper");
            return std::process::ExitCode::FAILURE;
        }
    };
    let server = Server::new(!service);
    let shutdown = server.shutdown_handle();
    let stopping = notifier.clone();
    if let Err(error) = signals::spawn_waiter(signals, move |_| {
        sd_notify::send(stopping.as_deref(), sd_notify::STOPPING);
        shutdown.request();
    }) {
        tracing::error!(%error, "failed to start the signal thread");
        helper.shutdown();
        return std::process::ExitCode::FAILURE;
    }
    sd_notify::send(notifier.as_deref(), sd_notify::READY);
    tracing::info!(service, "helper is ready");
    if let Err(error) = server.serve(listener, helper) {
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
    tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .with_writer(std::sync::Mutex::new(file))
        .with_ansi(false)
        .finish()
        .with(log_gate_layer(&gate))
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
            .map_or_else(|| parent.to_owned(), std::path::PathBuf::from))
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

/// A connect waits for this check, so a slow one explains a slow first
/// connect after boot.
const SLOW_ENGINE_CHECK: Duration = Duration::from_secs(5);

fn note_slow_engine_check(engine: &str, elapsed: Duration) {
    if elapsed > SLOW_ENGINE_CHECK {
        tracing::info!(
            engine,
            elapsed_ms = elapsed.as_millis(),
            "engine check was slow; an antivirus may be scanning the binary"
        );
    }
}

#[derive(Debug)]
struct StartError(String);

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

struct PreparedStart {
    listener: Listener,
    run_dir: std::path::PathBuf,
    data_dir: std::path::PathBuf,
}

#[cfg_attr(
    target_os = "linux",
    expect(
        unused_variables,
        reason = "the Linux service directories are fixed, so the caller's run directory is not used"
    )
)]
fn prepare_start(run_dir: &Path) -> Result<PreparedStart, StartError> {
    let endpoint = rosetun_ipc::default_endpoint();
    let listener = Listener::bind(&endpoint).map_err(|error| {
        StartError(format!(
            "failed to bind socket {}: {error}",
            endpoint.display()
        ))
    })?;
    #[cfg(target_os = "linux")]
    {
        rosetun_ipc::transport::prepare_service_directories(
            rosetun_engine::process::engine_group(),
        )
        .map_err(|error| StartError(format!("failed to prepare service directories: {error}")))?;
        Ok(PreparedStart {
            listener,
            run_dir: "/run/rosetun/private".into(),
            data_dir: "/var/lib/rosetun".into(),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let data_dir = run_dir
            .parent()
            .ok_or_else(|| StartError("engine run directory has no data directory".to_owned()))?;
        Ok(PreparedStart {
            listener,
            run_dir: run_dir.to_owned(),
            data_dir: data_dir.to_owned(),
        })
    }
}

fn start(
    run_dir: &Path,
    gate: VerboseGate,
    routing: Box<dyn rosetun_routing::RoutingBackend>,
) -> Result<(Listener, Arc<Helper>), StartError> {
    start_prepared(prepare_start(run_dir), |prepared| {
        initialize(prepared, gate, routing)
    })
}

/// Runs `initialize` only when path preparation succeeded: engines and
/// background threads must never start on a directory that failed its checks.
fn start_prepared<T>(
    prepared: Result<PreparedStart, StartError>,
    initialize: impl FnOnce(PreparedStart) -> Result<T, StartError>,
) -> Result<T, StartError> {
    initialize(prepared?)
}

fn initialize(
    prepared: PreparedStart,
    gate: VerboseGate,
    routing: Box<dyn rosetun_routing::RoutingBackend>,
) -> Result<(Listener, Arc<Helper>), StartError> {
    let PreparedStart {
        listener,
        run_dir,
        data_dir,
    } = prepared;
    #[cfg(windows)]
    process_job::install().map_err(|error| {
        StartError(format!(
            "failed to install helper process-lifetime job: {error}"
        ))
    })?;
    let run_dir = run_dir.as_path();
    let data_dir = data_dir.as_path();
    let mut engines = EngineRegistry::new();
    let singbox = singbox_backend(run_dir, data_dir);
    let xray = XrayHelper::new(run_dir.join("xray"));
    let lists = list_store::ListStore::open(data_dir.join("lists"))
        .map_err(|error| StartError(format!("failed to initialize list storage: {error}")))?;
    let warmup = singbox.clone();
    let xray_warmup = xray.clone();
    std::thread::Builder::new()
        .name("engine-warmup".to_owned())
        .spawn(move || {
            let started = Instant::now();
            let result = warmup.locate_binary();
            let elapsed = started.elapsed();
            match result {
                Ok(binary) => tracing::info!(
                    binary = %binary.display(),
                    elapsed_ms = elapsed.as_millis(),
                    "sing-box is ready"
                ),
                Err(error) => tracing::warn!(%error, "sing-box check at start failed"),
            }
            note_slow_engine_check("sing-box", elapsed);

            let started = Instant::now();
            let result = xray_warmup.locate_binary();
            let elapsed = started.elapsed();
            match result {
                Ok(binary) => tracing::info!(
                    binary = %binary.display(),
                    elapsed_ms = elapsed.as_millis(),
                    "Xray is ready"
                ),
                Err(error) => tracing::warn!(%error, "Xray check at start failed"),
            }
            note_slow_engine_check("Xray", elapsed);
        })
        .map_err(|error| StartError(format!("failed to start engine warmup thread: {error}")))?;
    engines.register(Box::new(singbox));

    let helper = Helper::new(engines, routing, gate)
        .with_xray(xray)
        .with_list_store(lists, run_dir.join("sing-box"));
    #[cfg(target_os = "linux")]
    let helper = helper
        .with_upgrade_marker(UPGRADE_MARKER.into())
        .with_process_rights_unavailable(rosetun_engine::process::rights_unavailable(
            rosetun_engine::EngineRights::NetworkAndProcesses,
        ));
    let helper = Arc::new(helper);
    helper.restore_lockdown();
    state::spawn_list_reaper(Arc::clone(&helper))
        .map_err(|error| StartError(format!("failed to start list cleanup thread: {error}")))?;
    state::spawn_supervisor(Arc::clone(&helper)).map_err(|error| {
        StartError(format!("failed to start engine supervisor thread: {error}"))
    })?;
    Ok((listener, helper))
}

/// sing-box runs only from its protected copy; without one, connects fail
/// with the reason instead of starting the installed binary.
#[cfg(windows)]
fn singbox_backend(run_dir: &Path, data_dir: &Path) -> SingBoxBackend {
    let work_dir = run_dir.join("sing-box");
    let copied = std::env::current_exe().and_then(|exe| {
        let dir = exe
            .parent()
            .ok_or_else(|| std::io::Error::other("service executable has no parent"))?;
        engine_copy::prepare(&dir.join("sing-box.exe"), data_dir)
    });
    backend_from_copy(work_dir, copied)
}

/// Who runs the engines. The service never falls back to root: without its
/// account no engine starts, and the reason reaches the user with the connect.
/// A helper started by hand is a developer's, with nothing installed.
#[cfg(target_os = "linux")]
fn engine_identity(
    account: std::io::Result<Option<rosetun_engine::process::Account>>,
    service: bool,
) -> rosetun_engine::process::Identity {
    use rosetun_engine::process::{ENGINE_ACCOUNT, Identity};

    let missing = match account {
        Ok(Some(account)) => return Identity::Account(account),
        Ok(None) => "the system has no such account".to_owned(),
        Err(error) => error.to_string(),
    };
    if service {
        tracing::error!(account = ENGINE_ACCOUNT, %missing, "engines cannot start");
        Identity::Missing
    } else {
        tracing::warn!(account = ENGINE_ACCOUNT, %missing, "engines run with the helper's rights");
        Identity::Inherit
    }
}

/// The engines next to the helper. On Linux they run only while root alone
/// can change them and every folder above them; there is no copy to fall
/// back to.
#[cfg(not(windows))]
fn singbox_backend(run_dir: &Path, _data_dir: &Path) -> SingBoxBackend {
    SingBoxBackend::new(run_dir.join("sing-box"))
}

#[cfg(windows)]
fn backend_from_copy(
    work_dir: std::path::PathBuf,
    copied: std::io::Result<std::path::PathBuf>,
) -> SingBoxBackend {
    match copied {
        Ok(copy) => SingBoxBackend::with_binary(work_dir, copy),
        Err(error) => {
            tracing::error!(%error, "cannot prepare the sing-box copy; connecting will fail");
            SingBoxBackend::unavailable(work_dir, format!("sing-box copy: {error}"))
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_verbose_log_lets_engine_lines_through_only_while_it_is_on() {
        use std::sync::{Arc, Mutex};

        use tracing_subscriber::prelude::*;

        #[derive(Clone, Default)]
        struct Captured(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for Captured {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        fn line(round: &str) {
            tracing::info!(target: rosetun_engine::ENGINE_OUTPUT_TARGET, "info {round}");
            tracing::debug!(target: rosetun_engine::ENGINE_OUTPUT_TARGET, "debug {round}");
        }

        let gate = super::VerboseGate::default();
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(super::log_filter())
            .with_writer(move || writer.clone())
            .finish()
            .with(super::log_gate_layer(&gate));
        tracing::subscriber::with_default(subscriber, || {
            line("closed-first");
            gate.open_until(u64::MAX);
            line("open");
            gate.close();
            line("closed-again");
        });
        let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(
            text.contains("info open") && text.contains("debug open"),
            "{text}"
        );
        assert!(!text.contains("closed"), "{text}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_service_looks_for_the_marker_where_the_package_leaves_it() {
        let line = format!("MARKER={}\n", super::UPGRADE_MARKER);
        for script in [
            include_str!("../../../packaging/linux/debian/prerm"),
            include_str!("../../../packaging/linux/debian/postinst"),
        ] {
            assert!(script.replace("\r\n", "\n").contains(&line));
        }
    }

    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn the_service_never_runs_engines_as_root() {
        use rosetun_engine::process::{Account, Identity};

        let account = Account {
            uid: 64000,
            gid: 64000,
        };
        for service in [false, true] {
            assert_eq!(
                engine_identity(Ok(Some(account)), service),
                Identity::Account(account)
            );
        }
        assert_eq!(engine_identity(Ok(None), true), Identity::Missing);
        assert_eq!(
            engine_identity(Err(std::io::Error::other("lookup failed")), true),
            Identity::Missing
        );
        assert_eq!(engine_identity(Ok(None), false), Identity::Inherit);
    }

    #[test]
    fn failed_path_preparation_never_initializes_engines_or_background_workers() {
        let mut initialized = false;
        let Err(error) = start_prepared(
            Err(StartError("unsafe service directory".to_owned())),
            |_| {
                initialized = true;
                Ok(())
            },
        ) else {
            panic!("preparation must fail");
        };
        assert_eq!(error.to_string(), "unsafe service directory");
        assert!(!initialized);
    }

    #[cfg(windows)]
    #[test]
    fn a_failed_engine_copy_never_runs_the_installed_engine() {
        let backend = backend_from_copy(
            "unused".into(),
            Err(std::io::Error::from(std::io::ErrorKind::StorageFull)),
        );
        assert!(matches!(
            backend.locate_binary(),
            Err(rosetun_engine::errors::EngineError::BinaryUnavailable(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_runs_the_console_the_service_and_lockdowns_commands() {
        let mode = |args: &[&str]| parse_mode(args.iter().map(OsString::from)).unwrap();
        assert!(runs_on_linux(&mode(&[])));
        assert!(runs_on_linux(&mode(&["--service"])));
        assert!(runs_on_linux(&mode(&["--reset-firewall"])));
        assert!(runs_on_linux(&mode(&["--restore-lockdown"])));
        assert!(runs_on_linux(&mode(&["--restart-for-upgrade"])));
        for args in [
            &["--install-service"][..],
            &["--uninstall-service"],
            &["--verify-install-dir", "/opt/example"],
            &["--secure-install-dir", "/opt/example"],
            &["--finalize-install-dir", "/opt/example"],
            &["--hold-for-upgrade", "/opt/example"],
        ] {
            assert!(!runs_on_linux(&mode(args)), "{args:?}");
        }
    }

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
        assert_eq!(mode(&["--reset-firewall"]), Ok(Mode::ResetFirewall));
        assert_eq!(mode(&["--restore-lockdown"]), Ok(Mode::RestoreLockdown));
        assert_eq!(
            mode(&["--reset-firewall", "--service"]),
            Err(USAGE.to_owned())
        );
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
        assert_eq!(
            mode(&["--hold-for-upgrade", r"D:\Example\Rosetun"]),
            Ok(Mode::HoldForUpgrade(r"D:\Example\Rosetun".into()))
        );
        assert_eq!(mode(&["--hold-for-upgrade"]), Err(USAGE.to_owned()));
        assert_eq!(mode(&["--verify-install-dir"]), Err(USAGE.to_owned()));
        assert_eq!(mode(&["--unknown"]), Err(USAGE.to_owned()));
        assert_eq!(
            mode(&["--service", "--install-service"]),
            Err(USAGE.to_owned())
        );
    }
}
