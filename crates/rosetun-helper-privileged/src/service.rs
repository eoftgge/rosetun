use std::ffi::c_void;
use std::io;
use std::path::Path;
use std::process::ExitCode;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::log_gate::VerboseGate;
use crate::server::{Server, ShutdownHandle};
use crate::state::Helper;
use windows_sys::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
    ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_EXISTS, ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
    RegisterServiceCtrlHandlerExW, SC_ACTION, SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_CREATE_SERVICE, SERVICE_ACCEPT_POWEREVENT, SERVICE_ACCEPT_PRESHUTDOWN,
    SERVICE_ACCEPT_STOP, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
    SERVICE_CONFIG_PRESHUTDOWN_INFO, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_POWEREVENT,
    SERVICE_CONTROL_PRESHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL,
    SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_FAILURE_ACTIONSW, SERVICE_PRESHUTDOWN_INFO,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_HANDLE, SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
    StartServiceW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND};

pub(crate) const SERVICE_NAME: &str = "Rosetun";
const DESCRIPTION: &str = "Runs the Rosetun tunnel and kill switch.";
const WAIT_HINT_MS: u32 = 30_000;
const DELETE: u32 = 0x0001_0000;

struct StatusHandle(SERVICE_STATUS_HANDLE);

// SAFETY: SetServiceStatus permits reporting through a registered status handle
// from both the service and control-handler threads for the handle's lifetime.
unsafe impl Send for StatusHandle {}
// SAFETY: The service status handle stays valid until the process exits.
unsafe impl Sync for StatusHandle {}

struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: This is a live SCM/service handle owned by this guard.
        unsafe { CloseServiceHandle(self.0) };
    }
}

static STATUS: OnceLock<StatusHandle> = OnceLock::new();
static SHUTDOWN: OnceLock<ShutdownHandle> = OnceLock::new();
static HELPER: OnceLock<Arc<Helper>> = OnceLock::new();
static VERBOSE_GATE: OnceLock<VerboseGate> = OnceLock::new();
static CHECKPOINT: AtomicU32 = AtomicU32::new(0);

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn report_status(state: u32, accepted: u32, exit_code: u32, specific_code: u32, wait: u32) {
    let Some(handle) = STATUS.get() else { return };
    let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: specific_code,
        dwCheckPoint: if pending {
            CHECKPOINT.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            0
        },
        dwWaitHint: wait,
    };
    // SAFETY: Registration keeps the status handle live; the status buffer
    // remains valid until this synchronous call returns.
    if unsafe { SetServiceStatus(handle.0, &status) } == 0 {
        tracing::error!(error = %io::Error::last_os_error(), "failed to report service status");
    }
}

unsafe extern "system" fn control_handler(
    control: u32,
    event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_PRESHUTDOWN => {
            report_status(SERVICE_STOP_PENDING, 0, NO_ERROR, 0, WAIT_HINT_MS);
            if let Some(handle) = SHUTDOWN.get() {
                handle.request();
            }
            NO_ERROR
        }
        SERVICE_CONTROL_POWEREVENT => {
            if matches!(event_type, PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND)
                && let Some(helper) = HELPER.get()
            {
                helper.notify_resume();
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide(SERVICE_NAME);
    // SAFETY: The service name stays live during registration; the callback
    // uses the system ABI and the status handle lives for the process lifetime.
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), ptr::null_mut())
    };
    if handle.is_null() {
        tracing::error!(error = %io::Error::last_os_error(), "failed to register service control handler");
        return;
    }
    if STATUS.set(StatusHandle(handle)).is_err() {
        tracing::error!("service status handle was already registered");
        return;
    }
    report_status(SERVICE_START_PENDING, 0, NO_ERROR, 0, WAIT_HINT_MS);

    let started = crate::data_dir::data_dir()
        .map(|dir| dir.join("run"))
        .map_err(|error| error.to_string())
        .and_then(|run_dir| {
            let gate = VERBOSE_GATE
                .get()
                .expect("service log gate configured")
                .clone();
            crate::start(&run_dir, gate).map_err(|error| error.to_string())
        });
    let (listener, helper) = match started {
        Ok(started) => started,
        Err(error) => {
            tracing::error!(%error, "failed to start Rosetun service");
            report_status(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR, 1, 0);
            return;
        }
    };

    if HELPER.set(Arc::clone(&helper)).is_err() {
        tracing::error!("service helper was already registered");
        report_status(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR, 1, 0);
        return;
    }
    let server = Server::new(false);
    if SHUTDOWN.set(server.shutdown_handle()).is_err() {
        tracing::error!("service shutdown handle was already registered");
        report_status(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR, 1, 0);
        return;
    }
    report_status(
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN | SERVICE_ACCEPT_POWEREVENT,
        NO_ERROR,
        0,
        0,
    );

    let result = server.serve(listener, helper);
    if let Err(error) = result {
        tracing::error!(%error, "Rosetun service stopped with an error");
        report_status(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR, 2, 0);
    } else {
        report_status(SERVICE_STOPPED, 0, NO_ERROR, 0, 0);
    }
}

pub(crate) fn run(gate: VerboseGate) -> ExitCode {
    if VERBOSE_GATE.set(gate).is_err() {
        tracing::error!("service log gate was already configured");
        return ExitCode::FAILURE;
    }
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: The table and its service name stay live until the dispatcher
    // returns after service_main has stopped; the final entry is a sentinel.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32) {
            eprintln!(
                "--service is for the Service Control Manager; run without arguments to start in the console"
            );
        } else {
            tracing::error!(%error, "service dispatcher failed");
        }
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn command_line(exe: &Path) -> String {
    format!("\"{}\" --service", exe.display())
}

fn service_config(service: &ScHandle) -> io::Result<()> {
    let mut description = wide(DESCRIPTION);
    let mut description_info = SERVICE_DESCRIPTIONW {
        lpDescription: description.as_mut_ptr(),
    };
    // SAFETY: The service handle and description buffer remain live for the call.
    if unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DESCRIPTION,
            (&raw mut description_info).cast(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5_000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5_000,
        },
    ];
    let mut failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 24 * 60 * 60,
        lpRebootMsg: ptr::null_mut(),
        lpCommand: ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    // SAFETY: The action array and configuration buffer remain live for the call.
    if unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            (&raw mut failure).cast(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut flag = SERVICE_FAILURE_ACTIONS_FLAG {
        fFailureActionsOnNonCrashFailures: 1,
    };
    // SAFETY: The flag buffer remains live for this call.
    if unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            (&raw mut flag).cast(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut preshutdown = SERVICE_PRESHUTDOWN_INFO {
        dwPreshutdownTimeout: WAIT_HINT_MS,
    };
    // SAFETY: The preshutdown configuration remains live for this call.
    if unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_PRESHUTDOWN_INFO,
            (&raw mut preshutdown).cast(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn install() -> io::Result<()> {
    // SAFETY: Null names select the local SCM and active database.
    let manager = unsafe {
        OpenSCManagerW(
            ptr::null(),
            ptr::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
        )
    };
    if manager.is_null() {
        return Err(io::Error::last_os_error());
    }
    let manager = ScHandle(manager);
    let name = wide(SERVICE_NAME);
    let exe = std::env::current_exe()?;
    let binary = wide(&command_line(&exe));
    let dependencies = wide("BFE\0");
    let access = SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_STATUS;

    // SAFETY: All strings and the SCM handle remain live throughout this call.
    let service = unsafe {
        CreateServiceW(
            manager.0,
            name.as_ptr(),
            name.as_ptr(),
            access,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binary.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            dependencies.as_ptr(),
            ptr::null(),
            ptr::null(),
        )
    };
    let service = if service.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_SERVICE_EXISTS as i32) {
            return Err(error);
        }
        // SAFETY: The SCM handle and name are live for the call.
        let existing = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
        if existing.is_null() {
            return Err(io::Error::last_os_error());
        }
        let existing = ScHandle(existing);
        // SAFETY: The handle and all configuration strings remain live for the call.
        if unsafe {
            ChangeServiceConfigW(
                existing.0,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                binary.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                dependencies.as_ptr(),
                ptr::null(),
                ptr::null(),
                name.as_ptr(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        existing
    } else {
        ScHandle(service)
    };

    service_config(&service)?;
    // SAFETY: The service handle is live and no start arguments are supplied.
    if unsafe { StartServiceW(service.0, 0, ptr::null()) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_SERVICE_ALREADY_RUNNING as i32) {
            return Err(error);
        }
    }
    println!("Rosetun service installed and started");
    Ok(())
}

pub(crate) fn uninstall() -> io::Result<()> {
    // SAFETY: Null names select the local SCM and active database.
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(io::Error::last_os_error());
    }
    let manager = ScHandle(manager);
    let name = wide(SERVICE_NAME);
    // SAFETY: The SCM handle and NUL-terminated name are live during the call.
    let service = unsafe {
        OpenServiceW(
            manager.0,
            name.as_ptr(),
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
        )
    };
    if service.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
            return Ok(());
        }
        return Err(error);
    }
    let service = ScHandle(service);
    let mut status = SERVICE_STATUS::default();
    // SAFETY: The service handle and status output remain live during the call.
    if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) } == 0 {
        let error = io::Error::last_os_error();
        let code = error.raw_os_error();
        if code != Some(ERROR_SERVICE_NOT_ACTIVE as i32)
            && code != Some(ERROR_SERVICE_CANNOT_ACCEPT_CTRL as i32)
        {
            return Err(error);
        }
    }

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        // SAFETY: The service handle and status output remain live during the call.
        if unsafe { QueryServiceStatus(service.0, &mut status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if status.dwCurrentState == SERVICE_STOPPED {
            break;
        }
        if status.dwCurrentState == SERVICE_RUNNING {
            // SAFETY: The service handle and status output remain live during the call.
            let _ = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) };
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for Rosetun service to stop",
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    // SAFETY: The service handle remains live until deletion completes.
    if unsafe { DeleteService(service.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    println!("Rosetun service removed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_binary_path_is_quoted() {
        assert_eq!(
            command_line(Path::new(
                r"C:\Program Files\Rosetun\rosetun-helper-privileged.exe"
            )),
            r#""C:\Program Files\Rosetun\rosetun-helper-privileged.exe" --service"#,
        );
    }
}
