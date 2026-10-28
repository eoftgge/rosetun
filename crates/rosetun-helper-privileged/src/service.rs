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
use rosetun_ipc::SERVICE_NAME;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
    ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_EXISTS, ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_SPECIFIC_ERROR, LocalFree,
    NO_ERROR,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
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
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceObjectSecurity, SetServiceStatus,
    StartServiceCtrlDispatcherW, StartServiceW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND};

const DESCRIPTION: &str = "Runs the Rosetun tunnel and kill switch.";
const WAIT_HINT_MS: u32 = 30_000;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
/// The SCM's default service DACL plus `SERVICE_QUERY_STATUS` (`LC`) for
/// Authenticated Users: the CLI checks the pipe server's process ID against
/// the service, and a batch logon (a scheduled task) is neither `IU` nor `SU`.
const SERVICE_SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;LC;;;AU)";

struct StatusHandle(SERVICE_STATUS_HANDLE);

// SAFETY: SetServiceStatus permits reporting through a registered status handle
// from both the service and control-handler threads for the handle's lifetime.
unsafe impl Send for StatusHandle {}
// SAFETY: The service status handle stays valid until the process exits.
unsafe impl Sync for StatusHandle {}

struct ScHandle(SC_HANDLE);

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: Allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
        // and released exactly once, after every borrowed use.
        unsafe { LocalFree(self.0) };
    }
}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let sddl = wide(sddl);
        let mut descriptor = ptr::null_mut();
        // SAFETY: The NUL-terminated string and output pointer are live for
        // this synchronous call; LocalFree in Drop owns the result.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

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

/// Applied on every install, so an upgrade brings the permission too.
fn service_security(service: &ScHandle) -> io::Result<()> {
    let descriptor = SecurityDescriptor::from_sddl(SERVICE_SDDL)?;
    // SAFETY: The service handle has WRITE_DAC and the descriptor stays live
    // for this synchronous call; the SCM copies it.
    if unsafe { SetServiceObjectSecurity(service.0, DACL_SECURITY_INFORMATION, descriptor.0) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    let access = SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_STATUS | WRITE_DAC;

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
    service_security(&service)?;
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
    stop_and_wait(&service)?;

    // SAFETY: The service handle remains live until deletion completes.
    if unsafe { DeleteService(service.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    println!("Rosetun service removed");
    Ok(())
}

/// Stops the service and waits until it has; returns whether it was running.
fn stop_and_wait(service: &ScHandle) -> io::Result<bool> {
    let mut status = SERVICE_STATUS::default();
    // SAFETY: The service handle and status output remain live during the call.
    if unsafe { QueryServiceStatus(service.0, &mut status) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let was_running = status.dwCurrentState != SERVICE_STOPPED;
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
            return Ok(was_running);
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
}

/// Exit codes of `--reset-firewall`; `rosetun reset-firewall` reads them.
pub(crate) mod reset_exit {
    pub(crate) const FAILED: u8 = 1;
    pub(crate) const NOT_ADMINISTRATOR: u8 = 3;
    pub(crate) const SERVICE_DID_NOT_STOP: u8 = 4;
    pub(crate) const FILTERS_REMAIN: u8 = 5;
    pub(crate) const SERVICE_DID_NOT_START: u8 = 6;
}

/// Removes Lockdown's persistent objects, and nothing else, by their fixed
/// keys. A running service is stopped first: its dynamic filters in the
/// Lockdown sublayer go with it, so the removal does not hit FWP_E_IN_USE.
/// The service is started again if it was running.
pub(crate) fn reset_firewall() -> ExitCode {
    let not_administrator = || {
        eprintln!("removing Lockdown needs administrator rights");
        ExitCode::from(reset_exit::NOT_ADMINISTRATOR)
    };
    // SAFETY: Null names select the local SCM and active database.
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        eprintln!(
            "cannot open the service manager: {}",
            io::Error::last_os_error()
        );
        return ExitCode::from(reset_exit::FAILED);
    }
    let manager = ScHandle(manager);
    let name = wide(SERVICE_NAME);
    // SAFETY: The SCM handle and NUL-terminated name are live during the call.
    let service = unsafe {
        OpenServiceW(
            manager.0,
            name.as_ptr(),
            SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS,
        )
    };
    let service = if service.is_null() {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(code) if code == ERROR_SERVICE_DOES_NOT_EXIST as i32 => None,
            Some(code) if code == ERROR_ACCESS_DENIED as i32 => return not_administrator(),
            _ => {
                eprintln!("cannot open the Rosetun service: {error}");
                return ExitCode::from(reset_exit::FAILED);
            }
        }
    } else {
        Some(ScHandle(service))
    };

    let was_running = match service.as_ref().map(stop_and_wait).transpose() {
        Ok(running) => running.unwrap_or(false),
        Err(error) => {
            eprintln!("cannot stop the Rosetun service: {error}");
            return ExitCode::from(reset_exit::SERVICE_DID_NOT_STOP);
        }
    };
    if was_running {
        println!("Rosetun service stopped");
    }

    let removal = rosetun_routing::lockdown::disable();
    let restarted = match service.as_ref().filter(|_| was_running) {
        // SAFETY: The service handle is live and no start arguments are supplied.
        Some(service) if unsafe { StartServiceW(service.0, 0, ptr::null()) } == 0 => {
            Err(io::Error::last_os_error())
        }
        _ => Ok(()),
    };
    let code = match removal {
        Ok(true) => {
            println!("Lockdown removed");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("Lockdown was not on; nothing to remove");
            ExitCode::SUCCESS
        }
        Err(rosetun_routing::RoutingError::Wfp { code, .. }) if code == ERROR_ACCESS_DENIED => {
            return not_administrator();
        }
        Err(error) if error.is_in_use() => {
            eprintln!(
                "Lockdown is still in use by a running Rosetun helper; stop it and run this again"
            );
            ExitCode::from(reset_exit::FILTERS_REMAIN)
        }
        Err(error) => {
            eprintln!("cannot remove Lockdown: {error}");
            ExitCode::from(reset_exit::FILTERS_REMAIN)
        }
    };
    if let Err(error) = restarted {
        eprintln!("cannot start the Rosetun service again: {error}");
        return ExitCode::from(reset_exit::SERVICE_DID_NOT_START);
    }
    if was_running {
        println!("Rosetun service started again");
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{
        ACL, ACL_SIZE_INFORMATION, AclSizeInformation, GetAce, GetAclInformation,
        GetSecurityDescriptorDacl, IsWellKnownSid, WinAuthenticatedUserSid,
    };

    #[test]
    fn authenticated_users_may_only_query_the_service_status() {
        let descriptor = SecurityDescriptor::from_sddl(SERVICE_SDDL).unwrap();
        let mut present = 0;
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: The descriptor is live; Windows writes into these locals and
        // the DACL is borrowed from the descriptor.
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted)
            },
            0
        );
        assert!(present != 0 && !dacl.is_null());
        let mut size = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        // SAFETY: The DACL is borrowed from the live descriptor; the output is
        // exactly sized and writable.
        assert_ne!(
            unsafe {
                GetAclInformation(
                    dacl,
                    (&raw mut size).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            },
            0
        );
        assert_eq!(size.AceCount, 5);
        let mut authenticated = Vec::new();
        for index in 0..size.AceCount {
            let mut ace: *mut c_void = ptr::null_mut();
            // SAFETY: The index is below the ACE count; the ACE is borrowed
            // from the live descriptor.
            assert_ne!(unsafe { GetAce(dacl, index, &mut ace) }, 0);
            // SAFETY: Every ACE parsed from this SDDL is an allowed ACE of at
            // least 16 bytes: header, mask, then the SID at offset 8.
            let bytes = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), 16) };
            let mask = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            // SAFETY: The SID at offset 8 lives inside the borrowed ACE.
            let sid = unsafe { ace.cast::<u8>().add(8).cast() };
            // SAFETY: The SID stays live for the comparison.
            if unsafe { IsWellKnownSid(sid, WinAuthenticatedUserSid) } != 0 {
                assert_eq!(bytes[0], 0); // ACCESS_ALLOWED_ACE_TYPE
                authenticated.push(mask);
            }
        }
        assert_eq!(authenticated, [SERVICE_QUERY_STATUS]);
    }

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
