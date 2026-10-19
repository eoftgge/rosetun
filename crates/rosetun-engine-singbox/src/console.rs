//! Console control events for sing-box on Windows.
//!
//! Go maps `CTRL_BREAK_EVENT` to `os.Interrupt`, which makes `sing-box run`
//! close its instance. A console event reaches only processes on the
//! caller's console, and `CTRL_C_EVENT` is ignored by a new process group, so
//! sing-box runs in its own group and gets `CTRL_BREAK_EVENT` for that group.
//! The service has no console: sing-box gets its own one without a window, and
//! the helper attaches to it for the moment of sending. Attaching is
//! process-wide, so attaching and spawning are serialised: a spawn during the
//! attach would inherit that console.

use std::io;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command};
use std::sync::{Mutex, MutexGuard, PoisonError};

use windows_sys::Win32::Foundation::{HANDLE, TRUE};
use windows_sys::Win32::System::Console::{
    AttachConsole, CTRL_BREAK_EVENT, FreeConsole, GenerateConsoleCtrlEvent, GetConsoleProcessList,
    GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    SetConsoleCtrlHandler, SetStdHandle,
};
use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};
use windows_sys::core::BOOL;

static CONSOLE: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    CONSOLE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The helper runs as a service without a console, or in the VM rig under
/// `cmd` with one. `GetConsoleWindow` cannot tell: a console created with
/// `CREATE_NO_WINDOW` has no window either.
fn has_console() -> bool {
    let mut pid = 0u32;
    // SAFETY: The buffer is one writable u32 and the count says so. The call
    // only reports the attached console's processes and fails with no console.
    unsafe { GetConsoleProcessList(&mut pid, 1) != 0 }
}

pub(crate) fn spawn(command: &mut Command) -> io::Result<Child> {
    let _console = lock();
    let mut flags = CREATE_NEW_PROCESS_GROUP;
    if !has_console() {
        flags |= CREATE_NO_WINDOW;
    }
    command.creation_flags(flags).spawn()
}

/// Sends `CTRL_BREAK_EVENT` to the process group `pid`, which a child
/// spawned by `spawn` leads.
pub(crate) fn interrupt_group(pid: u32) -> io::Result<()> {
    let _console = lock();
    if has_console() {
        return generate(pid);
    }
    let _ignore = IgnoreCtrl::install()?;
    let _attached = Attached::attach(pid)?;
    generate(pid)
}

fn generate(pid: u32) -> io::Result<()> {
    // SAFETY: Plain values; the event goes only to the group led by `pid`,
    // which the helper itself is not part of.
    if unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

unsafe extern "system" fn ignore_ctrl(_ctrl_type: u32) -> BOOL {
    TRUE
}

/// While the helper is attached, no console event may reach its default
/// handler, which would end the service. `SetConsoleCtrlHandler(None, TRUE)`
/// covers only Ctrl+C, so a handler that swallows every event is installed.
struct IgnoreCtrl;

impl IgnoreCtrl {
    fn install() -> io::Result<Self> {
        // SAFETY: `ignore_ctrl` is a 'static function with the HandlerRoutine
        // ABI that touches no state; it stays registered until drop.
        if unsafe { SetConsoleCtrlHandler(Some(ignore_ctrl), TRUE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self)
    }
}

impl Drop for IgnoreCtrl {
    fn drop(&mut self) {
        // SAFETY: Removes the registration added in `install`.
        unsafe { SetConsoleCtrlHandler(Some(ignore_ctrl), 0) };
    }
}

const STD_HANDLES: [STD_HANDLE; 3] = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];

/// Attached to another process's console; detaches on drop and restores the
/// standard handles, which attaching may point at console handles that
/// `FreeConsole` then closes.
struct Attached {
    std_handles: [HANDLE; 3],
}

impl Attached {
    fn attach(pid: u32) -> io::Result<Self> {
        // SAFETY: GetStdHandle only reads the process parameters; the values
        // are kept as opaque handles and never closed here.
        let std_handles = STD_HANDLES.map(|kind| unsafe { GetStdHandle(kind) });
        // SAFETY: Plain value. The caller holds the console lock and has no
        // console, so the process-wide attachment is ours until drop.
        if unsafe { AttachConsole(pid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { std_handles })
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        // SAFETY: Detaches the console attached in `attach`; the console
        // itself stays alive as long as sing-box holds it.
        unsafe { FreeConsole() };
        for (kind, handle) in STD_HANDLES.into_iter().zip(self.std_handles) {
            // SAFETY: Puts back the handle values read before attaching;
            // ownership never moved.
            unsafe { SetStdHandle(kind, handle) };
        }
    }
}
