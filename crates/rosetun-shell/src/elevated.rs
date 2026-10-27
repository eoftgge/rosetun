use std::io;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_FLAG_NO_UI, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// Runs `program` with `parameters` elevated through UAC, hidden, and waits
/// for it. `Ok(None)` when the user declined the UAC prompt; otherwise the
/// program's exit code.
pub fn run_elevated(program: &Path, parameters: &str) -> io::Result<Option<u32>> {
    let verb = wide("runas");
    let file = wide(&program.to_string_lossy());
    let parameters = wide(parameters);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_HIDE,
        ..Default::default()
    };
    // SAFETY: `info` is sized for this ABI and its strings are NUL-terminated
    // UTF-16 that outlive the synchronous call; on success with
    // SEE_MASK_NOCLOSEPROCESS the process handle is ours to close below.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_CANCELLED as i32) {
            return Ok(None);
        }
        return Err(error);
    }
    let process = info.hProcess;
    if process.is_null() {
        return Err(io::Error::other("the elevated program did not start"));
    }
    // SAFETY: `process` is the live handle from ShellExecuteExW, closed once
    // after the wait and the exit code are read.
    unsafe {
        let mut code = 0;
        let finished = WaitForSingleObject(process, INFINITE) == WAIT_OBJECT_0
            && GetExitCodeProcess(process, &mut code) != 0;
        let result = if finished {
            Ok(Some(code))
        } else {
            Err(io::Error::last_os_error())
        };
        CloseHandle(process);
        result
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
