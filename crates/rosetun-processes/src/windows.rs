use std::collections::HashSet;
use std::ffi::OsString;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{HANDLE, HWND, INVALID_HANDLE_VALUE, LPARAM};
use windows_sys::Win32::Graphics::Dwm::{DWMWA_CLOAKED, DwmGetWindowAttribute};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GW_OWNER, GWL_EXSTYLE, GetWindow, GetWindowLongPtrW, GetWindowTextLengthW,
    GetWindowThreadProcessId, IsWindowVisible, WS_EX_TOOLWINDOW,
};

use crate::{ProcessListError, RunningProcess};

pub(super) fn running_processes() -> Result<Vec<RunningProcess>, ProcessListError> {
    let mut windowed = HashSet::<u32>::new();
    // SAFETY: EnumWindows calls synchronously and does not retain lparam. The
    // pointer addresses a live HashSet exclusively borrowed for the entire call.
    unsafe { EnumWindows(Some(collect_windowed_pid), (&raw mut windowed) as LPARAM) };

    // SAFETY: windows-sys declares the Windows system ABI. This call takes no
    // pointers or borrowed handles; the returned snapshot is owned by us.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(ProcessListError::Snapshot(io::Error::last_os_error()));
    }
    // SAFETY: A successful snapshot returns a valid owned handle, transferred
    // immediately to OwnedHandle so every exit closes it exactly once.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..PROCESSENTRY32W::default()
    };
    let mut paths = vec![0u16; 32_768];
    let mut processes = Vec::new();

    // SAFETY: The owned snapshot and writable, correctly sized ABI struct stay
    // alive for the call. ToolHelp writes the entry only on success.
    let mut found = unsafe { Process32FirstW(snapshot.as_raw_handle() as HANDLE, &mut entry) };
    while found != 0 {
        let pid = entry.th32ProcessID;
        if pid != 0 && pid != 4 {
            let name_end = entry
                .szExeFile
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(entry.szExeFile.len());
            processes.push(RunningProcess {
                pid,
                name: String::from_utf16_lossy(&entry.szExeFile[..name_end]),
                path: process_path(pid, &mut paths),
                has_window: windowed.contains(&pid),
            });
        }
        // SAFETY: The snapshot remains owned for the loop, and the same sized
        // entry is writable for the duration of this Windows ABI call.
        found = unsafe { Process32NextW(snapshot.as_raw_handle() as HANDLE, &mut entry) };
    }
    Ok(processes)
}

unsafe extern "system" fn collect_windowed_pid(hwnd: HWND, param: LPARAM) -> i32 {
    // SAFETY: EnumWindows supplies valid HWNDs during the synchronous callback;
    // the read-only Win32 queries use their ABI and do not retain the handle.
    if unsafe { IsWindowVisible(hwnd) } == 0
        || !unsafe { GetWindow(hwnd, GW_OWNER) }.is_null()
        || unsafe { GetWindowTextLengthW(hwnd) } == 0
        || unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) } & WS_EX_TOOLWINDOW as isize != 0
    {
        return 1;
    }
    let mut cloaked = 0_u32;
    // SAFETY: hwnd is valid for this callback; cloaked is writable for the call
    // and its byte count matches the Windows ABI. The call retains no pointer.
    if unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_CLOAKED as u32,
            (&raw mut cloaked).cast(),
            size_of::<u32>() as u32,
        )
    } != 0
        || cloaked != 0
    {
        return 1;
    }
    let mut pid = 0;
    // SAFETY: hwnd belongs to the current enumeration and pid remains writable
    // for the duration of the Windows ABI call; neither address is retained.
    unsafe { GetWindowThreadProcessId(hwnd, &raw mut pid) };
    if pid != 0 {
        // SAFETY: param is the live, exclusive HashSet pointer passed to the
        // synchronous EnumWindows call; no other code accesses it until return.
        unsafe { &mut *(param as *mut HashSet<u32>) }.insert(pid);
    }
    1
}

fn process_path(pid: u32, buffer: &mut [u16]) -> Option<PathBuf> {
    // SAFETY: windows-sys supplies the Windows ABI. Only query permission is
    // requested (no memory reading), and the returned handle is not inherited.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    // SAFETY: OpenProcess returned a valid owned handle, transferred immediately
    // to OwnedHandle; it is closed on success and on any query failure.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut length = buffer.len() as u32;
    // SAFETY: The process handle and writable UTF-16 buffer stay alive during
    // this Windows ABI call. length describes the entire buffer; data is used
    // only on success and only up to the returned number of code units.
    let success = unsafe {
        QueryFullProcessImageNameW(
            process.as_raw_handle() as HANDLE,
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &mut length,
        )
    };
    if success == 0 || length == 0 {
        return None;
    }
    Some(PathBuf::from(OsString::from_wide(
        &buffer[..length as usize],
    )))
}
