use std::ffi::OsString;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::{ProcessListError, RunningProcess};

pub(super) fn running_processes() -> Result<Vec<RunningProcess>, ProcessListError> {
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
            });
        }
        // SAFETY: The snapshot remains owned for the loop, and the same sized
        // entry is writable for the duration of this Windows ABI call.
        found = unsafe { Process32NextW(snapshot.as_raw_handle() as HANDLE, &mut entry) };
    }
    Ok(processes)
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
