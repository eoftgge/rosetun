use std::collections::HashSet;
use std::ffi::OsString;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{HANDLE, HWND, INVALID_HANDLE_VALUE, LPARAM};
use windows_sys::Win32::Graphics::Dwm::{DWMWA_CLOAKED, DwmGetWindowAttribute};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
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

/// Version resources are a few kilobytes; a larger one is not read.
const MAX_VERSION_INFO: u32 = 1 << 20;

pub(super) fn file_description(path: &Path) -> Option<String> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    let local_drive = wide.len() > 3
        && wide[1] == u16::from(b':')
        && matches!(wide[2], 0x5c | 0x2f)
        && char::from_u32(u32::from(wide[0])).is_some_and(|letter| letter.is_ascii_alphabetic());
    if !local_drive || wide.contains(&0) {
        return None;
    }
    let wide: Vec<u16> = wide.into_iter().chain(std::iter::once(0)).collect();
    let mut ignored = 0;
    // SAFETY: wide is a NUL-terminated UTF-16 path that outlives the call, and
    // ignored is writable; the Windows ABI call retains neither pointer.
    let size = unsafe { GetFileVersionInfoSizeW(wide.as_ptr(), &raw mut ignored) };
    if size == 0 || size > MAX_VERSION_INFO {
        return None;
    }
    // u32 elements keep the block aligned for the WORD and DWORD values in it.
    let mut block = vec![0_u32; (size as usize).div_ceil(4)];
    // SAFETY: block is writable for at least size bytes and both buffers stay
    // alive for the call; Windows copies the resource into block and keeps no pointer.
    if unsafe { GetFileVersionInfoW(wide.as_ptr(), 0, size, block.as_mut_ptr().cast()) } == 0 {
        return None;
    }
    let mut languages: Vec<(u16, u16)> = query(&block, r"\VarFileInfo\Translation", 2)
        .map(|units| {
            units
                .chunks_exact(2)
                .map(|pair| (pair[0], pair[1]))
                .collect()
        })
        .unwrap_or_default();
    // US English in Unicode and in Windows-1252: the usual blocks of a file
    // without a translation table.
    languages.extend([(0x0409, 0x04b0), (0x0409, 0x04e4)]);
    languages.into_iter().find_map(|(language, codepage)| {
        let units = query(
            &block,
            &format!(r"\StringFileInfo\{language:04x}{codepage:04x}\FileDescription"),
            1,
        )?;
        let end = units
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(units.len());
        Some(String::from_utf16_lossy(&units[..end])).filter(|text| !text.is_empty())
    })
}

/// The value at `sub_block` as UTF-16 units, borrowed from `block`. The
/// reported length counts UTF-16 units for strings and bytes for binary
/// values, so `unit_bytes` is 1 or 2.
fn query<'a>(block: &'a [u32], sub_block: &str, unit_bytes: usize) -> Option<&'a [u16]> {
    let name: Vec<u16> = sub_block.encode_utf16().chain(std::iter::once(0)).collect();
    let mut value = std::ptr::null_mut();
    let mut length = 0_u32;
    // SAFETY: block holds the data GetFileVersionInfoW wrote, name is
    // NUL-terminated, and value and length are writable for the call. On
    // success value points inside block (not a new allocation).
    if unsafe {
        VerQueryValueW(
            block.as_ptr().cast(),
            name.as_ptr(),
            &raw mut value,
            &raw mut length,
        )
    } == 0
        || value.is_null()
    {
        return None;
    }
    let start = value as usize;
    let block_start = block.as_ptr() as usize;
    let block_end = block_start + std::mem::size_of_val(block);
    if start < block_start || start >= block_end || !start.is_multiple_of(2) {
        return None;
    }
    let units = (length as usize / unit_bytes).min((block_end - start) / 2);
    // SAFETY: the range starts inside block, is 2-byte aligned and was just
    // clamped to end within it; the slice borrows block for its lifetime.
    Some(unsafe { std::slice::from_raw_parts(value as *const u16, units) })
}
