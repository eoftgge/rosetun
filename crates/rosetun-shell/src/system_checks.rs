use std::io;
use std::mem::size_of;

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SERVICE_DOES_NOT_EXIST,
};
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, RRF_NOEXPAND, RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
    RegGetValueW,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_STATUS_PROCESS,
};

const INTERNET_SETTINGS: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
const MAX_PROXY_BYTES: u32 = 4096;

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn value(name: &str, flags: u32) -> io::Result<Option<Vec<u8>>> {
    let key = wide(INTERNET_SETTINGS);
    let name = wide(name);
    for _ in 0..3 {
        let mut size = 0;
        // SAFETY: HKCU is a borrowed predefined handle; both NUL-terminated
        // strings and the size output remain live through the synchronous ABI call.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                flags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if size > MAX_PROXY_BYTES {
            return Err(io::Error::other("proxy setting too large"));
        }
        let mut bytes = vec![0; size as usize];
        let mut returned = size;
        // SAFETY: The caller owns the writable initialized buffer and its size;
        // the registry API writes no more than the supplied length synchronously.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                flags,
                std::ptr::null_mut(),
                bytes.as_mut_ptr().cast(),
                &mut returned,
            )
        };
        if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
            return Ok(None);
        }
        if status == windows_sys::Win32::Foundation::ERROR_MORE_DATA {
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if returned > size {
            return Err(io::Error::other("invalid proxy setting size"));
        }
        bytes.truncate(returned as usize);
        return Ok(Some(bytes));
    }
    Err(io::Error::other("proxy setting changed during read"))
}

fn string_value(name: &str) -> io::Result<Option<String>> {
    value(name, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND)?
        .map(|bytes| {
            if bytes.len() % 2 != 0 {
                return Err(io::Error::other("invalid proxy setting text"));
            }
            let text: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            let text = text.strip_suffix(&[0]).unwrap_or(&text);
            String::from_utf16(text).map_err(|_| io::Error::other("invalid proxy setting text"))
        })
        .transpose()
}

/// Read only the three per-user Internet Settings values relevant to a foreign proxy.
pub fn proxy_settings() -> io::Result<(Option<u32>, Option<String>, Option<String>)> {
    let enabled = value("ProxyEnable", RRF_RT_REG_DWORD)?
        .map(|bytes| -> io::Result<u32> {
            let bytes: [u8; 4] = bytes
                .try_into()
                .map_err(|_| io::Error::other("invalid proxy flag"))?;
            Ok(u32::from_le_bytes(bytes))
        })
        .transpose()?;
    Ok((
        enabled,
        string_value("ProxyServer")?,
        string_value("AutoConfigURL")?,
    ))
}

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: This guard uniquely owns the SCM or service handle returned by Windows.
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// Reports a running WinDivert driver service, treating absent service names as stopped.
pub fn windivert_running() -> io::Result<bool> {
    // SAFETY: Null names select the local machine and active services database;
    // a successful call transfers ownership of the handle to ServiceHandle.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(io::Error::last_os_error());
    }
    let manager = ServiceHandle(manager);
    for name in ["WinDivert", "WinDivert14"] {
        let name = wide(name);
        // SAFETY: The manager is live and the name is NUL-terminated and live
        // throughout the synchronous call. The resulting handle is owned below.
        let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
        if service.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
                continue;
            }
            return Err(error);
        }
        let service = ServiceHandle(service);
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut returned = 0;
        // SAFETY: The service handle is live; the writable status buffer has
        // exactly the advertised ABI size and lives until the call returns.
        if unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_PROCESS_INFO,
                (&raw mut status).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if (returned as usize) < size_of::<SERVICE_STATUS_PROCESS>() {
            return Err(io::Error::other("incomplete driver service status"));
        }
        if status.dwCurrentState == SERVICE_RUNNING {
            return Ok(true);
        }
    }
    Ok(false)
}
