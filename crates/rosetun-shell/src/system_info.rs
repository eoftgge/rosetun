use std::io;
use std::mem::{MaybeUninit, size_of_val};

use windows_sys::Win32::Foundation::SYSTEMTIME;
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

pub fn windows_build() -> io::Result<u32> {
    let key: Vec<u16> = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let name: Vec<u16> = "CurrentBuildNumber"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut value = [0_u16; 32];
    let mut bytes = size_of_val(&value) as u32;
    // SAFETY: HKLM is a borrowed predefined registry handle. Both strings are
    // NUL-terminated UTF-16 and the writable buffer and size live through the call.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            value.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let length = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16(&value[..length])
        .map_err(|_| io::Error::other("invalid Windows build number"))?
        .parse()
        .map_err(|_| io::Error::other("invalid Windows build number"))
}

pub fn local_report_timestamp() -> String {
    let mut value = MaybeUninit::<SYSTEMTIME>::uninit();
    // SAFETY: GetLocalTime initializes the complete SYSTEMTIME output via the
    // Windows ABI before this stack value is read; no borrowed pointer escapes.
    let local = unsafe {
        GetLocalTime(value.as_mut_ptr());
        value.assume_init()
    };
    format!(
        "{:04}{:02}{:02}-{:02}{:02}",
        local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute
    )
}
