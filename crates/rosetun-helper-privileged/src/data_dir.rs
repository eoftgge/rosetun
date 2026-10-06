use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
};

const DATA_DACL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

struct SecurityDescriptor(*mut c_void);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: Windows allocated this descriptor; this guard frees it once.
        unsafe { LocalFree(self.0) };
    }
}

pub(crate) fn data_dir() -> io::Result<PathBuf> {
    if let Some(custom) = std::env::var_os("ROSETUN_DATA_DIR") {
        return Ok(PathBuf::from(custom));
    }
    let exe = std::env::current_exe()?;
    let parent = exe
        .parent()
        .ok_or_else(|| io::Error::other("helper executable has no parent"))?;
    Ok(parent.join("data"))
}

/// sing-box runs as SYSTEM with a config here, so only SYSTEM and
/// Administrators may write files it will consume.
pub(crate) fn secure(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;

    let sddl: Vec<u16> = DATA_DACL.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: The SDDL is NUL-terminated and the output pointer is valid.
    let result = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = SecurityDescriptor(descriptor);

    let mut present = 0;
    let mut dacl = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: The descriptor is live and all DACL output pointers are valid.
    let result =
        unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || dacl.is_null() {
        return Err(io::Error::other("data directory DACL is missing"));
    }

    let mut path: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: The path is NUL-terminated, and the DACL stays live in the
    // descriptor until SetNamedSecurityInfoW finishes copying it.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}
