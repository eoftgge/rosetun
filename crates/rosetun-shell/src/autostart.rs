use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
};
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_BINARY, RRF_RT_REG_SZ, RegDeleteKeyValueW, RegGetValueW,
    RegSetKeyValueW,
};

const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const APPROVED_KEY: &str =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run";
const VALUE_NAME: &str = "Rosetun";
const MAX_VALUE_BYTES: u32 = 64 * 1024;

/// Starts the GUI at sign-in through HKCU Run. `argument` follows the quoted path.
pub fn enable_autostart(exe: &Path, argument: &str) -> io::Result<()> {
    let command: Vec<u8> = command_line(exe, argument)
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect();
    write_value(RUN_KEY, VALUE_NAME, REG_SZ, &command)?;
    // Task Manager's disable marker would otherwise override the new Run value.
    delete_value(APPROVED_KEY, VALUE_NAME)
}

pub fn disable_autostart() -> io::Result<()> {
    delete_value(RUN_KEY, VALUE_NAME)
}

/// The Run value exists and Task Manager has not disabled it.
pub fn autostart_enabled() -> io::Result<bool> {
    autostart_enabled_at(RUN_KEY, APPROVED_KEY, VALUE_NAME)
}

fn autostart_enabled_at(run: &str, approved: &str, name: &str) -> io::Result<bool> {
    if read_value(run, name, RRF_RT_REG_SZ)?.is_none() {
        return Ok(false);
    }
    match read_value(approved, name, RRF_RT_REG_BINARY)? {
        None => Ok(true),
        Some(bytes) => bytes
            .first()
            .map(|byte| byte & 1 == 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty startup approval")),
    }
}

fn command_line(exe: &Path, argument: &str) -> Vec<u16> {
    let mut command = vec![u16::from(b'"')];
    command.extend(exe.as_os_str().encode_wide());
    command.extend([u16::from(b'"'), u16::from(b' ')]);
    command.extend(argument.encode_utf16());
    command.push(0);
    command
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn missing(status: u32) -> bool {
    status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND
}

fn write_value(subkey: &str, name: &str, kind: u32, data: &[u8]) -> io::Result<()> {
    let subkey = wide(subkey);
    let name = wide(name);
    // SAFETY: HKCU is a predefined borrowed handle. Both UTF-16 names and the
    // initialized data buffer remain valid for this synchronous Windows ABI call.
    let status = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            name.as_ptr(),
            kind,
            data.as_ptr().cast(),
            data.len() as u32,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

fn delete_value(subkey: &str, name: &str) -> io::Result<()> {
    let subkey = wide(subkey);
    let name = wide(name);
    // SAFETY: HKCU is borrowed; the NUL-terminated names live through the ABI call.
    let status = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, subkey.as_ptr(), name.as_ptr()) };
    if status == ERROR_SUCCESS || missing(status) {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

fn read_value(subkey: &str, name: &str, flags: u32) -> io::Result<Option<Vec<u8>>> {
    let subkey = wide(subkey);
    let name = wide(name);
    for _ in 0..4 {
        let mut size = 0;
        // SAFETY: HKCU is borrowed; both names and the writable byte count live
        // through the call. A null data pointer requests the required size.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                name.as_ptr(),
                flags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if missing(status) {
            return Ok(None);
        }
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if size > MAX_VALUE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "registry value too large",
            ));
        }
        if size == 0 {
            return Ok(Some(Vec::new()));
        }
        let mut bytes = vec![0u8; size as usize];
        let mut returned_size = size;
        // SAFETY: The vector is an initialized writable buffer of `size` bytes;
        // its pointer and byte count, HKCU and both names remain valid for this
        // synchronous ABI call. The returned size is checked before use.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                name.as_ptr(),
                flags,
                std::ptr::null_mut(),
                bytes.as_mut_ptr().cast(),
                &mut returned_size,
            )
        };
        if missing(status) {
            return Ok(None);
        }
        if status == ERROR_MORE_DATA {
            continue;
        }
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if returned_size > size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid registry value size",
            ));
        }
        bytes.truncate(returned_size as usize);
        return Ok(Some(bytes));
    }
    Err(io::Error::other("registry value changed during read"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Registry::{REG_BINARY, RegDeleteKeyW};

    struct TestKey {
        root: String,
    }

    impl Drop for TestKey {
        fn drop(&mut self) {
            for key in [
                format!("{}\\Approved", self.root),
                format!("{}\\Run", self.root),
                self.root.clone(),
            ] {
                let key = wide(&key);
                // SAFETY: HKCU is borrowed and the key name is NUL-terminated and
                // lives through the call. Test keys contain no child keys.
                unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, key.as_ptr()) };
            }
        }
    }

    #[test]
    fn command_line_quotes_executable_and_ends_with_nul() {
        let command = command_line(
            Path::new(r"C:\Program Files\Rosetun\rosetun-gui.exe"),
            "--hidden",
        );
        let expected: Vec<u16> = "\"C:\\Program Files\\Rosetun\\rosetun-gui.exe\" --hidden\0"
            .encode_utf16()
            .collect();
        assert_eq!(command, expected);
    }

    #[test]
    fn registry_value_lifecycle_and_approval() {
        let key = TestKey {
            root: format!("Software\\Rosetun-test-{}", std::process::id()),
        };
        let run = format!("{}\\Run", key.root);
        let approved = format!("{}\\Approved", key.root);
        let command: Vec<u8> = command_line(Path::new(r"C:\Rosetun\rosetun-gui.exe"), "--hidden")
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(!autostart_enabled_at(&run, &approved, VALUE_NAME).unwrap());
        write_value(&run, VALUE_NAME, REG_SZ, &command).unwrap();
        assert_eq!(
            read_value(&run, VALUE_NAME, RRF_RT_REG_SZ).unwrap(),
            Some(command)
        );
        assert!(autostart_enabled_at(&run, &approved, VALUE_NAME).unwrap());

        write_value(&approved, VALUE_NAME, REG_BINARY, &[0x03, 0]).unwrap();
        assert!(!autostart_enabled_at(&run, &approved, VALUE_NAME).unwrap());
        write_value(&approved, VALUE_NAME, REG_BINARY, &[0x04, 0]).unwrap();
        assert!(autostart_enabled_at(&run, &approved, VALUE_NAME).unwrap());
        delete_value(&approved, VALUE_NAME).unwrap();
        assert!(autostart_enabled_at(&run, &approved, VALUE_NAME).unwrap());

        delete_value(&run, VALUE_NAME).unwrap();
        delete_value(&run, VALUE_NAME).unwrap();
        assert_eq!(read_value(&run, VALUE_NAME, RRF_RT_REG_SZ).unwrap(), None);
        assert!(!autostart_enabled_at(&run, &approved, VALUE_NAME).unwrap());
    }
}
