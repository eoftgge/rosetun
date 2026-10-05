use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, REG_DWORD, REG_SZ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
    RegGetValueW,
};

use crate::HwidError;

const MAX_VALUE_BYTES: u32 = 64 * 1024;
const MAX_READ_ATTEMPTS: usize = 4;

pub(super) fn read_string(subkey: &str, value: &'static str) -> Result<String, HwidError> {
    let bytes = read_value(subkey, value, RRF_RT_REG_SZ, REG_SZ)?;

    if bytes.len() < 2 || bytes.len() % 2 != 0 {
        return Err(HwidError::InvalidRegistryValue { value });
    }

    let mut units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();

    if units.pop() != Some(0) || units.contains(&0) {
        return Err(HwidError::InvalidRegistryValue { value });
    }

    String::from_utf16(&units).map_err(|_| HwidError::InvalidRegistryValue { value })
}

pub(super) fn read_dword(subkey: &str, value: &'static str) -> Result<u32, HwidError> {
    let bytes = read_value(subkey, value, RRF_RT_REG_DWORD, REG_DWORD)?;
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| HwidError::InvalidRegistryValue { value })?;

    Ok(u32::from_le_bytes(bytes))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn read_value(
    subkey: &str,
    value: &'static str,
    type_flags: u32,
    expected_type: u32,
) -> Result<Vec<u8>, HwidError> {
    let subkey_wide = wide(subkey);
    let value_wide = wide(value);
    let flags = type_flags | RRF_SUBKEY_WOW6464KEY;

    for _ in 0..MAX_READ_ATTEMPTS {
        let mut size = 0u32;
        let mut actual_type = 0u32;

        // SAFETY: RegGetValueW uses the Windows system ABI provided by windows-sys.
        // Both owned UTF-16 vectors are NUL-terminated and remain alive for the call.
        // The type and byte-count pointers refer to writable local u32 values.
        // A null data pointer requests only the required size; no data buffer is read.
        // HKLM is a predefined borrowed handle, so this code must not close it.
        // Restricting the registry type and view avoids interpreting unrelated data.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                subkey_wide.as_ptr(),
                value_wide.as_ptr(),
                flags,
                &mut actual_type,
                std::ptr::null_mut(),
                &mut size,
            )
        };

        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(HwidError::Registry {
                value,
                code: status,
            });
        }
        if size > MAX_VALUE_BYTES {
            return Err(HwidError::RegistryValueTooLarge { value });
        }
        if size == 0 || actual_type != expected_type {
            return Err(HwidError::InvalidRegistryValue { value });
        }

        let mut bytes = vec![0u8; size as usize];
        let mut returned_size = size;
        actual_type = 0;

        // SAFETY: RegGetValueW uses the Windows system ABI. The owned, NUL-terminated
        // name vectors, output locals and data vector remain alive throughout the call.
        // The byte count equals the initialized vector's writable capacity and length.
        // pvData is an opaque byte-buffer pointer; typed values are decoded afterwards
        // without assuming alignment. The API does not retain any of these pointers.
        // Growth is handled via ERROR_MORE_DATA, and output is consumed only on success
        // after validating both its type and its returned size.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                subkey_wide.as_ptr(),
                value_wide.as_ptr(),
                flags,
                &mut actual_type,
                bytes.as_mut_ptr().cast(),
                &mut returned_size,
            )
        };

        if status == ERROR_MORE_DATA {
            continue;
        }
        if status != ERROR_SUCCESS {
            return Err(HwidError::Registry {
                value,
                code: status,
            });
        }
        if actual_type != expected_type || returned_size == 0 || returned_size > size {
            return Err(HwidError::InvalidRegistryValue { value });
        }

        bytes.truncate(returned_size as usize);
        return Ok(bytes);
    }

    Err(HwidError::RegistryValueUnstable { value })
}
