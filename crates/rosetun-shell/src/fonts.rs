use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{FOLDERID_Fonts, KF_FLAG_DONT_VERIFY, SHGetKnownFolderPath};
use windows_sys::core::PWSTR;

/// The system fonts folder, `None` when Windows does not name one.
pub fn fonts_dir() -> Option<PathBuf> {
    let mut path: PWSTR = std::ptr::null_mut();
    // SAFETY: The GUID is a static constant, the null token asks for the current user, and
    // `path` is a valid out pointer. On return Windows owns a NUL-terminated buffer in `path`
    // (also on failure, possibly null) that the caller frees with `CoTaskMemFree` below.
    let result = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_Fonts,
            KF_FLAG_DONT_VERIFY as u32,
            std::ptr::null_mut(),
            &mut path,
        )
    };
    let dir = (result >= 0 && !path.is_null()).then(|| {
        // SAFETY: On success `path` points to a NUL-terminated UTF-16 string that stays valid
        // until it is freed below; the length is counted up to the terminator.
        let wide = unsafe {
            let length = (0..).take_while(|&offset| *path.add(offset) != 0).count();
            std::slice::from_raw_parts(path, length)
        };
        PathBuf::from(OsString::from_wide(wide))
    });
    // SAFETY: `path` came from `SHGetKnownFolderPath`, which requires this release whatever it
    // returned; `CoTaskMemFree` accepts null. The slice above is no longer used.
    unsafe { CoTaskMemFree(path.cast()) };
    dir.filter(|dir| !dir.as_os_str().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fonts_folder_is_an_absolute_existing_folder() {
        let dir = fonts_dir().unwrap();
        assert!(dir.is_absolute());
        assert!(dir.is_dir());
    }
}
