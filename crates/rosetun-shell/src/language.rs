use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use windows_sys::Win32::Globalization::{GetUserDefaultUILanguage, LCIDToLocaleName};

/// `LOCALE_NAME_MAX_LENGTH`: the longest locale name with its NUL.
const LOCALE_NAME_MAX_LENGTH: usize = 85;

/// The Windows display language of the signed-in user as a locale name such as `ru-RU`.
pub fn user_language() -> Option<String> {
    // SAFETY: This Windows ABI call takes no pointers or owned resources and returns a LANGID.
    let langid = unsafe { GetUserDefaultUILanguage() };
    let mut name = [0u16; LOCALE_NAME_MAX_LENGTH];
    // SAFETY: A LANGID is the LCID with the default sort order; `name` is a writable buffer
    // whose length in UTF-16 units is passed and that outlives the call.
    let written = unsafe {
        LCIDToLocaleName(
            u32::from(langid),
            name.as_mut_ptr(),
            LOCALE_NAME_MAX_LENGTH as i32,
            0,
        )
    };
    // The count includes the terminating NUL; zero is a failure.
    let length = usize::try_from(written).ok()?.checked_sub(1)?;
    OsString::from_wide(name.get(..length)?).into_string().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_display_language_has_a_language_subtag() {
        let name = user_language().unwrap();
        let language = name.split('-').next().unwrap();
        assert!((2..=3).contains(&language.len()), "{name}");
    }
}
