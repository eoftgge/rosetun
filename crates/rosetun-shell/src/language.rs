use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;

/// The Windows display language of the signed-in user is Russian.
pub fn user_language_is_russian() -> bool {
    // SAFETY: This Windows ABI call takes no pointers or owned resources and returns a LANGID.
    let langid = unsafe { GetUserDefaultUILanguage() };
    langid & 0x3ff == 0x19
}
