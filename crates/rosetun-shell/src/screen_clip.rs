use std::io;

use windows_sys::Win32::System::DataExchange::GetClipboardSequenceNumber;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Changes whenever anything is put on the clipboard; read before and after a screen clip.
pub fn clipboard_sequence() -> u32 {
    // SAFETY: no arguments, no pointers; returns 0 when the window station has no clipboard
    // access, which only means a change is never seen.
    unsafe { GetClipboardSequenceNumber() }
}

/// Opens the system snipping overlay (Windows 10 1809 and later); the clip goes to the clipboard.
///
/// The system draws the selection, so Rosetun never captures the screen itself.
pub fn start_screen_clip() -> io::Result<()> {
    let verb = wide("open");
    let target = wide("ms-screenclip:");
    // SAFETY: both strings are NUL-terminated UTF-16 that outlive the call; the null window,
    // parameters and directory are allowed. A fixed `ms-screenclip:` URI carries no user data.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // Values up to 32 are errors (documented as an `HINSTANCE` for compatibility).
    if result as usize > 32 {
        Ok(())
    } else {
        Err(io::Error::other("the snipping overlay could not be opened"))
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
