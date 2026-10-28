use std::io;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Shell::{
    NIF_INFO, NIIF_NOSOUND, NIIF_USER, NIM_MODIFY, NOTIFYICONDATAW, Shell_NotifyIconW,
};

/// Shows a silent notification from an existing notification-area icon,
/// with that icon. Windows 10 and 11 show it as an ordinary notification
/// without registering the application.
///
/// `window` and `icon_id` name the icon as it was added with `NIM_ADD`.
/// Text longer than the fixed buffers is cut.
pub fn tray_notice(window: HWND, icon_id: u32, title: &str, text: &str) -> io::Result<()> {
    let mut data = NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: window,
        uID: icon_id,
        uFlags: NIF_INFO,
        dwInfoFlags: NIIF_USER | NIIF_NOSOUND,
        ..Default::default()
    };
    fill(&mut data.szInfoTitle, title);
    fill(&mut data.szInfo, text);
    // SAFETY: `data` is sized for this ABI and only read during the call;
    // its strings are NUL-terminated inside their fixed buffers. NIM_MODIFY
    // changes nothing but the notification of an icon this process added,
    // and fails without effect when `window` and `icon_id` name no icon.
    if unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) } == 0 {
        return Err(io::Error::other("the tray icon took no notification"));
    }
    Ok(())
}

/// Copies `text` as UTF-16, cut at a whole character so the last unit stays NUL.
fn fill(buffer: &mut [u16], text: &str) {
    let mut used = 0;
    for character in text.chars() {
        let mut units = [0; 2];
        let encoded = character.encode_utf16(&mut units);
        if used + encoded.len() >= buffer.len() {
            break;
        }
        buffer[used..used + encoded.len()].copy_from_slice(encoded);
        used += encoded.len();
    }
}

#[cfg(test)]
mod tests {
    use super::fill;

    #[test]
    fn text_is_cut_at_a_whole_character_and_stays_terminated() {
        let mut buffer = [0u16; 4];
        fill(&mut buffer, "ab😀");
        assert_eq!(buffer, [u16::from(b'a'), u16::from(b'b'), 0, 0]);
        let mut buffer = [0u16; 4];
        fill(&mut buffer, "abc");
        assert_eq!(buffer[3], 0);
        assert_eq!(String::from_utf16(&buffer[..3]).unwrap(), "abc");
    }
}
