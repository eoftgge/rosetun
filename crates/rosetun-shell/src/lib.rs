#![deny(unsafe_code)]

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod autostart;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod elevated;
#[cfg(any(windows, test))]
mod first_start;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod instance;

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod language;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod screen_clip;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod system_checks;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod system_info;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod window;

#[cfg(windows)]
pub use autostart::{autostart_enabled, disable_autostart, enable_autostart};
#[cfg(windows)]
pub use elevated::run_elevated;
#[cfg(windows)]
pub use instance::{Activation, Instance, acquire};
#[cfg(windows)]
pub use language::user_language_is_russian;
#[cfg(windows)]
pub use screen_clip::{clipboard_sequence, start_screen_clip};
#[cfg(windows)]
pub use system_checks::{proxy_settings, windivert_running};
#[cfg(windows)]
pub use system_info::{local_report_timestamp, windows_build};
#[cfg(windows)]
pub use window::{SavedWindow, place_window, saved_window, taskbar_small_icon_size};
