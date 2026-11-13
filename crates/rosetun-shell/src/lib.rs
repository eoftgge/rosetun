#![deny(unsafe_code)]

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod autostart;
#[cfg(target_os = "linux")]
mod autostart_linux;
#[cfg(target_os = "linux")]
mod desktop_linux;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod elevated;
#[cfg(target_os = "linux")]
mod file_dialog_linux;
#[cfg(any(windows, test))]
mod first_start;
#[cfg(target_os = "linux")]
mod folders_linux;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod instance;
#[cfg(target_os = "linux")]
#[expect(
    unsafe_code,
    reason = "socket credentials over libc; every unsafe block carries a SAFETY comment"
)]
mod instance_linux;
#[cfg(any(windows, target_os = "linux"))]
mod link_frame;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod link_pipe;
#[expect(
    unsafe_code,
    reason = "a file mapping; the unsafe block carries a SAFETY comment"
)]
mod mapped_file;
#[cfg_attr(
    windows,
    expect(
        unsafe_code,
        reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
    )
)]
mod program_icon;
#[cfg(target_os = "linux")]
#[expect(
    unsafe_code,
    reason = "the account's name over libc; every unsafe block carries a SAFETY comment"
)]
mod service_group_linux;
#[cfg(target_os = "linux")]
mod status_item;

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod fonts;
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
#[cfg(target_os = "linux")]
#[expect(
    unsafe_code,
    reason = "libc time calls; every unsafe block carries a SAFETY comment"
)]
mod system_info_linux;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod tray_notice;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod window;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod wininet;

mod desktop_proxy;
#[cfg(target_os = "linux")]
mod desktop_proxy_linux;

#[cfg(windows)]
pub use autostart::{
    Autostart, autostart_enabled, disable_autostart, enable_autostart, move_autostart_to_task,
};
#[cfg(target_os = "linux")]
pub use autostart_linux::{Autostart, autostart_enabled, disable_autostart, enable_autostart};
#[cfg(target_os = "linux")]
pub use desktop_linux::{tray_notice, user_language};
pub use desktop_proxy::{DesktopProxy, ProxyRestore, ProxySet};
#[cfg(windows)]
pub use elevated::run_elevated;
#[cfg(target_os = "linux")]
pub use file_dialog_linux::{FileDialogError, FileFilter, pick_file, save_file};
#[cfg(target_os = "linux")]
pub use folders_linux::open_folder;
#[cfg(windows)]
pub use fonts::fonts_dir;
#[cfg(windows)]
pub use instance::{Activation, Instance, acquire};
#[cfg(target_os = "linux")]
pub use instance_linux::{Activation, Instance, InstanceMessage, acquire, send_to_first};
#[cfg(windows)]
pub use language::user_language;
#[cfg(any(windows, target_os = "linux"))]
pub use link_frame::MAX_LINK_BYTES;
#[cfg(windows)]
pub use link_pipe::{LinkListener, send_link};
pub use mapped_file::{MappedFile, map_protected_file};
#[cfg(windows)]
pub use program_icon::ComApartment;
pub use program_icon::{IconImage, program_icon};
#[cfg(windows)]
pub use screen_clip::{clipboard_sequence, start_screen_clip};
#[cfg(target_os = "linux")]
pub use service_group_linux::{ServiceGroupJoin, join_service_group};
#[cfg(target_os = "linux")]
pub use status_item::{StatusItem, TrayEntry, TrayInput, TrayItem, TrayPixmap};
#[cfg(windows)]
pub use system_checks::{proxy_settings, windivert_running};
#[cfg(windows)]
pub use system_info::{local_report_timestamp, windows_build};
#[cfg(target_os = "linux")]
pub use system_info_linux::{local_report_timestamp, os_description};
#[cfg(windows)]
pub use tray_notice::tray_notice;
#[cfg(windows)]
pub use window::{
    SavedWindow, WindowActivity, cloak_on_show, cloak_window, paint_window_surface, place_window,
    quiet_moves, saved_window, session_ending, stop_raw_mouse_input, take_window_activity,
    taskbar_small_icon_size, uncloak_window, window_cloaked,
};
