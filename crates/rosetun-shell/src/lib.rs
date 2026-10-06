#![deny(unsafe_code)]

#[cfg(windows)]
#[allow(unsafe_code)]
mod autostart;
#[cfg(any(windows, test))]
mod first_start;
#[cfg(windows)]
#[allow(unsafe_code)]
mod instance;

#[cfg(windows)]
#[allow(unsafe_code)]
mod language;
#[cfg(windows)]
#[allow(unsafe_code)]
mod window;

#[cfg(windows)]
pub use autostart::{autostart_enabled, disable_autostart, enable_autostart};
#[cfg(windows)]
pub use instance::{Activation, Instance, acquire};
#[cfg(windows)]
pub use language::user_language_is_russian;
#[cfg(windows)]
pub use window::{SavedWindow, place_window, saved_window};
