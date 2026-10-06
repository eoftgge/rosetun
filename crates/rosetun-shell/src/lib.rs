#![deny(unsafe_code)]

#[cfg(windows)]
#[allow(unsafe_code)]
mod autostart;
#[cfg(windows)]
#[allow(unsafe_code)]
mod display;
#[cfg(windows)]
#[allow(unsafe_code)]
mod instance;

#[cfg(windows)]
#[allow(unsafe_code)]
mod language;

#[cfg(windows)]
pub use autostart::{autostart_enabled, disable_autostart, enable_autostart};
#[cfg(windows)]
pub use display::{WorkArea, primary_work_area};
#[cfg(windows)]
pub use instance::{Activation, Instance, acquire};
#[cfg(windows)]
pub use language::user_language_is_russian;
