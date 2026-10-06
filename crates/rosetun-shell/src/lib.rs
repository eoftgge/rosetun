#![deny(unsafe_code)]

#[cfg(windows)]
#[allow(unsafe_code)]
mod autostart;
#[cfg(windows)]
#[allow(unsafe_code)]
mod instance;

#[cfg(windows)]
pub use autostart::{autostart_enabled, disable_autostart, enable_autostart};
#[cfg(windows)]
pub use instance::{Activation, Instance, acquire};
