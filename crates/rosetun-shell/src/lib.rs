#![deny(unsafe_code)]

#[cfg(windows)]
#[allow(unsafe_code)]
mod instance;

#[cfg(windows)]
pub use instance::{Activation, Instance, acquire};
