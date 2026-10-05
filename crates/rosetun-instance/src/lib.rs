#![deny(unsafe_code)]

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

#[cfg(windows)]
pub use windows::{Activation, Instance, acquire};
