use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, SetEvent, WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{ASFW_ANY, AllowSetForegroundWindow};

const EVENT_NAME: &str = "Local\\Rosetun.Gui.Activate";

#[derive(Debug)]
pub enum Instance {
    /// No other instance is running; later ones reach this one through it.
    First(Activation),
    /// Another instance is running and has been asked to show its window.
    Other,
}

#[derive(Debug)]
pub struct Activation {
    event: OwnedHandle,
}

impl Activation {
    /// Blocks until a later instance asks this one to show its window.
    pub fn wait(&self) -> io::Result<()> {
        // SAFETY: The owned event remains open for the duration of the Windows ABI call.
        let result = unsafe { WaitForSingleObject(self.event.as_raw_handle() as HANDLE, INFINITE) };
        if result == WAIT_OBJECT_0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

pub fn acquire() -> io::Result<Instance> {
    acquire_named(EVENT_NAME)
}

fn acquire_named(name: &str) -> io::Result<Instance> {
    let name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: The null-terminated name is valid for this Windows ABI call. The
    // event is non-inheritable and its handle is transferred to OwnedHandle below.
    let event = unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) };
    // SAFETY: GetLastError takes no arguments; read the calling thread's value
    // immediately after CreateEventW, before another Windows call can change it.
    let last_error = unsafe { GetLastError() };
    if event.is_null() {
        return Err(io::Error::from_raw_os_error(last_error as i32));
    }
    let already_exists = last_error == ERROR_ALREADY_EXISTS;
    // SAFETY: CreateEventW returned a live owned handle, closed exactly once
    // by OwnedHandle on both the first-instance and subsequent-instance paths.
    let event = unsafe { OwnedHandle::from_raw_handle(event) };
    if already_exists {
        // The process being launched can delegate foreground permission to the
        // first process before the activation event wakes its window.
        // SAFETY: The Windows ABI call takes a constant process identifier.
        unsafe { AllowSetForegroundWindow(ASFW_ANY) };
        // SAFETY: The owned event remains open for the duration of the call.
        if unsafe { SetEvent(event.as_raw_handle() as HANDLE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Instance::Other)
    } else {
        Ok(Instance::First(Activation { event }))
    }
}

#[cfg(test)]
mod tests {
    use super::{Instance, acquire_named};

    #[test]
    fn later_instance_wakes_the_first() {
        let name = format!("Local\\Rosetun.Gui.Activate.Test.{}", std::process::id());
        let Instance::First(activation) = acquire_named(&name).unwrap() else {
            panic!("first acquisition should own the event");
        };
        assert!(matches!(acquire_named(&name).unwrap(), Instance::Other));
        activation.wait().unwrap();
    }
}
