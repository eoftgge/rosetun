use std::io;

use windows_sys::Win32::Foundation::{HWND, POINT};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MONITOR_DEFAULTTONULL, MONITOR_DEFAULTTOPRIMARY, MONITORINFO,
    MonitorFromPoint, MonitorFromWindow,
};
use windows_sys::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetWindowPlacement, IsIconic, IsWindowVisible, IsZoomed, SW_HIDE, SW_SHOWNOACTIVATE,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOZORDER, SetWindowPlacement, SetWindowPos, WINDOWPLACEMENT,
    WPF_RESTORETOMAXIMIZED,
};

use crate::first_start::{ScreenRect, first_start_rect};

/// Where the window was. The rect is the normal (not maximized) one, in the
/// coordinates that `GetWindowPlacement` and `SetWindowPlacement` use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SavedWindow {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub maximized: bool,
}

impl SavedWindow {
    /// Width and height are positive and below 32768.
    pub fn is_valid(&self) -> bool {
        let width = i64::from(self.right) - i64::from(self.left);
        let height = i64::from(self.bottom) - i64::from(self.top);
        (1..32768).contains(&width) && (1..32768).contains(&height)
    }
}

fn current_placement(hwnd: HWND) -> io::Result<WINDOWPLACEMENT> {
    // SAFETY: WINDOWPLACEMENT has no pointers or owned resources and is valid when zeroed.
    let mut placement: WINDOWPLACEMENT = unsafe { std::mem::zeroed() };
    placement.length = std::mem::size_of::<WINDOWPLACEMENT>() as u32;
    // SAFETY: hwnd is passed to the Windows ABI, and placement points to writable storage
    // with the required length for this call.
    if unsafe { GetWindowPlacement(hwnd, &mut placement) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(placement)
}

/// The window's normal rect and whether it is maximized.
pub fn saved_window(hwnd: isize) -> Option<SavedWindow> {
    let hwnd = hwnd as HWND;
    let placement = current_placement(hwnd).ok()?;
    let rect = placement.rcNormalPosition;
    // SAFETY: hwnd is borrowed for the duration of this Windows ABI call; no ownership changes.
    let maximized = unsafe { IsZoomed(hwnd) } != 0;
    // SAFETY: hwnd is borrowed for the duration of this Windows ABI call; no ownership changes.
    let minimized = unsafe { IsIconic(hwnd) } != 0;
    Some(SavedWindow {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
        maximized: maximized || (minimized && placement.flags & WPF_RESTORETOMAXIMIZED != 0),
    })
}

/// Puts the window where it was, or sizes it from the screen when nothing
/// was saved. Never shows or hides the window and never maximizes it.
pub fn place_window(hwnd: isize, saved: Option<SavedWindow>) -> io::Result<()> {
    let hwnd = hwnd as HWND;
    if let Some(saved) = saved {
        let mut placement = current_placement(hwnd)?;
        placement.rcNormalPosition.left = saved.left;
        placement.rcNormalPosition.top = saved.top;
        placement.rcNormalPosition.right = saved.right;
        placement.rcNormalPosition.bottom = saved.bottom;
        placement.flags = 0;
        // SAFETY: hwnd is borrowed for this Windows ABI call; visibility is queried, not changed.
        placement.showCmd = if unsafe { IsWindowVisible(hwnd) } != 0 {
            SW_SHOWNOACTIVATE as u32
        } else {
            SW_HIDE as u32
        };
        // SAFETY: hwnd is borrowed and placement points to an initialized, correctly sized
        // structure; Windows adjusts offscreen coordinates during this ABI call.
        if unsafe { SetWindowPlacement(hwnd, &placement) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // winit may resize a window after a DPI change during SetWindowPlacement.
        // SAFETY: hwnd is borrowed; the flags preserve position, z-order and activation.
        if unsafe {
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                0,
                0,
                saved.right - saved.left,
                saved.bottom - saved.top,
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        return Ok(());
    }

    // SAFETY: hwnd is borrowed; Windows returns a monitor handle it owns, not one we free.
    let mut monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL) };
    if monitor.is_null() {
        // SAFETY: The point is passed by value; the returned monitor handle is owned by Windows.
        monitor = unsafe { MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY) };
    }
    if monitor.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: MONITORINFO has no pointers or owned resources and is valid when zeroed.
    let mut info: MONITORINFO = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
    // SAFETY: monitor is a borrowed Windows handle and info points to a writable,
    // correctly sized structure for this ABI call.
    if unsafe { GetMonitorInfoW(monitor, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut dpi_x = 0;
    let mut dpi_y = 0;
    // SAFETY: monitor is a borrowed Windows handle, and the output pointers remain valid
    // for the duration of this ABI call.
    if unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut dpi_x, &mut dpi_y) } != 0
        || dpi_x == 0
    {
        return Err(io::Error::last_os_error());
    }
    let work = info.rcWork;
    let rect = first_start_rect(
        ScreenRect {
            left: work.left,
            top: work.top,
            right: work.right,
            bottom: work.bottom,
        },
        f64::from(dpi_x) / 96.0,
    );
    for _ in 0..2 {
        // winit may resize the window after the first placement changes its DPI.
        // SAFETY: hwnd is borrowed; the flags preserve visibility, z-order and activation.
        if unsafe {
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                rect.left,
                rect.top,
                rect.right - rect.left,
                rect.bottom - rect.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::SavedWindow;

    #[test]
    fn saved_window_requires_reasonable_positive_dimensions() {
        let valid = SavedWindow {
            left: -100,
            top: 15,
            right: 1100,
            bottom: 815,
            maximized: true,
        };
        assert!(valid.is_valid());
        assert!(
            !SavedWindow {
                right: valid.left,
                ..valid
            }
            .is_valid()
        );
        assert!(
            !SavedWindow {
                bottom: valid.top - 1,
                ..valid
            }
            .is_valid()
        );
        assert!(
            !SavedWindow {
                right: valid.left + 40000,
                ..valid
            }
            .is_valid()
        );
    }
}
