use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::Graphics::Dwm::{DWMWA_CLOAK, DwmSetWindowAttribute};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MONITOR_DEFAULTTONULL, MONITOR_DEFAULTTOPRIMARY, MONITORINFO,
    MonitorFromPoint, MonitorFromWindow,
};
use windows_sys::Win32::UI::HiDpi::{
    GetDpiForMonitor, GetDpiForSystem, GetDpiForWindow, GetSystemMetricsForDpi, MDT_EFFECTIVE_DPI,
};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetSystemMetrics, GetWindowPlacement, IsIconic, IsWindowVisible, IsZoomed,
    KillTimer, SM_CXSMICON, SM_SHUTTINGDOWN, SW_HIDE, SW_SHOWNOACTIVATE, SWP_NOACTIVATE,
    SWP_NOMOVE, SWP_NOZORDER, SetTimer, SetWindowPlacement, SetWindowPos, WINDOWPLACEMENT,
    WM_NCDESTROY, WM_QUERYOPEN, WM_SHOWWINDOW, WM_TIMER, WPF_RESTORETOMAXIMIZED,
};

use crate::first_start::{ScreenRect, first_start_rect};

const CLOAK_SUBCLASS_ID: usize = 1;
const UNCLOAK_TIMER_ID: usize = 0x5254_434C;
/// A window that never appears is worse than a white frame.
const CLOAK_LIMIT_MS: u32 = 500;

/// Only the main window is subclassed, and only on its own thread.
static CLOAKED: AtomicBool = AtomicBool::new(false);

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

/// Hides the window from the screen with a DWM cloak each time it is about to
/// appear: shown from hidden (including eframe's own show after its first,
/// unseen frame) or restored from minimized. Until a frame painted while the
/// window is visible reaches DWM, the screen would show an empty white surface.
/// The caller lifts the cloak with [`uncloak_window`] once such a frame is
/// painted; a timer lifts it after `CLOAK_LIMIT_MS` regardless.
///
/// Call once, on the thread that owns the window.
pub fn cloak_on_show(hwnd: isize) -> io::Result<()> {
    // SAFETY: hwnd is the caller's live top-level window, owned by winit on this thread;
    // the subclass procedure is a static function and is removed again on WM_NCDESTROY,
    // so it never outlives the window. No reference data is passed.
    if unsafe { SetWindowSubclass(hwnd as HWND, Some(cloak_proc), CLOAK_SUBCLASS_ID, 0) } == 0 {
        return Err(io::Error::other("could not subclass the main window"));
    }
    Ok(())
}

/// Whether [`cloak_on_show`] has cloaked the window and it is still cloaked.
pub fn window_cloaked() -> bool {
    CLOAKED.load(Ordering::Relaxed)
}

pub fn uncloak_window(hwnd: isize) {
    set_cloak(hwnd as HWND, false);
}

/// Hides the window from the screen just before it is hidden or closed: with
/// `DWMWA_CLOAK` set, DWM has nothing to play a disappearing animation over and
/// the empty surface behind the composited picture never shows.
///
/// No timer is set: the window is about to leave. The next time it appears,
/// `cloak_on_show` cloaks it afresh, sets the timer and the caller lifts the
/// cloak once a frame is painted, so a window shown after this one is not
/// left invisible.
pub fn cloak_window(hwnd: isize) {
    let hwnd = hwnd as HWND;
    if !apply_cloak(hwnd, true) {
        return;
    }
    // A cloak for showing, if one was pending, ends with the window it was for.
    CLOAKED.store(false, Ordering::Relaxed);
    // SAFETY: hwnd is borrowed; killing a timer that is not set is harmless.
    unsafe { KillTimer(hwnd, UNCLOAK_TIMER_ID) };
}

/// Sets `DWMWA_CLOAK`; whether DWM accepted it.
fn apply_cloak(hwnd: HWND, cloaked: bool) -> bool {
    let value = windows_sys::core::BOOL::from(cloaked);
    // SAFETY: hwnd is borrowed for this ABI call; the pointer and size describe a BOOL on
    // this stack frame, which is what DWMWA_CLOAK reads.
    let result = unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_CLOAK as u32,
            (&raw const value).cast(),
            std::mem::size_of_val(&value) as u32,
        )
    };
    result >= 0
}

fn set_cloak(hwnd: HWND, cloaked: bool) {
    let accepted = apply_cloak(hwnd, cloaked);
    if cloaked {
        if !accepted {
            return;
        }
        CLOAKED.store(true, Ordering::Relaxed);
        // SAFETY: hwnd is borrowed; the timer posts WM_TIMER to the subclass procedure and
        // is killed with the same id. Failure only loses the fallback.
        unsafe { SetTimer(hwnd, UNCLOAK_TIMER_ID, CLOAK_LIMIT_MS, None) };
    } else {
        CLOAKED.store(false, Ordering::Relaxed);
        // SAFETY: hwnd is borrowed; killing a timer that is not set is harmless.
        unsafe { KillTimer(hwnd, UNCLOAK_TIMER_ID) };
    }
}

unsafe extern "system" fn cloak_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    id: usize,
    _data: usize,
) -> LRESULT {
    match message {
        // Both arrive before the window becomes visible.
        WM_SHOWWINDOW if wparam != 0 && !window_cloaked() => set_cloak(hwnd, true),
        WM_QUERYOPEN if !window_cloaked() => set_cloak(hwnd, true),
        WM_TIMER if wparam == UNCLOAK_TIMER_ID => {
            set_cloak(hwnd, false);
            return 0;
        }
        WM_NCDESTROY => {
            // SAFETY: removes the subclass installed by `cloak_on_show` with the same
            // procedure and id, on the window's own thread.
            unsafe { RemoveWindowSubclass(hwnd, Some(cloak_proc), id) };
        }
        _ => {}
    }
    // SAFETY: forwards the message unchanged to the next procedure in the chain (winit's).
    unsafe { DefSubclassProc(hwnd, message, wparam, lparam) }
}

/// Whether the Windows session is signing out or shutting down. winit leaves
/// `WM_QUERYENDSESSION` to the default handler, so this is the GUI's only view of it.
pub fn session_ending() -> bool {
    // SAFETY: no pointers; reads session-wide state.
    unsafe { GetSystemMetrics(SM_SHUTTINGDOWN) != 0 }
}

/// The small-icon width at the DPI of the taskbar's monitor, falling back to
/// the system DPI; 0 when Windows cannot tell. Tray icons are drawn at this size.
pub fn taskbar_small_icon_size() -> i32 {
    let class: Vec<u16> = "Shell_TrayWnd".encode_utf16().chain([0]).collect();
    // SAFETY: class is a NUL-terminated UTF-16 string that outlives the call, and a null
    // window name matches any; the returned window is borrowed, never owned or closed.
    let taskbar = unsafe { FindWindowW(class.as_ptr(), std::ptr::null()) };
    let dpi = if taskbar.is_null() {
        0
    } else {
        // SAFETY: taskbar is borrowed for this ABI call; a window that has gone away gives 0.
        unsafe { GetDpiForWindow(taskbar) }
    };
    let dpi = if dpi == 0 {
        // SAFETY: no arguments; reads process-wide state.
        unsafe { GetDpiForSystem() }
    } else {
        dpi
    };
    // SAFETY: plain value arguments; returns 0 on failure.
    unsafe { GetSystemMetricsForDpi(SM_CXSMICON, dpi) }
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, KillTimer, WS_POPUP,
    };

    use super::{SavedWindow, UNCLOAK_TIMER_ID, cloak_window, set_cloak, window_cloaked};

    /// A window that is never shown, owned by the test's thread.
    struct Hidden(HWND);

    impl Hidden {
        fn new() -> Self {
            let class: Vec<u16> = "STATIC ".encode_utf16().collect();
            // SAFETY: a predefined class, no parent, menu, instance or creation data; the
            // window is destroyed on the same thread in `Drop`.
            let hwnd = unsafe {
                CreateWindowExW(
                    0,
                    class.as_ptr(),
                    class.as_ptr(),
                    WS_POPUP,
                    0,
                    0,
                    10,
                    10,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            };
            assert!(!hwnd.is_null(), "no test window");
            Self(hwnd)
        }

        /// Whether the unhide timer was set, clearing it.
        fn timer_was_set(&self) -> bool {
            // SAFETY: the window is this thread's; a timer that is not set gives 0.
            unsafe { KillTimer(self.0, UNCLOAK_TIMER_ID) != 0 }
        }
    }

    impl Drop for Hidden {
        fn drop(&mut self) {
            // SAFETY: the window was created by `new` on this thread.
            unsafe { DestroyWindow(self.0) };
        }
    }

    // One test: the cloak state is process-wide.
    #[test]
    fn cloaking_a_window_to_hide_it_sets_no_timer_and_showing_it_does() {
        let window = Hidden::new();
        let hwnd = window.0 as isize;

        set_cloak(window.0, true);
        assert!(window_cloaked());
        assert!(window.timer_was_set(), "a cloak for showing has a timer");

        set_cloak(window.0, true);
        cloak_window(hwnd);
        assert!(!window.timer_was_set(), "hiding left the timer running");
        assert!(
            !window_cloaked(),
            "the cloak for showing outlived the window it was for"
        );

        // The next show cloaks afresh and sets its own timer.
        set_cloak(window.0, true);
        assert!(window_cloaked());
        assert!(window.timer_was_set());
        set_cloak(window.0, false);
        assert!(!window_cloaked());
    }

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
