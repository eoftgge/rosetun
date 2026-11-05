use std::cell::Cell;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use windows_sys::Win32::Devices::HumanInterfaceDevice::{
    HID_USAGE_GENERIC_MOUSE, HID_USAGE_PAGE_GENERIC,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::Graphics::Dwm::{DWMWA_CLOAK, DwmSetWindowAttribute};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITOR_DEFAULTTONULL, MONITOR_DEFAULTTOPRIMARY,
    MONITORINFO, MonitorFromPoint, MonitorFromWindow,
};
use windows_sys::Win32::UI::HiDpi::{
    GetDpiForMonitor, GetDpiForSystem, GetDpiForWindow, GetSystemMetricsForDpi, MDT_EFFECTIVE_DPI,
};
use windows_sys::Win32::UI::Input::{RAWINPUTDEVICE, RIDEV_REMOVE, RegisterRawInputDevices};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DefWindowProcW, FindWindowW, GetSystemMetrics, GetWindowPlacement, IsIconic, IsWindowVisible,
    IsZoomed, KillTimer, SIZE_MINIMIZED, SM_CXSMICON, SM_SHUTTINGDOWN, SW_HIDE, SW_SHOWNOACTIVATE,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOZORDER, SetTimer, SetWindowPlacement, SetWindowPos,
    WINDOWPLACEMENT, WINDOWPOS, WM_DPICHANGED, WM_ENTERSIZEMOVE, WM_EXITSIZEMOVE, WM_KEYFIRST,
    WM_KEYLAST, WM_MOUSEFIRST, WM_MOUSELAST, WM_NCDESTROY, WM_QUERYOPEN, WM_SHOWWINDOW, WM_SIZE,
    WM_TIMER, WM_WINDOWPOSCHANGED, WPF_RESTORETOMAXIMIZED,
};

use crate::first_start::{ScreenRect, first_start_rect};

const CLOAK_SUBCLASS_ID: usize = 1;
const MOVE_SUBCLASS_ID: usize = 2;
const UNCLOAK_TIMER_ID: usize = 0x5254_434C;
/// A window that never appears is worse than a white frame.
const CLOAK_LIMIT_MS: u32 = 500;

/// Only the main window is subclassed, and only on its own thread.
static CLOAKED: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// What [`quiet_moves`] saw on this thread, which owns the window.
    static ACTIVITY: Cell<WindowActivity> = Cell::default();
}

/// What [`quiet_moves`] remembers between messages. It lives in the subclass's
/// reference data and is touched only on the window's thread.
#[derive(Debug)]
struct MoveWatch {
    /// Inside the modal loop Windows runs while the user drags or sizes the window.
    in_move_loop: Cell<bool>,
    /// The monitor that held most of the window after its last position change.
    monitor: Cell<usize>,
}

/// What happened to the window since the last [`take_window_activity`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WindowActivity {
    /// `WM_SIZE` with an area: eframe configures the swap chain again for each one.
    pub size_changes: u32,
    pub dpi_changes: u32,
    pub monitor_changes: u32,
    /// The earliest size or DPI change.
    pub surface_changed_at: Option<Instant>,
    /// The earliest mouse or keyboard message.
    pub input_at: Option<Instant>,
}

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

/// Keeps winit from hearing that the window moved while the user drags it,
/// unless it reached another monitor. A move changes nothing inside the
/// window, yet eframe answers each move winit reports with a frame: a stream
/// of vsync-bound presents that holds the drag back and, on a variable-refresh
/// display, stops abruptly with the drag. Size and DPI changes still reach
/// winit, as `WM_SIZE` and `WM_DPICHANGED`, and moves outside a drag
/// (restoring, placing, snapping from the keyboard) are reported as before.
///
/// Call once, on the thread that owns the window.
pub fn quiet_moves(hwnd: isize) -> io::Result<()> {
    let hwnd = hwnd as HWND;
    // SAFETY: hwnd is borrowed; the monitor handle is owned by Windows and only compared.
    let monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) } as usize;
    let watch = Box::into_raw(Box::new(MoveWatch {
        in_move_loop: Cell::new(false),
        monitor: Cell::new(monitor),
    }));
    // SAFETY: hwnd is the caller's live top-level window, owned by winit on this thread. The
    // subclass procedure is a static function; the reference data is the box above, which
    // `move_proc` frees on WM_NCDESTROY after removing the subclass, so neither outlives
    // the window.
    if unsafe { SetWindowSubclass(hwnd, Some(move_proc), MOVE_SUBCLASS_ID, watch as usize) } == 0 {
        // SAFETY: the subclass was not installed, so this is the only pointer to the box.
        drop(unsafe { Box::from_raw(watch) });
        return Err(io::Error::other("could not subclass the main window"));
    }
    Ok(())
}

/// What [`quiet_moves`] saw since the last call, which starts the count again.
/// Call on the thread that owns the window.
pub fn take_window_activity() -> WindowActivity {
    ACTIVITY.take()
}

/// Whether a position change goes on to winit, which reports a move as
/// `WindowEvent::Moved`. A frame on another monitor picks up its scale and
/// refresh; inside a drag on the same monitor there is nothing to draw.
fn forwards_position_change(in_move_loop: bool, moved: bool, monitor_changed: bool) -> bool {
    !in_move_loop || !moved || monitor_changed
}

/// Counts what the message says about the window. Runs for every message, so
/// it reads the clock only for the first of a kind since the last look.
fn note_activity(message: u32, wparam: WPARAM, lparam: LPARAM) {
    let mut activity = ACTIVITY.get();
    match message {
        WM_SIZE if size_has_area(wparam, lparam) => {
            activity.size_changes = activity.size_changes.saturating_add(1);
            activity.surface_changed_at.get_or_insert_with(Instant::now);
        }
        WM_DPICHANGED => {
            activity.dpi_changes = activity.dpi_changes.saturating_add(1);
            activity.surface_changed_at.get_or_insert_with(Instant::now);
        }
        WM_MOUSEFIRST..=WM_MOUSELAST | WM_KEYFIRST..=WM_KEYLAST => {
            activity.input_at.get_or_insert_with(Instant::now);
        }
        _ => return,
    }
    ACTIVITY.set(activity);
}

/// eframe ignores a size with no area, which is how minimizing arrives.
fn size_has_area(wparam: WPARAM, lparam: LPARAM) -> bool {
    let size = lparam as usize;
    wparam != SIZE_MINIMIZED as usize && size & 0xFFFF != 0 && (size >> 16) & 0xFFFF != 0
}

unsafe extern "system" fn move_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    id: usize,
    data: usize,
) -> LRESULT {
    let watch = data as *mut MoveWatch;
    note_activity(message, wparam, lparam);
    match message {
        WM_ENTERSIZEMOVE | WM_EXITSIZEMOVE => {
            // SAFETY: data is the box `quiet_moves` installed; it is freed only on
            // WM_NCDESTROY, the window's last message, on this same thread.
            unsafe { &*watch }
                .in_move_loop
                .set(message == WM_ENTERSIZEMOVE);
        }
        WM_WINDOWPOSCHANGED => {
            // SAFETY: as above.
            let watch = unsafe { &*watch };
            // SAFETY: for this message lparam points to a WINDOWPOS valid during the call.
            let flags = unsafe { (*(lparam as *const WINDOWPOS)).flags };
            // SAFETY: hwnd is borrowed; the monitor handle is owned by Windows and only compared.
            let monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) } as usize;
            let monitor_changed = watch.monitor.replace(monitor) != monitor;
            if monitor_changed {
                let mut activity = ACTIVITY.get();
                activity.monitor_changes = activity.monitor_changes.saturating_add(1);
                ACTIVITY.set(activity);
            }
            if !forwards_position_change(
                watch.in_move_loop.get(),
                flags & SWP_NOMOVE == 0,
                monitor_changed,
            ) {
                // What winit does after reporting the move: the default handler, which
                // sends WM_SIZE (still seen by winit) and WM_MOVE.
                // SAFETY: the message and its arguments exactly as received.
                return unsafe { DefWindowProcW(hwnd, message, wparam, lparam) };
            }
        }
        WM_NCDESTROY => {
            // SAFETY: removes the subclass installed by `quiet_moves` with the same procedure
            // and id, on the window's own thread; it is never called with `data` again.
            unsafe { RemoveWindowSubclass(hwnd, Some(move_proc), id) };
            // SAFETY: the box leaked by `quiet_moves`; with the subclass gone nothing else
            // holds the pointer.
            drop(unsafe { Box::from_raw(watch) });
        }
        _ => {}
    }
    // SAFETY: forwards the message unchanged to the next procedure in the chain.
    unsafe { DefSubclassProc(hwnd, message, wparam, lparam) }
}

/// Stops raw mouse input (`WM_INPUT`) for the whole process. winit registers it
/// when its event loop starts and passes every raw movement on as a device
/// event; eframe answers each one with a frame while the pointer is over the
/// window or a button is held. During a drag both are true for its whole
/// length, since the window moves under the pointer and the button is released
/// inside the move loop, where winit does not see it. So every movement of the
/// mouse asked for a frame that nothing on screen needed, and the drag ran as a
/// stream of vsync-bound presents. Ordinary pointer messages (`WM_MOUSEMOVE`, buttons, wheel) are unaffected,
/// and they are all the window needs.
///
/// Call after the event loop exists; a later winit registration would undo it.
pub fn stop_raw_mouse_input() -> io::Result<()> {
    let mouse = RAWINPUTDEVICE {
        usUsagePage: HID_USAGE_PAGE_GENERIC,
        usUsage: HID_USAGE_GENERIC_MOUSE,
        dwFlags: RIDEV_REMOVE,
        // RIDEV_REMOVE requires no target window.
        hwndTarget: std::ptr::null_mut(),
    };
    // SAFETY: one initialized RAWINPUTDEVICE on this stack frame with its exact size; the call
    // reads it and keeps no pointer. Removing a registration only changes this process's input.
    let removed =
        unsafe { RegisterRawInputDevices(&mouse, 1, std::mem::size_of::<RAWINPUTDEVICE>() as u32) };
    if removed == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    use std::cell::Cell;

    use windows_sys::Win32::Devices::HumanInterfaceDevice::{
        HID_USAGE_GENERIC_MOUSE, HID_USAGE_PAGE_GENERIC,
    };
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::UI::Input::{
        GetRegisteredRawInputDevices, RAWINPUTDEVICE, RegisterRawInputDevices,
    };
    use windows_sys::Win32::UI::Shell::{DefSubclassProc, SetWindowSubclass};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, KillTimer, SIZE_MINIMIZED, SIZE_RESTORED, SWP_NOACTIVATE,
        SWP_NOSIZE, SWP_NOZORDER, SendMessageW, SetWindowPos, WM_DPICHANGED, WM_ENTERSIZEMOVE,
        WM_EXITSIZEMOVE, WM_KEYDOWN, WM_MOUSEMOVE, WM_MOVE, WM_SIZE, WM_WINDOWPOSCHANGED, WS_POPUP,
    };

    use super::{
        SavedWindow, UNCLOAK_TIMER_ID, WindowActivity, cloak_window, forwards_position_change,
        quiet_moves, set_cloak, size_has_area, stop_raw_mouse_input, take_window_activity,
        window_cloaked,
    };

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

    /// What reached the procedure below `quiet_moves`, where winit would be.
    #[derive(Default)]
    struct Seen {
        position_changes: Cell<u32>,
        moves: Cell<u32>,
        sizes: Cell<u32>,
    }

    unsafe extern "system" fn record(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
        _id: usize,
        data: usize,
    ) -> LRESULT {
        // SAFETY: data points to the test's `Seen`, which outlives the window.
        let seen = unsafe { &*(data as *const Seen) };
        match message {
            WM_WINDOWPOSCHANGED => seen.position_changes.set(seen.position_changes.get() + 1),
            WM_MOVE => seen.moves.set(seen.moves.get() + 1),
            WM_SIZE => seen.sizes.set(seen.sizes.get() + 1),
            _ => {}
        }
        // SAFETY: forwards the message unchanged.
        unsafe { DefSubclassProc(hwnd, message, wparam, lparam) }
    }

    fn move_to(window: &Hidden, x: i32) {
        // SAFETY: the window is this thread's; only its position changes.
        let moved = unsafe {
            SetWindowPos(
                window.0,
                std::ptr::null_mut(),
                x,
                0,
                0,
                0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
            )
        };
        assert_ne!(moved, 0, "the test window did not move");
    }

    #[test]
    fn a_drag_on_one_monitor_reaches_the_window_without_a_move_report() {
        let seen = Seen::default();
        let window = Hidden::new();
        // SAFETY: the window is this thread's; `seen` outlives it (dropped after it).
        let installed =
            unsafe { SetWindowSubclass(window.0, Some(record), 99, (&raw const seen) as usize) };
        assert_ne!(installed, 0);
        quiet_moves(window.0 as isize).expect("subclass the test window");

        move_to(&window, 5);
        assert_eq!(
            seen.position_changes.get(),
            1,
            "a move outside a drag is reported"
        );

        // SAFETY: the window is this thread's; the messages carry no pointers.
        unsafe { SendMessageW(window.0, WM_ENTERSIZEMOVE, 0, 0) };
        let moves = seen.moves.get();
        move_to(&window, 15);
        move_to(&window, 25);
        assert_eq!(
            seen.position_changes.get(),
            1,
            "a move inside a drag reached winit"
        );
        assert_eq!(seen.moves.get(), moves + 2, "the default handling went on");
        // winit answers WM_SIZE with `Resized`, and eframe paints at once for that.
        assert_eq!(seen.sizes.get(), 0, "a move inside a drag reported a size");

        // SAFETY: as above.
        unsafe { SendMessageW(window.0, WM_EXITSIZEMOVE, 0, 0) };
        move_to(&window, 35);
        assert_eq!(seen.position_changes.get(), 2);
    }

    #[test]
    fn the_window_activity_counts_size_and_dpi_changes_and_starts_again() {
        let window = Hidden::new();
        assert_eq!(take_window_activity(), WindowActivity::default());
        quiet_moves(window.0 as isize).expect("subclass the test window");

        // SAFETY: the window is this thread's; the messages carry only values. The
        // WM_DPICHANGED has no rect, which `quiet_moves` does not read and STATIC ignores.
        unsafe {
            SendMessageW(window.0, WM_SIZE, SIZE_RESTORED as usize, 0x0020_0040);
            SendMessageW(window.0, WM_SIZE, SIZE_RESTORED as usize, 0x0030_0040);
            SendMessageW(window.0, WM_SIZE, SIZE_MINIMIZED as usize, 0);
            SendMessageW(window.0, WM_DPICHANGED, 0x0060_0060, 0);
        }
        let activity = take_window_activity();
        assert_eq!(activity.size_changes, 2, "minimizing is not a size change");
        assert_eq!(activity.dpi_changes, 1);
        assert!(activity.surface_changed_at.is_some());
        assert!(activity.input_at.is_none());

        // SAFETY: as above.
        unsafe {
            SendMessageW(window.0, WM_MOUSEMOVE, 0, 0);
            SendMessageW(window.0, WM_KEYDOWN, 0, 0);
        }
        let activity = take_window_activity();
        assert_eq!(activity.size_changes, 0, "the count started again");
        assert!(activity.surface_changed_at.is_none());
        assert!(activity.input_at.is_some());
    }

    #[test]
    fn a_size_without_an_area_is_no_change_of_the_surface() {
        assert!(size_has_area(SIZE_RESTORED as usize, 0x0020_0040));
        assert!(!size_has_area(SIZE_RESTORED as usize, 0x0020_0000));
        assert!(!size_has_area(SIZE_RESTORED as usize, 0x0000_0040));
        assert!(!size_has_area(SIZE_MINIMIZED as usize, 0x0020_0040));
    }

    fn registered_mouse_input() -> bool {
        let mut devices = [RAWINPUTDEVICE {
            usUsagePage: 0,
            usUsage: 0,
            dwFlags: 0,
            hwndTarget: std::ptr::null_mut(),
        }; 8];
        let mut count = devices.len() as u32;
        // SAFETY: the buffer holds `count` devices of the given size and outlives the call.
        let listed = unsafe {
            GetRegisteredRawInputDevices(
                devices.as_mut_ptr(),
                &mut count,
                std::mem::size_of::<RAWINPUTDEVICE>() as u32,
            )
        };
        assert_ne!(listed, u32::MAX, "could not list raw input devices");
        devices[..listed as usize].iter().any(|device| {
            device.usUsagePage == HID_USAGE_PAGE_GENERIC
                && device.usUsage == HID_USAGE_GENERIC_MOUSE
        })
    }

    #[test]
    fn raw_mouse_input_registered_as_winit_does_is_stopped() {
        let window = Hidden::new();
        let mouse = RAWINPUTDEVICE {
            usUsagePage: HID_USAGE_PAGE_GENERIC,
            usUsage: HID_USAGE_GENERIC_MOUSE,
            dwFlags: 0,
            hwndTarget: window.0,
        };
        // SAFETY: one initialized device of the given size; the window is this thread's.
        let registered = unsafe {
            RegisterRawInputDevices(&mouse, 1, std::mem::size_of::<RAWINPUTDEVICE>() as u32)
        };
        assert_ne!(registered, 0, "could not register raw mouse input");
        assert!(registered_mouse_input());

        stop_raw_mouse_input().expect("stop raw mouse input");
        assert!(!registered_mouse_input());
    }

    #[test]
    fn only_a_move_inside_a_drag_on_the_same_monitor_is_kept_from_winit() {
        assert!(!forwards_position_change(true, true, false));
        assert!(
            forwards_position_change(true, true, true),
            "another monitor"
        );
        assert!(
            forwards_position_change(true, false, false),
            "sized, not moved"
        );
        assert!(forwards_position_change(false, true, false), "not a drag");
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
