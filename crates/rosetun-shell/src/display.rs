use windows_sys::Win32::Foundation::POINT;
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MonitorFromPoint,
};
use windows_sys::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};

/// The part of the primary monitor that windows may cover, without the
/// taskbar, in logical pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WorkArea {
    pub left: f32,
    pub top: f32,
    pub width: f32,
    pub height: f32,
}

pub fn primary_work_area() -> Option<WorkArea> {
    // SAFETY: The point is passed by value; the returned handle is borrowed from Windows.
    let monitor = unsafe { MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY) };
    if monitor.is_null() {
        return None;
    }

    // SAFETY: MONITORINFO is a plain Windows data structure valid when zero-initialized.
    let mut info: MONITORINFO = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
    // SAFETY: The monitor handle is valid and info points to a writable, correctly sized structure.
    if unsafe { GetMonitorInfoW(monitor, &mut info) } == 0 {
        return None;
    }

    let mut dpi_x = 0;
    let mut dpi_y = 0;
    // SAFETY: The monitor handle is valid and both output pointers are writable for this call.
    if unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut dpi_x, &mut dpi_y) } != 0
        || dpi_x == 0
    {
        return None;
    }

    // Windows supplies virtualized coordinates and 96 DPI before DPI awareness is enabled.
    let logical = |coordinate: i32| coordinate as f32 * 96.0 / dpi_x as f32;
    let left = logical(info.rcWork.left);
    let top = logical(info.rcWork.top);
    let width = logical(info.rcWork.right) - left;
    let height = logical(info.rcWork.bottom) - top;
    if width <= 0.0 || height <= 0.0 {
        return None;
    }
    Some(WorkArea {
        left,
        top,
        width,
        height,
    })
}

#[cfg(test)]
mod tests {
    use super::primary_work_area;

    #[test]
    fn primary_monitor_has_a_work_area() {
        let area = primary_work_area().expect("primary monitor work area");
        assert!(area.width > 0.0);
        assert!(area.height > 0.0);
    }
}
