/// A rectangle in physical screen pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScreenRect {
    pub(crate) left: i32,
    pub(crate) top: i32,
    pub(crate) right: i32,
    pub(crate) bottom: i32,
}

/// Share of the work area's surface that the window takes on its first start.
const FIRST_START_SHARE: f64 = 0.30;
/// The smallest window the layout fits in, in logical pixels.
const MIN_SIZE: (f64, f64) = (960.0, 640.0);

/// The window on its first start: a share of the work area with the same
/// proportions, never below the minimum, centred in the work area.
pub(crate) fn first_start_rect(work: ScreenRect, scale: f64) -> ScreenRect {
    let work_w = work.right - work.left;
    let work_h = work.bottom - work.top;
    let min_w = (MIN_SIZE.0 * scale).round() as i32;
    let min_h = (MIN_SIZE.1 * scale).round() as i32;
    let min_w = min_w.min(work_w);
    let min_h = min_h.min(work_h);
    let side = FIRST_START_SHARE.sqrt();
    let w = ((f64::from(work_w) * side).round() as i32).max(min_w);
    let h = ((f64::from(work_h) * side).round() as i32).max(min_h);
    let left = work.left + (work_w - w) / 2;
    let top = work.top + (work_h - h) / 2;
    ScreenRect {
        left,
        top,
        right: left + w,
        bottom: top + h,
    }
}

#[cfg(test)]
mod tests {
    use super::{ScreenRect, first_start_rect};

    #[test]
    fn first_start_respects_work_area_and_dpi() {
        for (work, scale, expected) in [
            ((0, 0, 1920, 1032), 1.0, (434, 196, 1486, 836)),
            ((0, 0, 1920, 1020), 1.25, (360, 110, 1560, 910)),
            ((0, 0, 1920, 1008), 1.5, (240, 24, 1680, 984)),
            ((0, 0, 2560, 1392), 1.0, (579, 315, 1981, 1077)),
            ((0, 0, 3840, 2088), 1.5, (868, 472, 2971, 1616)),
            ((-1920, 0, 0, 1080), 1.0, (-1486, 220, -434, 860)),
            ((0, 0, 1366, 708), 1.25, (83, 0, 1283, 708)),
        ] {
            let (left, top, right, bottom) = work;
            let rect = ScreenRect {
                left,
                top,
                right,
                bottom,
            };
            let result = first_start_rect(rect, scale);
            let (left, top, right, bottom) = expected;
            assert_eq!(
                result,
                ScreenRect {
                    left,
                    top,
                    right,
                    bottom
                },
                "{rect:?}"
            );
        }
    }
}
