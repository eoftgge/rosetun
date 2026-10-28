//! Shared timing for animations. Short transitions run at the monitor's
//! rate through egui's `animate_*`; continuous ones ask for frames here.

use std::time::Duration;

use eframe::egui;

/// A transition that moves something larger: a list opening, a chart settling.
pub(crate) const NORMAL: f32 = 0.22;

const FOCUSED_FRAME: Duration = Duration::from_millis(16);
const UNFOCUSED_FRAME: Duration = Duration::from_millis(33);

#[derive(Clone, Copy, Debug)]
pub(crate) struct WindowView {
    pub(crate) hidden: bool,
    pub(crate) minimized: bool,
    pub(crate) focused: bool,
}

impl WindowView {
    pub(crate) fn of(ctx: &egui::Context, hidden: bool) -> Self {
        ctx.input(|input| Self {
            hidden,
            minimized: input.viewport().minimized.unwrap_or(false),
            focused: input.focused,
        })
    }
}

/// Cubic ease-out: fast at first, slowing to a stop.
pub(crate) fn ease_out(t: f32) -> f32 {
    1.0 - (1.0 - t.clamp(0.0, 1.0)).powi(3)
}

/// A transition's length, zero when the user asked for less motion.
pub(crate) fn duration(seconds: f32, reduce_motion: bool) -> f32 {
    if reduce_motion { 0.0 } else { seconds }
}

/// When a continuous animation (petal drift, the opening rose, the moving
/// chart) needs its next frame: 60 per second in focus, 30 out of it, none
/// for a window nobody can see or with motion reduced.
pub(crate) fn continuous_frame(window: WindowView, reduce_motion: bool) -> Option<Duration> {
    if reduce_motion || window.hidden || window.minimized {
        None
    } else if window.focused {
        Some(FOCUSED_FRAME)
    } else {
        Some(UNFOCUSED_FRAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(hidden: bool, minimized: bool, focused: bool) -> WindowView {
        WindowView {
            hidden,
            minimized,
            focused,
        }
    }

    #[test]
    fn continuous_frames_follow_focus_and_stop_off_screen() {
        assert_eq!(
            continuous_frame(window(false, false, true), false),
            Some(Duration::from_millis(16))
        );
        assert_eq!(
            continuous_frame(window(false, false, false), false),
            Some(Duration::from_millis(33))
        );
        assert_eq!(continuous_frame(window(true, false, true), false), None);
        assert_eq!(continuous_frame(window(false, true, false), false), None);
        assert_eq!(continuous_frame(window(false, false, true), true), None);
    }

    #[test]
    fn ease_out_starts_fast_and_ends_at_one() {
        assert_eq!(ease_out(0.0), 0.0);
        assert_eq!(ease_out(1.0), 1.0);
        assert!(ease_out(0.5) > 0.5);
        assert_eq!(ease_out(2.0), 1.0);
    }

    #[test]
    fn reduced_motion_makes_every_transition_instant() {
        assert_eq!(duration(NORMAL, true), 0.0);
        assert_eq!(duration(NORMAL, false), NORMAL);
    }
}
