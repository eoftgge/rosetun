//! Shared timing for animations. Short transitions run at the monitor's
//! rate through egui's `animate_*`; continuous ones ask for frames here.

use std::sync::atomic::{AtomicBool, Ordering};

use eframe::egui;

/// A short transition: content fading in, a dialog appearing.
pub(crate) const FAST: f32 = 0.14;
/// A transition that moves something larger: a list opening, a chart settling.
pub(crate) const NORMAL: f32 = 0.22;

/// `interface.reduce_motion` for widgets that see no state, set between frames.
static REDUCED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug)]
pub(crate) struct WindowView {
    pub(crate) hidden: bool,
    pub(crate) minimized: bool,
}

impl WindowView {
    pub(crate) fn of(ctx: &egui::Context, hidden: bool) -> Self {
        ctx.input(|input| Self {
            hidden,
            minimized: input.viewport().minimized.unwrap_or(false),
        })
    }
}

pub(crate) fn set_reduced(reduced: bool) {
    REDUCED.store(reduced, Ordering::Relaxed);
}

pub(crate) fn reduced() -> bool {
    REDUCED.load(Ordering::Relaxed)
}

/// Cubic ease-out: fast at first, slowing to a stop.
pub(crate) fn ease_out(t: f32) -> f32 {
    1.0 - (1.0 - t.clamp(0.0, 1.0)).powi(3)
}

/// A transition's length, zero when the user asked for less motion.
pub(crate) fn duration(seconds: f32, reduce_motion: bool) -> f32 {
    if reduce_motion { 0.0 } else { seconds }
}

/// Whether a continuous animation (petal drift, the opening rose, the moving
/// chart) asks for its next frame, with `request_repaint`: the present waits
/// for vsync, so frames follow the monitor's own rate. A fixed timer such as
/// 16 ms is not a whole number of refreshes at 100 or 300 Hz, so its frames
/// would land unevenly. No frames for a window nobody can see or with motion
/// reduced. Focus does not matter: the frames are as visible without it.
pub(crate) fn continuous_frames(window: WindowView, reduce_motion: bool) -> bool {
    !(reduce_motion || window.hidden || window.minimized)
}

/// How much of a section `full` points tall shows at `progress` of its
/// opening. Only the part that fits in `room`, the space left in view,
/// grows; the rest appears at the end below the edge, where nobody sees it
/// jump, and a hundred servers open as fast as ten.
pub(crate) fn reveal_height(full: f32, progress: f32, room: f32) -> f32 {
    if progress >= 1.0 {
        full
    } else {
        full.min(room.max(0.0)) * progress.max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(hidden: bool, minimized: bool) -> WindowView {
        WindowView { hidden, minimized }
    }

    #[test]
    fn continuous_frames_run_while_the_window_is_seen_and_stop_off_screen() {
        assert!(continuous_frames(window(false, false), false));
        assert!(!continuous_frames(window(true, false), false));
        assert!(!continuous_frames(window(false, true), false));
        assert!(!continuous_frames(window(false, false), true));
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
        assert_eq!(duration(FAST, true), 0.0);
        assert_eq!(duration(FAST, false), FAST);
    }

    #[test]
    fn a_short_section_grows_through_its_whole_height() {
        assert_eq!(reveal_height(200.0, 0.0, 600.0), 0.0);
        assert_eq!(reveal_height(200.0, 0.5, 600.0), 100.0);
        assert_eq!(reveal_height(200.0, 1.0, 600.0), 200.0);
    }

    #[test]
    fn a_long_section_grows_through_the_room_in_view_then_shows_the_rest() {
        assert_eq!(reveal_height(3000.0, 0.5, 700.0), 350.0);
        assert_eq!(reveal_height(3000.0, 0.99, 700.0), 693.0);
        assert_eq!(reveal_height(3000.0, 1.0, 700.0), 3000.0);
        assert_eq!(reveal_height(3000.0, 0.5, -20.0), 0.0, "below the view");
    }
}
