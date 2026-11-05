//! What the window showed between frames, as a summary in the GUI log at most
//! every 10 s, and only when something happened: nothing is logged for a window
//! that merely animates or stands idle.
//!
//! eframe tells the application nothing after a frame is presented. A frame is
//! built and presented in one go on this thread, so the start of the next frame
//! is taken as the end of the present. That makes the times upper bounds, and
//! they end where the present call returned: how long the frame then waited for
//! the screen is `MsUntilDisplayed` in `tools/perf/Measure-RosetunPresents.ps1`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use rosetun_shell::WindowActivity;
use wgpu::CurrentSurfaceTexture;

const SUMMARY_INTERVAL: Duration = Duration::from_secs(10);
/// egui draws a second frame right after one it was asked for. A later frame
/// says nothing about when the earlier one was presented.
const FOLLOW_UP_LIMIT: Duration = Duration::from_millis(250);

/// What wgpu reported while getting a frame, written from the surface status
/// handler and read once a frame.
pub(crate) static SURFACE: SurfaceEvents = SurfaceEvents::new();

#[derive(Debug)]
pub(crate) struct SurfaceEvents {
    outdated: AtomicU32,
    lost: AtomicU32,
    timeout: AtomicU32,
    occluded: AtomicU32,
    validation: AtomicU32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SurfaceCounts {
    outdated: u32,
    lost: u32,
    timeout: u32,
    occluded: u32,
    validation: u32,
}

/// Times from an event to the end of the present that showed it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Delays {
    samples: u32,
    total: Duration,
    longest: Duration,
    /// The next frame came too late to tell.
    unmeasured: u32,
}

/// Events the frame now being built has taken in.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Pending {
    started: Option<Instant>,
    surface_changed_at: Option<Instant>,
    input_at: Option<Instant>,
}

#[derive(Debug, Default)]
pub(crate) struct FrameStats {
    period_started: Option<Instant>,
    pending: Pending,
    summary: Summary,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Summary {
    frames: u32,
    size_changes: u32,
    dpi_changes: u32,
    monitor_changes: u32,
    surface: SurfaceCounts,
    surface_change: Delays,
    input: Delays,
}

impl SurfaceEvents {
    const fn new() -> Self {
        Self {
            outdated: AtomicU32::new(0),
            lost: AtomicU32::new(0),
            timeout: AtomicU32::new(0),
            occluded: AtomicU32::new(0),
            validation: AtomicU32::new(0),
        }
    }

    pub(crate) fn record(&self, status: &CurrentSurfaceTexture) {
        let counter = match status {
            CurrentSurfaceTexture::Outdated => &self.outdated,
            CurrentSurfaceTexture::Lost => &self.lost,
            CurrentSurfaceTexture::Timeout => &self.timeout,
            CurrentSurfaceTexture::Occluded => &self.occluded,
            CurrentSurfaceTexture::Validation => &self.validation,
            CurrentSurfaceTexture::Success(_) | CurrentSurfaceTexture::Suboptimal(_) => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn take(&self) -> SurfaceCounts {
        SurfaceCounts {
            outdated: self.outdated.swap(0, Ordering::Relaxed),
            lost: self.lost.swap(0, Ordering::Relaxed),
            timeout: self.timeout.swap(0, Ordering::Relaxed),
            occluded: self.occluded.swap(0, Ordering::Relaxed),
            validation: self.validation.swap(0, Ordering::Relaxed),
        }
    }
}

impl SurfaceCounts {
    fn add(&mut self, other: Self) {
        self.outdated = self.outdated.saturating_add(other.outdated);
        self.lost = self.lost.saturating_add(other.lost);
        self.timeout = self.timeout.saturating_add(other.timeout);
        self.occluded = self.occluded.saturating_add(other.occluded);
        self.validation = self.validation.saturating_add(other.validation);
    }

    /// The frames that wgpu had no surface for and the handler dropped.
    fn skipped_frames(self) -> u32 {
        self.timeout
            .saturating_add(self.occluded)
            .saturating_add(self.validation)
    }
}

impl Delays {
    fn record(&mut self, since: Option<Instant>, now: Instant, followed: bool) {
        let Some(since) = since else {
            return;
        };
        if !followed {
            self.unmeasured = self.unmeasured.saturating_add(1);
            return;
        }
        let delay = now.saturating_duration_since(since);
        self.samples = self.samples.saturating_add(1);
        self.total = self.total.saturating_add(delay);
        self.longest = self.longest.max(delay);
    }

    fn average_ms(self) -> u64 {
        if self.samples == 0 {
            return 0;
        }
        (self.total / self.samples).as_millis() as u64
    }

    fn longest_ms(self) -> u64 {
        self.longest.as_millis() as u64
    }
}

impl Summary {
    fn worth_logging(&self) -> bool {
        Self {
            frames: self.frames,
            ..Self::default()
        } != *self
    }

    /// eframe configures the swap chain for each size with an area and each
    /// `Outdated`; a lost surface is created and configured anew. On Direct3D 12
    /// wgpu never reports `Suboptimal`, the only other cause.
    fn swap_chain_configures(&self) -> u32 {
        self.size_changes
            .saturating_add(self.surface.outdated)
            .saturating_add(self.surface.lost)
    }
}

impl FrameStats {
    /// Call when a frame starts being built.
    pub(crate) fn observe(&mut self, activity: WindowActivity) {
        let summary = self.frame_started(Instant::now(), activity, SURFACE.take());
        let Some(summary) = summary else {
            return;
        };
        tracing::info!(
            frames = summary.frames,
            swap_chain_configures = summary.swap_chain_configures(),
            size_changes = summary.size_changes,
            dpi_changes = summary.dpi_changes,
            monitor_changes = summary.monitor_changes,
            surface_outdated = summary.surface.outdated,
            surface_lost = summary.surface.lost,
            surface_timeout = summary.surface.timeout,
            surface_occluded = summary.surface.occluded,
            surface_validation = summary.surface.validation,
            skipped_frames = summary.surface.skipped_frames(),
            surface_change_to_present_longest_ms = summary.surface_change.longest_ms(),
            surface_change_unmeasured = summary.surface_change.unmeasured,
            input_to_present_average_ms = summary.input.average_ms(),
            input_to_present_longest_ms = summary.input.longest_ms(),
            input_unmeasured = summary.input.unmeasured,
            "window frame summary"
        );
    }

    fn frame_started(
        &mut self,
        now: Instant,
        activity: WindowActivity,
        surface: SurfaceCounts,
    ) -> Option<Summary> {
        let previous = self.pending;
        let followed = previous
            .started
            .is_some_and(|started| now.saturating_duration_since(started) <= FOLLOW_UP_LIMIT);
        let summary = &mut self.summary;
        summary
            .surface_change
            .record(previous.surface_changed_at, now, followed);
        summary.input.record(previous.input_at, now, followed);
        summary.frames = summary.frames.saturating_add(1);
        summary.size_changes = summary.size_changes.saturating_add(activity.size_changes);
        summary.dpi_changes = summary.dpi_changes.saturating_add(activity.dpi_changes);
        summary.monitor_changes = summary
            .monitor_changes
            .saturating_add(activity.monitor_changes);
        summary.surface.add(surface);
        self.pending = Pending {
            started: Some(now),
            surface_changed_at: activity.surface_changed_at,
            input_at: activity.input_at,
        };

        let period_started = *self.period_started.get_or_insert(now);
        if now.saturating_duration_since(period_started) < SUMMARY_INTERVAL {
            return None;
        }
        self.period_started = Some(now);
        let summary = std::mem::take(&mut self.summary);
        summary.worth_logging().then_some(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AFTER_THE_PERIOD: Duration = Duration::from_secs(11);

    fn quiet() -> (WindowActivity, SurfaceCounts) {
        (WindowActivity::default(), SurfaceCounts::default())
    }

    #[test]
    fn frames_alone_are_never_logged() {
        let mut stats = FrameStats::default();
        let start = Instant::now();
        let (activity, surface) = quiet();
        assert_eq!(stats.frame_started(start, activity, surface), None);
        assert_eq!(
            stats.frame_started(start + AFTER_THE_PERIOD, activity, surface),
            None
        );
    }

    #[test]
    fn a_summary_waits_for_the_period_and_then_starts_again() {
        let mut stats = FrameStats::default();
        let start = Instant::now();
        let (quiet_activity, surface) = quiet();
        let resized = WindowActivity {
            size_changes: 2,
            surface_changed_at: Some(start),
            ..WindowActivity::default()
        };
        assert_eq!(stats.frame_started(start, resized, surface), None);

        let summary = stats
            .frame_started(start + AFTER_THE_PERIOD, quiet_activity, surface)
            .expect("the period is over");
        assert_eq!(summary.frames, 2);
        assert_eq!(summary.size_changes, 2);
        assert_eq!(summary.swap_chain_configures(), 2);

        assert_eq!(
            stats.frame_started(start + 2 * AFTER_THE_PERIOD, quiet_activity, surface),
            None,
            "what the last summary counted was logged twice"
        );
    }

    #[test]
    fn a_delay_runs_from_the_event_to_the_next_frame_after_the_one_that_took_it_in() {
        let mut stats = FrameStats::default();
        let start = Instant::now();
        let event = WindowActivity {
            size_changes: 1,
            surface_changed_at: Some(start),
            input_at: Some(start + Duration::from_millis(2)),
            ..WindowActivity::default()
        };
        let (quiet_activity, surface) = quiet();
        let took_it_in = start + Duration::from_millis(5);
        stats.frame_started(took_it_in, event, surface);
        assert_eq!(stats.summary.surface_change.samples, 0, "not presented yet");

        stats.frame_started(start + Duration::from_millis(20), quiet_activity, surface);
        assert_eq!(
            stats.summary.surface_change.longest,
            Duration::from_millis(20)
        );
        assert_eq!(stats.summary.input.longest, Duration::from_millis(18));
        assert_eq!(stats.summary.input.average_ms(), 18);

        stats.frame_started(start + Duration::from_millis(30), quiet_activity, surface);
        assert_eq!(stats.summary.surface_change.samples, 1, "counted once");
    }

    #[test]
    fn a_frame_long_after_the_last_one_measures_nothing() {
        let mut stats = FrameStats::default();
        let start = Instant::now();
        let event = WindowActivity {
            input_at: Some(start),
            ..WindowActivity::default()
        };
        let (quiet_activity, surface) = quiet();
        stats.frame_started(start, event, surface);
        stats.frame_started(start + Duration::from_secs(5), quiet_activity, surface);
        assert_eq!(stats.summary.input.samples, 0);
        assert_eq!(stats.summary.input.unmeasured, 1);
    }

    #[test]
    fn surface_events_are_counted_by_kind_and_taken_once() {
        let events = SurfaceEvents::new();
        for status in [
            CurrentSurfaceTexture::Outdated,
            CurrentSurfaceTexture::Outdated,
            CurrentSurfaceTexture::Lost,
            CurrentSurfaceTexture::Timeout,
            CurrentSurfaceTexture::Occluded,
            CurrentSurfaceTexture::Validation,
        ] {
            events.record(&status);
        }
        let counts = events.take();
        assert_eq!(
            counts,
            SurfaceCounts {
                outdated: 2,
                lost: 1,
                timeout: 1,
                occluded: 1,
                validation: 1,
            }
        );
        assert_eq!(counts.skipped_frames(), 3);
        assert_eq!(events.take(), SurfaceCounts::default());
    }

    #[test]
    fn a_reconfigure_and_a_new_surface_count_as_configures() {
        let summary = Summary {
            size_changes: 3,
            surface: SurfaceCounts {
                outdated: 2,
                lost: 1,
                ..SurfaceCounts::default()
            },
            ..Summary::default()
        };
        assert_eq!(summary.swap_chain_configures(), 6);
    }
}
