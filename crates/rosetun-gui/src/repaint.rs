//! Waking the GUI from another thread. On Linux a window comes and goes
//! while workers run on, so a wake goes to whichever window is open now, or
//! to the loop that runs without one.

use std::sync::{Arc, Condvar, Mutex, PoisonError};
#[cfg(target_os = "linux")]
use std::time::Duration;

use eframe::egui;

#[derive(Clone, Default)]
pub(crate) struct Repaint {
    shared: Arc<Shared>,
}

#[derive(Default)]
struct Shared {
    window: Mutex<Option<egui::Context>>,
    woken: Mutex<bool>,
    wake: Condvar,
}

impl Repaint {
    #[cfg(any(not(target_os = "linux"), test))]
    pub(crate) fn of(ctx: egui::Context) -> Self {
        let repaint = Self::default();
        repaint.attach(ctx);
        repaint
    }

    pub(crate) fn attach(&self, ctx: egui::Context) {
        *self
            .shared
            .window
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(ctx);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn detach(&self) {
        *self
            .shared
            .window
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    pub(crate) fn request(&self) {
        if let Some(ctx) = &*self
            .shared
            .window
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
        {
            ctx.request_repaint();
        }
        *self
            .shared
            .woken
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
        self.shared.wake.notify_all();
    }

    /// Blocks until a wake since the last call, or for `timeout`.
    #[cfg(target_os = "linux")]
    pub(crate) fn wait(&self, timeout: Duration) {
        let woken = self
            .shared
            .woken
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (mut woken, _) = self
            .shared
            .wake
            .wait_timeout_while(woken, timeout, |woken| !*woken)
            .unwrap_or_else(PoisonError::into_inner);
        *woken = false;
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn a_wake_before_the_wait_is_not_lost_and_counts_once() {
        let repaint = Repaint::default();
        repaint.request();
        let start = Instant::now();
        repaint.wait(Duration::from_secs(30));
        assert!(start.elapsed() < Duration::from_secs(10));
        let start = Instant::now();
        repaint.wait(Duration::from_millis(20));
        assert!(start.elapsed() >= Duration::from_millis(20));
    }

    #[test]
    fn a_wake_from_another_thread_ends_the_wait() {
        let repaint = Repaint::default();
        let other = repaint.clone();
        let wake = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            other.request();
        });
        let start = Instant::now();
        repaint.wait(Duration::from_secs(30));
        assert!(start.elapsed() < Duration::from_secs(10));
        wake.join().unwrap();
    }
}
