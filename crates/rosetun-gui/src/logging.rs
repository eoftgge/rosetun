use tracing::Level;

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Default)]
pub(crate) struct RepeatedWarning {
    last: Option<std::time::Instant>,
    count: u64,
}

#[cfg(any(windows, test))]
impl RepeatedWarning {
    pub(crate) fn observe(&mut self, now: std::time::Instant) -> Option<u64> {
        self.count = self.count.saturating_add(1);
        if self.last.is_none_or(|last| now.duration_since(last) >= std::time::Duration::from_secs(30)) {
            self.last = Some(now);
            Some(std::mem::take(&mut self.count))
        } else {
            None
        }
    }
}

pub(crate) fn allows(target: &str, level: Level) -> bool {
    // Hide startup adapter inventories at INFO, but preserve graphics failures.
    // The environment filter still controls DEBUG and TRACE diagnostics.
    !rosetun_core::is_sensitive_log_target(target)
        && (!(target.starts_with("wgpu") || target.starts_with("egui_wgpu")) || level != Level::INFO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_warning_is_immediate_and_repeats_are_counted() {
        let mut warning = RepeatedWarning::default();
        let start = std::time::Instant::now();
        assert_eq!(warning.observe(start), Some(1));
        for second in 1..30 {
            assert_eq!(warning.observe(start + std::time::Duration::from_secs(second)), None);
        }
        assert_eq!(warning.observe(start + std::time::Duration::from_secs(30)), Some(30));
    }

    #[test]
    fn graphics_failures_pass_without_startup_inventories() {
        for target in ["wgpu_hal::dx12", "wgpu_core", "wgpu", "egui_wgpu", "egui_wgpu::winit"] {
            for level in [Level::ERROR, Level::WARN, Level::DEBUG, Level::TRACE] {
                assert!(allows(target, level));
            }
            assert!(!allows(target, Level::INFO));
        }
        for level in [Level::ERROR, Level::WARN, Level::INFO, Level::DEBUG, Level::TRACE] {
            assert!(allows("rosetun_gui", level));
            for target in ["ureq", "ureq::request", "ureq_proto", "rustls", "rustls_platform_verifier::verify"] {
                assert!(!allows(target, level));
            }
        }
    }
}
