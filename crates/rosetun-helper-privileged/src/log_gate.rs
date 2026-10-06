use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Lets engine lines below WARN into the log only while the verbose log is
/// on: at INFO sing-box writes a line for every connection with its destination.
#[derive(Debug, Clone, Default)]
pub(crate) struct VerboseGate(Arc<AtomicU64>);

impl VerboseGate {
    /// Opens the gate until a Unix time in seconds.
    pub(crate) fn open_until(&self, until_unix: u64) {
        self.0.store(until_unix, Ordering::Release);
    }

    pub(crate) fn close(&self) {
        self.0.store(0, Ordering::Release);
    }

    pub(crate) fn allows(&self, metadata: &tracing::Metadata<'_>) -> bool {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs())
            .unwrap_or_default();
        line_allowed(
            metadata.target() == rosetun_engine::ENGINE_OUTPUT_TARGET,
            *metadata.level(),
            now_unix,
            self.0.load(Ordering::Acquire),
        )
    }

    #[cfg(test)]
    pub(crate) fn is_open(&self, now_unix: u64) -> bool {
        now_unix < self.0.load(Ordering::Acquire)
    }
}

fn line_allowed(engine_line: bool, level: tracing::Level, now_unix: u64, until_unix: u64) -> bool {
    !engine_line || level <= tracing::Level::WARN || now_unix < until_unix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_engine_lines_are_always_allowed() {
        for level in [
            tracing::Level::ERROR,
            tracing::Level::WARN,
            tracing::Level::INFO,
            tracing::Level::DEBUG,
            tracing::Level::TRACE,
        ] {
            assert!(line_allowed(false, level, 100, 0));
        }
    }

    #[test]
    fn engine_warnings_and_errors_are_always_allowed() {
        for level in [tracing::Level::ERROR, tracing::Level::WARN] {
            assert!(line_allowed(true, level, 100, 0));
            assert!(line_allowed(true, level, 100, 100));
        }
    }

    #[test]
    fn engine_info_debug_and_trace_require_an_unexpired_deadline() {
        for level in [
            tracing::Level::INFO,
            tracing::Level::DEBUG,
            tracing::Level::TRACE,
        ] {
            assert!(line_allowed(true, level, 99, 100));
            assert!(!line_allowed(true, level, 100, 100));
            assert!(!line_allowed(true, level, 101, 100));
            assert!(!line_allowed(true, level, 0, 0));
        }
    }

    #[test]
    fn cloned_gate_shares_its_deadline() {
        let gate = VerboseGate::default();
        let clone = gate.clone();
        gate.open_until(100);
        assert!(clone.is_open(99));
        assert!(!clone.is_open(100));
        clone.close();
        assert!(!gate.is_open(99));
    }
}
