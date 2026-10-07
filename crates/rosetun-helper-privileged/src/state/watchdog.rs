use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rosetun_config::{ConnectionState, Status};

use super::{dns, path};

const WAIT_SLICE: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy)]
pub(super) struct WatchdogTiming {
    pub interval: Duration,
    pub retry: Duration,
    pub dns_timeout: Duration,
    pub path_timeout: Duration,
    pub failures: u32,
    pub path_server: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Unchanged,
    DnsFailing,
    DnsRecovered,
    PathDown,
    Stalled,
}

struct DnsHealth {
    failures: u32,
    threshold: u32,
    signaled: bool,
    path_down: bool,
}

impl DnsHealth {
    fn new(threshold: u32) -> Self {
        Self {
            failures: 0,
            threshold,
            signaled: false,
            path_down: false,
        }
    }

    fn needs_path(&self) -> bool {
        self.failures.saturating_add(1) >= self.threshold
    }

    /// A failure that has not been explained yet is asked about again soon.
    fn pause(&self, timing: &WatchdogTiming) -> Duration {
        if self.failures != 0 && !self.signaled && !self.path_down {
            timing.retry
        } else {
            timing.interval
        }
    }

    fn observe(&mut self, dns_ok: bool, path_ok: Option<bool>) -> Verdict {
        if dns_ok {
            let recovered = self.failures != 0;
            self.failures = 0;
            self.signaled = false;
            self.path_down = false;
            return if recovered {
                Verdict::DnsRecovered
            } else {
                Verdict::Unchanged
            };
        }

        self.failures = self.failures.saturating_add(1);
        if self.failures < self.threshold {
            return if self.failures == 1 {
                Verdict::DnsFailing
            } else {
                Verdict::Unchanged
            };
        }
        match path_ok {
            Some(false) => {
                let newly_down = !self.path_down;
                self.path_down = true;
                if newly_down {
                    Verdict::PathDown
                } else {
                    Verdict::Unchanged
                }
            }
            Some(true) => {
                self.path_down = false;
                if self.signaled {
                    Verdict::Unchanged
                } else {
                    self.signaled = true;
                    Verdict::Stalled
                }
            }
            None => Verdict::Unchanged,
        }
    }
}

pub(super) struct DnsWatchdog {
    stop: Arc<AtomicBool>,
    stalled: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl DnsWatchdog {
    pub(super) fn start(
        status: Arc<Mutex<Status>>,
        server: SocketAddr,
        timing: WatchdogTiming,
    ) -> io::Result<Self> {
        Self::start_with_probes(
            status,
            timing,
            move |stopped| dns::probe(server, timing.dns_timeout, stopped),
            move |stopped| path::probe(timing.path_server, timing.path_timeout, stopped),
        )
    }

    fn start_with_probes(
        status: Arc<Mutex<Status>>,
        timing: WatchdogTiming,
        mut dns_probe: impl FnMut(&dyn Fn() -> bool) -> bool + Send + 'static,
        mut path_probe: impl FnMut(&dyn Fn() -> bool) -> bool + Send + 'static,
    ) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let stalled = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_stalled = Arc::clone(&stalled);
        let thread = thread::Builder::new()
            .name("tunnel-dns-watchdog".to_owned())
            .spawn(move || {
                let mut health = DnsHealth::new(timing.failures);
                loop {
                    if !wait(&worker_stop, health.pause(&timing)) {
                        return;
                    }
                    let connected = {
                        let status = status.lock().unwrap_or_else(|error| error.into_inner());
                        matches!(status.state, ConnectionState::Connected)
                    };
                    if !connected {
                        continue;
                    }

                    let stopped = || worker_stop.load(Ordering::Acquire);
                    let dns_ok = dns_probe(&stopped);
                    if stopped() {
                        return;
                    }
                    let path_ok = if !dns_ok && health.needs_path() {
                        let result = path_probe(&stopped);
                        if stopped() {
                            return;
                        }
                        Some(result)
                    } else {
                        None
                    };

                    let warned = health.signaled || health.path_down;
                    match health.observe(dns_ok, path_ok) {
                        Verdict::DnsFailing => {
                            tracing::debug!("DNS probe through the tunnel failed")
                        }
                        Verdict::DnsRecovered => {
                            worker_stalled.store(false, Ordering::Release);
                            if warned {
                                tracing::info!("DNS through the tunnel recovered");
                            } else {
                                tracing::debug!("DNS through the tunnel recovered");
                            }
                        }
                        Verdict::PathDown => {
                            worker_stalled.store(false, Ordering::Release);
                            tracing::warn!("DNS and HTTP through the tunnel are unavailable");
                        }
                        Verdict::Stalled => {
                            worker_stalled.store(true, Ordering::Release);
                            tracing::warn!("DNS through the tunnel stalled while HTTP is working");
                        }
                        Verdict::Unchanged => {}
                    }
                }
            })?;
        Ok(Self {
            stop,
            stalled,
            thread: Some(thread),
        })
    }

    pub(super) fn take_stalled(&self) -> bool {
        self.stalled.swap(false, Ordering::AcqRel)
    }

    pub(super) fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::warn!("DNS watchdog thread panicked");
        }
    }

    #[cfg(test)]
    pub(super) fn stalled_for_test() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            stalled: Arc::new(AtomicBool::new(true)),
            thread: None,
        }
    }
}

impl Drop for DnsWatchdog {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

fn wait(stop: &AtomicBool, interval: Duration) -> bool {
    let deadline = Instant::now() + interval;
    loop {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        thread::sleep(remaining.min(WAIT_SLICE));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn timing() -> WatchdogTiming {
        WatchdogTiming {
            interval: Duration::from_millis(10),
            retry: Duration::from_millis(10),
            dns_timeout: Duration::from_millis(10),
            path_timeout: Duration::from_millis(10),
            failures: 3,
            path_server: "127.0.0.1:80".parse().expect("test address"),
        }
    }

    fn connected() -> Arc<Mutex<Status>> {
        Arc::new(Mutex::new(Status {
            state: ConnectionState::Connected,
            ..Status::default()
        }))
    }

    fn wait_for(condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !condition() {
            assert!(
                Instant::now() < deadline,
                "watchdog did not reach expected state"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn health_requires_consecutive_failures_and_working_path() {
        let mut health = DnsHealth::new(3);
        assert_eq!(health.observe(true, None), Verdict::Unchanged);
        assert_eq!(health.observe(false, None), Verdict::DnsFailing);
        assert!(!health.needs_path());
        assert_eq!(health.observe(false, None), Verdict::Unchanged);
        assert!(health.needs_path());
        assert_eq!(health.observe(true, None), Verdict::DnsRecovered);
        assert!(!health.needs_path());
        assert_eq!(health.observe(false, None), Verdict::DnsFailing);
        assert_eq!(health.observe(false, None), Verdict::Unchanged);
        assert_eq!(health.observe(false, Some(false)), Verdict::PathDown);
        assert_eq!(health.observe(false, Some(false)), Verdict::Unchanged);
        assert_eq!(health.observe(false, Some(true)), Verdict::Stalled);
        assert_eq!(health.observe(false, Some(true)), Verdict::Unchanged);
        assert_eq!(health.observe(true, None), Verdict::DnsRecovered);
        assert_eq!(health.observe(true, None), Verdict::Unchanged);
        assert_eq!(health.observe(false, None), Verdict::DnsFailing);
        assert_eq!(health.observe(false, None), Verdict::Unchanged);
        assert_eq!(health.observe(false, Some(true)), Verdict::Stalled);
    }

    #[test]
    fn pause_retries_only_while_a_failure_is_open() {
        let timing = WatchdogTiming {
            interval: Duration::from_millis(400),
            ..timing()
        };
        let mut health = DnsHealth::new(3);
        assert_eq!(health.pause(&timing), timing.interval);
        health.observe(false, None);
        assert_eq!(health.pause(&timing), timing.retry);
        health.observe(false, None);
        assert_eq!(health.pause(&timing), timing.retry);
        health.observe(false, Some(false));
        assert_eq!(health.pause(&timing), timing.interval);
        health.observe(false, Some(true));
        assert_eq!(health.pause(&timing), timing.interval);
        health.observe(true, None);
        assert_eq!(health.pause(&timing), timing.interval);
    }

    #[test]
    fn failing_dns_is_rechecked_at_the_retry_pace() {
        let mut timing = timing();
        timing.interval = Duration::from_millis(400);
        let watchdog = DnsWatchdog::start_with_probes(connected(), timing, |_| false, |_| true)
            .expect("start watchdog");
        let started = Instant::now();
        wait_for(|| watchdog.stalled.load(Ordering::Acquire));
        assert!(started.elapsed() < Duration::from_millis(700));
        watchdog.stop();
    }

    #[test]
    fn signal_fires_once_and_rearms_after_dns_recovery() {
        let status = connected();
        let dns_ok = Arc::new(AtomicBool::new(false));
        let path_ok = Arc::new(AtomicBool::new(true));
        let dns_successes = Arc::new(AtomicUsize::new(0));
        let path_checks = Arc::new(AtomicUsize::new(0));
        let path_failures = Arc::new(AtomicUsize::new(0));
        let watchdog = DnsWatchdog::start_with_probes(
            status,
            timing(),
            {
                let dns_ok = Arc::clone(&dns_ok);
                let successes = Arc::clone(&dns_successes);
                move |_| {
                    let healthy = dns_ok.load(Ordering::Acquire);
                    if healthy {
                        successes.fetch_add(1, Ordering::AcqRel);
                    }
                    healthy
                }
            },
            {
                let path_ok = Arc::clone(&path_ok);
                let checks = Arc::clone(&path_checks);
                let failures = Arc::clone(&path_failures);
                move |_| {
                    checks.fetch_add(1, Ordering::AcqRel);
                    let healthy = path_ok.load(Ordering::Acquire);
                    if !healthy {
                        failures.fetch_add(1, Ordering::AcqRel);
                    }
                    healthy
                }
            },
        )
        .expect("start watchdog");
        assert!(!watchdog.take_stalled(), "first probe waits for interval");
        wait_for(|| watchdog.stalled.load(Ordering::Acquire));
        assert!(watchdog.take_stalled());
        wait_for(|| path_checks.load(Ordering::Acquire) >= 3);
        assert!(
            !watchdog.take_stalled(),
            "no second signal without recovery"
        );
        dns_ok.store(true, Ordering::Release);
        wait_for(|| dns_successes.load(Ordering::Acquire) >= 2);
        path_ok.store(false, Ordering::Release);
        dns_ok.store(false, Ordering::Release);
        wait_for(|| path_failures.load(Ordering::Acquire) >= 2);
        assert!(!watchdog.take_stalled(), "path outage suppresses restart");
        path_ok.store(true, Ordering::Release);
        wait_for(|| watchdog.stalled.load(Ordering::Acquire));
        assert!(watchdog.take_stalled());
        watchdog.stop();
    }

    #[test]
    fn first_probe_waits_and_status_is_unlocked_during_io() {
        use std::sync::mpsc::channel;

        let status = connected();
        let (entered, receiver) = channel();
        let mut timing = timing();
        timing.interval = Duration::from_millis(150);
        let watchdog = DnsWatchdog::start_with_probes(
            Arc::clone(&status),
            timing,
            move |_| {
                entered.send(()).expect("test observes DNS probe");
                thread::sleep(Duration::from_millis(100));
                true
            },
            |_| panic!("healthy DNS does not need an HTTP probe"),
        )
        .expect("start watchdog");
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("first probe after interval");
        assert!(status.try_lock().is_ok(), "probe does not hold status lock");
        watchdog.stop();
    }

    #[test]
    fn only_connected_state_is_probed_and_stop_is_prompt() {
        let status = Arc::new(Mutex::new(Status::default()));
        let checks = Arc::new(AtomicUsize::new(0));
        let watchdog = DnsWatchdog::start_with_probes(
            Arc::clone(&status),
            timing(),
            {
                let checks = Arc::clone(&checks);
                move |_| {
                    checks.fetch_add(1, Ordering::AcqRel);
                    false
                }
            },
            |_| true,
        )
        .expect("start watchdog");
        thread::sleep(Duration::from_millis(60));
        assert_eq!(checks.load(Ordering::Acquire), 0);
        status.lock().expect("test status mutex").state = ConnectionState::Reconnecting;
        thread::sleep(Duration::from_millis(30));
        assert_eq!(checks.load(Ordering::Acquire), 0);
        status.lock().expect("test status mutex").state = ConnectionState::Connected;
        wait_for(|| checks.load(Ordering::Acquire) >= 1);
        let started = Instant::now();
        watchdog.stop();
        assert!(started.elapsed() < Duration::from_millis(300));
    }
}
