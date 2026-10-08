use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use rosetun_config::{ConnectionState, Node};
use rosetun_engine::{
    ControlEndpoint, EngineBackend, EngineProcess, PROBE_TIMEOUT, PROBE_URL, ProbeRenderRequest,
    UrlTestTarget,
};
use rosetun_ipc::{
    ErrorCode, HelperError, MAX_PROBE_NODES, ProbeOutcome, ProbeRequest, ProbeResult,
};

use super::{Helper, node_with_endpoint, resolve_quiet, select_endpoint, wait_for_engine_ready};

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const RESOLVE_WORKERS: usize = 8;
const URL_TEST_WORKERS: usize = 16;
static DNS_WORKERS: AtomicUsize = AtomicUsize::new(0);

struct DnsWorkerSlot;

impl DnsWorkerSlot {
    fn acquire() -> Option<Self> {
        DNS_WORKERS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < RESOLVE_WORKERS).then_some(count + 1)
            })
            .ok()
            .map(|_| Self)
    }
}

impl Drop for DnsWorkerSlot {
    fn drop(&mut self) {
        DNS_WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}

struct ProbeProcess {
    process: Option<Box<dyn EngineProcess>>,
    config_path: PathBuf,
}

impl Drop for ProbeProcess {
    fn drop(&mut self) {
        if let Some(process) = self.process.as_mut()
            && process.stop().is_err()
        {
            tracing::warn!("failed to stop server check engine");
        }
        if let Err(error) = std::fs::remove_file(&self.config_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!("failed to remove server check configuration");
        }
    }
}

impl Helper {
    pub fn probe_nodes(&self, request: &ProbeRequest) -> Result<Vec<ProbeResult>, HelperError> {
        let _guard = match self.probe.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                return Err(HelperError::new(
                    ErrorCode::Busy,
                    "another server check is in progress",
                ));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(HelperError::new(
                    ErrorCode::Internal,
                    "server check state poisoned by an earlier panic",
                ));
            }
        };
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(HelperError::new(
                ErrorCode::InvalidState,
                "helper is shutting down",
            ));
        }
        if request.nodes.is_empty() || request.nodes.len() > MAX_PROBE_NODES {
            return Err(HelperError::new(
                ErrorCode::InvalidState,
                "server check requires between 1 and 256 nodes",
            ));
        }
        let backend = self.engines.get(request.settings.engine).ok_or_else(|| {
            HelperError::new(
                ErrorCode::EngineFailed,
                "server check engine is not registered",
            )
        })?;
        let started = Instant::now();
        let results = self.check_nodes(request, backend)?;
        let count = |outcome| {
            results
                .iter()
                .filter(|result| result.outcome == outcome)
                .count()
        };
        tracing::info!(
            nodes = results.len(),
            works = results
                .iter()
                .filter(|result| matches!(result.outcome, ProbeOutcome::Works { .. }))
                .count(),
            fails = count(ProbeOutcome::Fails),
            unresolved = count(ProbeOutcome::Unresolved),
            unsupported = count(ProbeOutcome::Unsupported),
            elapsed_ms = started.elapsed().as_millis(),
            "server check completed"
        );
        Ok(results)
    }

    fn check_nodes(
        &self,
        request: &ProbeRequest,
        backend: &dyn EngineBackend,
    ) -> Result<Vec<ProbeResult>, HelperError> {
        let mut results = request
            .nodes
            .iter()
            .map(|node| ProbeResult {
                node: node.id.clone(),
                outcome: ProbeOutcome::Unresolved,
            })
            .collect::<Vec<_>>();
        let endpoints = resolve_nodes(&request.nodes);
        let nodes = request
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(index, node)| {
                endpoints[index]
                    .map(|address| (format!("probe-{index}"), node_with_endpoint(node, address)))
            })
            .collect::<Vec<_>>();
        if nodes.is_empty() {
            return Ok(results);
        }

        let control = ControlEndpoint::local().map_err(|_| {
            HelperError::new(
                ErrorCode::EngineFailed,
                "server check control API is unavailable",
            )
        })?;
        let interface = rosetun_routing::physical_default_interface(&request.settings.tun.name);
        // A concurrent connect could raise its TUN after this lookup, so on Windows
        // never fall back to auto-detect without a known physical interface.
        if cfg!(windows) && interface.is_none() {
            return Err(HelperError::new(
                ErrorCode::EngineFailed,
                "physical interface is unavailable for server checks",
            ));
        }
        let config = backend
            .render_probe(&ProbeRenderRequest {
                nodes: &nodes,
                control: &control,
                interface: interface.as_deref(),
            })
            .map_err(|_| {
                HelperError::new(ErrorCode::EngineFailed, "failed to render server check")
            })?;
        let config_path = backend.probe_config_path(&config).ok_or_else(|| {
            HelperError::new(
                ErrorCode::EngineFailed,
                "server check configuration cleanup is unavailable",
            )
        })?;
        let mut process = ProbeProcess {
            process: None,
            config_path,
        };
        for (index, endpoint) in endpoints.iter().enumerate() {
            if endpoint.is_some()
                && config
                    .unsupported_probes
                    .contains(&format!("probe-{index}"))
            {
                results[index].outcome = ProbeOutcome::Unsupported;
            }
        }
        let supported = nodes
            .iter()
            .filter(|(tag, _)| !config.unsupported_probes.contains(tag))
            .collect::<Vec<_>>();
        if supported.is_empty() {
            return Ok(results);
        }
        let binary = backend.locate_binary().map_err(|_| {
            HelperError::new(
                ErrorCode::EngineFailed,
                "server check engine is unavailable",
            )
        })?;
        process.process = Some(backend.spawn(&binary, &config).map_err(|_| {
            HelperError::new(
                ErrorCode::EngineFailed,
                "failed to start server check engine",
            )
        })?);
        wait_for_engine_ready(process.process.as_mut().unwrap().as_mut()).map_err(|_| {
            HelperError::new(
                ErrorCode::EngineFailed,
                "server check engine did not become ready",
            )
        })?;

        let next = AtomicUsize::new(0);
        thread::scope(|scope| {
            let workers = (0..supported.len().min(URL_TEST_WORKERS))
                .map(|_| {
                    let next = &next;
                    let supported = &supported;
                    let control = &control;
                    scope.spawn(move || {
                        let mut outcomes = Vec::new();
                        while let Some((tag, _)) =
                            supported.get(next.fetch_add(1, Ordering::Relaxed))
                        {
                            let index = tag["probe-".len()..]
                                .parse::<usize>()
                                .expect("generated tag");
                            let outcome = probe_outcome(backend.url_test(
                                control,
                                UrlTestTarget::Probe(tag),
                                PROBE_URL,
                                PROBE_TIMEOUT,
                            ));
                            outcomes.push((index, outcome));
                        }
                        outcomes
                    })
                })
                .collect::<Vec<_>>();
            for worker in workers {
                for (index, outcome) in worker.join().expect("URL test worker panicked") {
                    results[index].outcome = outcome;
                }
            }
        });
        Ok(results)
    }

    pub fn tunnel_delay(&self) -> Result<ProbeOutcome, HelperError> {
        let session = self.session()?;
        let (state, engine) = self.with_status(|status| (status.state.clone(), status.engine));
        if !matches!(state, ConnectionState::Connected) {
            return Err(HelperError::new(
                ErrorCode::InvalidState,
                "the tunnel is not connected",
            ));
        }
        let control = session.control.clone().ok_or_else(|| {
            HelperError::new(
                ErrorCode::EngineFailed,
                "the engine control API is unavailable",
            )
        })?;
        drop(session);
        let backend = self
            .engines
            .get(engine.ok_or_else(|| {
                HelperError::new(
                    ErrorCode::EngineFailed,
                    "the connected engine is unavailable",
                )
            })?)
            .ok_or_else(|| {
                HelperError::new(
                    ErrorCode::EngineFailed,
                    "the connected engine is unavailable",
                )
            })?;
        Ok(probe_outcome(backend.url_test(
            &control,
            UrlTestTarget::Session,
            PROBE_URL,
            PROBE_TIMEOUT,
        )))
    }
}

fn probe_outcome<E>(result: Result<Duration, E>) -> ProbeOutcome {
    match result {
        Ok(delay) => ProbeOutcome::Works {
            millis: u32::try_from(delay.as_millis()).unwrap_or(u32::MAX),
        },
        Err(_) => ProbeOutcome::Fails,
    }
}

fn resolve_nodes(nodes: &[Node]) -> Vec<Option<IpAddr>> {
    let mut endpoints = vec![None; nodes.len()];
    let mut jobs = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        if let Ok(address) = node.server.parse::<IpAddr>() {
            endpoints[index] = Some(address);
        } else {
            jobs.push((index, node.server.clone(), node.port));
        }
    }
    if jobs.is_empty() {
        return endpoints;
    }
    let count = jobs.len();
    let jobs = Arc::new(jobs);
    let next = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel();
    // DNS has no portable cancellation API; receive only until the overall deadline.
    // At most eight detached workers can remain blocked inside the OS resolver.
    let deadline = Instant::now() + RESOLVE_TIMEOUT;
    for _ in 0..count.min(RESOLVE_WORKERS) {
        let Some(slot) = DnsWorkerSlot::acquire() else {
            break;
        };
        let jobs = Arc::clone(&jobs);
        let next = Arc::clone(&next);
        let tx = tx.clone();
        thread::spawn(move || {
            let _slot = slot;
            while let Some((index, server, port)) = jobs.get(next.fetch_add(1, Ordering::Relaxed)) {
                let address = resolve_quiet(server, *port)
                    .and_then(|addresses| select_endpoint(&addresses))
                    .ok();
                if tx.send((*index, address)).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);
    for _ in 0..count {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok((index, address)) => endpoints[index] = address,
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
        }
    }
    endpoints
}
