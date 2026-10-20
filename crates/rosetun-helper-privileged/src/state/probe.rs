use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use rosetun_config::{ConnectionState, Node, uses_xray};
use rosetun_engine::{
    ControlEndpoint, EngineBackend, EngineProcess, PROBE_TIMEOUT, ProbeRenderRequest, SocksProxy,
    UrlTestTarget, url_test_any,
};
use rosetun_engine_xray::SocksEndpoint;
use rosetun_ipc::{
    ErrorCode, ExitDelay, ExitOutcome, HelperError, MAX_PROBE_NODES, ProbeOutcome, ProbeRequest,
    ProbeResult, TunnelDelays,
};
use rosetun_routing::RoutingGuard;

use super::{
    Caller, Helper, NameLookup, lockdown, node_with_endpoint, resolve_quiet, select_endpoint,
    validate_tun_name, wait_for_engine_ready,
};

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const APPLY_DNS_SLOT_POLL: Duration = Duration::from_millis(25);
pub(super) const RESOLVE_WORKERS: usize = 8;
const URL_TEST_WORKERS: usize = 16;
static DNS_WORKERS: AtomicUsize = AtomicUsize::new(0);
static APPLY_DNS_WORKER: AtomicBool = AtomicBool::new(false);

pub(super) struct DnsWorkerSlot;

impl DnsWorkerSlot {
    pub(super) fn acquire() -> Option<Self> {
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

pub(super) struct ApplyDnsWorkerSlot;

impl ApplyDnsWorkerSlot {
    pub(super) fn acquire() -> Option<Self> {
        APPLY_DNS_WORKER
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for ApplyDnsWorkerSlot {
    fn drop(&mut self) {
        APPLY_DNS_WORKER.store(false, Ordering::Release);
    }
}

struct ProbeBinaryPermit {
    routing: Arc<std::sync::Mutex<RoutingGuard>>,
    binary: PathBuf,
}

impl ProbeBinaryPermit {
    fn new(
        routing: Arc<std::sync::Mutex<RoutingGuard>>,
        binary: &Path,
    ) -> Result<Self, HelperError> {
        routing
            .lock()
            .map_err(|_| HelperError::new(ErrorCode::RoutingFailed, "routing guard is poisoned"))?
            .permit_probe_binary(binary)
            .map_err(|error| HelperError::new(ErrorCode::RoutingFailed, error.to_string()))?;
        Ok(Self {
            routing,
            binary: binary.to_owned(),
        })
    }
}

impl Drop for ProbeBinaryPermit {
    fn drop(&mut self) {
        let mut guard = self
            .routing
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Err(error) = guard.remove_probe_binary(&self.binary) {
            tracing::error!(%error, "failed to remove temporary Xray probe authorization");
        }
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
        validate_tun_name(&request.settings.tun.name)?;
        let backend = self
            .engines
            .get_shared(request.settings.engine)
            .ok_or_else(|| {
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
        backend: Arc<dyn EngineBackend>,
    ) -> Result<Vec<ProbeResult>, HelperError> {
        let mut results = request
            .nodes
            .iter()
            .map(|node| ProbeResult {
                node: node.id.clone(),
                outcome: ProbeOutcome::Unresolved,
            })
            .collect::<Vec<_>>();
        let lookup = NameLookup::new(
            lockdown::read(&self.lockdown).enabled,
            self.with_status(|status| status.state == ConnectionState::Connected),
        );
        let endpoints = resolve_nodes(&request.nodes, lookup);
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
        let interface = (self.physical_interface)(&request.settings.tun.name);
        // A concurrent connect could raise its TUN after this lookup, so on Windows
        // never fall back to auto-detect without a known physical interface.
        if cfg!(windows) && interface.is_none() {
            return Err(HelperError::new(
                ErrorCode::EngineFailed,
                "physical interface is unavailable for server checks",
            ));
        }
        let xray_nodes = nodes
            .iter()
            .filter(|(_, node)| uses_xray(node, request.settings.xray))
            .map(|(tag, node)| {
                SocksEndpoint::local()
                    .map(|socks| (tag.clone(), node.clone(), socks))
                    .map_err(|_| {
                        HelperError::new(
                            ErrorCode::XrayStartFailed,
                            "Xray SOCKS endpoint is unavailable",
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let xray_config = if xray_nodes.is_empty() {
            None
        } else {
            let physical = interface.as_deref().ok_or_else(|| {
                HelperError::new(
                    ErrorCode::XrayStartFailed,
                    "physical interface is unavailable for Xray checks",
                )
            })?;
            Some(
                rosetun_engine_xray::render_probe(&xray_nodes, physical).map_err(|_| {
                    HelperError::new(
                        ErrorCode::XrayStartFailed,
                        "failed to render Xray server check",
                    )
                })?,
            )
        };
        let socks = xray_nodes
            .iter()
            .filter(|(tag, _, _)| {
                xray_config
                    .as_ref()
                    .is_some_and(|config| !config.unsupported_probes.contains(tag))
            })
            .map(|(tag, _, endpoint)| {
                (
                    tag.clone(),
                    SocksProxy {
                        address: endpoint.address(),
                        username: endpoint.username(),
                        password: endpoint.password(),
                    },
                )
            })
            .collect::<Vec<_>>();
        let mut config = backend
            .render_probe(&ProbeRenderRequest {
                nodes: &nodes,
                socks: &socks,
                control: &control,
                interface: interface.as_deref(),
            })
            .map_err(|_| {
                HelperError::new(ErrorCode::EngineFailed, "failed to render server check")
            })?;
        if let Some(xray_config) = &xray_config {
            config
                .unsupported_probes
                .extend(xray_config.unsupported_probes.iter().cloned());
        }
        let config_path = backend.probe_config_path(&config).ok_or_else(|| {
            HelperError::new(
                ErrorCode::EngineFailed,
                "server check configuration cleanup is unavailable",
            )
        })?;
        let engine_binary = backend.locate_binary().map_err(|_| {
            HelperError::new(
                ErrorCode::EngineFailed,
                "server check engine is unavailable",
            )
        })?;
        // Without a session nothing permits the check under Lockdown's block.
        let lockdown_routing = self.lockdown_probe_routing(&engine_binary)?;
        let mut _permit: Option<ProbeBinaryPermit> = None;
        let mut _xray_process: Option<ProbeProcess> = None;
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
            .map(|(tag, _)| {
                (
                    tag["probe-".len()..]
                        .parse::<usize>()
                        .expect("generated tag"),
                    tag.as_str(),
                )
            })
            .collect::<Vec<_>>();
        if supported.is_empty() {
            return Ok(results);
        }
        if !socks.is_empty() {
            let xray = self.xray.as_ref().ok_or_else(|| {
                HelperError::new(
                    ErrorCode::XrayStartFailed,
                    "Xray helper is unavailable for server checks",
                )
            })?;
            let xray_config = xray_config
                .as_ref()
                .expect("SOCKS endpoints require Xray config");
            let mut probe = ProbeProcess {
                process: None,
                config_path: xray.probe_config_path(),
            };
            let binary = xray.locate_binary().map_err(|_| {
                HelperError::new(
                    ErrorCode::XrayStartFailed,
                    "Xray is unavailable for server checks",
                )
            })?;
            let endpoints = xray_nodes
                .iter()
                .filter(|(tag, _, _)| !xray_config.unsupported_probes.contains(tag))
                .map(|(_, _, socks)| socks)
                .collect::<Vec<_>>();
            let routing = match &lockdown_routing {
                Some(routing) => Some(Arc::clone(routing)),
                None => match self.session.try_lock() {
                    Ok(session) => session
                        .guard
                        .as_ref()
                        .map(|guard| Arc::clone(&guard.routing)),
                    Err(TryLockError::WouldBlock) => {
                        return Err(HelperError::new(
                            ErrorCode::Busy,
                            "tunnel changes are in progress during server checks",
                        ));
                    }
                    Err(TryLockError::Poisoned(_)) => {
                        return Err(HelperError::new(
                            ErrorCode::Internal,
                            "helper state is unavailable during server checks",
                        ));
                    }
                },
            };
            _permit = routing
                .map(|routing| ProbeBinaryPermit::new(routing, &binary))
                .transpose()?;
            probe.process = Some(
                xray.spawn(
                    &binary,
                    xray_config,
                    &endpoints,
                    Arc::new(std::sync::atomic::AtomicU64::new(0)),
                )
                .map_err(|_| {
                    HelperError::new(
                        ErrorCode::XrayStartFailed,
                        "failed to start Xray server check",
                    )
                })?,
            );
            wait_for_engine_ready(probe.process.as_mut().unwrap().as_mut()).map_err(|_| {
                HelperError::new(
                    ErrorCode::XrayStartFailed,
                    "Xray server check did not become ready",
                )
            })?;
            _xray_process = Some(probe);
        }
        process.process = Some(backend.spawn(&engine_binary, &config).map_err(|_| {
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

        for &(index, _) in &supported {
            results[index].outcome = ProbeOutcome::Fails;
        }
        let next = AtomicUsize::new(0);
        thread::scope(|scope| {
            let workers = (0..supported.len().min(URL_TEST_WORKERS))
                .map(|_| {
                    let next = &next;
                    let supported = &supported;
                    let control = &control;
                    let backend = Arc::clone(&backend);
                    scope.spawn(move || {
                        let mut outcomes = Vec::new();
                        while let Some(&(index, tag)) =
                            supported.get(next.fetch_add(1, Ordering::Relaxed))
                        {
                            let outcome = probe_outcome(url_test_any(
                                Arc::clone(&backend),
                                control,
                                UrlTestTarget::Probe(tag),
                                PROBE_TIMEOUT,
                            ));
                            outcomes.push((index, outcome));
                        }
                        outcomes
                    })
                })
                .collect::<Vec<_>>();
            for worker in workers {
                match worker.join() {
                    Ok(outcomes) => {
                        for (index, outcome) in outcomes {
                            results[index].outcome = outcome;
                        }
                    }
                    Err(_) => tracing::warn!("URL test worker panicked"),
                }
            }
        });
        Ok(results)
    }

    pub(crate) fn tunnel_delay_as(&self, caller: &Caller) -> Result<TunnelDelays, HelperError> {
        self.check_owner(caller)?;
        let session = self.session()?;
        self.check_owner(caller)?;
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
        let exit_tags = session.exit_tags.clone();
        drop(session);
        let backend = self
            .engines
            .get_shared(engine.ok_or_else(|| {
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
        // The main node and every exit are checked at once, so the answer takes
        // as long as a single check.
        let delays = thread::scope(|scope| {
            let exits = exit_tags
                .iter()
                .map(|(exit, tag)| {
                    let backend = Arc::clone(&backend);
                    let control = &control;
                    let check = tag.as_deref().map(|tag| {
                        scope.spawn(move || {
                            probe_outcome(url_test_any(
                                backend,
                                control,
                                UrlTestTarget::SessionExit(tag),
                                PROBE_TIMEOUT,
                            ))
                        })
                    });
                    (exit, check)
                })
                .collect::<Vec<_>>();
            let proxy = probe_outcome(url_test_any(
                Arc::clone(&backend),
                &control,
                UrlTestTarget::Session,
                PROBE_TIMEOUT,
            ));
            let exits = exits
                .into_iter()
                .map(|(exit, check)| ExitDelay {
                    exit: exit.clone(),
                    outcome: match check {
                        Some(check) => {
                            ExitOutcome::Probed(check.join().unwrap_or(ProbeOutcome::Fails))
                        }
                        None => ExitOutcome::NoAddress,
                    },
                })
                .collect();
            TunnelDelays { proxy, exits }
        });
        if !delays.exits.is_empty() {
            let count = |works: bool| {
                delays
                    .exits
                    .iter()
                    .filter(|delay| {
                        matches!(
                            delay.outcome,
                            ExitOutcome::Probed(ProbeOutcome::Works { .. })
                        ) == works
                    })
                    .count()
            };
            tracing::debug!(
                exits = delays.exits.len(),
                works = count(true),
                other = count(false),
                "exit delays checked"
            );
        }
        Ok(delays)
    }

    #[cfg(test)]
    pub fn tunnel_delay(&self) -> Result<TunnelDelays, HelperError> {
        self.tunnel_delay_as(&super::test_caller())
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

pub(super) fn resolve_nodes(nodes: &[Node], lookup: NameLookup) -> Vec<Option<IpAddr>> {
    resolve_with_workers(
        nodes,
        lookup,
        RESOLVE_WORKERS,
        Instant::now() + RESOLVE_TIMEOUT,
        DnsWorkerSlot::acquire,
    )
}

pub(super) fn resolve_for_apply(node: &Node) -> Option<IpAddr> {
    resolve_for_apply_with_timeout(node, RESOLVE_TIMEOUT)
}

pub(super) fn resolve_for_apply_with_timeout(node: &Node, timeout: Duration) -> Option<IpAddr> {
    let deadline = Instant::now() + timeout;
    // Apply runs in a connected session, whose tunnel carries the system resolver.
    resolve_with_workers(
        std::slice::from_ref(node),
        NameLookup::System,
        1,
        deadline,
        || {
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return None;
                }
                if let Some(slot) = ApplyDnsWorkerSlot::acquire() {
                    return Some(slot);
                }
                thread::sleep(remaining.min(APPLY_DNS_SLOT_POLL));
            }
        },
    )[0]
}

fn resolve_with_workers<S: Send + 'static>(
    nodes: &[Node],
    lookup: NameLookup,
    limit: usize,
    deadline: Instant,
    acquire: impl Fn() -> Option<S>,
) -> Vec<Option<IpAddr>> {
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
    // DNS has no portable cancellation API; bounded slots also limit workers
    // left blocked inside the OS resolver after the deadline.
    for _ in 0..count.min(limit) {
        let Some(slot) = acquire() else {
            break;
        };
        let jobs = Arc::clone(&jobs);
        let next = Arc::clone(&next);
        let tx = tx.clone();
        thread::spawn(move || {
            let _slot = slot;
            while let Some((index, server, port)) = jobs.get(next.fetch_add(1, Ordering::Relaxed)) {
                let address = resolve_quiet(server, *port, lookup)
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
