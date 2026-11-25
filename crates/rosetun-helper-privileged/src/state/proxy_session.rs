//! The local proxy and its outbound-only engine processes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use rosetun_config::{ConnectStage, EngineKind, ExitId, Settings, uses_xray};
use rosetun_dataplane::rules::{RuleEngine, RulePlan};
use rosetun_dataplane::{
    Dataplane, DataplaneConfig, ExitUpstream, OutboundEndpoints, load_list_files,
};
use rosetun_engine::{
    DelayInbound, EngineProcess, EngineRights, ExtraOutbound, PROXY_TAG, RenderedConfig,
    SUBSCRIPTION_PROXY_USER, exit_tag,
};
use rosetun_engine_xray::SocksEndpoint;
use rosetun_ipc::{ConnectRequest, ErrorCode, HelperError};
use rosetun_routing::RoutingPlan;
use rosetun_routing::lan::LanAccess;

use super::{
    NameLookup, ResolvedNodeEndpoints, Session, StartMode, StartOptions, check_cancelled, dns,
    exits::{self, ExtraNodes, socks_proxy},
    lan, local_proxy, lockdown, node_with_endpoints, now_unix, protected_endpoints, protection,
    wait_for_engine_ready_from,
};

type ExitTags = Vec<(ExitId, Option<String>)>;

pub(super) struct ProxySession {
    pub(super) dataplane: Dataplane,
    pub(super) entry: DelayInbound,
    workers: Workers,
    outbounds: OutboundEndpoints,
    pub(super) plan: RoutingPlan,
    #[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
    native: Option<super::native_tun::NativeTun>,
}

#[derive(Default)]
struct Workers {
    singbox: Option<Worker>,
    xray: Option<Worker>,
}

struct Worker {
    process: Option<Box<dyn EngineProcess>>,
    binary: PathBuf,
    config: RenderedConfig,
    sockets: HashMap<String, SocksEndpoint>,
}

impl Worker {
    fn prepare(
        previous: Option<&Self>,
        tags: &[String],
        binary: impl FnOnce() -> Result<PathBuf, HelperError>,
        render: impl Fn(&HashMap<String, SocksEndpoint>) -> Result<RenderedConfig, HelperError>,
    ) -> Result<WorkerChange, HelperError> {
        if tags.is_empty() {
            return Ok(if previous.is_some() {
                WorkerChange::Replace(None)
            } else {
                WorkerChange::Keep
            });
        }
        if let Some(previous) = previous
            && tags.len() == previous.sockets.len()
            && tags.iter().all(|tag| previous.sockets.contains_key(tag))
            && render(&previous.sockets)?.body == previous.config.body
        {
            return Ok(WorkerChange::Keep);
        }
        let sockets = tags
            .iter()
            .map(|tag| {
                SocksEndpoint::local()
                    .map(|endpoint| (tag.clone(), endpoint))
                    .map_err(|_| {
                        HelperError::new(
                            ErrorCode::EngineFailed,
                            "cannot allocate a worker endpoint",
                        )
                    })
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        let mut config = render(&sockets)?;
        config.file_name =
            if previous.is_some_and(|worker| worker.config.file_name == "worker-a.json") {
                "worker-b.json"
            } else {
                "worker-a.json"
            }
            .to_owned();
        Ok(WorkerChange::Replace(Some(Self {
            process: None,
            binary: previous.map_or_else(binary, |worker| Ok(worker.binary.clone()))?,
            config,
            sockets,
        })))
    }

    fn stopped(&mut self) -> bool {
        !self
            .process
            .as_mut()
            .is_some_and(|process| matches!(process.is_running(), Ok(true)))
    }

    fn stop(&mut self) -> Result<(), HelperError> {
        if let Some(process) = &mut self.process {
            process
                .stop()
                .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;
        }
        self.process = None;
        Ok(())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            tracing::error!(code = ?error.code, "failed to stop an outbound worker");
        }
    }
}

enum WorkerChange {
    Keep,
    Replace(Option<Worker>),
}

impl WorkerChange {
    fn candidate<'a>(&'a self, previous: &'a Option<Worker>) -> Option<&'a Worker> {
        match self {
            Self::Keep => previous.as_ref(),
            Self::Replace(worker) => worker.as_ref(),
        }
    }

    fn commit(self, current: &mut Option<Worker>) {
        if let Self::Replace(worker) = self {
            *current = worker;
        }
    }
}

struct WorkerUpdate {
    singbox: WorkerChange,
    xray: WorkerChange,
}

impl WorkerUpdate {
    fn binaries<'a>(&'a self, previous: &'a Workers) -> Vec<&'a std::path::Path> {
        self.singbox
            .candidate(&previous.singbox)
            .into_iter()
            .chain(self.xray.candidate(&previous.xray))
            .map(|worker| worker.binary.as_path())
            .collect()
    }

    fn outbounds(&self, previous: &Workers, tags: &ExitTags) -> OutboundEndpoints {
        let singbox = self.singbox.candidate(&previous.singbox);
        let xray = self.xray.candidate(&previous.xray);
        let upstream = |tag: &str| {
            singbox
                .and_then(|worker| worker.sockets.get(tag))
                .or_else(|| xray.and_then(|worker| worker.sockets.get(tag)))
                .map(|endpoint| socks_proxy(endpoint).into())
        };
        OutboundEndpoints {
            proxy: upstream(PROXY_TAG),
            exits: tags
                .iter()
                .filter_map(|(exit, tag)| {
                    let tag = tag.as_ref()?;
                    Some(ExitUpstream {
                        exit: exit.clone(),
                        tag: tag.clone(),
                        upstream: upstream(tag)?,
                    })
                })
                .collect(),
        }
    }

    fn commit(self, workers: &mut Workers) {
        self.singbox.commit(&mut workers.singbox);
        self.xray.commit(&mut workers.xray);
    }
}

impl ProxySession {
    pub(super) fn exited(&mut self) -> (bool, Option<String>) {
        let xray = self.workers.xray.as_mut().is_some_and(Worker::stopped);
        let singbox = self.workers.singbox.as_mut().is_some_and(Worker::stopped);
        (
            xray,
            if xray {
                Some("Xray stopped".to_owned())
            } else {
                if self.dataplane.running() {
                    singbox.then(|| "sing-box outbound worker stopped".to_owned())
                } else {
                    Some("native tunnel packet worker stopped".to_owned())
                }
            },
        )
    }

    pub(super) fn stop(&mut self) -> Result<(), HelperError> {
        self.dataplane.shutdown();
        #[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
        if let Some(native) = self.native.as_mut() {
            native.close()?;
        }
        for worker in [&mut self.workers.singbox, &mut self.workers.xray]
            .into_iter()
            .flatten()
        {
            worker.stop()?;
        }
        Ok(())
    }
}

impl Session {
    pub(super) fn start_proxy(
        &mut self,
        request: &ConnectRequest,
        options: StartOptions,
    ) -> Result<(), HelperError> {
        let settings = &request.settings;
        let state = lockdown::read(&self.lockdown);
        let native_requested = super::native_tun_requested(request);
        let shared_addresses = (self.shared_proxy_addresses)();
        let listener = local_proxy::listen_for(
            settings,
            local_proxy::sharing_allowed(&state),
            &shared_addresses,
            &self.cancelled,
        )?;
        let listen = match listener {
            Some(listen) => listen,
            None if native_requested => rosetun_engine::LocalProxyListen {
                addresses: Vec::new(),
                dns: std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
            },
            None => {
                return Err(HelperError::new(
                    ErrorCode::InvalidState,
                    "local proxy listener is unavailable",
                ));
            }
        };
        let lookup = NameLookup::new(state.enabled, false);
        let endpoint = match options.endpoint {
            Some(endpoint) => endpoint,
            None if options.mode == StartMode::ProtectedReconnect => {
                protected_endpoints(&request.node, self.last_endpoint.as_ref())?
            }
            None => self.resolve_node_endpoints(&request.node, lookup)?,
        };
        let extra_endpoints = options.extra_endpoints.unwrap_or_else(|| {
            exits::start_endpoints(
                &request.extra_nodes,
                options.mode,
                &self.last_extra_endpoints,
                lookup,
            )
        });
        let (lan, servers) = self.proxy_lan(settings, &endpoint, &extra_endpoints);
        self.follow_servers_in_lockdown(&servers)?;
        let shared_proxy = local_proxy::shared_port(settings, &state);
        let scope = protection::protection_scope(
            options.mode,
            settings.kill_switch,
            true,
            state.enabled,
            true,
            shared_proxy.is_some(),
        );
        let plan = RoutingPlan {
            proxy_application: Some(local_proxy::application()?),
            scope: scope.unwrap_or(rosetun_routing::ProtectionScope::SharedProxy),
            allow_lan: settings.allow_lan,
            lan: lan.clone(),
            lockdown: state.enabled,
            shared_proxy,
        };
        let mut workers = Workers::default();
        let tags = exits::exit_tags(&request.extra_nodes, &extra_endpoints);
        let entry = delay_entry(None, &[], &tags)?;
        let rules = self.proxy_rules(request, &extra_endpoints, &lan)?;
        let verbose = settings
            .verbose_log_until
            .filter(|until| now_unix() < *until);
        self.stage(ConnectStage::CheckingEngine)?;
        let mut update = self.prepare_workers(
            request,
            &endpoint,
            &extra_endpoints,
            &workers,
            verbose.is_some(),
        )?;
        self.protection.permit_binaries(&update.binaries(&workers));
        match (scope, options.mode) {
            (Some(_), StartMode::ProtectedReconnect) => self.protection.prepare_reconnect(&plan)?,
            (Some(_), StartMode::Fresh) => self
                .protection
                .install(self.routing.as_mut(), &plan)
                .map_err(|error| HelperError::new(ErrorCode::RoutingFailed, error.to_string()))?,
            (None, _) => self.protection.release("failed to remove the DNS lock"),
        }
        if let Some(until) = verbose {
            self.gate.open_until(until);
        }
        #[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
        let mut native = if native_requested {
            let native = super::native_tun::NativeTun::open(&settings.tun)?;
            let deadline = Instant::now() + super::TUNNEL_READY_TIMEOUT;
            let tun = rosetun_routing::TunnelInterface::try_from(&settings.tun)
                .map_err(super::native_tun::route_error)?;
            loop {
                match self.protection.authorize_tunnel(&tun) {
                    Ok(()) => break,
                    Err(error) if error.is_tunnel_not_ready() && Instant::now() < deadline => {
                        super::sleep_cancellable(
                            super::TUNNEL_READY_POLL_INTERVAL,
                            &self.cancelled,
                        )?;
                    }
                    Err(error) => return Err(super::native_tun::route_error(error)),
                }
            }
            Some(native)
        } else {
            None
        };
        self.stage(ConnectStage::StartingEngine)?;
        self.spawn_workers(settings.engine, &mut update)?;
        let outbounds = update.outbounds(&workers, &tags);
        update.commit(&mut workers);
        let config = || DataplaneConfig {
            listen: listen.clone(),
            dns: settings.dns.clone(),
            dns_options: Default::default(),
            rules: rules.clone(),
            outbounds: outbounds.clone(),
            delay: Some(entry.clone()),
            router: Default::default(),
            sniff: Default::default(),
            direct_resolver: None,
        };
        #[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
        let dataplane = if let Some(native) = &mut native {
            let dataplane = Dataplane::start_native(config(), native.tunnel()?)
                .map_err(super::native_tun::route_error)?;
            let bypass = if settings.allow_lan {
                lan.segment.route_networks()
            } else {
                Vec::new()
            };
            #[cfg(all(windows, target_arch = "x86_64"))]
            self.authorize_native_listeners(&dataplane)?;
            native.capture(&bypass, &servers)?;
            dataplane
        } else {
            local_proxy::start(settings.local_proxy.port, &self.cancelled, || {
                Dataplane::start(config())
            })?
        };
        #[cfg(not(any(target_os = "linux", all(windows, target_arch = "x86_64"))))]
        let dataplane = local_proxy::start(settings.local_proxy.port, &self.cancelled, || {
            Dataplane::start(config())
        })?;
        let server = dataplane.dns_addr();
        let entry = DelayInbound {
            address: dataplane.delay_addr().unwrap_or(entry.address),
            ..entry
        };
        self.proxy_session = Some(ProxySession {
            dataplane,
            entry,
            workers,
            outbounds,
            plan,
            #[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
            native,
        });
        #[cfg(test)]
        let server = self.test_local_dns.unwrap_or(server);
        self.tunnel_dns = Some(server);
        self.stage(ConnectStage::CheckingServer)?;
        self.check_live_tunnel(options.dns_timeout)?;
        self.lan.begin_session(lan, servers);
        self.shared_addresses = shared_addresses;
        self.shared_address_watch = lan::LanWatch::default();
        self.remember_proxy_endpoints(request, endpoint, &extra_endpoints, tags);
        check_cancelled(&self.cancelled)
    }

    pub(super) fn apply_proxy(
        &mut self,
        current: &ConnectRequest,
        request: &ConnectRequest,
        endpoint: ResolvedNodeEndpoints,
        extra_endpoints: &[Option<ResolvedNodeEndpoints>],
    ) -> Result<(), HelperError> {
        let tags = exits::exit_tags(&request.extra_nodes, extra_endpoints);
        let (lan, servers) = self.proxy_lan(&request.settings, &endpoint, extra_endpoints);
        let engine = RuleEngine::compile(&self.proxy_rules(request, extra_endpoints, &lan)?)
            .map_err(rule_error)?;
        let mut proxy = self.proxy_session.take().ok_or_else(|| {
            HelperError::new(ErrorCode::InvalidState, "the local proxy is unavailable")
        })?;
        let result = (|| {
            let entry = delay_entry(Some(&proxy.entry), &self.exit_tags, &tags)?;
            let verbose = request
                .settings
                .verbose_log_until
                .filter(|until| now_unix() < *until);
            let mut update = self.prepare_workers(
                request,
                &endpoint,
                extra_endpoints,
                &proxy.workers,
                verbose.is_some(),
            )?;
            let state = lockdown::read(&self.lockdown);
            let plan = RoutingPlan {
                lan: lan.clone(),
                lockdown: state.enabled,
                scope: self.protection.scope().unwrap_or(proxy.plan.scope),
                shared_proxy: local_proxy::shared_port(&request.settings, &state),
                ..proxy.plan.clone()
            };
            let previous = WorkerUpdate {
                singbox: WorkerChange::Keep,
                xray: WorkerChange::Keep,
            };
            let previous_binaries = previous.binaries(&proxy.workers);
            let next_binaries = update.binaries(&proxy.workers);
            let replace_guard = self.protection.is_active()
                && (previous_binaries != next_binaries || proxy.plan != plan);
            let replace_lockdown_lan = servers != self.lan.servers();
            if replace_lockdown_lan {
                self.follow_servers_in_lockdown(&servers)?;
            }
            self.protection.permit_binaries(&next_binaries);
            let outbounds = update.outbounds(&proxy.workers, &tags);
            let result = (|| {
                if replace_guard {
                    self.protection.prepare_reconnect(&plan)?;
                    self.authorize_native_after_apply(request, &proxy.dataplane)?;
                }
                #[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
                if let Some(native) = proxy.native.as_mut() {
                    native.ensure_endpoints(&servers)?;
                }
                self.spawn_workers(request.settings.engine, &mut update)?;
                check_cancelled(&self.cancelled)?;
                let dns = (request.settings.dns != current.settings.dns
                    || outbounds.proxy != proxy.outbounds.proxy)
                    .then_some(&request.settings.dns);
                proxy
                    .dataplane
                    .update_session(engine, outbounds.clone(), dns, &entry)
                    .map_err(|error| {
                        HelperError::new(ErrorCode::EngineFailed, error.to_string())
                    })?;
                Ok(())
            })();
            if let Err(error) = result {
                drop(update);
                #[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
                if let Some(native) = proxy.native.as_mut() {
                    native.retain_endpoints(self.lan.servers());
                }
                self.protection.permit_binaries(&previous_binaries);
                if replace_guard
                    && let Err(restore) = self
                        .protection
                        .prepare_reconnect(&RoutingPlan {
                            lan: self.lan.access().clone(),
                            ..plan
                        })
                        .and_then(|()| self.authorize_native_after_apply(current, &proxy.dataplane))
                {
                    tracing::error!(code = ?restore.code, "failed to restore the previous proxy protection");
                }
                if replace_lockdown_lan {
                    let previous_servers = self.lan.servers().to_vec();
                    if let Err(restore) = self.follow_servers_in_lockdown(&previous_servers) {
                        tracing::error!(code = ?restore.code, "failed to restore the previous Lockdown network");
                    }
                }
                return Err(error);
            }
            update.commit(&mut proxy.workers);
            #[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
            if let Some(native) = proxy.native.as_mut() {
                native.retain_endpoints(&servers);
            }
            if let Some(until) = verbose {
                self.gate.open_until(until);
            } else {
                self.gate.close();
            }
            proxy.entry = entry;
            proxy.outbounds = outbounds;
            proxy.plan = plan;
            self.lan.begin_session(lan, servers);
            self.remember_proxy_endpoints(request, endpoint, extra_endpoints, tags);
            Ok(())
        })();
        self.proxy_session = Some(proxy);
        result
    }

    fn authorize_native_after_apply(
        &self,
        request: &ConnectRequest,
        _dataplane: &Dataplane,
    ) -> Result<(), HelperError> {
        if super::native_tun_requested(request) {
            let error = |error: rosetun_routing::RoutingError| {
                HelperError::new(ErrorCode::RoutingFailed, error.to_string())
            };
            let tunnel =
                rosetun_routing::TunnelInterface::try_from(&request.settings.tun).map_err(error)?;
            self.protection.authorize_tunnel(&tunnel).map_err(error)?;
            #[cfg(all(windows, target_arch = "x86_64"))]
            self.authorize_native_listeners(_dataplane)?;
        }
        Ok(())
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    fn authorize_native_listeners(&self, dataplane: &Dataplane) -> Result<(), HelperError> {
        let guard = self.protection.routing().ok_or_else(|| {
            super::native_tun::route_error("missing routing guard for native listeners")
        })?;
        let listeners = dataplane
            .native_redirects()
            .iter()
            .map(|redirect| (redirect.peer, redirect.listener.port()))
            .collect::<Vec<_>>();
        let application = local_proxy::application()?;
        guard
            .lock()
            .map_err(|_| super::native_tun::route_error("routing guard is poisoned"))?
            .authorize_native_listeners(&application, &listeners)
            .map_err(super::native_tun::route_error)
    }

    fn proxy_rules(
        &self,
        request: &ConnectRequest,
        endpoints: &[Option<ResolvedNodeEndpoints>],
        lan: &LanAccess,
    ) -> Result<RulePlan, HelperError> {
        let effective = request.effective_rule_set();
        let extra = ExtraNodes::new(&request.extra_nodes, endpoints, &effective);
        let lists = if request.lists.is_empty() {
            Vec::new()
        } else {
            let store = self.lists.as_ref().ok_or_else(|| {
                HelperError::new(ErrorCode::ListMissing, "list storage is unavailable")
            })?;
            let paths = {
                let mut store = store.lock().map_err(|_| {
                    HelperError::new(ErrorCode::Internal, "list storage is unavailable")
                })?;
                request
                    .lists
                    .iter()
                    .map(|reference| store.verified_path_for_staging(reference))
                    .collect::<Result<Vec<_>, _>>()?
            };
            let files = request
                .lists
                .iter()
                .cloned()
                .zip(paths.iter().map(PathBuf::as_path))
                .collect::<Vec<_>>();
            load_list_files(&files)
                .map_err(|error| HelperError::new(ErrorCode::UnsupportedRules, error.to_string()))?
        };
        Ok(RulePlan {
            rules: extra.rules(&effective).clone(),
            temporary_count: request.temporary_rules.len(),
            allow_lan: request.settings.allow_lan,
            lan_segment: lan.segment.route_networks(),
            lan_servers: lan.servers.clone(),
            private_networks: request.settings.private_networks,
            exits: request
                .extra_nodes
                .iter()
                .map(|entry| entry.exit.clone())
                .collect(),
            lists,
        })
    }

    fn prepare_workers(
        &self,
        request: &ConnectRequest,
        endpoint: &ResolvedNodeEndpoints,
        endpoints: &[Option<ResolvedNodeEndpoints>],
        previous: &Workers,
        verbose: bool,
    ) -> Result<WorkerUpdate, HelperError> {
        let settings = &request.settings;
        let main = node_with_endpoints(&request.node, endpoint);
        let rules = request.effective_rule_set();
        let extra = ExtraNodes::new(&request.extra_nodes, endpoints, &rules);
        let extra = extra.slots();
        let xray_nodes = std::iter::once((PROXY_TAG.to_owned(), &main))
            .chain(
                extra
                    .iter()
                    .map(|entry| (exit_tag(entry.index), entry.node)),
            )
            .filter(|(_, node)| uses_xray(node, settings))
            .collect::<Vec<_>>();
        let xray_tags = xray_nodes
            .iter()
            .map(|(tag, _)| tag.clone())
            .collect::<Vec<_>>();
        let xray_error = |error: rosetun_engine::errors::EngineError| {
            HelperError::new(ErrorCode::XrayStartFailed, error.to_string())
        };
        let xray = Worker::prepare(
            previous.xray.as_ref(),
            &xray_tags,
            || {
                self.xray
                    .as_ref()
                    .ok_or_else(|| {
                        HelperError::new(ErrorCode::XrayStartFailed, "Xray helper is unavailable")
                    })?
                    .locate_outbound_worker()
                    .map_err(xray_error)
            },
            |sockets| {
                let nodes = xray_nodes
                    .iter()
                    .map(|(tag, node)| (tag.as_str(), *node, &sockets[tag]))
                    .collect::<Vec<_>>();
                rosetun_engine_xray::render_outbound_worker(
                    &nodes,
                    &settings.tls_fragment,
                    verbose,
                    settings.log_level,
                )
                .map_err(xray_error)
            },
        )?;
        let xray_sockets = xray.candidate(&previous.xray).map(|worker| &worker.sockets);
        let singbox_main = (!uses_xray(&main, settings)).then_some(&main);
        let sb_extra = extra
            .iter()
            .filter_map(|entry| {
                let socks = xray_sockets.and_then(|sockets| sockets.get(&exit_tag(entry.index)));
                let needed_for_chain = extra.iter().any(|child| child.via == Some(entry.exit));
                (socks.is_none() || needed_for_chain).then(|| ExtraOutbound {
                    socks: socks.map(socks_proxy),
                    ..*entry
                })
            })
            .collect::<Vec<_>>();
        let singbox_tags = singbox_main
            .iter()
            .map(|_| PROXY_TAG.to_owned())
            .chain(
                sb_extra
                    .iter()
                    .filter(|entry| entry.socks.is_none())
                    .map(|entry| exit_tag(entry.index)),
            )
            .collect::<Vec<_>>();
        let singbox = Worker::prepare(
            previous.singbox.as_ref(),
            &singbox_tags,
            || {
                self.engines
                    .get(settings.engine)
                    .ok_or_else(|| {
                        HelperError::new(ErrorCode::EngineFailed, "sing-box backend is unavailable")
                    })?
                    .locate_outbound_worker()
                    .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))
            },
            |sockets| {
                let listeners = singbox_tags
                    .iter()
                    .map(|tag| (tag.as_str(), socks_proxy(&sockets[tag])))
                    .collect::<Vec<_>>();
                rosetun_engine_singbox::render_outbound_worker(
                    singbox_main,
                    &sb_extra,
                    &listeners,
                    verbose,
                    settings.log_level,
                )
                .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))
            },
        )?;
        Ok(WorkerUpdate { singbox, xray })
    }

    fn spawn_workers(
        &mut self,
        kind: EngineKind,
        update: &mut WorkerUpdate,
    ) -> Result<(), HelperError> {
        let cold_start = self.cold_start;
        for (change, code) in [
            (&mut update.xray, ErrorCode::XrayStartFailed),
            (&mut update.singbox, ErrorCode::EngineFailed),
        ] {
            let WorkerChange::Replace(Some(worker)) = change else {
                continue;
            };
            check_cancelled(&self.cancelled)?;
            let started = Instant::now();
            let deadline = self.gate.deadline();
            self.cold_start = false;
            let process = if code == ErrorCode::XrayStartFailed {
                let xray = self
                    .xray
                    .as_ref()
                    .ok_or_else(|| HelperError::new(code, "Xray helper is unavailable"))?;
                let sockets = worker.sockets.values().collect::<Vec<_>>();
                xray.spawn_outbound_worker(&worker.binary, &worker.config, &sockets, deadline)
            } else {
                let backend = self
                    .engines
                    .get(kind)
                    .ok_or_else(|| HelperError::new(code, "sing-box backend is unavailable"))?;
                backend.spawn_with_log_gate(
                    &worker.binary,
                    &worker.config,
                    deadline,
                    EngineRights::OutboundWorker,
                )
            };
            let process = worker
                .process
                .insert(process.map_err(|error| HelperError::new(code, error.to_string()))?);
            wait_for_engine_ready_from(process.as_mut(), started, cold_start, &self.cancelled)
                .map_err(|error| {
                    if error.code == ErrorCode::Cancelled {
                        error
                    } else {
                        HelperError::new(code, error.message)
                    }
                })?;
        }
        Ok(())
    }

    fn proxy_lan(
        &self,
        settings: &Settings,
        endpoint: &ResolvedNodeEndpoints,
        extra: &[Option<ResolvedNodeEndpoints>],
    ) -> (LanAccess, Vec<std::net::IpAddr>) {
        let mut servers = Vec::new();
        endpoint.push_unique_ips(&mut servers);
        for resolved in extra.iter().flatten() {
            resolved.push_unique_ips(&mut servers);
        }
        (self.lan.access_for(settings, &servers), servers)
    }

    fn remember_proxy_endpoints(
        &mut self,
        request: &ConnectRequest,
        endpoint: ResolvedNodeEndpoints,
        extra: &[Option<ResolvedNodeEndpoints>],
        tags: ExitTags,
    ) {
        self.last_endpoint = Some(endpoint.into_successful(&request.node.server));
        exits::remember(&mut self.last_extra_endpoints, &request.extra_nodes, extra);
        self.exit_tags = tags;
    }

    pub(super) fn delay_entry(&self) -> Option<&DelayInbound> {
        self.proxy_session
            .as_ref()
            .map(|proxy| &proxy.entry)
            .or_else(|| {
                self.control
                    .as_ref()
                    .and_then(|control| control.delay.as_ref())
            })
    }

    pub(super) fn check_proxy_dns(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<(), HelperError> {
        let server = self.tunnel_dns.ok_or_else(|| {
            HelperError::new(ErrorCode::DnsTimeout, "local proxy DNS is unavailable")
        })?;
        let proxy = self.proxy_session.as_mut().ok_or_else(|| {
            HelperError::new(ErrorCode::EngineFailed, "local proxy is unavailable")
        })?;
        dns::check_cancellable(
            server,
            self.dns_timeout.min(timeout),
            self.dns_attempt_timeout.min(timeout),
            None,
            || Ok((proxy.exited().1.is_none(), Default::default())),
            || self.cancelled.load(std::sync::atomic::Ordering::Acquire),
        )
    }
}

fn delay_entry(
    old: Option<&DelayInbound>,
    previous: &[(ExitId, Option<String>)],
    tags: &ExitTags,
) -> Result<DelayInbound, HelperError> {
    let mut entry = DelayInbound::local(
        std::iter::once(PROXY_TAG.to_owned())
            .chain(tags.iter().filter_map(|(_, tag)| tag.clone()))
            .chain([SUBSCRIPTION_PROXY_USER.to_owned()]),
    )
    .map_err(|_| {
        HelperError::new(
            ErrorCode::EngineFailed,
            "cannot create proxy entry credentials",
        )
    })?;
    if let Some(old) = old {
        entry.address = old.address;
        for account in &mut entry.accounts {
            let same_exit = tags.iter().any(|(exit, tag)| {
                tag.as_ref() == Some(&account.tag)
                    && previous
                        .iter()
                        .any(|(old_exit, old_tag)| exit == old_exit && tag == old_tag)
            });
            if (same_exit || matches!(account.tag.as_str(), PROXY_TAG | SUBSCRIPTION_PROXY_USER))
                && let Some(old) = old.accounts.iter().find(|old| old.tag == account.tag)
            {
                account.password.clone_from(&old.password);
            }
        }
    } else {
        entry.address.set_port(0);
    }
    Ok(entry)
}

fn rule_error(error: rosetun_dataplane::rules::RulesError) -> HelperError {
    HelperError::new(ErrorCode::UnsupportedRules, error.to_string())
}
