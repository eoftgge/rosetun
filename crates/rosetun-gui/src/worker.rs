use std::fs;
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::process::Command;
use std::sync::{Arc, Mutex, mpsc::Sender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eframe::egui;
use rosetun_config::{
    AppConfig, DnsSettings, LanguageSetting, Node, NodeId, Rule, RuleId, RuleMatcher, RuleSet,
    RuleSetId, RuleTarget, Status, Subscription, SubscriptionId,
};
use rosetun_core::{
    AddFromUrlError, AddOptions, AddedRules, AppliedSnapshot, ExitInfo, ExitInfoError,
    MoveSubscriptionError, PING_PARALLEL, PING_TIMEOUT, Ping, Release, RemoveSubscriptionError,
    RenameSubscriptionError, RuleSetError, SelectNodeError, SelectRuleSetError, SettingsError,
    Store, StoreError, SubscriptionUpdateResult, Timeouts, UpdateCheckError, UpdateReport,
    UpdateSubscriptionError, add_prepared_subscription, add_rule, add_rules, create_rule_set,
    delete_rule_set, move_rule, move_rules, move_subscription, ping_all, prepare_subscription,
    remove_rule, remove_rules, remove_subscription, rename_rule_set, rename_subscription,
    reset_settings, restore_rules_and_dns, select_node, select_rule_set, set_default_target,
    set_dns, set_interface_scale, set_kill_switch, set_language, set_rule_enabled, set_rule_target,
    set_verbose_log, update_all, update_rule, update_subscription,
};
use rosetun_ipc::{
    ClientError, ConnectRequest, ConnectRequestError, HelperClient, MAX_PROBE_NODES, ProbeOutcome,
    ProbeRequest, ProbeResult,
};
use rosetun_processes::{ProcessListError, RunningProcess, running_processes};

use crate::state::ExitRoute;
#[cfg(windows)]
use crate::strings::t;

const CLIENT_NAME: &str = concat!("rosetun-gui/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, thiserror::Error)]
pub(crate) enum HelperCommandError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Request(#[from] ConnectRequestError),
    #[error(transparent)]
    Client(#[from] ClientError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigWorkerError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("could not inspect the configuration file: {0}")]
    Metadata(std::io::Error),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct FailureInterference {
    pub(crate) other_vpns: Vec<String>,
    pub(crate) traffic_tools: Vec<String>,
}

pub(crate) enum WorkerEvent {
    Config {
        generation: u64,
        config: AppConfig,
    },
    ConfigError(ConfigWorkerError),
    HelperAvailable {
        version: String,
    },
    HelperUnavailable(ClientError),
    Status(Status),
    FailureInterference {
        request: u64,
        hints: FailureInterference,
    },
    Exit {
        generation: u64,
        route: ExitRoute,
        result: Result<ExitInfo, ExitInfoError>,
    },
    ConnectSnapshot(AppliedSnapshot),
    Connect(Result<ConnectRequest, HelperCommandError>),
    Apply(Result<ConnectRequest, HelperCommandError>),
    RestoreApplied(Result<AppliedSnapshot, RuleSetError>),
    RestoreEdits(Result<AppliedSnapshot, RuleSetError>),
    TemporaryRules {
        request: u64,
        result: Result<Vec<Rule>, HelperCommandError>,
    },
    Disconnect(Result<(), HelperCommandError>),
    SetInterfaceScale(Result<(), SettingsError>),
    SetLanguage(Result<(), SettingsError>),
    SetReduceMotion(Result<(), SettingsError>),
    #[cfg(windows)]
    AutostartLoaded(std::io::Result<bool>),
    #[cfg(windows)]
    SetAutostart(std::io::Result<bool>),
    #[cfg(windows)]
    SetCloseToTray(Result<(), SettingsError>),
    SetConnectOnStart(Result<(), SettingsError>),
    SetAutoReconnect(Result<(), SettingsError>),
    SetAutoUpdateSubscriptions(Result<(), SettingsError>),
    SetCheckUpdates(Result<(), SettingsError>),
    SkipVersion(Result<(), SettingsError>),
    UpdateCheck {
        checked_at: u64,
        result: Result<Option<Release>, UpdateCheckError>,
    },
    SetDns(Result<(), SettingsError>),
    ResetSettings(Result<(), SettingsError>),
    SetVerboseLog(Result<(), SettingsError>),
    #[cfg(windows)]
    OpenFolder(Result<(), std::io::Error>),
    SelectNode(Result<String, SelectNodeError>),
    SelectRuleSet(Result<(), SelectRuleSetError>),
    CreateRuleSet(Result<RuleSet, RuleSetError>),
    RenameRuleSet(Result<(), RuleSetError>),
    DeleteRuleSet(Result<(), RuleSetError>),
    SetDefaultTarget(Result<(), RuleSetError>),
    Processes {
        request: u64,
        result: Result<Vec<RunningProcess>, ProcessListError>,
    },
    #[cfg(windows)]
    BrowsedExecutable(Option<PathBuf>),
    AddRule(Result<Rule, RuleSetError>),
    AddRules(Result<AddedRules, RuleSetError>),
    UpdateRule(Result<(), RuleSetError>),
    SetRuleTarget(Result<(), RuleSetError>),
    SetRuleEnabled(Result<(), RuleSetError>),
    MoveRule(Result<(), RuleSetError>),
    MoveRules(Result<(), RuleSetError>),
    RemoveRule(Result<(), RuleSetError>),
    RemoveRules(Result<(), RuleSetError>),
    SetKillSwitch(Result<(), StoreError>),
    Add(Result<(Subscription, UpdateReport), AddFromUrlError>),
    Update {
        id: SubscriptionId,
        result: Result<(Subscription, UpdateReport), UpdateSubscriptionError>,
    },
    Ping {
        subscription: SubscriptionId,
        node: NodeId,
        result: Ping,
    },
    PingDone(SubscriptionId),
    FullCheck {
        subscription: SubscriptionId,
        result: Result<Vec<ProbeResult>, HelperCommandError>,
    },
    TunnelDelay(Result<ProbeOutcome, HelperCommandError>),
    UpdateAll(Result<Vec<SubscriptionUpdateResult>, StoreError>),
    Remove {
        id: SubscriptionId,
        result: Result<(), RemoveSubscriptionError>,
    },
    RenameSubscription(Result<(), RenameSubscriptionError>),
    MoveSubscription(Result<(), MoveSubscriptionError>),
}

#[derive(Clone)]
pub(crate) struct WorkerDispatcher {
    publisher: ConfigPublisher,
}

#[derive(Clone)]
struct ConfigPublisher {
    store: Store,
    tx: Sender<WorkerEvent>,
    repaint: egui::Context,
    generation: Arc<Mutex<u64>>,
}

impl ConfigPublisher {
    fn publish(&self) -> bool {
        // Loading and publication share one lock: a delayed reader must not
        // number an old snapshot after a newer mutation has been published.
        let mut generation = self
            .generation
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let event = match self.store.load() {
            Ok(config) => {
                *generation += 1;
                WorkerEvent::Config {
                    generation: *generation,
                    config,
                }
            }
            Err(error) => WorkerEvent::ConfigError(ConfigWorkerError::Store(error)),
        };
        emit(&self.tx, &self.repaint, event)
    }

    fn complete(&self, event: WorkerEvent) {
        self.publish();
        emit(&self.tx, &self.repaint, event);
    }
}

impl WorkerDispatcher {
    pub(crate) fn connect(&self) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            tracing::info!("Connect command started");
            let result = publisher
                .store
                .load()
                .map_err(HelperCommandError::Store)
                .and_then(|config| {
                    let request = ConnectRequest::from_config(&config)?;
                    let snapshot = AppliedSnapshot::from_config(&config);
                    with_helper(|client| client.connect_tunnel(request.clone()))?;
                    Ok((request, snapshot))
                });
            let result = match result {
                Ok((request, snapshot)) => {
                    tracing::info!("Connect command succeeded");
                    emit(
                        &publisher.tx,
                        &publisher.repaint,
                        WorkerEvent::ConnectSnapshot(snapshot),
                    );
                    Ok(request)
                }
                Err(error) => {
                    tracing::warn!(%error, "Connect command failed");
                    Err(error)
                }
            };
            publisher.complete(WorkerEvent::Connect(result));
        });
    }

    pub(crate) fn apply(&self, request: Box<ConnectRequest>) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            tracing::info!("Apply command started");
            let result = with_helper(|client| client.apply_tunnel(request.as_ref().clone()))
                .map(|()| *request);
            match &result {
                Ok(_) => tracing::info!("Apply command succeeded"),
                Err(error) => tracing::warn!(%error, "Apply command failed"),
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::Apply(result),
            );
        });
    }

    pub(crate) fn restore_applied(&self, snapshot: AppliedSnapshot) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = restore_rules_and_dns(&publisher.store, &snapshot);
            publisher.complete(WorkerEvent::RestoreApplied(result));
        });
    }

    pub(crate) fn restore_edits(&self, snapshot: AppliedSnapshot) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = restore_rules_and_dns(&publisher.store, &snapshot);
            publisher.complete(WorkerEvent::RestoreEdits(result));
        });
    }

    pub(crate) fn load_temporary_rules(&self, request: u64) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = with_helper(|client| client.temporary_rules());
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::TemporaryRules { request, result },
            );
        });
    }

    pub(crate) fn disconnect(&self) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            tracing::info!("Disconnect command started");
            let result = with_helper(|client| client.disconnect_tunnel());
            match &result {
                Ok(()) => tracing::info!("Disconnect command succeeded"),
                Err(error) => tracing::warn!(%error, "Disconnect command failed"),
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::Disconnect(result),
            );
        });
    }

    pub(crate) fn set_interface_scale(&self, percent: u16) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = set_interface_scale(&publisher.store, percent);
            publisher.complete(WorkerEvent::SetInterfaceScale(result));
        });
    }

    pub(crate) fn set_language(&self, language: LanguageSetting) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = set_language(&publisher.store, language);
            publisher.complete(WorkerEvent::SetLanguage(result));
        });
    }

    pub(crate) fn set_reduce_motion(&self, enabled: bool) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = rosetun_core::set_reduce_motion(&publisher.store, enabled);
            publisher.complete(WorkerEvent::SetReduceMotion(result));
        });
    }

    #[cfg(windows)]
    pub(crate) fn load_autostart(&self) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = rosetun_shell::autostart_enabled();
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::AutostartLoaded(result),
            );
        });
    }

    #[cfg(windows)]
    pub(crate) fn set_autostart(&self, enabled: bool) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = (|| {
                if enabled {
                    let exe = std::env::current_exe()?;
                    rosetun_shell::enable_autostart(&exe, crate::HIDDEN_ARG)?;
                } else {
                    rosetun_shell::disable_autostart()?;
                }
                rosetun_shell::autostart_enabled()
            })();
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::SetAutostart(result),
            );
        });
    }

    #[cfg(windows)]
    pub(crate) fn set_close_to_tray(&self, enabled: bool) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = rosetun_core::set_close_to_tray(&publisher.store, enabled);
            publisher.complete(WorkerEvent::SetCloseToTray(result));
        });
    }

    pub(crate) fn set_connect_on_start(&self, enabled: bool) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = rosetun_core::set_connect_on_start(&publisher.store, enabled);
            publisher.complete(WorkerEvent::SetConnectOnStart(result));
        });
    }

    pub(crate) fn set_auto_reconnect(&self, enabled: bool) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = rosetun_core::set_auto_reconnect(&publisher.store, enabled);
            publisher.complete(WorkerEvent::SetAutoReconnect(result));
        });
    }

    pub(crate) fn set_auto_update_subscriptions(&self, enabled: bool) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = rosetun_core::set_auto_update_subscriptions(&publisher.store, enabled);
            publisher.complete(WorkerEvent::SetAutoUpdateSubscriptions(result));
        });
    }

    pub(crate) fn set_check_updates(&self, enabled: bool) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = rosetun_core::set_check_updates(&publisher.store, enabled);
            publisher.complete(WorkerEvent::SetCheckUpdates(result));
        });
    }

    pub(crate) fn skip_version(&self, version: String) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = rosetun_core::skip_version(&publisher.store, Some(version));
            publisher.complete(WorkerEvent::SkipVersion(result));
        });
    }

    pub(crate) fn check_updates(&self) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = rosetun_core::latest_release(Duration::from_secs(15));
            let checked_at = crate::state::now_unix();
            if result.is_ok() {
                if rosetun_core::record_update_check(&publisher.store, checked_at).is_err() {
                    tracing::warn!("Could not save update check time");
                } else {
                    publisher.publish();
                }
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::UpdateCheck { checked_at, result },
            );
        });
    }

    pub(crate) fn set_dns(&self, dns: DnsSettings) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = set_dns(&publisher.store, dns);
            publisher.complete(WorkerEvent::SetDns(result));
        });
    }

    pub(crate) fn reset_settings(&self) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = reset_settings(&publisher.store);
            publisher.complete(WorkerEvent::ResetSettings(result));
        });
    }

    pub(crate) fn set_verbose_log(&self, on: bool) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_secs())
                .unwrap_or_default();
            let result = set_verbose_log(&publisher.store, on, now_unix);
            publisher.complete(WorkerEvent::SetVerboseLog(result));
        });
    }

    #[cfg(windows)]
    pub(crate) fn open_folder(&self, folder: PathBuf) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = Command::new("explorer.exe").arg(folder).spawn().map(|_| ());
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::OpenFolder(result),
            );
        });
    }

    pub(crate) fn select_node(&self, subscription: SubscriptionId, node: NodeId) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = select_node(&publisher.store, &subscription, &node);
            publisher.complete(WorkerEvent::SelectNode(result));
        });
    }

    pub(crate) fn select_rule_set(&self, id: Option<RuleSetId>) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = select_rule_set(&publisher.store, id.as_ref());
            publisher.complete(WorkerEvent::SelectRuleSet(result));
        });
    }

    pub(crate) fn create_rule_set(&self, name: String) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = create_rule_set(&publisher.store, &name, RuleTarget::Proxy);
            publisher.complete(WorkerEvent::CreateRuleSet(result));
        });
    }

    pub(crate) fn rename_rule_set(&self, id: RuleSetId, name: String) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = rename_rule_set(&publisher.store, &id, &name);
            publisher.complete(WorkerEvent::RenameRuleSet(result));
        });
    }

    pub(crate) fn delete_rule_set(&self, id: RuleSetId) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = delete_rule_set(&publisher.store, &id);
            publisher.complete(WorkerEvent::DeleteRuleSet(result));
        });
    }

    pub(crate) fn set_default_target(&self, id: RuleSetId, target: RuleTarget) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = set_default_target(&publisher.store, &id, target);
            publisher.complete(WorkerEvent::SetDefaultTarget(result));
        });
    }

    pub(crate) fn check_failure_interference(&self, request: u64, own_alias: String) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let adapters = rosetun_adapters::other_tunnels(&own_alias);
            let processes = running_processes();
            if adapters.is_err() || processes.is_err() {
                tracing::warn!("Could not inspect possible connection conflicts");
            }
            let hints = FailureInterference {
                other_vpns: adapters.unwrap_or_default(),
                traffic_tools: processes.map(conflicting_processes).unwrap_or_default(),
            };
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::FailureInterference { request, hints },
            );
        });
    }

    pub(crate) fn load_processes(&self, request: u64) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = running_processes();
            match &result {
                Ok(processes) => {
                    tracing::info!(count = processes.len(), "Loaded running processes")
                }
                Err(error) => tracing::warn!(%error, "Could not load running processes"),
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::Processes { request, result },
            );
        });
    }

    #[cfg(windows)]
    pub(crate) fn browse_executable(&self) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let path = rfd::FileDialog::new()
                .set_title(t().choose_program)
                .add_filter(t().programs, &["exe"])
                .pick_file();
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::BrowsedExecutable(path),
            );
        });
    }

    pub(crate) fn add_rule(&self, set: RuleSetId, matcher: RuleMatcher, target: RuleTarget) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = add_rule(&publisher.store, &set, matcher, target);
            publisher.complete(WorkerEvent::AddRule(result));
        });
    }

    pub(crate) fn add_rules(&self, set: RuleSetId, matchers: Vec<RuleMatcher>, target: RuleTarget) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = add_rules(&publisher.store, &set, matchers, target);
            publisher.complete(WorkerEvent::AddRules(result));
        });
    }

    pub(crate) fn update_rule(
        &self,
        set: RuleSetId,
        rule: RuleId,
        matcher: RuleMatcher,
        target: RuleTarget,
    ) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = update_rule(&publisher.store, &set, &rule, matcher, target);
            publisher.complete(WorkerEvent::UpdateRule(result));
        });
    }

    pub(crate) fn set_rule_target(&self, set: RuleSetId, rule: RuleId, target: RuleTarget) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = set_rule_target(&publisher.store, &set, &rule, target);
            publisher.complete(WorkerEvent::SetRuleTarget(result));
        });
    }

    pub(crate) fn set_rule_enabled(&self, set: RuleSetId, rule: RuleId, enabled: bool) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = set_rule_enabled(&publisher.store, &set, &rule, enabled);
            publisher.complete(WorkerEvent::SetRuleEnabled(result));
        });
    }

    pub(crate) fn move_rule(&self, set: RuleSetId, rule: RuleId, to_index: usize) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = move_rule(&publisher.store, &set, &rule, to_index);
            publisher.complete(WorkerEvent::MoveRule(result));
        });
    }

    pub(crate) fn move_rules(&self, set: RuleSetId, rules: Vec<RuleId>, to_index: usize) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = move_rules(&publisher.store, &set, &rules, to_index);
            publisher.complete(WorkerEvent::MoveRules(result));
        });
    }

    pub(crate) fn remove_rule(&self, set: RuleSetId, rule: RuleId) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = remove_rule(&publisher.store, &set, &rule);
            publisher.complete(WorkerEvent::RemoveRule(result));
        });
    }

    pub(crate) fn remove_rules(&self, set: RuleSetId, rules: Vec<RuleId>) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = remove_rules(&publisher.store, &set, &rules);
            publisher.complete(WorkerEvent::RemoveRules(result));
        });
    }

    pub(crate) fn set_kill_switch(&self, enabled: bool) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = set_kill_switch(&publisher.store, enabled);
            publisher.complete(WorkerEvent::SetKillSwitch(result));
        });
    }

    pub(crate) fn add(&self, input: String, options: AddOptions) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result =
                prepare_subscription(&publisher.store, &input, options).and_then(|prepared| {
                    add_prepared_subscription(&publisher.store, prepared, Timeouts::default())
                });
            if let Err(error) = &result {
                log_subscription_error("add", error);
            }
            publisher.complete(WorkerEvent::Add(result));
        });
    }

    pub(crate) fn update(&self, id: SubscriptionId) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = update_subscription(&publisher.store, &id, Timeouts::default());
            if let Err(error) = &result {
                log_subscription_error("update", error);
            }
            publisher.complete(WorkerEvent::Update { id, result });
        });
    }

    pub(crate) fn ping(&self, id: SubscriptionId, node: Option<NodeId>) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let subscription = publisher.store.load().ok().and_then(|config| {
                config
                    .subscriptions
                    .into_iter()
                    .find(|subscription| subscription.id == id)
            });
            if let Some(subscription) = subscription {
                let nodes = check_nodes(&subscription, node.as_ref());
                let (tcp_nodes, unsupported) = ping_targets(&nodes);
                for node in unsupported {
                    emit(
                        &publisher.tx,
                        &publisher.repaint,
                        WorkerEvent::Ping {
                            subscription: id.clone(),
                            node: node.id.clone(),
                            result: Ping::Unsupported,
                        },
                    );
                }
                let targets: Vec<_> = tcp_nodes
                    .iter()
                    .map(|node| (node.server.clone(), node.port))
                    .collect();
                if !targets.is_empty() {
                    ping_all(&targets, PING_PARALLEL, PING_TIMEOUT, |index, result| {
                        emit(
                            &publisher.tx,
                            &publisher.repaint,
                            WorkerEvent::Ping {
                                subscription: id.clone(),
                                node: tcp_nodes[index].id.clone(),
                                result,
                            },
                        );
                    });
                }
            }
            emit(&publisher.tx, &publisher.repaint, WorkerEvent::PingDone(id));
        });
    }

    pub(crate) fn full_check(&self, id: SubscriptionId, node: Option<NodeId>) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = publisher
                .store
                .load()
                .map_err(HelperCommandError::Store)
                .and_then(|config| {
                    let Some(subscription) = config.subscriptions.iter().find(|sub| sub.id == id)
                    else {
                        return Ok(Vec::new());
                    };
                    let nodes = check_nodes(subscription, node.as_ref())
                        .into_iter()
                        .take(MAX_PROBE_NODES)
                        .cloned()
                        .collect();
                    let request = ProbeRequest {
                        nodes,
                        settings: config.settings.clone(),
                    };
                    if request.nodes.is_empty() {
                        return Ok(Vec::new());
                    }
                    with_helper(|client| client.probe_nodes(request))
                });
            publisher.complete(WorkerEvent::FullCheck {
                subscription: id,
                result,
            });
        });
    }

    pub(crate) fn tunnel_delay(&self) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = with_helper(|client| client.tunnel_delay());
            publisher.complete(WorkerEvent::TunnelDelay(result));
        });
    }

    pub(crate) fn lookup_exit(&self, generation: u64, route: ExitRoute) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = rosetun_core::exit_info(Duration::from_secs(5));
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::Exit {
                    generation,
                    route,
                    result,
                },
            );
        });
    }

    pub(crate) fn update_all(&self) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = update_all(&publisher.store, Timeouts::default());
            match &result {
                Ok(results) => {
                    for (_, outcome) in results {
                        if let Err(error) = outcome {
                            log_subscription_error("update all", error);
                        }
                    }
                }
                Err(error) => log_subscription_error("update all", error),
            }
            publisher.complete(WorkerEvent::UpdateAll(result));
        });
    }

    pub(crate) fn remove(&self, id: SubscriptionId) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = remove_subscription(&publisher.store, &id);
            if let Err(error) = &result {
                log_subscription_error("remove", error);
            }
            publisher.complete(WorkerEvent::Remove { id, result });
        });
    }

    pub(crate) fn rename_subscription(&self, id: SubscriptionId, name: String) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = rename_subscription(&publisher.store, &id, &name);
            if let Err(error) = &result {
                log_subscription_error("rename", error);
            }
            publisher.complete(WorkerEvent::RenameSubscription(result));
        });
    }

    pub(crate) fn move_subscription(&self, id: SubscriptionId, to_index: usize) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            let result = move_subscription(&publisher.store, &id, to_index);
            if let Err(error) = &result {
                log_subscription_error("move", error);
            }
            publisher.complete(WorkerEvent::MoveSubscription(result));
        });
    }
}

pub(crate) fn start(
    store: Store,
    tx: Sender<WorkerEvent>,
    repaint: egui::Context,
) -> WorkerDispatcher {
    let publisher = ConfigPublisher {
        store,
        tx: tx.clone(),
        repaint: repaint.clone(),
        generation: Arc::new(Mutex::new(0)),
    };
    let watcher = publisher.clone();
    thread::spawn(move || {
        let mut previous = file_stamp(watcher.store.path()).ok();
        if !watcher.publish() {
            return;
        }
        loop {
            thread::sleep(Duration::from_secs(2));
            match file_stamp(watcher.store.path()) {
                Ok(stamp) if previous.as_ref() != Some(&stamp) => {
                    previous = Some(stamp);
                    if !watcher.publish() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    previous = None;
                    if !emit(
                        &watcher.tx,
                        &watcher.repaint,
                        WorkerEvent::ConfigError(ConfigWorkerError::Metadata(error)),
                    ) {
                        return;
                    }
                }
            }
        }
    });

    thread::spawn(move || {
        let endpoint = rosetun_ipc::default_endpoint();
        let mut available = None;
        loop {
            match HelperClient::connect(&endpoint, CLIENT_NAME) {
                Ok(mut client) => {
                    log_helper_availability(&mut available, true);
                    if !emit(
                        &tx,
                        &repaint,
                        WorkerEvent::HelperAvailable {
                            version: client.helper_version().to_owned(),
                        },
                    ) {
                        return;
                    }
                    loop {
                        match client.status() {
                            Ok(status) => {
                                if !emit(&tx, &repaint, WorkerEvent::Status(status)) {
                                    return;
                                }
                            }
                            Err(error) => {
                                log_helper_availability(&mut available, false);
                                if !emit(&tx, &repaint, WorkerEvent::HelperUnavailable(error)) {
                                    return;
                                }
                                break;
                            }
                        }
                        thread::sleep(Duration::from_secs(1));
                    }
                }
                Err(error) => {
                    log_helper_availability(&mut available, false);
                    if !emit(&tx, &repaint, WorkerEvent::HelperUnavailable(error)) {
                        return;
                    }
                }
            }
            thread::sleep(Duration::from_secs(2));
        }
    });
    WorkerDispatcher { publisher }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FileStamp {
    Missing,
    Present { modified: SystemTime, length: u64 },
}

fn file_stamp(path: &Path) -> Result<FileStamp, std::io::Error> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(FileStamp::Present {
            modified: metadata.modified()?,
            length: metadata.len(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(FileStamp::Missing),
        Err(error) => Err(error),
    }
}

fn check_nodes<'a>(subscription: &'a Subscription, selected: Option<&NodeId>) -> Vec<&'a Node> {
    subscription
        .nodes
        .iter()
        .filter(|node| selected.is_none_or(|id| &node.id == id))
        .collect()
}

fn ping_targets<'a>(nodes: &[&'a Node]) -> (Vec<&'a Node>, Vec<&'a Node>) {
    nodes
        .iter()
        .copied()
        .partition(|node| !matches!(&node.outbound, rosetun_config::Outbound::Hysteria2(_)))
}

fn conflicting_processes(processes: Vec<RunningProcess>) -> Vec<String> {
    let mut names: Vec<_> = processes
        .into_iter()
        .filter(|process| {
            process.name.eq_ignore_ascii_case("winws.exe")
                || process.name.eq_ignore_ascii_case("goodbyedpi.exe")
        })
        .map(|process| process.name)
        .collect();
    names.sort_by_key(|name| name.to_ascii_lowercase());
    names.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    names
}

fn with_helper<T>(
    operation: impl FnOnce(&mut HelperClient) -> Result<T, ClientError>,
) -> Result<T, HelperCommandError> {
    let mut client = HelperClient::connect(&rosetun_ipc::default_endpoint(), CLIENT_NAME)?;
    operation(&mut client).map_err(Into::into)
}

fn log_helper_availability(previous: &mut Option<bool>, available: bool) {
    if previous.replace(available) == Some(available) {
        return;
    }
    if available {
        tracing::info!("Helper available");
    } else {
        tracing::warn!("Helper unavailable");
    }
}

fn log_subscription_error(operation: &str, error: &impl std::fmt::Display) {
    let message = without_urls(&error.to_string());
    tracing::warn!(operation, error = %message, "Subscription operation failed");
}

fn without_urls(message: &str) -> String {
    message
        .split_whitespace()
        .map(|word| if word.contains("://") { "[URL]" } else { word })
        .collect::<Vec<_>>()
        .join(" ")
}

fn emit(tx: &Sender<WorkerEvent>, repaint: &egui::Context, event: WorkerEvent) -> bool {
    if tx.send(event).is_err() {
        return false;
    }
    repaint.request_repaint();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn check_nodes_selects_one_node_or_all_and_skips_removed_nodes() {
        let first = Node {
            id: NodeId::new("first"),
            name: "First".into(),
            server: "127.0.0.1".into(),
            port: 443,
            outbound: rosetun_config::Outbound::Vless(rosetun_config::VlessParams {
                uuid: "00000000-0000-0000-0000-000000000000".into(),
                flow: None,
            }),
            stream: Default::default(),
            raw: None,
        };
        let mut second = first.clone();
        second.id = NodeId::new("second");
        let subscription = Subscription {
            id: SubscriptionId::new("test"),
            name: "Test".into(),
            url: "https://example.com/sub".into(),
            nodes: vec![first, second],
            auto_update: false,
            updated_at_unix: None,
            user_agent: None,
            send_hwid: true,
            info: None,
            update_interval_hours: None,
            support_url: None,
            web_page_url: None,
            announce: None,
            notices: vec![],
        };
        assert_eq!(check_nodes(&subscription, None).len(), 2);
        assert_eq!(
            check_nodes(&subscription, Some(&NodeId::new("second")))[0].id,
            NodeId::new("second")
        );
        assert!(check_nodes(&subscription, Some(&NodeId::new("removed"))).is_empty());
    }

    #[test]
    fn hysteria2_is_excluded_from_tcp_ping_without_dropping_vless() {
        let tcp = Node {
            id: NodeId::new("tcp"),
            name: "TCP".into(),
            server: "192.0.2.1".into(),
            port: 443,
            outbound: rosetun_config::Outbound::Vless(rosetun_config::VlessParams {
                uuid: "11111111-1111-1111-1111-111111111111".into(),
                flow: None,
            }),
            stream: Default::default(),
            raw: None,
        };
        let mut udp = tcp.clone();
        udp.id = NodeId::new("udp");
        udp.outbound = rosetun_config::Outbound::Hysteria2(rosetun_config::Hysteria2Params {
            password: "test-secret".into(),
            obfs_password: None,
            port_ranges: Vec::new(),
            up_mbps: None,
            down_mbps: None,
        });
        let (targets, unsupported) = ping_targets(&[&udp, &tcp]);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, tcp.id);
        assert_eq!(unsupported.len(), 1);
        assert_eq!(unsupported[0].id, udp.id);
    }

    #[test]
    fn subscription_errors_do_not_log_urls_or_tokens() {
        assert_eq!(
            without_urls(
                "request failed for happ://add/https://example.com/sub?token=secret: timeout"
            ),
            "request failed for [URL] timeout"
        );
        assert_eq!(
            without_urls("subscription does not exist"),
            "subscription does not exist"
        );
    }

    #[test]
    fn missing_and_present_files_have_distinct_stamps() {
        let path = std::env::temp_dir().join(format!("rosetun-gui-stamp-{}", std::process::id()));
        assert_eq!(file_stamp(&path).unwrap(), FileStamp::Missing);
        fs::write(&path, b"{}").unwrap();
        assert!(matches!(
            file_stamp(&path).unwrap(),
            FileStamp::Present { length: 2, .. }
        ));
        fs::remove_file(&path).unwrap();
        assert_eq!(file_stamp(&path).unwrap(), FileStamp::Missing);
    }

    #[test]
    fn reload_and_publication_are_ordered_across_threads() {
        let path = std::env::temp_dir().join(format!("rosetun-gui-publish-{}", std::process::id()));
        let (tx, rx) = mpsc::channel();
        let publisher = ConfigPublisher {
            store: Store::at(&path),
            tx,
            repaint: egui::Context::default(),
            generation: Arc::new(Mutex::new(0)),
        };
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let publisher = publisher.clone();
                thread::spawn(move || {
                    publisher
                        .store
                        .modify::<_, StoreError>(|config| {
                            config.rule_sets.push(rosetun_config::RuleSet::new(
                                RuleSetId::new(config.rule_sets.len().to_string()),
                                "Test",
                                rosetun_config::RuleTarget::Proxy,
                            ));
                            Ok(())
                        })
                        .unwrap();
                    assert!(publisher.publish());
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        let mut last_count = 0;
        for generation in 1..=8 {
            let WorkerEvent::Config {
                generation: received,
                config,
            } = rx.recv().unwrap()
            else {
                panic!("expected a configuration");
            };
            assert_eq!(received, generation);
            assert!(config.rule_sets.len() >= last_count);
            last_count = config.rule_sets.len();
        }
        assert_eq!(last_count, 8);
        fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod failure_interference_tests {
    use super::{RunningProcess, conflicting_processes};

    #[test]
    fn identifies_traffic_tools_without_process_name_case_or_duplicates() {
        let processes = ["WINWS.EXE", "winws.exe", "GOODBYEDPI.exe", "example.exe"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| RunningProcess {
                pid: index as u32 + 5,
                name: name.into(),
                path: None,
                has_window: false,
            })
            .collect();
        assert_eq!(
            conflicting_processes(processes),
            ["GOODBYEDPI.exe", "WINWS.EXE"]
        );
    }
}
