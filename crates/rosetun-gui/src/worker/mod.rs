use std::fs;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;
use std::sync::{Arc, Mutex, mpsc::Sender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eframe::egui;
use rosetun_config::{
    AppConfig, DnsSettings, Exit, ExitId, ExitTarget, LanguageSetting, List, ListId,
    LiveConnection, Node, NodeId, Rule, RuleId, RuleMatcher, RuleSet, RuleSetId, RuleTarget,
    Status, Subscription, SubscriptionId,
};
use rosetun_core::{
    AddFromUrlError, AddOptions, AddedRules, AppliedSnapshot, ExitError, ExitInfo, ExitInfoError,
    ListError, ListOperation, ListPreparationError, ListUpdateResult, MissingListCategory,
    MoveSubscriptionError, NewExit, PING_PARALLEL, PING_TIMEOUT, Ping, Release,
    RemoveSubscriptionError, RenameSubscriptionError, RuleDestination, RuleSetError,
    SelectNodeError, SelectRuleSetError, SettingChange, SettingsError, Store, StoreError,
    SubscriptionUpdateResult, Timeouts, UpdateCheckError, UpdateReport, UpdateSubscriptionError,
    add_prepared_subscription, add_rule, add_rules, change_exit_target, create_exit,
    create_rule_set, delete_exit, delete_rule_set, move_rule, move_rules, move_subscription,
    ping_all, prepare_subscription, reconcile_lists, remove_rule, remove_rules,
    remove_subscription, rename_exit, rename_rule_set, rename_subscription, reset_settings,
    restore_rules_and_dns, select_node, select_rule_set, set_default_target, set_dns,
    set_interface_scale, set_kill_switch, set_language, set_rule_enabled, set_rule_target,
    set_verbose_log, update_all, update_all_lists, update_list, update_rule, update_subscription,
};
use rosetun_ipc::{
    ClientError, ConnectRequest, ConnectRequestError, HelperClient, MAX_PROBE_NODES, ProbeRequest,
    ProbeResult, TunnelDelays,
};
use rosetun_processes::{ProcessListError, RunningProcess, running_processes};

use crate::state::{ExitInputs, ExitRoute};

const CLIENT_NAME: &str = concat!("rosetun-gui/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, thiserror::Error)]
pub(crate) enum HelperCommandError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Request(#[from] ConnectRequestError),
    #[error(transparent)]
    ListPreparation(#[from] ListPreparationError),
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
    SystemChecks {
        request: u64,
        results: Vec<rosetun_core::CheckResult>,
    },
    #[cfg(windows)]
    ReportSaved {
        result: std::io::Result<Option<PathBuf>>,
        new_checks: Option<Vec<rosetun_core::CheckResult>>,
    },
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
    Setting(SettingChange, Result<(), SettingsError>),
    #[cfg(windows)]
    AutostartLoaded(std::io::Result<bool>),
    #[cfg(windows)]
    SetAutostart(std::io::Result<bool>),
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
    CreateExit(Result<Exit, ExitError>),
    SaveExit(Result<(), ExitError>),
    RenameExit(Result<(), ExitError>),
    DeleteExit {
        id: ExitId,
        result: Result<usize, ExitError>,
    },
    SetRuleEnabled(Result<(), RuleSetError>),
    MoveRule(Result<(), RuleSetError>),
    MoveRules(Result<(), RuleSetError>),
    RemoveRule(Result<(), RuleSetError>),
    RemoveRules(Result<(), RuleSetError>),
    SetKillSwitch(Result<(), StoreError>),
    SetLockdown {
        enabled: bool,
        result: Result<(), HelperCommandError>,
    },
    Add(Result<(Subscription, UpdateReport), AddFromUrlError>),
    BrowsedListFile(Option<PathBuf>),
    AddList(Result<(List, Option<usize>), ListError>),
    ListAvailability {
        revision: u64,
        result: Result<Vec<MissingListCategory>, ListError>,
    },
    RenameList(Result<List, ListError>),
    RemoveList(Result<(), ListError>),
    FileListUpdateCancelled(ListId),
    Update {
        id: SubscriptionId,
        result: Result<(Subscription, UpdateReport), UpdateSubscriptionError>,
    },
    UpdateList {
        id: ListId,
        result: Result<List, ListError>,
        manual: bool,
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
    TunnelDelay(Result<TunnelDelays, HelperCommandError>),
    Connections {
        result: Result<(Vec<LiveConnection>, Vec<LiveConnection>), HelperCommandError>,
        /// When the answer arrived, by `display::monotonic_ms`.
        received_ms: u64,
    },
    /// Program path and its name.
    ProgramNames(Vec<(String, String)>),
    CloseConnection(Result<(), HelperCommandError>),
    UpdateAll {
        subscriptions: Result<Vec<SubscriptionUpdateResult>, StoreError>,
        lists: Result<Vec<ListUpdateResult>, StoreError>,
    },
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
    /// Requests for the connection list, served over one kept pipe connection.
    connections: Arc<Mutex<Option<Sender<()>>>>,
}

#[derive(Clone)]
struct ConfigPublisher {
    store: Store,
    tx: Sender<WorkerEvent>,
    repaint: egui::Context,
    generation: Arc<Mutex<u64>>,
}

mod helper;
mod lists;
mod programs;
#[cfg(windows)]
mod report;
mod rules;
mod settings;
mod subscriptions;
mod system_checks;
mod updates;

impl WorkerDispatcher {
    fn spawn_task(&self, name: &'static str, task: impl FnOnce(ConfigPublisher) + Send + 'static) {
        let publisher = self.publisher.clone();
        thread::Builder::new()
            .name(name.into())
            .spawn(move || task(publisher))
            .expect("could not spawn GUI worker");
    }

    fn spawn_complete(
        &self,
        name: &'static str,
        task: impl FnOnce(&Store) -> WorkerEvent + Send + 'static,
    ) {
        self.spawn_task(name, move |publisher| {
            publisher.complete(task(&publisher.store));
        });
    }

    fn spawn_helper<T: Send + 'static>(
        &self,
        name: &'static str,
        command: impl FnOnce(&mut HelperClient) -> Result<T, ClientError> + Send + 'static,
        finish: impl FnOnce(ConfigPublisher, Result<T, HelperCommandError>) + Send + 'static,
    ) {
        self.spawn_task(name, move |publisher| {
            finish(publisher, with_helper(command));
        });
    }
}

impl ConfigPublisher {
    fn publish_initial(&self) -> bool {
        self.publish_with_reconciliation(true)
    }

    fn publish(&self) -> bool {
        self.publish_with_reconciliation(false)
    }

    fn publish_with_reconciliation(&self, reconcile_on_start: bool) -> bool {
        // Loading and publication share one lock: a delayed reader must not
        // number an old snapshot after a newer mutation has been published.
        let mut generation = self
            .generation
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let event = match self.store.load() {
            Ok(config) => {
                if reconcile_on_start && let Err(error) = reconcile_lists(&self.store) {
                    subscriptions::log_list_error("reconcile", &error);
                }
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
    thread::Builder::new()
        .name("rosetun-config-watch".into())
        .spawn(move || {
            let mut previous = file_stamp(watcher.store.path()).ok();
            if !watcher.publish_initial() {
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
        })
        .expect("could not spawn config watcher");

    thread::Builder::new()
        .name("rosetun-helper-watch".into())
        .spawn(move || {
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
                        let mut last_status = None;
                        let mut quiet = 0;
                        loop {
                            match client.status() {
                                Ok(status) => {
                                    rosetun_core::follow_service_status(Some(&status));
                                    let wake = quiet >= QUIET_STATUS_LIMIT
                                        || status_changed(last_status.as_ref(), &status);
                                    quiet = if wake { 0 } else { quiet + 1 };
                                    last_status = Some(status.clone());
                                    let event = WorkerEvent::Status(status);
                                    let sent = if wake {
                                        emit(&tx, &repaint, event)
                                    } else {
                                        tx.send(event).is_ok()
                                    };
                                    if !sent {
                                        return;
                                    }
                                }
                                Err(error) => {
                                    rosetun_core::follow_service_status(None);
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
                        rosetun_core::follow_service_status(None);
                        log_helper_availability(&mut available, false);
                        if !emit(&tx, &repaint, WorkerEvent::HelperUnavailable(error)) {
                            return;
                        }
                    }
                }
                thread::sleep(Duration::from_secs(2));
            }
        })
        .expect("could not spawn helper watcher");
    WorkerDispatcher {
        publisher,
        connections: Arc::default(),
    }
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

/// Traffic-only status updates queue without waking the window; this many of them in a row
/// wake it anyway, so a hidden window drains the queue about once a minute.
const QUIET_STATUS_LIMIT: u32 = 60;

fn status_changed(last: Option<&Status>, next: &Status) -> bool {
    last.is_none_or(|last| {
        Status {
            traffic: next.traffic,
            ..last.clone()
        } != *next
    })
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

    #[test]
    fn only_non_traffic_status_changes_wake_the_window() {
        let connected = Status {
            state: rosetun_config::ConnectionState::Connected,
            since_unix: Some(1_000),
            ..Status::default()
        };
        assert!(status_changed(None, &connected));
        let busier = Status {
            traffic: rosetun_config::Traffic {
                down_bps: 1_000,
                ..Default::default()
            },
            ..connected.clone()
        };
        assert!(!status_changed(Some(&connected), &busier));
        assert!(status_changed(Some(&busier), &Status::default()));
    }
}
