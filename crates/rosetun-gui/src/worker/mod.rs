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

mod helper;
mod rules;
mod settings;
mod subscriptions;
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
        })
        .expect("could not spawn helper watcher");
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
}
