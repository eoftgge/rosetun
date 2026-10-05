use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc::Sender};
use std::thread;
use std::time::{Duration, SystemTime};

use eframe::egui;
use rosetun_config::{AppConfig, NodeId, RuleSetId, Status, Subscription, SubscriptionId};
use rosetun_core::{
    AddFromUrlError, AddOptions, RemoveSubscriptionError, SelectNodeError, SelectRuleSetError,
    Store, StoreError, SubscriptionUpdateResult, Timeouts, UpdateReport, UpdateSubscriptionError,
    add_prepared_subscription, prepare_subscription, remove_subscription, select_node,
    select_rule_set, set_kill_switch, update_all, update_subscription,
};
use rosetun_ipc::{ClientError, ConnectRequest, ConnectRequestError, HelperClient};

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
    Connect(Result<(), HelperCommandError>),
    Disconnect(Result<(), HelperCommandError>),
    SelectNode(Result<String, SelectNodeError>),
    SelectRuleSet(Result<(), SelectRuleSetError>),
    SetKillSwitch(Result<(), StoreError>),
    Add(Result<(Subscription, UpdateReport), AddFromUrlError>),
    Update {
        id: SubscriptionId,
        result: Result<(Subscription, UpdateReport), UpdateSubscriptionError>,
    },
    UpdateAll(Result<Vec<SubscriptionUpdateResult>, StoreError>),
    Remove {
        id: SubscriptionId,
        result: Result<(), RemoveSubscriptionError>,
    },
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
                .and_then(|config| ConnectRequest::from_config(&config).map_err(Into::into))
                .and_then(|request| with_helper(|client| client.connect_tunnel(request)));
            match &result {
                Ok(()) => tracing::info!("Connect command succeeded"),
                Err(error) => tracing::warn!(%error, "Connect command failed"),
            }
            publisher.complete(WorkerEvent::Connect(result));
        });
    }

    pub(crate) fn disconnect(&self) {
        let publisher = self.publisher.clone();
        thread::spawn(move || {
            tracing::info!("Disconnect command started");
            let result = with_helper(|client| client.disconnect_tunnel());
            match &result {
                Ok(()) => tracing::info!("Connect command succeeded"),
                Err(error) => tracing::warn!(%error, "Connect command failed"),
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::Disconnect(result),
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

fn with_helper(
    operation: impl FnOnce(&mut HelperClient) -> Result<(), ClientError>,
) -> Result<(), HelperCommandError> {
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
