use std::collections::{BTreeMap, BTreeSet};

use rosetun_config::{AppConfig, SubscriptionId};
use rosetun_subscription::{Parsed, Skipped};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateReport {
    pub added: usize,
    pub removed: usize,
    pub retained: usize,
    pub selection_cleared: bool,
    pub skipped: BTreeMap<String, usize>,
    pub notices: Vec<String>,
}

pub fn group_skipped(skipped: &[Skipped]) -> BTreeMap<String, usize> {
    let mut grouped = BTreeMap::new();
    for entry in skipped {
        *grouped.entry(entry.reason.to_string()).or_default() += 1;
    }
    grouped
}

pub(crate) fn apply_update(
    config: &mut AppConfig,
    id: &SubscriptionId,
    parsed: Parsed,
    now_unix: u64,
) -> UpdateReport {
    let subscription = config
        .subscriptions
        .iter_mut()
        .find(|subscription| &subscription.id == id)
        .expect("apply_update requires an existing subscription");

    let previous_ids: BTreeSet<_> = subscription
        .nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect();
    let next_ids: BTreeSet<_> = parsed.nodes.iter().map(|node| node.id.as_str()).collect();

    let added = next_ids.difference(&previous_ids).count();
    let removed = previous_ids.difference(&next_ids).count();
    let retained = previous_ids.intersection(&next_ids).count();

    let selection_cleared = config.active.as_ref().is_some_and(|selection| {
        &selection.subscription == id && !next_ids.contains(selection.node.as_str())
    });

    let report = UpdateReport {
        added,
        removed,
        retained,
        selection_cleared,
        skipped: group_skipped(&parsed.skipped),
        notices: parsed.meta.notices.clone(),
    };

    subscription.nodes = parsed.nodes;
    subscription.info = parsed.meta.info;
    subscription.update_interval_hours = parsed.meta.update_interval_hours;
    subscription.support_url = parsed.meta.support_url;
    subscription.web_page_url = parsed.meta.web_page_url;
    subscription.announce = parsed.meta.announce;
    subscription.notices = parsed.meta.notices;
    subscription.updated_at_unix = Some(now_unix);

    if selection_cleared {
        config.active = None;
    }

    report
}

#[cfg(test)]
mod tests {
    use rosetun_config::{
        Node, NodeId, Outbound, Selection, StreamSettings, Subscription, SubscriptionInfo,
        TrojanParams,
    };
    use rosetun_subscription::{Format, SkipReason, SubscriptionMeta};

    use super::*;
    use crate::{CommitUpdateError, Store, StoreError, commit_subscription_update};

    static NEXT_DIRECTORY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    #[derive(Debug)]
    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            loop {
                let sequence = NEXT_DIRECTORY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("rosetun-update-{}-{sequence}", std::process::id()));

                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("could not create test directory: {error}"),
                }
            }
        }

        fn store(&self) -> Store {
            Store::at(self.0.join("config.json"))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn initialize(store: &Store, initial: AppConfig) {
        store
            .modify(|current| {
                *current = initial;
                Ok::<_, StoreError>(())
            })
            .unwrap();
    }

    #[test]
    fn commit_preserves_selection_and_preferences_changed_during_fetch() {
        let directory = TestDirectory::new();
        let store = directory.store();
        initialize(&store, config(Some("remove")));
        let requested = store.load().unwrap().subscriptions[0].clone();

        store
            .modify(|current| {
                current.active.as_mut().unwrap().node = NodeId::new("keep");
                current.subscriptions[0].name = "Renamed locally".to_owned();
                current.subscriptions[0].auto_update = true;
                Ok::<_, StoreError>(())
            })
            .unwrap();
        let before = store.load().unwrap();

        let report = commit_subscription_update(&store, &requested, parsed(), 42).unwrap();
        let saved = store.load().unwrap();

        assert_eq!(saved.active, before.active);
        assert_eq!(saved.rule_sets, before.rule_sets);
        assert_eq!(saved.active_rule_set, before.active_rule_set);
        assert_eq!(saved.subscriptions[0].name, "Renamed locally");
        assert!(saved.subscriptions[0].auto_update);
        assert_eq!(saved.subscriptions[0].updated_at_unix, Some(42));
        assert!(!report.selection_cleared);
        assert_eq!(report.added, 1);
        assert_eq!(report.removed, 1);
        assert_eq!(report.retained, 1);
    }

    #[test]
    fn commit_rejects_subscription_removed_during_fetch() {
        let directory = TestDirectory::new();
        let store = directory.store();
        initialize(&store, config(None));
        let requested = store.load().unwrap().subscriptions[0].clone();

        store
            .modify(|current| {
                current.subscriptions.clear();
                Ok::<_, StoreError>(())
            })
            .unwrap();
        let before = std::fs::read(store.path()).unwrap();

        let result = commit_subscription_update(&store, &requested, parsed(), 42);

        assert!(matches!(
            result,
            Err(CommitUpdateError::SubscriptionNotFound)
        ));
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
    }

    #[test]
    fn commit_rejects_request_settings_changed_during_fetch() {
        for field in 0..3 {
            let directory = TestDirectory::new();
            let store = directory.store();
            initialize(&store, config(None));
            let requested = store.load().unwrap().subscriptions[0].clone();

            store
                .modify(|current| {
                    let subscription = &mut current.subscriptions[0];
                    match field {
                        0 => {
                            subscription.url = "https://other.example.com/subscription".to_owned();
                        }
                        1 => subscription.user_agent = Some("OtherClient/1".to_owned()),
                        2 => subscription.send_hwid = !subscription.send_hwid,
                        _ => unreachable!(),
                    }
                    Ok::<_, StoreError>(())
                })
                .unwrap();
            let before = std::fs::read(store.path()).unwrap();

            let result = commit_subscription_update(&store, &requested, parsed(), 42);

            assert!(matches!(
                result,
                Err(CommitUpdateError::RequestSettingsChanged)
            ));
            assert_eq!(std::fs::read(store.path()).unwrap(), before);
        }
    }

    #[test]
    fn commit_save_failure_preserves_existing_configuration() {
        let directory = TestDirectory::new();
        let store = directory.store();
        initialize(&store, config(Some("remove")));
        let requested = store.load().unwrap().subscriptions[0].clone();
        let before = std::fs::read(store.path()).unwrap();
        std::fs::create_dir(directory.0.join("config.json.tmp")).unwrap();

        let result = commit_subscription_update(&store, &requested, parsed(), 42);

        assert!(matches!(
            result,
            Err(CommitUpdateError::Store(StoreError::Io { .. }))
        ));
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
    }

    fn node(id: &str) -> Node {
        Node {
            id: NodeId::new(id),
            name: format!("Node {id}"),
            server: "node.example.com".to_owned(),
            port: 443,
            outbound: Outbound::Trojan(TrojanParams {
                password: "test-secret".to_owned(),
            }),
            stream: StreamSettings::default(),
            raw: None,
        }
    }

    fn config(selected: Option<&str>) -> AppConfig {
        let id = SubscriptionId::new("1");
        AppConfig {
            subscriptions: vec![Subscription {
                id: id.clone(),
                name: "Chosen name".to_owned(),
                url: "https://sub.example.com/private?token=secret".to_owned(),
                nodes: vec![node("keep"), node("remove")],
                auto_update: false,
                updated_at_unix: Some(1),
                user_agent: Some("CustomClient/1".to_owned()),
                send_hwid: false,
                info: None,
                update_interval_hours: None,
                support_url: None,
                web_page_url: None,
                announce: None,
                notices: vec!["Old notice".to_owned()],
            }],
            active: selected.map(|node_id| Selection {
                subscription: id,
                node: NodeId::new(node_id),
            }),
            ..AppConfig::default()
        }
    }

    fn parsed() -> Parsed {
        Parsed {
            format: Format::Links { base64: false },
            nodes: vec![node("keep"), node("add")],
            skipped: vec![
                Skipped {
                    index: 1,
                    scheme: None,
                    reason: SkipReason::ServiceRecord,
                },
                Skipped {
                    index: 2,
                    scheme: None,
                    reason: SkipReason::ServiceRecord,
                },
                Skipped {
                    index: 3,
                    scheme: Some("vless".to_owned()),
                    reason: SkipReason::UnsupportedFlow,
                },
            ],
            meta: SubscriptionMeta {
                title: Some("New provider title".to_owned()),
                info: Some(SubscriptionInfo {
                    upload: 10,
                    download: 20,
                    total: Some(100),
                    expire_unix: Some(200),
                }),
                update_interval_hours: Some(12),
                support_url: Some("https://support.example.com/".to_owned()),
                web_page_url: Some("https://panel.example.com/".to_owned()),
                announce: Some("New announcement".to_owned()),
                notices: vec!["New notice".to_owned()],
            },
        }
    }

    #[test]
    fn retained_node_preserves_selection() {
        let mut config = config(Some("keep"));
        let selection = config.active.clone();

        let report = apply_update(&mut config, &SubscriptionId::new("1"), parsed(), 42);

        assert_eq!(config.active, selection);
        assert!(!report.selection_cleared);
        assert_eq!(report.added, 1);
        assert_eq!(report.removed, 1);
        assert_eq!(report.retained, 1);
        config.validate().unwrap();
    }

    #[test]
    fn removed_node_clears_selection() {
        let mut config = config(Some("remove"));

        let report = apply_update(&mut config, &SubscriptionId::new("1"), parsed(), 42);

        assert!(report.selection_cleared);
        assert!(config.active.is_none());
        config.validate().unwrap();
    }

    #[test]
    fn update_replaces_metadata_without_changing_local_preferences() {
        let mut config = config(None);
        let original_url = config.subscriptions[0].url.clone();

        let report = apply_update(&mut config, &SubscriptionId::new("1"), parsed(), 42);
        let subscription = &config.subscriptions[0];

        assert_eq!(subscription.name, "Chosen name");
        assert_eq!(subscription.url, original_url);
        assert_eq!(subscription.user_agent.as_deref(), Some("CustomClient/1"));
        assert!(!subscription.send_hwid);
        assert!(!subscription.auto_update);
        assert_eq!(subscription.updated_at_unix, Some(42));
        assert_eq!(
            subscription.info,
            Some(SubscriptionInfo {
                upload: 10,
                download: 20,
                total: Some(100),
                expire_unix: Some(200),
            })
        );
        assert_eq!(subscription.update_interval_hours, Some(12));
        assert_eq!(
            subscription.support_url.as_deref(),
            Some("https://support.example.com/")
        );
        assert_eq!(
            subscription.web_page_url.as_deref(),
            Some("https://panel.example.com/")
        );
        assert_eq!(subscription.announce.as_deref(), Some("New announcement"));
        assert_eq!(subscription.notices, ["New notice"]);
        assert_eq!(report.notices, ["New notice"]);
        assert_eq!(
            report.skipped.get("record contains a provider notice"),
            Some(&2)
        );
        assert_eq!(report.skipped.get("flow is not supported"), Some(&1));
    }

    #[test]
    fn missing_metadata_clears_previous_metadata() {
        let mut config = config(None);
        apply_update(&mut config, &SubscriptionId::new("1"), parsed(), 42);

        let next = Parsed {
            format: Format::Links { base64: false },
            nodes: vec![node("keep")],
            skipped: Vec::new(),
            meta: SubscriptionMeta::default(),
        };
        apply_update(&mut config, &SubscriptionId::new("1"), next, 43);

        let subscription = &config.subscriptions[0];
        assert!(subscription.info.is_none());
        assert!(subscription.update_interval_hours.is_none());
        assert!(subscription.support_url.is_none());
        assert!(subscription.web_page_url.is_none());
        assert!(subscription.announce.is_none());
        assert!(subscription.notices.is_empty());
        assert_eq!(subscription.updated_at_unix, Some(43));
    }

    #[test]
    fn selection_from_another_subscription_is_untouched() {
        let mut config = config(None);
        let mut other = config.subscriptions[0].clone();
        other.id = SubscriptionId::new("2");
        config.subscriptions.push(other);
        config.active = Some(Selection {
            subscription: SubscriptionId::new("2"),
            node: NodeId::new("remove"),
        });
        let selection = config.active.clone();

        let report = apply_update(&mut config, &SubscriptionId::new("1"), parsed(), 42);

        assert_eq!(config.active, selection);
        assert!(!report.selection_cleared);
        config.validate().unwrap();
    }
}
