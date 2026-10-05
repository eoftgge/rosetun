use rosetun_config::AppConfig;
use rosetun_subscription::ParseError;

use super::*;

static NEXT_DIRECTORY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct TestDirectory(std::path::PathBuf);

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = NEXT_DIRECTORY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rosetun-subscriptions-{}-{sequence}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("could not create test directory: {error}"),
            }
        }
    }

    fn config_path(&self) -> std::path::PathBuf {
        self.0.join("config.json")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn save_config(path: &std::path::Path, config: &AppConfig) -> Result<(), crate::StoreError> {
    crate::Store::at(path).modify(|current| {
        *current = config.clone();
        Ok::<_, crate::StoreError>(())
    })
}

fn test_subscription(id: &str) -> Subscription {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "name": "Chosen name",
        "url": format!("https://sub.example.com/private-token?id={id}"),
        "nodes": [{
            "id": "old",
            "name": "Old node",
            "server": "old.example.com",
            "port": 443,
            "outbound": {
                "trojan": {
                    "password": "old-secret"
                }
            }
        }],
        "updated_at_unix": 1
    }))
    .unwrap()
}

fn test_config() -> AppConfig {
    AppConfig {
        subscriptions: vec![test_subscription("1")],
        active: Some(rosetun_config::Selection {
            subscription: SubscriptionId::new("1"),
            node: rosetun_config::NodeId::new("old"),
        }),
        ..AppConfig::default()
    }
}

fn successful_update() -> rosetun_subscription::Parsed {
    rosetun_subscription::parse(
        b"trojan://new-secret@new.example.com:443#New",
        &|name| match name {
            "profile-title" => Some("Changed provider title".to_owned()),
            "profile-update-interval" => Some("12".to_owned()),
            "subscription-userinfo" => {
                Some("upload=10; download=20; total=100; expire=200".to_owned())
            }
            _ => None,
        },
    )
    .unwrap()
}

#[test]
fn commit_reloads_preferences_changed_during_fetch() {
    let directory = TestDirectory::new();
    let path = directory.config_path();
    let store = Store::at(&path);
    let original = test_config();
    save_config(&path, &original).unwrap();
    let requested = original.subscriptions[0].clone();

    let mut external = original.clone();
    external.subscriptions[0].name = "Renamed during fetch".to_owned();
    external.subscriptions[0].auto_update = true;
    external.active = None;
    save_config(&path, &external).unwrap();

    let (subscription, _) =
        commit_subscription_update(&store, &requested, successful_update(), 42).unwrap();

    let saved = store.load().unwrap();
    assert_eq!(subscription, saved.subscriptions[0]);
    assert_eq!(saved.subscriptions[0].name, "Renamed during fetch");
    assert!(saved.subscriptions[0].auto_update);
    assert!(saved.active.is_none());
    assert_eq!(saved.rule_sets, external.rule_sets);
    assert_eq!(saved.active_rule_set, external.active_rule_set);
    assert_eq!(saved.subscriptions[0].updated_at_unix, Some(42));
    assert_eq!(saved.subscriptions[0].nodes[0].server, "new.example.com");
    assert_eq!(original, test_config());
}

#[test]
fn successful_update_is_persisted_and_dangling_selection_is_cleared() {
    let directory = TestDirectory::new();
    let path = directory.config_path();
    let store = Store::at(&path);
    let original = test_config();
    save_config(&path, &original).unwrap();

    let (subscription, report) =
        commit_subscription_update(&store, &original.subscriptions[0], successful_update(), 42)
            .unwrap();

    assert!(report.selection_cleared);
    assert_eq!(report.added, 1);
    assert_eq!(report.removed, 1);
    assert_eq!(report.retained, 0);

    let saved = store.load().unwrap();
    assert_eq!(subscription, saved.subscriptions[0]);
    assert!(saved.active.is_none());
    assert_eq!(saved.subscriptions[0].name, "Chosen name");
    assert_eq!(saved.subscriptions[0].updated_at_unix, Some(42));
    assert_eq!(saved.subscriptions[0].update_interval_hours, Some(12));
    assert_eq!(saved.subscriptions[0].info.as_ref().unwrap().download, 20);
    assert_eq!(saved.subscriptions[0].nodes[0].server, "new.example.com");
    assert_eq!(saved.rule_sets, original.rule_sets);
    assert_eq!(saved.active_rule_set, original.active_rule_set);
}

#[test]
fn fetch_and_parse_errors_preserve_disk_and_snapshot() {
    let directory = TestDirectory::new();
    let path = directory.config_path();
    let store = Store::at(&path);
    let original = test_config();
    save_config(&path, &original).unwrap();
    let original_bytes = std::fs::read(&path).unwrap();

    let errors = [
        FetchError::RequestFailed,
        FetchError::ResponseTooLarge,
        FetchError::AccessDenied,
        FetchError::Parse(ParseError::DeviceLimit {
            max_devices_reached: true,
            not_supported: false,
            announce: Some("Device limit reached".to_owned()),
        }),
        FetchError::Parse(ParseError::NoUsableNodes {
            skipped: Vec::new(),
            notices: vec!["Subscription expired".to_owned()],
        }),
    ];

    for error in errors {
        let snapshot = store.load().unwrap();
        let mut pending = Some(error);
        let mut calls = 0;
        let result = update_subscription_with(
            &store,
            &SubscriptionId::new("1"),
            Timeouts::default(),
            &mut |subscription, _| {
                calls += 1;
                assert_eq!(subscription, &original.subscriptions[0]);
                Err(pending.take().unwrap())
            },
        );

        assert!(matches!(result, Err(UpdateSubscriptionError::Fetch { .. })));
        assert_eq!(calls, 1);
        assert_eq!(snapshot, original);
        assert_eq!(store.load().unwrap(), original);
        assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
        assert!(!directory.0.join("config.json.tmp").exists());
    }
}

#[test]
fn failed_save_preserves_snapshot_and_previous_file() {
    let directory = TestDirectory::new();
    let path = directory.config_path();
    let store = Store::at(&path);
    let original = test_config();
    save_config(&path, &original).unwrap();
    let original_bytes = std::fs::read(&path).unwrap();
    std::fs::create_dir(directory.0.join("config.json.tmp")).unwrap();

    let result = update_subscription_with(
        &store,
        &SubscriptionId::new("1"),
        Timeouts::default(),
        &mut |_, _| Ok(successful_update()),
    );

    assert!(matches!(result, Err(UpdateSubscriptionError::Store(_))));
    assert_eq!(original, test_config());
    assert_eq!(store.load().unwrap(), original);
    assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
}

#[test]
fn failed_subscription_does_not_prevent_a_later_successful_commit() {
    let directory = TestDirectory::new();
    let path = directory.config_path();
    let store = Store::at(&path);
    let mut original = test_config();
    original.subscriptions.push(test_subscription("2"));
    save_config(&path, &original).unwrap();

    let mut fetched_ids = Vec::new();
    let results = update_all_with(&store, Timeouts::default(), |subscription, _| {
        fetched_ids.push(subscription.id.clone());
        if subscription.id == SubscriptionId::new("1") {
            Err(FetchError::AccessDenied)
        } else {
            Ok(successful_update())
        }
    })
    .unwrap();

    assert_eq!(
        fetched_ids,
        vec![SubscriptionId::new("1"), SubscriptionId::new("2")]
    );
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].0, SubscriptionId::new("1"));
    assert!(matches!(
        &results[0].1,
        Err(UpdateSubscriptionError::Fetch {
            source: FetchError::AccessDenied,
            ..
        })
    ));
    assert_eq!(results[1].0, SubscriptionId::new("2"));
    let (subscription, report) = results[1].1.as_ref().unwrap();
    assert_eq!(subscription.id, SubscriptionId::new("2"));
    assert_eq!(report.added, 1);
    assert_eq!(report.removed, 1);
    assert!(!report.selection_cleared);

    let saved = store.load().unwrap();
    assert_eq!(saved.subscriptions[0], original.subscriptions[0]);
    assert_eq!(saved.subscriptions[1].name, "Chosen name");
    assert_eq!(saved.subscriptions[1].nodes[0].server, "new.example.com");
    assert!(saved.subscriptions[1].updated_at_unix.is_some());
    assert_eq!(saved.active, original.active);
    assert_eq!(saved.rule_sets, original.rule_sets);
    assert_eq!(saved.active_rule_set, original.active_rule_set);
}

#[test]
fn unknown_update_target_does_not_create_configuration() {
    let directory = TestDirectory::new();
    let path = directory.config_path();
    let store = Store::at(&path);

    let result = update_subscription_with(
        &store,
        &SubscriptionId::new("missing"),
        Timeouts::default(),
        &mut |_, _| panic!("an unknown subscription must not be fetched"),
    );

    assert!(matches!(result, Err(UpdateSubscriptionError::NotFound)));
    assert_eq!(store.load().unwrap(), AppConfig::default());
    assert!(!path.exists());
    assert!(!directory.0.join("config.json.tmp").exists());
}

#[test]
fn update_error_display_preserves_details_and_redacts_requested_url() {
    let directory = TestDirectory::new();
    let path = directory.config_path();
    let store = Store::at(&path);
    let config = test_config();
    save_config(&path, &config).unwrap();
    let before = std::fs::read(&path).unwrap();
    let requested_url = config.subscriptions[0].url.clone();

    let error = update_subscription_with(
        &store,
        &SubscriptionId::new("1"),
        Timeouts::default(),
        &mut |_, _| {
            Err(FetchError::Parse(ParseError::DeviceLimit {
                max_devices_reached: true,
                not_supported: false,
                announce: Some(format!("Visit {requested_url}")),
            }))
        },
    )
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "device limit reached for this subscription; remove an old device in your provider's panel\n  announce: Visit https://sub.example.com/…"
    );
    assert!(!error.to_string().contains("private-token"));
    assert!(matches!(
        &error,
        UpdateSubscriptionError::Fetch {
            source: FetchError::Parse(ParseError::DeviceLimit {
                max_devices_reached: true,
                ..
            }),
            ..
        }
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
