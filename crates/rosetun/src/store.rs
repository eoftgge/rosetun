use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rosetun_config::{AppConfig, ConfigError, RuleSet, RuleSetId, RuleTarget};
use rosetun_ipc::ConnectRequest;

#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("could not determine the configuration directory")]
    NoConfigDir,
    #[error("could not access {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    // serde_json's message can quote input values, credentials included, so
    // only the position is shown.
    #[error("invalid JSON in {} at line {}, column {}", path.display(), source.line(), source.column())]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid configuration in {}: {source}", path.display())]
    Invalid {
        path: PathBuf,
        #[source]
        source: ConfigError,
    },
}

pub(crate) fn config_path() -> Result<PathBuf, StoreError> {
    config_path_with(|name| std::env::var_os(name), cfg!(windows))
}

fn config_path_with(
    lookup: impl Fn(&str) -> Option<OsString>,
    windows: bool,
) -> Result<PathBuf, StoreError> {
    let nonempty = |name| lookup(name).filter(|value| !value.is_empty());

    if let Some(path) = nonempty("ROSETUN_CONFIG") {
        return Ok(PathBuf::from(path));
    }

    if windows {
        return nonempty("APPDATA")
            .map(|directory| PathBuf::from(directory).join("Rosetun").join("config.json"))
            .ok_or(StoreError::NoConfigDir);
    }

    let directory = nonempty("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| nonempty("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or(StoreError::NoConfigDir)?;

    Ok(directory.join("rosetun").join("config.json"))
}

pub(crate) fn load(path: &Path) -> Result<AppConfig, StoreError> {
    let contents = match fs::read(path) {
        Ok(contents) => contents,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(AppConfig::default());
        }
        Err(source) => {
            return Err(StoreError::Io {
                path: path.to_owned(),
                source,
            });
        }
    };

    let contents = contents.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&contents);
    let config: AppConfig =
        serde_json::from_slice(contents).map_err(|source| StoreError::Parse {
            path: path.to_owned(),
            source,
        })?;

    config.validate().map_err(|source| StoreError::Invalid {
        path: path.to_owned(),
        source,
    })?;

    Ok(config)
}

pub(crate) fn save(path: &Path, config: &AppConfig) -> Result<(), StoreError> {
    config.validate().map_err(|source| StoreError::Invalid {
        path: path.to_owned(),
        source,
    })?;

    let contents = serde_json::to_vec_pretty(config).map_err(|source| StoreError::Parse {
        path: path.to_owned(),
        source,
    })?;

    let file_name = path.file_name().ok_or_else(|| StoreError::Io {
        path: path.to_owned(),
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration path must name a file",
        ),
    })?;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let mut temporary_name = file_name.to_os_string();
    temporary_name.push(".tmp");
    let temporary_path = parent.join(temporary_name);

    // One writer at a time is assumed, so a fixed temporary name is fine; a file
    // left behind by a crashed save is simply overwritten.
    let result = (|| {
        fs::create_dir_all(parent).map_err(|source| StoreError::Io {
            path: parent.to_owned(),
            source,
        })?;

        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options
            .open(&temporary_path)
            .map_err(|source| StoreError::Io {
                path: temporary_path.clone(),
                source,
            })?;

        file.write_all(&contents)
            .and_then(|()| file.sync_all())
            .map_err(|source| StoreError::Io {
                path: temporary_path.clone(),
                source,
            })?;

        drop(file);

        fs::rename(&temporary_path, path).map_err(|source| StoreError::Io {
            path: path.to_owned(),
            source,
        })
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }

    result
}

pub(crate) fn connect_request(config: &AppConfig) -> Result<ConnectRequest, String> {
    let (_, node) = config.active_node().ok_or_else(|| {
        "select an existing node with rosetun select <subscription-id> <node-id>".to_owned()
    })?;
    let selection = config.active.as_ref().ok_or_else(|| {
        "select a node with rosetun select <subscription-id> <node-id>".to_owned()
    })?;

    let rule_set = match &config.active_rule_set {
        Some(_) => config
            .active_rules()
            .cloned()
            .ok_or_else(|| "the selected rule set does not exist".to_owned())?,
        None => RuleSet::new(RuleSetId::new("default"), "Default", RuleTarget::Proxy),
    };

    Ok(ConnectRequest {
        selection: selection.clone(),
        node: node.clone(),
        rule_set,
        settings: config.settings.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use rosetun_config::{
        AppConfig, CONFIG_VERSION, ConfigError, Node, NodeId, Outbound, Rule, RuleId, RuleMatcher,
        RuleSet, RuleSetId, RuleTarget, Selection, StreamSettings, Subscription, SubscriptionId,
        TrojanParams,
    };

    use super::{StoreError, config_path_with, connect_request, load, save};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            loop {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("rosetun-store-{}-{sequence}", std::process::id()));

                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("could not create test directory: {error}"),
                }
            }
        }

        fn config_path(&self) -> PathBuf {
            self.path.join("config.json")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn selected_config() -> AppConfig {
        let subscription_id = SubscriptionId::new("subscription");
        let node_id = NodeId::new("node");
        let rule_set_id = RuleSetId::new("rules");
        let node = Node {
            id: node_id.clone(),
            name: "Test node".to_owned(),
            server: "example.com".to_owned(),
            port: 443,
            outbound: Outbound::Trojan(TrojanParams {
                password: "test-secret".to_owned(),
            }),
            stream: StreamSettings::default(),
            raw: None,
        };

        let mut rule_set = RuleSet::new(rule_set_id.clone(), "Test rules", RuleTarget::Proxy);
        rule_set.rules.push(Rule {
            id: RuleId::new("block"),
            enabled: true,
            matcher: RuleMatcher::IpCidr("192.0.2.0/24".to_owned()),
            target: RuleTarget::Block,
        });

        AppConfig {
            subscriptions: vec![Subscription {
                id: subscription_id.clone(),
                name: "Test subscription".to_owned(),
                url: "https://example.com/subscription".to_owned(),
                nodes: vec![node],
                auto_update: false,
                updated_at_unix: None,
                user_agent: None,
                send_hwid: true,
                info: None,
                update_interval_hours: None,
                support_url: None,
                web_page_url: None,
                announce: None,
                notices: Vec::new(),
            }],
            rule_sets: vec![rule_set],
            active: Some(Selection {
                subscription: subscription_id,
                node: node_id,
            }),
            active_rule_set: Some(rule_set_id),
            ..AppConfig::default()
        }
    }

    fn dangling_node_config() -> AppConfig {
        AppConfig {
            active: Some(Selection {
                subscription: SubscriptionId::new("missing"),
                node: NodeId::new("missing"),
            }),
            ..AppConfig::default()
        }
    }

    fn dangling_rules_config() -> AppConfig {
        AppConfig {
            active_rule_set: Some(RuleSetId::new("missing")),
            ..AppConfig::default()
        }
    }

    #[test]
    fn missing_file_loads_defaults_without_creating_a_file() {
        let directory = TestDirectory::new();
        let path = directory.config_path();

        assert_eq!(load(&path).unwrap(), AppConfig::default());
        assert!(!path.exists());
    }

    #[test]
    fn save_and_load_round_trip_and_replace_existing_file() {
        let directory = TestDirectory::new();
        let path = directory.config_path();
        let config = selected_config();

        save(&path, &AppConfig::default()).unwrap();
        save(&path, &config).unwrap();

        assert_eq!(load(&path).unwrap(), config);
        assert!(!directory.path.join("config.json.tmp").exists());
    }

    #[test]
    fn missing_fields_load_defaults() {
        let directory = TestDirectory::new();
        let path = directory.config_path();

        for contents in ["{}", r#"{"version":1}"#] {
            fs::write(&path, contents).unwrap();
            assert_eq!(load(&path).unwrap(), AppConfig::default());
            assert_eq!(fs::read_to_string(&path).unwrap(), contents);
        }
    }

    #[test]
    fn leading_utf8_bom_is_removed_once() {
        let directory = TestDirectory::new();
        let path = directory.config_path();
        let contents = b"\xef\xbb\xbf{}";

        fs::write(&path, contents).unwrap();
        assert_eq!(load(&path).unwrap(), AppConfig::default());
        assert_eq!(fs::read(&path).unwrap(), contents);

        fs::write(&path, b"\xef\xbb\xbf\xef\xbb\xbf{}").unwrap();
        assert!(matches!(load(&path), Err(StoreError::Parse { .. })));
    }

    #[test]
    fn future_version_is_invalid() {
        let directory = TestDirectory::new();
        let path = directory.config_path();
        let found = CONFIG_VERSION + 1;

        fs::write(&path, format!(r#"{{"version":{found}}}"#)).unwrap();

        match load(&path) {
            Err(StoreError::Invalid {
                path: error_path,
                source:
                    ConfigError::UnsupportedVersion {
                        found: actual_found,
                        expected,
                    },
            }) => {
                assert_eq!(error_path, path);
                assert_eq!(actual_found, found);
                assert_eq!(expected, CONFIG_VERSION);
            }
            result => panic!("expected unsupported version error, got {result:?}"),
        }
    }

    #[test]
    fn dangling_node_is_invalid_on_load() {
        let directory = TestDirectory::new();
        let path = directory.config_path();

        fs::write(&path, serde_json::to_vec(&dangling_node_config()).unwrap()).unwrap();

        assert!(matches!(
            load(&path),
            Err(StoreError::Invalid {
                path: error_path,
                source: ConfigError::DanglingSelection { .. },
            }) if error_path == path
        ));
    }

    #[test]
    fn dangling_rule_set_is_invalid_on_load() {
        let directory = TestDirectory::new();
        let path = directory.config_path();

        fs::write(&path, serde_json::to_vec(&dangling_rules_config()).unwrap()).unwrap();

        assert!(matches!(
            load(&path),
            Err(StoreError::Invalid {
                path: error_path,
                source: ConfigError::DanglingRuleSet(_),
            }) if error_path == path
        ));
    }

    #[test]
    fn invalid_save_preserves_existing_bytes() {
        let directory = TestDirectory::new();
        let path = directory.config_path();
        let original = selected_config();
        save(&path, &original).unwrap();
        let original_bytes = fs::read(&path).unwrap();

        let future = AppConfig {
            version: CONFIG_VERSION + 1,
            ..AppConfig::default()
        };

        for invalid in [dangling_node_config(), dangling_rules_config(), future] {
            assert!(matches!(
                save(&path, &invalid),
                Err(StoreError::Invalid { path: error_path, .. }) if error_path == path
            ));
            assert_eq!(fs::read(&path).unwrap(), original_bytes);
            assert_eq!(load(&path).unwrap(), original);
            assert!(!directory.path.join("config.json.tmp").exists());
        }
    }

    #[test]
    fn invalid_json_reports_path_without_changing_file() {
        let directory = TestDirectory::new();
        let path = directory.config_path();
        let contents = b"{ invalid JSON";

        fs::write(&path, contents).unwrap();

        assert!(matches!(
            load(&path),
            Err(StoreError::Parse { path: error_path, .. }) if error_path == path
        ));
        assert_eq!(fs::read(&path).unwrap(), contents);
    }

    #[test]
    fn failed_save_leaves_old_configuration_usable() {
        let directory = TestDirectory::new();
        let path = directory.config_path();
        let original = selected_config();

        save(&path, &original).unwrap();
        let original_bytes = fs::read(&path).unwrap();
        let temporary_path = directory.path.join("config.json.tmp");
        fs::create_dir(&temporary_path).unwrap();

        assert!(matches!(
            save(&path, &AppConfig::default()),
            Err(StoreError::Io { path: error_path, .. }) if error_path == temporary_path
        ));
        assert_eq!(fs::read(&path).unwrap(), original_bytes);
        assert_eq!(load(&path).unwrap(), original);
    }

    #[test]
    fn save_creates_missing_parent_directories() {
        let directory = TestDirectory::new();
        let path = directory
            .path
            .join("nested")
            .join("rosetun")
            .join("config.json");

        save(&path, &selected_config()).unwrap();

        assert_eq!(load(&path).unwrap(), selected_config());
    }

    #[test]
    fn failed_rename_removes_temporary_file() {
        let directory = TestDirectory::new();
        let path = directory.config_path();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), b"unchanged").unwrap();

        assert!(matches!(
            save(&path, &AppConfig::default()),
            Err(StoreError::Io { path: error_path, .. }) if error_path == path
        ));
        assert!(!directory.path.join("config.json.tmp").exists());
        assert_eq!(fs::read(path.join("keep")).unwrap(), b"unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn saved_configuration_has_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let path = directory.config_path();
        save(&path, &selected_config()).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn config_path_override_has_priority_on_every_platform() {
        let directory = TestDirectory::new();
        let override_path = directory.path.join("custom.json");

        for windows in [false, true] {
            let lookup = |name: &str| match name {
                "ROSETUN_CONFIG" => Some(override_path.clone().into_os_string()),
                "APPDATA" | "XDG_CONFIG_HOME" | "HOME" => {
                    Some(directory.path.clone().into_os_string())
                }
                _ => None,
            };

            assert_eq!(config_path_with(lookup, windows).unwrap(), override_path);
        }
    }

    #[test]
    fn windows_config_path_uses_appdata() {
        let directory = TestDirectory::new();
        let lookup = |name: &str| match name {
            "ROSETUN_CONFIG" => Some(OsString::new()),
            "APPDATA" => Some(directory.path.clone().into_os_string()),
            "XDG_CONFIG_HOME" | "HOME" => Some(OsString::from("ignored")),
            _ => None,
        };

        assert_eq!(
            config_path_with(lookup, true).unwrap(),
            directory.path.join("Rosetun").join("config.json")
        );
    }

    #[test]
    fn unix_config_path_prefers_xdg() {
        let directory = TestDirectory::new();
        let lookup = |name: &str| match name {
            "ROSETUN_CONFIG" => Some(OsString::new()),
            "XDG_CONFIG_HOME" => Some(directory.path.clone().into_os_string()),
            "HOME" => Some(OsString::from("ignored")),
            _ => None,
        };

        assert_eq!(
            config_path_with(lookup, false).unwrap(),
            directory.path.join("rosetun").join("config.json")
        );
    }

    #[test]
    fn unix_config_path_falls_back_to_home() {
        let directory = TestDirectory::new();
        let lookup = |name: &str| match name {
            "ROSETUN_CONFIG" | "XDG_CONFIG_HOME" => Some(OsString::new()),
            "HOME" => Some(directory.path.clone().into_os_string()),
            _ => None,
        };

        assert_eq!(
            config_path_with(lookup, false).unwrap(),
            directory
                .path
                .join(".config")
                .join("rosetun")
                .join("config.json")
        );
    }

    #[test]
    fn config_path_requires_a_platform_config_directory() {
        let _directory = TestDirectory::new();

        for windows in [false, true] {
            assert!(matches!(
                config_path_with(|_| None, windows),
                Err(StoreError::NoConfigDir)
            ));
            assert!(matches!(
                config_path_with(|_| Some(OsString::new()), windows),
                Err(StoreError::NoConfigDir)
            ));
        }

        assert!(matches!(
            config_path_with(
                |name| match name {
                    "HOME" | "XDG_CONFIG_HOME" => Some(OsString::from("ignored")),
                    _ => None,
                },
                true,
            ),
            Err(StoreError::NoConfigDir)
        ));
    }

    #[test]
    fn request_contains_selected_node_rules_and_settings() {
        let _directory = TestDirectory::new();
        let config = selected_config();

        let request = connect_request(&config).unwrap();

        assert_eq!(Some(&request.selection), config.active.as_ref());
        assert_eq!(&request.node, config.active_node().unwrap().1);
        assert_eq!(&request.rule_set, config.active_rules().unwrap());
        assert_eq!(request.settings, config.settings);
    }

    #[test]
    fn request_requires_an_existing_selected_node() {
        let _directory = TestDirectory::new();

        for config in [AppConfig::default(), dangling_node_config()] {
            let error = connect_request(&config).unwrap_err();
            assert!(error.contains("rosetun select"));
        }
    }

    #[test]
    fn request_uses_default_proxy_rules_when_no_rule_set_is_selected() {
        let _directory = TestDirectory::new();
        let config = AppConfig {
            active_rule_set: None,
            ..selected_config()
        };

        let request = connect_request(&config).unwrap();

        assert_eq!(
            request.rule_set,
            RuleSet::new(RuleSetId::new("default"), "Default", RuleTarget::Proxy)
        );
    }

    #[test]
    fn request_does_not_replace_a_dangling_rule_set_with_defaults() {
        let _directory = TestDirectory::new();
        let config = AppConfig {
            active_rule_set: Some(RuleSetId::new("missing")),
            ..selected_config()
        };

        assert!(connect_request(&config).is_err());
    }
}
