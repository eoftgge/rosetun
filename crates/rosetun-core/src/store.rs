use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rosetun_config::{AppConfig, ConfigError};

#[derive(thiserror::Error)]
pub enum StoreError {
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

impl std::fmt::Debug for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "StoreError({self})")
    }
}

#[derive(Debug, Clone)]
pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn open_default() -> Result<Self, StoreError> {
        Ok(Self::at(config_path()?))
    }

    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<AppConfig, StoreError> {
        load(&self.path)
    }

    /// Loads the current file, applies `change` and saves the result.
    /// An error from `change` leaves the file untouched.
    pub fn modify<T, E>(&self, change: impl FnOnce(&mut AppConfig) -> Result<T, E>) -> Result<T, E>
    where
        E: From<StoreError>,
    {
        // Reloading narrows the race window but does not serialize concurrent writers.
        let mut config = self.load().map_err(E::from)?;
        let result = change(&mut config)?;
        save(&self.path, &config).map_err(E::from)?;
        Ok(result)
    }
}

fn config_path() -> Result<PathBuf, StoreError> {
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

fn load(path: &Path) -> Result<AppConfig, StoreError> {
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

fn save(path: &Path, config: &AppConfig) -> Result<(), StoreError> {
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

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{StoreError, config_path_with, load, save};
    use crate::Store;
    use rosetun_config::{
        AppConfig, CONFIG_VERSION, ConfigError, Node, NodeId, Outbound, Rule, RuleId, RuleMatcher,
        RuleSet, RuleSetId, RuleTarget, Selection, StreamSettings, Subscription, SubscriptionId,
        TrojanParams,
    };

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
    fn modify_reloads_configuration_before_applying_change() {
        let directory = TestDirectory::new();
        let store = Store::at(directory.config_path());
        save(store.path(), &selected_config()).unwrap();

        let stale = store.load().unwrap();
        let mut external = stale.clone();
        let mut second_node = external.subscriptions[0].nodes[0].clone();
        second_node.id = NodeId::new("external-node");
        second_node.name = "Externally selected node".to_owned();
        external.subscriptions[0].nodes.push(second_node);
        external.active.as_mut().unwrap().node = NodeId::new("external-node");

        fs::write(store.path(), serde_json::to_vec_pretty(&external).unwrap()).unwrap();

        store
            .modify(|config| {
                config.subscriptions[0].name = "Updated name".to_owned();
                Ok::<_, StoreError>(())
            })
            .unwrap();

        let saved = store.load().unwrap();
        assert_eq!(saved.active, external.active);
        assert_eq!(
            saved.subscriptions[0].nodes,
            external.subscriptions[0].nodes
        );
        assert_eq!(saved.subscriptions[0].name, "Updated name");
        assert_ne!(saved.active, stale.active);
    }

    #[test]
    fn change_error_preserves_existing_bytes() {
        #[derive(Debug, thiserror::Error)]
        enum ChangeError {
            #[error(transparent)]
            Store(#[from] StoreError),
            #[error("change rejected")]
            Rejected,
        }

        let directory = TestDirectory::new();
        let store = Store::at(directory.config_path());
        save(store.path(), &selected_config()).unwrap();
        let original = fs::read(store.path()).unwrap();

        let result = store.modify(|config| {
            config.subscriptions.clear();
            config.active = None;
            Err::<(), _>(ChangeError::Rejected)
        });

        assert!(matches!(result, Err(ChangeError::Rejected)));
        assert_eq!(fs::read(store.path()).unwrap(), original);
    }

    #[test]
    fn failed_modify_save_preserves_existing_bytes() {
        let directory = TestDirectory::new();
        let store = Store::at(directory.config_path());
        save(store.path(), &selected_config()).unwrap();
        let original = fs::read(store.path()).unwrap();
        fs::create_dir(directory.path.join("config.json.tmp")).unwrap();

        let result = store.modify(|config| {
            config.subscriptions[0].name = "Unsaved name".to_owned();
            Ok::<_, StoreError>(())
        });

        assert!(matches!(result, Err(StoreError::Io { .. })));
        assert_eq!(fs::read(store.path()).unwrap(), original);
    }

    #[test]
    fn change_error_does_not_create_a_missing_file() {
        let directory = TestDirectory::new();
        let store = Store::at(directory.config_path());

        let result = store.modify(|_| Err::<(), _>(StoreError::NoConfigDir));

        assert!(matches!(result, Err(StoreError::NoConfigDir)));
        assert!(!store.path().exists());
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
}
