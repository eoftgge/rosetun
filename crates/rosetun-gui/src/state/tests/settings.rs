use super::*;

#[test]
fn settings_section_survives_navigation_between_tabs() {
    let mut state = State::default();
    assert_eq!(state.settings.screen.section, SettingsSection::General);
    state.act(Action::OpenSettings);
    state.act(Action::OpenSettingsSection(SettingsSection::Service));
    assert_eq!(state.settings.screen.section, SettingsSection::Service);
    state.act(Action::ShowConnection);
    state.act(Action::OpenSettings);
    assert_eq!(state.screen, Screen::Settings);
    assert_eq!(state.settings.screen.section, SettingsSection::Service);
}

#[test]
fn settings_dns_form_initializes_on_open_and_follows_clean_config() {
    let mut state = State::default();
    let mut config = AppConfig::default();
    config.settings.dns =
        rosetun_core::parse_dns_input("1.1.1.1", "cloudflare-dns.com", "8443", "/dns-query")
            .unwrap();
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: config.clone(),
    });
    assert!(state.settings.screen.server.is_empty());
    state.act(Action::OpenSettings);
    assert_eq!(state.screen, Screen::Settings);
    assert_eq!(state.settings.screen.server, "1.1.1.1");
    assert_eq!(state.settings.screen.server_name, "cloudflare-dns.com");
    assert_eq!(state.settings.screen.port, "8443");
    assert_eq!(state.settings.screen.path, "/dns-query");
    assert!(state.settings.screen.custom_dns);

    config.settings.dns = DnsSettings::default();
    state.reduce(WorkerEvent::Config {
        generation: 2,
        config,
    });
    assert_eq!(state.settings.screen.server, "1.1.1.1");
    assert_eq!(state.settings.screen.server_name, "cloudflare-dns.com");
    assert!(state.settings.screen.port.is_empty());
    assert!(state.settings.screen.path.is_empty());
    assert!(!state.settings.screen.custom_dns);
}

#[test]
fn saved_google_and_presets_select_the_correct_card_and_job() {
    let mut state = State::default();
    let mut config = AppConfig::default();
    config.settings.dns = DnsPreset::Google.settings();
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    state.act(Action::OpenSettings);
    assert!(!state.settings.screen.custom_dns);
    assert_eq!(
        DnsPreset::matching(&state.config.settings.dns),
        Some(DnsPreset::Google)
    );
    assert!(state.act(Action::SetDnsPreset(DnsPreset::Google)).is_none());
    assert!(matches!(
        state.act(Action::SetDnsPreset(DnsPreset::Quad9)),
        Some(Job::SetDns(dns)) if dns == DnsPreset::Quad9.settings()
    ));
    assert!(!state.settings.screen.custom_dns);
}

#[test]
fn selecting_saved_preset_leaves_no_job_and_failed_preset_restores_saved_dns() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.act(Action::OpenSettings);
    state.act(Action::SelectCustomDns);
    state.settings.screen.server = "9.9.9.9".into();
    state.settings.screen.dirty = true;
    assert!(
        state
            .act(Action::SetDnsPreset(DnsPreset::Cloudflare))
            .is_none()
    );
    assert!(!state.settings.screen.custom_dns);
    assert!(!state.settings.screen.dirty);
    assert_eq!(state.settings.screen.server, "1.1.1.1");

    assert!(matches!(
        state.act(Action::SetDnsPreset(DnsPreset::Quad9)),
        Some(Job::SetDns(_))
    ));
    state.reduce(WorkerEvent::SetDns(Err(
        rosetun_core::SettingsError::Store(StoreError::NoConfigDir),
    )));
    assert_eq!(state.settings.screen.server, "1.1.1.1");
    assert!(!state.settings.screen.custom_dns);
}

#[test]
fn settings_reset_requires_disconnection_and_resynchronizes_dns() {
    let mut state = State {
        config_ready: true,
        helper_available: true,
        ..State::default()
    };
    state.config.settings.dns =
        rosetun_core::parse_dns_input("1.0.0.1", "cloudflare-dns.com", "", "").unwrap();
    state.act(Action::OpenSettings);
    assert!(state.settings.screen.custom_dns);
    state.settings.screen.server = "8.8.8.8".into();
    state.settings.screen.dirty = true;
    state.status.state = ConnectionState::Connected;
    assert!(!state.can_reset_settings());
    state.act(Action::RequestResetSettings);
    assert!(!state.settings.screen.reset_open);

    state.status.state = ConnectionState::Disconnected;
    state.operations.kill_switch = true;
    assert!(!state.can_reset_settings());
    state.operations.kill_switch = false;
    state.act(Action::RequestResetSettings);
    assert!(state.settings.screen.reset_open);
    assert!(matches!(
        state.act(Action::ConfirmResetSettings),
        Some(Job::ResetSettings)
    ));
    state.act(Action::CancelResetSettings);
    assert!(state.settings.screen.reset_open);
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: AppConfig::default(),
    });
    assert!(state.settings.screen.dirty);
    state.reduce(WorkerEvent::ResetSettings(Ok(())));
    assert!(!state.settings.screen.reset_open);
    assert!(!state.operations.settings);
    assert!(!state.settings.screen.dirty);
    assert!(!state.settings.screen.custom_dns);
    assert_eq!(state.settings.screen.server, "1.1.1.1");
}

#[test]
fn settings_reset_failure_closes_confirmation_and_reports_error() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.act(Action::RequestResetSettings);
    assert!(state.settings.screen.reset_open);
    assert!(matches!(
        state.act(Action::ConfirmResetSettings),
        Some(Job::ResetSettings)
    ));
    state.reduce(WorkerEvent::ResetSettings(Err(
        rosetun_core::SettingsError::Store(StoreError::NoConfigDir),
    )));
    assert!(!state.settings.screen.reset_open);
    assert!(!state.operations.settings);
    assert_eq!(
        state.operation_error.as_deref(),
        Some("could not determine the configuration directory")
    );
}

#[test]
fn settings_dns_form_preserves_unsaved_input_across_config_reloads() {
    let mut state = State::default();
    state.act(Action::OpenSettings);
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: AppConfig::default(),
    });
    assert_eq!(state.settings.screen.server, "1.1.1.1");
    state.act(Action::SelectCustomDns);
    assert!(state.settings.screen.custom_dns);
    state.settings.screen.server = "8.8.8.8".into();
    state.settings.screen.server_name = "dns.google".into();
    state.settings.screen.port = "8443".into();
    state.settings.screen.dirty = true;
    let mut config = AppConfig::default();
    config.settings.kill_switch = true;
    state.reduce(WorkerEvent::Config {
        generation: 2,
        config,
    });
    assert_eq!(state.settings.screen.server, "8.8.8.8");
    assert_eq!(state.settings.screen.server_name, "dns.google");
    assert!(state.settings.screen.dirty);

    let Some(Job::SetDns(dns)) = state.act(Action::SaveDns) else {
        panic!("expected DNS save");
    };
    assert_eq!(dns.server_name, "dns.google");
    assert!(state.operations.settings);
    assert!(state.act(Action::SetDnsPreset(DnsPreset::Quad9)).is_none());
    assert_eq!(state.settings.screen.server, "8.8.8.8");
    let mut config = state.config.clone();
    config.settings.dns = dns;
    state.reduce(WorkerEvent::Config {
        generation: 3,
        config,
    });
    assert!(state.settings.screen.dirty);
    state.reduce(WorkerEvent::SetDns(Ok(())));
    assert!(!state.operations.settings);
    assert!(!state.settings.screen.dirty);
    assert_eq!(state.settings.screen.server, "8.8.8.8");
    assert!(state.act(Action::SaveDns).is_none());
    assert!(state.settings.screen.custom_dns);
}

#[test]
fn expired_verbose_log_can_be_turned_on_again() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.config.settings.verbose_log_until = Some(now_unix().saturating_sub(1));
    assert!(state.act(Action::SetVerboseLog(false)).is_none());
    assert!(matches!(
        state.act(Action::SetVerboseLog(true)),
        Some(Job::SetVerboseLog(true))
    ));
}

#[test]
fn settings_operations_clear_busy_and_report_errors() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    assert!(state.act(Action::SetInterfaceScale(95)).is_none());
    assert!(state.act(Action::SetInterfaceScale(100)).is_none());
    assert!(matches!(
        state.act(Action::SetInterfaceScale(125)),
        Some(Job::SetInterfaceScale(125))
    ));
    assert!(state.operations.settings);
    assert!(state.act(Action::SetVerboseLog(true)).is_none());
    state.reduce(WorkerEvent::SetInterfaceScale(Err(
        rosetun_core::SettingsError::UnsupportedScale,
    )));
    assert!(!state.operations.settings);
    assert_eq!(
        state.operation_error.as_deref(),
        Some("unsupported interface scale")
    );

    assert!(matches!(
        state.act(Action::SetVerboseLog(true)),
        Some(Job::SetVerboseLog(true))
    ));
    state.reduce(WorkerEvent::SetVerboseLog(Err(
        rosetun_core::SettingsError::Store(StoreError::NoConfigDir),
    )));
    assert!(!state.operations.settings);
    assert_eq!(
        state.operation_error.as_deref(),
        Some("could not determine the configuration directory")
    );

    state.act(Action::OpenSettings);
    state.act(Action::SelectCustomDns);
    assert!(!state.settings.screen.dirty);
    state.settings.screen.server = "bad".into();
    assert!(state.act(Action::SaveDns).is_none());
    state.settings.screen.server = "8.8.8.8".into();
    state.settings.screen.dirty = true;
    assert!(matches!(state.act(Action::SaveDns), Some(Job::SetDns(_))));
    state.reduce(WorkerEvent::SetDns(Err(
        rosetun_core::SettingsError::Store(StoreError::NoConfigDir),
    )));
    assert!(!state.operations.settings);
    assert!(state.settings.screen.dirty);
    assert_eq!(state.settings.screen.server, "8.8.8.8");
    assert_eq!(
        state.operation_error.as_deref(),
        Some("could not determine the configuration directory")
    );
}

#[test]
fn changing_language_uses_a_settings_job_and_completion_clears_busy() {
    let mut state = State::default();
    assert!(
        state
            .act(Action::SetLanguage(LanguageSetting::Russian))
            .is_none()
    );
    state.config_ready = true;
    assert!(
        state
            .act(Action::SetLanguage(LanguageSetting::System))
            .is_none()
    );
    assert!(matches!(
        state.act(Action::SetLanguage(LanguageSetting::Russian)),
        Some(Job::SetLanguage(LanguageSetting::Russian))
    ));
    assert!(state.operations.settings);
    assert!(
        state
            .act(Action::SetLanguage(LanguageSetting::English))
            .is_none()
    );
    state.reduce(WorkerEvent::SetLanguage(Ok(())));
    assert!(!state.operations.settings);
    let mut config = state.config.clone();
    config.interface.language = LanguageSetting::Russian;
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    assert!(
        state
            .act(Action::SetLanguage(LanguageSetting::Russian))
            .is_none()
    );
}

#[test]
fn reduce_motion_setting_uses_a_settings_job_and_saved_value() {
    let mut state = State::default();
    assert!(state.act(Action::SetReduceMotion(true)).is_none());
    state.config_ready = true;
    assert!(state.act(Action::SetReduceMotion(false)).is_none());
    assert!(matches!(
        state.act(Action::SetReduceMotion(true)),
        Some(Job::Setting(SettingChange::ReduceMotion(true)))
    ));
    assert!(state.operations.settings);
    assert!(state.act(Action::SetReduceMotion(true)).is_none());
    state.reduce(WorkerEvent::Setting(
        SettingChange::ReduceMotion(true),
        Ok(()),
    ));
    assert!(!state.operations.settings);
    let mut config = state.config.clone();
    config.interface.reduce_motion = true;
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    assert!(state.act(Action::SetReduceMotion(true)).is_none());
}

#[test]
fn connection_settings_jobs_respect_busy_state_and_saved_values() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    assert!(state.act(Action::SetConnectOnStart(false)).is_none());
    assert!(state.act(Action::SetAutoReconnect(true)).is_none());
    assert!(matches!(
        state.act(Action::SetConnectOnStart(true)),
        Some(Job::Setting(SettingChange::ConnectOnStart(true)))
    ));
    assert!(state.act(Action::SetAutoReconnect(false)).is_none());
    state.reduce(WorkerEvent::Setting(
        SettingChange::ConnectOnStart(true),
        Ok(()),
    ));
    assert!(matches!(
        state.act(Action::SetAutoReconnect(false)),
        Some(Job::Setting(SettingChange::AutoReconnect(false)))
    ));
    state.reduce(WorkerEvent::Setting(
        SettingChange::AutoReconnect(false),
        Err(rosetun_core::SettingsError::Store(StoreError::NoConfigDir)),
    ));
    assert!(!state.operations.settings);
    assert!(state.operation_error.is_some());
    let mut config = AppConfig::default();
    config.interface.connect_on_start = true;
    config.settings.auto_reconnect = false;
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    assert!(state.act(Action::SetConnectOnStart(true)).is_none());
    assert!(state.act(Action::SetAutoReconnect(false)).is_none());
}

#[test]
fn auto_update_setting_uses_settings_job_and_respects_busy_state() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    assert!(
        state
            .act(Action::SetAutoUpdateSubscriptions(true))
            .is_none()
    );
    assert!(matches!(
        state.act(Action::SetAutoUpdateSubscriptions(false)),
        Some(Job::Setting(SettingChange::AutoUpdateSubscriptions(false)))
    ));
    assert!(
        state
            .act(Action::SetAutoUpdateSubscriptions(false))
            .is_none()
    );
    state.reduce(WorkerEvent::Setting(
        SettingChange::AutoUpdateSubscriptions(false),
        Ok(()),
    ));
    state.config.interface.auto_update_subscriptions = false;
    assert!(
        state
            .act(Action::SetAutoUpdateSubscriptions(false))
            .is_none()
    );
}

#[test]
fn release_settings_use_jobs_and_respect_busy_state() {
    let mut state = State {
        config_ready: true,
        updates: UpdatesState {
            newest_release: Some(Release {
                version: "999.0.0".into(),
                url: "https://example.com/release".into(),
                prerelease: false,
            }),
            ..UpdatesState::default()
        },
        ..State::default()
    };
    assert!(matches!(
        state.act(Action::SkipVersion),
        Some(Job::SkipVersion(version)) if version == "999.0.0"
    ));
    assert!(state.act(Action::SetCheckUpdates(false)).is_none());
    state.reduce(WorkerEvent::SkipVersion(Ok(())));
    assert!(matches!(
        state.act(Action::SetCheckUpdates(false)),
        Some(Job::Setting(SettingChange::CheckUpdates(false)))
    ));
}

#[cfg(windows)]
#[test]
fn opening_settings_refreshes_autostart_every_time() {
    let mut state = State::default();
    assert!(matches!(
        state.act(Action::OpenSettings),
        Some(Job::LoadAutostart)
    ));
    assert_eq!(state.settings.screen.autostart, None);
    state.reduce(WorkerEvent::AutostartLoaded(Ok(true)));
    assert_eq!(state.settings.screen.autostart, Some(true));

    state.act(Action::ShowConnection);
    assert!(matches!(
        state.act(Action::OpenSettings),
        Some(Job::LoadAutostart)
    ));
    assert_eq!(state.settings.screen.autostart, None);
    state.reduce(WorkerEvent::AutostartLoaded(Ok(false)));
    assert_eq!(state.settings.screen.autostart, Some(false));
    state.reduce(WorkerEvent::AutostartLoaded(Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "registry read denied",
    ))));
    assert_eq!(state.settings.screen.autostart, None);
    assert_eq!(
        state.operation_error.as_deref(),
        Some("could not read the autostart setting: registry read denied")
    );
}

#[cfg(windows)]
#[test]
fn windows_settings_jobs_respect_busy_state_and_saved_values() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    assert!(state.act(Action::SetAutostart(true)).is_none());
    state.reduce(WorkerEvent::AutostartLoaded(Ok(false)));
    assert!(state.act(Action::SetAutostart(false)).is_none());
    assert!(state.act(Action::SetCloseToTray(true)).is_none());
    assert!(matches!(
        state.act(Action::SetAutostart(true)),
        Some(Job::SetAutostart(true))
    ));
    assert!(state.operations.settings);
    assert!(state.act(Action::SetCloseToTray(false)).is_none());
    state.reduce(WorkerEvent::SetAutostart(Ok(true)));
    assert!(!state.operations.settings);
    assert_eq!(state.settings.screen.autostart, Some(true));

    assert!(matches!(
        state.act(Action::SetCloseToTray(false)),
        Some(Job::Setting(SettingChange::CloseToTray(false)))
    ));
    assert!(state.operations.settings);
    assert!(state.act(Action::SetAutostart(false)).is_none());
    state.reduce(WorkerEvent::Setting(
        SettingChange::CloseToTray(false),
        Err(rosetun_core::SettingsError::Store(StoreError::NoConfigDir)),
    ));
    assert!(!state.operations.settings);
    assert_eq!(
        state.operation_error.as_deref(),
        Some("could not determine the configuration directory")
    );
    assert!(matches!(
        state.act(Action::SetCloseToTray(false)),
        Some(Job::Setting(SettingChange::CloseToTray(false)))
    ));
    let mut config = AppConfig::default();
    config.interface.close_to_tray = false;
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    state.reduce(WorkerEvent::Setting(
        SettingChange::CloseToTray(false),
        Ok(()),
    ));
    assert!(!state.operations.settings);
    assert!(state.operation_error.is_none());
    assert!(state.act(Action::SetCloseToTray(false)).is_none());
}

#[cfg(windows)]
#[test]
fn failed_autostart_write_clears_busy_and_loaded_state() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.reduce(WorkerEvent::AutostartLoaded(Ok(false)));
    assert!(matches!(
        state.act(Action::SetAutostart(true)),
        Some(Job::SetAutostart(true))
    ));
    state.reduce(WorkerEvent::SetAutostart(Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "registry write denied",
    ))));
    assert!(!state.operations.settings);
    assert_eq!(state.settings.screen.autostart, None);
    assert_eq!(
        state.operation_error.as_deref(),
        Some("could not change autostart: registry write denied")
    );
    assert!(state.act(Action::SetAutostart(true)).is_none());
}

#[cfg(windows)]
#[test]
fn folder_launch_uses_the_worker_and_reports_failures() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.settings.screen.config_folder = Some(PathBuf::from("C:\\Users\\Test\\Rosetun"));
    assert!(
        state
            .act(Action::OpenFolder(AboutFolder::Licenses))
            .is_none()
    );
    assert!(matches!(
        state.act(Action::OpenFolder(AboutFolder::Config)),
        Some(Job::OpenFolder(path)) if path.as_path() == std::path::Path::new("C:\\Users\\Test\\Rosetun")
    ));
    assert!(state.operations.settings);
    state.reduce(WorkerEvent::OpenFolder(Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "explorer unavailable",
    ))));
    assert!(!state.operations.settings);
    assert_eq!(
        state.operation_error.as_deref(),
        Some("could not open the folder: explorer unavailable")
    );

    let licenses = PathBuf::from("C:\\Program Files\\Rosetun\\licenses");
    state.settings.screen.licenses_folder = Some(licenses.clone());
    assert!(matches!(
        state.act(Action::OpenFolder(AboutFolder::Licenses)),
        Some(Job::OpenFolder(path)) if path == licenses
    ));
}
