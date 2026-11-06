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
    assert!(state.operations.settings.is_none());
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
    assert!(state.operations.settings.is_none());
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
    assert!(state.operations.settings.is_some());
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
    assert!(state.operations.settings.is_none());
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
    assert!(state.operations.settings.is_some());
    assert!(state.act(Action::SetVerboseLog(true)).is_none());
    state.reduce(WorkerEvent::SetInterfaceScale(Err(
        rosetun_core::SettingsError::UnsupportedScale,
    )));
    assert!(state.operations.settings.is_none());
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
    assert!(state.operations.settings.is_none());
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
    assert!(state.operations.settings.is_none());
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
    assert!(state.operations.settings.is_some());
    assert!(
        state
            .act(Action::SetLanguage(LanguageSetting::English))
            .is_none()
    );
    state.reduce(WorkerEvent::SetLanguage(Ok(())));
    assert!(state.operations.settings.is_none());
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
fn choosing_an_accent_saves_it_and_switches_the_palette_it_selects() {
    use rosetun_config::AccentPreset;

    let mut state = State::default();
    assert!(state.act(Action::SetAccent(AccentPreset::Teal)).is_none());
    state.config_ready = true;
    assert_eq!(state.config.interface.accent, AccentPreset::Rose);
    assert!(state.act(Action::SetAccent(AccentPreset::Rose)).is_none());
    assert!(matches!(
        state.act(Action::SetAccent(AccentPreset::Teal)),
        Some(Job::SetAccent(AccentPreset::Teal))
    ));
    assert!(state.operations.settings.is_some());
    assert!(state.act(Action::SetAccent(AccentPreset::Amber)).is_none());
    state.reduce(WorkerEvent::SetAccent(Ok(())));
    assert!(state.operations.settings.is_none());

    let mut config = state.config.clone();
    config.interface.accent = AccentPreset::Teal;
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    assert_eq!(state.config.interface.accent, AccentPreset::Teal);
    assert_eq!(
        crate::theme::palette_of(state.config.interface.accent),
        &crate::theme::Palette::TEAL
    );
    assert!(state.act(Action::SetAccent(AccentPreset::Teal)).is_none());
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
    assert!(state.operations.settings.is_some());
    assert!(state.act(Action::SetReduceMotion(true)).is_none());
    state.reduce(WorkerEvent::Setting(
        SettingChange::ReduceMotion(true),
        Ok(()),
    ));
    assert!(state.operations.settings.is_none());
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
    assert!(state.operations.settings.is_none());
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
fn local_network_setting_applies_on_the_next_connection() {
    let mut state = state_for_auto_connect();
    assert!(!state.config.settings.allow_lan);
    assert!(matches!(
        state.act(Action::SetAllowLan(true)),
        Some(Job::Setting(SettingChange::AllowLan(true)))
    ));
    assert!(state.act(Action::SetAllowLan(true)).is_none());
    state.reduce(WorkerEvent::Setting(SettingChange::AllowLan(true), Ok(())));
    state.config.settings.allow_lan = true;
    assert!(
        rosetun_ipc::ConnectRequest::from_config(&state.config)
            .unwrap()
            .settings
            .allow_lan
    );
    assert!(state.act(Action::SetAllowLan(true)).is_none());
}

#[test]
fn private_networks_change_only_with_the_local_network_on() {
    let mut state = state_for_auto_connect();
    assert!(state.act(Action::SetPrivateNetworks(true)).is_none());
    state.config.settings.allow_lan = true;
    assert!(matches!(
        state.act(Action::SetPrivateNetworks(true)),
        Some(Job::Setting(SettingChange::PrivateNetworks(true)))
    ));
    state.reduce(WorkerEvent::Setting(
        SettingChange::PrivateNetworks(true),
        Ok(()),
    ));
    state.config.settings.private_networks = true;
    assert!(state.act(Action::SetPrivateNetworks(true)).is_none());
}

#[test]
fn local_network_hint_requires_a_known_active_request_with_a_different_value() {
    let mut state = connected_state_for_apply();
    assert!(!state.allow_lan_next_connect());
    state.config.settings.allow_lan = !state
        .session
        .session_request
        .as_ref()
        .unwrap()
        .settings
        .allow_lan;
    assert!(state.allow_lan_next_connect());
    state.session.session_request = None;
    assert!(!state.allow_lan_next_connect());
    state.session.session_request =
        Some(rosetun_ipc::ConnectRequest::from_config(&state.config).unwrap());
    state.config.settings.allow_lan = !state.config.settings.allow_lan;
    assert!(state.allow_lan_next_connect());
    state.status.state = ConnectionState::Disconnected;
    assert!(!state.allow_lan_next_connect());
    state.status.state = ConnectionState::Connected;
    state.helper_available = false;
    assert!(!state.allow_lan_next_connect());
}

#[test]
fn each_connection_setting_waits_on_its_own() {
    let mut state = connected_state_for_apply();
    assert!(!state.private_networks_next_connect());
    assert!(!state.auto_reconnect_next_connect());

    state.config.settings.auto_reconnect = !state.config.settings.auto_reconnect;
    assert!(state.auto_reconnect_next_connect());
    assert!(!state.allow_lan_next_connect());
    assert!(!state.private_networks_next_connect());
    state.config.settings.auto_reconnect = !state.config.settings.auto_reconnect;

    state.config.settings.private_networks = !state.config.settings.private_networks;
    assert!(
        !state.private_networks_next_connect(),
        "does nothing without the local network"
    );
    state.config.settings.allow_lan = true;
    assert!(state.private_networks_next_connect());
    assert!(state.allow_lan_next_connect());

    state.status.state = ConnectionState::Disconnected;
    assert!(!state.private_networks_next_connect());
    assert!(!state.allow_lan_next_connect());
    assert!(!state.auto_reconnect_next_connect());
}

#[test]
fn the_kill_switch_waits_for_a_connection_even_when_apply_is_open() {
    let mut state = connected_state_for_apply();
    assert!(!state.waits_for_next_connect(SessionPart::Protection));
    state.config.settings.kill_switch = !state.config.settings.kill_switch;
    state.refresh_cached_request();
    assert!(state.waits_for_next_connect(SessionPart::Protection));
    state.status.state = ConnectionState::Disconnected;
    assert!(!state.waits_for_next_connect(SessionPart::Protection));
}

#[test]
fn dns_waits_for_a_connection_only_while_apply_is_closed() {
    let mut state = connected_state_for_apply();
    state.config.settings.dns.server_name = "changed.example.com".to_owned();
    state.refresh_cached_request();
    assert!(state.can_apply());
    assert!(!state.waits_for_next_connect(SessionPart::Dns));
    state.status.state = ConnectionState::Reconnecting;
    assert!(!state.can_apply());
    assert!(state.waits_for_next_connect(SessionPart::Dns));
}

#[test]
fn network_protection_hint_uses_running_request_not_edited_settings() {
    let mut state = connected_state_for_apply();
    state.status.state = ConnectionState::Reconnecting;
    state.config.settings.kill_switch = false;
    state
        .session
        .session_request
        .as_mut()
        .unwrap()
        .settings
        .kill_switch = true;
    assert!(state.running_session_protected());

    state.config.settings.kill_switch = true;
    state
        .session
        .session_request
        .as_mut()
        .unwrap()
        .settings
        .kill_switch = false;
    assert!(!state.running_session_protected());
    state.session.session_request = None;
    assert!(!state.running_session_protected());
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

#[cfg(any(windows, target_os = "linux"))]
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
    assert!(state.operations.settings.is_some());
    assert!(state.act(Action::SetCloseToTray(false)).is_none());
    state.reduce(WorkerEvent::SetAutostart(Ok(true)));
    assert!(state.operations.settings.is_none());
    assert_eq!(state.settings.screen.autostart, Some(true));

    assert!(matches!(
        state.take_queued_setting(),
        Some(Job::Setting(SettingChange::CloseToTray(false)))
    ));
    assert!(state.operations.settings.is_some());
    assert!(state.act(Action::SetAutostart(false)).is_none());
    state.reduce(WorkerEvent::Setting(
        SettingChange::CloseToTray(false),
        Err(rosetun_core::SettingsError::Store(StoreError::NoConfigDir)),
    ));
    assert!(state.operations.settings.is_none());
    assert_eq!(
        state.operation_error.as_deref(),
        Some("could not determine the configuration directory")
    );
    assert!(matches!(
        state.take_queued_setting(),
        Some(Job::SetAutostart(false))
    ));
    state.reduce(WorkerEvent::SetAutostart(Ok(false)));
    assert!(state.take_queued_setting().is_none());
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
    assert!(state.operations.settings.is_none());
    assert!(state.operation_error.is_none());
    assert!(state.act(Action::SetCloseToTray(false)).is_none());
}

#[cfg(any(windows, target_os = "linux"))]
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
    assert!(state.operations.settings.is_none());
    assert_eq!(state.settings.screen.autostart, None);
    assert_eq!(
        state.operation_error.as_deref(),
        Some("could not change autostart: registry write denied")
    );
    assert!(state.act(Action::SetAutostart(true)).is_none());
}

#[cfg(windows)]
#[test]
fn report_flow_handles_cancel_and_saved_folder_without_a_helper() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    assert!(matches!(
        state.act(Action::SaveReport),
        Some(Job::SaveReport { snapshot, .. }) if snapshot.helper_version.is_none()
    ));
    assert!(state.act(Action::SaveReport).is_none());
    state.reduce(WorkerEvent::ReportSaved {
        result: Ok(None),
        new_checks: None,
    });
    assert!(!state.settings.screen.report_running);
    assert!(state.settings.screen.report_saved.is_none());

    assert!(matches!(
        state.act(Action::SaveReport),
        Some(Job::SaveReport { .. })
    ));
    state.reduce(WorkerEvent::ReportSaved {
        result: Ok(Some(PathBuf::from("C:\\Users\\ExampleUser\\report.txt"))),
        new_checks: None,
    });
    assert!(matches!(
        state.act(Action::ShowReportFolder),
        Some(Job::OpenFolder(path)) if path.as_path() == std::path::Path::new("C:\\Users\\ExampleUser")
    ));
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
    assert!(state.operations.settings.is_some());
    state.reduce(WorkerEvent::OpenFolder(Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "explorer unavailable",
    ))));
    assert!(state.operations.settings.is_none());
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

#[test]
fn xray_settings_count_reality_nodes_and_keep_running_chain() {
    let mut state = state_for_auto_connect();
    state.config.subscriptions[0].nodes[0].stream.tls =
        rosetun_config::TlsMode::Reality(rosetun_config::RealityParams {
            sni: Some("example.com".into()),
            public_key: "test-public-key".into(),
            short_id: None,
            fingerprint: None,
        });
    state.config.settings.xray = XrayUse::Off;
    assert_eq!(state.xray_reality_count(), 1);
    let node = &state.config.subscriptions[0].nodes[0];
    let with = |xray| rosetun_config::Settings {
        xray,
        ..Default::default()
    };
    assert!(!rosetun_core::uses_xray(node, &with(XrayUse::Off)));
    assert!(rosetun_core::uses_xray(node, &with(XrayUse::Auto)));
    state.status.state = ConnectionState::Connected;
    state.status.node = Some(NodeId::new("node"));
    state.status.xray = true;
    state.status.xray_use = Some(XrayUse::Auto);
    assert_eq!(
        state.running_node().map(|node| node.name.as_str()),
        Some("Test")
    );
    assert_ne!(state.status.xray_use, Some(state.config.settings.xray));
}

#[test]
fn reality_rejection_button_persists_auto_before_connect() {
    let mut state = state_for_auto_connect();
    state.config.subscriptions[0].nodes[0].stream.tls =
        rosetun_config::TlsMode::Reality(rosetun_config::RealityParams {
            sni: Some("example.com".into()),
            public_key: "test-public-key".into(),
            short_id: None,
            fingerprint: None,
        });
    state.config.settings.xray = XrayUse::Off;
    state.status.state = ConnectionState::Failed {
        reason: "reality verification failed".into(),
        failure_kind: Some(FailureKind::ServerRejected),
    };
    assert!(matches!(
        state.act(Action::EnableXrayAutoAndConnect),
        Some(Job::Setting(SettingChange::Xray(XrayUse::Auto)))
    ));
    assert!(state.take_xray_connect().is_none());
    let mut saved = state.config.clone();
    saved.settings.xray = XrayUse::Auto;
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: saved,
    });
    state.reduce(WorkerEvent::Setting(
        SettingChange::Xray(XrayUse::Auto),
        Ok(()),
    ));
    assert!(matches!(state.take_xray_connect(), Some(Job::Connect(_))));
    assert!(state.take_xray_connect().is_none());
}

#[test]
fn xhttp_without_xray_blocks_connect_and_offers_xray_first() {
    let mut state = state_for_auto_connect();
    state.config.subscriptions[0].nodes[0].stream.transport = rosetun_config::Transport::Xhttp {
        path: "/example".into(),
        host: None,
        mode: rosetun_config::XhttpMode::Auto,
        extra: rosetun_config::XhttpExtra::default(),
    };
    state.config.settings.xray = XrayUse::Auto;
    assert!(!state.xhttp_without_xray());
    assert_eq!(state.primary_action(), PrimaryAction::Connect);

    state.config.settings.xray = XrayUse::Off;
    state.status.state = ConnectionState::Disconnected;
    assert!(state.xhttp_without_xray());
    assert_eq!(state.primary_action(), PrimaryAction::Disabled);
    assert!(state.act(Action::Primary).is_none());

    assert!(matches!(
        state.act(Action::EnableXrayAutoAndConnect),
        Some(Job::Setting(SettingChange::Xray(XrayUse::Auto)))
    ));
    let mut saved = state.config.clone();
    saved.settings.xray = XrayUse::Auto;
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: saved,
    });
    state.reduce(WorkerEvent::Setting(
        SettingChange::Xray(XrayUse::Auto),
        Ok(()),
    ));
    assert!(matches!(state.take_xray_connect(), Some(Job::Connect(_))));
}

fn state_with_unreadable_config() -> State {
    let mut state = State::default();
    state.reduce(WorkerEvent::ConfigError(ConfigWorkerError::Store(
        StoreError::NoConfigDir,
    )));
    state
}

#[cfg(windows)]
#[test]
fn unreadable_settings_still_open_their_folder_and_collect_a_report() {
    let mut state = state_with_unreadable_config();
    state.settings.screen.config_folder = Some(PathBuf::from(r"C:\Users\Test\Rosetun"));
    assert!(state.config_unreadable());
    assert!(state.can_open_folders());
    assert!(state.can_save_report());
    assert!(!state.can_edit_settings());
    assert!(!state.can_reset_settings());

    assert!(matches!(
        state.act(Action::OpenFolder(AboutFolder::Config)),
        Some(Job::OpenFolder(path)) if path.as_path() == std::path::Path::new(r"C:\Users\Test\Rosetun")
    ));
    state.reduce(WorkerEvent::OpenFolder(Ok(())));
    assert!(matches!(
        state.act(Action::SaveReport),
        Some(Job::SaveReport { .. })
    ));
    assert!(state.act(Action::RequestResetSettings).is_none());
    assert!(state.act(Action::ConfirmResetSettings).is_none());
}

#[test]
fn unreadable_settings_keep_their_error_and_close_the_window() {
    let state = State::default();
    assert!(state.close_hides_window());
    assert!(!state.can_save_report());

    let mut state = state_with_unreadable_config();
    assert!(!state.close_hides_window());
    assert!(state.act(Action::DismissConfigError).is_none());
    assert!(state.config_error.is_some());

    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: AppConfig::default(),
    });
    assert!(!state.config_unreadable());
    assert!(state.close_hides_window());
    state.config.interface.close_to_tray = false;
    assert!(!state.close_hides_window());
}

#[cfg(not(windows))]
#[test]
fn reports_are_unavailable_even_with_loaded_or_unreadable_settings() {
    let state = State {
        config_ready: true,
        ..State::default()
    };
    assert!(!state.can_save_report());
    assert!(!state_with_unreadable_config().can_save_report());
}

#[test]
fn a_short_save_leaves_the_settings_looking_available() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.set_frame_time(10_000);
    assert!(matches!(
        state.act(Action::SetReduceMotion(true)),
        Some(Job::Setting(SettingChange::ReduceMotion(true)))
    ));
    assert!(!state.settings_busy_shown(10_000));
    assert!(!state.settings_busy_shown(10_399));
    assert!(state.settings_busy_shown(10_400));
    assert!(state.can_edit_settings());
    assert_eq!(
        state.settings_busy_wake(),
        Some(std::time::Duration::from_millis(400))
    );

    state.set_frame_time(10_250);
    assert!(state.can_edit_settings());
    assert_eq!(
        state.settings_busy_wake(),
        Some(std::time::Duration::from_millis(150))
    );

    state.set_frame_time(10_400);
    assert!(!state.can_edit_settings());
    assert!(!state.can_open_folders());
    assert_eq!(state.settings_busy_wake(), None);

    state.reduce(WorkerEvent::Setting(
        SettingChange::ReduceMotion(true),
        Ok(()),
    ));
    assert!(state.can_edit_settings());
    assert_eq!(state.settings_busy_wake(), None);
}

#[test]
fn a_change_during_a_save_is_queued_and_sent_after_it() {
    use rosetun_config::AccentPreset;

    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    assert!(matches!(
        state.act(Action::SetAccent(AccentPreset::Teal)),
        Some(Job::SetAccent(AccentPreset::Teal))
    ));
    assert!(
        state
            .act(Action::SetLanguage(LanguageSetting::Russian))
            .is_none()
    );
    assert!(state.take_queued_setting().is_none());

    let mut config = state.config.clone();
    config.interface.accent = AccentPreset::Teal;
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    state.reduce(WorkerEvent::SetAccent(Ok(())));
    assert!(matches!(
        state.take_queued_setting(),
        Some(Job::SetLanguage(LanguageSetting::Russian))
    ));
    assert!(state.operations.settings.is_some());
    assert!(state.take_queued_setting().is_none());
}

#[test]
fn repeated_clicks_on_one_setting_save_only_the_last() {
    use rosetun_config::AccentPreset;

    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    assert!(matches!(
        state.act(Action::SetAccent(AccentPreset::Teal)),
        Some(Job::SetAccent(AccentPreset::Teal))
    ));
    assert!(state.act(Action::SetAccent(AccentPreset::Amber)).is_none());
    assert!(state.act(Action::SetAccent(AccentPreset::Rose)).is_none());

    let mut config = state.config.clone();
    config.interface.accent = AccentPreset::Teal;
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    state.reduce(WorkerEvent::SetAccent(Ok(())));
    assert!(matches!(
        state.take_queued_setting(),
        Some(Job::SetAccent(AccentPreset::Rose))
    ));
    let mut config = state.config.clone();
    config.interface.accent = AccentPreset::Rose;
    state.reduce(WorkerEvent::Config {
        generation: 2,
        config,
    });
    state.reduce(WorkerEvent::SetAccent(Ok(())));
    assert!(state.take_queued_setting().is_none());
}

#[test]
fn different_settings_queued_during_a_save_go_out_in_order() {
    use rosetun_config::AccentPreset;

    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    assert!(matches!(
        state.act(Action::SetReduceMotion(true)),
        Some(Job::Setting(SettingChange::ReduceMotion(true)))
    ));
    assert!(state.act(Action::SetCheckUpdates(false)).is_none());
    assert!(state.act(Action::SetAccent(AccentPreset::Amber)).is_none());
    state.reduce(WorkerEvent::Setting(
        SettingChange::ReduceMotion(true),
        Ok(()),
    ));
    assert!(matches!(
        state.take_queued_setting(),
        Some(Job::Setting(SettingChange::CheckUpdates(false)))
    ));
    state.reduce(WorkerEvent::Setting(
        SettingChange::CheckUpdates(false),
        Ok(()),
    ));
    assert!(matches!(
        state.take_queued_setting(),
        Some(Job::SetAccent(AccentPreset::Amber))
    ));
}

#[test]
fn a_failed_save_keeps_its_error_and_the_queue_behind_it() {
    use rosetun_config::AccentPreset;

    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    assert!(matches!(
        state.act(Action::SetReduceMotion(true)),
        Some(Job::Setting(SettingChange::ReduceMotion(true)))
    ));
    assert!(state.act(Action::SetAccent(AccentPreset::Teal)).is_none());
    state.reduce(WorkerEvent::Setting(
        SettingChange::ReduceMotion(true),
        Err(rosetun_core::SettingsError::Store(StoreError::NoConfigDir)),
    ));
    let error = Some("could not determine the configuration directory");
    assert_eq!(state.operation_error.as_deref(), error);

    assert!(matches!(
        state.take_queued_setting(),
        Some(Job::SetAccent(AccentPreset::Teal))
    ));
    assert_eq!(state.operation_error.as_deref(), error);
    state.reduce(WorkerEvent::SetAccent(Ok(())));
    assert_eq!(state.operation_error.as_deref(), error);
    assert!(state.take_queued_setting().is_none());

    assert!(matches!(
        state.act(Action::SetReduceMotion(true)),
        Some(Job::Setting(SettingChange::ReduceMotion(true)))
    ));
    assert!(state.operation_error.is_none());
}

fn state_with_fragment_screen(xray: XrayUse) -> State {
    let mut state = State::default();
    let mut config = AppConfig::default();
    config.settings.xray = xray;
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    state.act(Action::OpenSettings);
    state
}

#[test]
fn the_fragment_form_starts_from_the_saved_values() {
    let mut state = State::default();
    let mut config = AppConfig::default();
    config.settings.tls_fragment = rosetun_config::TlsFragment {
        enabled: true,
        packets: "1-3".parse().unwrap(),
        length: "100-200".parse().unwrap(),
        interval: "5-15".parse().unwrap(),
    };
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    state.act(Action::OpenSettings);
    let screen = &state.settings.screen;
    assert_eq!(screen.fragment_packets, "1-3");
    assert_eq!(screen.fragment_length, "100-200");
    assert_eq!(screen.fragment_interval, "5-15");
}

#[test]
fn fragmentation_cannot_be_turned_on_while_xray_is_off() {
    let mut state = state_with_fragment_screen(XrayUse::Off);
    assert!(state.act(Action::SetTlsFragment(true)).is_none());
    assert!(state.act(Action::SaveTlsFragment).is_none());
    assert!(state.operations.settings.is_none());

    let mut state = state_with_fragment_screen(XrayUse::Auto);
    let Some(Job::Setting(SettingChange::TlsFragment(fragment))) =
        state.act(Action::SetTlsFragment(true))
    else {
        panic!("expected a fragmentation job");
    };
    assert!(fragment.enabled);
    assert_eq!(
        fragment.length,
        rosetun_config::TlsFragment::default().length
    );
}

#[test]
fn a_wrong_fragment_value_blocks_saving_and_a_right_one_saves_with_the_switch_as_it_is() {
    let mut state = state_with_fragment_screen(XrayUse::Always);
    state.config.settings.tls_fragment.enabled = true;
    for (field, value) in [
        ("packets", "0-3"),
        ("packets", "tlshello2"),
        ("length", "1-1501"),
        ("length", ""),
        ("interval", "20-10"),
    ] {
        state
            .settings
            .screen
            .sync_fragment(&state.config.settings.tls_fragment);
        match field {
            "packets" => state.settings.screen.fragment_packets = value.into(),
            "length" => state.settings.screen.fragment_length = value.into(),
            _ => state.settings.screen.fragment_interval = value.into(),
        }
        state.settings.screen.fragment_dirty = true;
        assert!(
            state.settings.screen.parsed_fragment(true).is_err(),
            "{field} {value:?}"
        );
        assert!(
            state.act(Action::SaveTlsFragment).is_none(),
            "{field} {value:?}"
        );
    }

    state
        .settings
        .screen
        .sync_fragment(&state.config.settings.tls_fragment);
    assert!(state.act(Action::SaveTlsFragment).is_none());
    state.settings.screen.fragment_length = "100-200".into();
    let Some(Job::Setting(SettingChange::TlsFragment(fragment))) =
        state.act(Action::SaveTlsFragment)
    else {
        panic!("expected a fragmentation job");
    };
    assert!(fragment.enabled);
    assert_eq!(fragment.length.to_string(), "100-200");
}

#[test]
fn unsaved_fragment_input_survives_a_config_reload_until_it_is_saved() {
    let mut state = state_with_fragment_screen(XrayUse::Auto);
    state.settings.screen.fragment_length = "100-200".into();
    state.settings.screen.fragment_dirty = true;
    let mut config = state.config.clone();
    config.settings.kill_switch = true;
    state.reduce(WorkerEvent::Config {
        generation: 2,
        config,
    });
    assert_eq!(state.settings.screen.fragment_length, "100-200");

    state.config.settings.tls_fragment.enabled = true;
    let Some(Job::Setting(change @ SettingChange::TlsFragment(_))) =
        state.act(Action::SaveTlsFragment)
    else {
        panic!("expected a fragmentation job");
    };
    state.reduce(WorkerEvent::Setting(change, Ok(())));
    assert!(!state.settings.screen.fragment_dirty);
}

fn proxy_config(state: &mut State, generation: u64) {
    let mut config = state.config.clone();
    config.settings.connection_mode = rosetun_config::ConnectionMode::SystemProxy;
    state.reduce(WorkerEvent::Config { generation, config });
}

#[test]
fn turning_the_kill_switch_on_in_the_proxy_mode_asks_first() {
    let mut state = connected_state_for_apply();
    proxy_config(&mut state, 100);
    assert!(state.act(Action::SetKillSwitch(true)).is_none());
    assert!(state.proxy_kill_switch_confirmation);
    assert!(!state.operations.kill_switch);

    assert!(state.act(Action::CancelProxyKillSwitch).is_none());
    assert!(!state.proxy_kill_switch_confirmation);

    state.act(Action::SetKillSwitch(true));
    assert!(matches!(
        state.act(Action::ConfirmProxyKillSwitch),
        Some(Job::SetKillSwitch(true))
    ));
    assert!(!state.proxy_kill_switch_confirmation);
}

#[test]
fn the_kill_switch_of_the_tunnel_mode_and_turning_it_off_ask_nothing() {
    let mut state = connected_state_for_apply();
    assert!(matches!(
        state.act(Action::SetKillSwitch(true)),
        Some(Job::SetKillSwitch(true))
    ));
    assert!(!state.proxy_kill_switch_confirmation);

    let mut state = connected_state_for_apply();
    proxy_config(&mut state, 100);
    assert!(matches!(
        state.act(Action::SetKillSwitch(false)),
        Some(Job::SetKillSwitch(false))
    ));
}

#[test]
fn a_change_of_mode_during_a_session_goes_in_through_apply() {
    let mut state = connected_state_for_apply();
    assert!(state.take_local_proxy_apply().is_none());
    let job = state.act(Action::SetConnectionMode(
        rosetun_config::ConnectionMode::SystemProxy,
    ));
    assert!(matches!(
        job,
        Some(Job::Setting(rosetun_core::SettingChange::ConnectionMode(_)))
    ));
    // Still saving: the new mode is not in the config yet.
    assert!(state.take_local_proxy_apply().is_none());

    state.operations.settings = None;
    proxy_config(&mut state, 100);
    let Some(Job::Apply(request)) = state.take_local_proxy_apply() else {
        panic!("the session takes the new mode");
    };
    assert_eq!(
        request.settings.connection_mode,
        rosetun_config::ConnectionMode::SystemProxy
    );
    assert!(state.take_local_proxy_apply().is_none(), "only once");
}

#[test]
fn a_change_of_mode_without_a_session_waits_for_the_next_connect() {
    let mut state = State::default();
    state.config_ready = true;
    state.system_proxy.follow_session();
    assert!(state.take_local_proxy_apply().is_none());
    assert!(state.take_local_proxy_apply().is_none());
}

#[test]
fn a_port_below_the_allowed_range_is_not_saved() {
    let mut state = connected_state_for_apply();
    assert!(state.act(Action::SetLocalProxyPort(80)).is_none());
    assert!(matches!(
        state.act(Action::SetLocalProxyPort(20808)),
        Some(Job::Setting(rosetun_core::SettingChange::LocalProxyPort(
            20808
        )))
    ));
}

#[test]
fn the_captions_say_what_each_mode_does_with_the_rest() {
    let mut state = connected_state_for_apply();
    assert_eq!(
        state.connection_mode_detail(),
        tr!("connection-mode-tun-detail")
    );
    assert_eq!(state.kill_switch_detail(), tr!("kill-switch-detail"));

    state.config.settings.connection_mode = rosetun_config::ConnectionMode::SystemProxy;
    assert_eq!(
        state.connection_mode_detail(),
        tr!("connection-mode-proxy-detail")
    );
    assert_eq!(state.kill_switch_detail(), tr!("kill-switch-proxy-detail"));

    state.config.settings.kill_switch = true;
    assert_eq!(
        state.connection_mode_detail(),
        tr!("connection-mode-proxy-strict-detail")
    );
}

#[test]
fn the_address_for_other_devices_is_read_only_while_it_shows() {
    let mut state = State::default();
    assert!(state.take_lan_address().is_none());
    state.config.settings.connection_mode = rosetun_config::ConnectionMode::SystemProxy;
    assert!(state.take_lan_address().is_none());
    state.config.settings.local_proxy.share_on_lan = true;
    assert!(matches!(
        state.take_lan_address(),
        Some(Job::ReadLanAddress)
    ));
    assert!(state.take_lan_address().is_none(), "one read at a time");
    state.reduce(WorkerEvent::LanAddress(Some("192.0.2.5".parse().unwrap())));
    assert_eq!(
        state.system_proxy.lan_address,
        Some("192.0.2.5".parse().unwrap())
    );
    assert!(state.take_lan_address().is_none(), "not again right away");
}
