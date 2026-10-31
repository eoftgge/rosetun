use std::mem::{Discriminant, discriminant};
use std::path::PathBuf;
use std::time::Duration;

use rosetun_config::{ConnectionState, DnsSettings, Node, Outbound, TlsMode, XrayUse};
use rosetun_core::{DnsPreset, SettingChange};

use super::{Action, Job, Screen, State, now_unix};
use crate::errors;
use crate::worker::WorkerEvent;

/// A save shorter than this leaves the controls as they look; a click during it waits in
/// `SettingsState::queued`. Saves take tens of milliseconds, and greying the page for that
/// long reads as a flicker.
pub(crate) const SETTINGS_BUSY_SHOWN_AFTER_MS: u64 = 400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub(crate) enum SettingsSection {
    #[default]
    General,
    Connection,
    Network,
    Advanced,
    Service,
    About,
}

#[derive(Default)]
pub(crate) struct SettingsScreen {
    pub(crate) section: SettingsSection,
    pub(crate) custom_dns: bool,
    pub(crate) reset_open: bool,
    pub(crate) server: String,
    pub(crate) server_name: String,
    pub(crate) port: String,
    pub(crate) path: String,
    pub(crate) dirty: bool,
    pub(crate) connect_after_xray_change: bool,
    pub(crate) xray_connect_ready: bool,
    pub(crate) config_folder: Option<PathBuf>,
    pub(crate) licenses_folder: Option<PathBuf>,
    #[cfg(windows)]
    pub(crate) autostart: Option<bool>,
    #[cfg(windows)]
    pub(crate) report_running: bool,
    #[cfg(windows)]
    pub(crate) report_saved: Option<PathBuf>,
    pub(super) opened: bool,
}

impl SettingsScreen {
    pub(super) fn sync_dns(&mut self, dns: &DnsSettings) {
        self.custom_dns = DnsPreset::matching(dns).is_none();
        self.server = dns.server.to_string();
        self.server_name = dns.server_name.clone();
        self.port = dns.port.map_or_else(String::new, |port| port.to_string());
        self.path = dns.path.clone().unwrap_or_default();
    }

    pub(crate) fn parsed_dns(&self) -> Result<DnsSettings, rosetun_core::DnsInputError> {
        rosetun_core::parse_dns_input(&self.server, &self.server_name, &self.port, &self.path)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AboutFolder {
    Config,
    Licenses,
}

#[derive(Default)]
pub(crate) struct SettingsState {
    pub(crate) screen: SettingsScreen,
    /// Changes asked for while a save ran, sent one by one after it.
    pub(super) queued: Vec<Action>,
    /// Keeps a failed save's error on screen while the changes queued behind it go out.
    keep_error: bool,
    /// This frame's `display::monotonic_ms`, set by the app before anything else.
    now_ms: u64,
}

/// Changes that replace each other's pending value share a slot.
fn queue_slot(action: &Action) -> Discriminant<Action> {
    match action {
        Action::SetDnsPreset(_) => discriminant(&Action::SaveDns),
        Action::EnableXrayAutoAndConnect => discriminant(&Action::SetXray(XrayUse::Auto)),
        action => discriminant(action),
    }
}

fn waits_for_save(action: &Action) -> bool {
    match action {
        Action::SetInterfaceScale(_)
        | Action::SetLanguage(_)
        | Action::SetAccent(_)
        | Action::SetReduceMotion(_)
        | Action::SetConnectOnStart(_)
        | Action::SetAutoReconnect(_)
        | Action::SetAllowLan(_)
        | Action::SetXray(_)
        | Action::EnableXrayAutoAndConnect
        | Action::SetAutoUpdateSubscriptions(_)
        | Action::SetCheckUpdates(_)
        | Action::SaveDns
        | Action::SetDnsPreset(_)
        | Action::RequestResetSettings
        | Action::ConfirmResetSettings
        | Action::SetVerboseLog(_)
        | Action::SkipVersion
        | Action::Apply
        | Action::RestoreMyEdits => true,
        #[cfg(any(windows, test))]
        Action::AnnounceUpdate(_) => true,
        #[cfg(windows)]
        Action::SetAutostart(_)
        | Action::SetCloseToTray(_)
        | Action::SetOnQuit(_)
        | Action::SetNotifications(_)
        | Action::ShowReportFolder
        | Action::OpenFolder(_) => true,
        _ => false,
    }
}

impl State {
    pub(crate) fn running_node(&self) -> Option<&Node> {
        self.session
            .session_request
            .as_ref()
            .map(|request| &request.node)
            .or_else(|| {
                self.config
                    .subscriptions
                    .iter()
                    .flat_map(|subscription| &subscription.nodes)
                    .find(|node| self.status.node.as_ref() == Some(&node.id))
            })
    }

    pub(crate) fn allow_lan_next_connect(&self) -> bool {
        self.visible_status()
            .is_some_and(|status| status.state.is_active() || status.state.is_transitional())
            && self
                .session
                .session_request
                .as_ref()
                .is_some_and(|request| request.settings.allow_lan != self.config.settings.allow_lan)
    }

    pub(crate) fn running_session_protected(&self) -> bool {
        self.session
            .session_request
            .as_ref()
            .is_some_and(|request| request.settings.kill_switch)
    }

    pub(crate) fn xray_reality_count(&self) -> usize {
        self.config
            .subscriptions
            .iter()
            .flat_map(|subscription| &subscription.nodes)
            .filter(|node| {
                matches!(&node.outbound, Outbound::Vless(_))
                    && matches!(&node.stream.tls, TlsMode::Reality(_))
            })
            .count()
    }

    pub(crate) fn take_xray_connect(&mut self) -> Option<Job> {
        if !self.settings.screen.xray_connect_ready
            || self.config.settings.xray != XrayUse::Auto
            || !self.helper_available
            || !matches!(
                self.status.state,
                ConnectionState::Disconnected
                    | ConnectionState::Failed { .. }
                    | ConnectionState::FailedProtected { .. }
            )
        {
            return None;
        }
        self.settings.screen.xray_connect_ready = false;
        self.act_connection(Action::Primary)
    }

    /// Reset is allowed only when the running tunnel cannot disagree with the
    /// kill switch value that will be written to the configuration.
    pub(crate) fn can_reset_settings(&self) -> bool {
        self.can_edit_settings()
            && !self.operations.helper
            && !self.operations.kill_switch
            && (!self.helper_available
                || matches!(
                    self.status.state,
                    ConnectionState::Disconnected | ConnectionState::Failed { .. }
                ))
    }

    /// Whether settings controls look available. A click on one while a save runs is queued.
    pub(crate) fn can_edit_settings(&self) -> bool {
        self.config_ready && !self.settings_busy_shown(self.settings.now_ms)
    }

    pub(crate) fn set_frame_time(&mut self, now_ms: u64) {
        self.settings.now_ms = now_ms;
    }

    pub(crate) fn frame_time(&self) -> u64 {
        self.settings.now_ms
    }

    /// Whether a settings save has run long enough to show it.
    pub(crate) fn settings_busy_shown(&self, now_ms: u64) -> bool {
        self.operations
            .settings
            .is_some_and(|started| now_ms.saturating_sub(started) >= SETTINGS_BUSY_SHOWN_AFTER_MS)
    }

    /// When a running save starts to show, so the controls grey out without a pointer move.
    pub(crate) fn settings_busy_wake(&self) -> Option<Duration> {
        let shown_at = self
            .operations
            .settings?
            .saturating_add(SETTINGS_BUSY_SHOWN_AFTER_MS);
        (shown_at > self.settings.now_ms)
            .then(|| Duration::from_millis(shown_at - self.settings.now_ms))
    }

    /// Queues an action that would start a save while another runs, or hands it back.
    pub(super) fn defer_setting(&mut self, action: Action) -> Option<Action> {
        if self.operations.settings.is_none() || !waits_for_save(&action) {
            return Some(action);
        }
        let slot = queue_slot(&action);
        match self
            .settings
            .queued
            .iter_mut()
            .find(|queued| queue_slot(queued) == slot)
        {
            Some(queued) => *queued = action,
            None => self.settings.queued.push(action),
        }
        None
    }

    /// The next queued change, once nothing saves. Each one is checked again against the
    /// saved settings, so a change the earlier saves made unnecessary is dropped.
    pub(crate) fn take_queued_setting(&mut self) -> Option<Job> {
        while self.operations.settings.is_none() && !self.settings.queued.is_empty() {
            let action = self.settings.queued.remove(0);
            if let Some(job) = self.act(action) {
                return Some(job);
            }
        }
        if self.operations.settings.is_none() {
            self.settings.keep_error = false;
        }
        None
    }

    /// The settings file could not be read. Nothing is loaded and nothing may
    /// be written over it, but its folder and a report stay within reach.
    pub(crate) fn config_unreadable(&self) -> bool {
        !self.config_ready && self.config_error.is_some()
    }

    #[cfg(any(windows, test))]
    pub(crate) fn can_open_folders(&self) -> bool {
        (self.config_ready || self.config_unreadable())
            && !self.settings_busy_shown(self.settings.now_ms)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn can_save_report(&self) -> bool {
        #[cfg(windows)]
        {
            (self.config_ready || self.config_unreadable()) && !self.settings.screen.report_running
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    /// Whether closing the window hides it to the tray. With unreadable
    /// settings there is nothing to keep running, so closing quits.
    #[cfg(any(windows, test))]
    pub(crate) fn close_hides_window(&self) -> bool {
        if self.config_ready {
            self.config.interface.close_to_tray
        } else {
            self.config_error.is_none()
        }
    }

    pub(super) fn start_settings(&mut self, job: Job) -> Option<Job> {
        self.operations.settings = Some(self.settings.now_ms);
        if !self.settings.keep_error {
            self.operation_error = None;
        }
        Some(job)
    }

    fn finish_settings(&mut self, result: Result<(), rosetun_core::SettingsError>) {
        let error = result
            .err()
            .map(|error| self.text(&errors::settings(crate::i18n::language(), &error)));
        self.end_settings(error);
    }

    fn end_settings(&mut self, error: Option<String>) {
        self.operations.settings = None;
        let failed = error.is_some();
        if failed || !self.settings.keep_error {
            self.operation_error = error;
        }
        self.settings.keep_error =
            (failed || self.settings.keep_error) && !self.settings.queued.is_empty();
    }

    pub(super) fn reduce_settings(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::SetInterfaceScale(result) => self.finish_settings(result),
            WorkerEvent::SetLanguage(result) => self.finish_settings(result),
            WorkerEvent::SetAccent(result) => self.finish_settings(result),
            #[cfg(windows)]
            WorkerEvent::AutostartLoaded(result) => match result {
                Ok(enabled) => self.settings.screen.autostart = Some(enabled),
                Err(error) => {
                    self.settings.screen.autostart = None;
                    let message = tr!("error-autostart-read", detail = error.to_string());
                    self.operation_error = Some(self.text(&message));
                }
            },
            #[cfg(windows)]
            WorkerEvent::SetAutostart(result) => {
                self.settings.screen.autostart = result.as_ref().ok().copied();
                let error = result.err().map(|error| {
                    let message = tr!("error-autostart-write", detail = error.to_string());
                    self.text(&message)
                });
                self.end_settings(error);
            }
            WorkerEvent::Setting(change, result) => {
                if change == SettingChange::Xray(XrayUse::Auto)
                    && self.settings.screen.connect_after_xray_change
                {
                    self.settings.screen.xray_connect_ready = result.is_ok();
                    self.settings.screen.connect_after_xray_change = false;
                }
                if matches!(change, SettingChange::AllowLan(_)) && result.is_ok() {
                    self.queue_lockdown_lan();
                }
                self.finish_settings(result);
            }
            WorkerEvent::SkipVersion(result) => self.finish_settings(result),
            // A background record: its failure costs one more notice at most.
            WorkerEvent::AnnounceUpdate => self.end_settings(None),
            WorkerEvent::SetDns(result) => {
                if result.is_ok() {
                    self.settings.screen.dirty = false;
                    self.settings.screen.sync_dns(&self.config.settings.dns);
                } else if !self.settings.screen.dirty {
                    self.settings.screen.sync_dns(&self.config.settings.dns);
                }
                self.finish_settings(result);
            }
            WorkerEvent::ResetSettings(result) => {
                if result.is_ok() {
                    self.settings.screen.dirty = false;
                    self.settings.screen.sync_dns(&self.config.settings.dns);
                }
                self.settings.screen.reset_open = false;
                self.finish_settings(result);
            }
            WorkerEvent::SetVerboseLog(result) => self.finish_settings(result),
            #[cfg(windows)]
            WorkerEvent::ReportSaved { result, new_checks } => {
                self.settings.screen.report_running = false;
                if let Some(checks) = new_checks
                    && self.system_checks.results.is_none()
                    && !self.system_checks.checking
                {
                    self.system_checks.results = Some(checks);
                    self.system_checks.checked_at = Some(now_unix());
                }
                match result {
                    Ok(Some(path)) => self.settings.screen.report_saved = Some(path),
                    Ok(None) => {}
                    Err(error) => {
                        let message = tr!("report-save-error", detail = error.to_string());
                        self.operation_error = Some(self.text(&message));
                    }
                }
            }
            #[cfg(windows)]
            WorkerEvent::OpenFolder(result) => {
                let error = result.err().map(|error| {
                    let message = tr!("error-open-folder", detail = error.to_string());
                    self.text(&message)
                });
                self.end_settings(error);
            }
            _ => unreachable!("only settings events are dispatched here"),
        }
    }

    pub(super) fn act_settings(&mut self, action: Action) -> Option<Job> {
        let action = self.defer_setting(action)?;
        match action {
            Action::OpenSettings => {
                if !self.settings.screen.opened {
                    self.settings.screen.opened = true;
                    if self.config_ready {
                        self.settings.screen.sync_dns(&self.config.settings.dns);
                    }
                }
                let job = self.show_screen(Screen::Settings);
                #[cfg(windows)]
                {
                    self.session.queued_leave_apply = job;
                    self.settings.screen.autostart = None;
                    return Some(Job::LoadAutostart);
                }
                #[cfg(not(windows))]
                return job;
            }
            Action::OpenSettingsSection(section) => {
                self.settings.screen.section = section;
            }
            Action::OpenLanSettings => {
                if self
                    .rules
                    .screen
                    .add
                    .as_ref()
                    .is_some_and(|dialog| !dialog.busy)
                {
                    self.rules.screen.add = None;
                    self.settings.screen.section = SettingsSection::Connection;
                    return self.act_settings(Action::OpenSettings);
                }
            }
            Action::SetInterfaceScale(percent) => {
                if self.can_edit_settings()
                    && self.config.interface.scale_percent != percent
                    && rosetun_core::INTERFACE_SCALES.contains(&percent)
                {
                    return self.start_settings(Job::SetInterfaceScale(percent));
                }
            }
            Action::SetLanguage(language) => {
                if self.can_edit_settings() && self.config.interface.language != language {
                    return self.start_settings(Job::SetLanguage(language));
                }
            }
            Action::SetAccent(accent) => {
                if self.can_edit_settings() && self.config.interface.accent != accent {
                    return self.start_settings(Job::SetAccent(accent));
                }
            }
            Action::SetReduceMotion(enabled) => {
                if self.can_edit_settings() && self.config.interface.reduce_motion != enabled {
                    return self.start_settings(Job::Setting(SettingChange::ReduceMotion(enabled)));
                }
            }
            #[cfg(windows)]
            Action::SetAutostart(enabled) => {
                if self.can_edit_settings()
                    && self.settings.screen.autostart.is_some()
                    && self.settings.screen.autostart != Some(enabled)
                {
                    return self.start_settings(Job::SetAutostart(enabled));
                }
            }
            #[cfg(windows)]
            Action::SetCloseToTray(enabled) => {
                if self.can_edit_settings() && self.config.interface.close_to_tray != enabled {
                    return self.start_settings(Job::Setting(SettingChange::CloseToTray(enabled)));
                }
            }
            #[cfg(windows)]
            Action::SetOnQuit(action) => {
                if self.can_edit_settings() && self.config.interface.quit_action != action {
                    return self.start_settings(Job::Setting(SettingChange::QuitAction(action)));
                }
            }
            #[cfg(windows)]
            Action::SetNotifications(enabled) => {
                if self.can_edit_settings() && self.config.interface.notifications != enabled {
                    return self
                        .start_settings(Job::Setting(SettingChange::Notifications(enabled)));
                }
            }
            Action::SetConnectOnStart(enabled) => {
                if self.can_edit_settings() && self.config.interface.connect_on_start != enabled {
                    return self
                        .start_settings(Job::Setting(SettingChange::ConnectOnStart(enabled)));
                }
            }
            Action::SetAutoReconnect(enabled) => {
                if self.can_edit_settings() && self.config.settings.auto_reconnect != enabled {
                    return self
                        .start_settings(Job::Setting(SettingChange::AutoReconnect(enabled)));
                }
            }
            Action::SetAllowLan(enabled) => {
                if self.can_edit_settings() && self.config.settings.allow_lan != enabled {
                    return self.start_settings(Job::Setting(SettingChange::AllowLan(enabled)));
                }
            }
            Action::SetXray(setting) => {
                if self.can_edit_settings() && self.config.settings.xray != setting {
                    return self.start_settings(Job::Setting(SettingChange::Xray(setting)));
                }
            }
            Action::EnableXrayAutoAndConnect => {
                let rejected = matches!(
                    self.status.state,
                    ConnectionState::Failed {
                        failure_kind: Some(rosetun_config::FailureKind::ServerRejected),
                        ..
                    } | ConnectionState::FailedProtected {
                        failure_kind: Some(rosetun_config::FailureKind::ServerRejected),
                        ..
                    }
                );
                let reality = self.config.active_node().is_some_and(|(_, node)| {
                    matches!(&node.outbound, Outbound::Vless(_))
                        && matches!(&node.stream.tls, TlsMode::Reality(_))
                });
                let xhttp = self.xhttp_without_xray()
                    && matches!(
                        self.status.state,
                        ConnectionState::Disconnected
                            | ConnectionState::Failed { .. }
                            | ConnectionState::FailedProtected { .. }
                    );
                if self.can_edit_settings()
                    && self.helper_available
                    && !self.operations.helper
                    && ((rejected && reality) || xhttp)
                    && self.config.settings.xray == XrayUse::Off
                {
                    self.settings.screen.connect_after_xray_change = true;
                    return self.start_settings(Job::Setting(SettingChange::Xray(XrayUse::Auto)));
                }
            }
            Action::SetAutoUpdateSubscriptions(enabled) => {
                if self.can_edit_settings()
                    && self.config.interface.auto_update_subscriptions != enabled
                {
                    return self.start_settings(Job::Setting(
                        SettingChange::AutoUpdateSubscriptions(enabled),
                    ));
                }
            }
            Action::SetCheckUpdates(enabled) => {
                if self.can_edit_settings() && self.config.interface.check_updates != enabled {
                    return self.start_settings(Job::Setting(SettingChange::CheckUpdates(enabled)));
                }
            }
            Action::SaveDns => {
                if self.can_edit_settings()
                    && self.settings.screen.custom_dns
                    && let Ok(dns) = self.settings.screen.parsed_dns()
                    && dns != self.config.settings.dns
                {
                    return self.start_settings(Job::SetDns(dns));
                }
            }
            Action::SelectCustomDns => {
                if self.config_ready {
                    self.settings.screen.custom_dns = true;
                }
            }
            Action::SetDnsPreset(preset) => {
                if self.can_edit_settings() {
                    self.settings.screen.custom_dns = false;
                    self.settings.screen.dirty = false;
                    self.settings.screen.sync_dns(&preset.settings());
                    if self.config.settings.dns != preset.settings() {
                        return self.start_settings(Job::SetDns(preset.settings()));
                    }
                }
            }
            Action::RequestResetSettings => {
                if self.can_reset_settings() {
                    self.settings.screen.reset_open = true;
                }
            }
            Action::CancelResetSettings => {
                if self.operations.settings.is_none() {
                    self.settings.screen.reset_open = false;
                }
            }
            Action::ConfirmResetSettings => {
                if self.settings.screen.reset_open && self.can_reset_settings() {
                    return self.start_settings(Job::ResetSettings);
                }
            }
            Action::SetVerboseLog(on) => {
                if self.can_edit_settings()
                    && self.config.settings.verbose_log_active(now_unix()) != on
                {
                    return self.start_settings(Job::SetVerboseLog(on));
                }
            }
            #[cfg(windows)]
            Action::SaveReport => {
                if self.can_save_report() {
                    self.settings.screen.report_running = true;
                    self.settings.screen.report_saved = None;
                    self.operation_error = None;
                    return Some(Job::SaveReport {
                        snapshot: Box::new(
                            crate::report::ReportSnapshot::new(
                                &self.config,
                                &self.status,
                                self.helper_available,
                                self.system_checks.results.as_deref(),
                                self.helper_version.as_deref(),
                                crate::i18n::language(),
                                now_unix(),
                            )
                            .with_last_dns(self.system_checks.last_dns.as_ref()),
                        ),
                        own_alias: self.config.settings.tun.name.clone(),
                    });
                }
            }
            #[cfg(windows)]
            Action::ShowReportFolder => {
                if let Some(folder) = self
                    .settings
                    .screen
                    .report_saved
                    .as_ref()
                    .and_then(|path| path.parent())
                    .map(PathBuf::from)
                {
                    return self.start_settings(Job::OpenFolder(folder));
                }
            }
            #[cfg(windows)]
            Action::OpenFolder(folder) => {
                let path = match folder {
                    AboutFolder::Config => &self.settings.screen.config_folder,
                    AboutFolder::Licenses => &self.settings.screen.licenses_folder,
                };
                if self.can_open_folders()
                    && let Some(path) = path
                {
                    return self.start_settings(Job::OpenFolder(path.clone()));
                }
            }
            _ => unreachable!("only settings actions are dispatched here"),
        }
        None
    }
}
