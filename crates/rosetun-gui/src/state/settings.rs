use std::path::PathBuf;

use rosetun_config::{ConnectionState, DnsSettings};
use rosetun_core::DnsPreset;

use super::{Action, Job, Screen, State, now_unix};
use crate::errors;
use crate::worker::WorkerEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SettingsSection {
    #[default]
    General,
    Connection,
    Network,
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
    pub(crate) config_folder: Option<PathBuf>,
    pub(crate) licenses_folder: Option<PathBuf>,
    #[cfg(windows)]
    pub(crate) autostart: Option<bool>,
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
}

impl State {
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

    pub(crate) fn can_edit_settings(&self) -> bool {
        self.config_ready && !self.operations.settings
    }

    pub(super) fn start_settings(&mut self, job: Job) -> Option<Job> {
        self.operations.settings = true;
        self.operation_error = None;
        Some(job)
    }

    fn finish_settings(&mut self, result: Result<(), rosetun_core::SettingsError>) {
        self.operations.settings = false;
        self.operation_error = result
            .err()
            .map(|error| self.text(&errors::settings(crate::i18n::language(), &error)));
    }

    pub(super) fn reduce_settings(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::SetInterfaceScale(result) => self.finish_settings(result),
            WorkerEvent::SetLanguage(result) => self.finish_settings(result),
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
                self.operations.settings = false;
                self.settings.screen.autostart = result.as_ref().ok().copied();
                self.operation_error = result.err().map(|error| {
                    let message = tr!("error-autostart-write", detail = error.to_string());
                    self.text(&message)
                });
            }
            #[cfg(windows)]
            WorkerEvent::SetCloseToTray(result) => self.finish_settings(result),
            WorkerEvent::SetReduceMotion(result) => self.finish_settings(result),
            WorkerEvent::SetConnectOnStart(result) => self.finish_settings(result),
            WorkerEvent::SetAutoReconnect(result) => self.finish_settings(result),
            WorkerEvent::SetAutoUpdateSubscriptions(result) => self.finish_settings(result),
            WorkerEvent::SetCheckUpdates(result) => self.finish_settings(result),
            WorkerEvent::SkipVersion(result) => self.finish_settings(result),
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
            WorkerEvent::OpenFolder(result) => {
                self.operations.settings = false;
                self.operation_error = result.err().map(|error| {
                    let message = tr!("error-open-folder", detail = error.to_string());
                    self.text(&message)
                });
            }
            _ => unreachable!("only settings events are dispatched here"),
        }
    }

    pub(super) fn act_settings(&mut self, action: Action) -> Option<Job> {
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
                    self.queued_leave_apply = job;
                    self.settings.screen.autostart = None;
                    return Some(Job::LoadAutostart);
                }
                #[cfg(not(windows))]
                return job;
            }
            Action::OpenSettingsSection(section) => {
                self.settings.screen.section = section;
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
            Action::SetReduceMotion(enabled) => {
                if self.can_edit_settings() && self.config.interface.reduce_motion != enabled {
                    return self.start_settings(Job::SetReduceMotion(enabled));
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
                    return self.start_settings(Job::SetCloseToTray(enabled));
                }
            }
            Action::SetConnectOnStart(enabled) => {
                if self.can_edit_settings() && self.config.interface.connect_on_start != enabled {
                    return self.start_settings(Job::SetConnectOnStart(enabled));
                }
            }
            Action::SetAutoReconnect(enabled) => {
                if self.can_edit_settings() && self.config.settings.auto_reconnect != enabled {
                    return self.start_settings(Job::SetAutoReconnect(enabled));
                }
            }
            Action::SetAutoUpdateSubscriptions(enabled) => {
                if self.can_edit_settings()
                    && self.config.interface.auto_update_subscriptions != enabled
                {
                    return self.start_settings(Job::SetAutoUpdateSubscriptions(enabled));
                }
            }
            Action::SetCheckUpdates(enabled) => {
                if self.can_edit_settings() && self.config.interface.check_updates != enabled {
                    return self.start_settings(Job::SetCheckUpdates(enabled));
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
                if self.can_edit_settings() {
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
                if !self.operations.settings {
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
            Action::OpenFolder(folder) => {
                let path = match folder {
                    AboutFolder::Config => &self.settings.screen.config_folder,
                    AboutFolder::Licenses => &self.settings.screen.licenses_folder,
                };
                if self.can_edit_settings()
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
