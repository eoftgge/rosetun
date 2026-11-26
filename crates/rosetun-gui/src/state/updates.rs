use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rosetun_config::ConnectionState;
use rosetun_core::{
    DownloadedUpdate, Release, UpdateCheckError, UpdateDownloadError, is_newer, remembered_release,
};

use super::{Action, Job, State};
use crate::worker::WorkerEvent;

const UPDATE_CHECK_DEFER: u64 = 60;
pub(super) const UPDATE_CHECK_INTERVAL: u64 = 24 * 60 * 60;
pub(super) const UPDATE_CHECK_RETRY: u64 = 6 * 60 * 60;

#[derive(Default)]
pub(crate) struct UpdatesState {
    pub(super) next_update_check: Option<u64>,
    pub(crate) update_check_pending: bool,
    pub(crate) update_check_failed: bool,
    pub(crate) newest_release: Option<Release>,
    pub(crate) download: UpdateDownload,
    /// Set by Cancel; the download thread checks it between reads.
    pub(super) cancel: Arc<AtomicBool>,
    /// "Install and restart" waits for this confirmation while a session is up.
    pub(crate) confirm_install: bool,
    /// Set when a package installer finishes with code 0 so the host can relaunch.
    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    pub(super) installed: bool,
}

/// The offered version's installer, from the first click to the installer starting.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum UpdateDownload {
    #[default]
    Idle,
    Downloading {
        version: String,
        received: u64,
        total: Option<u64>,
    },
    /// Downloaded and checked; nothing runs until the user asks.
    Ready(DownloadedUpdate),
    /// The installer was started and has not answered yet.
    Installing(DownloadedUpdate),
    Failed {
        version: String,
        failure: UpdateFailure,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UpdateFailure {
    Download(UpdateDownloadError),
    /// The user declined the administrator prompt.
    #[cfg_attr(
        not(any(windows, target_os = "linux", target_os = "macos", test)),
        expect(dead_code, reason = "used on desktop installer platforms")
    )]
    Declined,
    /// Installer ended with this exit code without installing.
    #[cfg_attr(
        not(any(windows, target_os = "linux", target_os = "macos", test)),
        expect(dead_code, reason = "used on desktop installer platforms")
    )]
    Installer(u32),
    /// The installer could not be started.
    Start,
}

impl UpdateDownload {
    /// The version this state belongs to, if any.
    pub(crate) fn version(&self) -> Option<&str> {
        match self {
            Self::Idle => None,
            Self::Downloading { version, .. } | Self::Failed { version, .. } => Some(version),
            Self::Ready(update) | Self::Installing(update) => Some(&update.version),
        }
    }
}

impl State {
    pub(crate) fn update_check_blocked_by_connection(&self) -> bool {
        matches!(
            self.visible_status().map(|status| &status.state),
            Some(
                ConnectionState::Connecting
                    | ConnectionState::Reconnecting
                    | ConnectionState::FailedProtected { .. }
            )
        )
    }

    pub(crate) fn can_check_updates(&self) -> bool {
        self.config_ready
            && !self.updates.update_check_pending
            && !self.update_check_blocked_by_connection()
    }

    /// The download state of the offered version; another version's state reads as idle.
    pub(crate) fn offer_download(&self) -> &UpdateDownload {
        const IDLE: &UpdateDownload = &UpdateDownload::Idle;
        match self.available_update() {
            Some(release) if self.updates.download.version() == Some(release.version.as_str()) => {
                &self.updates.download
            }
            _ => IDLE,
        }
    }

    /// Whether this build downloads and runs an installer itself.
    pub(crate) fn can_install_updates() -> bool {
        #[cfg(test)]
        {
            true
        }
        #[cfg(all(not(test), windows))]
        {
            true
        }
        #[cfg(all(not(test), any(target_os = "linux", target_os = "macos")))]
        {
            static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
            *SUPPORTED.get_or_init(rosetun_shell::can_install_updates)
        }
        #[cfg(all(not(test), not(any(windows, target_os = "linux", target_os = "macos"))))]
        {
            false
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    pub(crate) fn take_update_installed(&mut self) -> bool {
        std::mem::take(&mut self.updates.installed)
    }

    pub(super) fn reduce_update_download(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::UpdateProgress {
                version,
                received,
                total,
            } => {
                if let UpdateDownload::Downloading {
                    version: current,
                    received: shown,
                    total: size,
                } = &mut self.updates.download
                    && *current == version
                {
                    *shown = received;
                    *size = total;
                }
            }
            WorkerEvent::UpdateDownloaded { version, result } => {
                if !matches!(&self.updates.download, UpdateDownload::Downloading { version: current, .. } if *current == version)
                {
                    return;
                }
                self.updates.download = match result {
                    Ok(update) => UpdateDownload::Ready(update),
                    Err(UpdateDownloadError::Cancelled) => UpdateDownload::Idle,
                    Err(error) => UpdateDownload::Failed {
                        version,
                        failure: UpdateFailure::Download(error),
                    },
                };
            }
            WorkerEvent::UpdateInstall(failure) => {
                let UpdateDownload::Installing(update) = &self.updates.download else {
                    return;
                };
                self.updates.download = match failure {
                    None => {
                        #[cfg(any(target_os = "linux", target_os = "macos", test))]
                        {
                            self.updates.installed = true;
                        }
                        UpdateDownload::Idle
                    }
                    // Declining the prompt changes nothing; the file stays checked.
                    Some(UpdateFailure::Declined) => UpdateDownload::Ready(update.clone()),
                    Some(failure) => UpdateDownload::Failed {
                        version: update.version.clone(),
                        failure,
                    },
                };
            }
            _ => unreachable!("only update download events are reduced here"),
        }
    }

    fn start_install(&mut self) -> Option<Job> {
        let UpdateDownload::Ready(update) = self.offer_download() else {
            return None;
        };
        let update = update.clone();
        self.updates.download = UpdateDownload::Installing(update.clone());
        Some(Job::InstallUpdate(update))
    }

    pub(crate) fn available_update(&self) -> Option<&Release> {
        self.updates.newest_release.as_ref().filter(|release| {
            self.config.interface.skipped_version.as_deref() != Some(release.version.as_str())
        })
    }

    /// The offer found before a restart, kept while it is still newer than
    /// this build; an older record (Rosetun was updated since) reads as none.
    pub(super) fn restore_found_update(&mut self) {
        self.updates.newest_release = self
            .config
            .interface
            .newest_release
            .as_deref()
            .and_then(|version| remembered_release(version, env!("CARGO_PKG_VERSION")));
    }

    pub(super) fn update_check_due(&self, now: u64) -> Option<u64> {
        if !self.config_ready
            || !self.config.interface.check_updates
            || self.updates.update_check_pending
        {
            return None;
        }
        let due = match self.config.interface.last_update_check {
            Some(last) if last <= now => last.saturating_add(UPDATE_CHECK_INTERVAL),
            _ => now,
        };
        Some(due.max(self.updates.next_update_check.unwrap_or(0)))
    }

    pub(crate) fn take_update_check(&mut self, now: u64) -> Option<Job> {
        if now < self.update_check_due(now)? {
            return None;
        }
        if !self.can_check_updates() {
            self.updates.next_update_check = Some(now.saturating_add(UPDATE_CHECK_DEFER));
            return None;
        }
        self.updates.update_check_pending = true;
        Some(Job::CheckUpdates)
    }

    pub(super) fn finish_update_check(
        &mut self,
        result: Result<Option<Release>, UpdateCheckError>,
        now: u64,
    ) {
        if !self.updates.update_check_pending {
            return;
        }
        self.updates.update_check_pending = false;
        match result {
            Ok(release) => {
                self.config.interface.last_update_check = Some(now);
                self.updates.next_update_check = None;
                self.updates.update_check_failed = false;
                self.updates.newest_release =
                    release.filter(|release| is_newer(&release.version, env!("CARGO_PKG_VERSION")));
                self.config.interface.newest_release = self
                    .updates
                    .newest_release
                    .as_ref()
                    .map(|release| release.version.clone());
            }
            Err(_) => {
                self.updates.next_update_check = Some(now.saturating_add(UPDATE_CHECK_RETRY));
                self.updates.update_check_failed = true;
            }
        }
    }

    pub(super) fn reduce_updates(
        &mut self,
        result: Result<Option<Release>, UpdateCheckError>,
        checked_at: u64,
    ) {
        self.finish_update_check(result, checked_at);
    }

    pub(super) fn act_updates(&mut self, action: Action) -> Option<Job> {
        let action = self.defer_setting(action)?;
        match action {
            Action::CheckUpdatesNow => {
                if self.can_check_updates() {
                    self.updates.update_check_pending = true;
                    return Some(Job::CheckUpdates);
                }
            }
            Action::DownloadUpdate => {
                let busy = matches!(
                    self.offer_download(),
                    UpdateDownload::Downloading { .. } | UpdateDownload::Installing(_)
                );
                if Self::can_install_updates()
                    && self.config_ready
                    && !busy
                    && let Some(release) = self.available_update()
                {
                    let version = release.version.clone();
                    self.updates.cancel = Arc::new(AtomicBool::new(false));
                    self.updates.download = UpdateDownload::Downloading {
                        version: version.clone(),
                        received: 0,
                        total: None,
                    };
                    return Some(Job::DownloadUpdate {
                        version,
                        via_vpn: self.config.interface.subscriptions_via_vpn,
                        cancel: Arc::clone(&self.updates.cancel),
                    });
                }
            }
            Action::CancelUpdateDownload => {
                if matches!(self.updates.download, UpdateDownload::Downloading { .. }) {
                    self.updates.cancel.store(true, Ordering::Relaxed);
                }
            }
            Action::InstallUpdate => {
                if matches!(self.offer_download(), UpdateDownload::Ready(_)) {
                    if self.session_up() {
                        self.updates.confirm_install = true;
                    } else {
                        return self.start_install();
                    }
                }
            }
            Action::ConfirmInstallUpdate(confirmed) => {
                if !self.updates.confirm_install {
                    return None;
                }
                self.updates.confirm_install = false;
                if confirmed {
                    return self.start_install();
                }
            }
            Action::SkipVersion => {
                if self.can_edit_settings()
                    && let Some(release) = self.available_update()
                {
                    return self.start_settings(Job::SkipVersion(release.version.clone()));
                }
            }
            #[cfg(any(windows, target_os = "linux", test))]
            Action::AnnounceUpdate(version) => {
                if self.config_ready
                    && self.config.interface.announced_update.as_deref() != Some(version.as_str())
                {
                    self.config.interface.announced_update = Some(version.clone());
                    return self.start_settings(Job::AnnounceUpdate(version));
                }
            }
            _ => unreachable!("only update actions are dispatched here"),
        }
        None
    }
}
