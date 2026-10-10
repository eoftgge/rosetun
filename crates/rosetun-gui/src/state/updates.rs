use rosetun_config::ConnectionState;
use rosetun_core::{Release, UpdateCheckError, is_newer};

use super::{Action, Job, State};

const UPDATE_CHECK_DEFER: u64 = 60;
pub(super) const UPDATE_CHECK_INTERVAL: u64 = 24 * 60 * 60;
pub(super) const UPDATE_CHECK_RETRY: u64 = 6 * 60 * 60;

#[derive(Default)]
pub(crate) struct UpdatesState {
    pub(super) next_update_check: Option<u64>,
    pub(crate) update_check_pending: bool,
    pub(crate) update_check_failed: bool,
    pub(crate) newest_release: Option<Release>,
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

    pub(crate) fn available_update(&self) -> Option<&Release> {
        self.updates.newest_release.as_ref().filter(|release| {
            self.config.interface.skipped_version.as_deref() != Some(release.version.as_str())
        })
    }

    pub(crate) fn take_update_check(&mut self, now: u64) -> Option<Job> {
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
        if now < due.max(self.updates.next_update_check.unwrap_or(0)) {
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
        match action {
            Action::CheckUpdatesNow => {
                if self.can_check_updates() {
                    self.updates.update_check_pending = true;
                    return Some(Job::CheckUpdates);
                }
            }
            Action::SkipVersion => {
                if self.can_edit_settings()
                    && let Some(release) = self.available_update()
                {
                    return self.start_settings(Job::SkipVersion(release.version.clone()));
                }
            }
            _ => unreachable!("only update actions are dispatched here"),
        }
        None
    }
}
