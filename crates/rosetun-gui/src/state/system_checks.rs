use rosetun_config::ConnectionState;
use rosetun_core::{CheckResult, CheckStatus};

use super::{Action, Job, Screen, State, now_unix};

#[derive(Default)]
pub(crate) struct SystemChecksState {
    pub(crate) results: Option<Vec<CheckResult>>,
    pub(crate) checked_at: Option<u64>,
    pub(crate) checking: bool,
    pub(crate) failure_warning: Option<CheckResult>,
    request: u64,
    failure_request: Option<u64>,
    auto_checked: bool,
}

impl State {
    pub(super) fn reset_system_failure(&mut self) {
        let checks = &mut self.system_checks;
        checks.failure_warning = None;
        checks.auto_checked = false;
        checks.failure_request = None;
        checks.checking = false;
        checks.request = checks.request.wrapping_add(1);
    }

    pub(crate) fn take_system_check(&mut self) -> Option<Job> {
        let checks = &mut self.system_checks;
        if !self.status_received
            || !self.helper_available
            || checks.checking
            || checks.auto_checked
            || !failed(&self.status.state)
        {
            return None;
        }
        checks.auto_checked = true;
        checks.checking = true;
        checks.request = checks.request.wrapping_add(1);
        checks.failure_request = Some(checks.request);
        Some(Job::CheckSystem {
            request: checks.request,
            own_alias: self.config.settings.tun.name.clone(),
        })
    }

    pub(super) fn act_system_checks(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::CheckSystem => {
                let checks = &mut self.system_checks;
                if checks.checking {
                    return None;
                }
                checks.checking = true;
                checks.request = checks.request.wrapping_add(1);
                checks.failure_request = failed(&self.status.state).then_some(checks.request);
                if checks.failure_request.is_some() {
                    checks.auto_checked = true;
                }
                Some(Job::CheckSystem {
                    request: checks.request,
                    own_alias: self.config.settings.tun.name.clone(),
                })
            }
            Action::ShowSystemChecks => {
                let job = self.act_settings(Action::OpenSettings);
                self.settings.screen.section = super::SettingsSection::Service;
                self.screen = Screen::Settings;
                job
            }
            _ => None,
        }
    }

    pub(super) fn reduce_system_checks(&mut self, request: u64, results: Vec<CheckResult>) {
        let checks = &mut self.system_checks;
        if !checks.checking || request != checks.request {
            return;
        }
        checks.checking = false;
        checks.checked_at = Some(now_unix());
        if checks.failure_request == Some(request) && failed(&self.status.state) {
            checks.failure_warning = results
                .iter()
                .find(|result| result.status == CheckStatus::Warning)
                .cloned();
        }
        checks.failure_request = None;
        checks.results = Some(results);
    }
}

fn failed(state: &ConnectionState) -> bool {
    matches!(
        state,
        ConnectionState::Failed { .. } | ConnectionState::FailedProtected { .. }
    )
}
