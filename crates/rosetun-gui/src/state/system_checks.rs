use rosetun_config::{ConnectionState, FailureKind};
use rosetun_core::{CheckKind, CheckResult, CheckStatus};

use super::{Action, Job, Screen, State, now_unix};

#[derive(Default)]
pub(crate) struct SystemChecksState {
    pub(crate) results: Option<Vec<CheckResult>>,
    pub(crate) checked_at: Option<u64>,
    pub(crate) checking: bool,
    pub(crate) failure_warning: Option<CheckResult>,
    /// The last DNS substitution check that actually ran, kept while later
    /// checks skip it under a tunnel.
    pub(crate) last_dns: Option<CheckResult>,
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
            guarded: self.traffic_guarded(),
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
                    guarded: self.traffic_guarded(),
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
            // A replaced DNS does not explain a failure that came after
            // the server's address was found.
            checks.failure_warning = results
                .iter()
                .find(|result| {
                    result.status == CheckStatus::Warning
                        && result.kind != CheckKind::DnsSubstitution
                })
                .cloned();
        }
        checks.failure_request = None;
        if let Some(dns) = results.iter().find(|result| {
            result.kind == CheckKind::DnsSubstitution && result.status != CheckStatus::Skipped
        }) {
            checks.last_dns = Some(dns.clone());
        }
        checks.results = Some(results);
    }
}

impl State {
    /// A tunnel or the kill switch holds the traffic, so a DNS check would
    /// test the tunnel or be blocked instead of testing the network.
    pub(crate) fn traffic_guarded(&self) -> bool {
        matches!(
            self.status.state,
            ConnectionState::Connecting
                | ConnectionState::Connected
                | ConnectionState::Reconnecting
                | ConnectionState::FailedProtected { .. }
        )
    }
}

/// A failure the system checks may explain. An unresolved server name is
/// not one: their findings (another VPN, a proxy) only mislead there.
fn failed(state: &ConnectionState) -> bool {
    match state {
        ConnectionState::Failed { failure_kind, .. }
        | ConnectionState::FailedProtected { failure_kind, .. } => {
            *failure_kind != Some(FailureKind::ServerNameUnresolved)
        }
        _ => false,
    }
}
