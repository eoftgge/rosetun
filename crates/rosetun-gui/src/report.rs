use std::fmt::Write;

use rosetun_config::{
    AppConfig, ConnectionState, EngineKind, FailureKind, LanguageSetting, Status, XrayUse,
    redact_report_text,
};
use rosetun_core::{CheckKind, CheckResult, CheckStatus, DnsPreset};

use crate::i18n::{self, Language};

pub(crate) struct ReportSnapshot {
    kill_switch: bool,
    lockdown: Option<bool>,
    allow_lan: bool,
    xray_mode: XrayUse,
    dns_preset: Option<DnsPreset>,
    verbose_log: bool,
    language: LanguageSetting,
    subscriptions: usize,
    nodes: usize,
    rules: usize,
    lists: usize,
    sensitive_names: Vec<String>,
    state: ConnectionStateKind,
    failure: Option<FailureKind>,
    engine: EngineKind,
    xray: bool,
    pub(crate) checks: Option<Vec<(CheckKind, CheckStatus)>>,
    pub(crate) helper_version: Option<String>,
    pub(crate) language_for_report: Language,
}

#[derive(Clone, Copy)]
enum ConnectionStateKind {
    Disconnected,
    Unavailable,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
    FailedProtected,
}

impl ReportSnapshot {
    pub(crate) fn new(
        config: &AppConfig,
        status: &Status,
        helper_available: bool,
        checks: Option<&[CheckResult]>,
        helper_version: Option<&str>,
        language_for_report: Language,
        now: u64,
    ) -> Self {
        let (state, failure) = match &status.state {
            ConnectionState::Disconnected => (ConnectionStateKind::Disconnected, None),
            ConnectionState::Connecting => (ConnectionStateKind::Connecting, None),
            ConnectionState::Connected => (ConnectionStateKind::Connected, None),
            ConnectionState::Reconnecting => (
                ConnectionStateKind::Reconnecting,
                status.reconnect_failure_kind,
            ),
            ConnectionState::Failed { failure_kind, .. } => {
                (ConnectionStateKind::Failed, *failure_kind)
            }
            ConnectionState::FailedProtected { failure_kind, .. } => {
                (ConnectionStateKind::FailedProtected, *failure_kind)
            }
        };
        let (state, failure) = if helper_available {
            (state, failure)
        } else {
            (ConnectionStateKind::Unavailable, None)
        };
        let mut sensitive_names: Vec<String> = config
            .subscriptions
            .iter()
            .flat_map(|subscription| {
                std::iter::once(subscription.name.clone())
                    .chain(subscription.nodes.iter().map(|node| node.name.clone()))
            })
            .chain(config.lists.iter().map(|list| list.name.clone()))
            .chain(config.rule_sets.iter().map(|set| set.name.clone()))
            .filter(|name| name.chars().count() >= 3)
            .collect();
        sensitive_names.sort_by_key(|name| std::cmp::Reverse(name.chars().count()));
        Self {
            kill_switch: config.settings.kill_switch,
            lockdown: helper_available.then_some(status.lockdown),
            allow_lan: config.settings.allow_lan,
            xray_mode: config.settings.xray,
            dns_preset: DnsPreset::matching(&config.settings.dns),
            verbose_log: config.settings.verbose_log_active(now),
            language: config.interface.language,
            subscriptions: config.subscriptions.len(),
            nodes: config
                .subscriptions
                .iter()
                .map(|item| item.nodes.len())
                .sum(),
            rules: config.rule_sets.iter().map(|set| set.rules.len()).sum(),
            lists: config.lists.len(),
            sensitive_names,
            state,
            failure,
            engine: status.engine.unwrap_or(config.settings.engine),
            xray: helper_available && status.xray,
            checks: checks.map(check_statuses),
            helper_version: helper_version.map(str::to_owned),
            language_for_report,
        }
    }

    pub(crate) fn set_checks(&mut self, checks: &[CheckResult]) {
        self.checks = Some(check_statuses(checks));
    }

    fn scrub_names(&self, text: &str) -> String {
        let mut text = redact_report_text(text);
        for name in &self.sensitive_names {
            text = redact_whole_name(&text, name);
        }
        text
    }

    pub(crate) fn render(
        &self,
        windows_build: Option<u32>,
        engine_versions: (Option<&str>, Option<&str>),
        client_log: &str,
        helper_log: &str,
    ) -> String {
        let lang = self.language_for_report;
        macro_rules! report_label {
            ($key:literal) => {
                i18n::tr_in(lang, $key, &fluent_bundle::FluentArgs::new())
            };
        }
        let missing = report_label!("report-unavailable");
        let mut text = String::new();
        let _ = writeln!(text, "[{}]", report_label!("report-versions"));
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("report-program"),
            env!("CARGO_PKG_VERSION")
        );
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("report-service"),
            self.helper_version.as_deref().unwrap_or(&missing)
        );
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("report-protocol"),
            rosetun_ipc::PROTOCOL_VERSION
        );
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("report-windows-build"),
            windows_build.map_or_else(|| missing.clone(), |value| value.to_string())
        );
        let _ = writeln!(text, "sing-box: {}", engine_versions.0.unwrap_or(&missing));
        let _ = writeln!(text, "Xray: {}", engine_versions.1.unwrap_or(&missing));

        let switch = |enabled| {
            if enabled {
                report_label!("report-on")
            } else {
                report_label!("report-off")
            }
        };
        let _ = writeln!(text, "\n[{}]", report_label!("report-settings"));
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("kill-switch"),
            switch(self.kill_switch)
        );
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("lockdown"),
            self.lockdown.map_or_else(|| missing.clone(), switch)
        );
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("allow-lan"),
            switch(self.allow_lan)
        );
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("xray-title"),
            match self.xray_mode {
                XrayUse::Auto => report_label!("xray-auto"),
                XrayUse::Off => report_label!("xray-off"),
                XrayUse::Always => report_label!("xray-always"),
            }
        );
        let dns = match self.dns_preset {
            Some(DnsPreset::Cloudflare) => "Cloudflare".to_owned(),
            Some(DnsPreset::Google) => "Google".to_owned(),
            Some(DnsPreset::Quad9) => "Quad9".to_owned(),
            None => format!("{} (<url>)", report_label!("dns-custom")),
        };
        let _ = writeln!(text, "DNS: {dns}");
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("verbose-log"),
            switch(self.verbose_log)
        );
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("language-title"),
            match self.language {
                LanguageSetting::System => report_label!("language-system"),
                LanguageSetting::English => report_label!("language-english"),
                LanguageSetting::Russian => report_label!("language-russian"),
            }
        );
        for (title, count) in [
            (report_label!("report-subscriptions"), self.subscriptions),
            (report_label!("report-nodes"), self.nodes),
            (report_label!("report-rules"), self.rules),
            (report_label!("report-lists"), self.lists),
        ] {
            let _ = writeln!(text, "{title}: {count}");
        }

        let _ = writeln!(text, "\n[{}]", report_label!("report-connection"));
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("report-state"),
            match self.state {
                ConnectionStateKind::Disconnected => report_label!("report-state-disconnected"),
                ConnectionStateKind::Unavailable => report_label!("report-unavailable"),
                ConnectionStateKind::Connecting => report_label!("report-state-connecting"),
                ConnectionStateKind::Connected => report_label!("report-state-connected"),
                ConnectionStateKind::Reconnecting => report_label!("report-state-reconnecting"),
                ConnectionStateKind::Failed => report_label!("report-state-failed"),
                ConnectionStateKind::FailedProtected =>
                    report_label!("report-state-failed-protected"),
            }
        );
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("report-failure"),
            self.failure.map_or_else(
                || missing.clone(),
                |kind| {
                    match kind {
                        FailureKind::EngineNotReady => report_label!("report-failure-engine"),
                        FailureKind::XrayStartFailed => report_label!("report-failure-xray-start"),
                        FailureKind::XrayStopped => report_label!("report-failure-xray-stopped"),
                        FailureKind::NoNetwork => report_label!("report-failure-no-network"),
                        FailureKind::ServerUnreachable => {
                            report_label!("report-failure-unreachable")
                        }
                        FailureKind::ServerRejected => report_label!("report-failure-rejected"),
                        FailureKind::ServerClosed => report_label!("report-failure-closed"),
                        FailureKind::DnsTimeout => report_label!("report-failure-dns"),
                    }
                }
            )
        );
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("report-engine"),
            self.engine.as_str()
        );
        let _ = writeln!(
            text,
            "{}: {}",
            report_label!("report-through-xray"),
            switch(self.xray)
        );

        let _ = writeln!(text, "\n[{}]", report_label!("system-check-title"));
        if let Some(checks) = &self.checks {
            for (kind, status) in checks {
                let title = match kind {
                    CheckKind::Clock => report_label!("system-check-clock"),
                    CheckKind::Proxy => report_label!("system-check-proxy"),
                    CheckKind::PacketInterceptor => report_label!("system-check-packet"),
                    CheckKind::OtherVpn => report_label!("system-check-vpn"),
                };
                let result = match status {
                    CheckStatus::Ok => report_label!("system-check-ok"),
                    CheckStatus::Warning => report_label!("report-warning"),
                    CheckStatus::Unavailable => report_label!("system-check-unavailable"),
                };
                let _ = writeln!(text, "{title}: {result}");
            }
        } else {
            let _ = writeln!(text, "{}", missing);
        }

        let _ = writeln!(text, "\n[{}]", report_label!("report-client-log"));
        let _ = writeln!(text, "{}", self.scrub_names(client_log));
        let _ = writeln!(text, "[{}]", report_label!("report-helper-log"));
        let _ = writeln!(text, "{}", self.scrub_names(helper_log));
        redact_report_text(&text)
    }
}

fn redact_whole_name(text: &str, name: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut copied = 0;
    for (start, _) in text.match_indices(name) {
        let end = start + name.len();
        let boundary = |ch: Option<char>| ch.is_none_or(|ch| !ch.is_alphanumeric() && ch != '_');
        if boundary(text[..start].chars().next_back()) && boundary(text[end..].chars().next()) {
            result.push_str(&text[copied..start]);
            result.push_str("<redacted>");
            copied = end;
        }
    }
    result.push_str(&text[copied..]);
    result
}

fn check_statuses(checks: &[CheckResult]) -> Vec<(CheckKind, CheckStatus)> {
    checks
        .iter()
        .map(|result| (result.kind, result.status))
        .collect()
}

#[cfg(test)]
mod tests {
    use rosetun_config::{
        Node, NodeId, Outbound, RuleSet, RuleSetId, RuleTarget, Subscription, SubscriptionId,
    };

    use super::*;

    #[test]
    fn report_without_helper_contains_unavailable_marker() {
        let snapshot = ReportSnapshot::new(
            &AppConfig::default(),
            &Status::default(),
            false,
            None,
            None,
            Language::Russian,
            0,
        );
        let report = snapshot.render(None, (None, None), "", "служба недоступна");
        assert!(report.contains("[Журнал службы]\nслужба недоступна"));
        assert!(report.contains("[Версии]"));
        assert!(report.contains("Lockdown: Недоступно\n"));
    }

    #[test]
    fn check_results_and_failure_kind_do_not_include_sensitive_details() {
        let mut config = AppConfig::default();
        config.settings.dns.server_name = "custom.example.com".to_owned();
        let status = Status {
            state: ConnectionState::Failed {
                reason: "could not reach 192.0.2.10".to_owned(),
                failure_kind: Some(FailureKind::ServerUnreachable),
            },
            lockdown: true,
            ..Status::default()
        };
        let checks = [CheckResult {
            kind: CheckKind::Proxy,
            status: CheckStatus::Warning,
            detail: rosetun_core::CheckDetail::Proxy {
                server: Some("https://proxy.example.com/account".to_owned()),
                auto_config: None,
            },
        }];
        let snapshot = ReportSnapshot::new(
            &config,
            &status,
            true,
            Some(&checks),
            Some("0.2.0-alpha.3"),
            Language::English,
            0,
        );
        let report = snapshot.render(Some(26300), (Some("1.14.1"), Some("26.10.10")), "", "");
        assert!(report.contains("ServerUnreachable"));
        assert!(report.contains("System proxy: Warning"));
        assert!(report.contains("Windows build: 26300"));
        assert!(report.contains("Lockdown: On\n"));
        assert!(report.contains("DNS: Custom (<url>)"));
        assert!(!report.contains("192.0.2.10"));
        assert!(!report.contains("proxy.example.com"));
    }

    #[test]
    fn replaces_only_whole_names() {
        assert_eq!(
            redact_whole_name(
                "Amsterdam Amsterdamer _Amsterdam Amsterdam_\nAmsterdam",
                "Amsterdam"
            ),
            "<redacted> Amsterdamer _Amsterdam Amsterdam_\n<redacted>"
        );
    }

    #[test]
    fn report_never_includes_node_subscription_or_windows_account() {
        let mut config = AppConfig::default();
        config.subscriptions.push(Subscription {
            id: SubscriptionId::new("test-subscription"),
            name: "Secret provider".to_owned(),
            url: "https://panel.example.com/subscription?token=credential_marker".to_owned(),
            nodes: vec![Node {
                id: NodeId::new("test-node"),
                name: "Private node".to_owned(),
                server: "203.0.113.12".to_owned(),
                port: 443,
                outbound: Outbound::Unknown {
                    scheme: "test".to_owned(),
                    params: Default::default(),
                },
                stream: Default::default(),
                raw: None,
            }],
            auto_update: false,
            updated_at_unix: None,
            user_agent: None,
            send_hwid: false,
            info: None,
            update_interval_hours: None,
            support_url: None,
            web_page_url: None,
            announce: None,
            notices: Vec::new(),
        });
        let example = config.subscriptions[0].nodes[0].clone();
        for name in ["1", "DE", "NL", "Amsterdam 3", "Amsterdam", "Server NL 2"] {
            let mut node = example.clone();
            node.id = NodeId::new(name);
            node.name = name.to_owned();
            config.subscriptions[0].nodes.push(node);
        }
        config.rule_sets.push(RuleSet::new(
            RuleSetId::new("server"),
            "Server",
            RuleTarget::Proxy,
        ));
        config.settings.dns.server_name = "custom.example.com".to_owned();
        let snapshot = ReportSnapshot::new(
            &config,
            &Status::default(),
            false,
            None,
            None,
            Language::English,
            0,
        );
        let text = snapshot.render(
            None,
            (None, None),
            "WARN Private node at 203.0.113.12 failed; C:\\Users\\ExampleUser\\AppData",
            "TRACE Secret provider visited www.example.com password=credential_marker\n2026-10-15T15:02:03Z ErrorCode::DnsTimeout 1 DE NL Amsterdam 3 Amsterdamer Server NL 2 Default",
        );
        for private in [
            "203.0.113.12",
            "panel.example.com",
            "Secret provider",
            "Private node",
            "ExampleUser",
            "www.example.com",
            "credential_marker",
        ] {
            assert!(!text.contains(private), "private value leaked: {private}");
        }
        assert!(text.contains("<ip>"));
        assert!(text.contains("C:\\Users\\<user>"));
        assert!(text.contains("Subscriptions: 1"));
        assert!(text.contains("Nodes: 7"));
        assert!(text.contains(
            "2026-10-15T15:02:03Z ErrorCode::DnsTimeout 1 DE NL <redacted> Amsterdamer <redacted> Default"
        ));
        assert!(!text.contains("<redacted> NL 2"));
    }
}
