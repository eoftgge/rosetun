use rosetun_core::{CheckDetail, CheckKind, CheckResult, CheckStatus};

use crate::display;

fn names(values: &[String]) -> String {
    values
        .iter()
        .map(|name| display::safe_text(name))
        .collect::<Vec<_>>()
        .join(&tr!("system-check-separator"))
}

pub(crate) fn check_issue(result: &CheckResult) -> String {
    match &result.detail {
        CheckDetail::Clock { minutes, ahead } => {
            if *ahead {
                tr!(
                    "system-check-clock-ahead",
                    count = *minutes,
                    n = minutes.to_string()
                )
            } else {
                tr!(
                    "system-check-clock-behind",
                    count = *minutes,
                    n = minutes.to_string()
                )
            }
        }
        CheckDetail::Proxy {
            server,
            auto_config,
        } => {
            let mut parts = Vec::new();
            if let Some(server) = server {
                parts.push(tr!(
                    "system-check-proxy-manual",
                    address = display::safe_text(server)
                ));
            }
            if let Some(url) = auto_config {
                parts.push(tr!(
                    "system-check-proxy-auto",
                    address = display::safe_text(url)
                ));
            }
            parts.join(&tr!("system-check-separator"))
        }
        CheckDetail::PacketInterceptor { processes, driver } => {
            let mut parts = processes
                .iter()
                .map(|name| display::safe_text(name))
                .collect::<Vec<_>>();
            if *driver {
                parts.push(tr!("system-check-windivert"));
            }
            tr!(
                "system-check-packet-found",
                names = parts.join(&tr!("system-check-separator"))
            )
        }
        CheckDetail::OtherVpn {
            processes,
            adapters,
        } => {
            let mut parts = Vec::new();
            if !processes.is_empty() {
                parts.push(names(processes));
            }
            if !adapters.is_empty() {
                parts.push(names(adapters));
            }
            tr!(
                "system-check-vpn-found",
                names = parts.join(&tr!("system-check-separator"))
            )
        }
        CheckDetail::DnsSubstitution { server } => tr!(
            "system-check-dns-found",
            server = display::safe_text(server)
        ),
        CheckDetail::None => tr!("system-check-unavailable"),
    }
}

pub(crate) fn check_detail(result: &CheckResult) -> String {
    match result.status {
        CheckStatus::Ok if result.kind == CheckKind::DnsSubstitution => tr!("system-check-dns-ok"),
        CheckStatus::Ok => tr!("system-check-ok"),
        CheckStatus::Unavailable => tr!("system-check-unavailable"),
        CheckStatus::Skipped => tr!("system-check-offline-only"),
        CheckStatus::Warning => {
            let advice = match result.kind {
                CheckKind::Clock => tr!("system-check-clock-advice"),
                CheckKind::Proxy => tr!("system-check-proxy-advice"),
                CheckKind::PacketInterceptor => tr!("system-check-packet-advice"),
                CheckKind::OtherVpn => tr!("system-check-vpn-advice"),
                // One sentence with its own advice.
                CheckKind::DnsSubstitution => return check_issue(result),
            };
            tr!(
                "system-check-with-advice",
                issue = check_issue(result),
                advice = advice
            )
        }
    }
}
