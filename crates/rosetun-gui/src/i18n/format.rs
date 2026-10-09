use fluent_bundle::FluentArgs;
use rosetun_config::{ConnectStage, FailureKind, RuleTemplate};

use super::{Language, tr_in};

pub(crate) fn about_version(app: &str, helper: Option<&str>) -> String {
    match helper {
        Some(helper) => tr!("about-version-with-helper", app = app, helper = helper),
        None => tr!("about-version-without-helper", app = app),
    }
}

pub(crate) fn update_available(version: &str) -> String {
    tr!("update-available", version = version)
}

pub(crate) fn update_skipped(version: &str) -> String {
    tr!("update-skipped", version = version)
}

pub(crate) fn update_checked(age: &str) -> String {
    tr!("update-checked", age = age)
}

pub(crate) fn update_last_checked(age: &str) -> String {
    tr!("update-last-checked", age = age)
}

pub(crate) fn update_skipped_detail(age: &str) -> String {
    tr!("update-skipped-detail", age = age)
}

pub(crate) fn template_name(template: RuleTemplate) -> String {
    match template {
        RuleTemplate::RussianSites => tr!("russian-sites-name"),
        RuleTemplate::Messengers => tr!("messengers-name"),
        RuleTemplate::Youtube => tr!("youtube-name"),
        RuleTemplate::Torrents => tr!("torrents-name"),
    }
}

pub(crate) fn template_description(template: RuleTemplate) -> String {
    match template {
        RuleTemplate::RussianSites => tr!("russian-sites-description"),
        RuleTemplate::Messengers => tr!("messengers-description"),
        RuleTemplate::Youtube => tr!("youtube-description"),
        RuleTemplate::Torrents => tr!("torrents-description"),
    }
}

pub(crate) fn connected_in(code: &str) -> String {
    tr!("connected-in-template", code = code)
}

pub(crate) fn all_processes(count: usize) -> String {
    tr!("all-processes", n = count.to_string())
}

pub(crate) fn found(count: usize) -> String {
    tr!("found", n = count.to_string())
}

pub(crate) fn line_error(line: usize, error: &str) -> String {
    tr!("line-error", n = line.to_string(), error = error)
}

pub(crate) fn more_errors(count: usize) -> String {
    tr!("more-errors", k = count.to_string())
}

pub(crate) fn selected_rule_count(count: usize) -> String {
    tr!("selected-rule-count", n = count.to_string())
}

pub(crate) fn delete_selected_rules(count: usize) -> String {
    tr!("delete-selected-rules", n = count.to_string())
}

pub(crate) fn delete_rules_heading(count: usize) -> String {
    let rules = tr!("rule-count", count = count, n = count.to_string());
    tr!("delete-rules-heading", n = count.to_string(), rules = rules)
}

pub(crate) fn and_more_rules(count: usize) -> String {
    tr!("and-more-rules", k = count.to_string())
}

pub(crate) fn add_rules(count: usize) -> String {
    tr!("add-rules", count = count, n = count.to_string())
}

pub(crate) fn stored_as(ascii: &str) -> String {
    tr!("stored-as", ascii = ascii)
}

pub(crate) fn engine_detail(engine: &str) -> String {
    format!("{}: {engine}", tr!("engine"))
}

pub(crate) fn servers(count: usize) -> String {
    tr!("servers", count = count, n = count.to_string())
}

pub(crate) fn last_updated(age: &str) -> String {
    tr!("last-updated-template", age = age)
}

pub(crate) fn traffic_rates(down: &str, up: &str) -> String {
    tr!("traffic-rates-template", down = down, up = up)
}

pub(crate) fn traffic_chart_caption(range: &str, peak: &str) -> String {
    tr!("traffic-chart-caption-template", range = range, peak = peak)
}

pub(crate) fn temporary_count(count: usize) -> String {
    tr!("temporary-count", n = count.to_string())
}

pub(crate) fn more_rules(count: usize) -> String {
    tr!("more-rules", n = count.to_string())
}

pub(crate) fn switching_to(name: &str) -> String {
    tr!("switching-to", name = name)
}

pub(crate) fn selected_not_applied(name: &str) -> String {
    tr!("selected-not-applied", name = name)
}

pub(crate) fn apply_failed(reason: &str) -> String {
    tr!("apply-failed", reason = reason)
}

pub(crate) fn selected_pending(name: &str) -> String {
    tr!("selected-pending", name = name)
}

pub(crate) fn updated(added: usize, removed: usize, retained: usize) -> String {
    tr!(
        "updated-summary",
        added = added.to_string(),
        removed = removed.to_string(),
        retained = retained.to_string()
    )
}

pub(crate) fn skipped(count: usize, reason: &str) -> String {
    tr!(
        "skipped-summary",
        count = count.to_string(),
        reason = reason
    )
}

pub(crate) fn helper_version(version: &str) -> String {
    tr!("helper-version", version = version)
}

pub(crate) fn verbose_log_on_detail(hours: u64) -> String {
    let hours = tr!("verbose-hours", count = hours, n = hours.to_string());
    tr!("verbose-log-on-detail", hours = hours)
}

pub(crate) fn updated_ago(timestamp: u64, now: u64) -> String {
    updated_ago_in(super::language(), timestamp, now)
}

pub(crate) fn updated_ago_in(language: Language, timestamp: u64, now: u64) -> String {
    let elapsed = now.saturating_sub(timestamp);
    let (unit, count) = match elapsed {
        0..60 => return tr_in(language, "updated-ago-just-now", &FluentArgs::new()),
        60..3600 => (0, elapsed / 60),
        3600..86400 => (1, elapsed / 3600),
        _ => (2, elapsed / 86400),
    };
    let mut args = FluentArgs::new();
    args.set("count", count);
    args.set("n", count.to_string());
    match unit {
        0 => tr_in(language, "updated-ago-minute", &args),
        1 => tr_in(language, "updated-ago-hour", &args),
        _ => tr_in(language, "updated-ago-day", &args),
    }
}

pub(crate) fn term_left(expire: u64, now: u64) -> (String, bool) {
    if expire <= now {
        return (tr!("term-expired"), true);
    }
    let days = (expire - now) / 86_400;
    if days == 0 {
        return (tr!("term-under-day"), false);
    }
    let unit = tr!("term-day-unit", count = days);
    (
        tr!("term-left-template", days = days.to_string(), unit = unit),
        false,
    )
}

pub(crate) fn bytes(value: u64) -> String {
    let mut amount = value as f64;
    let mut unit = 0;
    while amount >= 1000.0 && unit < 4 {
        amount /= 1024.0;
        unit += 1;
    }
    let number = if unit == 0 || amount >= 100.0 {
        format!("{amount:.0}")
    } else if amount >= 10.0 {
        format!("{amount:.1}")
    } else {
        format!("{amount:.2}")
    };
    let number = if super::language() == super::Language::Russian {
        number.replace('.', ",")
    } else {
        number
    };
    let label = match unit {
        0 => tr!("bytes-unit-b"),
        1 => tr!("bytes-unit-kib"),
        2 => tr!("bytes-unit-mib"),
        3 => tr!("bytes-unit-gib"),
        _ => tr!("bytes-unit-tib"),
    };
    format!("{number} {label}")
}

pub(crate) fn rate(bytes_per_second: u64) -> String {
    tr!("rate-format", bytes = bytes(bytes_per_second))
}

pub(crate) fn connection_stage(stage: ConnectStage, seconds: u64) -> String {
    let label = match stage {
        ConnectStage::WaitingForAdapter => tr!("stage-waiting"),
        ConnectStage::StartingEngine => tr!("stage-starting"),
        ConnectStage::CheckingServer => tr!("stage-checking"),
    };
    tr!(
        "stage-elapsed",
        stage = label,
        seconds = seconds.to_string()
    )
}

pub(crate) fn connection_failure(kind: FailureKind) -> (String, String) {
    let (title, hint) = match kind {
        FailureKind::EngineNotReady => (
            tr!("error-code-engine-not-ready"),
            tr!(
                "engine-not-ready-hint",
                retry = tr!("retry"),
                url_test = tr!("check-full")
            ),
        ),
        FailureKind::ServerUnreachable => (
            tr!("error-code-server-unreachable"),
            tr!(
                "server-unreachable-hint",
                retry = tr!("retry"),
                url_test = tr!("check-full")
            ),
        ),
        FailureKind::ServerRejected => (
            tr!("error-code-server-rejected"),
            tr!(
                "server-rejected-hint",
                retry = tr!("retry"),
                url_test = tr!("check-full")
            ),
        ),
        FailureKind::ServerClosed => (
            tr!("error-code-server-closed"),
            tr!(
                "server-closed-hint",
                retry = tr!("retry"),
                url_test = tr!("check-full")
            ),
        ),
        FailureKind::DnsTimeout => (
            tr!("error-code-dns-timeout"),
            tr!(
                "dns-timeout-hint",
                retry = tr!("retry"),
                url_test = tr!("check-full")
            ),
        ),
    };
    (title, hint)
}

pub(crate) fn other_vpn(name: &str) -> String {
    tr!("other-vpn-hint", name = name, retry = tr!("retry"))
}

pub(crate) fn traffic_tool(name: &str) -> String {
    tr!("traffic-tool-hint", name = name)
}
