use rosetun_config::SubscriptionInfo;
use url::Url;

use crate::SubscriptionMeta;
use crate::common::{clean, decode_base64, percent_decode};

const KEYS: &[&str] = &[
    "content-disposition",
    "profile-title",
    "subscription-userinfo",
    "profile-update-interval",
    "support-url",
    "profile-web-page-url",
    "announce",
];

pub(crate) fn from_headers(header: &dyn Fn(&str) -> Option<String>) -> SubscriptionMeta {
    let mut meta = SubscriptionMeta::default();
    for key in KEYS {
        if let Some(value) = header(key) {
            apply(&mut meta, key, &value);
        }
    }
    meta
}

pub(crate) fn apply_comment(meta: &mut SubscriptionMeta, line: &str) {
    let Some((key, value)) = line.strip_prefix('#').and_then(|line| line.split_once(':')) else {
        return;
    };
    let key = key.trim().to_ascii_lowercase();
    if KEYS.contains(&key.as_str()) {
        apply(meta, &key, value.trim());
    }
}

pub(crate) fn display_text(value: &str, limit: usize) -> Option<String> {
    let value = value.trim();
    let decoded;
    let value = if let Some(encoded) = value.strip_prefix("base64:") {
        decoded = String::from_utf8(decode_base64(encoded)?).ok()?;
        decoded.as_str()
    } else {
        value
    };
    let value = clean(value, limit);
    (!value.is_empty()).then_some(value)
}

fn apply(meta: &mut SubscriptionMeta, key: &str, value: &str) {
    match key {
        "profile-title" => replace_if_some(&mut meta.title, display_text(value, 128)),
        "announce" => replace_if_some(&mut meta.announce, display_text(value, 1000)),
        "subscription-userinfo" => replace_if_some(&mut meta.info, userinfo(value)),
        "profile-update-interval" => {
            replace_if_some(&mut meta.update_interval_hours, value.trim().parse().ok());
        }
        "support-url" => replace_if_some(&mut meta.support_url, http_url(value)),
        "profile-web-page-url" => replace_if_some(&mut meta.web_page_url, http_url(value)),
        "content-disposition" if meta.title.is_none() => {
            replace_if_some(&mut meta.title, filename(value));
        }
        _ => {}
    }
}

fn replace_if_some<T>(target: &mut Option<T>, value: Option<T>) {
    if let Some(value) = value {
        *target = Some(value);
    }
}

fn userinfo(value: &str) -> Option<SubscriptionInfo> {
    let mut info = SubscriptionInfo::default();
    let mut recognized = false;

    for part in value.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let Ok(value) = value.trim().parse::<u64>() else {
            continue;
        };
        match key.trim() {
            "upload" => info.upload = value,
            "download" => info.download = value,
            "total" => info.total = (value != 0).then_some(value),
            "expire" => info.expire_unix = (value != 0).then_some(value),
            _ => continue,
        }
        recognized = true;
    }

    recognized.then_some(info)
}

fn http_url(value: &str) -> Option<String> {
    let value = clean(value, 2048);
    let url = Url::parse(&value).ok()?;
    matches!(url.scheme(), "http" | "https").then_some(value)
}

fn filename(value: &str) -> Option<String> {
    let mut plain = None;
    for parameter in disposition_parameters(value) {
        let Some((key, value)) = parameter.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        if key.eq_ignore_ascii_case("filename*") {
            if let Some((charset, rest)) = value.split_once('\'')
                && charset.eq_ignore_ascii_case("utf-8")
                && let Some((_, encoded)) = rest.split_once('\'')
            {
                let decoded = clean(&percent_decode(encoded), 128);
                if !decoded.is_empty() {
                    return Some(decoded);
                }
            }
        } else if key.eq_ignore_ascii_case("filename") {
            let name = clean(value, 128);
            if !name.is_empty() {
                plain = Some(name);
            }
        }
    }
    plain
}

fn disposition_parameters(value: &str) -> Vec<&str> {
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    let mut result = Vec::new();
    for (offset, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && quoted {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if ch == ';' && !quoted {
            result.push(&value[start..offset]);
            start = offset + 1;
        }
    }
    result.push(&value[start..]);
    result
}
