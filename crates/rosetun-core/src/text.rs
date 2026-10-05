use crate::FetchError;
use rosetun_subscription::ParseError;

pub fn terminal_text(input: &str) -> String {
    input
        .chars()
        .map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{2028}'
                        | '\u{2029}'
                )
            {
                ' '
            } else {
                character
            }
        })
        .collect()
}

pub fn provider_text(text: &str, subscription_url: &str) -> String {
    let mut output = terminal_text(text);
    let secret = terminal_text(subscription_url);
    if !secret.is_empty() {
        output = output.replace(&secret, &crate::redacted_subscription_url(subscription_url));
    }

    if let Ok(url) = url::Url::parse(subscription_url) {
        let mut path_and_query = url.path().to_owned();
        if let Some(query) = url.query() {
            path_and_query.push('?');
            path_and_query.push_str(query);
        }
        if path_and_query.len() > 8 {
            output = output.replace(&terminal_text(&path_and_query), "/…");
        }
    }

    output
}

pub fn fetch_error_message(error: &FetchError, subscription_url: &str) -> String {
    match error {
        FetchError::Parse(ParseError::DeviceLimit {
            max_devices_reached,
            not_supported,
            announce,
        }) => {
            let message = if *max_devices_reached {
                "device limit reached for this subscription; remove an old device in your provider's panel"
            } else if *not_supported {
                "the panel did not accept this device ID"
            } else {
                "subscription access was refused by the device policy"
            };

            let mut output = message.to_owned();
            if let Some(announce) = announce {
                output.push_str("\n  announce: ");
                output.push_str(&provider_text(announce, subscription_url));
            }
            output
        }
        FetchError::Parse(ParseError::NoUsableNodes { skipped, notices }) => {
            let mut output = error.to_string();
            for notice in notices {
                output.push_str("\n  notice: ");
                output.push_str(&provider_text(notice, subscription_url));
            }
            for (reason, count) in crate::group_skipped(skipped) {
                output.push_str(&format!("\n  skipped {count}: {}", terminal_text(&reason)));
            }
            output
        }
        _ => terminal_text(&error.to_string()),
    }
}
