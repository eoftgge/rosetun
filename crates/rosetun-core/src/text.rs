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
