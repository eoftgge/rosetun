use rosetun_core::{provider_link, provider_text, terminal_text};

#[test]
fn terminal_text_removes_controls_and_bidi_markers() {
    assert_eq!(
        terminal_text("Name\n\x1b[31m\u{202e}text\u{2066}"),
        "Name  [31m text "
    );
}

#[test]
fn provider_text_preserves_renewal_links() {
    assert_eq!(
        provider_text(
            "Renew at https://t.me/example_bot",
            "https://sub.example.com/private-token?key=query-secret",
        ),
        "Renew at https://t.me/example_bot"
    );
}

#[test]
fn provider_text_redacts_subscription_url_and_token_path() {
    let subscription_url = "https://sub.example.com/private-token?key=query-secret";

    assert_eq!(
        provider_text(
            &format!("Subscription: {subscription_url}"),
            subscription_url,
        ),
        "Subscription: https://sub.example.com/…"
    );
    assert_eq!(
        provider_text(
            "Subscription path: /private-token?key=query-secret",
            subscription_url,
        ),
        "Subscription path: /…"
    );
}

#[test]
fn provider_text_does_not_redact_short_paths() {
    assert_eq!(
        provider_text("Open /renew", "https://sub.example.com/renew"),
        "Open /renew"
    );
}

#[test]
fn terminal_text_preserves_links_and_unicode() {
    assert_eq!(
        terminal_text("消息 HTTPS://sub.example.com/private"),
        "消息 HTTPS://sub.example.com/private"
    );
}

#[test]
fn provider_text_removes_controls_and_bidi() {
    assert_eq!(
        provider_text(
            "Renew\nat\u{202e} https://t.me/example_bot\x1b",
            "https://sub.example.com/private-token",
        ),
        "Renew at  https://t.me/example_bot "
    );
}

#[test]
fn provider_link_hides_the_subscription_link_and_its_path() {
    let subscription_url = "https://sub.example.com/private-token?key=query-secret";

    for link in [
        subscription_url,
        "https://sub.example.com/private-token?key=query-secret/",
        " https://panel.example.com/private-token?key=query-secret ",
        "",
    ] {
        assert_eq!(provider_link(link, subscription_url), None, "{link}");
    }
    assert_eq!(
        provider_link(
            "https://panel.example.com/info/private-token?key=query-secret",
            subscription_url,
        )
        .as_deref(),
        Some("https://panel.example.com/info/…")
    );
}

#[test]
fn provider_link_keeps_other_links() {
    let subscription_url = "https://sub.example.com/private-token";

    assert_eq!(
        provider_link("https://t.me/example_support", subscription_url).as_deref(),
        Some("https://t.me/example_support")
    );
    assert_eq!(
        provider_link("https://sub.example.com/", subscription_url).as_deref(),
        Some("https://sub.example.com/")
    );
    assert_eq!(
        provider_link("https://panel.example.com/sub", "https://panel.example.com/sub/").as_deref(),
        None
    );
}
