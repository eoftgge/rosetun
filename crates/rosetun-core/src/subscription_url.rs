use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use percent_encoding::percent_decode_str;
use url::Url;

/// The longest `rosetun://` link the system may hand over, checked before any
/// parsing.
pub const MAX_OPEN_LINK_BYTES: usize = 8 * 1024;
const MAX_LINK_NAME_CHARS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SubscriptionUrlError {
    #[error("invalid subscription URL")]
    Invalid,
    #[error("subscription URL requires a host")]
    MissingHost,
    #[error("Happ link is encrypted; ask your provider for a regular subscription link")]
    EncryptedHappLink,
    #[error("subscription URL must use http or https")]
    UnsupportedScheme,
    #[error("invalid subscription import link")]
    InvalidImportLink,
    #[error("subscription import link requires a URL")]
    ImportLinkWithoutUrl,
    #[error("subscription import link contains multiple URLs")]
    ImportLinkWithMultipleUrls,
    #[error("too many nested subscription import links")]
    TooManyNestedLinks,
}

/// A `rosetun://add/` link opened from outside Rosetun: a normalized
/// subscription URL and the name the provider suggests.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenLink {
    pub url: String,
    pub name: Option<String>,
}

impl fmt::Debug for OpenLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenLink")
            .field("url", &redacted(&self.url))
            .field("name", &self.name)
            .finish()
    }
}

pub fn normalize(input: &str) -> Result<String, SubscriptionUrlError> {
    let input = input.trim();
    let mut current = if assumes_https(input) {
        format!("https://{input}")
    } else {
        input.to_owned()
    };

    for _ in 0..8 {
        let Some((scheme, remainder)) = current.split_once("://") else {
            return Err(SubscriptionUrlError::Invalid);
        };

        match scheme.to_ascii_lowercase().as_str() {
            "http" | "https" => {
                let parsed = Url::parse(&current).map_err(|_| SubscriptionUrlError::Invalid)?;
                if parsed.host_str().is_none() {
                    return Err(SubscriptionUrlError::MissingHost);
                }
                return Ok(parsed.to_string());
            }
            "rosetun" => {
                current = unwrap_path(remainder, "add/")?;
            }
            "happ" => {
                if remainder
                    .get(..5)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("crypt"))
                {
                    return Err(SubscriptionUrlError::EncryptedHappLink);
                }
                current = unwrap_path(remainder, "add/")?;
            }
            "v2raytun" | "hiddify" | "streisand" => {
                current = unwrap_path(remainder, "import/")?;
            }
            "sing-box" => {
                current = unwrap_query(&current, "import-remote-profile")?;
            }
            "clash" | "clashmeta" => {
                current = unwrap_query(&current, "install-config")?;
            }
            _ => {
                return Err(SubscriptionUrlError::UnsupportedScheme);
            }
        }
    }

    Err(SubscriptionUrlError::TooManyNestedLinks)
}

/// Reads a `rosetun://add/<link>[#name]` link handed over by the system. Any
/// web page can open one, so the link gets the same checks as a pasted one.
pub fn parse_open_link(input: &str) -> Result<OpenLink, SubscriptionUrlError> {
    if input.len() > MAX_OPEN_LINK_BYTES {
        return Err(SubscriptionUrlError::InvalidImportLink);
    }
    let (scheme, remainder) = input
        .trim()
        .split_once("://")
        .ok_or(SubscriptionUrlError::InvalidImportLink)?;
    if !scheme.eq_ignore_ascii_case("rosetun") {
        return Err(SubscriptionUrlError::InvalidImportLink);
    }

    let (link, name) = match remainder.rsplit_once('#') {
        Some((link, name)) => (link, link_name(name)),
        None => (remainder, None),
    };
    let link = unwrap_path(link, "add/")?;
    // Only a link encoded as a whole is decoded: escapes in a raw link belong
    // to the provider's token.
    let link = if starts_with_ignore_case(&link, "http%3A")
        || starts_with_ignore_case(&link, "https%3A")
    {
        percent_decode_str(&link)
            .decode_utf8()
            .map_err(|_| SubscriptionUrlError::Invalid)?
            .into_owned()
    } else {
        link
    };

    Ok(OpenLink {
        url: normalize(&link)?,
        name,
    })
}

fn link_name(encoded: &str) -> Option<String> {
    let decoded = percent_decode_str(encoded).decode_utf8_lossy();
    let name: String = decoded
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_LINK_NAME_CHARS)
        .collect();
    let name = name.trim_end();
    (!name.is_empty()).then(|| name.to_owned())
}

fn starts_with_ignore_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

/// Whether `normalize` reads `input` as an `https://` link: it has no scheme
/// and starts with a host. Never assumes `http://`, which would send the
/// token in clear text.
pub fn assumes_https(input: &str) -> bool {
    let input = input.trim();
    if input.is_empty() || input.contains(char::is_whitespace) {
        return false;
    }
    let authority_end = input.find(['/', '?', '#']).unwrap_or(input.len());
    let has_scheme = input
        .find("://")
        .is_some_and(|index| !input[..index].contains(['/', '?', '#']));
    !has_scheme && is_host_with_port(&input[..authority_end])
}

fn is_host_with_port(authority: &str) -> bool {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((address, port)) = rest.split_once(']') else {
            return false;
        };
        if address.parse::<Ipv6Addr>().is_err() {
            return false;
        }
        (None, port)
    } else {
        match authority.find(':') {
            Some(index) => (Some(&authority[..index]), &authority[index..]),
            None => (Some(authority), ""),
        }
    };

    let port_is_valid = port.is_empty()
        || port.strip_prefix(':').is_some_and(|port| {
            port.bytes().all(|byte| byte.is_ascii_digit()) && port.parse::<u16>().is_ok()
        });
    port_is_valid && host.is_none_or(is_host_name)
}

fn is_host_name(host: &str) -> bool {
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() > 1
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|character| character.is_alphanumeric() || character == '-')
        })
        // `1.2` is not a valid IPv4 address, but URL parsers read it as one.
        && !labels
            .last()
            .is_some_and(|label| label.chars().all(|character| character.is_ascii_digit()))
}

fn unwrap_path(remainder: &str, prefix: &str) -> Result<String, SubscriptionUrlError> {
    let inner = remainder
        .strip_prefix(prefix)
        .filter(|value| !value.is_empty())
        .ok_or(SubscriptionUrlError::InvalidImportLink)?;

    // Keep the embedded URL verbatim: its query and percent escapes belong
    // to the provider's token, not to the outer import link.
    Ok(inner.to_owned())
}

fn unwrap_query(input: &str, action: &str) -> Result<String, SubscriptionUrlError> {
    let parsed = Url::parse(input).map_err(|_| SubscriptionUrlError::InvalidImportLink)?;

    if parsed.host_str() != Some(action)
        || !matches!(parsed.path(), "" | "/")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
    {
        return Err(SubscriptionUrlError::InvalidImportLink);
    }

    let mut urls = parsed
        .query_pairs()
        .filter(|(name, _)| name == "url")
        .map(|(_, value)| value.into_owned());

    let inner = urls
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(SubscriptionUrlError::ImportLinkWithoutUrl)?;

    if urls.next().is_some() {
        return Err(SubscriptionUrlError::ImportLinkWithMultipleUrls);
    }

    Ok(inner)
}

pub fn redacted(input: &str) -> String {
    let Ok(parsed) = Url::parse(input) else {
        return "<redacted>".to_owned();
    };

    if !matches!(parsed.scheme(), "http" | "https") {
        return "<redacted>".to_owned();
    }

    let Some(host) = parsed.host_str() else {
        return "<redacted>".to_owned();
    };

    format!("{}://{host}/…", parsed.scheme())
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_OPEN_LINK_BYTES, OpenLink, SubscriptionUrlError, assumes_https, normalize,
        parse_open_link, redacted,
    };

    const SECRET_URL: &str = "https://sub.example.com/private-token?key=query-secret";

    #[test]
    fn direct_http_and_https_urls_are_accepted() {
        assert_eq!(normalize(SECRET_URL).unwrap(), SECRET_URL);
        assert_eq!(
            normalize("http://sub.example.com/private-token").unwrap(),
            "http://sub.example.com/private-token"
        );
    }

    #[test]
    fn a_host_without_a_scheme_becomes_https() {
        for (input, expected) in [
            (
                "sub.example.com/path?token=x",
                "https://sub.example.com/path?token=x",
            ),
            (
                "  sub.example.com:8443/sub  ",
                "https://sub.example.com:8443/sub",
            ),
            ("192.0.2.1/sub", "https://192.0.2.1/sub"),
            ("[2001:db8::1]:443/sub", "https://[2001:db8::1]/sub"),
            ("sub.example.com", "https://sub.example.com/"),
            (
                "sub.example.com/x?r=https://y",
                "https://sub.example.com/x?r=https://y",
            ),
        ] {
            assert!(assumes_https(input), "{input}");
            assert_eq!(normalize(input).unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn text_that_is_not_a_host_is_still_invalid() {
        for input in [
            "sub",
            "sub example.com",
            "",
            "localhost/sub",
            "user:pass@sub.example.com/x",
            "sub.example.com:port/x",
            "1.2/sub",
            "[2001:db8::zz]/sub",
            "happ://add/sub.example.com/x",
        ] {
            assert!(!assumes_https(input), "{input}");
            assert_eq!(
                normalize(input),
                Err(SubscriptionUrlError::Invalid),
                "{input}"
            );
        }
    }

    #[test]
    fn links_with_a_scheme_are_not_rewritten() {
        assert!(!assumes_https("http://sub.example.com/x"));
        assert_eq!(
            normalize("http://sub.example.com/x").unwrap(),
            "http://sub.example.com/x"
        );
        assert!(!assumes_https(&format!("happ://add/{SECRET_URL}")));
        assert_eq!(
            normalize("vless://private-token@example.com:443"),
            Err(SubscriptionUrlError::UnsupportedScheme)
        );
    }

    #[test]
    fn path_wrappers_are_unwrapped() {
        for prefix in [
            "happ://add/",
            "rosetun://add/",
            "v2raytun://import/",
            "hiddify://import/",
            "streisand://import/",
        ] {
            assert_eq!(
                normalize(&format!("{prefix}{SECRET_URL}")).unwrap(),
                SECRET_URL
            );
        }
    }

    #[test]
    fn query_wrappers_are_unwrapped() {
        let encoded: String = url::form_urlencoded::byte_serialize(SECRET_URL.as_bytes()).collect();

        for prefix in [
            "sing-box://import-remote-profile",
            "clash://install-config",
            "clashmeta://install-config",
        ] {
            assert_eq!(
                normalize(&format!("{prefix}?name=Example&url={encoded}")).unwrap(),
                SECRET_URL
            );
        }
    }

    #[test]
    fn embedded_percent_escapes_are_not_decoded_twice() {
        let inner = "https://sub.example.com/token%2Fpart?key=a%26b%2Bc";
        let encoded: String = url::form_urlencoded::byte_serialize(inner.as_bytes()).collect();

        assert_eq!(
            normalize(&format!("clash://install-config?url={encoded}")).unwrap(),
            inner
        );
        assert_eq!(normalize(&format!("happ://add/{inner}")).unwrap(), inner);
    }

    #[test]
    fn nested_wrappers_are_unwrapped() {
        assert_eq!(
            normalize(&format!("happ://add/hiddify://import/{SECRET_URL}")).unwrap(),
            SECRET_URL
        );
    }

    #[test]
    fn encrypted_happ_links_use_the_parser_message() {
        for input in [
            "happ://crypt/private-token",
            "happ://crypt2/private-token",
            "happ://add/happ://crypt/private-token",
        ] {
            assert_eq!(
                normalize(input),
                Err(SubscriptionUrlError::EncryptedHappLink)
            );
        }
        assert_eq!(
            SubscriptionUrlError::EncryptedHappLink.to_string(),
            rosetun_subscription::ParseError::EncryptedHappLink.to_string()
        );
    }

    #[test]
    fn non_http_inner_urls_are_rejected() {
        for input in [
            "happ://add/file:///private-token",
            "v2raytun://import/vless://private-token@example.com",
            "clash://install-config?url=ftp%3A%2F%2Fexample.com%2Fprivate-token",
        ] {
            assert_eq!(
                normalize(input),
                Err(SubscriptionUrlError::UnsupportedScheme)
            );
        }
    }

    #[test]
    fn malformed_import_links_are_rejected() {
        for (input, expected) in [
            ("happ://add/", SubscriptionUrlError::InvalidImportLink),
            (
                "happ://unknown/private-token",
                SubscriptionUrlError::InvalidImportLink,
            ),
            ("hiddify://import/", SubscriptionUrlError::InvalidImportLink),
            (
                "sing-box://wrong-action?url=https%3A%2F%2Fexample.com",
                SubscriptionUrlError::InvalidImportLink,
            ),
            (
                "clash://install-config",
                SubscriptionUrlError::ImportLinkWithoutUrl,
            ),
            (
                "clash://install-config?url=",
                SubscriptionUrlError::ImportLinkWithoutUrl,
            ),
            (
                "clash://install-config?url=https%3A%2F%2Fa.example&url=https%3A%2F%2Fb.example",
                SubscriptionUrlError::ImportLinkWithMultipleUrls,
            ),
            (
                "clash://install-config/extra?url=https%3A%2F%2Fexample.com",
                SubscriptionUrlError::InvalidImportLink,
            ),
        ] {
            assert_eq!(normalize(input), Err(expected), "{input}");
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let input = format!("{}{SECRET_URL}", "happ://add/".repeat(20));

        assert_eq!(
            normalize(&input),
            Err(SubscriptionUrlError::TooManyNestedLinks)
        );
    }

    #[test]
    fn errors_never_include_the_original_url() {
        for input in [
            "private-token?key=query-secret",
            "ftp://sub.example.com/private-token?key=query-secret",
            "happ://crypt/private-token?key=query-secret",
            "clash://wrong-action?url=private-token%3Fkey%3Dquery-secret",
        ] {
            let error = normalize(input).unwrap_err().to_string();
            assert!(!error.contains("private-token"));
            assert!(!error.contains("query-secret"));
            assert!(!error.contains(input));
        }
    }

    #[test]
    fn redacted_url_contains_only_scheme_and_host() {
        assert_eq!(
            redacted(
                "https://user:password@sub.example.com:8443/private-token?key=query-secret#fragment"
            ),
            "https://sub.example.com/…"
        );
        assert_eq!(
            redacted("http://[2001:db8::1]:8080/private-token"),
            "http://[2001:db8::1]/…"
        );
        assert_eq!(redacted("invalid-private-token"), "<redacted>");
        assert_eq!(redacted("file:///private-token"), "<redacted>");
    }

    #[test]
    fn an_open_link_carries_a_raw_or_encoded_url() {
        let encoded: String = url::form_urlencoded::byte_serialize(SECRET_URL.as_bytes()).collect();

        for input in [
            format!("rosetun://add/{SECRET_URL}"),
            format!("ROSETUN://add/{SECRET_URL}"),
            format!("rosetun://add/{encoded}"),
            format!(
                "  rosetun://add/{}  ",
                encoded.replace("https%3A", "HTTPS%3a")
            ),
        ] {
            assert_eq!(
                parse_open_link(&input).unwrap(),
                OpenLink {
                    url: SECRET_URL.to_owned(),
                    name: None
                },
                "{input}"
            );
        }
    }

    #[test]
    fn an_open_link_name_follows_the_last_hash() {
        for (suffix, expected) in [
            ("#Example", Some("Example")),
            (
                "#%D0%9F%D1%80%D0%BE%D0%B2%D0%B0%D0%B9%D0%B4%D0%B5%D1%80",
                Some("Провайдер"),
            ),
            ("#%20Example%20VPN%20", Some("Example VPN")),
            ("#first#second", Some("second")),
            ("#", None),
            ("#%20%20", None),
        ] {
            let link =
                parse_open_link(&format!("rosetun://add/https://example.com/sub{suffix}")).unwrap();
            assert_eq!(link.name.as_deref(), expected, "{suffix}");
            assert!(link.url.starts_with("https://example.com/sub"), "{suffix}");
        }
    }

    #[test]
    fn a_long_open_link_name_is_cut() {
        let name = "й".repeat(100);
        let link =
            parse_open_link(&format!("rosetun://add/https://example.com/sub#{name}")).unwrap();

        assert_eq!(link.name.unwrap().chars().count(), 64);
    }

    #[test]
    fn escapes_in_a_raw_open_link_are_kept() {
        let inner = "https://sub.example.com/token%2Fpart?key=a%26b";

        assert_eq!(
            parse_open_link(&format!("rosetun://add/{inner}"))
                .unwrap()
                .url,
            inner
        );
    }

    #[test]
    fn bad_open_links_are_rejected() {
        for (input, expected) in [
            (
                format!("rosetun://connect/{SECRET_URL}"),
                SubscriptionUrlError::InvalidImportLink,
            ),
            (
                "rosetun://add/".to_owned(),
                SubscriptionUrlError::InvalidImportLink,
            ),
            (
                "rosetun://add/#Example".to_owned(),
                SubscriptionUrlError::InvalidImportLink,
            ),
            (
                "rosetun:add/x".to_owned(),
                SubscriptionUrlError::InvalidImportLink,
            ),
            (
                format!("happ://add/{SECRET_URL}"),
                SubscriptionUrlError::InvalidImportLink,
            ),
            (
                "rosetun://add/file:///private-token".to_owned(),
                SubscriptionUrlError::UnsupportedScheme,
            ),
            (
                "rosetun://add/happ://crypt/private-token".to_owned(),
                SubscriptionUrlError::EncryptedHappLink,
            ),
            (
                format!(
                    "rosetun://add/https://example.com/{}",
                    "a".repeat(MAX_OPEN_LINK_BYTES)
                ),
                SubscriptionUrlError::InvalidImportLink,
            ),
        ] {
            assert_eq!(parse_open_link(&input), Err(expected), "{input}");
        }
    }

    #[test]
    fn open_link_debug_has_no_token() {
        let link = parse_open_link(&format!("rosetun://add/{SECRET_URL}#Example")).unwrap();
        let debug = format!("{link:?}");

        assert!(debug.contains("sub.example.com"));
        assert!(!debug.contains("private-token"));
        assert!(!debug.contains("query-secret"));
    }
}
