use url::Url;

pub(crate) fn normalize(input: &str) -> Result<String, String> {
    let mut current = input.trim().to_owned();

    for _ in 0..8 {
        let Some((scheme, remainder)) = current.split_once("://") else {
            return Err("invalid subscription URL".to_owned());
        };

        match scheme.to_ascii_lowercase().as_str() {
            "http" | "https" => {
                let parsed =
                    Url::parse(&current).map_err(|_| "invalid subscription URL".to_owned())?;
                if parsed.host_str().is_none() {
                    return Err("subscription URL requires a host".to_owned());
                }
                return Ok(parsed.to_string());
            }
            "happ" => {
                if remainder
                    .get(..5)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("crypt"))
                {
                    return Err(rosetun_subscription::ParseError::EncryptedHappLink.to_string());
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
                return Err("subscription URL must use http or https".to_owned());
            }
        }
    }

    Err("too many nested subscription import links".to_owned())
}

fn unwrap_path(remainder: &str, prefix: &str) -> Result<String, String> {
    let inner = remainder
        .strip_prefix(prefix)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "invalid subscription import link".to_owned())?;

    // Keep the embedded URL verbatim: its query and percent escapes belong
    // to the provider's token, not to the outer import link.
    Ok(inner.to_owned())
}

fn unwrap_query(input: &str, action: &str) -> Result<String, String> {
    let parsed = Url::parse(input).map_err(|_| "invalid subscription import link".to_owned())?;

    if parsed.host_str() != Some(action)
        || !matches!(parsed.path(), "" | "/")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
    {
        return Err("invalid subscription import link".to_owned());
    }

    let mut urls = parsed
        .query_pairs()
        .filter(|(name, _)| name == "url")
        .map(|(_, value)| value.into_owned());

    let inner = urls
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "subscription import link requires a URL".to_owned())?;

    if urls.next().is_some() {
        return Err("subscription import link contains multiple URLs".to_owned());
    }

    Ok(inner)
}

pub(crate) fn redacted(input: &str) -> String {
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
    use super::{normalize, redacted};

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
    fn path_wrappers_are_unwrapped() {
        for prefix in [
            "happ://add/",
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
                normalize(input).unwrap_err(),
                rosetun_subscription::ParseError::EncryptedHappLink.to_string()
            );
        }
    }

    #[test]
    fn non_http_inner_urls_are_rejected() {
        for input in [
            "happ://add/file:///private-token",
            "v2raytun://import/vless://private-token@example.com",
            "clash://install-config?url=ftp%3A%2F%2Fexample.com%2Fprivate-token",
        ] {
            assert_eq!(
                normalize(input).unwrap_err(),
                "subscription URL must use http or https"
            );
        }
    }

    #[test]
    fn malformed_import_links_are_rejected() {
        for input in [
            "happ://add/",
            "happ://unknown/private-token",
            "hiddify://import/",
            "sing-box://wrong-action?url=https%3A%2F%2Fexample.com",
            "clash://install-config",
            "clash://install-config?url=",
            "clash://install-config?url=https%3A%2F%2Fa.example&url=https%3A%2F%2Fb.example",
            "clash://install-config/extra?url=https%3A%2F%2Fexample.com",
        ] {
            assert!(normalize(input).is_err());
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let input = format!("{}{SECRET_URL}", "happ://add/".repeat(20));

        assert_eq!(
            normalize(&input).unwrap_err(),
            "too many nested subscription import links"
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
            let error = normalize(input).unwrap_err();
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
}
