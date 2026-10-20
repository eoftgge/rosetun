use std::cmp::Ordering;
use std::io::Read;
use std::time::Duration;

use ureq::tls::{RootCerts, TlsConfig};

use crate::fetch::{DEFAULT_USER_AGENT, MAX_BODY_BYTES};

const RELEASES_URL: &str = "https://api.github.com/repos/eoftgge/rosetun/releases?per_page=30";
const RELEASE_PAGE_PREFIX: &str = "https://github.com/eoftgge/rosetun/releases/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub prerelease: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateCheckError {
    #[error("request failed: {0}")]
    Request(&'static str),
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("unexpected answer")]
    Parse,
}

#[derive(PartialEq, Eq)]
enum Identifier<'a> {
    Numeric(&'a str),
    Text(&'a str),
}

impl Ord for Identifier<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Numeric(left), Self::Numeric(right)) => {
                left.len().cmp(&right.len()).then_with(|| left.cmp(right))
            }
            (Self::Numeric(_), Self::Text(_)) => Ordering::Less,
            (Self::Text(_), Self::Numeric(_)) => Ordering::Greater,
            (Self::Text(left), Self::Text(right)) => left.cmp(right),
        }
    }
}

impl PartialOrd for Identifier<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(PartialEq, Eq)]
struct Version<'a> {
    core: [u64; 3],
    prerelease: Option<Vec<Identifier<'a>>>,
}

impl Ord for Version<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core
            .cmp(&other.core)
            .then_with(|| match (&self.prerelease, &other.prerelease) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(left), Some(right)) => left.cmp(right),
            })
    }
}

impl PartialOrd for Version<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn version(value: &str) -> Option<Version<'_>> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let (core, suffix) = match value.split_once('-') {
        Some((core, suffix)) => (core, Some(suffix)),
        None => (value, None),
    };
    let mut numbers = core.split('.');
    let mut next_number = || {
        let part = numbers.next()?;
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        part.parse().ok()
    };
    let core = [next_number()?, next_number()?, next_number()?];
    if numbers.next().is_some() {
        return None;
    }
    let prerelease = match suffix {
        Some(suffix) => Some(
            suffix
                .split('.')
                .map(|part| {
                    if part.is_empty()
                        || !part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    {
                        return None;
                    }
                    if part.bytes().all(|byte| byte.is_ascii_digit()) {
                        if part.len() > 1 && part.starts_with('0') {
                            return None;
                        }
                        Some(Identifier::Numeric(part))
                    } else {
                        Some(Identifier::Text(part))
                    }
                })
                .collect::<Option<Vec<_>>>()?,
        ),
        None => None,
    };
    Some(Version { core, prerelease })
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (version(candidate), version(current)) {
        (Some(candidate), Some(current)) => candidate > current,
        _ => false,
    }
}

/// alpha < beta < rc < release. Unknown pre-release labels count as alpha.
fn stability(version: &Version<'_>) -> u8 {
    match version.prerelease.as_deref() {
        None => 3,
        Some([Identifier::Text("rc"), ..]) => 2,
        Some([Identifier::Text("beta"), ..]) => 1,
        Some(_) => 0,
    }
}

/// A newer release that is at least as stable as the running one: a beta
/// user is offered later betas and the release, not the next version's
/// alphas; a release user is offered releases only.
fn is_offered(candidate: &Version<'_>, current: &Version<'_>) -> bool {
    candidate > current && stability(candidate) >= stability(current)
}

fn parse_releases(body: &str, current: &str) -> Result<Option<Release>, UpdateCheckError> {
    let current = version(current);
    let entries: serde_json::Value =
        serde_json::from_str(body).map_err(|_| UpdateCheckError::Parse)?;
    let entries = entries.as_array().ok_or(UpdateCheckError::Parse)?;
    let mut newest: Option<Release> = None;
    for entry in entries {
        if entry.get("draft").and_then(serde_json::Value::as_bool) != Some(false) {
            continue;
        }
        let Some(url) = entry.get("html_url").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !url.starts_with(RELEASE_PAGE_PREFIX) {
            continue;
        }
        let Some(tag) = entry.get("tag_name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let normalized = tag.strip_prefix('v').unwrap_or(tag);
        let Some(candidate) = version(normalized) else {
            continue;
        };
        if current
            .as_ref()
            .is_some_and(|current| !is_offered(&candidate, current))
        {
            continue;
        }
        if newest.as_ref().is_none_or(|previous| {
            candidate > version(&previous.version).expect("validated release version")
        }) {
            newest = Some(Release {
                version: normalized.to_owned(),
                url: url.to_owned(),
                prerelease: entry
                    .get("prerelease")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            });
        }
    }
    Ok(newest)
}

/// The newest release offered to `current` (see `is_offered`).
pub fn latest_release(
    current: &str,
    timeout: Duration,
) -> Result<Option<Release>, UpdateCheckError> {
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build();
    let agent = crate::resolve::agent(
        ureq::Agent::config_builder()
            .tls_config(tls)
            .timeout_global(Some(timeout))
            .max_redirects(0)
            .https_only(true)
            .http_status_as_error(false)
            .build(),
    );

    // ureq errors can contain the request URI; never forward them to the GUI or log.
    let mut response = agent
        .get(RELEASES_URL)
        .header("User-Agent", DEFAULT_USER_AGENT)
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|_| UpdateCheckError::Request("connection failed"))?;
    if response.status().as_u16() != 200 {
        return Err(UpdateCheckError::Status(response.status().as_u16()));
    }

    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(MAX_BODY_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| UpdateCheckError::Request("response read failed"))?;
    if body.len() as u64 > MAX_BODY_BYTES {
        return Err(UpdateCheckError::Parse);
    }
    parse_releases(
        std::str::from_utf8(&body).map_err(|_| UpdateCheckError::Parse)?,
        current,
    )
}

#[cfg(test)]
mod tests {
    use super::{Release, UpdateCheckError, is_newer, parse_releases, stability, version};

    #[test]
    fn version_order_includes_numeric_prerelease_parts() {
        let versions = [
            "0.1.0-alpha.3",
            "0.1.0-alpha.9",
            "0.1.0-alpha.10",
            "0.1.0-beta.1",
            "0.1.0",
        ];
        for pair in versions.windows(2) {
            assert!(is_newer(pair[1], pair[0]));
            assert!(!is_newer(pair[0], pair[1]));
        }
        assert!(!is_newer("0.1.0-alpha.3", "0.1.0-alpha.3"));
        assert!(is_newer("v0.1.0-alpha.10", "v0.1.0-alpha.9"));
        assert!(is_newer("0.1.0-alpha.1", "0.1.0-alpha"));
        assert!(!is_newer("anything", "0.1.0"));
    }

    #[test]
    fn selects_highest_valid_release_not_first_in_list() {
        let body = r#"[
            {"tag_name":"v0.1.0-alpha.3","html_url":"https://github.com/eoftgge/rosetun/releases/tag/v0.1.0-alpha.3","draft":false},
            {"tag_name":"v0.1.0-alpha.10","html_url":"https://github.com/eoftgge/rosetun/releases/tag/v0.1.0-alpha.10","draft":false,"prerelease":true},
            {"tag_name":"0.1.0","html_url":"https://github.com/eoftgge/rosetun/releases/tag/0.1.0","draft":true},
            {"tag_name":"0.2.0","html_url":"https://github.com/other/rosetun/releases/tag/0.2.0","draft":false},
            {"tag_name":"not-a-version","html_url":"https://github.com/eoftgge/rosetun/releases/tag/not-a-version","draft":false}
        ]"#;
        assert_eq!(
            parse_releases(body, "0.0.1-alpha.1").unwrap(),
            Some(Release {
                version: "0.1.0-alpha.10".into(),
                url: "https://github.com/eoftgge/rosetun/releases/tag/v0.1.0-alpha.10".into(),
                prerelease: true,
            })
        );
    }

    #[test]
    fn missing_or_invalid_prerelease_flag_is_false() {
        for suffix in ["", ",\"prerelease\":\"yes\""] {
            let body = format!(
                "[{{\"tag_name\":\"1.0.0\",\"html_url\":\"https://github.com/eoftgge/rosetun/releases/tag/v1.0.0\",\"draft\":false{suffix}}}]"
            );
            assert!(
                !parse_releases(&body, "0.0.1-alpha.1")
                    .unwrap()
                    .unwrap()
                    .prerelease
            );
        }
    }

    fn offered(current: &str) -> Option<String> {
        let body = r#"[
            {"tag_name":"v0.2.0-alpha.1","html_url":"https://github.com/eoftgge/rosetun/releases/tag/v0.2.0-alpha.1","draft":false,"prerelease":true},
            {"tag_name":"v0.1.0-beta.3","html_url":"https://github.com/eoftgge/rosetun/releases/tag/v0.1.0-beta.3","draft":false,"prerelease":true},
            {"tag_name":"v0.1.0-beta.2","html_url":"https://github.com/eoftgge/rosetun/releases/tag/v0.1.0-beta.2","draft":false,"prerelease":true}
        ]"#;
        parse_releases(body, current)
            .unwrap()
            .map(|release| release.version)
    }

    #[test]
    fn beta_users_get_betas_not_the_next_alphas() {
        assert_eq!(offered("0.1.0-beta.1").as_deref(), Some("0.1.0-beta.3"));
        assert_eq!(offered("0.1.0-beta.3"), None);
        assert_eq!(offered("0.1.0-alpha.6").as_deref(), Some("0.2.0-alpha.1"));
        assert_eq!(offered("0.2.0-alpha.1"), None);
    }

    #[test]
    fn release_users_get_releases_only() {
        assert_eq!(offered("0.0.9"), None);
        let body = r#"[
            {"tag_name":"v0.2.0-beta.1","html_url":"https://github.com/eoftgge/rosetun/releases/tag/v0.2.0-beta.1","draft":false,"prerelease":true},
            {"tag_name":"v0.1.1","html_url":"https://github.com/eoftgge/rosetun/releases/tag/v0.1.1","draft":false}
        ]"#;
        assert_eq!(
            parse_releases(body, "0.1.0").unwrap().unwrap().version,
            "0.1.1"
        );
    }

    #[test]
    fn stability_order() {
        let order = ["1.0.0-alpha.2", "1.0.0-beta.1", "1.0.0-rc.1", "1.0.0"];
        for pair in order.windows(2) {
            assert!(stability(&version(pair[0]).unwrap()) < stability(&version(pair[1]).unwrap()));
        }
        assert_eq!(stability(&version("1.0.0-dev.1").unwrap()), 0);
    }

    #[test]
    fn empty_and_malformed_responses() {
        assert_eq!(parse_releases("[]", "0.1.0").unwrap(), None);
        assert!(matches!(
            parse_releases("not JSON", "0.1.0"),
            Err(UpdateCheckError::Parse)
        ));
        assert!(matches!(
            parse_releases("{}", "0.1.0"),
            Err(UpdateCheckError::Parse)
        ));
    }
}
