use std::cmp::Ordering;
use std::io::Read;
use std::time::Duration;

use ureq::tls::{RootCerts, TlsConfig};

use crate::fetch::{DEFAULT_USER_AGENT, MAX_BODY_BYTES};

const RELEASES_URL: &str = "https://api.github.com/repos/eoftgge/rosetun/releases?per_page=30";
/// The same releases without the API's hourly limit per address, which a
/// shared VPN server address uses up.
const RELEASES_FEED_URL: &str = "https://github.com/eoftgge/rosetun/releases.atom";
const RELEASE_PAGE_PREFIX: &str = "https://github.com/eoftgge/rosetun/releases/";
const RELEASE_TAG_PREFIX: &str = "https://github.com/eoftgge/rosetun/releases/tag/";

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

/// A version remembered from an earlier check, offered again without the
/// network if it is still offered to `current` (see `is_offered`).
pub fn remembered_release(version_text: &str, current: &str) -> Option<Release> {
    let candidate = version(version_text)?;
    if version_text.starts_with('v') || !is_offered(&candidate, &version(current)?) {
        return None;
    }
    Some(Release {
        version: version_text.to_owned(),
        url: format!("{RELEASE_TAG_PREFIX}v{version_text}"),
        prerelease: candidate.prerelease.is_some(),
    })
}

/// A published release before the offer rules: its tag, page and whether
/// the source marks it as a pre-release.
struct Candidate<'a> {
    tag: &'a str,
    url: &'a str,
    prerelease: bool,
}

/// The newest candidate offered to `current` (see `is_offered`); the same
/// rules for the API and the feed.
fn newest_offered<'a>(
    candidates: impl IntoIterator<Item = Candidate<'a>>,
    current: &str,
) -> Option<Release> {
    let current = version(current);
    let mut newest: Option<Release> = None;
    for Candidate {
        tag,
        url,
        prerelease,
    } in candidates
    {
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
                prerelease,
            });
        }
    }
    newest
}

fn parse_releases(body: &str, current: &str) -> Result<Option<Release>, UpdateCheckError> {
    let entries: serde_json::Value =
        serde_json::from_str(body).map_err(|_| UpdateCheckError::Parse)?;
    let entries = entries.as_array().ok_or(UpdateCheckError::Parse)?;
    let candidates = entries.iter().filter_map(|entry| {
        if entry.get("draft").and_then(serde_json::Value::as_bool) != Some(false) {
            return None;
        }
        let url = entry.get("html_url").and_then(serde_json::Value::as_str)?;
        if !url.starts_with(RELEASE_PAGE_PREFIX) {
            return None;
        }
        Some(Candidate {
            tag: entry.get("tag_name").and_then(serde_json::Value::as_str)?,
            url,
            prerelease: entry
                .get("prerelease")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        })
    });
    Ok(newest_offered(candidates, current))
}

/// Release pages linked from the Atom feed. The feed has no drafts and no
/// pre-release flag, so a pre-release is told by its version suffix.
fn feed_candidates(body: &str) -> impl Iterator<Item = Candidate<'_>> {
    body.split("href=\"").skip(1).filter_map(|rest| {
        let url = &rest[..rest.find('"')?];
        let tag = url.strip_prefix(RELEASE_TAG_PREFIX)?;
        let parsed = version(tag)?;
        Some(Candidate {
            tag,
            url,
            prerelease: parsed.prerelease.is_some(),
        })
    })
}

fn parse_feed(body: &str, current: &str) -> Option<Release> {
    newest_offered(feed_candidates(body), current)
}

/// The API refuses a client over its hourly limit with 403 or 429.
fn falls_back_to_feed(api_status: u16) -> bool {
    matches!(api_status, 403 | 429)
}

fn read_body(response: &mut ureq::http::Response<ureq::Body>) -> Result<String, UpdateCheckError> {
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
    String::from_utf8(body).map_err(|_| UpdateCheckError::Parse)
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
    let get = |url: &str, accept: &str| {
        agent
            .get(url)
            .header("User-Agent", DEFAULT_USER_AGENT)
            .header("Accept", accept)
            .call()
            .map_err(|_| UpdateCheckError::Request("connection failed"))
    };
    let mut response = get(RELEASES_URL, "application/vnd.github+json")?;
    let api_status = response.status().as_u16();
    if api_status == 200 {
        return parse_releases(&read_body(&mut response)?, current);
    }
    if !falls_back_to_feed(api_status) {
        return Err(UpdateCheckError::Status(api_status));
    }

    tracing::info!(
        status = api_status,
        "release API refused, checking the releases feed"
    );
    let mut response = get(RELEASES_FEED_URL, "application/atom+xml")?;
    let feed_status = response.status().as_u16();
    if feed_status != 200 {
        return Err(UpdateCheckError::Status(feed_status));
    }
    Ok(parse_feed(&read_body(&mut response)?, current))
}

#[cfg(test)]
mod tests {
    use super::{
        Release, UpdateCheckError, falls_back_to_feed, is_newer, parse_feed, parse_releases,
        remembered_release, stability, version,
    };

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
    fn a_remembered_release_follows_the_same_offer_rules() {
        assert_eq!(
            remembered_release("0.3.1", "0.2.0-beta.2"),
            Some(Release {
                version: "0.3.1".into(),
                url: "https://github.com/eoftgge/rosetun/releases/tag/v0.3.1".into(),
                prerelease: false,
            })
        );
        assert!(
            remembered_release("0.3.0-beta.1", "0.2.0-beta.2")
                .unwrap()
                .prerelease
        );
        assert_eq!(remembered_release("0.3.1", "0.3.1"), None);
        assert_eq!(remembered_release("0.3.0", "0.3.1"), None);
        assert_eq!(remembered_release("0.4.0-alpha.1", "0.3.1"), None);
        assert_eq!(remembered_release("v0.3.1", "0.2.0"), None);
        assert_eq!(remembered_release("0.3.1/../x", "0.2.0"), None);
        assert_eq!(remembered_release("0.3.1", "not a version"), None);
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

    const FEED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en-US">
  <id>tag:github.com,2008:https://github.com/eoftgge/rosetun/releases</id>
  <link type="text/html" rel="alternate" href="https://github.com/eoftgge/rosetun/releases"/>
  <link type="application/atom+xml" rel="self" href="https://github.com/eoftgge/rosetun/releases.atom"/>
  <entry>
    <link rel="alternate" type="text/html" href="https://github.com/eoftgge/rosetun/releases/tag/v0.4.0-beta.1"/>
  </entry>
  <entry>
    <link rel="alternate" type="text/html" href="https://github.com/eoftgge/rosetun/releases/tag/0.3.1"/>
  </entry>
  <entry>
    <link rel="alternate" type="text/html" href="https://github.com/eoftgge/rosetun/releases/tag/v0.3.0"/>
  </entry>
  <entry>
    <link rel="alternate" type="text/html" href="https://github.com/other/rosetun/releases/tag/v9.0.0"/>
    <link href="https://github.com/eoftgge/rosetun/releases/tag/v8.0.0/../x"/>
    <link href="https://github.com/eoftgge/rosetun/releases/tag/nightly"/>
    <link href="https://github.com/eoftgge/rosetun/releases/tag/v7.0.0
  </entry>
</feed>"#;

    #[test]
    fn the_feed_gives_tags_of_this_repository_only() {
        assert_eq!(
            parse_feed(FEED, "0.2.0"),
            Some(Release {
                version: "0.3.1".into(),
                url: "https://github.com/eoftgge/rosetun/releases/tag/0.3.1".into(),
                prerelease: false,
            })
        );
        let beta = parse_feed(FEED, "0.3.1-beta.1").unwrap();
        assert_eq!(beta.version, "0.4.0-beta.1");
        assert_eq!(
            beta.url,
            "https://github.com/eoftgge/rosetun/releases/tag/v0.4.0-beta.1"
        );
        assert!(beta.prerelease);
        assert_eq!(parse_feed(FEED, "0.3.1"), None);
    }

    #[test]
    fn a_feed_without_release_links_offers_nothing() {
        assert_eq!(parse_feed("", "0.1.0"), None);
        assert_eq!(parse_feed("not a feed href=\"", "0.1.0"), None);
        assert_eq!(parse_feed("<html>rate limited</html>", "0.1.0"), None);
    }

    #[test]
    fn the_api_and_the_feed_follow_the_same_stability_rules() {
        let tags = [
            "v0.2.0-alpha.1",
            "v0.1.0-beta.3",
            "v0.1.0-beta.2",
            "v0.1.0",
            "v0.1.1-rc.1",
        ];
        let api = format!(
            "[{}]",
            tags.map(|tag| format!(
                r#"{{"tag_name":"{tag}","html_url":"https://github.com/eoftgge/rosetun/releases/tag/{tag}","draft":false,"prerelease":{}}}"#,
                tag.contains('-')
            ))
            .join(",")
        );
        let feed = tags
            .map(|tag| {
                format!(r#"<link href="https://github.com/eoftgge/rosetun/releases/tag/{tag}"/>"#)
            })
            .join("\n");
        for current in [
            "0.0.9",
            "0.1.0-alpha.6",
            "0.1.0-beta.1",
            "0.1.0-beta.3",
            "0.1.0",
            "0.1.1-rc.1",
            "0.2.0-alpha.1",
        ] {
            assert_eq!(
                parse_releases(&api, current).unwrap(),
                parse_feed(&feed, current),
                "{current}"
            );
        }
    }

    #[test]
    fn only_a_refusal_of_the_api_asks_the_feed() {
        assert!(falls_back_to_feed(403));
        assert!(falls_back_to_feed(429));
        for status in [200, 304, 404, 500, 502, 503] {
            assert!(!falls_back_to_feed(status), "{status}");
        }
    }
}
