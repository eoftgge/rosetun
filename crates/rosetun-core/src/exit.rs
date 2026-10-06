use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

use ureq::tls::{RootCerts, TlsConfig};

use crate::fetch::DEFAULT_USER_AGENT;

const TRACE_URL: &str = "https://1.1.1.1/cdn-cgi/trace";
const MAX_BODY_BYTES: u64 = 16 * 1024;

/// Where traffic leaves for the internet: the address the world sees and its country.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInfo {
    pub ip: IpAddr,
    /// ISO 3166-1 alpha-2, upper case.
    pub country: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExitInfoError {
    #[error("request failed: {0}")]
    Request(String),
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("unexpected answer")]
    Parse,
}

/// Asks Cloudflare's trace endpoint.
pub fn exit_info(timeout: Duration) -> Result<ExitInfo, ExitInfoError> {
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .https_only(true)
        .http_status_as_error(false)
        .build()
        .into();

    // ureq errors can contain the request URI; never forward them to the GUI or log.
    let mut response = agent
        .get(TRACE_URL)
        .header("User-Agent", DEFAULT_USER_AGENT)
        .call()
        .map_err(|_| ExitInfoError::Request("connection failed".into()))?;
    if response.status().as_u16() != 200 {
        return Err(ExitInfoError::Status(response.status().as_u16()));
    }

    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(MAX_BODY_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| ExitInfoError::Request("response read failed".into()))?;
    if body.len() as u64 > MAX_BODY_BYTES {
        return Err(ExitInfoError::Parse);
    }
    parse_trace(std::str::from_utf8(&body).map_err(|_| ExitInfoError::Parse)?)
        .ok_or(ExitInfoError::Parse)
}

fn parse_trace(body: &str) -> Option<ExitInfo> {
    let mut ip = None;
    let mut country = None;
    for line in body.lines() {
        match line.split_once('=') {
            Some(("ip", value)) => ip = Some(value),
            Some(("loc", value)) => country = Some(value),
            _ => {}
        }
    }
    let ip = ip?.parse().ok()?;
    let country = country
        .filter(|value| value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_alphabetic()));
    let country = country
        .map(str::to_ascii_uppercase)
        .filter(|value| value != "XX");
    Some(ExitInfo { ip, country })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{ExitInfo, parse_trace};

    #[test]
    fn parses_a_trace_response() {
        assert_eq!(
            parse_trace(
                "fl=abc\nh=1.1.1.1\nip=203.0.113.7\nts=123\ncolo=AMS\nloc=NL\ntls=TLSv1.3\n"
            ),
            Some(ExitInfo {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                country: Some("NL".into()),
            })
        );
    }

    #[test]
    fn parses_ipv6() {
        assert_eq!(
            parse_trace("ip=2001:db8::7\nloc=NL"),
            Some(ExitInfo {
                ip: IpAddr::V6("2001:db8::7".parse::<Ipv6Addr>().unwrap()),
                country: Some("NL".into()),
            })
        );
    }

    #[test]
    fn uppercases_country() {
        assert_eq!(
            parse_trace("ip=203.0.113.7\nloc=nl")
                .unwrap()
                .country
                .as_deref(),
            Some("NL")
        );
    }

    #[test]
    fn unknown_country_is_omitted() {
        assert_eq!(parse_trace("ip=203.0.113.7\nloc=XX").unwrap().country, None);
        assert_eq!(parse_trace("ip=203.0.113.7\nloc=T1").unwrap().country, None);
    }

    #[test]
    fn rejects_long_country_codes() {
        assert_eq!(
            parse_trace("ip=203.0.113.7\nloc=NLD").unwrap().country,
            None
        );
    }

    #[test]
    fn rejects_missing_ip() {
        assert_eq!(parse_trace("loc=NL"), None);
    }

    #[test]
    fn rejects_invalid_ip() {
        assert_eq!(parse_trace("ip=garbage\nloc=NL"), None);
    }
}
