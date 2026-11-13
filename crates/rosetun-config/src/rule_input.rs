use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Host;

use crate::DomainMatch;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleInputError {
    #[error("enter a domain such as example.com or *.example.com")]
    InvalidDomain,
    #[error("this is an IP address, not a domain")]
    IpAddress,
    #[error("enter a full domain such as example.com; use *.label for a top-level domain")]
    SingleLabel,
    #[error("enter a process name such as app.exe or a full path to it")]
    InvalidProcess,
    #[error("a process path must be absolute")]
    RelativePath,
}


#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IpCidrError {
    #[error("enter an IP address or subnet")]
    Invalid,
    #[error("subnet starts at {corrected}")]
    HostBits { corrected: String },
}


pub fn parse_ip_cidr(value: &str) -> Result<String, IpCidrError> {
    let (ip, prefix) = match value.split_once('/') {
        Some((ip, prefix)) => {
            let ip = ip.parse::<IpAddr>().map_err(|_| IpCidrError::Invalid)?;
            let prefix = prefix.parse::<u8>().map_err(|_| IpCidrError::Invalid)?;
            (ip, prefix)
        }
        None => {
            let ip = value.parse::<IpAddr>().map_err(|_| IpCidrError::Invalid)?;
            (ip, if ip.is_ipv4() { 32 } else { 128 })
        }
    };
    let network = match ip {
        IpAddr::V4(ip) if prefix <= 32 => {
            let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask))
        }
        IpAddr::V6(ip) if prefix <= 128 => {
            let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask))
        }
        _ => return Err(IpCidrError::Invalid),
    };
    let canonical = format!("{network}/{prefix}");
    if network == ip {
        Ok(canonical)
    } else {
        Err(IpCidrError::HostBits {
            corrected: canonical,
        })
    }
}


pub fn parse_domain_input(input: &str) -> Result<DomainMatch, RuleInputError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(RuleInputError::InvalidDomain);
    }

    if input.contains("://") {
        let url = url::Url::parse(input).map_err(|_| RuleInputError::InvalidDomain)?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(RuleInputError::InvalidDomain);
        }
        return match url.host() {
            Some(Host::Domain(host)) => parse_domain(host, false),
            Some(Host::Ipv4(_) | Host::Ipv6(_)) => Err(RuleInputError::IpAddress),
            None => Err(RuleInputError::InvalidDomain),
        };
    }

    let input = input.split(['/', '?', '#']).next().unwrap_or(input);
    let (host, suffix) = if let Some(host) = input.strip_prefix("*.") {
        (host, true)
    } else if let Some(host) = input.strip_prefix('.') {
        (host, true)
    } else {
        (input, false)
    };
    parse_domain(host, suffix)
}

fn parse_domain(host: &str, suffix: bool) -> Result<DomainMatch, RuleInputError> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return Err(RuleInputError::InvalidDomain);
    }
    match Host::parse(host) {
        Ok(Host::Ipv4(_) | Host::Ipv6(_)) => Err(RuleInputError::IpAddress),
        Ok(Host::Domain(domain)) => {
            if host.contains(['*', '/', ':']) || host.chars().any(char::is_whitespace) {
                return Err(RuleInputError::InvalidDomain);
            }
            if suffix {
                Ok(DomainMatch::Suffix(domain))
            } else if !domain.contains('.') {
                Err(RuleInputError::SingleLabel)
            } else {
                Ok(DomainMatch::Exact(domain))
            }
        }
        Err(_) => Err(RuleInputError::InvalidDomain),
    }
}

