//! What the address field of the rule dialog takes: domains, IPv4 and IPv6 addresses and
//! subnets in one input, each item's kind found from its text.

use rosetun_config::{DomainMatch, RuleMatcher};
use rosetun_core::{IpCidrError, IpLineError, IpLines, RuleInputError};

/// The characters between items: they may be typed, pasted or come one per line.
pub(crate) const ADDRESS_SEPARATORS: [char; 6] = [' ', ',', ';', '\n', '\r', '\t'];

/// The most items one dialog adds. A temporary rule is one of the service's
/// `MAX_TEMPORARY_RULES`, so more could never be applied at once.
pub(crate) const MAX_ADDRESSES: usize = rosetun_ipc::MAX_TEMPORARY_RULES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Address {
    /// As typed: `with_subdomains` turns it into the stored form.
    Domain(DomainMatch),
    /// The canonical `address/prefix`.
    Ip(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AddressError {
    Domain(RuleInputError),
    Ip(IpCidrError),
}

impl Address {
    pub(crate) fn is_domain(&self) -> bool {
        matches!(self, Self::Domain(_))
    }

    pub(crate) fn matcher(&self, subdomains: bool) -> RuleMatcher {
        match self {
            Self::Domain(domain) => {
                RuleMatcher::Domain(rosetun_core::with_subdomains(domain.clone(), subdomains))
            }
            Self::Ip(cidr) => RuleMatcher::IpCidr(cidr.clone()),
        }
    }

    /// The text of the item as it will be stored: a domain in Unicode without `*.` when
    /// subdomains are on anyway, a single address without its full-length prefix.
    pub(crate) fn label(&self, subdomains: bool) -> String {
        match self {
            Self::Domain(_) => {
                let text = rosetun_core::rule_value_text(&self.matcher(subdomains));
                if subdomains {
                    text.strip_prefix("*.")
                        .map_or_else(|| text.clone(), str::to_owned)
                } else {
                    text
                }
            }
            Self::Ip(cidr) => cidr
                .strip_suffix("/32")
                .filter(|ip| ip.contains('.'))
                .or_else(|| cidr.strip_suffix("/128").filter(|ip| ip.contains(':')))
                .unwrap_or(cidr)
                .to_owned(),
        }
    }
}

/// One item of the field: the text as it came, and what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddressChip {
    pub(crate) text: String,
    pub(crate) parsed: Result<Address, AddressError>,
}

impl AddressChip {
    pub(crate) fn new(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            parsed: parse_address(text),
        }
    }

    /// The same rule as `other`, or the same bad text.
    pub(crate) fn repeats(&self, other: &Self, subdomains: bool) -> bool {
        match (&self.parsed, &other.parsed) {
            (Ok(this), Ok(other)) => this.matcher(subdomains) == other.matcher(subdomains),
            (Err(_), Err(_)) => self.text.eq_ignore_ascii_case(&other.text),
            _ => false,
        }
    }
}

/// The items of `text`, split at any of `ADDRESS_SEPARATORS`.
pub(crate) fn split_addresses(text: &str) -> impl Iterator<Item = &str> {
    text.split(ADDRESS_SEPARATORS)
        .filter(|item| !item.is_empty())
}

/// One item: an address or subnet when it reads as one, else a domain, a site's link or
/// `*.zone`.
pub(crate) fn parse_address(item: &str) -> Result<Address, AddressError> {
    match rosetun_core::parse_ip_cidr(item) {
        Ok(cidr) => return Ok(Address::Ip(cidr)),
        Err(error @ IpCidrError::HostBits { .. }) => return Err(AddressError::Ip(error)),
        Err(IpCidrError::Invalid) => {}
    }
    match rosetun_core::parse_domain_input(item) {
        // The URL host parser keeps empty labels; no site has one.
        Ok(DomainMatch::Exact(domain) | DomainMatch::Suffix(domain))
            if domain.split('.').any(str::is_empty) =>
        {
            Err(AddressError::Domain(RuleInputError::InvalidDomain))
        }
        Ok(domain) => Ok(Address::Domain(domain)),
        // An address with a bad prefix, or a link to one.
        Err(RuleInputError::IpAddress) => Err(AddressError::Ip(IpCidrError::Invalid)),
        Err(error) => Err(AddressError::Domain(error)),
    }
}

/// The rules for `addresses`, each once, in their order.
pub(crate) fn address_matchers<'a>(
    addresses: impl IntoIterator<Item = &'a Address>,
    subdomains: bool,
) -> Vec<RuleMatcher> {
    let mut matchers: Vec<RuleMatcher> = Vec::new();
    for address in addresses {
        let matcher = address.matcher(subdomains);
        if !matchers.contains(&matcher) {
            matchers.push(matcher);
        }
    }
    matchers
}

/// Whether any address, or a subnet that only needs its host bits cleared, is on a local
/// network, where traffic does not enter the tunnel.
pub(crate) fn has_local_address<'a>(
    parsed: impl IntoIterator<Item = &'a Result<Address, AddressError>>,
) -> bool {
    let mut lines = IpLines::default();
    for item in parsed {
        match item {
            Ok(Address::Ip(cidr)) => lines.addresses.push(cidr.clone()),
            Err(AddressError::Ip(error @ IpCidrError::HostBits { .. })) => {
                lines.errors.push(IpLineError {
                    line: 0,
                    error: error.clone(),
                });
            }
            _ => {}
        }
    }
    rosetun_core::ip_lines_have_local_address(&lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<Result<Address, AddressError>> {
        split_addresses(text).map(parse_address).collect()
    }

    #[test]
    fn a_pasted_mix_splits_into_domains_addresses_and_subnets() {
        let parsed = kinds(
            "youtube.com, 192.0.2.1\n198.51.100.0/24; 2001:db8::1 https://www.example.com/path",
        );
        assert_eq!(
            parsed,
            [
                Ok(Address::Domain(DomainMatch::Exact("youtube.com".into()))),
                Ok(Address::Ip("192.0.2.1/32".into())),
                Ok(Address::Ip("198.51.100.0/24".into())),
                Ok(Address::Ip("2001:db8::1/128".into())),
                Ok(Address::Domain(DomainMatch::Exact(
                    "www.example.com".into()
                ))),
            ]
        );
        assert_eq!(
            parsed[4].as_ref().unwrap().matcher(true),
            RuleMatcher::Domain(DomainMatch::Suffix("example.com".into()))
        );
        let labels: Vec<_> = parsed
            .iter()
            .map(|item| item.as_ref().unwrap().label(true))
            .collect();
        assert_eq!(
            labels,
            [
                "youtube.com",
                "192.0.2.1",
                "198.51.100.0/24",
                "2001:db8::1",
                "example.com"
            ]
        );
    }

    #[test]
    fn a_domain_is_stored_in_punycode_shown_in_unicode_and_keeps_an_explicit_zone() {
        let domain = parse_address("xn--e1afmkfd.example").unwrap();
        assert_eq!(domain.label(true), "пример.example");
        assert_eq!(
            parse_address("пример.example").unwrap().matcher(true),
            RuleMatcher::Domain(DomainMatch::Suffix("xn--e1afmkfd.example".into()))
        );
        let zone = parse_address("*.example").unwrap();
        assert_eq!(zone.label(false), "*.example");
        assert_eq!(
            zone.matcher(false),
            RuleMatcher::Domain(DomainMatch::Suffix("example".into()))
        );
        let www = parse_address("www.example.com").unwrap();
        assert_eq!(www.label(false), "www.example.com");
        assert_eq!(www.label(true), "example.com");
        assert_eq!(
            www.matcher(false),
            RuleMatcher::Domain(DomainMatch::Exact("www.example.com".into()))
        );
    }

    #[test]
    fn bad_items_say_which_kind_they_failed_as() {
        assert_eq!(
            parse_address("bad..domain"),
            Err(AddressError::Domain(RuleInputError::InvalidDomain))
        );
        assert_eq!(
            parse_address("example"),
            Err(AddressError::Domain(RuleInputError::SingleLabel))
        );
        assert_eq!(
            parse_address("198.51.100.0/33"),
            Err(AddressError::Ip(IpCidrError::Invalid))
        );
        assert_eq!(
            parse_address("192.0.2.5/24"),
            Err(AddressError::Ip(IpCidrError::HostBits {
                corrected: "192.0.2.0/24".into()
            }))
        );
    }

    #[test]
    fn matchers_follow_the_subdomain_choice_and_drop_repeats() {
        let parsed: Vec<_> = kinds("https://www.example.com/a example.com 192.0.2.1 192.0.2.1/32")
            .into_iter()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            address_matchers(&parsed, true),
            [
                RuleMatcher::Domain(DomainMatch::Suffix("example.com".into())),
                RuleMatcher::IpCidr("192.0.2.1/32".into()),
            ]
        );
        assert_eq!(
            address_matchers(&parsed, false),
            [
                RuleMatcher::Domain(DomainMatch::Exact("www.example.com".into())),
                RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
                RuleMatcher::IpCidr("192.0.2.1/32".into()),
            ]
        );
    }

    #[test]
    fn a_chip_repeats_another_by_its_rule_or_by_its_bad_text() {
        let chip = AddressChip::new;
        assert!(chip("www.example.com").repeats(&chip("https://example.com/a"), true));
        assert!(!chip("www.example.com").repeats(&chip("example.com"), false));
        assert!(chip("192.0.2.1").repeats(&chip("192.0.2.1/32"), true));
        assert!(chip("Bad..Domain").repeats(&chip("bad..domain"), true));
        assert!(!chip("bad..domain").repeats(&chip("example.com"), true));
    }

    #[test]
    fn local_addresses_include_subnets_with_host_bits() {
        assert!(!has_local_address(&kinds("192.0.2.1 example.com")));
        assert!(has_local_address(&kinds("192.168.1.5/24")));
        assert!(has_local_address(&kinds("fd00::1")));
    }
}
