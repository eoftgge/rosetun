//! The sites the tunnel carried lately, offered under the address field of the rule dialog.
//! They come from the connection list the Traffic tab shows, only live, in memory: the list
//! is the user's browsing history, so nothing here is logged, saved or reported.

use std::collections::HashSet;
use std::net::IpAddr;

use rosetun_config::{DomainMatch, LiveConnection, RuleMatcher};

use super::super::{Screen, State};
use super::address::{Address, parse_address};
use super::dialog::RuleInputKind;

/// The most sites offered at once.
pub(crate) const MAX_RECENT_SITES: usize = 12;

/// One site offered in the address field.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RecentSite {
    /// The domain without a leading `www.`, or the IP address when no domain was seen.
    pub(crate) address: String,
    /// The set being edited has a rule that already covers it.
    pub(crate) has_rule: bool,
}

impl std::fmt::Debug for RecentSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecentSite")
            .field("has_rule", &self.has_rule)
            .finish_non_exhaustive()
    }
}

impl State {
    /// Whether the open rule dialog shows the recent sites, so their source is polled.
    pub(crate) fn recent_sites_wanted(&self) -> bool {
        self.screen == Screen::Rules
            && self.rules.screen.add.as_ref().is_some_and(|dialog| {
                dialog.kind == RuleInputKind::Address && dialog.editing.is_none()
            })
    }

    /// Up to `MAX_RECENT_SITES` sites, the latest first: from the active and the lately
    /// closed connections. A domain stands once whatever its `www.` prefix; an address only
    /// when no domain was seen for it. Empty without a tunnel or an answer.
    pub(crate) fn recent_sites(&self) -> Vec<RecentSite> {
        if !self.recent_sites_wanted() || !self.connections_available() {
            return Vec::new();
        }
        let list = &self.traffic.connections;
        let mut seen: Vec<(&LiveConnection, Address)> = list
            .active
            .iter()
            .chain(&list.closed)
            .filter_map(|connection| {
                let address = parse_address(connection.host.trim()).ok()?;
                Some((connection, address))
            })
            .collect();
        // An active connection is seen now, a closed one when it ended.
        seen.sort_by_key(|(connection, _)| {
            std::cmp::Reverse((
                connection.end_unix_ms.unwrap_or(u64::MAX),
                connection.start_unix_ms,
            ))
        });
        let named: HashSet<IpAddr> = seen
            .iter()
            .filter(|(_, address)| address.is_domain())
            .filter_map(|(connection, _)| connection.ip.as_deref()?.parse().ok())
            .collect();
        let mut sites: Vec<RecentSite> = Vec::new();
        let mut taken = HashSet::new();
        for (_, address) in &seen {
            let text = address.label(true);
            if let Address::Ip(_) = address
                && text.parse::<IpAddr>().is_ok_and(|ip| named.contains(&ip))
            {
                continue;
            }
            if !taken.insert(text.to_lowercase()) {
                continue;
            }
            sites.push(RecentSite {
                has_rule: self.rule_covers(&text),
                address: text,
            });
            if sites.len() == MAX_RECENT_SITES {
                break;
            }
        }
        sites
    }

    /// Whether the rules of the set being edited, and the session's temporary ones when that
    /// set is the active one, already cover `address`.
    fn rule_covers(&self, address: &str) -> bool {
        let Some(dialog) = &self.rules.screen.add else {
            return false;
        };
        let saved = self
            .config
            .rule_sets
            .iter()
            .filter(|set| set.id == dialog.set)
            .flat_map(|set| &set.rules);
        let temporary = self
            .session
            .temporary_rules
            .iter()
            .filter(|_| self.config.active_rule_set.as_ref() == Some(&dialog.set));
        saved
            .chain(temporary)
            .any(|rule| covers(&rule.matcher, address))
    }
}

/// Whether `matcher` applies to the site `address` (a domain, or an IP address).
fn covers(matcher: &RuleMatcher, address: &str) -> bool {
    let address = address.to_lowercase();
    match matcher {
        RuleMatcher::Domain(DomainMatch::Exact(domain)) => domain.to_lowercase() == address,
        RuleMatcher::Domain(DomainMatch::Suffix(suffix)) => {
            let suffix = suffix.to_lowercase();
            address == suffix || address.ends_with(&format!(".{suffix}"))
        }
        RuleMatcher::IpCidr(cidr) => {
            let single = cidr
                .strip_suffix("/32")
                .or_else(|| cidr.strip_suffix("/128"))
                .unwrap_or(cidr);
            single.to_lowercase() == address
        }
        _ => false,
    }
}
