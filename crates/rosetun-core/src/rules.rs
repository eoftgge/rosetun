use std::collections::BTreeSet;
use std::path::PathBuf;

use rosetun_config::{
    AppConfig, DomainMatch, ProcessMatch, Rule, RuleId, RuleMatcher, RuleSet, RuleSetId, RuleTarget,
};
use url::Host;

use crate::{Store, StoreError};

#[derive(Debug, thiserror::Error)]
pub enum RuleSetError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("rule set does not exist")]
    SetNotFound,
    #[error("rule does not exist")]
    RuleNotFound,
    #[error("rule set name must not be empty")]
    EmptyName,
    #[error("this rule is already in the set")]
    DuplicateRule,
}

fn next_id<'a>(ids: impl Iterator<Item = &'a str>) -> String {
    let occupied: BTreeSet<_> = ids.collect();
    let mut candidate = 1_u64;
    loop {
        let value = candidate.to_string();
        if !occupied.contains(value.as_str()) {
            return value;
        }
        candidate += 1;
    }
}

fn rule_set_mut<'a>(
    config: &'a mut AppConfig,
    id: &RuleSetId,
) -> Result<&'a mut RuleSet, RuleSetError> {
    config
        .rule_sets
        .iter_mut()
        .find(|set| &set.id == id)
        .ok_or(RuleSetError::SetNotFound)
}

fn rule_mut<'a>(set: &'a mut RuleSet, id: &RuleId) -> Result<&'a mut Rule, RuleSetError> {
    set.rules
        .iter_mut()
        .find(|rule| &rule.id == id)
        .ok_or(RuleSetError::RuleNotFound)
}

pub fn create_rule_set(
    store: &Store,
    name: &str,
    default_target: RuleTarget,
) -> Result<RuleSet, RuleSetError> {
    store.modify(|config| {
        let name = name.trim();
        if name.is_empty() {
            return Err(RuleSetError::EmptyName);
        }

        let id = RuleSetId::new(next_id(config.rule_sets.iter().map(|set| set.id.as_str())));
        let set = RuleSet::new(id.clone(), name, default_target);
        if config.rule_sets.is_empty() && config.active_rule_set.is_none() {
            config.active_rule_set = Some(id);
        }
        config.rule_sets.push(set.clone());
        Ok(set)
    })
}

pub fn rename_rule_set(store: &Store, id: &RuleSetId, name: &str) -> Result<(), RuleSetError> {
    store.modify(|config| {
        let set = rule_set_mut(config, id)?;
        let name = name.trim();
        if name.is_empty() {
            return Err(RuleSetError::EmptyName);
        }
        set.name = name.to_owned();
        Ok(())
    })
}

pub fn delete_rule_set(store: &Store, id: &RuleSetId) -> Result<(), RuleSetError> {
    store.modify(|config| {
        let index = config
            .rule_sets
            .iter()
            .position(|set| &set.id == id)
            .ok_or(RuleSetError::SetNotFound)?;
        config.rule_sets.remove(index);
        if config.active_rule_set.as_ref() == Some(id) {
            config.active_rule_set = None;
        }
        Ok(())
    })
}

pub fn set_default_target(
    store: &Store,
    id: &RuleSetId,
    target: RuleTarget,
) -> Result<(), RuleSetError> {
    store.modify(|config| {
        rule_set_mut(config, id)?.default_target = target;
        Ok(())
    })
}

pub fn add_rule(
    store: &Store,
    set: &RuleSetId,
    matcher: RuleMatcher,
    target: RuleTarget,
) -> Result<Rule, RuleSetError> {
    store.modify(|config| {
        let set = rule_set_mut(config, set)?;
        if set.rules.iter().any(|rule| rule.matcher == matcher) {
            return Err(RuleSetError::DuplicateRule);
        }

        let rule = Rule {
            id: RuleId::new(next_id(set.rules.iter().map(|rule| rule.id.as_str()))),
            enabled: true,
            matcher,
            target,
        };
        set.rules.insert(0, rule.clone());
        Ok(rule)
    })
}

pub fn set_rule_target(
    store: &Store,
    set: &RuleSetId,
    rule: &RuleId,
    target: RuleTarget,
) -> Result<(), RuleSetError> {
    store.modify(|config| {
        rule_mut(rule_set_mut(config, set)?, rule)?.target = target;
        Ok(())
    })
}

pub fn set_rule_enabled(
    store: &Store,
    set: &RuleSetId,
    rule: &RuleId,
    enabled: bool,
) -> Result<(), RuleSetError> {
    store.modify(|config| {
        rule_mut(rule_set_mut(config, set)?, rule)?.enabled = enabled;
        Ok(())
    })
}

pub fn move_rule(
    store: &Store,
    set: &RuleSetId,
    rule: &RuleId,
    to_index: usize,
) -> Result<(), RuleSetError> {
    store.modify(|config| {
        let set = rule_set_mut(config, set)?;
        let index = set
            .rules
            .iter()
            .position(|item| &item.id == rule)
            .ok_or(RuleSetError::RuleNotFound)?;
        let rule = set.rules.remove(index);
        set.rules.insert(to_index.min(set.rules.len()), rule);
        Ok(())
    })
}

pub fn remove_rule(store: &Store, set: &RuleSetId, rule: &RuleId) -> Result<(), RuleSetError> {
    store.modify(|config| {
        let set = rule_set_mut(config, set)?;
        let index = set
            .rules
            .iter()
            .position(|item| &item.id == rule)
            .ok_or(RuleSetError::RuleNotFound)?;
        set.rules.remove(index);
        Ok(())
    })
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleInputError {
    #[error("enter a domain such as example.com or *.example.com")]
    InvalidDomain,
    #[error("this is an IP address, not a domain")]
    IpAddress,
    #[error("enter a process name such as app.exe or a full path to it")]
    InvalidProcess,
    #[error("a process path must be absolute")]
    RelativePath,
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
            } else {
                Ok(DomainMatch::Exact(domain))
            }
        }
        Err(_) => Err(RuleInputError::InvalidDomain),
    }
}

pub fn parse_process_input(input: &str) -> Result<ProcessMatch, RuleInputError> {
    let input = input.trim();
    let input = input
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(input);
    if input.is_empty() {
        return Err(RuleInputError::InvalidProcess);
    }

    if input.contains(['\\', '/']) {
        let bytes = input.as_bytes();
        let absolute = input.starts_with('/')
            || input.starts_with("\\\\")
            || (bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'\\' | b'/'));
        if !absolute {
            return Err(RuleInputError::RelativePath);
        }
        Ok(ProcessMatch::Path(PathBuf::from(input)))
    } else if input.contains(['<', '>', ':', '"', '|', '?', '*']) {
        Err(RuleInputError::InvalidProcess)
    } else {
        Ok(ProcessMatch::Name(input.to_owned()))
    }
}

pub fn rule_value_text(matcher: &RuleMatcher) -> String {
    match matcher {
        RuleMatcher::Domain(DomainMatch::Exact(domain)) => domain.clone(),
        RuleMatcher::Domain(DomainMatch::Suffix(domain)) => format!("*.{domain}"),
        RuleMatcher::Domain(DomainMatch::Keyword(keyword)) => format!("contains \"{keyword}\""),
        RuleMatcher::Process(ProcessMatch::Name(name)) => name.clone(),
        RuleMatcher::Process(ProcessMatch::Path(path)) => path.to_string_lossy().into_owned(),
        RuleMatcher::IpCidr(cidr) => cidr.clone(),
    }
}

#[cfg(test)]
mod tests;
