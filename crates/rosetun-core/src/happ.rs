use std::collections::HashSet;

use rosetun_config::{
    DomainMatch, List, ListFormat, ListSource, Rule, RuleId, RuleMatcher, RuleSet, RuleSetId,
    RuleTarget,
};
use rosetun_subscription::{HappBucket, HappRouting};

use crate::lists::{LIST_PRESETS, ListError, add_list_from_url};
use crate::rules::{parse_domain_input, parse_ip_cidr, with_subdomains};
use crate::{Store, StoreError, Timeouts};

#[derive(Debug, thiserror::Error)]
pub enum HappImportError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    List(#[from] ListError),
    #[error("routing profile contains no supported rules")]
    NoSupportedRules,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HappImportReport {
    pub rule_set: RuleSet,
    pub added_rules: usize,
    pub skipped: usize,
    pub downloaded_lists: Vec<List>,
}

/// Imports a Happ routing profile into a new independent `RuleSet`, downloading
/// any required `geosite.dat` / `geoip.dat` lists on demand if not already present.
pub fn import_happ_routing(
    store: &Store,
    routing: &HappRouting,
    fallback_name: &str,
    activate: bool,
    timeouts: Timeouts,
) -> Result<HappImportReport, HappImportError> {
    import_happ_routing_with(
        store,
        routing,
        fallback_name,
        activate,
        |store, name, url| add_list_from_url(store, url, name, timeouts),
    )
}

pub(crate) fn import_happ_routing_with<F>(
    store: &Store,
    routing: &HappRouting,
    fallback_name: &str,
    activate: bool,
    mut fetch_list: F,
) -> Result<HappImportReport, HappImportError>
where
    F: FnMut(&Store, &str, &str) -> Result<List, ListError>,
{
    let mut downloaded_lists = Vec::new();
    let geosite_list = if routing.uses_geosite() {
        let list = ensure_geo_list(
            store,
            ListFormat::GeoSite,
            routing.geosite_url.as_deref(),
            &mut fetch_list,
            &mut downloaded_lists,
        )?;
        Some(list)
    } else {
        None
    };
    let geoip_list = if routing.uses_geoip() {
        let list = ensure_geo_list(
            store,
            ListFormat::GeoIp,
            routing.geoip_url.as_deref(),
            &mut fetch_list,
            &mut downloaded_lists,
        )?;
        Some(list)
    } else {
        None
    };

    let mut rules = Vec::new();
    let mut skipped = 0usize;
    let mut next_rule_index = 1usize;

    for bucket in routing.route_order.sequence() {
        let (target, sites, ips) = match bucket {
            HappBucket::Block => (RuleTarget::Block, &routing.block_sites, &routing.block_ips),
            HappBucket::Proxy => (RuleTarget::Proxy, &routing.proxy_sites, &routing.proxy_ips),
            HappBucket::Direct => (
                RuleTarget::Direct,
                &routing.direct_sites,
                &routing.direct_ips,
            ),
        };
        for raw in sites {
            match parse_happ_site(raw, geosite_list.as_ref()) {
                Some(matcher) => {
                    rules.push(Rule {
                        id: RuleId::new(format!("happ-{next_rule_index}")),
                        enabled: true,
                        matcher,
                        target,
                        exit: None,
                    });
                    next_rule_index += 1;
                }
                None => skipped += 1,
            }
        }
        for raw in ips {
            match parse_happ_ip(raw, geoip_list.as_ref()) {
                Some(matcher) => {
                    rules.push(Rule {
                        id: RuleId::new(format!("happ-{next_rule_index}")),
                        enabled: true,
                        matcher,
                        target,
                        exit: None,
                    });
                    next_rule_index += 1;
                }
                None => skipped += 1,
            }
        }
    }

    if rules.is_empty() {
        return Err(HappImportError::NoSupportedRules);
    }

    let default_target = if !routing.global_proxy
        && routing.direct_sites.is_empty()
        && routing.direct_ips.is_empty()
        && (!routing.proxy_sites.is_empty() || !routing.proxy_ips.is_empty())
    {
        RuleTarget::Direct
    } else {
        RuleTarget::Proxy
    };

    let base_name = routing
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .or_else(|| {
            let trimmed = fallback_name.trim();
            (!trimmed.is_empty()).then_some(trimmed)
        })
        .unwrap_or("Happ");

    let added_rules = rules.len();
    let mut created_set = None;
    store.modify(|config| {
        let name = unique_set_name(&config.rule_sets, base_name);
        let id = next_rule_set_id(&config.rule_sets);
        let mut set = RuleSet::new(id.clone(), name, default_target);
        set.rules = rules.clone();
        config.rule_sets.push(set.clone());
        if activate || config.active_rule_set.is_none() {
            config.active_rule_set = Some(id);
        }
        created_set = Some(set);
        Ok::<_, StoreError>(())
    })?;

    Ok(HappImportReport {
        rule_set: created_set.expect("created rule set"),
        added_rules,
        skipped,
        downloaded_lists,
    })
}

fn ensure_geo_list<F>(
    store: &Store,
    format: ListFormat,
    explicit_url: Option<&str>,
    fetch_list: &mut F,
    downloaded: &mut Vec<List>,
) -> Result<List, HappImportError>
where
    F: FnMut(&Store, &str, &str) -> Result<List, ListError>,
{
    let config = store.load()?;
    if let Some(url) = explicit_url {
        if let Some(existing) = config
            .lists
            .iter()
            .find(|list| list.format == format && list.source == ListSource::Url(url.to_owned()))
        {
            return Ok(existing.clone());
        }
        let default_name = match format {
            ListFormat::GeoSite => "Geosite",
            ListFormat::GeoIp => "GeoIP",
            _ => "List",
        };
        let list = fetch_list(store, default_name, url)?;
        downloaded.push(list.clone());
        return Ok(list);
    }

    if let Some(existing) = config.lists.iter().find(|list| list.format == format) {
        return Ok(existing.clone());
    }

    let preset = LIST_PRESETS
        .iter()
        .find(|preset| preset.format == format)
        .expect("default geosite/geoip preset exists");
    let list = fetch_list(store, preset.name, preset.url)?;
    downloaded.push(list.clone());
    Ok(list)
}

fn parse_happ_site(raw: &str, geosite: Option<&List>) -> Option<RuleMatcher> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if let Some(cat) = strip_prefix_ci(trimmed, &lower, "geosite:") {
        let list = geosite?;
        let category = cat.trim().to_ascii_lowercase();
        list.validate_category(Some(&category)).ok()?;
        return Some(RuleMatcher::List {
            list: list.id.clone(),
            category: Some(category),
        });
    }
    if strip_prefix_ci(trimmed, &lower, "regexp:").is_some() {
        return None;
    }
    if let Some(exact) = strip_prefix_ci(trimmed, &lower, "full:") {
        let domain = with_subdomains(parse_domain_input(exact).ok()?, false);
        return Some(RuleMatcher::Domain(domain));
    }
    if let Some(keyword) = strip_prefix_ci(trimmed, &lower, "keyword:") {
        let kw = keyword.trim().to_ascii_lowercase();
        if kw.is_empty() || kw.contains(char::is_whitespace) {
            return None;
        }
        return Some(RuleMatcher::Domain(DomainMatch::Keyword(kw)));
    }
    let domain_raw = strip_prefix_ci(trimmed, &lower, "domain:").unwrap_or(trimmed);
    let domain = with_subdomains(parse_domain_input(domain_raw).ok()?, true);
    Some(RuleMatcher::Domain(domain))
}

fn parse_happ_ip(raw: &str, geoip: Option<&List>) -> Option<RuleMatcher> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if let Some(cat) = strip_prefix_ci(trimmed, &lower, "geoip:") {
        let list = geoip?;
        let category = cat.trim().to_ascii_lowercase();
        list.validate_category(Some(&category)).ok()?;
        return Some(RuleMatcher::List {
            list: list.id.clone(),
            category: Some(category),
        });
    }
    let cidr = parse_ip_cidr(trimmed).ok()?;
    Some(RuleMatcher::IpCidr(cidr))
}

fn strip_prefix_ci<'a>(original: &'a str, lower: &str, prefix: &str) -> Option<&'a str> {
    lower.starts_with(prefix).then(|| &original[prefix.len()..])
}

fn unique_set_name(existing: &[RuleSet], base: &str) -> String {
    let taken: HashSet<&str> = existing.iter().map(|set| set.name.as_str()).collect();
    if !taken.contains(base) {
        return base.to_owned();
    }
    for index in 2..=10_000 {
        let candidate = format!("{base} ({index})");
        if !taken.contains(candidate.as_str()) {
            return candidate;
        }
    }
    format!("{base}-imported")
}

fn next_rule_set_id(existing: &[RuleSet]) -> RuleSetId {
    let taken: HashSet<&str> = existing.iter().map(|set| set.id.as_str()).collect();
    for index in 1..=100_000 {
        let candidate = format!("happ-{index}");
        if !taken.contains(candidate.as_str()) {
            return RuleSetId::new(candidate);
        }
    }
    RuleSetId::new("happ-imported")
}

#[cfg(test)]
mod tests {
    use rosetun_subscription::HappRouteOrder;

    use super::*;

    fn test_store(name: &str) -> Store {
        let path = std::env::temp_dir()
            .join(format!("rosetun-happ-{name}-{}", std::process::id()))
            .join("config.json");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        Store::at(path)
    }

    #[test]
    fn imports_happ_profile_with_geosite_geoip_and_route_order() {
        let store = test_store("basic");
        let routing = HappRouting {
            name: Some("Provider RU".into()),
            route_order: HappRouteOrder::BlockDirectProxy,
            global_proxy: false,
            geosite_url: Some("https://lists.example.com/geosite.dat".into()),
            geoip_url: None,
            direct_sites: vec![
                "geosite:category-ru".into(),
                "full:exact.example.com".into(),
                "domain:example.org".into(),
            ],
            direct_ips: vec!["geoip:ru".into(), "192.0.2.0/24".into()],
            proxy_sites: vec!["keyword:youtube".into(), "regexp:^bad.*".into()],
            proxy_ips: vec![],
            block_sites: vec!["geosite:category-ads-all".into()],
            block_ips: vec![],
        };
        let mut next_id = 1u32;
        let report =
            import_happ_routing_with(&store, &routing, "Fallback", true, |store, name, url| {
                let format = if url.contains("geoip") {
                    ListFormat::GeoIp
                } else {
                    ListFormat::GeoSite
                };
                let categories = match format {
                    ListFormat::GeoSite => {
                        vec!["category-ru".into(), "category-ads-all".into()]
                    }
                    ListFormat::GeoIp => vec!["ru".into()],
                    _ => vec![],
                };
                let list = List {
                    id: rosetun_config::ListId::new(next_id.to_string()),
                    name: name.to_owned(),
                    source: ListSource::Url(url.to_owned()),
                    format,
                    updated_at: Some(1_700_000_000),
                    size: Some(10),
                    sha256: Some("a".repeat(64)),
                    categories,
                    auto_update: true,
                };
                next_id += 1;
                store.modify(|config| {
                    config.lists.push(list.clone());
                    Ok::<_, StoreError>(())
                })?;
                Ok(list)
            })
            .unwrap();

        assert_eq!(report.rule_set.name, "Provider RU");
        assert_eq!(report.rule_set.default_target, RuleTarget::Proxy);
        assert_eq!(report.added_rules, 7);
        assert_eq!(report.skipped, 1);
        assert_eq!(report.downloaded_lists.len(), 2);
        // BlockDirectProxy order: block first, then direct, then proxy.
        assert_eq!(report.rule_set.rules[0].target, RuleTarget::Block);
        assert_eq!(report.rule_set.rules[1].target, RuleTarget::Direct);
        assert_eq!(report.rule_set.rules[6].target, RuleTarget::Proxy);
        let config = store.load().unwrap();
        assert_eq!(config.active_rule_set, Some(report.rule_set.id));
    }
}
