//! Firewall tables other programs have put redirects in (Linux): `redirect`, `tproxy` and
//! `dnat` rules send traffic somewhere else before Rosetun's chains see it. Only reported;
//! nothing here changes a rule.
//!
//! Needs the rights the service has, which is why the service looks and the GUI asks.

#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeSet;

/// Verdicts that send a packet to another address or port.
#[cfg(any(target_os = "linux", test))]
const REDIRECTING: [&str; 3] = ["redirect", "tproxy", "dnat"];
/// Chains of container runtimes: they publish container ports with `dnat` and take no
/// traffic of the host's programs, so on a machine with Docker they would only be noise.
#[cfg(any(target_os = "linux", test))]
const RUNTIME_CHAINS: [&str; 6] = ["DOCKER", "CNI-", "KUBE-", "NETAVARK", "PODMAN", "cali-"];
/// A list for a message, not for a firewall audit.
#[cfg(any(target_os = "linux", test))]
const MAX_TABLES: usize = 8;

/// The tables that redirect, such as `ip nat`: names only, never addresses.
pub(crate) fn interceptors() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        match rosetun_routing::ruleset_json() {
            Ok(json) => tables_with_redirects(&json),
            Err(error) => {
                tracing::debug!(%error, "could not read the firewall rules");
                Vec::new()
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

#[cfg(any(target_os = "linux", test))]
fn tables_with_redirects(json: &str) -> Vec<String> {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(items) = root.get("nftables").and_then(|items| items.as_array()) else {
        return Vec::new();
    };
    let mut tables = BTreeSet::new();
    for rule in items.iter().filter_map(|item| item.get("rule")) {
        let text = |key: &str| rule.get(key).and_then(|value| value.as_str()).unwrap_or("");
        let (family, table, chain) = (text("family"), text("table"), text("chain"));
        if (family == "inet" && table == "rosetun")
            || RUNTIME_CHAINS
                .iter()
                .any(|prefix| chain.starts_with(prefix))
        {
            continue;
        }
        let redirects = rule
            .get("expr")
            .and_then(|expr| expr.as_array())
            .is_some_and(|expr| {
                expr.iter().any(|statement| {
                    REDIRECTING
                        .iter()
                        .any(|verdict| statement.get(verdict).is_some())
                })
            });
        if redirects && !table.is_empty() {
            tables.insert(format!("{family} {table}"));
        }
    }
    tables.into_iter().take(MAX_TABLES).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(family: &str, table: &str, chain: &str, statement: &str) -> String {
        format!(
            r#"{{"rule":{{"family":"{family}","table":"{table}","chain":"{chain}","expr":[{{"match":{{}}}},{{"{statement}":{{}}}}]}}}}"#
        )
    }

    fn ruleset(rules: &[String]) -> String {
        format!(
            r#"{{"nftables":[{{"metainfo":{{"version":"1.1.3"}}}},{}]}}"#,
            rules.join(",")
        )
    }

    #[test]
    fn a_table_that_redirects_is_named_once() {
        let json = ruleset(&[
            rule("ip", "fw4", "dstnat", "redirect"),
            rule("ip", "fw4", "dstnat", "dnat"),
            rule("inet", "mangle", "tp", "tproxy"),
        ]);
        assert_eq!(tables_with_redirects(&json), ["inet mangle", "ip fw4"]);
    }

    #[test]
    fn our_own_table_and_container_runtimes_are_not_reported() {
        let json = ruleset(&[
            rule("inet", "rosetun", "output", "redirect"),
            rule("ip", "nat", "DOCKER", "dnat"),
            rule("ip", "nat", "CNI-HOSTPORT-DNAT", "dnat"),
            rule("ip", "filter", "forward", "accept"),
        ]);
        assert!(tables_with_redirects(&json).is_empty());
    }

    #[test]
    fn something_that_is_not_a_ruleset_says_nothing() {
        assert!(tables_with_redirects("").is_empty());
        assert!(tables_with_redirects("{}").is_empty());
        assert!(tables_with_redirects("[1,2]").is_empty());
    }

    #[test]
    fn the_list_is_short() {
        let rules: Vec<String> = (0..20)
            .map(|index| rule("ip", &format!("t{index:02}"), "c", "dnat"))
            .collect();
        assert_eq!(tables_with_redirects(&ruleset(&rules)).len(), MAX_TABLES);
    }
}
