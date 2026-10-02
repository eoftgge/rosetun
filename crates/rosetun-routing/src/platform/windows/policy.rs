use std::path::{Path, PathBuf};

use crate::RoutingPlan;

const TUNNEL_WEIGHT: u8 = 3;
const BOOTSTRAP_ALLOW_WEIGHT: u8 = 2;
const BLOCK_WEIGHT: u8 = 1;

/// Network family used by an outbound WFP layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AddressFamily {
    Ipv4,
    Ipv6,
}

/// WFP action to apply when every condition in a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    Allow,
    Block,
}

/// A platform-neutral representation of a WFP filter condition.
///
/// Conditions within one rule are combined with logical AND.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Condition {
    /// Limits endpoint access to the selected engine executable.
    Application(PathBuf),
    /// Matches loopback traffic.
    Loopback,
    /// Matches the client side of DHCPv4: UDP port 68 to UDP port 67.
    DhcpV4,
    /// Matches traffic whose local interface is the engine-created TUN adapter.
    ///
    /// This is the opaque `NET_LUID` value consumed later by
    /// `FWPM_CONDITION_IP_LOCAL_INTERFACE`.
    LocalInterface(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Rule {
    pub(super) family: AddressFamily,
    pub(super) action: Action,
    pub(super) conditions: Vec<Condition>,
    pub(super) weight: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BootstrapPolicy {
    pub(super) rules: Vec<Rule>,
}

impl BootstrapPolicy {
    /// Builds phase-1 protection before spawning the engine.
    ///
    /// The engine enforces routing policy and may reach any destination.
    /// WFP identifies the exemption by executable path, not by process ID.
    pub(super) fn from_plan(_plan: &RoutingPlan, engine_binary: &Path) -> Self {
        let mut rules = Vec::with_capacity(7);

        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            rules.push(Rule {
                family,
                action: Action::Allow,
                conditions: vec![Condition::Application(engine_binary.to_owned())],
                weight: BOOTSTRAP_ALLOW_WEIGHT,
            });
        }

        rules.extend([
            Rule {
                family: AddressFamily::Ipv4,
                action: Action::Allow,
                conditions: vec![Condition::Loopback],
                weight: BOOTSTRAP_ALLOW_WEIGHT,
            },
            Rule {
                family: AddressFamily::Ipv6,
                action: Action::Allow,
                conditions: vec![Condition::Loopback],
                weight: BOOTSTRAP_ALLOW_WEIGHT,
            },
            Rule {
                family: AddressFamily::Ipv4,
                action: Action::Allow,
                conditions: vec![Condition::DhcpV4],
                weight: BOOTSTRAP_ALLOW_WEIGHT,
            },
            block_rule(AddressFamily::Ipv4),
            block_rule(AddressFamily::Ipv6),
        ]);

        Self { rules }
    }
}

/// Builds the phase-2 authorization added after the TUN adapter has been
/// discovered and validated. This is intentionally separate from bootstrap
/// policy because its LUID does not exist before the engine starts.
pub(super) fn tunnel_authorization(luid: u64) -> [Rule; 2] {
    [
        Rule {
            family: AddressFamily::Ipv4,
            action: Action::Allow,
            conditions: vec![Condition::LocalInterface(luid)],
            weight: TUNNEL_WEIGHT,
        },
        Rule {
            family: AddressFamily::Ipv6,
            action: Action::Allow,
            conditions: vec![Condition::LocalInterface(luid)],
            weight: TUNNEL_WEIGHT,
        },
    ]
}

fn block_rule(family: AddressFamily) -> Rule {
    Rule {
        family,
        action: Action::Block,
        conditions: Vec::new(),
        weight: BLOCK_WEIGHT,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{Action, AddressFamily, BootstrapPolicy, Condition, tunnel_authorization};
    use crate::RoutingPlan;

    fn plan() -> RoutingPlan {
        RoutingPlan { kill_switch: true }
    }

    #[test]
    fn endpoint_access_is_restricted_to_the_engine_binary() {
        let engine = Path::new(r"C:\Program Files\Rosetun\sing-box.exe");
        let policy = BootstrapPolicy::from_plan(&plan(), engine);

        assert_eq!(
            policy.rules[0].conditions,
            vec![Condition::Application(engine.to_owned()),]
        );
        assert_eq!(
            policy.rules[1].conditions,
            vec![Condition::Application(engine.to_owned()),]
        );
    }

    #[test]
    fn bootstrap_policy_allows_required_local_network_traffic_then_blocks_both_families() {
        let policy = BootstrapPolicy::from_plan(&plan(), Path::new(r"C:\sing-box.exe"));

        assert_eq!(policy.rules.len(), 7);

        assert_eq!(policy.rules[2].conditions, vec![Condition::Loopback]);
        assert_eq!(policy.rules[3].conditions, vec![Condition::Loopback]);
        assert_eq!(policy.rules[4].conditions, vec![Condition::DhcpV4]);

        assert_eq!(policy.rules[5].family, AddressFamily::Ipv4);
        assert_eq!(policy.rules[5].action, Action::Block);
        assert!(policy.rules[5].conditions.is_empty());

        assert_eq!(policy.rules[6].family, AddressFamily::Ipv6);
        assert_eq!(policy.rules[6].action, Action::Block);
        assert!(policy.rules[6].conditions.is_empty());

        for rule in &policy.rules[..5] {
            assert!(rule.weight > policy.rules[5].weight);
            assert!(rule.weight > policy.rules[6].weight);
        }
    }

    #[test]
    fn phase_two_tunnel_rules_have_higher_priority_than_bootstrap_rules() {
        let bootstrap = BootstrapPolicy::from_plan(&plan(), Path::new(r"C:\sing-box.exe"));
        let authorization = tunnel_authorization(0x1234_5678);

        assert_eq!(authorization[0].family, AddressFamily::Ipv4);
        assert_eq!(
            authorization[0].conditions,
            vec![Condition::LocalInterface(0x1234_5678)]
        );
        assert_eq!(authorization[1].family, AddressFamily::Ipv6);
        assert_eq!(
            authorization[1].conditions,
            vec![Condition::LocalInterface(0x1234_5678)]
        );

        assert!(authorization[0].weight > bootstrap.rules[0].weight);
        assert!(authorization[1].weight > bootstrap.rules[1].weight);
    }
}
