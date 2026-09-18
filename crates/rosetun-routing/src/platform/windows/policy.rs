use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

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
    /// Matches one exact remote IPv4 or IPv6 address.
    RemoteAddress(IpAddr),
    /// Matches loopback traffic.
    Loopback,
    /// Matches the client side of DHCPv4: UDP port 68 to UDP port 67.
    DhcpV4,
    /// Matches IPv6 ICMP Neighbor Solicitation and Neighbor Advertisement.
    NeighborDiscoveryV6,
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
    /// Builds phase-1 protection, which is installed before spawning the
    /// engine. The endpoint exception is deliberately restricted to the engine
    /// executable, so no unrelated application can bypass the kill switch.
    pub(super) fn from_plan(plan: &RoutingPlan, engine_binary: &Path) -> Self {
        let mut rules = Vec::with_capacity(plan.bypass.len() + 5);

        for address in &plan.bypass {
            rules.push(Rule {
                family: address_family(*address),
                action: Action::Allow,
                conditions: vec![
                    Condition::Application(engine_binary.to_owned()),
                    Condition::RemoteAddress(*address),
                ],
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
            Rule {
                family: AddressFamily::Ipv6,
                action: Action::Allow,
                conditions: vec![Condition::NeighborDiscoveryV6],
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

fn address_family(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::Ipv4,
        IpAddr::V6(_) => AddressFamily::Ipv6,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::Path,
    };

    use super::{
        Action, AddressFamily, BootstrapPolicy, Condition, tunnel_authorization,
    };
    use crate::RoutingPlan;

    fn plan() -> RoutingPlan {
        RoutingPlan {
            bypass: vec![
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10)),
            ],
            kill_switch: true,
        }
    }

    #[test]
    fn endpoint_access_is_restricted_to_the_engine_binary() {
        let engine = Path::new(r"C:\Program Files\Rosetun\sing-box.exe");
        let policy = BootstrapPolicy::from_plan(&plan(), engine);

        assert_eq!(
            policy.rules[0].conditions,
            vec![
                Condition::Application(engine.to_owned()),
                Condition::RemoteAddress(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            ]
        );
        assert_eq!(
            policy.rules[1].conditions,
            vec![
                Condition::Application(engine.to_owned()),
                Condition::RemoteAddress(IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 0, 0, 0, 0, 10
                ))),
            ]
        );
    }

    #[test]
    fn bootstrap_policy_allows_required_local_network_traffic_then_blocks_both_families() {
        let policy = BootstrapPolicy::from_plan(&plan(), Path::new(r"C:\sing-box.exe"));

        assert_eq!(policy.rules.len(), 8);

        assert_eq!(policy.rules[2].conditions, vec![Condition::Loopback]);
        assert_eq!(policy.rules[3].conditions, vec![Condition::Loopback]);
        assert_eq!(policy.rules[4].conditions, vec![Condition::DhcpV4]);
        assert_eq!(
            policy.rules[5].conditions,
            vec![Condition::NeighborDiscoveryV6]
        );

        assert_eq!(policy.rules[6].family, AddressFamily::Ipv4);
        assert_eq!(policy.rules[6].action, Action::Block);
        assert!(policy.rules[6].conditions.is_empty());

        assert_eq!(policy.rules[7].family, AddressFamily::Ipv6);
        assert_eq!(policy.rules[7].action, Action::Block);
        assert!(policy.rules[7].conditions.is_empty());

        for rule in &policy.rules[..6] {
            assert!(rule.weight > policy.rules[6].weight);
            assert!(rule.weight > policy.rules[7].weight);
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