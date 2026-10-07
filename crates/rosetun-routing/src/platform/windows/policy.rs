use std::path::{Path, PathBuf};

use crate::{ProtectionScope, RoutingPlan};

const TUNNEL_WEIGHT: u8 = 4;
const PRIVATE_DNS_BLOCK_WEIGHT: u8 = 3;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Subnet {
    V4 { address: [u8; 4], prefix: u8 },
    V6 { address: [u8; 16], prefix: u8 },
}

impl Subnet {
    pub(super) fn family(self) -> AddressFamily {
        match self {
            Self::V4 { .. } => AddressFamily::Ipv4,
            Self::V6 { .. } => AddressFamily::Ipv6,
        }
    }
}

const LAN_SUBNETS: [Subnet; 6] = [
    Subnet::V4 {
        address: [10, 0, 0, 0],
        prefix: 8,
    },
    Subnet::V4 {
        address: [172, 16, 0, 0],
        prefix: 12,
    },
    Subnet::V4 {
        address: [192, 168, 0, 0],
        prefix: 16,
    },
    Subnet::V4 {
        address: [169, 254, 0, 0],
        prefix: 16,
    },
    Subnet::V6 {
        address: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        prefix: 10,
    },
    Subnet::V6 {
        address: [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        prefix: 7,
    },
];

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
    /// Matches the validated engine-created TUN local-interface LUID.
    LocalInterface(u64),
    RemoteSubnet(Subnet),
    Protocol(u8),
    RemotePort(u16),
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
    pub(super) fn from_plan(plan: &RoutingPlan, engine_binary: &Path) -> Self {
        match plan.scope {
            ProtectionScope::AllTraffic => Self::all_traffic(plan.allow_lan, engine_binary),
            ProtectionScope::DnsOnly => Self::dns_only(engine_binary),
        }
    }

    fn all_traffic(allow_lan: bool, engine_binary: &Path) -> Self {
        let mut rules = common_rules(engine_binary);
        rules.push(Rule {
            family: AddressFamily::Ipv4,
            action: Action::Allow,
            conditions: vec![Condition::DhcpV4],
            weight: BOOTSTRAP_ALLOW_WEIGHT,
        });

        if allow_lan {
            for subnet in LAN_SUBNETS {
                rules.push(Rule {
                    family: subnet.family(),
                    action: Action::Allow,
                    conditions: vec![Condition::RemoteSubnet(subnet)],
                    weight: BOOTSTRAP_ALLOW_WEIGHT,
                });

                // IP protocol numbers: UDP = 17, TCP = 6.
                for protocol in [17, 6] {
                    rules.push(Rule {
                        family: subnet.family(),
                        action: Action::Block,
                        conditions: vec![
                            Condition::RemoteSubnet(subnet),
                            Condition::Protocol(protocol),
                            Condition::RemotePort(53),
                        ],
                        weight: PRIVATE_DNS_BLOCK_WEIGHT,
                    });
                }
            }
        }

        rules.extend([
            block_rule(AddressFamily::Ipv4),
            block_rule(AddressFamily::Ipv6),
        ]);

        Self { rules }
    }

    fn dns_only(engine_binary: &Path) -> Self {
        let mut rules = common_rules(engine_binary);
        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            for protocol in [17, 6] {
                rules.push(Rule {
                    family,
                    action: Action::Block,
                    conditions: vec![Condition::Protocol(protocol), Condition::RemotePort(53)],
                    weight: BLOCK_WEIGHT,
                });
            }
        }
        Self { rules }
    }
}

fn common_rules(engine_binary: &Path) -> Vec<Rule> {
    // The engine's own requests follow its routing rules, as with the kill switch.
    let mut rules = Vec::with_capacity(4);
    for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
        rules.push(Rule {
            family,
            action: Action::Allow,
            conditions: vec![Condition::Application(engine_binary.to_owned())],
            weight: BOOTSTRAP_ALLOW_WEIGHT,
        });
    }

    // A local resolver is not a leak; its outbound requests face the same filter.
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
    ]);
    rules
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

    use super::{
        Action, AddressFamily, BootstrapPolicy, Condition, Rule, Subnet, tunnel_authorization,
    };
    use crate::{ProtectionScope, RoutingPlan};

    fn plan() -> RoutingPlan {
        RoutingPlan {
            scope: ProtectionScope::AllTraffic,
            allow_lan: false,
        }
    }

    /// What WFP does with a non-engine IPv4 connection: the heaviest matching
    /// rule decides; with no match the traffic leaves this sublayer allowed.
    fn decide(rules: &[&Rule], destination: [u8; 4], protocol: u8, port: u16, luid: u64) -> Action {
        rules
            .iter()
            .filter(|rule| {
                rule.family == AddressFamily::Ipv4
                    && rule.conditions.iter().all(|condition| match condition {
                        Condition::RemoteSubnet(Subnet::V4 { address, prefix }) => {
                            let mask = u32::MAX << (32 - *prefix);
                            u32::from_be_bytes(destination) & mask
                                == u32::from_be_bytes(*address) & mask
                        }
                        Condition::Protocol(value) => *value == protocol,
                        Condition::RemotePort(value) => *value == port,
                        Condition::LocalInterface(value) => *value == luid,
                        _ => false,
                    })
            })
            .max_by_key(|rule| rule.weight)
            .map_or(Action::Allow, |rule| rule.action)
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

    #[test]
    fn lan_dns_and_tunnel_have_the_required_priority() {
        let bootstrap = BootstrapPolicy::from_plan(
            &RoutingPlan {
                scope: ProtectionScope::AllTraffic,
                allow_lan: true,
            },
            Path::new(r"C:\sing-box.exe"),
        );
        let authorization = tunnel_authorization(123);
        let rules: Vec<_> = bootstrap.rules.iter().chain(&authorization).collect();

        for protocol in [17, 6] {
            assert_eq!(
                decide(&rules, [172, 19, 0, 2], protocol, 53, 123),
                Action::Allow
            );
            assert_eq!(
                decide(&rules, [172, 19, 0, 2], protocol, 53, 999),
                Action::Block
            );
            assert_eq!(
                decide(&rules, [192, 168, 3, 1], protocol, 53, 999),
                Action::Block
            );
        }
        assert_eq!(decide(&rules, [192, 168, 3, 1], 6, 80, 999), Action::Allow);
        assert_eq!(decide(&rules, [100, 64, 0, 1], 6, 80, 999), Action::Block);
        assert_eq!(decide(&rules, [1, 1, 1, 1], 6, 443, 999), Action::Block);

        let dns_blocks: Vec<_> = bootstrap
            .rules
            .iter()
            .filter(|rule| {
                rule.conditions
                    .iter()
                    .any(|condition| matches!(condition, Condition::RemotePort(53)))
            })
            .collect();
        assert_eq!(dns_blocks.len(), 12);

        for dns in dns_blocks {
            assert_eq!(dns.action, Action::Block);
            assert!(authorization.iter().all(|tun| tun.weight > dns.weight));
            assert!(
                bootstrap
                    .rules
                    .iter()
                    .filter(|rule| rule.action == Action::Allow)
                    .all(|allow| dns.weight > allow.weight)
            );
        }
    }

    #[test]
    fn lan_subnets_are_exact_and_opt_in() {
        let engine = Path::new(r"C:\sing-box.exe");
        let disabled = BootstrapPolicy::from_plan(&plan(), engine);
        assert!(disabled.rules.iter().all(|rule| {
            rule.conditions
                .iter()
                .all(|condition| !matches!(condition, Condition::RemoteSubnet(_)))
        }));

        let enabled = BootstrapPolicy::from_plan(
            &RoutingPlan {
                scope: ProtectionScope::AllTraffic,
                allow_lan: true,
            },
            engine,
        );
        let permits: Vec<_> = enabled
            .rules
            .iter()
            .filter_map(|rule| match (rule.action, rule.conditions.as_slice()) {
                (Action::Allow, [Condition::RemoteSubnet(subnet)]) => Some(*subnet),
                _ => None,
            })
            .collect();

        assert_eq!(permits, super::LAN_SUBNETS);
        assert_eq!(enabled.rules.len(), 25);
    }

    #[test]
    fn dns_only_confines_port_53_to_the_tunnel() {
        let engine = Path::new(r"C:\sing-box.exe");
        let policy = BootstrapPolicy::from_plan(
            &RoutingPlan {
                scope: ProtectionScope::DnsOnly,
                allow_lan: false,
            },
            engine,
        );
        assert_eq!(policy.rules.len(), 8);
        assert!(policy.rules.iter().all(|rule| !rule.conditions.is_empty()));
        for rule in &policy.rules[..2] {
            assert_eq!(rule.conditions, [Condition::Application(engine.to_owned())]);
            assert_eq!(rule.action, Action::Allow);
        }

        let authorization = tunnel_authorization(123);
        let rules: Vec<_> = policy.rules.iter().chain(&authorization).collect();
        for protocol in [17, 6] {
            assert_eq!(
                decide(&rules, [172, 19, 0, 2], protocol, 53, 123),
                Action::Allow
            );
            for destination in [[1, 1, 1, 1], [192, 168, 3, 1]] {
                assert_eq!(
                    decide(&rules, destination, protocol, 53, 999),
                    Action::Block
                );
            }
        }
        assert_eq!(decide(&rules, [1, 1, 1, 1], 6, 443, 999), Action::Allow);
        assert_eq!(decide(&rules, [1, 1, 1, 1], 17, 443, 999), Action::Allow);
        assert_eq!(decide(&rules, [1, 1, 1, 1], 6, 853, 999), Action::Allow);
        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            let blocks: Vec<_> = policy
                .rules
                .iter()
                .filter(|rule| rule.family == family && rule.action == Action::Block)
                .collect();
            assert_eq!(blocks.len(), 2);
            for block in blocks {
                assert!(matches!(
                    block.conditions.as_slice(),
                    [Condition::Protocol(17 | 6), Condition::RemotePort(53)]
                ));
                assert!(authorization.iter().all(|tun| tun.weight > block.weight));
                assert!(
                    policy.rules[..4]
                        .iter()
                        .all(|allow| allow.weight > block.weight)
                );
            }
        }
    }

    #[test]
    fn dns_only_ignores_allow_lan() {
        let plan = RoutingPlan {
            scope: ProtectionScope::DnsOnly,
            allow_lan: false,
        };
        let engine = Path::new(r"C:\sing-box.exe");
        let disabled = BootstrapPolicy::from_plan(&plan, engine);
        let enabled = BootstrapPolicy::from_plan(
            &RoutingPlan {
                allow_lan: true,
                ..plan
            },
            engine,
        );
        assert_eq!(disabled, enabled);
    }
}
