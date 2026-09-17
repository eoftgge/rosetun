use std::net::IpAddr;

use crate::RoutingPlan;

const ALLOW_WEIGHT: u8 = 2;
const BLOCK_WEIGHT: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    Allow,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Rule {
    pub(super) family: AddressFamily,
    pub(super) action: Action,
    pub(super) remote_address: Option<IpAddr>,
    pub(super) weight: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OutboundPolicy {
    pub(super) rules: Vec<Rule>,
}

impl OutboundPolicy {
    pub(super) fn from_plan(plan: &RoutingPlan) -> Self {
        let mut rules = Vec::with_capacity(plan.bypass.len() + 2);

        for address in &plan.bypass {
            rules.push(Rule {
                family: address_family(*address),
                action: Action::Allow,
                remote_address: Some(*address),
                weight: ALLOW_WEIGHT,
            });
        }

        rules.push(Rule {
            family: AddressFamily::Ipv4,
            action: Action::Block,
            remote_address: None,
            weight: BLOCK_WEIGHT,
        });
        rules.push(Rule {
            family: AddressFamily::Ipv6,
            action: Action::Block,
            remote_address: None,
            weight: BLOCK_WEIGHT,
        });

        Self { rules }
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{Action, AddressFamily, OutboundPolicy};
    use crate::RoutingPlan;

    #[test]
    fn creates_allow_rules_before_family_block_rules() {
        let policy = OutboundPolicy::from_plan(&RoutingPlan {
            bypass: vec![
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10)),
            ],
            kill_switch: true,
        });

        assert_eq!(policy.rules.len(), 4);

        assert_eq!(policy.rules[0].family, AddressFamily::Ipv4);
        assert_eq!(policy.rules[0].action, Action::Allow);
        assert_eq!(
            policy.rules[0].remote_address,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
        );
        assert!(policy.rules[0].weight > policy.rules[2].weight);

        assert_eq!(policy.rules[1].family, AddressFamily::Ipv6);
        assert_eq!(policy.rules[1].action, Action::Allow);
        assert_eq!(
            policy.rules[1].remote_address,
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 10
            )))
        );
        assert!(policy.rules[1].weight > policy.rules[3].weight);

        assert_eq!(policy.rules[2].family, AddressFamily::Ipv4);
        assert_eq!(policy.rules[2].action, Action::Block);
        assert_eq!(policy.rules[2].remote_address, None);

        assert_eq!(policy.rules[3].family, AddressFamily::Ipv6);
        assert_eq!(policy.rules[3].action, Action::Block);
        assert_eq!(policy.rules[3].remote_address, None);
    }

    #[test]
    fn always_blocks_both_ip_families() {
        let policy = OutboundPolicy::from_plan(&RoutingPlan {
            bypass: Vec::new(),
            kill_switch: true,
        });

        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0].family, AddressFamily::Ipv4);
        assert_eq!(policy.rules[0].action, Action::Block);
        assert_eq!(policy.rules[1].family, AddressFamily::Ipv6);
        assert_eq!(policy.rules[1].action, Action::Block);
    }
}