use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rosetun_config::{IpPrefix, LINK_LOCAL_V4, LINK_LOCAL_V6};

use crate::lan::{LanAccess, MAX_SERVERS_PER_NETWORK};
use crate::{ProtectionScope, RoutingPlan};

pub(super) const TUNNEL_WEIGHT: u8 = 4;
pub(super) const PRIVATE_DNS_BLOCK_WEIGHT: u8 = 3;
pub(super) const BOOTSTRAP_ALLOW_WEIGHT: u8 = 2;
pub(super) const BLOCK_WEIGHT: u8 = 1;

/// Network family used by an outbound WFP layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AddressFamily {
    Ipv4,
    Ipv6,
}

/// The ALE layer a rule is added to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Layer {
    /// `ALE_AUTH_CONNECT`: outbound connections.
    Connect,
    /// `ALE_AUTH_RECV_ACCEPT`: inbound connections, used by Lockdown only.
    RecvAccept,
}

/// WFP action to apply when every condition in a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    Allow,
    Block,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Subnet {
    V4 { address: [u8; 4], prefix: u8 },
    V6 { address: [u8; 16], prefix: u8 },
}

/// A public network tells where the computer is, and conditions go to the
/// debug log.
impl std::fmt::Debug for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = self.prefix();
        if prefix.is_private() {
            write!(f, "Subnet({prefix})")
        } else {
            f.write_str("Subnet(public)")
        }
    }
}

impl Subnet {
    pub(super) fn family(self) -> AddressFamily {
        match self {
            Self::V4 { .. } => AddressFamily::Ipv4,
            Self::V6 { .. } => AddressFamily::Ipv6,
        }
    }

    fn prefix(self) -> IpPrefix {
        let (address, length) = match self {
            Self::V4 { address, prefix } => (IpAddr::from(address), prefix),
            Self::V6 { address, prefix } => (IpAddr::from(address), prefix),
        };
        IpPrefix::new(address, length).expect("a subnet's length fits its family")
    }
}

impl From<IpPrefix> for Subnet {
    fn from(prefix: IpPrefix) -> Self {
        match prefix.address() {
            IpAddr::V4(address) => Self::V4 {
                address: address.octets(),
                prefix: prefix.length(),
            },
            IpAddr::V6(address) => Self::V6 {
                address: address.octets(),
                prefix: prefix.length(),
            },
        }
    }
}

/// "Private networks behind the router": every private range, on any
/// adapter.
pub(super) const LAN_SUBNETS: [Subnet; 6] = [
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

/// Remote addresses from `low` to `high`, both included, of one family.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct AddressRange {
    pub(super) low: IpAddr,
    pub(super) high: IpAddr,
}

/// The bounds tell where a VPN server is, and conditions go to the debug log.
impl std::fmt::Debug for AddressRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AddressRange(..)")
    }
}

/// IP protocol numbers of the private DNS block, in this order: UDP, TCP.
pub(super) const DNS_PROTOCOLS: [u8; 2] = [17, 6];

/// A platform-neutral representation of a WFP filter condition.
///
/// Conditions within one rule are combined with logical AND.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Condition {
    /// Limits endpoint access to the selected engine executable.
    Application(PathBuf),
    /// Matches processes running as the account of this process: SYSTEM for
    /// the service, the user who started it in console mode. The engines
    /// inherit its token, so a user who starts the same executable does not
    /// match.
    ServiceAccount,
    /// Matches loopback traffic.
    Loopback,
    /// Matches the client side of DHCPv4: UDP port 68 to UDP port 67. At the
    /// receive layer the ports are the same, so it matches the server's replies.
    DhcpV4,
    /// Matches the validated engine-created TUN local-interface LUID, or a
    /// physical adapter's. WFP joins conditions on the same field with OR,
    /// so several of them match any of these adapters.
    LocalInterface(u64),
    RemoteSubnet(Subnet),
    /// Like `LocalInterface`, several of them match any of these ranges.
    RemoteRange(AddressRange),
    Protocol(u8),
    RemotePort(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Rule {
    pub(super) family: AddressFamily,
    pub(super) layer: Layer,
    pub(super) action: Action,
    pub(super) conditions: Vec<Condition>,
    pub(super) weight: u8,
}

impl Rule {
    pub(super) fn allow(family: AddressFamily, conditions: Vec<Condition>, weight: u8) -> Self {
        Self {
            family,
            layer: Layer::Connect,
            action: Action::Allow,
            conditions,
            weight,
        }
    }

    pub(super) fn block(family: AddressFamily, conditions: Vec<Condition>, weight: u8) -> Self {
        Self {
            action: Action::Block,
            ..Self::allow(family, conditions, weight)
        }
    }

    pub(super) fn inbound(self) -> Self {
        Self {
            layer: Layer::RecvAccept,
            ..self
        }
    }
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
    pub(super) fn from_plan(plan: &RoutingPlan, engine_binaries: &[&Path]) -> Self {
        match plan.scope {
            ProtectionScope::AllTraffic => {
                Self::all_traffic(plan.allow_lan.then_some(&plan.lan), engine_binaries)
            }
            ProtectionScope::DnsOnly => Self::dns_only(engine_binaries),
        }
    }

    fn all_traffic(lan: Option<&LanAccess>, engine_binaries: &[&Path]) -> Self {
        let mut rules = common_rules(engine_binaries);
        rules.push(Rule::allow(
            AddressFamily::Ipv4,
            vec![Condition::DhcpV4],
            BOOTSTRAP_ALLOW_WEIGHT,
        ));

        if let Some(lan) = lan {
            rules.extend(lan_rules(lan).into_iter().map(|(_, rule)| rule));
        }

        rules.extend([
            Rule::block(AddressFamily::Ipv4, Vec::new(), BLOCK_WEIGHT),
            Rule::block(AddressFamily::Ipv6, Vec::new(), BLOCK_WEIGHT),
        ]);

        Self { rules }
    }

    fn dns_only(engine_binaries: &[&Path]) -> Self {
        let mut rules = common_rules(engine_binaries);
        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            for protocol in DNS_PROTOCOLS {
                rules.push(Rule::block(
                    family,
                    vec![Condition::Protocol(protocol), Condition::RemotePort(53)],
                    BLOCK_WEIGHT,
                ));
            }
        }
        Self { rules }
    }
}

/// What a LAN rule stands for, so Lockdown can give each its own key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LanRule {
    /// The permit for one connected network, on its adapter.
    Segment(IpPrefix),
    /// The DNS block of one connected network, `[UDP, TCP]` by index.
    SegmentDns(IpPrefix, usize),
    /// A link-local network, on every physical adapter.
    LinkLocal(IpPrefix),
    LinkLocalDns(IpPrefix, usize),
    /// One of `LAN_SUBNETS`, on any adapter.
    Private(usize),
    PrivateDns(usize, usize),
}

/// The connect-layer rules of "Local network": the computer's own segment,
/// each network only on its adapter; link-local networks on the physical
/// adapters; with "Private networks behind the router" also every private
/// range on any adapter. DNS to each of them is blocked above the permits.
pub(super) fn lan_rules(lan: &LanAccess) -> Vec<(LanRule, Rule)> {
    let mut rules = Vec::new();
    for network in lan.segment.networks() {
        let destination = segment_destination(network.prefix, lan.segment.left_out());
        // A permit with no address condition would open the whole adapter.
        if destination.is_empty() {
            continue;
        }
        let family = Subnet::from(network.prefix).family();
        let mut permit = destination.clone();
        permit.push(Condition::LocalInterface(network.interface.0));
        rules.push((
            LanRule::Segment(network.prefix),
            Rule::allow(family, permit, BOOTSTRAP_ALLOW_WEIGHT),
        ));
        for (index, block) in dns_blocks(family, &destination).into_iter().enumerate() {
            rules.push((LanRule::SegmentDns(network.prefix, index), block));
        }
    }
    let interfaces: Vec<u64> = lan.segment.interfaces().iter().map(|id| id.0).collect();
    for prefix in link_local(lan.ipv6_multicast) {
        let family = Subnet::from(prefix).family();
        let destination = bounded_destination(prefix, &lan.servers);
        // Without a physical adapter there is nothing to permit on, and a
        // permit without the interface condition would open every adapter.
        if !interfaces.is_empty() && !destination.is_empty() {
            let mut permit = destination.clone();
            permit.extend(
                interfaces
                    .iter()
                    .map(|&luid| Condition::LocalInterface(luid)),
            );
            rules.push((
                LanRule::LinkLocal(prefix),
                Rule::allow(family, permit, BOOTSTRAP_ALLOW_WEIGHT),
            ));
        }
        for (index, block) in dns_blocks(family, &whole_if_empty(destination, prefix))
            .into_iter()
            .enumerate()
        {
            rules.push((LanRule::LinkLocalDns(prefix, index), block));
        }
    }
    if lan.private_networks {
        for (index, subnet) in LAN_SUBNETS.into_iter().enumerate() {
            let prefix = subnet.prefix();
            let destination = bounded_destination(prefix, &lan.servers);
            if !destination.is_empty() {
                rules.push((
                    LanRule::Private(index),
                    Rule::allow(subnet.family(), destination.clone(), BOOTSTRAP_ALLOW_WEIGHT),
                ));
            }
            for (protocol, block) in
                dns_blocks(subnet.family(), &whole_if_empty(destination, prefix))
                    .into_iter()
                    .enumerate()
            {
                rules.push((LanRule::PrivateDns(index, protocol), block));
            }
        }
    }
    rules
}

/// `segment_destination` for a range that no scan looked at: past the limit of
/// servers it has no destination, and so no permit.
fn bounded_destination(prefix: IpPrefix, servers: &[IpAddr]) -> Vec<Condition> {
    let inside = servers
        .iter()
        .filter(|server| prefix.contains(**server))
        .count();
    if inside > MAX_SERVERS_PER_NETWORK {
        tracing::warn!(
            "local network: a private range holds too many VPN servers and stays closed"
        );
        return Vec::new();
    }
    segment_destination(prefix, servers)
}

/// A range without a permit keeps its DNS block whole: nothing else is open
/// there, and an empty condition list would block all DNS everywhere.
fn whole_if_empty(destination: Vec<Condition>, prefix: IpPrefix) -> Vec<Condition> {
    if destination.is_empty() {
        vec![Condition::RemoteSubnet(prefix.into())]
    } else {
        destination
    }
}

/// A LAN resolver must not become a DNS leak, so DNS there is blocked above
/// the permit; the tunnel permit still outranks it. The block also outranks
/// the engine's permit, so with a server's address in it an engine could not
/// reach a server on port 53. Without it, other programs still hit the block
/// of everything else.
fn dns_blocks(family: AddressFamily, destination: &[Condition]) -> [Rule; 2] {
    DNS_PROTOCOLS.map(|protocol| {
        let mut block = destination.to_vec();
        block.extend([Condition::Protocol(protocol), Condition::RemotePort(53)]);
        Rule::block(family, block, PRIVATE_DNS_BLOCK_WEIGHT)
    })
}

/// The remote-address conditions of a connected network: the whole network,
/// or the ranges around the VPN servers in it.
///
/// A permit that does not match is why a server's address stays closed: other
/// programs fall to the block of everything else, while the engine keeps its
/// own permit. A block on the address at a higher weight would decide for the
/// engine too, since only the heaviest matching filter counts. All ranges sit
/// in one filter, so the number of filters and Lockdown's keys do not change.
/// Should Windows ever take the conditions as AND, the permit would match
/// nothing, which is closed.
fn segment_destination(prefix: IpPrefix, left_out: &[IpAddr]) -> Vec<Condition> {
    if !left_out.iter().any(|address| prefix.contains(*address)) {
        return vec![Condition::RemoteSubnet(prefix.into())];
    }
    prefix
        .ranges_without(left_out)
        .into_iter()
        .map(|(low, high)| Condition::RemoteRange(AddressRange { low, high }))
        .collect()
}

/// The link-local networks "Local network" opens. IPv6 link-local
/// multicast only when the tunnel carries IPv6: otherwise sing-box blocks
/// all IPv6 while it runs, and mDNS and SSDP work over IPv4 anyway.
pub(super) fn link_local(ipv6_multicast: bool) -> impl Iterator<Item = IpPrefix> {
    let multicast_v6 = LINK_LOCAL_V6[1];
    LINK_LOCAL_V4
        .into_iter()
        .chain(LINK_LOCAL_V6)
        .filter(move |prefix| ipv6_multicast || *prefix != multicast_v6)
}

/// The conditions of an engine permit: the program, run by the service.
pub(super) fn engine_permit(binary: &Path) -> Vec<Condition> {
    vec![
        Condition::Application(binary.to_owned()),
        Condition::ServiceAccount,
    ]
}

fn common_rules(engine_binaries: &[&Path]) -> Vec<Rule> {
    // Each process in the selected chain dials under its own app ID.
    let mut rules = Vec::with_capacity(engine_binaries.len() * 2 + 2);
    for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
        for binary in engine_binaries {
            rules.push(Rule::allow(
                family,
                engine_permit(binary),
                BOOTSTRAP_ALLOW_WEIGHT,
            ));
        }
    }

    // A local resolver is not a leak; its outbound requests face the same filter.
    rules.extend(
        [AddressFamily::Ipv4, AddressFamily::Ipv6]
            .map(|family| Rule::allow(family, vec![Condition::Loopback], BOOTSTRAP_ALLOW_WEIGHT)),
    );
    rules
}

pub(super) fn probe_authorization(binary: &Path) -> [Rule; 2] {
    [AddressFamily::Ipv4, AddressFamily::Ipv6]
        .map(|family| Rule::allow(family, engine_permit(binary), BOOTSTRAP_ALLOW_WEIGHT))
}

/// Builds the phase-2 authorization added after the TUN adapter has been
/// discovered and validated. This is intentionally separate from bootstrap
/// policy because its LUID does not exist before the engine starts.
///
/// Under Lockdown inbound is blocked too, so the tunnel is also permitted at
/// the receive layer.
pub(super) fn tunnel_authorization(luid: u64, lockdown: bool) -> Vec<Rule> {
    let outbound = [AddressFamily::Ipv4, AddressFamily::Ipv6]
        .map(|family| Rule::allow(family, vec![Condition::LocalInterface(luid)], TUNNEL_WEIGHT));
    let mut rules = outbound.to_vec();
    if lockdown {
        rules.extend(outbound.map(Rule::inbound));
    }
    rules
}

#[cfg(test)]
pub(super) mod tests {
    use std::net::IpAddr;
    use std::path::Path;

    use super::{
        Action, AddressFamily, BootstrapPolicy, Condition, Layer, Rule, Subnet,
        tunnel_authorization,
    };
    use rosetun_config::IpPrefix;

    use crate::lan::{InterfaceId, LanAccess, LanSegment, SegmentNetwork};
    use crate::{ProtectionScope, RoutingPlan};

    fn plan() -> RoutingPlan {
        RoutingPlan {
            scope: ProtectionScope::AllTraffic,
            allow_lan: false,
            lan: Default::default(),
            lockdown: false,
        }
    }

    fn decide(rules: &[&Rule], destination: [u8; 4], protocol: u8, port: u16, luid: u64) -> Action {
        decide_at(Layer::Connect, rules, destination, protocol, port, luid)
    }

    /// What WFP does with a non-engine, non-loopback IPv4 connection at one
    /// layer: the heaviest matching rule decides; with no match the traffic
    /// leaves this sublayer allowed.
    pub(in crate::platform::windows) fn decide_at(
        layer: Layer,
        rules: &[&Rule],
        destination: [u8; 4],
        protocol: u8,
        port: u16,
        luid: u64,
    ) -> Action {
        decide_for(None, layer, rules, destination, protocol, port, luid)
    }

    /// A program making a connection, and whether it runs as the service's
    /// account (started by the service) or as a user.
    #[derive(Debug, Clone, Copy)]
    pub(in crate::platform::windows) struct Process<'a> {
        pub(in crate::platform::windows) path: &'a Path,
        pub(in crate::platform::windows) service_account: bool,
    }

    /// `decide_at` for a connection made by `process`.
    pub(in crate::platform::windows) fn decide_for(
        process: Option<Process<'_>>,
        layer: Layer,
        rules: &[&Rule],
        destination: [u8; 4],
        protocol: u8,
        port: u16,
        luid: u64,
    ) -> Action {
        rules
            .iter()
            .filter(|rule| {
                // Conditions on the interface are joined with OR.
                let mut interfaces =
                    rule.conditions
                        .iter()
                        .filter_map(|condition| match condition {
                            Condition::LocalInterface(value) => Some(*value),
                            _ => None,
                        });
                let interface_matches = rule
                    .conditions
                    .iter()
                    .all(|condition| !matches!(condition, Condition::LocalInterface(_)))
                    || interfaces.any(|value| value == luid);
                // So are conditions on the remote address.
                let target = u32::from_be_bytes(destination);
                let mut ranges = rule
                    .conditions
                    .iter()
                    .filter_map(|condition| match condition {
                        Condition::RemoteRange(range) => Some(range),
                        _ => None,
                    })
                    .peekable();
                let range_matches = ranges.peek().is_none()
                    || ranges.any(|range| match (range.low, range.high) {
                        (IpAddr::V4(low), IpAddr::V4(high)) => {
                            (low.to_bits()..=high.to_bits()).contains(&target)
                        }
                        _ => false,
                    });
                rule.family == AddressFamily::Ipv4
                    && rule.layer == layer
                    && interface_matches
                    && range_matches
                    && rule.conditions.iter().all(|condition| match condition {
                        Condition::RemoteRange(_) => true,
                        Condition::RemoteSubnet(Subnet::V4 { address, prefix }) => {
                            let mask = u32::MAX << (32 - *prefix);
                            u32::from_be_bytes(destination) & mask
                                == u32::from_be_bytes(*address) & mask
                        }
                        Condition::Protocol(value) => *value == protocol,
                        Condition::RemotePort(value) => *value == port,
                        Condition::LocalInterface(_) => true,
                        Condition::Application(path) => {
                            process.is_some_and(|process| process.path == path)
                        }
                        Condition::ServiceAccount => {
                            process.is_some_and(|process| process.service_account)
                        }
                        _ => false,
                    })
            })
            .max_by_key(|rule| rule.weight)
            .map_or(Action::Allow, |rule| rule.action)
    }

    #[test]
    fn xray_is_authorized_only_for_the_chain_and_loopback_stays_available() {
        let singbox = Path::new(r"C:\Program Files\Rosetun\sing-box.exe");
        let xray = Path::new(r"C:\Program Files\Rosetun\xray.exe");
        let plain = BootstrapPolicy::from_plan(&plan(), &[singbox]);
        let chained = BootstrapPolicy::from_plan(&plan(), &[singbox, xray]);
        assert!(!plain.rules.iter().any(|rule| {
            rule.conditions
                .contains(&Condition::Application(xray.to_owned()))
        }));
        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            assert!(chained.rules.iter().any(|rule| {
                rule.family == family
                    && rule.action == Action::Allow
                    && rule.conditions == super::engine_permit(xray)
            }));
            assert!(chained.rules.iter().any(|rule| {
                rule.family == family
                    && rule.action == Action::Allow
                    && rule.conditions == [Condition::Loopback]
            }));
        }
    }

    #[test]
    fn temporary_probe_permit_uses_only_xray_app_id() {
        let xray = Path::new(r"C:\Program Files\Rosetun\xray.exe");
        let [ipv4, ipv6] = super::probe_authorization(xray);
        assert_eq!(ipv4.family, AddressFamily::Ipv4);
        assert_eq!(ipv6.family, AddressFamily::Ipv6);
        for rule in [ipv4, ipv6] {
            assert_eq!(rule.action, Action::Allow);
            assert_eq!(rule.conditions, super::engine_permit(xray));
            assert!(rule.weight > super::BLOCK_WEIGHT);
        }
    }

    #[test]
    fn endpoint_access_is_restricted_to_the_engine_binary_run_by_the_service() {
        let engine = Path::new(r"C:\Program Files\Rosetun\sing-box.exe");
        let policy = BootstrapPolicy::from_plan(&plan(), &[engine]);

        for rule in &policy.rules[..2] {
            assert_eq!(
                rule.conditions,
                [
                    Condition::Application(engine.to_owned()),
                    Condition::ServiceAccount
                ]
            );
        }
        let rules = policy.rules.iter().collect::<Vec<_>>();
        let decide = |service_account| {
            decide_for(
                Some(Process {
                    path: engine,
                    service_account,
                }),
                Layer::Connect,
                &rules,
                [203, 0, 113, 7],
                6,
                443,
                0,
            )
        };
        assert_eq!(decide(true), Action::Allow);
        assert_eq!(decide(false), Action::Block);
    }

    #[test]
    fn bootstrap_policy_allows_required_local_network_traffic_then_blocks_both_families() {
        let policy = BootstrapPolicy::from_plan(&plan(), &[Path::new(r"C:\sing-box.exe")]);

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
        let bootstrap = BootstrapPolicy::from_plan(&plan(), &[Path::new(r"C:\sing-box.exe")]);
        let authorization = tunnel_authorization(0x1234_5678, false);

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

    /// The segment 192.0.2.0/24 on adapter 7, adapters 7 and 8 physical.
    fn lan(private_networks: bool) -> LanAccess {
        LanAccess {
            segment: LanSegment::from_parts(
                vec![SegmentNetwork {
                    prefix: IpPrefix::new("192.0.2.0".parse().unwrap(), 24).unwrap(),
                    interface: InterfaceId(7),
                }],
                vec![InterfaceId(7), InterfaceId(8)],
            ),
            private_networks,
            ipv6_multicast: false,
            servers: Vec::new(),
        }
    }

    fn lan_plan(private_networks: bool) -> RoutingPlan {
        RoutingPlan {
            scope: ProtectionScope::AllTraffic,
            allow_lan: true,
            lan: lan(private_networks),
            lockdown: false,
        }
    }

    #[test]
    fn lan_dns_and_tunnel_have_the_required_priority() {
        let bootstrap =
            BootstrapPolicy::from_plan(&lan_plan(true), &[Path::new(r"C:\sing-box.exe")]);
        let authorization = tunnel_authorization(123, false);
        let rules: Vec<_> = bootstrap.rules.iter().chain(&authorization).collect();

        for protocol in [17, 6] {
            assert_eq!(
                decide(&rules, [172, 19, 0, 2], protocol, 53, 123),
                Action::Allow
            );
            for destination in [[172, 19, 0, 2], [192, 168, 3, 1], [192, 0, 2, 1]] {
                assert_eq!(decide(&rules, destination, protocol, 53, 7), Action::Block);
            }
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
        // The segment, five link-local networks and six private ranges.
        assert_eq!(dns_blocks.len(), 2 * (1 + 5 + 6));

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
    fn the_segment_is_open_only_on_its_adapter_and_link_local_only_on_physical_ones() {
        let engine = Path::new(r"C:\sing-box.exe");
        let disabled = BootstrapPolicy::from_plan(&plan(), &[engine]);
        assert!(disabled.rules.iter().all(|rule| {
            rule.conditions
                .iter()
                .all(|condition| !matches!(condition, Condition::RemoteSubnet(_)))
        }));
        let without_lan = BootstrapPolicy::from_plan(
            &RoutingPlan {
                lan: lan(true),
                ..plan()
            },
            &[engine],
        );
        assert_eq!(without_lan, disabled);

        let enabled = BootstrapPolicy::from_plan(&lan_plan(false), &[engine]);
        let rules: Vec<_> = enabled.rules.iter().collect();
        for (destination, protocol, port, luid, action) in [
            ([192, 0, 2, 10], 6, 7575, 7, Action::Allow),
            ([192, 0, 2, 10], 6, 7575, 8, Action::Block),
            ([192, 0, 2, 10], 6, 7575, 999, Action::Block),
            ([169, 254, 1, 1], 6, 80, 8, Action::Allow),
            ([224, 0, 0, 251], 17, 5353, 7, Action::Allow),
            ([224, 0, 0, 251], 17, 5353, 999, Action::Block),
            ([239, 255, 255, 250], 17, 1900, 8, Action::Allow),
            ([255, 255, 255, 255], 17, 9, 7, Action::Allow),
            ([239, 1, 2, 3], 17, 5000, 7, Action::Block),
            ([192, 168, 3, 101], 6, 7575, 7, Action::Block),
            ([10, 1, 2, 3], 6, 445, 7, Action::Block),
        ] {
            assert_eq!(
                decide(&rules, destination, protocol, port, luid),
                action,
                "{destination:?} on {luid}"
            );
        }
        // No LAN permit leaves the interface out.
        assert!(enabled.rules.iter().all(|rule| {
            rule.action == Action::Block
                || !rule
                    .conditions
                    .iter()
                    .any(|condition| matches!(condition, Condition::RemoteSubnet(_)))
                || rule
                    .conditions
                    .iter()
                    .any(|condition| matches!(condition, Condition::LocalInterface(_)))
        }));

        let private = BootstrapPolicy::from_plan(&lan_plan(true), &[engine]);
        let permits: Vec<_> = private
            .rules
            .iter()
            .filter_map(|rule| match (rule.action, rule.conditions.as_slice()) {
                (Action::Allow, [Condition::RemoteSubnet(subnet)]) => Some(*subnet),
                _ => None,
            })
            .collect();
        assert_eq!(permits, super::LAN_SUBNETS);
        let rules: Vec<_> = private.rules.iter().collect();
        assert_eq!(
            decide(&rules, [192, 168, 3, 101], 6, 7575, 999),
            Action::Allow
        );
    }

    /// `lan_plan(false)` with VPN servers at 192.0.2.1 and 192.0.2.200.
    fn plan_with_servers() -> RoutingPlan {
        let mut plan = lan_plan(false);
        plan.lan.segment = plan.lan.segment.leaving_out(&[
            "192.0.2.1".parse().unwrap(),
            "192.0.2.200".parse().unwrap(),
            "203.0.113.5".parse().unwrap(),
        ]);
        plan
    }

    #[test]
    fn the_segment_opens_without_the_servers_and_the_engine_still_reaches_them() {
        let engine = Path::new(r"C:\sing-box.exe");
        let policy = BootstrapPolicy::from_plan(&plan_with_servers(), &[engine]);
        let rules: Vec<_> = policy.rules.iter().collect();

        for (destination, action) in [
            ([192, 0, 2, 0], Action::Allow),
            ([192, 0, 2, 1], Action::Block),
            ([192, 0, 2, 2], Action::Allow),
            ([192, 0, 2, 199], Action::Allow),
            ([192, 0, 2, 200], Action::Block),
            ([192, 0, 2, 201], Action::Allow),
            ([192, 0, 2, 255], Action::Allow),
            ([203, 0, 113, 5], Action::Block),
        ] {
            assert_eq!(
                decide(&rules, destination, 6, 7575, 7),
                action,
                "{destination:?}"
            );
        }
        // The ranges are still on this adapter only.
        assert_eq!(decide(&rules, [192, 0, 2, 10], 6, 7575, 8), Action::Block);

        // A server on any port, DNS's included, is open to the engine alone.
        for port in [443, 53] {
            for (service_account, action) in [(true, Action::Allow), (false, Action::Block)] {
                let reach = decide_for(
                    Some(Process {
                        path: engine,
                        service_account,
                    }),
                    Layer::Connect,
                    &rules,
                    [192, 0, 2, 1],
                    6,
                    port,
                    7,
                );
                assert_eq!(reach, action, "port {port}, service {service_account}");
            }
        }

        // DNS to the other devices stays blocked, to the server by the rest.
        for destination in [[192, 0, 2, 10], [192, 0, 2, 1]] {
            for protocol in [17, 6] {
                assert_eq!(
                    decide(&rules, destination, protocol, 53, 7),
                    Action::Block,
                    "{destination:?}"
                );
            }
        }
    }

    #[test]
    fn no_range_of_any_filter_covers_a_server() {
        let policy = BootstrapPolicy::from_plan(&plan_with_servers(), &[Path::new("C:\\e.exe")]);
        let server: IpAddr = "192.0.2.1".parse().unwrap();
        for rule in &policy.rules {
            for condition in &rule.conditions {
                if let Condition::RemoteRange(range) = condition {
                    assert!(
                        !(range.low..=range.high).contains(&server),
                        "{:?} covers the server",
                        rule.action
                    );
                }
            }
        }
    }

    #[test]
    fn a_segment_without_servers_keeps_its_filters_as_they_were() {
        let engine = Path::new(r"C:\sing-box.exe");
        let plain = BootstrapPolicy::from_plan(&lan_plan(false), &[engine]);
        let mut elsewhere = lan_plan(false);
        elsewhere.lan.segment = elsewhere
            .lan
            .segment
            .leaving_out(&["203.0.113.5".parse().unwrap()]);
        assert_eq!(BootstrapPolicy::from_plan(&elsewhere, &[engine]), plain);
    }

    /// Private networks on, with a VPN server at 192.168.3.1 behind the router.
    fn private_plan_with(servers: &[&str]) -> RoutingPlan {
        let mut plan = lan_plan(true);
        plan.lan.servers = crate::lan::canonical_servers(
            &servers
                .iter()
                .map(|server| server.parse().unwrap())
                .collect::<Vec<IpAddr>>(),
        );
        plan
    }

    #[test]
    fn private_networks_open_without_the_server_and_the_engine_still_reaches_it() {
        let engine = Path::new(r"C:\sing-box.exe");
        let policy = BootstrapPolicy::from_plan(&private_plan_with(&["192.168.3.1"]), &[engine]);
        let rules: Vec<_> = policy.rules.iter().collect();
        for (destination, port, action) in [
            ([192, 168, 3, 0], 7575, Action::Allow),
            ([192, 168, 3, 1], 7575, Action::Block),
            ([192, 168, 3, 2], 7575, Action::Allow),
            ([10, 1, 2, 3], 7575, Action::Allow),
            // DNS to the neighbours stays blocked, to the server by the rest.
            ([192, 168, 3, 2], 53, Action::Block),
            ([192, 168, 3, 1], 53, Action::Block),
        ] {
            assert_eq!(
                decide(&rules, destination, 6, port, 999),
                action,
                "{destination:?}:{port}"
            );
        }
        for port in [443, 53] {
            let reach = decide_for(
                Some(Process {
                    path: engine,
                    service_account: true,
                }),
                Layer::Connect,
                &rules,
                [192, 168, 3, 1],
                6,
                port,
                999,
            );
            assert_eq!(reach, Action::Allow, "port {port}");
        }
    }

    #[test]
    fn a_public_server_leaves_private_networks_as_they_were() {
        let engine = Path::new(r"C:\sing-box.exe");
        assert_eq!(
            BootstrapPolicy::from_plan(&private_plan_with(&["203.0.113.5"]), &[engine]),
            BootstrapPolicy::from_plan(&lan_plan(true), &[engine])
        );
    }

    #[test]
    fn a_link_local_server_is_left_out_on_the_physical_adapters() {
        let engine = Path::new(r"C:\sing-box.exe");
        let mut plan = lan_plan(false);
        plan.lan.servers = vec!["169.254.3.4".parse().unwrap()];
        let policy = BootstrapPolicy::from_plan(&plan, &[engine]);
        let rules: Vec<_> = policy.rules.iter().collect();
        assert_eq!(decide(&rules, [169, 254, 3, 4], 6, 80, 7), Action::Block);
        assert_eq!(decide(&rules, [169, 254, 3, 5], 6, 80, 7), Action::Allow);
        assert_eq!(decide(&rules, [169, 254, 3, 5], 6, 80, 999), Action::Block);
    }

    #[test]
    fn a_private_range_with_too_many_servers_stays_closed_with_its_dns_block() {
        let engine = Path::new(r"C:\sing-box.exe");
        let servers: Vec<String> = (1..=crate::lan::MAX_SERVERS_PER_NETWORK + 1)
            .map(|host| format!("192.168.3.{host}"))
            .collect();
        let servers: Vec<&str> = servers.iter().map(String::as_str).collect();
        let policy = BootstrapPolicy::from_plan(&private_plan_with(&servers), &[engine]);
        let rules: Vec<_> = policy.rules.iter().collect();
        assert_eq!(
            decide(&rules, [192, 168, 3, 100], 6, 80, 999),
            Action::Block
        );
        assert_eq!(decide(&rules, [10, 1, 2, 3], 6, 80, 999), Action::Allow);
        // The block has an address: without one it would close all DNS.
        assert!(policy.rules.iter().all(|rule| {
            !rule.conditions.starts_with(&[Condition::Protocol(17)])
                && !rule.conditions.starts_with(&[Condition::Protocol(6)])
        }));
        assert_eq!(decide(&rules, [203, 0, 113, 7], 17, 53, 999), Action::Block);
        assert_eq!(
            decide(&rules, [192, 168, 3, 100], 17, 53, 999),
            Action::Block
        );
        let at_limit = &servers[..crate::lan::MAX_SERVERS_PER_NETWORK];
        let open = BootstrapPolicy::from_plan(&private_plan_with(at_limit), &[engine]);
        let rules: Vec<_> = open.rules.iter().collect();
        assert_eq!(
            decide(&rules, [192, 168, 3, 100], 6, 80, 999),
            Action::Allow
        );
    }

    #[test]
    fn an_ipv6_segment_also_opens_without_its_server() {
        let prefix = IpPrefix::new("2001:db8:1::".parse().unwrap(), 64).unwrap();
        let server: IpAddr = "2001:db8:1::5".parse().unwrap();
        let lan = LanAccess {
            segment: LanSegment::from_parts(
                vec![SegmentNetwork {
                    prefix,
                    interface: InterfaceId(7),
                }],
                vec![InterfaceId(7)],
            )
            .leaving_out(&[server]),
            ..LanAccess::default()
        };
        let rules = super::lan_rules(&lan);
        let segment: Vec<_> = rules
            .iter()
            .filter(|(what, _)| {
                matches!(
                    what,
                    super::LanRule::Segment(_) | super::LanRule::SegmentDns(..)
                )
            })
            .collect();
        assert_eq!(segment.len(), 3);
        for (_, rule) in segment {
            assert_eq!(rule.family, AddressFamily::Ipv6);
            let ranges: Vec<_> = rule
                .conditions
                .iter()
                .filter_map(|condition| match condition {
                    Condition::RemoteRange(range) => Some(*range),
                    _ => None,
                })
                .collect();
            assert_eq!(ranges.len(), 2);
            assert!(
                ranges
                    .iter()
                    .all(|range| !(range.low..=range.high).contains(&server))
            );
        }
    }

    #[test]
    fn the_debug_form_of_a_rule_names_private_networks_only() {
        let policy = BootstrapPolicy::from_plan(&lan_plan(true), &[Path::new("C:\\e.exe")]);
        let text = format!("{policy:?}");
        assert!(text.contains("Subnet(192.168.0.0/16)"), "{text}");
        assert!(text.contains("Subnet(public)"), "{text}");
        assert!(!text.contains("192.0.2"), "{text}");
        assert!(!text.contains("[192, 0, 2"), "{text}");
    }

    #[test]
    fn the_debug_form_of_a_rule_does_not_name_a_server() {
        let policy = BootstrapPolicy::from_plan(&plan_with_servers(), &[Path::new("C:\\e.exe")]);
        let text = format!("{policy:?}");
        assert!(text.contains("AddressRange"));
        assert!(!text.contains("192.0.2."));
    }

    #[test]
    fn without_a_physical_adapter_link_local_stays_closed() {
        let plan = RoutingPlan {
            lan: LanAccess::default(),
            ..lan_plan(false)
        };
        let policy = BootstrapPolicy::from_plan(&plan, &[Path::new(r"C:\sing-box.exe")]);
        assert!(policy.rules.iter().all(|rule| {
            rule.action == Action::Block
                || !rule
                    .conditions
                    .iter()
                    .any(|condition| matches!(condition, Condition::RemoteSubnet(_)))
        }));
    }

    #[test]
    fn ipv6_link_local_multicast_needs_an_ipv6_tunnel() {
        let multicast = Condition::RemoteSubnet(rosetun_config::LINK_LOCAL_V6[1].into());
        let has = |ipv6_multicast| {
            let mut plan = lan_plan(false);
            plan.lan.ipv6_multicast = ipv6_multicast;
            BootstrapPolicy::from_plan(&plan, &[Path::new(r"C:\sing-box.exe")])
                .rules
                .iter()
                .any(|rule| rule.action == Action::Allow && rule.conditions.contains(&multicast))
        };
        assert!(!has(false));
        assert!(has(true));
    }

    #[test]
    fn dns_only_confines_port_53_to_the_tunnel() {
        let engine = Path::new(r"C:\sing-box.exe");
        let policy = BootstrapPolicy::from_plan(
            &RoutingPlan {
                scope: ProtectionScope::DnsOnly,
                allow_lan: false,
                lan: Default::default(),
                lockdown: false,
            },
            &[engine],
        );
        assert_eq!(policy.rules.len(), 8);
        assert!(policy.rules.iter().all(|rule| !rule.conditions.is_empty()));
        for rule in &policy.rules[..2] {
            assert_eq!(rule.conditions, super::engine_permit(engine));
            assert_eq!(rule.action, Action::Allow);
        }

        let authorization = tunnel_authorization(123, false);
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
    fn lockdown_tunnel_authorization_also_permits_inbound_on_the_tunnel() {
        let plain = tunnel_authorization(7, false);
        assert!(plain.iter().all(|rule| rule.layer == Layer::Connect));
        let locked = tunnel_authorization(7, true);
        assert_eq!(locked.len(), 4);
        for layer in [Layer::Connect, Layer::RecvAccept] {
            for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
                assert!(locked.iter().any(|rule| {
                    rule.layer == layer
                        && rule.family == family
                        && rule.action == Action::Allow
                        && rule.conditions == [Condition::LocalInterface(7)]
                        && rule.weight == super::TUNNEL_WEIGHT
                }));
            }
        }
    }

    #[test]
    fn dns_only_ignores_allow_lan() {
        let plan = RoutingPlan {
            scope: ProtectionScope::DnsOnly,
            allow_lan: false,
            lan: Default::default(),
            lockdown: false,
        };
        let engine = Path::new(r"C:\sing-box.exe");
        let disabled = BootstrapPolicy::from_plan(&plan, &[engine]);
        let enabled = BootstrapPolicy::from_plan(
            &RoutingPlan {
                allow_lan: true,
                lan: Default::default(),
                ..plan
            },
            &[engine],
        );
        assert_eq!(disabled, enabled);
    }
}
