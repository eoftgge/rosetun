//! The text of Rosetun's nftables table (Linux).
//!
//! Everything lives in one table of its own, `inet rosetun`, with a base
//! chain on the output hook for what this host sends and one on the
//! forward hook for what it passes on; other tables and chains are never
//! touched. A
//! change is always one `nft -f -` transaction that creates the table if
//! it is missing, deletes it and defines it anew, so the kernel switches
//! from the old rules to the new ones with no moment in between.
//!
//! Why a drop here cannot be bypassed: every base chain registered on a
//! hook sees the packet in priority order, and `accept` only ends the
//! chain that says it. A `drop` is final wherever it happens. So another
//! table's `accept`, at whatever priority, never lets a packet past this
//! chain, and this chain's `accept` never overrides another table's drop.
//! The chains sit at `priority filter`, after any `type route` chain at
//! `mangle` that may reroute a packet, so `oif` is the final interface.
//!
//! Only checked values reach the text: interface names as `InterfaceName`,
//! cgroup paths as `CgroupPath`, addresses as `IpPrefix` and `IpAddr`.

use std::fmt::Write as _;
use std::net::IpAddr;

use rosetun_config::{IpPrefix, LINK_LOCAL_V4, LINK_LOCAL_V6};

use crate::cgroup::CgroupPath;
use crate::lan::{LanAccess, MAX_SERVERS_PER_NETWORK};
use crate::{ProtectionScope, RoutingError};

pub(crate) const TABLE: &str = "rosetun";
/// `IFNAMSIZ` minus the terminating zero.
const MAX_INTERFACE_BYTES: usize = 15;

/// "Private networks behind the router", as on Windows: the private ranges
/// and link-local, on any interface, but never for DNS.
const PRIVATE_NETWORKS: [IpPrefix; 6] = [
    IpPrefix::v4([10, 0, 0, 0], 8),
    IpPrefix::v4([172, 16, 0, 0], 12),
    IpPrefix::v4([192, 168, 0, 0], 16),
    IpPrefix::v4([169, 254, 0, 0], 16),
    IpPrefix::v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
    IpPrefix::v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
];
/// IPv6 neighbor discovery the kernel sends without a socket, so with no
/// cgroup: without it the engine cannot reach a server over IPv6 and the
/// host loses its neighbors. Hop limit 255 is what RFC 4861 requires: a
/// copy that crossed a router arrives with less and is discarded, so the
/// permit reaches the link only, and forging one takes `CAP_NET_RAW`. Not
/// all of ICMPv6, which would be a way out past the kill switch.
const NEIGHBOR_DISCOVERY: &str = "icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept";
/// The same from the link to this host, under Lockdown: the router's
/// advertisements, the neighbors' solicitations and their answers.
const NEIGHBOR_DISCOVERY_IN: &str = "icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept";

/// A network interface name the kernel could hold: 1 to 15 bytes of
/// `[A-Za-z0-9_.-]`, not `.` or `..`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterfaceName(String);

impl InterfaceName {
    pub(crate) fn new(name: &str) -> Result<Self, RoutingError> {
        let valid = !name.is_empty()
            && name.len() <= MAX_INTERFACE_BYTES
            && name != "."
            && name != ".."
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'));
        if valid {
            Ok(Self(name.to_owned()))
        } else {
            Err(RoutingError::Tun {
                name: name.escape_debug().to_string(),
                reason: "not a valid interface name".to_owned(),
            })
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a table found at start, with no session of this process, does to
/// the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeftBehind {
    /// A base chain drops by default: the kill switch or its hold.
    KillSwitch,
    /// Every base chain accepts by default and drops nothing but DNS: the
    /// DNS lock alone.
    DnsLock,
    /// Anything this version did not write, or `nft` printed differently.
    Unknown,
}

/// What one version of the table permits.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Rules<'a> {
    pub(crate) scope: ProtectionScope,
    /// "Local network", out and forwarded; only with `AllTraffic`.
    pub(crate) allow_lan: bool,
    /// What it opens (`None` is an empty segment), when `allow_lan` or
    /// Lockdown's own "Local network" is on.
    pub(crate) lan: Option<&'a LanAccess>,
    /// The engines' leaf: everything an engine sends passes. `None` only in
    /// Lockdown's set at boot, before the unit has made its leaves: a rule
    /// naming a cgroup that does not exist cannot be loaded.
    pub(crate) engines: Option<&'a CgroupPath>,
    /// The hold after a crash, with the helper's own leaf: the helper may
    /// send DNS, to resolve a server name for the connect that lifts the
    /// hold, and nothing is forwarded.
    pub(crate) hold: Option<&'a CgroupPath>,
    /// Phase 2: the engine's TUN, once it exists.
    pub(crate) tunnel: Option<&'a InterfaceName>,
    /// Lockdown: always `AllTraffic`, closed inbound as well.
    pub(crate) lockdown: Option<Lockdown<'a>>,
}

/// What Lockdown adds to the kill switch.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Lockdown<'a> {
    /// "Local network" of Lockdown itself: the local network may also
    /// connect to this host, and this host may answer it.
    pub(crate) lan: bool,
    /// A session runs: what this host forwards may use the tunnel and,
    /// with `Rules::allow_lan`, the local network. Without one nothing is
    /// forwarded.
    pub(crate) session: bool,
    /// The helper's leaf: DNS for its own name lookups. `None` at boot.
    pub(crate) helper: Option<&'a CgroupPath>,
    /// The scopes of the GUI and the CLI: TCP to any port and DNS. Empty
    /// while a session runs and at boot.
    pub(crate) programs: &'a [CgroupPath],
}

/// The lines "Local network" adds, written once per table.
#[derive(Default)]
struct LanLines {
    /// Leaving this host, and forwarded.
    permits: Vec<String>,
    /// DNS to the local networks is dropped above the permits.
    dns_drops: Vec<String>,
    /// Reaching this host, under Lockdown only.
    inbound: Vec<String>,
}

impl Rules<'_> {
    /// The local networks this host may send to.
    fn lan(&self) -> bool {
        let lockdown_lan = self.lockdown.is_some_and(|lockdown| lockdown.lan);
        (self.allow_lan || lockdown_lan) && self.scope() == ProtectionScope::AllTraffic
    }

    fn lan_lines(&self) -> LanLines {
        if !self.lan() {
            return LanLines::default();
        }
        let access = self.lan.cloned().unwrap_or_default();
        LanLines {
            permits: lan_permits(&access, Way::Out),
            dns_drops: lan_dns_drops(&access),
            inbound: if self.lockdown.is_some_and(|lockdown| lockdown.lan) {
                lan_permits(&access, Way::In)
            } else {
                Vec::new()
            },
        }
    }

    fn scope(&self) -> ProtectionScope {
        if self.lockdown.is_some() {
            ProtectionScope::AllTraffic
        } else {
            self.scope
        }
    }

    fn forwards(&self) -> bool {
        self.hold.is_none() && self.lockdown.is_none_or(|lockdown| lockdown.session)
    }
}

/// Replaces the table with `rules` in one transaction.
pub(crate) fn replace(rules: &Rules<'_>) -> String {
    let mut text = remove();
    let lan = rules.lan_lines();
    let _ = writeln!(text, "table inet {TABLE} {{");
    if rules.lockdown.is_some() {
        input_chain(&mut text, rules, &lan);
    }
    output_chain(&mut text, rules, &lan);
    forward_chain(&mut text, rules, &lan);
    text.push_str("}\n");
    text
}

/// What reaches this host, only under Lockdown: loopback, answers to what
/// this host sent, the DHCP server's replies, neighbor discovery from the
/// link, the tunnel of a session, and the local network when Lockdown has
/// it. As on Windows, where Lockdown blocks inbound too and a session's
/// tunnel permit covers it.
///
/// Why `established,related` opens nothing: conntrack confirms a
/// connection only once its first packet has passed every hook, so an
/// entry exists only for what the output chain let out (or what this
/// chain let in). A first packet from outside is `new` and dropped here
/// with its entry. `related` carries ICMP errors for those connections,
/// which path MTU discovery needs.
fn input_chain(text: &mut String, rules: &Rules<'_>, lan: &LanLines) {
    chain_head(text, "input", ProtectionScope::AllTraffic);
    text.push_str("\t\tiif \"lo\" accept\n");
    if let Some(tunnel) = rules.tunnel {
        let _ = writeln!(text, "\t\tiif \"{}\" accept", tunnel.as_str());
    }
    text.push_str("\t\tct state established,related accept\n");
    text.push_str("\t\tmeta nfproto ipv4 udp sport 67 udp dport 68 accept\n");
    let _ = writeln!(text, "\t\t{NEIGHBOR_DISCOVERY_IN}");
    for line in &lan.inbound {
        let _ = writeln!(text, "\t\t{line}");
    }
    text.push_str("\t}\n");
}

/// What this host sends.
fn output_chain(text: &mut String, rules: &Rules<'_>, lan: &LanLines) {
    chain_head(text, "output", rules.scope());
    // The tunnel first: its own DNS address lies in 172.16/12, which the
    // private DNS drop below would catch.
    tunnel_permit(text, rules);
    if let Some(lockdown) = rules.lockdown {
        // Above the private DNS drop, as their DNS permits outrank it on
        // Windows: the resolver may well be the router.
        if let Some(helper) = lockdown.helper {
            let _ = writeln!(
                text,
                "\t\t{} meta l4proto {{ tcp, udp }} th dport 53 accept",
                cgroup_match(helper)
            );
        }
        for program in lockdown.programs {
            let _ = writeln!(
                text,
                "\t\t{} meta l4proto tcp accept",
                cgroup_match(program)
            );
            let _ = writeln!(text, "\t\t{} udp dport 53 accept", cgroup_match(program));
        }
    }
    lan_dns_drop(text, lan);
    text.push_str("\t\toif \"lo\" accept\n");
    if rules.scope() == ProtectionScope::AllTraffic && rules.lockdown.is_none() {
        // Answers to connections opened from outside, as under the Windows
        // kill switch, which authorizes only connects: the other side knows
        // the address already. A connection this host opened sends in the
        // original direction and is not let out by this, provided conntrack
        // saw it begin; one it picks up halfway takes its direction from the
        // first packet it sees. Lockdown lets nothing in from outside but
        // the tunnel and the local network, and both are permitted out.
        text.push_str("\t\tct direction reply accept\n");
    }
    if let Some(engines) = rules.engines {
        let _ = writeln!(text, "\t\t{} accept", cgroup_match(engines));
    }
    if let Some(helper) = rules.hold {
        let _ = writeln!(
            text,
            "\t\t{} meta l4proto {{ tcp, udp }} th dport 53 accept",
            cgroup_match(helper)
        );
    }
    match rules.scope() {
        ProtectionScope::AllTraffic => {
            text.push_str("\t\tmeta nfproto ipv4 udp sport 68 udp dport 67 accept\n");
            let _ = writeln!(text, "\t\t{NEIGHBOR_DISCOVERY}");
            lan_permit(text, lan);
        }
        ProtectionScope::DnsOnly => {
            text.push_str("\t\tmeta l4proto { tcp, udp } th dport 53 drop\n");
        }
        // Nothing to write: see `lockdown::protection_scope` in the helper.
        ProtectionScope::SharedProxy => {}
    }
    text.push_str("\t}\n");
}

/// What this host passes on for others: containers, virtual machines,
/// a shared connection. Under the kill switch they get the tunnel, the
/// local network if it is on, and answers to what was opened towards them
/// (the tunnel's answers come back on the tunnel and leave towards them,
/// so without this the tunnel would carry nothing back); under the DNS
/// lock only their DNS beside the tunnel is dropped. Nothing has a cgroup
/// here, so there is no engine permit. In the hold, and under Lockdown
/// without a session, nothing is forwarded.
fn forward_chain(text: &mut String, rules: &Rules<'_>, lan: &LanLines) {
    chain_head(text, "forward", rules.scope());
    if rules.forwards() {
        tunnel_permit(text, rules);
        lan_dns_drop(text, lan);
        match rules.scope() {
            ProtectionScope::AllTraffic => {
                text.push_str("\t\tct direction reply accept\n");
                lan_permit(text, lan);
            }
            ProtectionScope::DnsOnly => {
                text.push_str("\t\tmeta l4proto { tcp, udp } th dport 53 drop\n");
            }
            ProtectionScope::SharedProxy => {}
        }
    }
    text.push_str("\t}\n");
}

fn chain_head(text: &mut String, hook: &str, scope: ProtectionScope) {
    let policy = match scope {
        ProtectionScope::AllTraffic => "drop",
        ProtectionScope::DnsOnly | ProtectionScope::SharedProxy => "accept",
    };
    let _ = writeln!(text, "\tchain {hook} {{");
    let _ = writeln!(
        text,
        "\t\ttype filter hook {hook} priority filter; policy {policy};"
    );
}

fn tunnel_permit(text: &mut String, rules: &Rules<'_>) {
    if let Some(tunnel) = rules.tunnel {
        let _ = writeln!(text, "\t\toif \"{}\" accept", tunnel.as_str());
    }
}

fn lan_dns_drop(text: &mut String, lan: &LanLines) {
    for line in &lan.dns_drops {
        let _ = writeln!(text, "\t\t{line}");
    }
}

fn lan_permit(text: &mut String, lan: &LanLines) {
    for line in &lan.permits {
        let _ = writeln!(text, "\t\t{line}");
    }
}

#[derive(Clone, Copy)]
enum Way {
    /// Leaving this host: the output and forward chains.
    Out,
    /// Reaching this host: the input chain.
    In,
}

impl Way {
    fn interface(self) -> &'static str {
        match self {
            Self::Out => "oifname",
            Self::In => "iifname",
        }
    }

    /// `ip daddr`, `ip6 saddr` and so on, for the family of `prefix`.
    fn address(self, prefix: IpPrefix) -> &'static str {
        match (self, prefix.is_ipv4()) {
            (Self::Out, true) => "ip daddr",
            (Self::Out, false) => "ip6 daddr",
            (Self::In, true) => "ip saddr",
            (Self::In, false) => "ip6 saddr",
        }
    }
}

/// What "Local network" permits: each connected network only on its own
/// interface; link-local networks on the physical interfaces; with "Private
/// networks behind the router" also the private ranges on any interface. The
/// VPN servers' addresses are left out of all of them: only the engine goes
/// there, by its own permit. A rule with no address would open a whole
/// interface, so a network with nothing left to open gets no line.
///
/// Each line is one set: the sets of two lines may overlap, the elements of
/// one never do, which nftables would refuse to load.
fn lan_permits(access: &LanAccess, way: Way) -> Vec<String> {
    let mut lines = Vec::new();
    let segment = &access.segment;
    for network in segment.networks() {
        let Some(name) = segment
            .interface_name(network.interface)
            .and_then(|name| InterfaceName::new(name).ok())
        else {
            continue;
        };
        let pieces = open_pieces(network.prefix, segment.left_out());
        if !pieces.is_empty() {
            lines.push(format!(
                "{} \"{}\" {} {{ {} }} accept",
                way.interface(),
                name.as_str(),
                way.address(network.prefix),
                pieces.join(", ")
            ));
        }
    }
    let names = physical_names(access);
    if !names.is_empty() {
        let prefixes: Vec<IpPrefix> = match way {
            Way::Out => link_local(access.ipv6_multicast).collect(),
            Way::In => vec![LINK_LOCAL_V4[0], LINK_LOCAL_V6[0]],
        };
        for ipv4 in [true, false] {
            if let Some((first, pieces)) = family_pieces(&prefixes, ipv4, &access.servers) {
                lines.push(format!(
                    "{} {{ {} }} {} {{ {} }} accept",
                    way.interface(),
                    names.join(", "),
                    way.address(first),
                    pieces.join(", ")
                ));
            }
        }
    }
    if access.private_networks {
        for ipv4 in [true, false] {
            if let Some((first, pieces)) = family_pieces(&PRIVATE_NETWORKS, ipv4, &access.servers) {
                lines.push(format!(
                    "{} {{ {} }} accept",
                    way.address(first),
                    pieces.join(", ")
                ));
            }
        }
    }
    lines
}

/// The pieces of the networks of one family, with the first of them to tell
/// the family by; `None` when nothing is left to open.
fn family_pieces(
    prefixes: &[IpPrefix],
    ipv4: bool,
    servers: &[IpAddr],
) -> Option<(IpPrefix, Vec<String>)> {
    let wanted: Vec<IpPrefix> = prefixes
        .iter()
        .copied()
        .filter(|prefix| prefix.is_ipv4() == ipv4)
        .collect();
    let pieces: Vec<String> = wanted
        .iter()
        .flat_map(|prefix| open_pieces(*prefix, servers))
        .collect();
    let first = *wanted.first()?;
    (!pieces.is_empty()).then_some((first, pieces))
}

/// DNS to any of the local networks stays blocked, so a resolver there is not
/// a way round the tunnel's. The block sits above the permits and above the
/// engine's, which is why a server's address is left out of it as well: the
/// engine could not reach a server on port 53 otherwise.
fn lan_dns_drops(access: &LanAccess) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut add = |prefixes: &[IpPrefix], servers: &[IpAddr]| {
        for ipv4 in [true, false] {
            let wanted: Vec<IpPrefix> = prefixes
                .iter()
                .copied()
                .filter(|prefix| prefix.is_ipv4() == ipv4)
                .collect();
            let Some(first) = wanted.first() else {
                continue;
            };
            let pieces: Vec<String> = wanted
                .iter()
                .flat_map(|prefix| closed_pieces(*prefix, servers))
                .collect();
            let line = format!(
                "{} {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 drop",
                Way::Out.address(*first),
                pieces.join(", ")
            );
            if !lines.contains(&line) {
                lines.push(line);
            }
        }
    };
    for network in access.segment.networks() {
        add(&[network.prefix], access.segment.left_out());
    }
    add(
        &link_local(access.ipv6_multicast).collect::<Vec<_>>(),
        &access.servers,
    );
    if access.private_networks {
        add(&PRIVATE_NETWORKS, &access.servers);
    }
    lines
}

/// The link-local networks "Local network" opens. IPv6 link-local multicast
/// only when the tunnel carries IPv6: otherwise sing-box blocks all IPv6
/// while it runs, and mDNS and SSDP work over IPv4 anyway.
fn link_local(ipv6_multicast: bool) -> impl Iterator<Item = IpPrefix> {
    let multicast_v6 = LINK_LOCAL_V6[1];
    LINK_LOCAL_V4
        .into_iter()
        .chain(LINK_LOCAL_V6)
        .filter(move |prefix| ipv6_multicast || *prefix != multicast_v6)
}

/// The names of the physical interfaces, quoted, for `oifname { ... }`.
fn physical_names(access: &LanAccess) -> Vec<String> {
    let mut names: Vec<String> = access
        .segment
        .interfaces()
        .iter()
        .filter_map(|id| access.segment.interface_name(*id))
        .filter_map(|name| InterfaceName::new(name).ok())
        .map(|name| format!("\"{}\"", name.as_str()))
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// The network as address conditions: whole, or the ranges around the
/// servers inside it. Empty past `MAX_SERVERS_PER_NETWORK` servers or when
/// nothing is left: such a network is closed.
fn open_pieces(prefix: IpPrefix, servers: &[IpAddr]) -> Vec<String> {
    let inside = servers
        .iter()
        .filter(|server| prefix.contains(**server))
        .count();
    if inside > MAX_SERVERS_PER_NETWORK {
        tracing::warn!("local network: a range holds too many VPN servers and stays closed");
        return Vec::new();
    }
    if inside == 0 {
        return vec![prefix.to_string()];
    }
    prefix
        .ranges_without(servers)
        .into_iter()
        .map(|(low, high)| {
            if low == high {
                low.to_string()
            } else {
                format!("{low}-{high}")
            }
        })
        .collect()
}

/// A range without a permit keeps its DNS block whole: nothing else is open
/// there, and an empty set would not load.
fn closed_pieces(prefix: IpPrefix, servers: &[IpAddr]) -> Vec<String> {
    let pieces = open_pieces(prefix, servers);
    if pieces.is_empty() {
        vec![prefix.to_string()]
    } else {
        pieces
    }
}

/// Removes the table; harmless when there is none.
pub(crate) fn remove() -> String {
    format!("add table inet {TABLE}\ndelete table inet {TABLE}\n")
}

/// Whether `nft list tables inet` shows Rosetun's table.
/// A listing without what `nft` may change between two runs: indentation and
/// empty lines. Everything else counts, so any change to the rules shows.
pub(crate) fn normalized(listing: &str) -> String {
    listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn lists_table(listing: &str) -> bool {
    let wanted = format!("table inet {TABLE}");
    listing.lines().any(|line| line.trim() == wanted)
}

/// Reads `nft list table inet rosetun`. Decided by the chains' policies,
/// which are what closes the network, and read strictly: every line must
/// have the shape Rosetun writes, or the table is `Unknown`.
pub(crate) fn left_behind(listing: &str) -> LeftBehind {
    read_left_behind(listing).unwrap_or(LeftBehind::Unknown)
}

fn read_left_behind(listing: &str) -> Option<LeftBehind> {
    let mut lines = listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    if lines.next()? != format!("table inet {TABLE} {{") {
        return None;
    }
    let mut hooks: Vec<&str> = Vec::new();
    let mut drops_by_default = false;
    let mut drops_beyond_dns = false;
    loop {
        let line = lines.next()?;
        if line == "}" {
            break;
        }
        let name = line.strip_prefix("chain ")?.strip_suffix(" {")?;
        let (hook, policy) = lines
            .next()?
            .strip_prefix("type filter hook ")?
            .split_once(" priority filter; policy ")?;
        if hook != name || !matches!(hook, "output" | "forward") || hooks.contains(&hook) {
            return None;
        }
        hooks.push(hook);
        match policy {
            "drop;" => drops_by_default = true,
            "accept;" => {}
            _ => return None,
        }
        loop {
            let rule = lines.next()?;
            if rule == "}" {
                break;
            }
            if rule.ends_with(" th dport 53 drop") {
                continue;
            }
            if !rule.ends_with(" accept") {
                drops_beyond_dns = true;
            }
        }
    }
    if lines.next().is_some() || !hooks.contains(&"output") {
        return None;
    }
    if drops_by_default {
        Some(LeftBehind::KillSwitch)
    } else if drops_beyond_dns {
        None
    } else {
        Some(LeftBehind::DnsLock)
    }
}

fn cgroup_match(path: &CgroupPath) -> String {
    format!(
        "socket cgroupv2 level {} \"{}\"",
        path.level(),
        path.relative()
    )
}

#[cfg(test)]
mod proxy_mode_tests {
    use super::*;

    fn engines() -> CgroupPath {
        CgroupPath::parse("/system.slice/rosetun-helper.service/engines").unwrap()
    }

    fn private_networks() -> LanAccess {
        LanAccess {
            private_networks: true,
            ..LanAccess::default()
        }
    }

    fn proxy_mode<'a>(
        engines: &'a CgroupPath,
        allow_lan: bool,
        lan: Option<&'a LanAccess>,
    ) -> Rules<'a> {
        Rules {
            lan,
            scope: ProtectionScope::AllTraffic,
            allow_lan,
            engines: Some(engines),
            hold: None,
            // The proxy mode's kill switch has no second phase.
            tunnel: None,
            lockdown: None,
        }
    }

    #[test]
    fn the_kill_switch_of_the_proxy_mode_stays_in_its_first_phase() {
        let engines = engines();
        let text = replace(&proxy_mode(&engines, false, None));
        assert!(text.contains("type filter hook output priority filter; policy drop;"));
        assert!(text.contains("oif \"lo\" accept"));
        assert!(text.contains("system.slice/rosetun-helper.service/engines"));
        assert!(text.contains("udp sport 68 udp dport 67 accept"));
        assert!(text.contains(NEIGHBOR_DISCOVERY));
        assert!(!text.contains("oif \"rosetun"), "no tunnel to permit");
        assert!(!text.contains("th dport 53 drop"), "no DNS lock");
        assert!(!text.contains("hook input"), "inbound stays free");
    }

    #[test]
    fn local_network_in_the_proxy_mode_opens_the_private_ranges_as_in_the_tunnel_mode() {
        let engines = engines();
        let access = private_networks();
        let open = replace(&proxy_mode(&engines, true, Some(&access)));
        let closed = replace(&proxy_mode(&engines, false, Some(&access)));
        let ranges =
            "ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept";
        assert!(open.contains(ranges));
        assert!(!closed.contains(ranges));
        let tunnel = InterfaceName::new("rosetun0").unwrap();
        let tunnel_mode = replace(&Rules {
            tunnel: Some(&tunnel),
            ..proxy_mode(&engines, true, Some(&access))
        });
        assert_eq!(
            open,
            tunnel_mode
                .lines()
                .filter(|line| !line.contains("\"rosetun0\""))
                .map(|line| format!("{line}\n"))
                .collect::<String>()
        );
    }

    #[test]
    fn lockdown_takes_inbound_only_from_its_local_network() {
        let engines = engines();
        let access = private_networks();
        let with = |lan| {
            replace(&Rules {
                lockdown: Some(Lockdown {
                    lan,
                    session: true,
                    helper: None,
                    programs: &[],
                }),
                ..proxy_mode(&engines, false, Some(&access))
            })
        };
        // Sharing adds no rule: this is the proxy's port like any other.
        let open = with(true);
        let closed = with(false);
        assert!(open.contains(
            "ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept"
        ));
        assert!(open.contains("ip6 saddr { fe80::/10, fc00::/7 } accept"));
        assert!(!closed.contains("saddr {"));
        assert!(closed.contains("type filter hook input priority filter; policy drop;"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::{
        Adapter, ETHERNET, InterfaceId, SegmentQuery, WIFI, canonical_servers, select,
    };

    #[test]
    fn a_listing_compares_equal_whatever_its_layout() {
        assert_eq!(
            normalized("table inet rosetun {\n\tchain output {\n\n\t}\n}\n"),
            normalized("table inet rosetun {\n  chain output {\n  }\n}")
        );
    }

    #[test]
    fn a_changed_rule_or_chain_shows_in_a_listing() {
        let base = "table inet rosetun {\n\tchain output {\n\t\toif \"lo\" accept\n\t}\n}\n";
        assert_ne!(
            normalized(base),
            normalized(&base.replace("oif \"lo\" accept", "oif \"lo\" drop"))
        );
        assert_ne!(
            normalized(base),
            normalized(&base.replace("chain output", "chain forward"))
        );
    }

    fn engines() -> CgroupPath {
        CgroupPath::parse("/system.slice/rosetun-helper.service/engines").unwrap()
    }

    fn helper() -> CgroupPath {
        CgroupPath::parse("/system.slice/rosetun-helper.service/helper").unwrap()
    }

    const HEAD: &str = "add table inet rosetun\ndelete table inet rosetun\ntable inet rosetun {\n\tchain output {\n";

    #[test]
    fn phase_one_of_the_kill_switch_drops_everything_but_the_bootstrap() {
        let engines = engines();
        let text = replace(&Rules {
            lan: None,
            scope: ProtectionScope::AllTraffic,
            allow_lan: false,
            engines: Some(&engines),
            lockdown: None,
            hold: None,
            tunnel: None,
        });
        assert_eq!(
            text,
            format!(
                "{HEAD}\
\t\ttype filter hook output priority filter; policy drop;
\t\toif \"lo\" accept
\t\tct direction reply accept
\t\tsocket cgroupv2 level 3 \"system.slice/rosetun-helper.service/engines\" accept
\t\tmeta nfproto ipv4 udp sport 68 udp dport 67 accept
\t\ticmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} ip6 hoplimit 255 accept
\t}}
\tchain forward {{
\t\ttype filter hook forward priority filter; policy drop;
\t\tct direction reply accept
\t}}
}}
"
            )
        );
    }

    #[test]
    fn phase_two_adds_the_tunnel_before_everything_else() {
        let engines = engines();
        let tunnel = InterfaceName::new("rosetun0").unwrap();
        let text = replace(&Rules {
            lan: None,
            scope: ProtectionScope::AllTraffic,
            allow_lan: false,
            engines: Some(&engines),
            lockdown: None,
            hold: None,
            tunnel: Some(&tunnel),
        });
        assert_eq!(
            text,
            format!(
                "{HEAD}\
\t\ttype filter hook output priority filter; policy drop;
\t\toif \"rosetun0\" accept
\t\toif \"lo\" accept
\t\tct direction reply accept
\t\tsocket cgroupv2 level 3 \"system.slice/rosetun-helper.service/engines\" accept
\t\tmeta nfproto ipv4 udp sport 68 udp dport 67 accept
\t\ticmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} ip6 hoplimit 255 accept
\t}}
\tchain forward {{
\t\ttype filter hook forward priority filter; policy drop;
\t\toif \"rosetun0\" accept
\t\tct direction reply accept
\t}}
}}
"
            )
        );
    }

    fn adapter(index: u64, name: &str, if_type: u32, addresses: &[(&str, u8)]) -> Adapter {
        Adapter {
            interface: InterfaceId(index),
            alias: name.to_owned(),
            description: String::new(),
            if_type,
            up: true,
            hardware: true,
            has_gateway: false,
            addresses: addresses
                .iter()
                .map(|(address, length)| (address.parse().unwrap(), *length))
                .collect(),
        }
    }

    /// Two physical interfaces on documentation networks, with these VPN servers.
    fn access(servers: &[&str], private_networks: bool, ipv6_multicast: bool) -> LanAccess {
        let adapters = [
            adapter(2, "eth0", ETHERNET, &[("192.0.2.15", 24), ("fe80::1", 64)]),
            adapter(
                3,
                "wlan0",
                WIFI,
                &[("198.51.100.20", 24), ("2001:db8:1::20", 64)],
            ),
        ];
        let servers: Vec<IpAddr> = servers.iter().map(|text| text.parse().unwrap()).collect();
        let scan = select(
            &adapters,
            &SegmentQuery {
                tunnel_alias: "rosetun0",
                tunnel_networks: &[],
                servers: &servers,
            },
        );
        LanAccess {
            segment: scan.segment,
            private_networks,
            ipv6_multicast,
            servers: canonical_servers(&servers),
        }
    }

    fn kill_switch(access: &LanAccess) -> String {
        let engines = engines();
        let tunnel = InterfaceName::new("rosetun0").unwrap();
        replace(&Rules {
            lan: Some(access),
            scope: ProtectionScope::AllTraffic,
            allow_lan: true,
            engines: Some(&engines),
            lockdown: None,
            hold: None,
            tunnel: Some(&tunnel),
        })
    }

    /// The lines of "Local network" in one chain of `text`.
    fn lan_lines(text: &str, chain: &str) -> Vec<String> {
        let start = text.find(&format!("\tchain {chain} {{")).unwrap();
        let body = &text[start..];
        let end = body.find("\t}\n").unwrap();
        body[..end]
            .lines()
            .map(str::trim)
            .filter(|line| {
                line.contains("daddr") || line.contains("saddr") || line.contains("th dport 53")
            })
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn each_connected_network_is_permitted_only_on_its_own_interface() {
        let text = kill_switch(&access(&[], false, false));
        assert_eq!(
            lan_lines(&text, "output"),
            [
                "ip daddr { 192.0.2.0/24 } meta l4proto { tcp, udp } th dport 53 drop",
                "ip daddr { 198.51.100.0/24 } meta l4proto { tcp, udp } th dport 53 drop",
                "ip6 daddr { 2001:db8:1::/64 } meta l4proto { tcp, udp } th dport 53 drop",
                "ip daddr { 169.254.0.0/16, 224.0.0.0/24, 239.255.255.250/32, 255.255.255.255/32 } meta l4proto { tcp, udp } th dport 53 drop",
                "ip6 daddr { fe80::/10 } meta l4proto { tcp, udp } th dport 53 drop",
                "oifname \"eth0\" ip daddr { 192.0.2.0/24 } accept",
                "oifname \"wlan0\" ip daddr { 198.51.100.0/24 } accept",
                "oifname \"wlan0\" ip6 daddr { 2001:db8:1::/64 } accept",
                "oifname { \"eth0\", \"wlan0\" } ip daddr { 169.254.0.0/16, 224.0.0.0/24, 239.255.255.250/32, 255.255.255.255/32 } accept",
                "oifname { \"eth0\", \"wlan0\" } ip6 daddr { fe80::/10 } accept",
            ]
        );
        // The same lines leave for the machines this host forwards for.
        assert_eq!(lan_lines(&text, "forward").len(), 10);
    }

    #[test]
    fn the_private_ranges_behind_the_router_stay_closed_without_their_option() {
        let text = kill_switch(&access(&[], false, false));
        assert!(!text.contains("10.0.0.0/8"));
        assert!(!text.contains("192.168.0.0/16"));
        let with = kill_switch(&access(&[], true, false));
        assert!(with.contains(
            "\t\tip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept\n"
        ));
        assert!(with.contains("\t\tip6 daddr { fe80::/10, fc00::/7 } accept\n"));
    }

    #[test]
    fn a_vpn_server_in_the_own_network_is_left_out_of_the_permit_and_the_dns_block() {
        let text = kill_switch(&access(&["198.51.100.200"], false, false));
        let lines = lan_lines(&text, "output");
        let ranges = "198.51.100.0-198.51.100.199, 198.51.100.201-198.51.100.255";
        assert!(lines.contains(&format!("oifname \"wlan0\" ip daddr {{ {ranges} }} accept")));
        assert!(lines.contains(&format!(
            "ip daddr {{ {ranges} }} meta l4proto {{ tcp, udp }} th dport 53 drop"
        )));
        assert!(lines.contains(&"oifname \"eth0\" ip daddr { 192.0.2.0/24 } accept".to_owned()));
        assert!(!text.contains("198.51.100.200 "), "{text}");
    }

    #[test]
    fn a_server_in_a_private_range_is_left_out_of_it_too() {
        let text = kill_switch(&access(&["10.1.2.3"], true, false));
        assert!(text.contains("ip daddr { 10.0.0.0-10.1.2.2, 10.1.2.4-10.255.255.255, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept"));
    }

    #[test]
    fn ipv6_multicast_is_permitted_only_when_the_tunnel_carries_ipv6() {
        let without = kill_switch(&access(&[], false, false));
        let with = kill_switch(&access(&[], false, true));
        assert!(!without.contains("ff02::/16"));
        assert!(
            with.contains(
                "oifname { \"eth0\", \"wlan0\" } ip6 daddr { fe80::/10, ff02::/16 } accept"
            )
        );
    }

    #[test]
    fn an_empty_segment_opens_no_interface() {
        let text = kill_switch(&LanAccess::default());
        assert!(!text.contains("oifname"));
        assert!(
            !text
                .lines()
                .any(|line| line.contains("daddr") && line.ends_with("accept"))
        );
    }

    #[test]
    fn an_interface_name_nftables_could_misread_gets_no_rule() {
        let adapters = [adapter(2, "eth0\"; drop", ETHERNET, &[("192.0.2.15", 24)])];
        let scan = select(
            &adapters,
            &SegmentQuery {
                tunnel_alias: "rosetun0",
                tunnel_networks: &[],
                servers: &[],
            },
        );
        let text = kill_switch(&LanAccess {
            segment: scan.segment,
            ..LanAccess::default()
        });
        assert!(!text.contains("oifname"));
        assert!(!text.contains("drop\""));
    }

    #[test]
    fn lockdown_takes_the_own_network_in_on_its_interface_only() {
        let engines = engines();
        let helper = helper();
        let access = access(&["198.51.100.200"], false, false);
        let text = replace(&Rules {
            lan: Some(&access),
            scope: ProtectionScope::AllTraffic,
            allow_lan: false,
            engines: Some(&engines),
            hold: None,
            tunnel: None,
            lockdown: Some(Lockdown {
                lan: true,
                session: false,
                helper: Some(&helper),
                programs: &[],
            }),
        });
        let input = lan_lines(&text, "input");
        assert_eq!(
            input,
            [
                "iifname \"eth0\" ip saddr { 192.0.2.0/24 } accept",
                "iifname \"wlan0\" ip saddr { 198.51.100.0-198.51.100.199, 198.51.100.201-198.51.100.255 } accept",
                "iifname \"wlan0\" ip6 saddr { 2001:db8:1::/64 } accept",
                "iifname { \"eth0\", \"wlan0\" } ip saddr { 169.254.0.0/16 } accept",
                "iifname { \"eth0\", \"wlan0\" } ip6 saddr { fe80::/10 } accept",
            ]
        );
    }

    #[test]
    fn the_dns_lock_drops_only_port_53_outside_the_tunnel() {
        let engines = engines();
        let tunnel = InterfaceName::new("rosetun0").unwrap();
        for (tunnel, tunnel_line) in [(None, ""), (Some(&tunnel), "\t\toif \"rosetun0\" accept\n")]
        {
            // "Local network" does not apply to the DNS lock.
            let text = replace(&Rules {
                lan: None,
                scope: ProtectionScope::DnsOnly,
                allow_lan: true,
                engines: Some(&engines),
                lockdown: None,
                hold: None,
                tunnel,
            });
            assert_eq!(
                text,
                format!(
                    "{HEAD}\
\t\ttype filter hook output priority filter; policy accept;
{tunnel_line}\
\t\toif \"lo\" accept
\t\tsocket cgroupv2 level 3 \"system.slice/rosetun-helper.service/engines\" accept
\t\tmeta l4proto {{ tcp, udp }} th dport 53 drop
\t}}
\tchain forward {{
\t\ttype filter hook forward priority filter; policy accept;
{tunnel_line}\
\t\tmeta l4proto {{ tcp, udp }} th dport 53 drop
\t}}
}}
"
                )
            );
        }
    }

    #[test]
    fn the_hold_lets_the_helper_send_dns_and_nothing_else() {
        let engines = engines();
        let helper = helper();
        let text = replace(&Rules {
            lan: None,
            scope: ProtectionScope::AllTraffic,
            allow_lan: false,
            engines: Some(&engines),
            lockdown: None,
            hold: Some(&helper),
            tunnel: None,
        });
        assert!(text.contains(
            "\t\tsocket cgroupv2 level 3 \"system.slice/rosetun-helper.service/helper\" meta l4proto { tcp, udp } th dport 53 accept\n"
        ));
        assert!(text.contains("policy drop;"));
        assert!(text.contains(&format!("\t\t{NEIGHBOR_DISCOVERY}\n")));
        assert!(text.contains("\t\tct direction reply accept\n"));
        assert!(text.ends_with(
            "\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n"
        ));
    }

    #[test]
    fn neighbor_discovery_alone_passes_and_only_on_the_link() {
        assert_eq!(
            NEIGHBOR_DISCOVERY,
            "icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept"
        );
        let engines = engines();
        let text = replace(&Rules {
            lan: None,
            scope: ProtectionScope::DnsOnly,
            allow_lan: false,
            engines: Some(&engines),
            lockdown: None,
            hold: None,
            tunnel: None,
        });
        // The DNS lock accepts by default; it needs no permit of its own.
        assert!(!text.contains("icmpv6"));
        assert!(!text.contains("ct direction"));
    }

    #[test]
    fn removal_never_fails_on_a_missing_table() {
        assert_eq!(
            remove(),
            "add table inet rosetun\ndelete table inet rosetun\n"
        );
    }

    #[test]
    fn only_our_own_table_is_recognised() {
        assert!(lists_table("table inet filter\ntable inet rosetun\n"));
        assert!(!lists_table("table inet rosetun-old\ntable ip rosetun\n"));
        assert!(!lists_table(""));
    }

    /// The table as `nft list table` prints it: the script without the
    /// removal in front.
    fn listing(rules: &Rules<'_>) -> String {
        replace(rules)[remove().len()..].to_owned()
    }

    #[test]
    fn a_left_table_is_told_apart_by_its_policies() {
        let engines = engines();
        let helper = helper();
        let tunnel = InterfaceName::new("rosetun0").unwrap();
        for allow_lan in [false, true] {
            for tunnel in [None, Some(&tunnel)] {
                for (scope, hold, expected) in [
                    (ProtectionScope::AllTraffic, None, LeftBehind::KillSwitch),
                    (
                        ProtectionScope::AllTraffic,
                        Some(&helper),
                        LeftBehind::KillSwitch,
                    ),
                    (ProtectionScope::DnsOnly, None, LeftBehind::DnsLock),
                ] {
                    let text = listing(&Rules {
                        lan: None,
                        scope,
                        allow_lan,
                        engines: Some(&engines),
                        lockdown: None,
                        hold,
                        tunnel,
                    });
                    assert_eq!(left_behind(&text), expected, "{text}");
                }
            }
        }
    }

    #[test]
    fn a_dns_lock_as_nft_prints_it_is_recognised() {
        let printed = "table inet rosetun {
\tchain output {
\t\ttype filter hook output priority filter; policy accept;
\t\toif \"rosetun0\" accept
\t\toif \"lo\" accept
\t\tsocket cgroupv2 level 3 \"system.slice/rosetun-helper.service/engines\" accept
\t\tmeta l4proto { tcp, udp } th dport 53 drop
\t}
}
";
        assert_eq!(left_behind(printed), LeftBehind::DnsLock);
    }

    #[test]
    fn a_left_table_of_any_other_shape_is_unknown() {
        let lock = "table inet rosetun {\n\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t\tmeta l4proto { tcp, udp } th dport 53 drop\n\t}\n}\n";
        assert_eq!(left_behind(lock), LeftBehind::DnsLock);
        for (what, text) in [
            ("nothing", String::new()),
            ("another table", lock.replace("inet rosetun", "inet rosetun-old")),
            ("another family", lock.replace("inet rosetun", "ip rosetun")),
            (
                "a drop beyond DNS",
                lock.replace("th dport 53 drop", "th dport 443 drop"),
            ),
            ("a bare drop", lock.replace("meta l4proto { tcp, udp } th dport 53 drop", "drop")),
            ("a reject", lock.replace("th dport 53 drop", "th dport 53 reject")),
            ("a numeric priority", lock.replace("priority filter", "priority 0")),
            ("another hook", lock.replace("hook output", "hook input")),
            ("a chain named apart from its hook", lock.replace("chain output", "chain out")),
            ("no policy", lock.replace(" policy accept;", "")),
            ("an unknown policy", lock.replace("policy accept", "policy queue")),
            ("a table-level line", lock.replace("\tchain output {", "\tflags dormant\n\tchain output {")),
            ("no end", lock.trim_end().trim_end_matches('}').to_owned()),
            ("something after the end", format!("{lock}table inet rosetun {{\n}}\n")),
            (
                "only a forward chain",
                lock.replace("chain output", "chain forward")
                    .replace("hook output", "hook forward"),
            ),
            (
                "two output chains",
                lock.replace(
                    "\t}\n}",
                    "\t}\n\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t}\n}",
                ),
            ),
        ] {
            assert_eq!(left_behind(&text), LeftBehind::Unknown, "{what}");
        }
    }

    #[test]
    fn interface_names_outside_the_kernels_alphabet_are_refused() {
        for name in [
            "",
            ".",
            "..",
            "tun\"0",
            "tun 0",
            "tun;0",
            "tun0\n",
            "tun}",
            "a234567890123456",
            "tün0",
            "tun/0",
        ] {
            assert!(
                matches!(InterfaceName::new(name), Err(RoutingError::Tun { .. })),
                "{name:?}"
            );
        }
        for name in ["rosetun0", "tun-0", "a.b_c", "a23456789012345"] {
            assert_eq!(InterfaceName::new(name).unwrap().as_str(), name);
        }
    }

    /// Every text is made of the fixed words and checked values only; a
    /// quote, brace or newline can come from nowhere else.
    #[test]
    fn the_text_holds_nothing_but_known_words_and_checked_values() {
        let engines = engines();
        let helper = helper();
        let tunnel = InterfaceName::new("tun-0.a_b").unwrap();
        for scope in [ProtectionScope::AllTraffic, ProtectionScope::DnsOnly] {
            for allow_lan in [false, true] {
                let text = replace(&Rules {
                    lan: None,
                    scope,
                    allow_lan,
                    engines: Some(&engines),
                    lockdown: None,
                    hold: Some(&helper),
                    tunnel: Some(&tunnel),
                });
                for line in text.lines() {
                    let quoted: Vec<&str> = line.split('"').skip(1).step_by(2).collect();
                    for value in quoted {
                        assert!(
                            ["lo", "tun-0.a_b", &engines.relative(), &helper.relative()]
                                .contains(&value),
                            "{value}"
                        );
                    }
                    assert!(
                        line.chars()
                            .all(|c| c.is_ascii_graphic() || c == ' ' || c == '\t'),
                        "{line:?}"
                    );
                }
                assert_eq!(text.matches('{').count(), text.matches('}').count());
            }
        }
    }

    fn gui() -> CgroupPath {
        CgroupPath::parse(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/rosetun-gui.scope",
        )
        .unwrap()
    }

    const LOCKDOWN_HEAD: &str = "add table inet rosetun\ndelete table inet rosetun\ntable inet rosetun {\n\tchain input {\n";
    const INPUT_BASE: &str = "\t\tct state established,related accept
\t\tmeta nfproto ipv4 udp sport 67 udp dport 68 accept
\t\ticmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept
";
    const OUTPUT_BOOTSTRAP: &str = "\t\tmeta nfproto ipv4 udp sport 68 udp dport 67 accept
\t\ticmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept
";

    /// Lockdown's set as the boot unit writes it: no cgroup at all.
    fn boot(lan: bool) -> String {
        let access = LanAccess {
            private_networks: true,
            ..LanAccess::default()
        };
        replace(&Rules {
            lan: lan.then_some(&access),
            scope: ProtectionScope::AllTraffic,
            allow_lan: false,
            engines: None,
            hold: None,
            tunnel: None,
            lockdown: Some(Lockdown {
                lan,
                session: false,
                helper: None,
                programs: &[],
            }),
        })
    }

    #[test]
    fn lockdown_at_boot_names_no_cgroup_and_closes_both_ways() {
        assert_eq!(
            boot(false),
            format!(
                "{LOCKDOWN_HEAD}\
\t\ttype filter hook input priority filter; policy drop;
\t\tiif \"lo\" accept
{INPUT_BASE}\
\t}}
\tchain output {{
\t\ttype filter hook output priority filter; policy drop;
\t\toif \"lo\" accept
{OUTPUT_BOOTSTRAP}\
\t}}
\tchain forward {{
\t\ttype filter hook forward priority filter; policy drop;
\t}}
}}
"
            )
        );
        assert!(!boot(true).contains("cgroupv2"));
    }

    #[test]
    fn lockdowns_local_network_opens_it_both_ways_but_never_for_dns() {
        let text = boot(true);
        assert_eq!(
            text,
            format!(
                "{LOCKDOWN_HEAD}\
\t\ttype filter hook input priority filter; policy drop;
\t\tiif \"lo\" accept
{INPUT_BASE}\
\t\tip saddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }} accept
\t\tip6 saddr {{ fe80::/10, fc00::/7 }} accept
\t}}
\tchain output {{
\t\ttype filter hook output priority filter; policy drop;
\t\tip daddr {{ 169.254.0.0/16, 224.0.0.0/24, 239.255.255.250/32, 255.255.255.255/32 }} meta l4proto {{ tcp, udp }} th dport 53 drop
\t\tip6 daddr {{ fe80::/10 }} meta l4proto {{ tcp, udp }} th dport 53 drop
\t\tip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }} meta l4proto {{ tcp, udp }} th dport 53 drop
\t\tip6 daddr {{ fe80::/10, fc00::/7 }} meta l4proto {{ tcp, udp }} th dport 53 drop
\t\toif \"lo\" accept
{OUTPUT_BOOTSTRAP}\
\t\tip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }} accept
\t\tip6 daddr {{ fe80::/10, fc00::/7 }} accept
\t}}
\tchain forward {{
\t\ttype filter hook forward priority filter; policy drop;
\t}}
}}
"
            )
        );
    }

    #[test]
    fn lockdown_without_a_session_permits_the_service_and_the_programs_first() {
        let engines = engines();
        let helper = helper();
        let programs = [gui()];
        let access = LanAccess {
            private_networks: true,
            ..LanAccess::default()
        };
        let text = replace(&Rules {
            lan: Some(&access),
            scope: ProtectionScope::AllTraffic,
            allow_lan: false,
            engines: Some(&engines),
            hold: None,
            tunnel: None,
            lockdown: Some(Lockdown {
                lan: true,
                session: false,
                helper: Some(&helper),
                programs: &programs,
            }),
        });
        let gui = "socket cgroupv2 level 5 \"user.slice/user-1000.slice/user@1000.service/app.slice/rosetun-gui.scope\"";
        assert_eq!(
            text,
            format!(
                "{LOCKDOWN_HEAD}\
\t\ttype filter hook input priority filter; policy drop;
\t\tiif \"lo\" accept
{INPUT_BASE}\
\t\tip saddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }} accept
\t\tip6 saddr {{ fe80::/10, fc00::/7 }} accept
\t}}
\tchain output {{
\t\ttype filter hook output priority filter; policy drop;
\t\tsocket cgroupv2 level 3 \"system.slice/rosetun-helper.service/helper\" meta l4proto {{ tcp, udp }} th dport 53 accept
\t\t{gui} meta l4proto tcp accept
\t\t{gui} udp dport 53 accept
\t\tip daddr {{ 169.254.0.0/16, 224.0.0.0/24, 239.255.255.250/32, 255.255.255.255/32 }} meta l4proto {{ tcp, udp }} th dport 53 drop
\t\tip6 daddr {{ fe80::/10 }} meta l4proto {{ tcp, udp }} th dport 53 drop
\t\tip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }} meta l4proto {{ tcp, udp }} th dport 53 drop
\t\tip6 daddr {{ fe80::/10, fc00::/7 }} meta l4proto {{ tcp, udp }} th dport 53 drop
\t\toif \"lo\" accept
\t\tsocket cgroupv2 level 3 \"system.slice/rosetun-helper.service/engines\" accept
{OUTPUT_BOOTSTRAP}\
\t\tip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }} accept
\t\tip6 daddr {{ fe80::/10, fc00::/7 }} accept
\t}}
\tchain forward {{
\t\ttype filter hook forward priority filter; policy drop;
\t}}
}}
"
            )
        );
    }

    fn locked_session(lan: bool, allow_lan: bool, tunnel: Option<&InterfaceName>) -> String {
        let engines = engines();
        let helper = helper();
        let access = LanAccess {
            private_networks: true,
            ..LanAccess::default()
        };
        replace(&Rules {
            lan: Some(&access),
            // Lockdown makes any session all-traffic.
            scope: ProtectionScope::DnsOnly,
            allow_lan,
            engines: Some(&engines),
            hold: None,
            tunnel,
            lockdown: Some(Lockdown {
                lan,
                session: true,
                helper: Some(&helper),
                programs: &[],
            }),
        })
    }

    #[test]
    fn a_session_under_lockdown_starts_with_no_reply_permit_and_nothing_forwarded_but_answers() {
        assert_eq!(
            locked_session(false, false, None),
            format!(
                "{LOCKDOWN_HEAD}\
\t\ttype filter hook input priority filter; policy drop;
\t\tiif \"lo\" accept
{INPUT_BASE}\
\t}}
\tchain output {{
\t\ttype filter hook output priority filter; policy drop;
\t\tsocket cgroupv2 level 3 \"system.slice/rosetun-helper.service/helper\" meta l4proto {{ tcp, udp }} th dport 53 accept
\t\toif \"lo\" accept
\t\tsocket cgroupv2 level 3 \"system.slice/rosetun-helper.service/engines\" accept
{OUTPUT_BOOTSTRAP}\
\t}}
\tchain forward {{
\t\ttype filter hook forward priority filter; policy drop;
\t\tct direction reply accept
\t}}
}}
"
            )
        );
    }

    #[test]
    fn a_tunnel_under_lockdown_is_open_both_ways_and_forwarded() {
        let tunnel = InterfaceName::new("rosetun0").unwrap();
        assert_eq!(
            locked_session(false, false, Some(&tunnel)),
            format!(
                "{LOCKDOWN_HEAD}\
\t\ttype filter hook input priority filter; policy drop;
\t\tiif \"lo\" accept
\t\tiif \"rosetun0\" accept
{INPUT_BASE}\
\t}}
\tchain output {{
\t\ttype filter hook output priority filter; policy drop;
\t\toif \"rosetun0\" accept
\t\tsocket cgroupv2 level 3 \"system.slice/rosetun-helper.service/helper\" meta l4proto {{ tcp, udp }} th dport 53 accept
\t\toif \"lo\" accept
\t\tsocket cgroupv2 level 3 \"system.slice/rosetun-helper.service/engines\" accept
{OUTPUT_BOOTSTRAP}\
\t}}
\tchain forward {{
\t\ttype filter hook forward priority filter; policy drop;
\t\toif \"rosetun0\" accept
\t\tct direction reply accept
\t}}
}}
"
            )
        );
    }

    #[test]
    fn a_sessions_local_network_under_lockdown_goes_out_and_forwarded_but_not_in() {
        let tunnel = InterfaceName::new("rosetun0").unwrap();
        let text = locked_session(false, true, Some(&tunnel));
        let input = &text[..text.find("\tchain output").unwrap()];
        assert!(!input.contains("saddr"), "{input}");
        let output =
            &text[text.find("\tchain output").unwrap()..text.find("\tchain forward").unwrap()];
        assert!(output.contains(
            "\t\tip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept\n"
        ));
        let forward = &text[text.find("\tchain forward").unwrap()..];
        assert!(forward.contains("\t\tip6 daddr { fe80::/10, fc00::/7 } accept\n"));
        assert!(forward.contains("th dport 53 drop"));
        // Lockdown's own "Local network" lets the private ranges in too.
        let with_lockdown_lan = locked_session(true, false, Some(&tunnel));
        assert!(with_lockdown_lan.contains("\t\tip saddr { 10.0.0.0/8"));
        assert!(with_lockdown_lan.contains(
            "\t\tip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept\n"
        ));
    }

    #[test]
    fn a_lockdown_table_found_without_its_record_is_unknown() {
        let listing = boot(true)[remove().len()..].to_owned();
        assert_eq!(left_behind(&listing), LeftBehind::Unknown);
    }

    #[test]
    fn lockdown_text_holds_nothing_but_known_words_and_checked_values() {
        let engines = engines();
        let helper = helper();
        let programs = [gui()];
        let tunnel = InterfaceName::new("tun-0.a_b").unwrap();
        for lan in [false, true] {
            for session in [false, true] {
                let text = replace(&Rules {
                    lan: None,
                    scope: ProtectionScope::AllTraffic,
                    allow_lan: lan,
                    engines: Some(&engines),
                    hold: None,
                    tunnel: Some(&tunnel),
                    lockdown: Some(Lockdown {
                        lan,
                        session,
                        helper: Some(&helper),
                        programs: &programs,
                    }),
                });
                for line in text.lines() {
                    for value in line.split('"').skip(1).step_by(2) {
                        assert!(
                            [
                                "lo",
                                "tun-0.a_b",
                                &engines.relative(),
                                &helper.relative(),
                                &programs[0].relative()
                            ]
                            .contains(&value),
                            "{value}"
                        );
                    }
                    assert!(
                        line.chars()
                            .all(|c| c.is_ascii_graphic() || c == ' ' || c == '\t'),
                        "{line:?}"
                    );
                }
                assert_eq!(text.matches('{').count(), text.matches('}').count());
            }
        }
    }
}
