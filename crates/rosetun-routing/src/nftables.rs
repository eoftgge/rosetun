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
//! cgroup paths as `CgroupPath`, addresses as `Ipv4Addr` and `Ipv6Addr`.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::cgroup::CgroupPath;
use crate::{ProtectionScope, RoutingError};

pub(crate) const TABLE: &str = "rosetun";
/// `IFNAMSIZ` minus the terminating zero.
const MAX_INTERFACE_BYTES: usize = 15;

/// As on Windows: the private ranges and link-local, permitted with "Local
/// network", but never for DNS.
const LAN_V4: [(Ipv4Addr, u8); 4] = [
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
];
const LAN_V6: [(Ipv6Addr, u8); 2] = [
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
];
/// IPv6 neighbor discovery the kernel sends without a socket, so with no
/// cgroup: without it the engine cannot reach a server over IPv6 and the
/// host loses its neighbors. Hop limit 255 is what RFC 4861 requires: a
/// copy that crossed a router arrives with less and is discarded, so the
/// permit reaches the link only, and forging one takes `CAP_NET_RAW`. Not
/// all of ICMPv6, which would be a way out past the kill switch.
const NEIGHBOR_DISCOVERY: &str = "icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept";

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
    /// Private ranges and link-local; only with `AllTraffic`.
    pub(crate) allow_lan: bool,
    /// The engines' leaf: everything an engine sends passes.
    pub(crate) engines: &'a CgroupPath,
    /// The hold after a crash, with the helper's own leaf: the helper may
    /// send DNS, to resolve a server name for the connect that lifts the
    /// hold, and nothing is forwarded.
    pub(crate) hold: Option<&'a CgroupPath>,
    /// Phase 2: the engine's TUN, once it exists.
    pub(crate) tunnel: Option<&'a InterfaceName>,
}

impl Rules<'_> {
    fn lan(&self) -> bool {
        self.allow_lan && self.scope == ProtectionScope::AllTraffic
    }
}

/// Replaces the table with `rules` in one transaction.
pub(crate) fn replace(rules: &Rules<'_>) -> String {
    let mut text = remove();
    let _ = writeln!(text, "table inet {TABLE} {{");
    output_chain(&mut text, rules);
    forward_chain(&mut text, rules);
    text.push_str("}\n");
    text
}

/// What this host sends.
fn output_chain(text: &mut String, rules: &Rules<'_>) {
    chain_head(text, "output", rules.scope);
    // The tunnel first: its own DNS address lies in 172.16/12, which the
    // private DNS drop below would catch.
    tunnel_permit(text, rules);
    lan_dns_drop(text, rules);
    text.push_str("\t\toif \"lo\" accept\n");
    if rules.scope == ProtectionScope::AllTraffic {
        // Answers to connections opened from outside, as under the Windows
        // kill switch, which authorizes only connects: the other side knows
        // the address already. A connection this host opened sends in the
        // original direction and is not let out by this, provided conntrack
        // saw it begin; one it picks up halfway takes its direction from the
        // first packet it sees.
        text.push_str("\t\tct direction reply accept\n");
    }
    let _ = writeln!(text, "\t\t{} accept", cgroup_match(rules.engines));
    if let Some(helper) = rules.hold {
        let _ = writeln!(
            text,
            "\t\t{} meta l4proto {{ tcp, udp }} th dport 53 accept",
            cgroup_match(helper)
        );
    }
    match rules.scope {
        ProtectionScope::AllTraffic => {
            text.push_str("\t\tmeta nfproto ipv4 udp sport 68 udp dport 67 accept\n");
            let _ = writeln!(text, "\t\t{NEIGHBOR_DISCOVERY}");
            lan_permit(text, rules);
        }
        ProtectionScope::DnsOnly => {
            text.push_str("\t\tmeta l4proto { tcp, udp } th dport 53 drop\n");
        }
    }
    text.push_str("\t}\n");
}

/// What this host passes on for others: containers, virtual machines,
/// a shared connection. Under the kill switch they get the tunnel, the
/// local network if it is on, and answers to what was opened towards them
/// (the tunnel's answers come back on the tunnel and leave towards them,
/// so without this the tunnel would carry nothing back); under the DNS
/// lock only their DNS beside the tunnel is dropped. Nothing has a cgroup
/// here, so there is no engine permit.
fn forward_chain(text: &mut String, rules: &Rules<'_>) {
    chain_head(text, "forward", rules.scope);
    if rules.hold.is_none() {
        tunnel_permit(text, rules);
        lan_dns_drop(text, rules);
        match rules.scope {
            ProtectionScope::AllTraffic => {
                text.push_str("\t\tct direction reply accept\n");
                lan_permit(text, rules);
            }
            ProtectionScope::DnsOnly => {
                text.push_str("\t\tmeta l4proto { tcp, udp } th dport 53 drop\n");
            }
        }
    }
    text.push_str("\t}\n");
}

fn chain_head(text: &mut String, hook: &str, scope: ProtectionScope) {
    let policy = match scope {
        ProtectionScope::AllTraffic => "drop",
        ProtectionScope::DnsOnly => "accept",
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

fn lan_dns_drop(text: &mut String, rules: &Rules<'_>) {
    if rules.lan() {
        let _ = writeln!(
            text,
            "\t\tip daddr {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 drop",
            v4_list()
        );
        let _ = writeln!(
            text,
            "\t\tip6 daddr {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 drop",
            v6_list()
        );
    }
}

fn lan_permit(text: &mut String, rules: &Rules<'_>) {
    if rules.lan() {
        let _ = writeln!(text, "\t\tip daddr {{ {} }} accept", v4_list());
        let _ = writeln!(text, "\t\tip6 daddr {{ {} }} accept", v6_list());
    }
}

/// Removes the table; harmless when there is none.
pub(crate) fn remove() -> String {
    format!("add table inet {TABLE}\ndelete table inet {TABLE}\n")
}

/// Whether `nft list tables inet` shows Rosetun's table.
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

fn v4_list() -> String {
    LAN_V4
        .iter()
        .map(|(address, prefix)| format!("{address}/{prefix}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn v6_list() -> String {
    LAN_V6
        .iter()
        .map(|(address, prefix)| format!("{address}/{prefix}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

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
            scope: ProtectionScope::AllTraffic,
            allow_lan: false,
            engines: &engines,
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
            scope: ProtectionScope::AllTraffic,
            allow_lan: false,
            engines: &engines,
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

    #[test]
    fn the_local_network_is_permitted_but_never_for_dns() {
        let engines = engines();
        let tunnel = InterfaceName::new("rosetun0").unwrap();
        let text = replace(&Rules {
            scope: ProtectionScope::AllTraffic,
            allow_lan: true,
            engines: &engines,
            hold: None,
            tunnel: Some(&tunnel),
        });
        assert_eq!(
            text,
            format!(
                "{HEAD}\
\t\ttype filter hook output priority filter; policy drop;
\t\toif \"rosetun0\" accept
\t\tip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }} meta l4proto {{ tcp, udp }} th dport 53 drop
\t\tip6 daddr {{ fe80::/10, fc00::/7 }} meta l4proto {{ tcp, udp }} th dport 53 drop
\t\toif \"lo\" accept
\t\tct direction reply accept
\t\tsocket cgroupv2 level 3 \"system.slice/rosetun-helper.service/engines\" accept
\t\tmeta nfproto ipv4 udp sport 68 udp dport 67 accept
\t\ticmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} ip6 hoplimit 255 accept
\t\tip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }} accept
\t\tip6 daddr {{ fe80::/10, fc00::/7 }} accept
\t}}
\tchain forward {{
\t\ttype filter hook forward priority filter; policy drop;
\t\toif \"rosetun0\" accept
\t\tip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }} meta l4proto {{ tcp, udp }} th dport 53 drop
\t\tip6 daddr {{ fe80::/10, fc00::/7 }} meta l4proto {{ tcp, udp }} th dport 53 drop
\t\tct direction reply accept
\t\tip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }} accept
\t\tip6 daddr {{ fe80::/10, fc00::/7 }} accept
\t}}
}}
"
            )
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
                scope: ProtectionScope::DnsOnly,
                allow_lan: true,
                engines: &engines,
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
            scope: ProtectionScope::AllTraffic,
            allow_lan: false,
            engines: &engines,
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
            scope: ProtectionScope::DnsOnly,
            allow_lan: false,
            engines: &engines,
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
                    (ProtectionScope::AllTraffic, Some(&helper), LeftBehind::KillSwitch),
                    (ProtectionScope::DnsOnly, None, LeftBehind::DnsLock),
                ] {
                    let text = listing(&Rules {
                        scope,
                        allow_lan,
                        engines: &engines,
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
                    scope,
                    allow_lan,
                    engines: &engines,
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
}
