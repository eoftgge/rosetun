//! The DNS servers the system resolver would ask.

use std::net::{IpAddr, SocketAddr};

pub(crate) const DNS_PORT: u16 = 53;

/// The servers of the network adapters that carry a default route, the
/// best-metric adapter first, IPv4 servers before IPv6 ones.
#[cfg(windows)]
pub(crate) fn system() -> Vec<SocketAddr> {
    order(crate::windows::adapter_servers())
}

/// `/etc/resolv.conf`; when it names only a local stub, as with
/// systemd-resolved (127.0.0.53), the servers behind the stub: under
/// Lockdown the stub's own queries cannot get out, while this process's
/// may.
#[cfg(not(windows))]
pub(crate) fn system() -> Vec<SocketAddr> {
    let read = |path| std::fs::read_to_string(path).unwrap_or_default();
    let configured = resolv_conf(&read("/etc/resolv.conf"));
    let servers = if configured.iter().all(|server| server.ip().is_loopback()) {
        let upstream = resolv_conf(&read("/run/systemd/resolve/resolv.conf"));
        behind_stub(configured, upstream)
    } else {
        configured
    };
    order(vec![(0, servers)])
}

/// The stub's upstream servers, unless they are local too or missing.
#[cfg(not(windows))]
fn behind_stub(configured: Vec<SocketAddr>, upstream: Vec<SocketAddr>) -> Vec<SocketAddr> {
    if upstream.is_empty() || upstream.iter().all(|server| server.ip().is_loopback()) {
        configured
    } else {
        upstream
    }
}

#[cfg(not(windows))]
fn resolv_conf(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("nameserver"))
                .then(|| fields.next()?.parse::<IpAddr>().ok())
                .flatten()
        })
        .map(|address| SocketAddr::new(address, DNS_PORT))
        .collect()
}

/// Windows lists `fec0:0:0:ffff::1` to `::3` on adapters without IPv6
/// servers: deprecated site-local placeholders that nobody answers.
fn usable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified() && !address.is_broadcast() && !address.is_multicast()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_multicast()
                && address.segments()[0] & 0xffc0 != 0xfec0
        }
    }
}

/// Orders `(metric, servers)` per adapter: lower metric first, then IPv4
/// before IPv6 (Lockdown passes no IPv6 neighbor discovery, so a link-local
/// IPv6 server may never answer), without repeats.
fn order(mut adapters: Vec<(u32, Vec<SocketAddr>)>) -> Vec<SocketAddr> {
    adapters.sort_by_key(|(metric, _)| *metric);
    let mut servers = Vec::new();
    for ipv6 in [false, true] {
        for (_, list) in &adapters {
            for server in list {
                if server.is_ipv6() == ipv6 && usable(server.ip()) && !servers.contains(server) {
                    servers.push(*server);
                }
            }
        }
    }
    servers
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::order;

    fn servers(list: &[&str]) -> Vec<SocketAddr> {
        list.iter().map(|server| server.parse().unwrap()).collect()
    }

    #[test]
    fn best_adapter_first_ipv4_first_placeholders_dropped() {
        let ordered = order(vec![
            (
                50,
                servers(&["198.51.100.53:53", "[2001:db8::53]:53", "192.0.2.53:53"]),
            ),
            (
                10,
                servers(&[
                    "[fec0:0:0:ffff::1%1]:53",
                    "[fe80::1%7]:53",
                    "192.0.2.1:53",
                    "0.0.0.0:53",
                ]),
            ),
        ]);
        assert_eq!(
            ordered,
            servers(&[
                "192.0.2.1:53",
                "198.51.100.53:53",
                "192.0.2.53:53",
                "[fe80::1%7]:53",
                "[2001:db8::53]:53",
            ])
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_local_stub_gives_way_to_the_servers_behind_it() {
        let stub = servers(&["127.0.0.53:53"]);
        let upstream = servers(&["192.0.2.53:53"]);
        assert_eq!(super::behind_stub(stub.clone(), upstream.clone()), upstream);
        assert_eq!(super::behind_stub(stub.clone(), Vec::new()), stub);
        assert_eq!(
            super::behind_stub(stub.clone(), servers(&["127.0.0.1:53"])),
            stub
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn resolv_conf_nameservers_are_read() {
        let text = "# generated\nnameserver 192.0.2.53\nsearch example.com\nnameserver 2001:db8::53\nnameserver bad\n";
        assert_eq!(
            super::resolv_conf(text),
            servers(&["192.0.2.53:53", "[2001:db8::53]:53"])
        );
    }
}
