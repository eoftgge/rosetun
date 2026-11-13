//! The adapters "Local network" looks at on Linux: what `getifaddrs` and
//! `/sys/class/net` say about the interfaces that are up, in the form
//! `lan::select` takes, so one rule decides on both systems which of them
//! lead to a real network next to the computer.

use std::io;
use std::path::Path;

use super::connected::{self, Found, SYS_NET};
use super::physical;
use crate::lan::{Adapter, ETHERNET, InterfaceId, WIFI};

/// `ARPHRD_ETHER` in `/sys/class/net/<name>/type`. Tunnels (`ARPHRD_NONE`,
/// `ARPHRD_TUNNEL`) and loopback have other values.
const ARPHRD_ETHER: &str = "1";

pub(in crate::platform) fn adapters(tunnel_alias: &str) -> io::Result<Vec<Adapter>> {
    let found = connected::interfaces_up()?;
    let gateways = physical::interfaces_with_default_route(tunnel_alias);
    Ok(adapters_of(&found, Path::new(SYS_NET), &gateways))
}

fn read(sys_net: &Path, name: &str, file: &str) -> Option<String> {
    std::fs::read_to_string(sys_net.join(name).join(file))
        .ok()
        .map(|text| text.trim().to_owned())
}

/// One adapter per interface name, with every address it holds.
fn adapters_of(found: &[Found], sys_net: &Path, gateways: &[String]) -> Vec<Adapter> {
    let mut adapters: Vec<Adapter> = Vec::new();
    for entry in found {
        if let Some(adapter) = adapters.iter_mut().find(|a| a.alias == entry.name) {
            adapter.addresses.push((entry.address, entry.length));
            continue;
        }
        // An interface that vanished since `getifaddrs` has no index: skip it.
        let Some(index) = read(sys_net, &entry.name, "ifindex").and_then(|text| text.parse().ok())
        else {
            continue;
        };
        let dir = sys_net.join(&entry.name);
        let ethernet = read(sys_net, &entry.name, "type").as_deref() == Some(ARPHRD_ETHER);
        let wireless = dir.join("wireless").exists() || dir.join("phy80211").exists();
        // `unknown` is what many drivers report for an interface that works.
        let up = read(sys_net, &entry.name, "operstate")
            .is_none_or(|state| matches!(state.as_str(), "up" | "unknown"));
        adapters.push(Adapter {
            interface: InterfaceId(index),
            alias: entry.name.clone(),
            description: String::new(),
            if_type: match (ethernet, wireless) {
                (true, true) => WIFI,
                (true, false) => ETHERNET,
                // Not Ethernet-like at all: a tunnel, a bridge to nothing.
                (false, _) => 0,
            },
            up,
            hardware: dir.join("device").exists(),
            has_gateway: gateways.contains(&entry.name),
            addresses: vec![(entry.address, entry.length)],
        });
    }
    adapters
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::path::PathBuf;

    use super::*;
    use crate::lan::{SegmentQuery, select};

    struct Sys(PathBuf);

    impl Sys {
        fn new(test: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("rosetun-segment-{test}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }

        fn interface(&self, name: &str, index: u32, kind: &str, state: &str, device: bool) {
            let dir = self.0.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("ifindex"), format!("{index}\n")).unwrap();
            std::fs::write(dir.join("type"), format!("{kind}\n")).unwrap();
            std::fs::write(dir.join("operstate"), format!("{state}\n")).unwrap();
            if device {
                std::fs::create_dir_all(dir.join("device")).unwrap();
            }
        }

        fn wireless(&self, name: &str) {
            std::fs::create_dir_all(self.0.join(name).join("wireless")).unwrap();
        }
    }

    impl Drop for Sys {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn found(name: &str, address: &str, length: u8) -> Found {
        Found {
            name: name.to_owned(),
            address: address.parse().unwrap(),
            length,
        }
    }

    fn prefixes(adapters: &[Adapter]) -> Vec<String> {
        let query = SegmentQuery {
            tunnel_alias: "rosetun0",
            tunnel_networks: &[],
            servers: &[],
        };
        select(adapters, &query)
            .segment
            .prefixes()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn a_nic_and_a_bridge_with_a_gateway_are_the_segment_and_software_interfaces_are_not() {
        let sys = Sys::new("kinds");
        sys.interface("eth0", 2, "1", "up", true);
        sys.interface("wlan0", 3, "1", "up", true);
        sys.wireless("wlan0");
        sys.interface("br0", 4, "1", "up", false);
        sys.interface("docker0", 5, "1", "up", false);
        sys.interface("virbr0", 6, "1", "up", false);
        sys.interface("wg0", 7, "65534", "unknown", false);
        sys.interface("rosetun0", 8, "65534", "unknown", false);
        sys.interface("lo", 1, "772", "unknown", false);
        let list = [
            found("lo", "127.0.0.1", 8),
            found("eth0", "192.0.2.15", 24),
            found("eth0", "2001:db8:1::15", 64),
            found("wlan0", "198.51.100.20", 24),
            found("br0", "203.0.113.7", 24),
            found("docker0", "172.17.0.1", 16),
            found("virbr0", "192.168.122.1", 24),
            found("wg0", "10.8.0.2", 24),
            found("rosetun0", "172.19.0.1", 30),
        ];
        let adapters = adapters_of(&list, &sys.0, &["br0".to_owned()]);
        assert_eq!(adapters.len(), 8);
        assert_eq!(
            prefixes(&adapters),
            [
                "192.0.2.0/24",
                "198.51.100.0/24",
                "203.0.113.0/24",
                "2001:db8:1::/64"
            ]
        );
    }

    #[test]
    fn one_adapter_holds_all_the_addresses_of_its_interface() {
        let sys = Sys::new("addresses");
        sys.interface("eth0", 2, "1", "up", true);
        let list = [
            found("eth0", "192.0.2.15", 24),
            found("eth0", "fe80::1", 64),
            found("eth0", "198.51.100.9", 25),
        ];
        let adapters = adapters_of(&list, &sys.0, &[]);
        assert_eq!(adapters.len(), 1);
        assert_eq!(adapters[0].interface, InterfaceId(2));
        assert_eq!(adapters[0].addresses.len(), 3);
        assert!(adapters[0].hardware && !adapters[0].has_gateway);
        assert_eq!(adapters[0].if_type, ETHERNET);
    }

    #[test]
    fn a_link_that_is_down_and_an_interface_that_vanished_are_not_up() {
        let sys = Sys::new("down");
        sys.interface("eth0", 2, "1", "down", true);
        sys.interface("eth1", 3, "1", "lowerlayerdown", true);
        let list = [
            found("eth0", "192.0.2.15", 24),
            found("eth1", "198.51.100.9", 24),
            found("gone0", "203.0.113.9", 24),
        ];
        let adapters = adapters_of(&list, &sys.0, &[]);
        assert_eq!(adapters.len(), 2);
        assert!(adapters.iter().all(|adapter| !adapter.up));
        assert!(prefixes(&adapters).is_empty());
    }

    #[test]
    fn a_wireless_interface_is_wifi_and_a_tunnel_is_neither() {
        let sys = Sys::new("wifi");
        sys.interface("wlan0", 3, "1", "up", true);
        sys.wireless("wlan0");
        sys.interface("tun0", 4, "65534", "unknown", false);
        let list = [
            found("wlan0", "192.0.2.15", 24),
            found("tun0", "10.8.0.2", 24),
        ];
        let adapters = adapters_of(&list, &sys.0, &["tun0".to_owned()]);
        assert_eq!(adapters[0].if_type, WIFI);
        assert_eq!(adapters[1].if_type, 0);
        let address: IpAddr = "10.8.0.2".parse().unwrap();
        assert_eq!(adapters[1].addresses[0].0, address);
    }

    #[test]
    fn this_machines_adapters_can_be_read() {
        assert!(adapters("rosetun0").is_ok());
    }
}
