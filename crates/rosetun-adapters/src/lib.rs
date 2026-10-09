#![deny(unsafe_code)]

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

use std::io;
use std::net::Ipv4Addr;

#[derive(Debug)]
struct Adapter {
    name: String,
    description: String,
    luid: u64,
    interface_type: u32,
    up: bool,
}

#[derive(Debug, Default, Clone, Copy)]
struct DefaultRoutes {
    full: bool,
    lower_half: bool,
    upper_half: bool,
}

impl DefaultRoutes {
    fn observe(&mut self, address: Ipv4Addr, prefix: u8) {
        match (address.octets(), prefix) {
            ([0, 0, 0, 0], 0) => self.full = true,
            ([0, 0, 0, 0], 1) => self.lower_half = true,
            ([128, 0, 0, 0], 1) => self.upper_half = true,
            _ => {}
        }
    }

    fn covers_default(self) -> bool {
        self.full || (self.lower_half && self.upper_half)
    }
}

fn is_other_tunnel(adapter: &Adapter, routes: DefaultRoutes, own_alias: &str) -> bool {
    let description = adapter.description.to_ascii_lowercase();
    adapter.up
        && matches!(adapter.interface_type, 53 | 131)
        && !adapter.name.is_empty()
        && adapter.name.to_lowercase() != own_alias.to_lowercase()
        && ![
            "teredo",
            "isatap",
            "6to4",
            "ip-https",
            "iphttps",
            "kernel debug",
        ]
        .iter()
        .any(|marker| description.contains(marker))
        && routes.covers_default()
}

/// Names of operational virtual/tunnel adapters that carry an IPv4 default route.
/// A lookup failure is returned without adapter names so callers can log it privately.
pub fn other_tunnels(own_alias: &str) -> io::Result<Vec<String>> {
    #[cfg(windows)]
    {
        windows::other_tunnels(own_alias)
    }
    #[cfg(not(windows))]
    {
        let _ = own_alias;
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(name: &str, description: &str, interface_type: u32, up: bool) -> Adapter {
        Adapter {
            name: name.into(),
            description: description.into(),
            luid: 1,
            interface_type,
            up,
        }
    }

    fn routes(entries: &[(Ipv4Addr, u8)]) -> DefaultRoutes {
        let mut routes = DefaultRoutes::default();
        for &(address, prefix) in entries {
            routes.observe(address, prefix);
        }
        routes
    }

    #[test]
    fn recognizes_only_a_full_or_split_default_on_another_active_tunnel() {
        let vpn = adapter("Example VPN", "Example virtual adapter", 53, true);
        let full = routes(&[(Ipv4Addr::UNSPECIFIED, 0)]);
        let split = routes(&[(Ipv4Addr::UNSPECIFIED, 1), (Ipv4Addr::new(128, 0, 0, 0), 1)]);
        assert!(is_other_tunnel(&vpn, full, "rosetun0"));
        assert!(is_other_tunnel(&vpn, split, "rosetun0"));
        assert!(is_other_tunnel(
            &adapter("Example VPN", "Example tunnel", 131, true),
            full,
            "rosetun0"
        ));
        assert!(!is_other_tunnel(
            &vpn,
            routes(&[(Ipv4Addr::UNSPECIFIED, 1)]),
            "rosetun0"
        ));
        assert!(!is_other_tunnel(
            &vpn,
            routes(&[(Ipv4Addr::new(192, 0, 2, 0), 24)]),
            "rosetun0"
        ));
    }

    #[test]
    fn excludes_own_system_down_and_physical_adapters() {
        let full = routes(&[(Ipv4Addr::UNSPECIFIED, 0)]);
        assert!(!is_other_tunnel(
            &adapter("rosetun0", "Example", 53, true),
            full,
            "ROSETUN0"
        ));
        assert!(!is_other_tunnel(
            &adapter("Teredo", "Microsoft Teredo Tunneling", 131, true),
            full,
            "rosetun0"
        ));
        for description in ["ISATAP", "6to4", "IP-HTTPS", "Kernel Debug Network Adapter"] {
            assert!(!is_other_tunnel(
                &adapter("Example", description, 53, true),
                full,
                "rosetun0"
            ));
        }
        assert!(!is_other_tunnel(
            &adapter("Example", "VPN", 53, false),
            full,
            "rosetun0"
        ));
        assert!(!is_other_tunnel(
            &adapter("Ethernet", "Ethernet", 6, true),
            full,
            "rosetun0"
        ));
    }
}
