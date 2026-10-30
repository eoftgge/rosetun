#![deny(unsafe_code)]

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod windows;

use std::io;
#[cfg(any(windows, test))]
use std::net::Ipv4Addr;

#[cfg(any(windows, test))]
#[derive(Debug)]
struct Adapter {
    name: String,
    description: String,
    #[cfg(windows)]
    luid: u64,
    interface_type: u32,
    up: bool,
}

#[cfg(any(windows, test))]
#[derive(Debug, Default, Clone, Copy)]
struct DefaultRoutes {
    full: bool,
    lower_half: bool,
    upper_half: bool,
}

#[cfg(any(windows, test))]
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

#[cfg(any(windows, test))]
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

#[cfg(any(windows, test))]
fn is_active_vpn_adapter(adapter: &Adapter, own_alias: &str) -> bool {
    let description = adapter.description.to_ascii_lowercase();
    adapter.up
        && !adapter.name.is_empty()
        && !adapter.name.eq_ignore_ascii_case(own_alias)
        && ["wintun", "wireguard", "tap"].iter().any(|marker| {
            description.contains(marker) || adapter.name.to_ascii_lowercase().contains(marker)
        })
}

/// Names of active Wintun, TAP or WireGuard adapters other than our own.
pub fn active_vpn_adapters(own_alias: &str) -> io::Result<Vec<String>> {
    #[cfg(windows)]
    {
        windows::active_vpn_adapters(own_alias)
    }
    #[cfg(not(windows))]
    {
        let _ = own_alias;
        Ok(Vec::new())
    }
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
            #[cfg(windows)]
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
    fn active_vpn_adapters_require_up_and_exclude_our_alias() {
        assert!(is_active_vpn_adapter(
            &adapter("Example", "Example Wintun Adapter", 53, true),
            "rosetun0"
        ));
        assert!(is_active_vpn_adapter(
            &adapter("Example TAP", "Example virtual adapter", 6, true),
            "rosetun0"
        ));
        assert!(is_active_vpn_adapter(
            &adapter("Example", "WireGuard Tunnel", 53, true),
            "rosetun0"
        ));
        assert!(!is_active_vpn_adapter(
            &adapter("rosetun0", "Wintun", 53, true),
            "ROSETUN0"
        ));
        assert!(!is_active_vpn_adapter(
            &adapter("Example", "TAP", 53, false),
            "rosetun0"
        ));
        assert!(!is_active_vpn_adapter(
            &adapter("Ethernet", "Physical adapter", 6, true),
            "rosetun0"
        ));
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
