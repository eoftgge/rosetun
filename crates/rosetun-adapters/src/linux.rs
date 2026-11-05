//! Other VPNs on Linux: WireGuard and TUN/TAP interfaces in `/sys`, and the
//! VPN connections NetworkManager has up.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use zbus::blocking::Connection;
use zbus::blocking::connection::Builder;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use crate::DefaultRoutes;

const SYS_NET: &str = "/sys/class/net";
const PROC_ROUTE: &str = "/proc/net/route";
const IFF_UP: u32 = 0x1;
/// The `type` of an interface without a link layer, as TUN and WireGuard are.
const ARPHRD_NONE: u32 = 65534;
/// Interface names that mean a tunnel when their type does not say otherwise.
const TUNNEL_PREFIXES: &[&str] = &["wg", "tun", "tap"];
/// TAP devices a hypervisor makes for its guests; they carry no VPN.
const GUEST_PREFIXES: &[&str] = &["vnet", "virbr", "vmnet", "vboxnet"];
const NETWORK_MANAGER: &str = "org.freedesktop.NetworkManager";
const NETWORK_MANAGER_PATH: &str = "/org/freedesktop/NetworkManager";
const ACTIVE_INTERFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
/// `NM_ACTIVE_CONNECTION_STATE_ACTIVATED`.
const ACTIVATED: u32 = 2;
/// A check must not wait long for a busy or broken NetworkManager.
const BUS_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) fn active_vpn_adapters(own_alias: &str) -> io::Result<Vec<String>> {
    let mut names: BTreeSet<String> = tunnel_interfaces(Path::new(SYS_NET), own_alias)?
        .into_iter()
        .collect();
    // Only as far as it answers: most systems without it are no less checked.
    if let Some(connections) = network_manager_vpns() {
        names.extend(connections);
    }
    Ok(names.into_iter().collect())
}

pub(super) fn other_tunnels(own_alias: &str) -> io::Result<Vec<String>> {
    let tunnels = tunnel_interfaces(Path::new(SYS_NET), own_alias)?;
    let routes = fs::read_to_string(PROC_ROUTE)?;
    let carrying = interfaces_with_default_route(&routes);
    Ok(tunnels
        .into_iter()
        .filter(|name| carrying.contains(name.as_str()))
        .collect())
}

/// Interfaces under `root` (a `/sys/class/net`) that are up tunnels and not ours.
fn tunnel_interfaces(root: &Path, own_alias: &str) -> io::Result<Vec<String>> {
    let mut names: Vec<String> = fs::read_dir(root)?
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            (name != own_alias && is_up_tunnel(&entry.path(), &name)).then_some(name)
        })
        .collect();
    names.sort();
    Ok(names)
}

fn is_up_tunnel(interface: &Path, name: &str) -> bool {
    let read = |file: &str| fs::read_to_string(interface.join(file)).ok();
    let up = read("flags")
        .and_then(|flags| u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).ok())
        .is_some_and(|flags| flags & IFF_UP != 0);
    if !up || GUEST_PREFIXES.iter().any(|prefix| name.starts_with(prefix)) {
        return false;
    }
    let wireguard = read("uevent")
        .is_some_and(|event| event.lines().any(|line| line.trim() == "DEVTYPE=wireguard"));
    let tun_or_tap = interface.join("tun_flags").exists();
    let named_tunnel = TUNNEL_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        && read("type").is_some_and(|kind| kind.trim().parse() == Ok(ARPHRD_NONE));
    wireguard || tun_or_tap || named_tunnel
}

/// Interfaces that carry an IPv4 default route, whole or as the two halves
/// VPN programs add. `wg-quick` puts its route in a table of its own, which
/// this file does not show, so such a tunnel is left out here.
fn interfaces_with_default_route(routes: &str) -> HashSet<&str> {
    let mut seen = std::collections::HashMap::<&str, DefaultRoutes>::new();
    for line in routes.lines().skip(1) {
        let mut fields = line.split_ascii_whitespace();
        let (Some(name), Some(destination)) = (fields.next(), fields.next()) else {
            continue;
        };
        // Interface, Destination, Gateway, Flags, RefCnt, Use, Metric, Mask.
        let (Some(destination), Some(mask)) = (route_address(destination), fields.nth(5)) else {
            continue;
        };
        let Some(mask) = route_address(mask) else {
            continue;
        };
        seen.entry(name)
            .or_default()
            .observe(destination, mask.to_bits().count_ones() as u8);
    }
    seen.into_iter()
        .filter(|(_, routes)| routes.covers_default())
        .map(|(name, _)| name)
        .collect()
}

/// `/proc/net/route` prints an address as a hexadecimal `u32` in memory order.
fn route_address(hex: &str) -> Option<Ipv4Addr> {
    let value = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(value.to_ne_bytes()))
}

fn network_manager_vpns() -> Option<Vec<String>> {
    let connection = Builder::system()
        .ok()?
        .method_timeout(BUS_TIMEOUT)
        .build()
        .ok()?;
    active_vpns(&connection)
}

/// `None` when NetworkManager does not answer.
fn active_vpns(connection: &Connection) -> Option<Vec<String>> {
    let active: Vec<OwnedObjectPath> = property(
        connection,
        NETWORK_MANAGER_PATH,
        NETWORK_MANAGER,
        "ActiveConnections",
    )?
    .try_into()
    .ok()?;
    Some(
        active
            .iter()
            .filter_map(|path| active_vpn_name(connection, path.as_str()))
            .collect(),
    )
}

fn active_vpn_name(connection: &Connection, path: &str) -> Option<String> {
    let text = |name: &str| -> Option<String> {
        property(connection, path, ACTIVE_INTERFACE, name)?
            .try_into()
            .ok()
    };
    let state: u32 = property(connection, path, ACTIVE_INTERFACE, "State")?
        .try_into()
        .ok()?;
    let vpn: bool = property(connection, path, ACTIVE_INTERFACE, "Vpn")?
        .try_into()
        .ok()?;
    let is_vpn = vpn || text("Type").as_deref() == Some("wireguard");
    (state == ACTIVATED && is_vpn).then(|| text("Id"))?
}

fn property(
    connection: &Connection,
    path: &str,
    interface: &str,
    name: &str,
) -> Option<OwnedValue> {
    connection
        .call_method(
            Some(NETWORK_MANAGER),
            path,
            Some(PROPERTIES),
            "Get",
            &(interface, name),
        )
        .ok()?
        .body()
        .deserialize()
        .ok()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn fake_sys(test: &str) -> PathBuf {
        static FOLDERS: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "rosetun-sys-net-{test}-{}-{}",
            std::process::id(),
            FOLDERS.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn interface(root: &Path, name: &str, files: &[(&str, &str)]) {
        let folder = root.join(name);
        fs::create_dir(&folder).unwrap();
        for (file, text) in files {
            fs::write(folder.join(file), format!("{text}\n")).unwrap();
        }
    }

    #[test]
    fn wireguard_and_tun_and_tap_are_found_and_the_rest_is_not() {
        let root = fake_sys("kinds");
        let up = ("flags", "0x1091");
        interface(&root, "lo", &[("flags", "0x9"), ("type", "772")]);
        interface(&root, "eth0", &[up, ("type", "1")]);
        interface(
            &root,
            "wlan0",
            &[up, ("type", "1"), ("uevent", "DEVTYPE=wlan")],
        );
        interface(
            &root,
            "office",
            &[up, ("type", "65534"), ("uevent", "DEVTYPE=wireguard")],
        );
        interface(
            &root,
            "vpn0",
            &[up, ("type", "65534"), ("tun_flags", "0x1001")],
        );
        interface(
            &root,
            "bridge5",
            &[up, ("type", "1"), ("tun_flags", "0x1002")],
        );
        interface(&root, "wg1", &[up, ("type", "65534")]);
        interface(&root, "wgnotvpn", &[up, ("type", "1")]);
        assert_eq!(
            tunnel_interfaces(&root, "rosetun0").unwrap(),
            ["bridge5", "office", "vpn0", "wg1"]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn our_own_interface_and_a_downed_one_do_not_count() {
        let root = fake_sys("own");
        interface(
            &root,
            "rosetun0",
            &[("flags", "0x1091"), ("tun_flags", "0x1001")],
        );
        interface(
            &root,
            "tun1",
            &[("flags", "0x1090"), ("tun_flags", "0x1001")],
        );
        interface(&root, "tun2", &[("tun_flags", "0x1001")]);
        assert!(tunnel_interfaces(&root, "rosetun0").unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_hypervisors_tap_devices_are_no_vpn() {
        let root = fake_sys("guests");
        for name in ["vnet0", "virbr0-nic", "vmnet1", "vboxnet0"] {
            interface(&root, name, &[("flags", "0x1"), ("tun_flags", "0x1002")]);
        }
        assert!(tunnel_interfaces(&root, "rosetun0").unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_missing_sys_is_an_error_not_a_clean_result() {
        assert!(tunnel_interfaces(Path::new("/nonexistent/sys"), "rosetun0").is_err());
    }

    #[test]
    fn a_default_route_is_read_whole_or_as_two_halves() {
        // In memory order, as on the little-endian systems this runs on.
        let half = |octets: [u8; 4]| format!("{:08X}", u32::from_ne_bytes(octets));
        let header =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n";
        let row = |name: &str, destination: [u8; 4], mask: [u8; 4]| {
            format!(
                "{name}\t{}\t00000000\t0001\t0\t0\t0\t{}\t0\t0\t0\n",
                half(destination),
                half(mask)
            )
        };
        let table = [
            header.to_owned(),
            row("eth0", [0, 0, 0, 0], [0, 0, 0, 0]),
            row("wg0", [0, 0, 0, 0], [128, 0, 0, 0]),
            row("wg0", [128, 0, 0, 0], [128, 0, 0, 0]),
            row("tun1", [0, 0, 0, 0], [128, 0, 0, 0]),
            row("tun2", [192, 0, 2, 0], [255, 255, 255, 0]),
        ]
        .concat();
        let carrying = interfaces_with_default_route(&table);
        assert!(carrying.contains("eth0"));
        assert!(carrying.contains("wg0"));
        assert!(!carrying.contains("tun1"), "half of the addresses only");
        assert!(!carrying.contains("tun2"));
        assert!(interfaces_with_default_route(&format!("{header}garbage\n")).is_empty());
    }

    /// A fake NetworkManager on the session bus. `dbus-run-session -- cargo
    /// test -p rosetun-adapters -- --ignored` runs it.
    #[test]
    #[ignore = "needs a session bus"]
    fn only_activated_vpn_connections_are_named() {
        struct Manager;

        #[zbus::interface(name = "org.freedesktop.NetworkManager")]
        impl Manager {
            #[zbus(property)]
            fn active_connections(&self) -> Vec<OwnedObjectPath> {
                ["/a/1", "/a/2", "/a/3", "/a/4"]
                    .iter()
                    .map(|path| OwnedObjectPath::try_from(*path).unwrap())
                    .collect()
            }
        }

        struct Active {
            id: &'static str,
            kind: &'static str,
            vpn: bool,
            state: u32,
        }

        #[zbus::interface(name = "org.freedesktop.NetworkManager.Connection.Active")]
        impl Active {
            #[zbus(property)]
            fn id(&self) -> &str {
                self.id
            }

            #[zbus(property, name = "Type")]
            fn kind(&self) -> &str {
                self.kind
            }

            #[zbus(property)]
            fn vpn(&self) -> bool {
                self.vpn
            }

            #[zbus(property)]
            fn state(&self) -> u32 {
                self.state
            }
        }

        let active = |id, kind, vpn, state| Active {
            id,
            kind,
            vpn,
            state,
        };
        let _server = Builder::session()
            .unwrap()
            .name(NETWORK_MANAGER)
            .unwrap()
            .serve_at(NETWORK_MANAGER_PATH, Manager)
            .unwrap()
            .serve_at("/a/1", active("Office", "vpn", true, ACTIVATED))
            .unwrap()
            .serve_at("/a/2", active("Home", "wireguard", false, ACTIVATED))
            .unwrap()
            .serve_at("/a/3", active("Cable", "802-3-ethernet", false, ACTIVATED))
            .unwrap()
            .serve_at("/a/4", active("Coming up", "vpn", true, 1))
            .unwrap()
            .build()
            .unwrap();
        let client = Connection::session().unwrap();
        assert_eq!(active_vpns(&client).unwrap(), ["Office", "Home"]);
    }
}
