use std::ffi::CString;
use std::net::IpAddr;
use std::time::Duration;

use zbus::blocking::{Connection, connection::Builder, fdo::DBusProxy};
use zbus::fdo::Error;
use zbus::zvariant::OwnedValue;

const RESOLVED: &str = "org.freedesktop.resolve1";
const BUS_TIMEOUT: Duration = Duration::from_millis(500);

/// Checks resolved's per-link registration without starting the service or
/// making a DNS request. Bus errors other than an absent service are unknown.
pub(super) fn registered(tunnel: &str, address: IpAddr) -> Option<bool> {
    let name = CString::new(tunnel).ok()?;
    // SAFETY: the CString remains live and nul-terminated for this call.
    let index = i32::try_from(unsafe { libc::if_nametoindex(name.as_ptr()) }).ok()?;
    if index == 0 {
        return None;
    }

    let connection = Builder::system()
        .ok()?
        .method_timeout(BUS_TIMEOUT)
        .build()
        .ok()?;
    registered_on_bus(&connection, index, address)
}

fn registered_on_bus(connection: &Connection, index: i32, address: IpAddr) -> Option<bool> {
    let dbus = DBusProxy::new(connection).ok()?;
    let owner = match dbus.get_name_owner(RESOLVED.try_into().ok()?) {
        Ok(owner) => owner,
        Err(Error::NameHasNoOwner(_)) => return Some(false),
        Err(_) => return None,
    };
    let property: OwnedValue = connection
        .call_method(
            Some(owner.as_str()),
            "/org/freedesktop/resolve1",
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.resolve1.Manager", "DNS"),
        )
        .ok()?
        .body()
        .deserialize()
        .ok()?;
    let entries: Vec<(i32, i32, Vec<u8>)> = property.try_into().ok()?;
    Some(has_server(&entries, index, address))
}

fn has_server(entries: &[(i32, i32, Vec<u8>)], index: i32, address: IpAddr) -> bool {
    entries.iter().any(|(link, family, bytes)| {
        *link == index
            && match address {
                IpAddr::V4(address) => *family == libc::AF_INET && *bytes == address.octets(),
                IpAddr::V6(address) => *family == libc::AF_INET6 && *bytes == address.octets(),
            }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_expected_dns_on_the_tunnel_link_counts() {
        let expected = "192.0.2.53".parse().unwrap();
        let mut entries = vec![
            (0, libc::AF_INET, vec![192, 0, 2, 53]),
            (3, libc::AF_INET, vec![192, 0, 2, 53]),
            (9, libc::AF_INET, vec![192, 0, 2, 54]),
        ];
        assert!(!has_server(&entries, 9, expected));
        entries.push((9, libc::AF_INET, vec![192, 0, 2, 53]));
        assert!(has_server(&entries, 9, expected));
    }

    #[test]
    #[ignore = "requires a private session bus (dbus-run-session)"]
    fn resolved_registration_can_be_read_without_starting_the_service() {
        struct Resolver;

        #[zbus::interface(name = "org.freedesktop.resolve1.Manager")]
        impl Resolver {
            #[zbus(property, name = "DNS")]
            fn dns(&self) -> Vec<(i32, i32, Vec<u8>)> {
                vec![(9, libc::AF_INET, vec![192, 0, 2, 53])]
            }
        }

        let client = Connection::session().unwrap();
        let address = "192.0.2.53".parse().unwrap();
        assert_eq!(registered_on_bus(&client, 9, address), Some(false));
        let _service = Builder::session()
            .unwrap()
            .name(RESOLVED)
            .unwrap()
            .serve_at("/org/freedesktop/resolve1", Resolver)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(registered_on_bus(&client, 8, address), Some(false));
        assert_eq!(registered_on_bus(&client, 9, address), Some(true));
    }
}
