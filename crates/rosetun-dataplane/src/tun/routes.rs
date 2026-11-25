use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(windows)]
use std::num::NonZeroU32;

use rosetun_config::IpPrefix;

use super::DeviceSettings;

const MAX_CAPTURE_ROUTES: usize = 1024;

/// Routes that take precedence over the physical default while leaving more
/// specific connected routes (and the local routing table) available.
pub struct CaptureRoutes {
    prefixes: Vec<IpPrefix>,
}

impl fmt::Debug for CaptureRoutes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaptureRoutes")
            .field("count", &self.prefixes.len())
            .finish_non_exhaustive()
    }
}

impl CaptureRoutes {
    pub fn plan(settings: &DeviceSettings, lan: &[IpPrefix]) -> io::Result<Self> {
        let mut prefixes = vec![IpPrefix::v4([0; 4], 1), IpPrefix::v4([128, 0, 0, 0], 1)];
        if settings.ipv6.is_some() {
            prefixes.extend([
                IpPrefix::v6([0; 8], 1),
                IpPrefix::v6([0x8000, 0, 0, 0, 0, 0, 0, 0], 1),
            ]);
        }
        let mut exclusions = vec![
            IpPrefix::v4([127, 0, 0, 0], 8),
            IpPrefix::v6([0, 0, 0, 0, 0, 0, 0, 1], 128),
        ];
        for address in [Some(settings.ipv4), settings.ipv6].into_iter().flatten() {
            let prefix = IpPrefix::new(address.local, address.prefix).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid tunnel prefix")
            })?;
            exclusions.push(prefix);
        }
        exclusions.extend_from_slice(lan);
        for exclude in exclusions {
            let mut next = Vec::new();
            for route in prefixes {
                subtract(route, exclude, &mut next)?;
            }
            prefixes = next;
        }
        if prefixes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no routes remain to capture",
            ));
        }
        Ok(Self { prefixes })
    }

    pub fn prefixes(&self) -> &[IpPrefix] {
        &self.prefixes
    }
}

/// Adds an exact route or fails on an existing route. The lease only removes
/// routes the backend confirmed it added.
pub trait RouteBackend {
    fn add(&mut self, prefix: IpPrefix) -> io::Result<()>;

    fn delete(&mut self, prefix: IpPrefix) -> io::Result<()>;
}

pub struct RouteLease<B: RouteBackend> {
    backend: B,
    inserted: Vec<IpPrefix>,
}

impl<B: RouteBackend> fmt::Debug for RouteLease<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteLease")
            .field("count", &self.inserted.len())
            .finish_non_exhaustive()
    }
}

impl<B: RouteBackend> RouteLease<B> {
    pub fn install(backend: B, plan: &CaptureRoutes) -> io::Result<Self> {
        let mut lease = Self {
            backend,
            inserted: Vec::with_capacity(plan.prefixes.len()),
        };
        for &route in plan.prefixes() {
            lease.backend.add(route)?;
            lease.inserted.push(route);
        }
        Ok(lease)
    }

    /// Retries removal on Drop for routes whose first removal failed.
    pub fn close(&mut self) -> io::Result<()> {
        let mut retained = Vec::new();
        let mut first_error = None;
        while let Some(route) = self.inserted.pop() {
            if let Err(error) = self.backend.delete(route) {
                retained.push(route);
                first_error.get_or_insert(error);
            }
        }
        self.inserted.extend(retained.into_iter().rev());
        first_error.map_or(Ok(()), Err)
    }
}

impl<B: RouteBackend> Drop for RouteLease<B> {
    fn drop(&mut self) {
        if self.close().is_err() {
            tracing::error!("could not remove all native tunnel routes");
        }
    }
}

#[cfg(windows)]
#[derive(Debug)]
pub struct InterfaceRoutes {
    index: NonZeroU32,
}

#[cfg(windows)]
impl InterfaceRoutes {
    pub fn new(index: NonZeroU32) -> Self {
        Self { index }
    }
}

#[cfg(windows)]
impl RouteBackend for InterfaceRoutes {
    fn add(&mut self, prefix: IpPrefix) -> io::Result<()> {
        windows::change(self.index, prefix, true)
    }

    fn delete(&mut self, prefix: IpPrefix) -> io::Result<()> {
        windows::change(self.index, prefix, false)
    }
}

fn subtract(prefix: IpPrefix, exclude: IpPrefix, routes: &mut Vec<IpPrefix>) -> io::Result<()> {
    if !prefix.overlaps(exclude) {
        if routes.len() == MAX_CAPTURE_ROUTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many native tunnel routes",
            ));
        }
        routes.push(prefix);
        return Ok(());
    }
    if exclude.length() <= prefix.length() {
        return Ok(());
    }
    let child = prefix.length() + 1;
    let sibling = match prefix.address() {
        IpAddr::V4(address) => Ipv4Addr::from_bits(address.to_bits() | 1 << (32 - child)).into(),
        IpAddr::V6(address) => Ipv6Addr::from_bits(address.to_bits() | 1 << (128 - child)).into(),
    };
    let error = || io::Error::new(io::ErrorKind::InvalidInput, "invalid tunnel route prefix");
    subtract(
        IpPrefix::new(prefix.address(), child).ok_or_else(error)?,
        exclude,
        routes,
    )?;
    subtract(
        IpPrefix::new(sibling, child).ok_or_else(error)?,
        exclude,
        routes,
    )
}

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "adds and deletes exact session routes through IP Helper"
)]
mod windows {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::num::NonZeroU32;

    use rosetun_config::IpPrefix;
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, GetBestRoute2, IP_ADDRESS_PREFIX,
        InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
        SOCKADDR_INET,
    };

    use super::{CaptureRoutes, InterfaceRoutes, RouteLease};
    use crate::tun::PhysicalEgress;

    pub struct WindowsRoutes {
        physical: PhysicalEgress,
        ipv4: NonZeroU32,
        ipv6: Option<NonZeroU32>,
        capture: Option<RouteLease<InterfaceRoutes>>,
        endpoints: Vec<(IpAddr, MIB_IPFORWARD_ROW2)>,
    }

    impl std::fmt::Debug for WindowsRoutes {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WindowsRoutes").finish_non_exhaustive()
        }
    }

    impl WindowsRoutes {
        /// Looks up physical routes before the tunnel installs any routes.
        pub fn before_capture() -> io::Result<Self> {
            let ipv4 = interface_of(best_route(0, Ipv4Addr::new(203, 0, 113, 193).into())?)?;
            let ipv6 = best_route(0, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x193).into())
                .and_then(interface_of)
                .ok();
            Ok(Self {
                physical: PhysicalEgress::new(Some(ipv4), ipv6),
                ipv4,
                ipv6,
                capture: None,
                endpoints: Vec::new(),
            })
        }

        pub fn physical(&self) -> PhysicalEgress {
            self.physical
        }

        pub fn capture(
            &mut self,
            interface: NonZeroU32,
            plan: &CaptureRoutes,
            endpoints: &[IpAddr],
        ) -> io::Result<()> {
            if self.capture.is_some() || self.ipv4 == interface || self.ipv6 == Some(interface) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid native route interface",
                ));
            }
            self.ensure_endpoints(endpoints)?;
            self.capture = Some(RouteLease::install(InterfaceRoutes::new(interface), plan)?);
            Ok(())
        }

        pub fn ensure_endpoints(&mut self, endpoints: &[IpAddr]) -> io::Result<()> {
            for &address in endpoints {
                if self
                    .endpoints
                    .iter()
                    .any(|(existing, _)| *existing == address)
                {
                    continue;
                }
                let physical = if address.is_ipv4() {
                    Some(self.ipv4)
                } else {
                    self.ipv6
                }
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NetworkUnreachable,
                        "no physical route for server address family",
                    )
                })?;
                let best = best_route(physical.get(), address)?;
                let prefix = IpPrefix::new(address, if address.is_ipv4() { 32 } else { 128 })
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid server route")
                    })?;
                // A pre-existing exact physical route has the precedence we
                // need. It remains owned by the program that installed it.
                if best.DestinationPrefix.PrefixLength == prefix.length() {
                    continue;
                }
                let mut row = row_for(physical, prefix);
                row.NextHop = best.NextHop;
                apply(&row, true)?;
                self.endpoints.push((address, row));
            }
            Ok(())
        }

        pub fn retain_endpoints(&mut self, endpoints: &[IpAddr]) -> io::Result<()> {
            let mut index = 0;
            while index < self.endpoints.len() {
                let (address, row) = &self.endpoints[index];
                if endpoints.contains(address) {
                    index += 1;
                } else {
                    apply(row, false)?;
                    self.endpoints.remove(index);
                }
            }
            Ok(())
        }

        pub fn close(&mut self) -> io::Result<()> {
            if let Some(capture) = self.capture.as_mut() {
                capture.close()?;
            }
            self.capture.take();
            self.retain_endpoints(&[])
        }
    }

    impl Drop for WindowsRoutes {
        fn drop(&mut self) {
            if self.close().is_err() {
                tracing::error!("could not remove the native Windows routes");
            }
        }
    }

    fn interface_of(row: MIB_IPFORWARD_ROW2) -> io::Result<NonZeroU32> {
        NonZeroU32::new(row.InterfaceIndex).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NetworkUnreachable, "route has no interface")
        })
    }

    fn best_route(interface: u32, target: IpAddr) -> io::Result<MIB_IPFORWARD_ROW2> {
        let address = sockaddr(target);
        let mut route = MIB_IPFORWARD_ROW2::default();
        let mut source = SOCKADDR_INET::default();
        // SAFETY: Destination and both output structs have the SDK layout.
        // The API borrows them during this routing lookup and sends no packet.
        let code = unsafe {
            GetBestRoute2(
                std::ptr::null(),
                interface,
                std::ptr::null(),
                &raw const address,
                0,
                &raw mut route,
                &raw mut source,
            )
        };
        if code != NO_ERROR {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(route)
    }

    pub(super) fn change(interface: NonZeroU32, prefix: IpPrefix, add: bool) -> io::Result<()> {
        apply(&row_for(interface, prefix), add)
    }

    fn row_for(interface: NonZeroU32, prefix: IpPrefix) -> MIB_IPFORWARD_ROW2 {
        let mut row = MIB_IPFORWARD_ROW2::default();
        // SAFETY: The row is initialized writable storage with the Windows ABI.
        // IP Helper fills its defaults synchronously before we use it.
        unsafe { InitializeIpForwardEntry(&raw mut row) };
        row.InterfaceIndex = interface.get();
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: sockaddr(prefix.address()),
            PrefixLength: prefix.length(),
        };
        row.NextHop = if prefix.is_ipv4() {
            sockaddr(Ipv4Addr::UNSPECIFIED.into())
        } else {
            sockaddr(Ipv6Addr::UNSPECIFIED.into())
        };
        row.Metric = 0;
        row
    }

    fn apply(row: &MIB_IPFORWARD_ROW2, add: bool) -> io::Result<()> {
        // SAFETY: The row owns all input values. Calls do not retain its pointer.
        let code = unsafe {
            if add {
                CreateIpForwardEntry2(row)
            } else {
                DeleteIpForwardEntry2(row)
            }
        };
        match code {
            NO_ERROR => Ok(()),
            ERROR_NOT_FOUND if !add => Ok(()),
            code => Err(io::Error::from_raw_os_error(code as i32)),
        }
    }

    fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
        match ip {
            IpAddr::V4(ip) => SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(ip.octets()),
                        },
                    },
                    ..SOCKADDR_IN::default()
                },
            },
            IpAddr::V6(ip) => SOCKADDR_INET {
                Ipv6: SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 { Byte: ip.octets() },
                    },
                    ..SOCKADDR_IN6::default()
                },
            },
        }
    }
}

#[cfg(windows)]
pub use windows::WindowsRoutes;

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    #[test]
    fn routes_exclude_the_lan_and_own_segment_in_both_families() {
        let settings = DeviceSettings::try_from(&rosetun_config::TunSettings {
            ipv4: "192.0.2.1/30".into(),
            ipv6: Some("2001:db8::1/64".into()),
            ..rosetun_config::TunSettings::default()
        })
        .unwrap();
        let routes = CaptureRoutes::plan(
            &settings,
            &[
                IpPrefix::v4([198, 51, 100, 0], 24),
                IpPrefix::v6([0x2001, 0xdb8, 17, 0, 0, 0, 0, 0], 48),
            ],
        )
        .unwrap();
        let captures = |ip: &str| {
            routes
                .prefixes()
                .iter()
                .any(|route| route.contains(ip.parse().unwrap()))
        };
        for ip in [
            "192.0.2.2",
            "198.51.100.18",
            "2001:db8::2",
            "2001:db8:11::1",
        ] {
            assert!(!captures(ip));
        }
        assert!(captures("203.0.113.14"));
        assert!(captures("2001:db8:12::8"));
    }

    #[test]
    fn failure_reverts_only_routes_created_this_attempt_in_reverse_order() {
        type Events = Rc<RefCell<Vec<(bool, IpPrefix)>>>;
        struct Backend(Events, IpPrefix);
        impl RouteBackend for Backend {
            fn add(&mut self, prefix: IpPrefix) -> io::Result<()> {
                self.0.borrow_mut().push((true, prefix));
                if prefix == self.1 {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                Ok(())
            }

            fn delete(&mut self, prefix: IpPrefix) -> io::Result<()> {
                self.0.borrow_mut().push((false, prefix));
                Ok(())
            }
        }
        let a = IpPrefix::v4([192, 0, 2, 0], 24);
        let b = IpPrefix::v4([198, 51, 100, 0], 24);
        let c = IpPrefix::v4([203, 0, 113, 0], 24);
        let events = Events::default();
        let result = RouteLease::install(
            Backend(Rc::clone(&events), c),
            &CaptureRoutes {
                prefixes: vec![a, b, c],
            },
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            *events.borrow(),
            [(true, a), (true, b), (true, c), (false, b), (false, a)]
        );
    }
}
