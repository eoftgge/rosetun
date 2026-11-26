use std::fmt::Display;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use rosetun_config::{IpPrefix, TunSettings};
use rosetun_dataplane::NativeTunnel;
use rosetun_dataplane::tun::{
    CaptureRoutes, DeviceSettings, LinuxProcessLookup, LinuxRoutes, NativeDevice, PhysicalEgress,
};
use rosetun_ipc::{ErrorCode, HelperError};
use zbus::blocking::{Connection, connection::Builder, fdo::DBusProxy};

const MARK: NonZeroU32 = NonZeroU32::new(0x5254_0002).expect("the native mark is nonzero");
const TABLE: NonZeroU32 = NonZeroU32::new(0x5254).expect("the native route table is nonzero");
const PRIORITY: u16 = 12420;

pub(super) struct NativeTun {
    resolver: Option<Resolver>,
    routes: Option<LinuxRoutes>,
    device: Arc<NativeDevice>,
    settings: DeviceSettings,
}

impl NativeTun {
    pub(super) fn open(settings: &TunSettings) -> Result<Self, HelperError> {
        let settings = DeviceSettings::try_from(settings).map_err(route_error)?;
        let device = NativeDevice::open(&settings).map_err(route_error)?;
        Ok(Self {
            resolver: None,
            routes: None,
            device: Arc::new(device),
            settings,
        })
    }

    pub(super) fn name(&self) -> Result<String, HelperError> {
        self.device.name().map_err(route_error)
    }

    pub(super) fn tunnel(&self) -> Result<NativeTunnel, HelperError> {
        // Linux egress uses the policy rule and mark rather than the interface
        // index. A positive device index also confirms that it exists.
        let index = NonZeroU32::new(self.device.index().map_err(route_error)?)
            .ok_or_else(|| route_error("native tunnel has no interface index"))?;
        Ok(NativeTunnel {
            device: self.device.clone(),
            settings: self.settings.clone(),
            egress: PhysicalEgress::new(Some(index), self.settings.ipv6.map(|_| index), MARK),
            process: Arc::new(LinuxProcessLookup::default()),
        })
    }

    pub(super) fn capture(
        &mut self,
        lan: &[IpPrefix],
        servers: &[IpAddr],
        auto_route: bool,
    ) -> Result<(), HelperError> {
        let plan = if auto_route {
            CaptureRoutes::plan(&self.settings, lan).map_err(route_error)?
        } else {
            CaptureRoutes::manual()
        };
        let name = self.device.name().map_err(route_error)?;
        self.routes = Some(
            LinuxRoutes::install(
                &name,
                &plan,
                TABLE,
                MARK,
                PRIORITY,
                servers,
                self.settings.ipv6.is_some(),
            )
            .map_err(route_error)?,
        );
        let index =
            i32::try_from(self.device.index().map_err(route_error)?).map_err(route_error)?;
        self.resolver = Resolver::install(index, self.settings.ipv4.peer).map_err(route_error)?;
        Ok(())
    }

    pub(super) fn ensure_endpoints(&mut self, servers: &[IpAddr]) -> Result<(), HelperError> {
        self.routes
            .as_mut()
            .ok_or_else(|| route_error("native routes are unavailable"))?
            .ensure_endpoints(servers)
            .map_err(route_error)
    }

    pub(super) fn retain_endpoints(&mut self, servers: &[IpAddr]) {
        if let Some(routes) = self.routes.as_mut()
            && routes.retain_endpoints(servers).is_err()
        {
            tracing::warn!("could not remove a retired native worker route");
        }
    }

    pub(super) fn close(&mut self) -> Result<(), HelperError> {
        self.resolver.take();
        if let Some(routes) = self.routes.as_mut() {
            routes.close().map_err(route_error)?;
        }
        self.routes.take();
        Ok(())
    }
}

struct Resolver {
    connection: Connection,
    index: i32,
}

impl Resolver {
    fn install(index: i32, address: IpAddr) -> zbus::Result<Option<Self>> {
        let connection = Builder::system()?
            .method_timeout(Duration::from_secs(2))
            .build()?;
        let proxy = DBusProxy::new(&connection)?;
        if !proxy.name_has_owner("org.freedesktop.resolve1".try_into()?)? {
            // With a static resolver, the capture rules intercept the configured
            // DNS servers. The kill switch covers traffic outside the capture.
            return Ok(None);
        }
        drop(proxy);
        let resolver = Self { connection, index };
        let (family, bytes) = match address {
            IpAddr::V4(address) => (libc::AF_INET, address.octets().to_vec()),
            IpAddr::V6(address) => (libc::AF_INET6, address.octets().to_vec()),
        };
        resolver.call("SetLinkDNS", &(index, [(family, bytes)]))?;
        resolver.call("SetLinkDomains", &(index, [(".", true)]))?;
        resolver.call("SetLinkDefaultRoute", &(index, true))?;
        Ok(Some(resolver))
    }

    fn call(
        &self,
        method: &str,
        args: &(impl serde::Serialize + zbus::zvariant::DynamicType),
    ) -> zbus::Result<()> {
        self.connection.call_method(
            Some("org.freedesktop.resolve1"),
            "/org/freedesktop/resolve1",
            Some("org.freedesktop.resolve1.Manager"),
            method,
            args,
        )?;
        Ok(())
    }
}

impl Drop for Resolver {
    fn drop(&mut self) {
        let _ = self.call("RevertLink", &(self.index,));
    }
}

pub(super) fn route_error(error: impl Display) -> HelperError {
    HelperError::new(ErrorCode::RoutingFailed, error.to_string())
}
