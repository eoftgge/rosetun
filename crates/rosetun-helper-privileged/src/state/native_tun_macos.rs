use std::fmt::Display;
use std::net::IpAddr;
use std::sync::Arc;

use rosetun_config::{IpPrefix, TunSettings};
use rosetun_dataplane::NativeTunnel;
use rosetun_dataplane::tun::{
    CaptureRoutes, DeviceSettings, MacosProcessLookup, MacosRoutes, NativeDevice,
};
use rosetun_ipc::{ErrorCode, HelperError};

use super::system_dns_macos::MacosSystemDns;

pub(super) struct NativeTun {
    dns: Option<MacosSystemDns>,
    routes: MacosRoutes,
    device: Arc<NativeDevice>,
    settings: DeviceSettings,
    interface_name: String,
}

impl NativeTun {
    pub(super) fn open(settings: &TunSettings) -> Result<Self, HelperError> {
        let settings = DeviceSettings::try_from(settings).map_err(route_error)?;
        let routes = MacosRoutes::before_capture().map_err(route_error)?;
        let device = NativeDevice::open(&settings).map_err(route_error)?;
        let interface_name = device.name().map_err(route_error)?;
        Ok(Self {
            dns: None,
            routes,
            device: Arc::new(device),
            settings,
            interface_name,
        })
    }

    pub(super) fn name(&self) -> Result<String, HelperError> {
        Ok(self.interface_name.clone())
    }

    pub(super) fn tunnel(&self) -> Result<NativeTunnel, HelperError> {
        Ok(NativeTunnel {
            device: self.device.clone(),
            settings: self.settings.clone(),
            egress: self.routes.physical(),
            process: Arc::new(MacosProcessLookup::default()),
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
        self.routes
            .capture(&self.interface_name, &plan, servers)
            .map_err(route_error)?;
        if !cfg!(test) {
            let mut dns_servers = vec![self.settings.ipv4.peer];
            if let Some(ipv6) = self.settings.ipv6 {
                dns_servers.push(ipv6.peer);
            }
            self.dns = Some(MacosSystemDns::install(&dns_servers).map_err(|error| {
                route_error(format!("failed to configure macOS system DNS: {error}"))
            })?);
        }
        Ok(())
    }

    pub(super) fn ensure_endpoints(&mut self, servers: &[IpAddr]) -> Result<(), HelperError> {
        self.routes.ensure_endpoints(servers).map_err(route_error)
    }

    pub(super) fn retain_endpoints(&mut self, servers: &[IpAddr]) {
        if self.routes.retain_endpoints(servers).is_err() {
            tracing::warn!("could not remove a retired native worker route");
        }
    }

    pub(super) fn close(&mut self) -> Result<(), HelperError> {
        self.dns.take();
        self.routes.close().map_err(route_error)
    }
}

pub(super) fn route_error(error: impl Display) -> HelperError {
    HelperError::new(ErrorCode::RoutingFailed, error.to_string())
}
