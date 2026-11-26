use std::fmt::Display;
use std::io;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use rosetun_config::{IpPrefix, TunSettings};
use rosetun_dataplane::NativeTunnel;
use rosetun_dataplane::tun::{
    CaptureRoutes, DeviceSettings, InterfaceRoutes, NativeDevice, PinnedWintun,
    WindowsProcessLookup, WindowsRoutes,
};
use rosetun_ipc::{ErrorCode, HelperError};

const WINTUN_AMD64_SHA256: [u8; 32] = [
    0xe5, 0xda, 0x84, 0x47, 0xdc, 0x2c, 0x32, 0x0e, 0xdc, 0x0f, 0xc5, 0x2f, 0xa0, 0x18, 0x85, 0xc1,
    0x03, 0xde, 0x8c, 0x11, 0x84, 0x81, 0xf6, 0x83, 0x64, 0x3c, 0xac, 0xc3, 0x22, 0x0d, 0xaf, 0xce,
];

pub(super) struct NativeTun {
    resolver: Option<resolver::Resolver>,
    routes: WindowsRoutes,
    device: Arc<NativeDevice>,
    settings: DeviceSettings,
}

impl NativeTun {
    pub(super) fn open(settings: &TunSettings) -> Result<Self, HelperError> {
        let settings = DeviceSettings::try_from(settings).map_err(route_error)?;
        let routes = WindowsRoutes::before_capture().map_err(route_error)?;
        let exe = std::env::current_exe().map_err(route_error)?;
        let dll = exe
            .parent()
            .ok_or_else(|| route_error("the service has no install directory"))?
            .join("wintun.dll");
        let driver = PinnedWintun::open(&dll, &WINTUN_AMD64_SHA256).map_err(|error| {
            let message = if error.kind() == io::ErrorKind::NotFound {
                "the pinned Wintun driver is missing"
            } else {
                "the pinned Wintun driver could not be verified"
            };
            route_error(message)
        })?;
        let device = NativeDevice::open(&settings, driver).map_err(route_error)?;
        Ok(Self {
            resolver: None,
            routes,
            device: Arc::new(device),
            settings,
        })
    }

    pub(super) fn name(&self) -> Result<String, HelperError> {
        self.device.name().map_err(route_error)
    }

    pub(super) fn tunnel(&self) -> Result<NativeTunnel, HelperError> {
        Ok(NativeTunnel {
            device: self.device.clone(),
            settings: self.settings.clone(),
            egress: self.routes.physical(),
            process: Arc::new(WindowsProcessLookup::default()),
        })
    }

    pub(super) fn capture(
        &mut self,
        lan: &[IpPrefix],
        servers: &[IpAddr],
    ) -> Result<(), HelperError> {
        let plan = CaptureRoutes::plan(&self.settings, lan).map_err(route_error)?;
        let index = NonZeroU32::new(self.device.index().map_err(route_error)?)
            .ok_or_else(|| route_error("native tunnel has no interface index"))?;
        let interface = InterfaceRoutes::with_peers(
            index,
            self.settings.ipv4.peer,
            self.settings.ipv6.map(|address| address.peer),
        );
        self.routes
            .capture(interface, &plan, servers)
            .map_err(route_error)?;
        self.resolver = Some(
            resolver::Resolver::install(
                index,
                self.settings.ipv4.peer,
                self.settings.ipv6.map(|addr| addr.peer),
            )
            .map_err(route_error)?,
        );
        self.routes
            .refresh_paths(self.settings.ipv6.is_some())
            .map_err(route_error)?;
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
        self.resolver.take();
        self.routes.close().map_err(route_error)?;
        if self
            .routes
            .refresh_paths(self.settings.ipv6.is_some())
            .is_err()
        {
            tracing::warn!("could not refresh IP paths after closing the native tunnel");
        }
        Ok(())
    }
}

#[expect(
    unsafe_code,
    reason = "IP Helper per-interface DNS on the owned adapter"
)]
mod resolver {
    use std::io;
    use std::net::IpAddr;
    use std::num::NonZeroU32;

    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid, DNS_INTERFACE_SETTINGS,
        DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
        SetInterfaceDnsSettings,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::core::GUID;

    pub(super) struct Resolver {
        guid: GUID,
        ipv6: bool,
    }

    impl Resolver {
        pub(super) fn install(
            index: NonZeroU32,
            ipv4: IpAddr,
            ipv6: Option<IpAddr>,
        ) -> io::Result<Self> {
            let mut luid = NET_LUID_LH::default();
            let mut guid = GUID::default();
            // SAFETY: The SDK output variables are writable for the synchronous
            // calls. The index comes from the owned, validated adapter.
            let code = unsafe { ConvertInterfaceIndexToLuid(index.get(), &raw mut luid) };
            status(code)?;
            // SAFETY: The previous call initialized the LUID, and the GUID
            // is an output of the documented type.
            let code = unsafe { ConvertInterfaceLuidToGuid(&raw const luid, &raw mut guid) };
            status(code)?;
            let mut resolver = Self { guid, ipv6: false };
            resolver.write(false, &ipv4.to_string())?;
            if let Some(ipv6) = ipv6 {
                resolver.write(true, &ipv6.to_string())?;
                resolver.ipv6 = true;
            }
            Ok(resolver)
        }

        fn write(&self, ipv6: bool, value: &str) -> io::Result<()> {
            let mut buffer: Vec<u16> = value.encode_utf16().chain([0]).collect();
            let settings = DNS_INTERFACE_SETTINGS {
                Version: DNS_INTERFACE_SETTINGS_VERSION1,
                Flags: u64::from(DNS_SETTING_NAMESERVER | if ipv6 { DNS_SETTING_IPV6 } else { 0 }),
                NameServer: buffer.as_mut_ptr(),
                ..DNS_INTERFACE_SETTINGS::default()
            };
            // SAFETY: The initialized struct and its NUL-terminated UTF-16
            // string remain alive. Windows copies these values before returning.
            status(unsafe { SetInterfaceDnsSettings(self.guid, &raw const settings) })
        }
    }

    impl Drop for Resolver {
        fn drop(&mut self) {
            let _ = self.write(false, "");
            if self.ipv6 {
                let _ = self.write(true, "");
            }
        }
    }

    fn status(code: u32) -> io::Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(code as i32))
        }
    }
}

pub(super) fn route_error(error: impl Display) -> HelperError {
    HelperError::new(ErrorCode::RoutingFailed, error.to_string())
}
