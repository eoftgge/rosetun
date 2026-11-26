use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use rosetun_config::TunSettings;

#[derive(Clone, Copy)]
pub struct TunnelAddress {
    pub local: IpAddr,
    pub peer: IpAddr,
    pub prefix: u8,
}

impl fmt::Debug for TunnelAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelAddress")
            .field("ipv4", &self.local.is_ipv4())
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl TunnelAddress {
    fn parse(cidr: &str, ipv4: bool) -> io::Result<Self> {
        let address_error =
            || io::Error::new(io::ErrorKind::InvalidInput, "invalid tunnel address");
        let (literal, length) = cidr.split_once('/').ok_or_else(address_error)?;
        let local = literal.parse::<IpAddr>().map_err(|_| address_error())?;
        let prefix = length.parse::<u8>().map_err(|_| address_error())?;
        if local.is_ipv4() != ipv4
            || local.is_unspecified()
            || local.is_loopback()
            || local.is_multicast()
        {
            return Err(address_error());
        }
        let (bits, width) = match local {
            IpAddr::V4(address) => (u128::from(address.to_bits()), 32),
            IpAddr::V6(address) => (address.to_bits(), 128),
        };
        if prefix == 0 || prefix >= width {
            return Err(address_error());
        }
        let host_mask = (1u128 << (width - prefix)) - 1;
        let host = bits & host_mask;
        if ipv4 && host_mask > 1 && (host == 0 || host >= host_mask - 1) {
            return Err(address_error());
        }
        let next = bits
            .checked_add(1)
            .filter(|peer| peer & !host_mask == bits & !host_mask)
            .ok_or_else(address_error)?;
        let peer = if ipv4 {
            Ipv4Addr::from_bits(u32::try_from(next).map_err(|_| address_error())?).into()
        } else {
            Ipv6Addr::from_bits(next).into()
        };
        Ok(Self {
            local,
            peer,
            prefix,
        })
    }
}

#[derive(Clone)]
pub struct DeviceSettings {
    pub name: String,
    pub mtu: u16,
    pub ipv4: TunnelAddress,
    pub ipv6: Option<TunnelAddress>,
}

impl fmt::Debug for DeviceSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceSettings")
            .field("mtu", &self.mtu)
            .field("ipv4", &self.ipv4)
            .field("ipv6", &self.ipv6)
            .finish_non_exhaustive()
    }
}

impl TryFrom<&TunSettings> for DeviceSettings {
    type Error = io::Error;

    fn try_from(settings: &TunSettings) -> io::Result<Self> {
        let ipv4 = TunnelAddress::parse(&settings.ipv4, true)?;
        let ipv6 = settings
            .ipv6
            .as_deref()
            .map(|cidr| TunnelAddress::parse(cidr, false))
            .transpose()?;
        if settings.mtu < if ipv6.is_some() { 1280 } else { 576 } {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid tunnel MTU",
            ));
        }
        Ok(Self {
            name: settings.name.clone(),
            mtu: settings.mtu,
            ipv4,
            ipv6,
        })
    }
}

pub trait PacketDevice: Send + Sync {
    fn receive(&self, packet: &mut [u8], wait: Duration) -> io::Result<usize>;

    fn send(&self, packet: &[u8]) -> io::Result<()>;

    fn interrupt(&self) -> io::Result<()>;
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod platform {
    use std::fmt;
    use std::io;
    use std::net::IpAddr;
    #[cfg(windows)]
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    #[cfg(windows)]
    use std::time::Instant;

    use tun_rs::{DeviceBuilder, InterruptEvent, SyncDevice};

    #[cfg(windows)]
    use super::wintun::PinnedWintun;
    use super::{DeviceSettings, PacketDevice};

    /// Synchronous layer-3 device. The owner installs regular routes separately,
    /// after admitting this interface to the routing guard.
    pub struct NativeDevice {
        device: SyncDevice,
        cancellation: InterruptEvent,
        #[cfg(windows)]
        send_stats: Option<WintunSendStats>,
        #[cfg(windows)]
        _wintun: PinnedWintun,
    }

    #[cfg(windows)]
    #[derive(Default)]
    struct WintunSendStats {
        attempts: AtomicU64,
        ring_full: AtomicU64,
        max_write_us: AtomicU64,
    }

    #[cfg(windows)]
    impl Drop for WintunSendStats {
        fn drop(&mut self) {
            tracing::debug!(
                attempts = *self.attempts.get_mut(),
                ring_full = *self.ring_full.get_mut(),
                max_write_us = *self.max_write_us.get_mut(),
                "native Wintun send counters"
            );
        }
    }

    impl fmt::Debug for NativeDevice {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("NativeDevice").finish_non_exhaustive()
        }
    }

    impl NativeDevice {
        #[cfg(windows)]
        pub fn open(settings: &DeviceSettings, wintun: PinnedWintun) -> io::Result<Self> {
            let builder = builder(settings)?
                .name(&settings.name)
                .mtu_v6(settings.mtu)
                .reuse_dev(false)
                .ring_capacity(8 * 1024 * 1024)
                .wintun_file(wintun.loader_path()?);
            let cancellation = InterruptEvent::new()?;
            Ok(Self {
                device: builder.build_sync()?,
                cancellation,
                send_stats: tracing::enabled!(tracing::Level::DEBUG).then(WintunSendStats::default),
                _wintun: wintun,
            })
        }

        #[cfg(not(windows))]
        pub fn open(settings: &DeviceSettings) -> io::Result<Self> {
            let builder = builder(settings)?.packet_information(false);
            #[cfg(target_os = "linux")]
            let builder = builder.name(&settings.name);
            #[cfg(target_os = "macos")]
            let builder = {
                let builder = builder.associate_route(false);
                match settings.name.strip_prefix("utun") {
                    Some(number) if number.parse::<u32>().is_ok() => builder.name(&settings.name),
                    _ => builder,
                }
            };
            let cancellation = InterruptEvent::new()?;
            let device = builder.build_sync()?;
            device.set_nonblocking(true)?;
            Ok(Self {
                device,
                cancellation,
            })
        }

        pub fn name(&self) -> io::Result<String> {
            self.device.name()
        }

        pub fn index(&self) -> io::Result<u32> {
            self.device.if_index()
        }

        #[cfg(windows)]
        fn send_packet(&self, packet: &[u8]) -> io::Result<usize> {
            let start = self.send_stats.as_ref().map(|_| Instant::now());
            // A full ring must leave the reader free to process other flows.
            let result = self.device.try_send(packet);
            if let (Some(stats), Some(start)) = (&self.send_stats, start) {
                stats.attempts.fetch_add(1, Ordering::Relaxed);
                if result
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
                {
                    stats.ring_full.fetch_add(1, Ordering::Relaxed);
                }
                let elapsed = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                stats.max_write_us.fetch_max(elapsed, Ordering::Relaxed);
            }
            result
        }
    }

    impl PacketDevice for NativeDevice {
        fn receive(&self, packet: &mut [u8], wait: Duration) -> io::Result<usize> {
            #[cfg(windows)]
            {
                // A read notification can cover several packets already in the ring.
                match self.device.try_recv(packet) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock && !wait.is_zero() => {}
                    result => return result,
                }
            }
            self.device
                .recv_intr_timeout(packet, &self.cancellation, Some(wait))
        }

        fn send(&self, packet: &[u8]) -> io::Result<()> {
            #[cfg(windows)]
            let sent = self.send_packet(packet)?;
            #[cfg(not(windows))]
            let sent = self.device.send_intr(packet, &self.cancellation)?;
            if sent != packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial tunnel packet",
                ));
            }
            Ok(())
        }

        fn interrupt(&self) -> io::Result<()> {
            self.cancellation.trigger()
        }
    }

    fn builder(settings: &DeviceSettings) -> io::Result<DeviceBuilder> {
        let (IpAddr::V4(local), IpAddr::V4(peer)) = (settings.ipv4.local, settings.ipv4.peer)
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid IPv4 tunnel address",
            ));
        };
        // On Windows tun-rs interprets a peer as a request for a default route.
        let destination = (!cfg!(windows)).then_some(peer);
        let mut builder = DeviceBuilder::new()
            .ipv4(local, settings.ipv4.prefix, destination)
            .mtu(settings.mtu)
            .enable(true);
        if let Some(address) = settings.ipv6 {
            let IpAddr::V6(local) = address.local else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid IPv6 tunnel address",
                ));
            };
            builder = builder.ipv6(local, address.prefix);
        }
        Ok(builder)
    }
}

#[cfg(windows)]
mod wintun {
    use std::fmt;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read};
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};

    use ring::digest::{Context, SHA256};

    /// Verified driver file held open without sharing writes or deletion.
    pub struct PinnedWintun {
        path: PathBuf,
        _file: File,
    }

    impl fmt::Debug for PinnedWintun {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PinnedWintun").finish_non_exhaustive()
        }
    }

    impl PinnedWintun {
        /// The expected hash comes from the trusted distributable, never from the DLL directory.
        pub fn open(path: &Path, expected: &[u8; 32]) -> io::Result<Self> {
            const FILE_SHARE_READ: u32 = 1;
            const MAX_DLL_BYTES: u64 = 4 * 1024 * 1024;
            let path = path.canonicalize()?;
            let mut file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(&path)?;
            let size = file.metadata()?.len();
            if size == 0 || size > MAX_DLL_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Wintun image size",
                ));
            }
            let mut digest = Context::new(&SHA256);
            let mut bytes = [0; 8192];
            loop {
                let count = file.read(&mut bytes)?;
                if count == 0 {
                    break;
                }
                digest.update(&bytes[..count]);
            }
            if digest.finish().as_ref() != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Wintun image hash mismatch",
                ));
            }
            Ok(Self { path, _file: file })
        }

        pub(super) fn loader_path(&self) -> io::Result<String> {
            self.path.to_str().map(str::to_owned).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Wintun path cannot be passed to the loader",
                )
            })
        }
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub use platform::NativeDevice;
#[cfg(windows)]
pub use wintun::PinnedWintun;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_peer_is_inside_the_prefix_and_ipv6_requires_its_minimum_mtu() {
        let mut settings = TunSettings {
            ipv4: "192.0.2.1/30".to_owned(),
            ipv6: Some("2001:db8::1/64".to_owned()),
            ..TunSettings::default()
        };
        let device = DeviceSettings::try_from(&settings).unwrap();
        assert_eq!(device.ipv4.peer, "192.0.2.2".parse::<IpAddr>().unwrap());
        assert_eq!(
            device.ipv6.unwrap().peer,
            "2001:db8::2".parse::<IpAddr>().unwrap()
        );
        settings.mtu = 1279;
        assert!(DeviceSettings::try_from(&settings).is_err());
    }

    #[test]
    fn a_broadcast_or_out_of_prefix_peer_is_refused() {
        assert!(TunnelAddress::parse("192.0.2.2/30", true).is_err());
        assert!(TunnelAddress::parse("2001:db8::ffff/112", false).is_err());
    }
}
