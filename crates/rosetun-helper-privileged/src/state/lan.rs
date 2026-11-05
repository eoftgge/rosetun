//! "Local network": the segment a session opens, and following it when the
//! computer moves to another network.

use std::net::IpAddr;

use rosetun_config::{IpPrefix, Settings, TunSettings};
use rosetun_ipc::{ErrorCode, HelperError};
use rosetun_routing::{
    RouteRelease, TunnelInterface,
    lan::{LanAccess, LanSegment, SegmentQuery, SegmentScan, SkipReason},
};

use super::{Session, lockdown};

/// Reads the adapters; a hook for tests.
pub(super) type LanScan = fn(&SegmentQuery<'_>) -> std::io::Result<SegmentScan>;

/// Takes the system's broadcast route off the tunnel; a hook for tests.
pub(super) type BroadcastRouteRelease = fn(&TunnelInterface) -> RouteRelease;

/// Equal reads in a row, one supervisor tick (500 ms) apart, before a new
/// segment counts. Joining Wi-Fi, a DHCP lease and waking from sleep change
/// addresses in bursts over about a second, and every change the session
/// follows costs an engine restart.
const SETTLE_READS: u8 = 3;

/// Debounces segment reads.
#[derive(Debug)]
pub(super) struct LanWatch<T = LanSegment> {
    candidate: Option<T>,
    reads: u8,
}

impl<T> Default for LanWatch<T> {
    fn default() -> Self {
        Self {
            candidate: None,
            reads: 0,
        }
    }
}

impl<T: PartialEq> LanWatch<T> {
    /// One read; the new segment once it has held for `SETTLE_READS`.
    fn observe(&mut self, current: &T, read: T) -> Option<T> {
        if read == *current {
            *self = Self::default();
            return None;
        }
        if self.candidate.as_ref() == Some(&read) {
            self.reads += 1;
        } else {
            self.candidate = Some(read);
            self.reads = 1;
        }
        if self.reads < SETTLE_READS {
            return None;
        }
        self.reads = 0;
        self.candidate.take()
    }
}

#[cfg(test)]
pub(super) fn test_scan(_: &SegmentQuery<'_>) -> std::io::Result<SegmentScan> {
    Ok(SegmentScan::default())
}

#[cfg(test)]
pub(super) fn test_release(_: &TunnelInterface) -> RouteRelease {
    RouteRelease::default()
}

/// The failure to log: a tick repeats the release, and the same error twice a
/// second would bury the log.
fn new_failure(previous: Option<u32>, current: Option<u32>) -> Option<u32> {
    current.filter(|_| current != previous)
}

/// The tunnel's own networks, from its configured addresses.
fn tunnel_networks(tun: &TunSettings) -> Vec<IpPrefix> {
    [Some(tun.ipv4.as_str()), tun.ipv6.as_deref()]
        .into_iter()
        .flatten()
        .filter_map(|cidr| {
            let (address, length) = cidr.split_once('/')?;
            IpPrefix::new(address.parse().ok()?, length.parse().ok()?)
        })
        .collect()
}

fn log_scan(scan: &SegmentScan) {
    let networks = scan
        .segment
        .prefixes()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    tracing::info!(
        %networks,
        "local network: connected networks stay outside the tunnel"
    );
    for (prefix, reason) in &scan.skipped {
        match reason {
            SkipReason::TooWide => tracing::info!(
                network = %prefix,
                "local network: a connected network is too wide to open"
            ),
            SkipReason::OverlapsTunnel => tracing::warn!(
                network = %prefix,
                "local network: a connected network overlaps the tunnel's addresses and stays closed"
            ),
            // The network would tell where the servers are.
            SkipReason::TooManyServers => tracing::warn!(
                "local network: a connected network holds too many VPN servers and stays closed"
            ),
        }
    }
    if !scan.segment.left_out().is_empty() {
        tracing::info!(
            "local network: a connected network is open without the address of a VPN server"
        );
    }
}

impl Session {
    fn scan_lan(&self, tun: &TunSettings, servers: &[IpAddr], log: bool) -> LanSegment {
        let tunnel_networks = tunnel_networks(tun);
        let query = SegmentQuery {
            tunnel_alias: &tun.name,
            tunnel_networks: &tunnel_networks,
            servers,
        };
        match (self.lan_scan)(&query) {
            Ok(scan) => {
                if log {
                    log_scan(&scan);
                }
                scan.segment
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "could not read the local networks; they stay closed"
                );
                LanSegment::default()
            }
        }
    }

    /// What "Local network" opens for a session with these settings and
    /// servers; nothing when it is off.
    pub(super) fn lan_access(&self, settings: &Settings, servers: &[IpAddr]) -> LanAccess {
        if !settings.allow_lan {
            return LanAccess::default();
        }
        LanAccess {
            segment: self.scan_lan(&settings.tun, servers, true),
            private_networks: settings.private_networks,
            ipv6_multicast: settings.tun.ipv6.is_some(),
        }
    }

    /// Lockdown's "Local network" set, `None` when it is off. Lockdown
    /// outlives sessions, so it takes the tunnel of the running session or
    /// the default one.
    pub(super) fn lockdown_lan(
        &self,
        allow_lan: bool,
        private_networks: bool,
    ) -> Option<LanAccess> {
        allow_lan.then(|| LanAccess {
            segment: self.lockdown_segment_around(&self.lan_servers),
            private_networks,
            ipv6_multicast: false,
        })
    }

    fn lockdown_segment_around(&self, servers: &[IpAddr]) -> LanSegment {
        let tun = self
            .request
            .as_ref()
            .map(|request| request.settings.tun.clone())
            .unwrap_or_default();
        self.scan_lan(&tun, servers, false)
    }

    /// The session's servers are these from now on. Lockdown's persistent
    /// permit of the segment follows before the session's filters go in: it
    /// sits beside them in one sublayer, so a server's address left open there
    /// would be open whatever the session's own permit says. An error fails the
    /// connect, and teardown puts the segment back as it was.
    pub(super) fn follow_servers_in_lockdown(
        &mut self,
        servers: &[IpAddr],
    ) -> Result<(), HelperError> {
        let previous = std::mem::replace(&mut self.lan_servers, servers.to_vec());
        let state = lockdown::read(&self.lockdown);
        if !state.enabled || !state.allow_lan || state.upgrade_hold {
            return Ok(());
        }
        let Some(lan) = self.lockdown_lan(true, state.private_networks) else {
            return Ok(());
        };
        if lan.segment == self.lockdown_segment_around(&previous) {
            return Ok(());
        }
        self.routing
            .enable_lockdown(Some(&lan), &self.lockdown_programs())
            .map_err(|error| HelperError::new(ErrorCode::RoutingFailed, error.to_string()))?;
        Ok(())
    }

    /// With "Local network" on, a broadcast without a chosen adapter leaves the
    /// tunnel. A failure only logs: the session works, and such a broadcast
    /// stays in the tunnel as it would without this.
    pub(super) fn release_broadcast_route(&mut self, tun: &TunSettings) {
        let Ok(tunnel) = TunnelInterface::try_from(tun) else {
            return;
        };
        let release = (self.broadcast_route_release)(&tunnel);
        if release.removed > 0 {
            tracing::info!(
                "local network: a broadcast without a chosen adapter stays out of the tunnel"
            );
        }
        if let Some(code) = new_failure(self.broadcast_route_failure, release.failure) {
            tracing::warn!(
                code,
                "local network: could not take the broadcast route off the tunnel"
            );
        }
        self.broadcast_route_failure = release.failure;
    }

    /// A supervisor tick of a running session: whether the computer is on
    /// another segment for good, which the session follows with a protected
    /// reconnect. Lockdown's persistent set follows at once. The broadcast
    /// route is checked here too: Windows puts it back when the adapter's
    /// address or state changes.
    pub(super) fn local_network_changed(&mut self) -> bool {
        let Some(settings) = self
            .request
            .as_ref()
            .map(|request| request.settings.clone())
        else {
            return false;
        };
        if !settings.allow_lan {
            return false;
        }
        self.release_broadcast_route(&settings.tun);
        let read = self.scan_lan(&settings.tun, &self.lan_servers, false);
        let Some(segment) = self.lan_watch.observe(&self.lan.segment, read) else {
            return false;
        };
        tracing::info!(networks = segment.networks().len(), "local network changed");
        self.follow_lan_in_lockdown_now();
        true
    }

    /// A supervisor tick without a session: Lockdown's "Local network"
    /// follows the network the computer is on.
    pub(super) fn follow_lan_in_lockdown(&mut self) {
        let state = lockdown::read(&self.lockdown);
        if !state.enabled || !state.allow_lan || state.upgrade_hold {
            return;
        }
        let tun = TunSettings::default();
        let read = self.scan_lan(&tun, &[], false);
        if let Some(segment) = self.lan_watch.observe(&self.lockdown_segment, read) {
            tracing::info!(networks = segment.networks().len(), "local network changed");
            self.follow_lan_in_lockdown_now();
        }
    }

    fn follow_lan_in_lockdown_now(&mut self) {
        let state = lockdown::read(&self.lockdown);
        if !state.enabled || !state.allow_lan || state.upgrade_hold {
            return;
        }
        let Some(lan) = self.lockdown_lan(true, state.private_networks) else {
            return;
        };
        match self
            .routing
            .enable_lockdown(Some(&lan), &self.lockdown_programs())
        {
            Ok(_) => {
                self.lockdown_segment = lan.segment;
                tracing::info!("Lockdown's local network follows the new network");
            }
            Err(error) => tracing::error!(
                %error,
                "Lockdown's local network could not follow the new network; it stays as it was"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_segment_counts_once_it_has_held_for_a_while() {
        let mut watch = LanWatch::default();
        assert_eq!(watch.observe(&1, 1), None);
        assert_eq!(watch.observe(&1, 2), None);
        assert_eq!(watch.observe(&1, 2), None);
        assert_eq!(watch.observe(&1, 2), Some(2));
        // A flap back to the old segment starts over.
        assert_eq!(watch.observe(&2, 3), None);
        assert_eq!(watch.observe(&2, 2), None);
        assert_eq!(watch.observe(&2, 3), None);
        assert_eq!(watch.observe(&2, 4), None);
        assert_eq!(watch.observe(&2, 4), None);
        assert_eq!(watch.observe(&2, 4), Some(4));
    }

    #[test]
    fn a_repeated_route_failure_is_logged_once() {
        assert_eq!(new_failure(None, None), None);
        assert_eq!(new_failure(None, Some(5)), Some(5));
        assert_eq!(new_failure(Some(5), Some(5)), None);
        assert_eq!(new_failure(Some(5), Some(87)), Some(87));
        assert_eq!(new_failure(Some(5), None), None);
    }

    #[test]
    fn the_tunnels_own_networks_come_from_its_addresses() {
        let mut tun = TunSettings::default();
        assert_eq!(
            tunnel_networks(&tun)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["172.19.0.0/30"]
        );
        tun.ipv6 = Some("fdfe:dcba:9876::1/126".to_owned());
        assert_eq!(tunnel_networks(&tun).len(), 2);
    }
}
