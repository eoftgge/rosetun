//! Warn about a persistent route outside a connected, unprotected TUN.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use rosetun_config::{ConnectionMode, ConnectionState};

use super::Session;

const INTERVAL: Duration = Duration::from_secs(2);
const READS: u8 = 3;
type RouteLookup = fn(IpAddr) -> std::io::Result<String>;

pub(super) struct BypassWatch {
    pub(super) lookup: RouteLookup,
    next: Option<Instant>,
    consecutive: u8,
}

impl Default for BypassWatch {
    fn default() -> Self {
        Self {
            #[cfg(not(test))]
            lookup: rosetun_routing::route_interface,
            #[cfg(test)]
            lookup: |_| Err(std::io::ErrorKind::Unsupported.into()),
            next: None,
            consecutive: 0,
        }
    }
}

impl BypassWatch {
    pub(super) fn reset(&mut self) {
        self.next = None;
        self.consecutive = 0;
    }

    fn observe(&mut self, outside: Option<bool>, previous: bool) -> bool {
        match outside {
            Some(true) => {
                self.consecutive = self.consecutive.saturating_add(1).min(READS);
                previous || self.consecutive >= READS
            }
            Some(false) => {
                self.consecutive = 0;
                false
            }
            None => {
                self.consecutive = 0;
                previous
            }
        }
    }
}

impl Session {
    pub(super) fn observe_bypass(&mut self, now: Instant) {
        let status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let eligible = self.request.as_ref().filter(|request| {
            status.state == ConnectionState::Connected
                && request.settings.connection_mode == ConnectionMode::Tun
                && !request.settings.kill_switch
                && !self.protection.keeps_protection()
                && !super::lockdown::read(&self.lockdown).enabled
        });
        let Some(request) = eligible else {
            self.bypass.reset();
            self.set_bypass(false);
            return;
        };
        if self.bypass.next.is_some_and(|next| now < next) {
            return;
        }
        self.bypass.next = Some(now + INTERVAL);
        let literal_matches = |node: &rosetun_config::Node, address: &IpAddr| {
            node.server.parse::<IpAddr>().ok() == Some(*address)
                || matches!(
                    &node.outbound,
                    rosetun_config::Outbound::XrayBalancer(balancer)
                        if balancer
                            .members
                            .iter()
                            .any(|member| member.server.parse::<IpAddr>().ok() == Some(*address))
                )
        };
        let excluded = |address: &IpAddr| {
            literal_matches(&request.node, address)
                || self
                    .last_endpoint
                    .as_ref()
                    .is_some_and(|server| server.contains_address(*address))
                || self
                    .last_extra_endpoints
                    .values()
                    .any(|server| server.contains_address(*address))
                || request
                    .extra_nodes
                    .iter()
                    .any(|extra| literal_matches(&extra.node, address))
                || (request.settings.allow_lan
                    && self
                        .lan
                        .access()
                        .segment
                        .prefixes()
                        .iter()
                        .any(|prefix| prefix.contains(*address)))
        };
        // IPv6 without a TUN address is blocked by strict_route, so its physical
        // default route alone is not evidence of a usable bypass.
        let ipv4 = [
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(9, 9, 9, 9),
            Ipv4Addr::new(8, 8, 8, 8),
        ]
        .into_iter()
        .map(IpAddr::V4)
        .find(|address| !excluded(address));
        let ipv6 = request.settings.tun.ipv6.as_ref().and_then(|_| {
            [
                Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
                Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe),
            ]
            .into_iter()
            .map(IpAddr::V6)
            .find(|address| !excluded(address))
        });
        let expected_interface = self.effective_tun_name(&request.settings.tun);
        let results: Vec<_> = [ipv4, ipv6]
            .into_iter()
            .flatten()
            .map(|address| {
                (self.bypass.lookup)(address).ok().map(|interface| {
                    if cfg!(windows) {
                        !interface.eq_ignore_ascii_case(expected_interface)
                    } else {
                        interface != expected_interface
                    }
                })
            })
            .collect();
        let outside = if results.contains(&Some(true)) {
            Some(true)
        } else if !results.is_empty() && results.iter().all(|result| *result == Some(false)) {
            Some(false)
        } else {
            None
        };
        let detected = self.bypass.observe(outside, status.bypass_detected);
        self.set_bypass(detected);
    }

    fn set_bypass(&self, detected: bool) {
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if status.bypass_detected != detected {
            status.bypass_detected = detected;
            if detected {
                tracing::warn!("a route bypasses the VPN without the kill switch");
            } else {
                tracing::info!("the VPN bypass warning cleared");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_three_consecutive_confirmed_bypasses_raise_a_warning() {
        let mut watch = BypassWatch::default();
        assert!(!watch.observe(Some(true), false));
        assert!(!watch.observe(Some(true), false));
        assert!(!watch.observe(None, false));
        assert!(!watch.observe(Some(true), false));
        assert!(!watch.observe(Some(true), false));
        assert!(watch.observe(Some(true), false));
        assert!(watch.observe(None, true));
        assert!(!watch.observe(Some(false), true));
        assert!(!watch.observe(Some(true), false));
        watch.reset();
        assert!(!watch.observe(Some(true), false));
    }
}
