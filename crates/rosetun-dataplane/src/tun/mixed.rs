use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::packet::{Packet, PacketError, Transport, rewrite_endpoints_in_place};

const FIRST_PORT: u16 = 1024;
const FLOW_LIMIT: usize = 16_384;
const HANDSHAKE_UNANSWERED: Duration = Duration::from_secs(15);
const HANDSHAKE_IDLE: Duration = Duration::from_secs(60);
const RST_COOLDOWN: Duration = Duration::from_secs(5);
const PORT_REUSE_DELAY: Duration = Duration::from_secs(60);

/// A listener on the local TUN address and the peer whose route leads back to TUN.
#[derive(Clone, Copy)]
pub struct TcpRedirect {
    pub listener: SocketAddr,
    pub peer: IpAddr,
}

impl fmt::Debug for TcpRedirect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpRedirect")
            .field("ipv4", &self.listener.is_ipv4())
            .finish_non_exhaustive()
    }
}

/// The endpoints before redirection, used for policy, DNS and process lookup.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpFlow {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl fmt::Debug for TcpFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpFlow").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RedirectError {
    #[error("invalid tunnel TCP redirection addresses")]
    Address,
    #[error("no tunnel TCP redirection for this address family")]
    Family,
    #[error("tunnel TCP redirection table is full")]
    Capacity,
    #[error("invalid tunnel TCP packet: {0}")]
    Packet(#[from] PacketError),
}

struct Mapping {
    peer: SocketAddr,
    opened: Instant,
    saw_reply: bool,
    state: State,
}

enum State {
    Pending,
    Accepted,
    Closed { until: Instant },
}

pub trait TcpStack {
    fn redirect(
        &mut self,
        packet: &Packet<'_>,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, RedirectError>;

    fn accept(&mut self, peer: SocketAddr) -> Option<TcpFlow>;

    fn close(&mut self, peer: SocketAddr, now: Instant);
}

/// TCP address translation into the host stack with a distinct peer port per flow.
pub struct MixedTcp {
    v4: Option<TcpRedirect>,
    v6: Option<TcpRedirect>,
    flows: HashMap<TcpFlow, Mapping>,
    by_peer: HashMap<SocketAddr, TcpFlow>,
    cooldown: HashMap<SocketAddr, Instant>,
    next_port: u16,
    reap_at: Option<Instant>,
}

impl fmt::Debug for MixedTcp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MixedTcp")
            .field("ipv4", &self.v4.is_some())
            .field("ipv6", &self.v6.is_some())
            .field("flows", &self.flows.len())
            .finish_non_exhaustive()
    }
}

impl MixedTcp {
    pub fn new(redirects: impl IntoIterator<Item = TcpRedirect>) -> Result<Self, RedirectError> {
        let mut table = Self {
            v4: None,
            v6: None,
            flows: HashMap::new(),
            by_peer: HashMap::new(),
            cooldown: HashMap::new(),
            next_port: FIRST_PORT,
            reap_at: None,
        };
        for redirect in redirects {
            if redirect.listener.is_ipv4() != redirect.peer.is_ipv4()
                || redirect.listener.port() == 0
                || redirect.listener.ip() == redirect.peer
                || !unicast(redirect.listener.ip())
                || !unicast(redirect.peer)
            {
                return Err(RedirectError::Address);
            }
            let family = if redirect.peer.is_ipv4() {
                &mut table.v4
            } else {
                &mut table.v6
            };
            if family.replace(redirect).is_some() {
                return Err(RedirectError::Address);
            }
        }
        Ok(table)
    }

    fn reap(&mut self, now: Instant) {
        if self.reap_at.is_some_and(|next| now < next) {
            return;
        }
        self.reap_at = now.checked_add(Duration::from_secs(1));
        self.flows.retain(|_, mapping| {
            let live = match mapping.state {
                State::Pending => {
                    let limit = if mapping.saw_reply {
                        HANDSHAKE_IDLE
                    } else {
                        HANDSHAKE_UNANSWERED
                    };
                    now.saturating_duration_since(mapping.opened) < limit
                }
                State::Accepted => true,
                State::Closed { until } => now < until,
            };
            if !live {
                self.by_peer.remove(&mapping.peer);
            }
            live
        });
        self.cooldown.retain(|_, until| now < *until);
    }

    fn evict_closed_flows(&mut self) {
        self.flows.retain(|_, mapping| {
            if let State::Closed { until } = mapping.state {
                self.by_peer.remove(&mapping.peer);
                self.cooldown.insert(mapping.peer, until);
                false
            } else {
                true
            }
        });
    }

    fn allocate_peer(&mut self, ip: IpAddr, now: Instant) -> Result<SocketAddr, RedirectError> {
        if self.flows.len() >= FLOW_LIMIT {
            self.evict_closed_flows();
            if self.flows.len() >= FLOW_LIMIT {
                return Err(RedirectError::Capacity);
            }
        }
        for _ in FIRST_PORT..=u16::MAX {
            let port = self.next_port;
            self.next_port = port.checked_add(1).unwrap_or(FIRST_PORT);
            let candidate = SocketAddr::new(ip, port);
            if self.by_peer.contains_key(&candidate) {
                continue;
            }
            if let Some(&until) = self.cooldown.get(&candidate) {
                if now < until {
                    continue;
                }
                self.cooldown.remove(&candidate);
            }
            return Ok(candidate);
        }
        // Under heavy port churn, reclaim the oldest cooled-down peer port
        // instead of failing new connections while inactive ports sit in TIME_WAIT.
        if let Some((&oldest_peer, _)) = self
            .cooldown
            .iter()
            .filter(|(peer, _)| peer.ip() == ip && !self.by_peer.contains_key(peer))
            .min_by_key(|(_, until)| *until)
        {
            self.cooldown.remove(&oldest_peer);
            return Ok(oldest_peer);
        }
        Err(RedirectError::Capacity)
    }

    fn plan_redirect(
        &mut self,
        flow: TcpFlow,
        starts_connection: bool,
        is_rst: bool,
        now: Instant,
    ) -> Result<Option<(SocketAddr, SocketAddr)>, RedirectError> {
        self.reap(now);
        let redirect = if flow.source.is_ipv4() {
            self.v4
        } else {
            self.v6
        }
        .ok_or(RedirectError::Family)?;
        if flow.source == redirect.listener {
            // Only this listener can send a segment on the reverse mapping.
            let Some(&original) = self.by_peer.get(&flow.destination) else {
                return Ok(None);
            };
            if let Some(mapping) = self.flows.get_mut(&original) {
                mapping.saw_reply = true;
                if is_rst {
                    let rst_until = now + RST_COOLDOWN;
                    mapping.state = match mapping.state {
                        State::Closed { until } => State::Closed {
                            until: until.min(rst_until),
                        },
                        State::Pending | State::Accepted => State::Closed { until: rst_until },
                    };
                }
            }
            return Ok(Some((original.destination, original.source)));
        }
        if flow.source.ip() != redirect.listener.ip()
            || flow.destination.ip() == redirect.peer
            || flow.destination.ip() == redirect.listener.ip()
            || !unicast(flow.destination.ip())
        {
            return Ok(None);
        }
        if let Some(mapped) = self.flows.get_mut(&flow) {
            let peer = mapped.peer;
            if let State::Closed { until } = mapped.state {
                if starts_connection {
                    self.flows.remove(&flow);
                    self.by_peer.remove(&peer);
                    self.cooldown.insert(peer, until);
                } else {
                    if is_rst {
                        mapped.state = State::Closed {
                            until: until.min(now + RST_COOLDOWN),
                        };
                    }
                    return Ok(Some((peer, redirect.listener)));
                }
            } else {
                if is_rst {
                    mapped.state = State::Closed {
                        until: now + RST_COOLDOWN,
                    };
                }
                return Ok(Some((peer, redirect.listener)));
            }
        }
        if !starts_connection {
            return Ok(None);
        }
        let peer = self.allocate_peer(redirect.peer, now)?;
        self.by_peer.insert(peer, flow);
        self.flows.insert(
            flow,
            Mapping {
                peer,
                opened: now,
                saw_reply: false,
                state: State::Pending,
            },
        );
        Ok(Some((peer, redirect.listener)))
    }

    /// Translates a parsed TCP packet in place without allocating a new buffer.
    pub(crate) fn redirect_in_place(
        &mut self,
        frame: &mut [u8],
        offset: usize,
        flow: TcpFlow,
        starts_connection: bool,
        is_rst: bool,
        now: Instant,
    ) -> Result<bool, RedirectError> {
        let Some((new_source, new_destination)) =
            self.plan_redirect(flow, starts_connection, is_rst, now)?
        else {
            return Ok(false);
        };
        rewrite_endpoints_in_place(
            frame,
            offset,
            Transport::Tcp,
            flow.source,
            flow.destination,
            new_source,
            new_destination,
        )?;
        Ok(true)
    }
}

impl TcpStack for MixedTcp {
    fn redirect(
        &mut self,
        packet: &Packet<'_>,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, RedirectError> {
        if packet.transport() != Transport::Tcp {
            return Ok(None);
        }
        let flow = TcpFlow {
            source: packet.source(),
            destination: packet.destination(),
        };
        let Some((new_source, new_destination)) = self.plan_redirect(
            flow,
            packet.tcp_starts_connection(),
            packet.tcp_is_rst(),
            now,
        )?
        else {
            return Ok(None);
        };
        Ok(Some(packet.rewrite(new_source, new_destination)?))
    }

    fn accept(&mut self, peer: SocketAddr) -> Option<TcpFlow> {
        let flow = *self.by_peer.get(&peer)?;
        let mapping = self.flows.get_mut(&flow)?;
        if matches!(mapping.state, State::Pending) {
            mapping.state = State::Accepted;
            Some(flow)
        } else {
            None
        }
    }

    fn close(&mut self, peer: SocketAddr, now: Instant) {
        if let Some(flow) = self.by_peer.get(&peer)
            && let Some(mapping) = self.flows.get_mut(flow)
        {
            let until = now + PORT_REUSE_DELAY;
            mapping.state = match mapping.state {
                State::Closed { until: existing } => State::Closed {
                    until: existing.min(until),
                },
                State::Pending | State::Accepted => State::Closed { until },
            };
        }
    }
}

fn unicast(ip: IpAddr) -> bool {
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(addr) if addr.is_broadcast()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::packet::tcp_test_packet;

    #[test]
    fn mixed_redirection_rewrites_both_directions_and_recovers_original_flow() {
        for (client, destination, listener, peer) in [
            (
                "192.0.2.1:25000",
                "198.51.100.1:443",
                "192.0.2.1:45000",
                "192.0.2.2",
            ),
            (
                "[2001:db8::1]:25000",
                "[2001:db8:1::1]:443",
                "[2001:db8::1]:45000",
                "2001:db8::2",
            ),
        ] {
            let client = client.parse().unwrap();
            let destination = destination.parse().unwrap();
            let listener = listener.parse().unwrap();
            let peer = peer.parse().unwrap();
            let now = Instant::now();
            let mut nat = MixedTcp::new([TcpRedirect { listener, peer }]).unwrap();
            let syn = tcp_test_packet(client, destination, 0x02);
            let injection = nat
                .redirect(&Packet::parse(&syn).unwrap(), now)
                .unwrap()
                .unwrap();
            let injection = Packet::parse(&injection).unwrap();
            assert_eq!(injection.destination(), listener);
            assert_eq!(injection.source().ip(), peer);
            assert!(injection.tcp_starts_connection());

            let reply = tcp_test_packet(listener, injection.source(), 0x12);
            let original = nat
                .redirect(&Packet::parse(&reply).unwrap(), now)
                .unwrap()
                .unwrap();
            let original = Packet::parse(&original).unwrap();
            assert_eq!(original.source(), destination);
            assert_eq!(original.destination(), client);
            assert!(!original.tcp_starts_connection());
            assert_eq!(
                nat.accept(injection.source()),
                Some(TcpFlow {
                    source: client,
                    destination
                })
            );
            assert!(nat.accept(injection.source()).is_none());
        }
    }

    #[test]
    fn mixed_redirection_keeps_flows_with_the_same_source_port_separate() {
        let client = "192.0.2.1:25000".parse().unwrap();
        let listener = "192.0.2.1:45000".parse().unwrap();
        let mut nat = MixedTcp::new([TcpRedirect {
            listener,
            peer: "192.0.2.2".parse().unwrap(),
        }])
        .unwrap();
        let now = Instant::now();
        let mut redirect_to = |destination: &str| {
            let syn = tcp_test_packet(client, destination.parse().unwrap(), 0x02);
            let injection = nat
                .redirect(&Packet::parse(&syn).unwrap(), now)
                .unwrap()
                .unwrap();
            Packet::parse(&injection).unwrap().source()
        };
        let first = redirect_to("198.51.100.1:443");
        assert_eq!(redirect_to("198.51.100.1:443"), first);
        assert_ne!(redirect_to("198.51.100.2:443"), first);
    }

    #[test]
    fn a_new_syn_after_close_allocates_a_fresh_peer_port_without_reusing_the_closed_one() {
        let client = "192.0.2.1:25000".parse().unwrap();
        let destination = "198.51.100.1:443".parse().unwrap();
        let listener = "192.0.2.1:45000".parse().unwrap();
        let mut nat = MixedTcp::new([TcpRedirect {
            listener,
            peer: "192.0.2.2".parse().unwrap(),
        }])
        .unwrap();
        let now = Instant::now();
        let syn = tcp_test_packet(client, destination, 0x02);
        let first_peer = Packet::parse(
            &nat.redirect(&Packet::parse(&syn).unwrap(), now)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
        .source();
        assert_eq!(
            nat.accept(first_peer),
            Some(TcpFlow {
                source: client,
                destination
            })
        );
        nat.close(first_peer, now);
        let second_peer = Packet::parse(
            &nat.redirect(&Packet::parse(&syn).unwrap(), now)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
        .source();
        assert_ne!(second_peer, first_peer);
        assert_eq!(
            nat.accept(second_peer),
            Some(TcpFlow {
                source: client,
                destination
            })
        );
    }

    #[test]
    fn rst_segment_shortens_cooldown_and_unanswered_syn_expires_promptly() {
        let client = "192.0.2.1:25000".parse().unwrap();
        let destination = "198.51.100.1:443".parse().unwrap();
        let listener = "192.0.2.1:45000".parse().unwrap();
        let mut nat = MixedTcp::new([TcpRedirect {
            listener,
            peer: "192.0.2.2".parse().unwrap(),
        }])
        .unwrap();
        let start = Instant::now();

        let syn = tcp_test_packet(client, destination, 0x02);
        let peer = Packet::parse(
            &nat.redirect(&Packet::parse(&syn).unwrap(), start)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
        .source();

        // Unanswered SYN expires after HANDSHAKE_UNANSWERED (15s), well before 60s.
        let after_unanswered = start + Duration::from_secs(16);
        let probe_syn = tcp_test_packet("192.0.2.1:25001".parse().unwrap(), destination, 0x02);
        let _ = nat
            .redirect(&Packet::parse(&probe_syn).unwrap(), after_unanswered)
            .unwrap();
        assert!(nat.accept(peer).is_none());

        // RST from client transitions flow to short cooldown (5s instead of 60s).
        let peer2 = Packet::parse(
            &nat.redirect(&Packet::parse(&syn).unwrap(), after_unanswered)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
        .source();
        let rst = tcp_test_packet(client, destination, 0x04);
        let _ = nat
            .redirect(&Packet::parse(&rst).unwrap(), after_unanswered)
            .unwrap();
        let after_rst = after_unanswered + Duration::from_secs(6);
        let _ = nat
            .redirect(&Packet::parse(&probe_syn).unwrap(), after_rst)
            .unwrap();
        assert!(!nat.by_peer.contains_key(&peer2));
    }
}
