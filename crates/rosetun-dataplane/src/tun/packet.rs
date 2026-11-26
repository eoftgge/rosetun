use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const UDP_HEADER: usize = 8;
const TCP_HEADER: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("invalid IP or transport header")]
    Malformed,
    #[error("invalid IP or transport checksum")]
    Checksum,
    #[error("fragmented IP packet")]
    Fragment,
    #[error("unsupported IP header")]
    Unsupported,
    #[error("packet exceeds the tunnel MTU")]
    Mtu,
    #[error("addresses have different families")]
    AddressFamily,
}

/// An IP packet with a complete TCP segment or UDP datagram.
pub struct Packet<'a> {
    bytes: &'a [u8],
    source: SocketAddr,
    destination: SocketAddr,
    offset: usize,
    transport: Transport,
}

impl fmt::Debug for Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("length", &self.bytes.len())
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl<'a> Packet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        let (source, destination, offset, length, protocol) =
            match bytes.first().map(|byte| byte >> 4) {
                Some(4) => ipv4(bytes)?,
                Some(6) => ipv6(bytes)?,
                _ => return Err(PacketError::Malformed),
            };
        let payload = &bytes[offset..length];
        let transport = match protocol {
            6 if payload.len() >= TCP_HEADER => {
                let header_length = usize::from(payload[12] >> 4) * 4;
                if !(TCP_HEADER..=payload.len()).contains(&header_length) {
                    return Err(PacketError::Malformed);
                }
                Transport::Tcp
            }
            17 if payload.len() >= UDP_HEADER => {
                if usize::from(read_u16(payload, 4)) != payload.len() {
                    return Err(PacketError::Malformed);
                }
                Transport::Udp
            }
            6 | 17 => return Err(PacketError::Malformed),
            _ => return Err(PacketError::Unsupported),
        };
        let udp_checksum = transport == Transport::Udp && read_u16(payload, 6) == 0;
        if udp_checksum && source.is_ipv6()
            || !udp_checksum && transport_checksum(source, destination, protocol, payload) != 0
        {
            return Err(PacketError::Checksum);
        }
        let source = SocketAddr::new(source, read_u16(payload, 0));
        let destination = SocketAddr::new(destination, read_u16(payload, 2));
        if source.port() == 0 || destination.port() == 0 {
            return Err(PacketError::Malformed);
        }
        Ok(Self {
            bytes: &bytes[..length],
            source,
            destination,
            offset,
            transport,
        })
    }

    pub fn source(&self) -> SocketAddr {
        self.source
    }

    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    pub fn transport(&self) -> Transport {
        self.transport
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn header_offset(&self) -> usize {
        self.offset
    }

    pub fn udp_payload(&self) -> Option<&'a [u8]> {
        (self.transport == Transport::Udp).then(|| &self.bytes[self.offset + UDP_HEADER..])
    }

    pub fn tcp_starts_connection(&self) -> bool {
        self.transport == Transport::Tcp && self.bytes[self.offset + 13] & 0x17 == 0x02
    }

    /// Changes addresses and ports while preserving TCP sequence numbers, options and flags.
    pub fn rewrite(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Result<Vec<u8>, PacketError> {
        let mut result = self.bytes.to_vec();
        rewrite_endpoints_in_place(
            &mut result,
            self.offset,
            self.transport,
            self.source,
            self.destination,
            source,
            destination,
        )?;
        Ok(result)
    }
}

/// Rewrites IP/transport endpoints in place using RFC 1624 incremental checksum
/// updates for TCP (O(1) instead of scanning the whole payload).
pub(crate) fn rewrite_endpoints_in_place(
    packet: &mut [u8],
    offset: usize,
    transport: Transport,
    old_source: SocketAddr,
    old_destination: SocketAddr,
    source: SocketAddr,
    destination: SocketAddr,
) -> Result<(), PacketError> {
    if source.is_ipv4() != old_source.is_ipv4()
        || destination.is_ipv4() != old_destination.is_ipv4()
    {
        return Err(PacketError::AddressFamily);
    }
    if transport == Transport::Tcp {
        update_tcp_endpoints_incremental(
            packet,
            offset,
            old_source,
            old_destination,
            source,
            destination,
        );
    } else {
        set_endpoints(packet, offset, transport, source, destination);
    }
    Ok(())
}

type IpHeader = (IpAddr, IpAddr, usize, usize, u8);

fn ipv4(bytes: &[u8]) -> Result<IpHeader, PacketError> {
    if bytes.len() < IPV4_HEADER {
        return Err(PacketError::Malformed);
    }
    let offset = usize::from(bytes[0] & 0xf) * 4;
    let length = usize::from(read_u16(bytes, 2));
    if offset < IPV4_HEADER || offset > length || length > bytes.len() || bytes[8] == 0 {
        return Err(PacketError::Malformed);
    }
    if read_u16(bytes, 6) & 0x3fff != 0 {
        return Err(PacketError::Fragment);
    }
    if checksum(word_sum(&bytes[..offset])) != 0 {
        return Err(PacketError::Checksum);
    }
    // IP options can change where the packet is delivered. A transparent rewrite
    // cannot safely preserve source-routing options.
    if offset != IPV4_HEADER {
        return Err(PacketError::Unsupported);
    }
    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    Ok((source.into(), destination.into(), offset, length, bytes[9]))
}

fn ipv6(bytes: &[u8]) -> Result<IpHeader, PacketError> {
    if bytes.len() < IPV6_HEADER || bytes[7] == 0 {
        return Err(PacketError::Malformed);
    }
    let length = IPV6_HEADER + usize::from(read_u16(bytes, 4));
    let packet = bytes.get(..length).ok_or(PacketError::Malformed)?;
    let source =
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).map_err(|_| PacketError::Malformed)?);
    let destination =
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).map_err(|_| PacketError::Malformed)?);
    let mut protocol = packet[6];
    let mut offset = IPV6_HEADER;
    // The only extensions accepted here do not alter the transport endpoints.
    for _ in 0..8 {
        match protocol {
            0 | 60 => {
                if protocol == 0 && offset != IPV6_HEADER {
                    return Err(PacketError::Malformed);
                }
                let header = packet
                    .get(offset..offset + 2)
                    .ok_or(PacketError::Malformed)?;
                protocol = header[0];
                offset += (usize::from(header[1]) + 1) * 8;
                if offset > length {
                    return Err(PacketError::Malformed);
                }
            }
            44 => return Err(PacketError::Fragment),
            _ => return Ok((source.into(), destination.into(), offset, length, protocol)),
        }
    }
    Err(PacketError::Unsupported)
}

/// Encodes a complete UDP response. A datagram is either emitted intact or
/// rejected. Truncating it would turn an oversized response into valid data.
pub fn udp_reply(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    mtu: usize,
) -> Result<Vec<u8>, PacketError> {
    let mut packet = Vec::new();
    udp_reply_into(source, destination, payload, mtu, &mut packet)?;
    Ok(packet)
}

/// Encodes a complete UDP response into a reusable buffer without allocating
/// once `out` has sufficient capacity.
pub(crate) fn udp_reply_into(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    mtu: usize,
    out: &mut Vec<u8>,
) -> Result<(), PacketError> {
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(PacketError::AddressFamily);
    }
    let offset = if source.is_ipv4() {
        IPV4_HEADER
    } else {
        IPV6_HEADER
    };
    let length = offset + UDP_HEADER + payload.len();
    if length > mtu || length > usize::from(u16::MAX) {
        return Err(PacketError::Mtu);
    }
    out.clear();
    out.resize(length, 0);
    if source.is_ipv4() {
        out[0] = 0x45;
        out[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        out[6] = 0x40;
        out[8] = 64;
        out[9] = Transport::Udp.number();
    } else {
        out[0] = 0x60;
        out[4..6].copy_from_slice(&((length - offset) as u16).to_be_bytes());
        out[6] = Transport::Udp.number();
        out[7] = 64;
    }
    out[offset + 4..offset + 6].copy_from_slice(&((length - offset) as u16).to_be_bytes());
    out[offset + UDP_HEADER..].copy_from_slice(payload);
    set_endpoints(out, offset, Transport::Udp, source, destination);
    Ok(())
}

fn update_tcp_endpoints_incremental(
    packet: &mut [u8],
    offset: usize,
    old_source: SocketAddr,
    old_destination: SocketAddr,
    source: SocketAddr,
    destination: SocketAddr,
) {
    let old_ip = ip_word_sum(old_source.ip()) + ip_word_sum(old_destination.ip());
    let new_ip = ip_word_sum(source.ip()) + ip_word_sum(destination.ip());
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            packet[12..16].copy_from_slice(&src.octets());
            packet[16..20].copy_from_slice(&dst.octets());
            let old_hc = read_u16(packet, 10);
            let new_hc = incremental_checksum(old_hc, fold(old_ip), fold(new_ip));
            packet[10..12].copy_from_slice(&new_hc.to_be_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            packet[8..24].copy_from_slice(&src.octets());
            packet[24..40].copy_from_slice(&dst.octets());
        }
        _ => unreachable!("packet addresses have a common family"),
    }
    let segment = &mut packet[offset..];
    segment[..2].copy_from_slice(&source.port().to_be_bytes());
    segment[2..4].copy_from_slice(&destination.port().to_be_bytes());
    let old_tcp = fold(old_ip + u32::from(old_source.port()) + u32::from(old_destination.port()));
    let new_tcp = fold(new_ip + u32::from(source.port()) + u32::from(destination.port()));
    let old_hc = read_u16(segment, 16);
    let new_hc = incremental_checksum(old_hc, old_tcp, new_tcp);
    segment[16..18].copy_from_slice(&new_hc.to_be_bytes());
}

fn ip_word_sum(ip: IpAddr) -> u32 {
    match ip {
        IpAddr::V4(ip) => word_sum(&ip.octets()),
        IpAddr::V6(ip) => word_sum(&ip.octets()),
    }
}

fn incremental_checksum(old_hc: u16, old_words: u16, new_words: u16) -> u16 {
    checksum(u32::from(!old_hc) + u32::from(!old_words) + u32::from(new_words))
}

fn set_endpoints(
    packet: &mut [u8],
    offset: usize,
    transport: Transport,
    source: SocketAddr,
    destination: SocketAddr,
) {
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&destination.octets());
            packet[10..12].fill(0);
            let sum = checksum(word_sum(&packet[..offset]));
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&destination.octets());
        }
        _ => unreachable!("packet addresses have a common family"),
    }
    let transport_offset = if transport == Transport::Tcp { 16 } else { 6 };
    let segment = &mut packet[offset..];
    segment[..2].copy_from_slice(&source.port().to_be_bytes());
    segment[2..4].copy_from_slice(&destination.port().to_be_bytes());
    segment[transport_offset..transport_offset + 2].fill(0);
    let mut sum = transport_checksum(source.ip(), destination.ip(), transport.number(), segment);
    if transport == Transport::Udp && sum == 0 {
        sum = u16::MAX;
    }
    segment[transport_offset..transport_offset + 2].copy_from_slice(&sum.to_be_bytes());
}

fn transport_checksum(source: IpAddr, destination: IpAddr, protocol: u8, segment: &[u8]) -> u16 {
    let addresses = match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            word_sum(&source.octets()) + word_sum(&destination.octets())
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            word_sum(&source.octets()) + word_sum(&destination.octets())
        }
        _ => unreachable!("the IP header provides a common address family"),
    };
    checksum(addresses + u32::from(protocol) + segment.len() as u32 + word_sum(segment))
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn word_sum(bytes: &[u8]) -> u32 {
    let (pairs, remainder) = bytes.as_chunks::<2>();
    let words = pairs
        .iter()
        .map(|pair| u32::from(u16::from_be_bytes(*pair)))
        .sum::<u32>();
    words + remainder.first().map_or(0, |byte| u32::from(*byte) << 8)
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn checksum(sum: u32) -> u16 {
    !fold(sum)
}

#[cfg(test)]
pub(super) fn tcp_test_packet(source: SocketAddr, destination: SocketAddr, flags: u8) -> Vec<u8> {
    let mut packet = udp_reply(source, destination, &[0; TCP_HEADER - UDP_HEADER], 1500)
        .expect("the test generates same-family addresses");
    let offset = if source.is_ipv4() {
        packet[9] = Transport::Tcp.number();
        IPV4_HEADER
    } else {
        packet[6] = Transport::Tcp.number();
        IPV6_HEADER
    };
    packet[offset..].fill(0);
    packet[offset + 12] = 5 << 4;
    packet[offset + 13] = flags;
    set_endpoints(&mut packet, offset, Transport::Tcp, source, destination);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_packets_roundtrip_for_both_families() {
        for (source, destination) in [
            ("192.0.2.1:53", "198.51.100.2:12345"),
            ("[2001:db8::1]:53", "[2001:db8::2]:12345"),
        ] {
            let source = source.parse().unwrap();
            let destination = destination.parse().unwrap();
            let mut bytes = udp_reply(source, destination, b"query", 1500).unwrap();
            let packet = Packet::parse(&bytes).unwrap();
            assert_eq!(packet.source(), source);
            assert_eq!(packet.destination(), destination);
            assert_eq!(packet.udp_payload(), Some(&b"query"[..]));
            *bytes.last_mut().unwrap() ^= 1;
            assert_eq!(Packet::parse(&bytes).unwrap_err(), PacketError::Checksum);
        }
    }

    #[test]
    fn oversized_datagrams_are_refused_instead_of_truncated() {
        let source = "[2001:db8::1]:53".parse().unwrap();
        let destination = "[2001:db8::2]:10050".parse().unwrap();
        assert_eq!(
            udp_reply(source, destination, &[0; 1233], 1280),
            Err(PacketError::Mtu)
        );
    }

    #[test]
    fn incremental_tcp_rewrite_matches_full_checksum_recomputation() {
        for (old_src, old_dst, new_src, new_dst) in [
            (
                "192.0.2.1:25000",
                "198.51.100.1:443",
                "192.0.2.2:49152",
                "192.0.2.1:45000",
            ),
            (
                "[2001:db8::1]:25000",
                "[2001:db8:1::1]:443",
                "[2001:db8::2]:49152",
                "[2001:db8::1]:45000",
            ),
        ] {
            let old_src = old_src.parse().unwrap();
            let old_dst = old_dst.parse().unwrap();
            let new_src = new_src.parse().unwrap();
            let new_dst = new_dst.parse().unwrap();
            let original = tcp_test_packet(old_src, old_dst, 0x18);
            let parsed = Packet::parse(&original).unwrap();
            let mut full = original.clone();
            set_endpoints(
                &mut full,
                parsed.header_offset(),
                Transport::Tcp,
                new_src,
                new_dst,
            );
            let incremental = parsed.rewrite(new_src, new_dst).unwrap();
            assert_eq!(incremental, full);
            let reparsed = Packet::parse(&incremental).unwrap();
            assert_eq!(reparsed.source(), new_src);
            assert_eq!(reparsed.destination(), new_dst);
        }
    }
}
