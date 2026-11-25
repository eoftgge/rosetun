//! QUIC v1 (RFC 9001) and v2 (RFC 9369) Initial packet decryption and SNI sniffer.

use std::fmt;

use ring::aead::quic::{AES_128 as QUIC_HP_AES_128, HeaderProtectionKey};
use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};

use super::tls::parse_client_hello_message;
use super::wire::Reader;
use super::{Probe, Protocol, Sniffed};

const MAX_QUIC_PACKETS: usize = 8;
const MAX_CRYPTO_BYTES: usize = 16 * 1024;
const MAX_QUIC_PACKET_BYTES: usize = 65_535;
const MAX_CID_LEN: usize = 20;
const AEAD_TAG_LEN: usize = 16;
const HP_SAMPLE_OFFSET: usize = 4;
const HP_SAMPLE_LEN: usize = 16;

const QUIC_V1_VERSION: u32 = 0x0000_0001;
const QUIC_V2_VERSION: u32 = 0x6b33_43cf;

const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_V2_INITIAL_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

const FRAME_PADDING: u64 = 0x00;
const FRAME_PING: u64 = 0x01;
const FRAME_ACK: u64 = 0x02;
const FRAME_ACK_ECN: u64 = 0x03;
const FRAME_CRYPTO: u64 = 0x06;

/// Progress of a stateful QUIC Initial sniffer across UDP datagrams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicProgress {
    Found(Sniffed),
    NeedMore,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QuicVersion {
    V1,
    V2,
}

impl QuicVersion {
    fn from_wire(version: u32) -> Option<Self> {
        match version {
            QUIC_V1_VERSION => Some(Self::V1),
            QUIC_V2_VERSION => Some(Self::V2),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(super) fn to_wire(self) -> u32 {
        match self {
            Self::V1 => QUIC_V1_VERSION,
            Self::V2 => QUIC_V2_VERSION,
        }
    }

    pub(super) fn initial_packet_type(self) -> u8 {
        match self {
            Self::V1 => 0b00,
            Self::V2 => 0b01,
        }
    }

    fn initial_salt(self) -> &'static [u8; 20] {
        match self {
            Self::V1 => &QUIC_V1_INITIAL_SALT,
            Self::V2 => &QUIC_V2_INITIAL_SALT,
        }
    }

    fn key_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic key",
            Self::V2 => b"quicv2 key",
        }
    }

    fn iv_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic iv",
            Self::V2 => b"quicv2 iv",
        }
    }

    fn hp_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic hp",
            Self::V2 => b"quicv2 hp",
        }
    }
}

pub(super) struct InitialKeys {
    pub(super) key: [u8; 16],
    pub(super) iv: [u8; 12],
    pub(super) hp: [u8; 16],
}

/// Reassembles QUIC Initial `CRYPTO` frames across up to 8 UDP datagrams of
/// the same connection to extract the TLS ClientHello SNI.
pub struct QuicSniffer {
    version: Option<QuicVersion>,
    dcid: Option<Vec<u8>>,
    keys: Option<InitialKeys>,
    largest_pn: Option<u64>,
    packets_seen: usize,
    crypto: CryptoReassembler,
}

impl fmt::Debug for QuicSniffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicSniffer")
            .field("version", &self.version)
            .field("packets_seen", &self.packets_seen)
            .field("crypto_buffered", &self.crypto.buf.len())
            .finish()
    }
}

impl Default for QuicSniffer {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicSniffer {
    pub fn new() -> Self {
        Self {
            version: None,
            dcid: None,
            keys: None,
            largest_pn: None,
            packets_seen: 0,
            crypto: CryptoReassembler::new(),
        }
    }

    /// Feeds one UDP datagram from the client into the sniffer.
    ///
    /// Coalesced packets after the first Initial packet in the datagram are
    /// ignored. Returns [`QuicProgress::Failed`] on a malformed packet, wrong
    /// connection, decryption failure, or when the packet/buffer cap is hit.
    pub fn feed(&mut self, datagram: &[u8]) -> QuicProgress {
        if self.packets_seen >= MAX_QUIC_PACKETS {
            return QuicProgress::Failed;
        }

        let Some(header) = parse_initial_header(datagram) else {
            return QuicProgress::Failed;
        };

        if let Some(expected_version) = self.version
            && header.version != expected_version
        {
            return QuicProgress::Failed;
        }
        if let Some(expected_dcid) = &self.dcid
            && header.dcid != expected_dcid.as_slice()
        {
            return QuicProgress::Failed;
        }

        let keys = match &self.keys {
            Some(keys) => keys,
            None => {
                let Some(derived) = derive_initial_keys(header.version, header.dcid, b"client in")
                else {
                    return QuicProgress::Failed;
                };
                self.keys.insert(derived)
            }
        };

        let Some((pn, plaintext)) = decrypt_initial_packet(
            &datagram[..header.packet_end],
            header.pn_offset,
            keys,
            self.largest_pn,
        ) else {
            if self.dcid.is_none() {
                // Do not retain keys derived from a packet that failed AEAD.
                self.keys = None;
            }
            return QuicProgress::Failed;
        };

        if self.dcid.is_none() {
            self.version = Some(header.version);
            self.dcid = Some(header.dcid.to_vec());
        }
        self.largest_pn = Some(self.largest_pn.map_or(pn, |prev| prev.max(pn)));
        self.packets_seen += 1;

        if !parse_initial_frames(&plaintext, &mut self.crypto) {
            return QuicProgress::Failed;
        }

        let prefix = self.crypto.contiguous_prefix();
        if prefix.is_empty() {
            return if self.packets_seen >= MAX_QUIC_PACKETS {
                QuicProgress::Failed
            } else {
                QuicProgress::NeedMore
            };
        }

        match parse_client_hello_message(prefix, Protocol::Quic) {
            Probe::Found(sniffed) => QuicProgress::Found(sniffed),
            Probe::NeedMore => {
                if self.packets_seen >= MAX_QUIC_PACKETS {
                    QuicProgress::Failed
                } else {
                    QuicProgress::NeedMore
                }
            }
            Probe::NotThis => QuicProgress::Failed,
        }
    }
}

/// Convenience helper for sniffing a single QUIC Initial UDP datagram.
pub fn sniff_quic_datagram(datagram: &[u8]) -> Option<Sniffed> {
    match QuicSniffer::new().feed(datagram) {
        QuicProgress::Found(sniffed) => Some(sniffed),
        QuicProgress::NeedMore | QuicProgress::Failed => None,
    }
}

struct InitialHeader<'a> {
    version: QuicVersion,
    dcid: &'a [u8],
    pn_offset: usize,
    packet_end: usize,
}

fn parse_initial_header(datagram: &[u8]) -> Option<InitialHeader<'_>> {
    if datagram.is_empty() || datagram.len() > MAX_QUIC_PACKET_BYTES {
        return None;
    }

    let mut reader = Reader::new(datagram);
    let first = reader.u8()?;
    // Long header form bit (0x80) and fixed bit (0x40) must both be set.
    if (first & 0xc0) != 0xc0 {
        return None;
    }

    let version = QuicVersion::from_wire(reader.u32()?)?;
    let packet_type = (first >> 4) & 0x03;
    if packet_type != version.initial_packet_type() {
        return None;
    }

    let dcid = reader.vec8()?;
    if dcid.len() > MAX_CID_LEN {
        return None;
    }
    let scid = reader.vec8()?;
    if scid.len() > MAX_CID_LEN {
        return None;
    }

    let token_len = reader.varint_len()?;
    let _token = reader.take(token_len)?;

    let payload_and_pn_len = reader.varint_len()?;
    let pn_offset = datagram.len() - reader.remaining();

    // Header protection always samples 16 bytes starting 4 bytes past pn_offset,
    // which also guarantees room for a 1..4 byte packet number plus the 16-byte tag.
    if payload_and_pn_len < HP_SAMPLE_OFFSET + HP_SAMPLE_LEN {
        return None;
    }

    let packet_end = pn_offset.checked_add(payload_and_pn_len)?;
    if packet_end > datagram.len() {
        return None;
    }

    Some(InitialHeader {
        version,
        dcid,
        pn_offset,
        packet_end,
    })
}

fn decrypt_initial_packet(
    packet: &[u8],
    pn_offset: usize,
    keys: &InitialKeys,
    largest_pn: Option<u64>,
) -> Option<(u64, Vec<u8>)> {
    let sample_start = pn_offset.checked_add(HP_SAMPLE_OFFSET)?;
    let sample_end = sample_start.checked_add(HP_SAMPLE_LEN)?;
    let sample = packet.get(sample_start..sample_end)?;

    let hp_key = HeaderProtectionKey::new(&QUIC_HP_AES_128, &keys.hp).ok()?;
    let mask = hp_key.new_mask(sample).ok()?;

    let mut buf = packet.to_vec();
    buf[0] ^= mask[0] & 0x0f;
    // Reserved bits (bits 3..2) in an Initial header must be zero once unmasked.
    if (buf[0] & 0x0c) != 0 {
        return None;
    }

    let pn_len = usize::from((buf[0] & 0x03) + 1);
    let payload_offset = pn_offset.checked_add(pn_len)?;
    if buf.len().checked_sub(payload_offset)? < AEAD_TAG_LEN {
        return None;
    }

    let mut truncated_pn = 0u64;
    for i in 0..pn_len {
        buf[pn_offset + i] ^= mask[1 + i];
        truncated_pn = (truncated_pn << 8) | u64::from(buf[pn_offset + i]);
    }

    let pn = decode_packet_number(largest_pn, truncated_pn, pn_len);
    let nonce = make_nonce(&keys.iv, pn);

    let (aad, ciphertext) = buf.split_at_mut(payload_offset);
    let opening_key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &keys.key).ok()?);
    let plaintext = opening_key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            ciphertext,
        )
        .ok()?;

    Some((pn, plaintext.to_vec()))
}

pub(super) fn make_nonce(iv: &[u8; 12], pn: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn_bytes = pn.to_be_bytes();
    for (slot, byte) in nonce[4..12].iter_mut().zip(pn_bytes) {
        *slot ^= byte;
    }
    nonce
}

fn decode_packet_number(largest_pn: Option<u64>, truncated_pn: u64, pn_len: usize) -> u64 {
    let Some(largest) = largest_pn else {
        return truncated_pn;
    };
    let expected_pn = largest.saturating_add(1);
    let pn_nbits = (pn_len as u32) * 8;
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;

    let candidate_pn = (expected_pn & !pn_mask) | truncated_pn;
    if candidate_pn.saturating_add(pn_hwin) <= expected_pn && candidate_pn < (1u64 << 62) - pn_win {
        candidate_pn + pn_win
    } else if candidate_pn > expected_pn.saturating_add(pn_hwin) && candidate_pn >= pn_win {
        candidate_pn - pn_win
    } else {
        candidate_pn
    }
}

pub(super) fn derive_initial_keys(
    version: QuicVersion,
    dcid: &[u8],
    role_label: &[u8],
) -> Option<InitialKeys> {
    let salt = Salt::new(HKDF_SHA256, version.initial_salt());
    let initial_secret = salt.extract(dcid);

    let mut role_secret = [0u8; 32];
    hkdf_expand_label(&initial_secret, role_label, &mut role_secret)?;
    let role_prk = Prk::new_less_safe(HKDF_SHA256, &role_secret);

    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    hkdf_expand_label(&role_prk, version.key_label(), &mut key)?;
    hkdf_expand_label(&role_prk, version.iv_label(), &mut iv)?;
    hkdf_expand_label(&role_prk, version.hp_label(), &mut hp)?;

    Some(InitialKeys { key, iv, hp })
}

struct ExactLen(usize);

impl KeyType for ExactLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_expand_label(prk: &Prk, label: &[u8], out: &mut [u8]) -> Option<()> {
    let out_len = u16::try_from(out.len()).ok()?.to_be_bytes();
    let full_label_len = u8::try_from(6usize.checked_add(label.len())?).ok()?;
    let info: [&[u8]; 5] = [
        &out_len,
        std::slice::from_ref(&full_label_len),
        b"tls13 ",
        label,
        &[0u8],
    ];
    let okm = prk.expand(&info, ExactLen(out.len())).ok()?;
    okm.fill(out).ok()
}

fn parse_initial_frames(plaintext: &[u8], crypto: &mut CryptoReassembler) -> bool {
    let mut reader = Reader::new(plaintext);
    while !reader.is_empty() {
        let Some(frame_type) = reader.varint() else {
            return false;
        };
        match frame_type {
            FRAME_PADDING | FRAME_PING => {}
            FRAME_CRYPTO => {
                let Some(offset) = reader.varint_len() else {
                    return false;
                };
                let Some(len) = reader.varint_len() else {
                    return false;
                };
                let Some(data) = reader.take(len) else {
                    return false;
                };
                if !crypto.insert(offset, data) {
                    return false;
                }
            }
            FRAME_ACK | FRAME_ACK_ECN => {
                if !skip_ack_frame(&mut reader, frame_type == FRAME_ACK_ECN) {
                    return false;
                }
            }
            _ => break,
        }
    }
    true
}

fn skip_ack_frame(reader: &mut Reader<'_>, has_ecn: bool) -> bool {
    if reader.varint().is_none() || reader.varint().is_none() {
        return false;
    }
    let Some(range_count) = reader.varint_len() else {
        return false;
    };
    if reader.varint().is_none() {
        return false;
    }
    // Each additional ACK range occupies at least two varint bytes.
    if range_count > reader.remaining() / 2 {
        return false;
    }
    for _ in 0..range_count {
        if reader.varint().is_none() || reader.varint().is_none() {
            return false;
        }
    }
    if has_ecn
        && (reader.varint().is_none() || reader.varint().is_none() || reader.varint().is_none())
    {
        return false;
    }
    true
}

const MAX_CRYPTO_FRAMES: usize = 64;
const MAX_CRYPTO_RANGES: usize = 32;

struct CryptoReassembler {
    buf: Vec<u8>,
    ranges: Vec<(usize, usize)>,
    frames: usize,
}

impl CryptoReassembler {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            ranges: Vec::new(),
            frames: 0,
        }
    }

    fn insert(&mut self, offset: usize, data: &[u8]) -> bool {
        if self.frames >= MAX_CRYPTO_FRAMES {
            return false;
        }
        self.frames += 1;
        if data.is_empty() {
            return true;
        }
        let Some(end) = offset.checked_add(data.len()) else {
            return false;
        };
        if end > MAX_CRYPTO_BYTES {
            return false;
        }
        if end > self.buf.len() {
            self.buf.resize(end, 0);
        }
        self.buf[offset..end].copy_from_slice(data);

        self.ranges.push((offset, end));
        self.ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.ranges.len());
        for (start, stop) in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(stop);
            } else {
                merged.push((start, stop));
            }
        }
        if merged.len() > MAX_CRYPTO_RANGES {
            return false;
        }
        self.ranges = merged;
        true
    }

    fn contiguous_prefix(&self) -> &[u8] {
        match self.ranges.first() {
            Some(&(0, end)) => &self.buf[..end],
            _ => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{
        build_client_hello_message, decode_hex, encode_crypto_frame, encode_quic_initial,
    };
    use super::*;

    const RFC9001_DCID_HEX: &str = "8394c8f03e515708";

    // RFC 9001 Appendix A.2 Client Initial CRYPTO frame (contains ClientHello with SNI example.com).
    const RFC9001_A2_CRYPTO_FRAME_HEX: &str = concat!(
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868",
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578",
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005",
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba",
        "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400",
        "0d0010000e0403050306030203080408050806002d00020101001c0002400100",
        "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000",
        "75300901100f088394c8f03e51570806048000ffff",
    );

    // First 64 bytes of the protected Client Initial packet in RFC 9001 Appendix A.2.
    const RFC9001_A2_PROTECTED_PREFIX_HEX: &str = concat!(
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
        "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399",
    );

    #[test]
    fn derives_rfc9001_appendix_a1_initial_keys() {
        let dcid = decode_hex(RFC9001_DCID_HEX);
        let client = derive_initial_keys(QuicVersion::V1, &dcid, b"client in").unwrap();
        assert_eq!(
            client.key.as_slice(),
            decode_hex("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(client.iv.as_slice(), decode_hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(
            client.hp.as_slice(),
            decode_hex("9f50449e04a0e810283a1e9933adedd2")
        );

        let server = derive_initial_keys(QuicVersion::V1, &dcid, b"server in").unwrap();
        assert_eq!(
            server.key.as_slice(),
            decode_hex("cf3a5331653c364c88f0f379b6067e37")
        );
    }

    #[test]
    fn sniffs_rfc9001_appendix_a2_client_initial_and_matches_protected_prefix() {
        let dcid = decode_hex(RFC9001_DCID_HEX);
        let crypto_frame = decode_hex(RFC9001_A2_CRYPTO_FRAME_HEX);
        let packet = encode_quic_initial(QuicVersion::V1, &dcid, &[], 2, 4, &crypto_frame, 1200);

        assert_eq!(packet.len(), 1200);
        assert_eq!(
            &packet[..64],
            decode_hex(RFC9001_A2_PROTECTED_PREFIX_HEX).as_slice()
        );

        assert_eq!(
            sniff_quic_datagram(&packet),
            Some(Sniffed {
                protocol: Protocol::Quic,
                domain: Some("example.com".to_owned()),
            })
        );
    }

    #[test]
    fn derives_rfc9369_appendix_a1_quic_v2_initial_keys_and_sniffs_v2_initial() {
        let dcid = decode_hex(RFC9001_DCID_HEX);
        let client = derive_initial_keys(QuicVersion::V2, &dcid, b"client in").unwrap();
        assert_eq!(
            client.key.as_slice(),
            decode_hex("8b1a0bc121284290a29e0971b5cd045d")
        );
        assert_eq!(client.iv.as_slice(), decode_hex("91f73e2351d8fa91660e909f"));
        assert_eq!(
            client.hp.as_slice(),
            decode_hex("45b95e15235d6f45a6b19cbcb0294ba9")
        );

        let crypto_frame = decode_hex(RFC9001_A2_CRYPTO_FRAME_HEX);
        let packet = encode_quic_initial(QuicVersion::V2, &dcid, &[], 2, 4, &crypto_frame, 1200);
        assert_eq!(
            sniff_quic_datagram(&packet),
            Some(Sniffed {
                protocol: Protocol::Quic,
                domain: Some("example.com".to_owned()),
            })
        );
    }

    #[test]
    fn reassembles_client_hello_split_out_of_order_across_two_initial_packets() {
        let dcid = decode_hex("0102030405060708");
        let ch = build_client_hello_message(Some(b"quic-split.example.com"));
        let mid = ch.len() / 2;

        let frame_second = encode_crypto_frame(mid, &ch[mid..]);
        let frame_first = encode_crypto_frame(0, &ch[..mid]);

        let pkt_second =
            encode_quic_initial(QuicVersion::V1, &dcid, b"scid", 1, 1, &frame_second, 0);
        let pkt_first = encode_quic_initial(QuicVersion::V1, &dcid, b"scid", 0, 1, &frame_first, 0);

        let mut sniffer = QuicSniffer::new();
        assert_eq!(sniffer.feed(&pkt_second), QuicProgress::NeedMore);
        assert_eq!(
            sniffer.feed(&pkt_first),
            QuicProgress::Found(Sniffed {
                protocol: Protocol::Quic,
                domain: Some("quic-split.example.com".to_owned()),
            })
        );
    }

    #[test]
    fn reassembles_overlapping_crypto_frames_with_ack_and_ping_frames() {
        let dcid = decode_hex("1122334455667788");
        let ch = build_client_hello_message(Some(b"overlap.example.com"));
        let split = ch.len() / 2;

        // Prepend PADDING, PING, and an ACK frame before the CRYPTO frame.
        let mut payload1 = vec![0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00];
        payload1.extend_from_slice(&encode_crypto_frame(0, &ch[..split + 8]));

        let payload2 = encode_crypto_frame(split, &ch[split..]);

        let pkt1 = encode_quic_initial(QuicVersion::V2, &dcid, &[], 0, 2, &payload1, 0);
        let pkt2 = encode_quic_initial(QuicVersion::V2, &dcid, &[], 1, 2, &payload2, 0);

        let mut sniffer = QuicSniffer::new();
        assert_eq!(sniffer.feed(&pkt1), QuicProgress::NeedMore);
        assert_eq!(
            sniffer.feed(&pkt2),
            QuicProgress::Found(Sniffed {
                protocol: Protocol::Quic,
                domain: Some("overlap.example.com".to_owned()),
            })
        );
    }

    #[test]
    fn processes_only_the_first_initial_in_a_coalesced_datagram() {
        let dcid = decode_hex(RFC9001_DCID_HEX);
        let ch = build_client_hello_message(Some(b"coalesced.example.com"));
        let frame = encode_crypto_frame(0, &ch);
        let mut datagram = encode_quic_initial(QuicVersion::V1, &dcid, &[], 0, 1, &frame, 0);
        // Append trailing Handshake-looking bytes belonging to a second coalesced packet.
        datagram.extend_from_slice(&[0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x10, 0xaa, 0xbb]);

        assert_eq!(
            sniff_quic_datagram(&datagram),
            Some(Sniffed {
                protocol: Protocol::Quic,
                domain: Some("coalesced.example.com".to_owned()),
            })
        );
    }

    #[test]
    fn rejects_garbage_truncated_wrong_version_and_oversized_datagrams() {
        let valid = {
            let dcid = decode_hex(RFC9001_DCID_HEX);
            let ch = build_client_hello_message(Some(b"example.com"));
            let frame = encode_crypto_frame(0, &ch);
            encode_quic_initial(QuicVersion::V1, &dcid, &[], 0, 1, &frame, 0)
        };

        let mut tampered = valid.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;

        let mut wrong_version = valid.clone();
        wrong_version[1..5].copy_from_slice(&0x0000_0002u32.to_be_bytes());

        let mut wrong_type_v1 = valid.clone();
        wrong_type_v1[0] = (wrong_type_v1[0] & !0x30) | 0x20; // Handshake, not Initial

        let mut oversized_dcid = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 21];
        oversized_dcid.resize(64, 0xaa);

        let oversized_datagram = vec![0xc0; MAX_QUIC_PACKET_BYTES + 1];

        let cases: [&[u8]; 10] = [
            b"",
            &[0x40, 0x00, 0x00, 0x00, 0x01],
            &[0x80, 0x00, 0x00, 0x00, 0x01],
            &valid[..5],
            &valid[..20],
            &valid[..valid.len() - 1],
            &tampered,
            &wrong_version,
            &wrong_type_v1,
            &oversized_dcid,
        ];
        for case in cases {
            assert_eq!(QuicSniffer::new().feed(case), QuicProgress::Failed);
            assert_eq!(sniff_quic_datagram(case), None);
        }
        assert_eq!(
            QuicSniffer::new().feed(&oversized_datagram),
            QuicProgress::Failed
        );
    }

    #[test]
    fn fails_when_packet_cap_or_dcid_mismatch_is_hit() {
        let dcid_a = decode_hex("0102030405060708");
        let dcid_b = decode_hex("8877665544332211");
        let ch = build_client_hello_message(Some(b"cap.example.com"));
        let partial = encode_crypto_frame(0, &ch[..8]);

        let pkt_a = encode_quic_initial(QuicVersion::V1, &dcid_a, &[], 0, 1, &partial, 0);
        let pkt_b = encode_quic_initial(QuicVersion::V1, &dcid_b, &[], 0, 1, &partial, 0);

        let mut sniffer = QuicSniffer::new();
        assert_eq!(sniffer.feed(&pkt_a), QuicProgress::NeedMore);
        assert_eq!(sniffer.feed(&pkt_b), QuicProgress::Failed);

        let mut cap_sniffer = QuicSniffer::new();
        for pn in 0..MAX_QUIC_PACKETS {
            let pkt = encode_quic_initial(QuicVersion::V1, &dcid_a, &[], pn as u64, 1, &partial, 0);
            let expected = if pn + 1 < MAX_QUIC_PACKETS {
                QuicProgress::NeedMore
            } else {
                QuicProgress::Failed
            };
            assert_eq!(cap_sniffer.feed(&pkt), expected, "pn={pn}");
        }
    }

    #[test]
    fn sniffer_debug_never_exposes_buffered_domain() {
        let dcid = decode_hex(RFC9001_DCID_HEX);
        let ch = build_client_hello_message(Some(b"private.example.com"));
        let partial = encode_crypto_frame(0, &ch[..ch.len() - 4]);
        let pkt = encode_quic_initial(QuicVersion::V1, &dcid, &[], 0, 1, &partial, 0);

        let mut sniffer = QuicSniffer::new();
        assert_eq!(sniffer.feed(&pkt), QuicProgress::NeedMore);
        let rendered = format!("{sniffer:?}");
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains("example.com"));
    }

    #[test]
    fn rejects_excessive_disjoint_crypto_frames() {
        let mut reassembler = CryptoReassembler::new();
        for index in 0..MAX_CRYPTO_RANGES {
            assert!(reassembler.insert(index * 4, b"a"));
        }
        assert!(!reassembler.insert(MAX_CRYPTO_RANGES * 4, b"a"));

        let mut frame_cap = CryptoReassembler::new();
        for index in 0..MAX_CRYPTO_FRAMES {
            assert!(frame_cap.insert(index, b"x"));
        }
        assert!(!frame_cap.insert(MAX_CRYPTO_FRAMES, b"x"));
    }
}
