//! Test-only wire builders for TLS ClientHello records and QUIC Initial packets.

use ring::aead::quic::{AES_128 as QUIC_HP_AES_128, HeaderProtectionKey};
use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

use super::quic::{QuicVersion, derive_initial_keys, make_nonce};

pub(super) fn decode_hex(hex: &str) -> Vec<u8> {
    let bytes = hex.as_bytes();
    let (pairs, remainder) = bytes.as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let s = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(s, 16).unwrap()
        })
        .collect()
}

pub(super) fn build_client_hello_message(sni: Option<&[u8]>) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(host) = sni {
        append_sni_extension(&mut extensions, host);
    }
    build_client_hello_with_extensions(&extensions, &[], &[0x13, 0x01, 0x13, 0x02])
}

pub(super) fn build_realistic_client_hello_message(sni: Option<&[u8]>) -> Vec<u8> {
    let mut extensions = Vec::new();
    // GREASE extension.
    append_extension(&mut extensions, 0x0a0a, &[]);
    // supported_groups (GREASE + x25519 + secp256r1).
    append_extension(
        &mut extensions,
        0x000a,
        &[0x00, 0x06, 0x2a, 0x2a, 0x00, 0x1d, 0x00, 0x17],
    );
    // ALPN (h2, http/1.1).
    append_extension(
        &mut extensions,
        0x0010,
        &[
            0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ],
    );
    if let Some(host) = sni {
        append_sni_extension(&mut extensions, host);
    }
    // supported_versions (TLS 1.3, TLS 1.2).
    append_extension(&mut extensions, 0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]);
    let session_id = [0x42u8; 32];
    let suites = [0x1a, 0x1a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2f];
    build_client_hello_with_extensions(&extensions, &session_id, &suites)
}

fn build_client_hello_with_extensions(
    extensions: &[u8],
    session_id: &[u8],
    cipher_suites: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
    body.extend_from_slice(&[0x55u8; 32]); // random
    body.push(u8::try_from(session_id.len()).unwrap());
    body.extend_from_slice(session_id);
    body.extend_from_slice(&u16::try_from(cipher_suites.len()).unwrap().to_be_bytes());
    body.extend_from_slice(cipher_suites);
    body.extend_from_slice(&[0x01, 0x00]); // compression_methods = [null]
    if !extensions.is_empty() {
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(extensions);
    }

    let len = body.len();
    let mut msg = Vec::with_capacity(4 + len);
    msg.push(0x01); // ClientHello
    msg.push(((len >> 16) & 0xff) as u8);
    msg.push(((len >> 8) & 0xff) as u8);
    msg.push((len & 0xff) as u8);
    msg.extend_from_slice(&body);
    msg
}

fn append_sni_extension(out: &mut Vec<u8>, host: &[u8]) {
    let host_len = u16::try_from(host.len()).unwrap();
    let list_len = host_len + 3;
    let mut data = Vec::with_capacity(usize::from(list_len) + 2);
    data.extend_from_slice(&list_len.to_be_bytes());
    data.push(0x00); // host_name
    data.extend_from_slice(&host_len.to_be_bytes());
    data.extend_from_slice(host);
    append_extension(out, 0x0000, &data);
}

fn append_extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(data);
}

pub(super) fn wrap_tls_record(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.extend_from_slice(&[0x16, 0x03, 0x01]);
    out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub(super) fn wrap_tls_records_split(payload: &[u8], split_at: usize) -> Vec<u8> {
    let mut out = wrap_tls_record(&payload[..split_at]);
    out.extend_from_slice(&wrap_tls_record(&payload[split_at..]));
    out
}

pub(crate) fn quic_v1_initial_datagram(sni: &str) -> Vec<u8> {
    let ch = build_client_hello_message(Some(sni.as_bytes()));
    let crypto = encode_crypto_frame(0, &ch);
    encode_quic_initial(
        QuicVersion::V1,
        &[1, 2, 3, 4, 5, 6, 7, 8],
        &[9, 10, 11, 12],
        0,
        2,
        &crypto,
        1200,
    )
}

pub(super) fn encode_crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x06);
    push_varint(&mut out, offset as u64);
    push_varint(&mut out, data.len() as u64);
    out.extend_from_slice(data);
    out
}

/// Builds a header-protected, AEAD-encrypted QUIC Initial packet for tests.
///
/// If `min_packet_len` is larger than the unpadded packet, PADDING frames
/// (`0x00`) are appended inside the encrypted payload so the resulting packet
/// has at least `min_packet_len` bytes (e.g., 1200 bytes for RFC 9001 A.2).
pub(super) fn encode_quic_initial(
    version: QuicVersion,
    dcid: &[u8],
    scid: &[u8],
    pn: u64,
    pn_len: usize,
    frames: &[u8],
    min_packet_len: usize,
) -> Vec<u8> {
    assert!((1..=4).contains(&pn_len));
    let keys = derive_initial_keys(version, dcid, b"client in").unwrap();

    // Build header prefix up to the Length varint.
    let first_byte = 0xc0 | (version.initial_packet_type() << 4) | ((pn_len - 1) as u8);
    let mut header_prefix = Vec::new();
    header_prefix.push(first_byte);
    header_prefix.extend_from_slice(&version.to_wire().to_be_bytes());
    header_prefix.push(u8::try_from(dcid.len()).unwrap());
    header_prefix.extend_from_slice(dcid);
    header_prefix.push(u8::try_from(scid.len()).unwrap());
    header_prefix.extend_from_slice(scid);
    header_prefix.push(0x00); // token length = 0

    // Ensure payload + pn is at least 20 bytes so the HP sample fits, plus any
    // requested minimum datagram size.
    let mut plaintext = frames.to_vec();
    let min_plain_for_hp = 20usize.saturating_sub(pn_len + 16);
    if plaintext.len() < min_plain_for_hp {
        plaintext.resize(min_plain_for_hp, 0);
    }

    // Account for varint encoding size of Length when padding to min_packet_len.
    if min_packet_len > 0 {
        let mut len_field = pn_len + plaintext.len() + 16;
        loop {
            let total = header_prefix.len() + varint_size(len_field as u64) + len_field;
            if total >= min_packet_len {
                break;
            }
            let diff = min_packet_len - total;
            plaintext.resize(plaintext.len() + diff, 0);
            len_field = pn_len + plaintext.len() + 16;
        }
    }

    let length_val = (pn_len + plaintext.len() + 16) as u64;
    let mut header = header_prefix;
    push_varint(&mut header, length_val);
    let pn_offset = header.len();

    let pn_be = pn.to_be_bytes();
    header.extend_from_slice(&pn_be[8 - pn_len..]);

    let nonce = make_nonce(&keys.iv, pn);
    let sealing_key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &keys.key).unwrap());
    let mut ciphertext = plaintext;
    sealing_key
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&header),
            &mut ciphertext,
        )
        .unwrap();

    let mut packet = header;
    packet.extend_from_slice(&ciphertext);

    let sample = &packet[pn_offset + 4..pn_offset + 20];
    let hp_key = HeaderProtectionKey::new(&QUIC_HP_AES_128, &keys.hp).unwrap();
    let mask = hp_key.new_mask(sample).unwrap();

    packet[0] ^= mask[0] & 0x0f;
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }

    packet
}

fn varint_size(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    }
}

fn push_varint(out: &mut Vec<u8>, value: u64) {
    if value < (1 << 6) {
        out.push(value as u8);
    } else if value < (1 << 14) {
        let bytes = ((value as u16) | 0x4000).to_be_bytes();
        out.extend_from_slice(&bytes);
    } else if value < (1 << 30) {
        let bytes = ((value as u32) | 0x8000_0000).to_be_bytes();
        out.extend_from_slice(&bytes);
    } else {
        let bytes = (value | 0xc000_0000_0000_0000).to_be_bytes();
        out.extend_from_slice(&bytes);
    }
}
