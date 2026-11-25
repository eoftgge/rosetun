use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

fn append_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        buf.push(u8::try_from(label.len()).unwrap());
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}

fn append_record(buf: &mut Vec<u8>, name: &[u8], rtype: u16, class: u16, ttl: u32, rdata: &[u8]) {
    buf.extend_from_slice(name);
    buf.extend_from_slice(&rtype.to_be_bytes());
    buf.extend_from_slice(&class.to_be_bytes());
    buf.extend_from_slice(&ttl.to_be_bytes());
    buf.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    buf.extend_from_slice(rdata);
}

fn build_a_response(id: u16, qname: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    append_name(&mut msg, qname);
    msg.extend_from_slice(&TYPE_A.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    append_record(&mut msg, &[0xc0, 0x0c], TYPE_A, CLASS_IN, ttl, &ip.octets());
    msg
}

#[test]
fn built_query_round_trips_through_parser_with_lowercase_name() {
    let raw = build_query(0x1234, "WWW.Example.COM.", TYPE_AAAA).unwrap();
    let parsed = parse_query(&raw).unwrap();
    assert_eq!(parsed.id, 0x1234);
    assert!(parsed.recursion_desired);
    assert_eq!(parsed.question.name, "www.example.com");
    assert_eq!(parsed.question.qtype, TYPE_AAAA);
    assert_eq!(parsed.question.qclass, CLASS_IN);
    assert_eq!(parsed.edns, None);
}

#[test]
fn invalid_names_are_rejected_when_building_a_query() {
    let long_label = "a".repeat(64);
    let long_name = format!(
        "{}.{}.{}.{}.example.com",
        "a".repeat(60),
        "b".repeat(60),
        "c".repeat(60),
        "d".repeat(60)
    );
    for bad in [
        "a..example.com",
        ".example.com",
        &long_label,
        &long_name,
        "caf\u{00e9}.example.com",
    ] {
        assert_eq!(build_query(1, bad, TYPE_A), Err(WireError::InvalidName));
    }
}

#[test]
fn multi_question_and_response_packets_are_rejected_as_queries() {
    let mut multi = build_query(7, "www.example.com", TYPE_A).unwrap();
    let question = multi[HEADER_LEN..].to_vec();
    multi[5] = 2;
    multi.extend_from_slice(&question);
    assert_eq!(parse_query(&multi), Err(WireError::QuestionCount));

    let mut zero = vec![0u8; HEADER_LEN];
    zero[0..2].copy_from_slice(&7u16.to_be_bytes());
    assert_eq!(parse_query(&zero), Err(WireError::QuestionCount));

    let resp = build_a_response(7, "www.example.com", Ipv4Addr::new(192, 0, 2, 1), 60);
    assert_eq!(parse_query(&resp), Err(WireError::NotAQuery));

    let mut opcode = build_query(7, "www.example.com", TYPE_A).unwrap();
    opcode[2] |= 0x20;
    assert_eq!(parse_query(&opcode), Err(WireError::UnsupportedOpcode));
}

#[test]
fn edns_payload_size_and_dnssec_bit_are_parsed_and_clamped_for_udp() {
    let mut query = build_query(9, "www.example.com", TYPE_A).unwrap();
    assert_eq!(udp_limit(&query), 512);

    query[11] = 1;
    append_record(&mut query, &[0], TYPE_OPT, 4096, DNSSEC_OK, &[]);
    let parsed = parse_query(&query).unwrap();
    assert_eq!(
        parsed.edns,
        Some(Edns {
            payload: 4096,
            dnssec_ok: true,
        })
    );
    assert_eq!(udp_limit(&query), 1232);

    let mut small = build_query(9, "www.example.com", TYPE_A).unwrap();
    small[11] = 1;
    append_record(&mut small, &[0], TYPE_OPT, 256, 0, &[]);
    assert_eq!(udp_limit(&small), 512);
}

#[test]
fn cname_chain_addresses_are_extracted_and_unrelated_owners_ignored() {
    let mut msg = Vec::new();
    msg.extend_from_slice(&0x0042u16.to_be_bytes());
    msg.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 4, 0, 0, 0, 0]);
    append_name(&mut msg, "www.example.com");
    msg.extend_from_slice(&TYPE_A.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());

    let mut cname_target = Vec::new();
    append_name(&mut cname_target, "edge.example.com");
    append_record(
        &mut msg,
        &[0xc0, 0x0c],
        TYPE_CNAME,
        CLASS_IN,
        120,
        &cname_target,
    );

    let mut edge_wire = Vec::new();
    append_name(&mut edge_wire, "edge.example.com");
    append_record(&mut msg, &edge_wire, TYPE_A, CLASS_IN, 45, &[192, 0, 2, 10]);

    let ipv6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 10);
    append_record(
        &mut msg,
        &edge_wire,
        TYPE_AAAA,
        CLASS_IN,
        90,
        &ipv6.octets(),
    );

    let mut unrelated = Vec::new();
    append_name(&mut unrelated, "other.example.com");
    append_record(
        &mut msg,
        &unrelated,
        TYPE_A,
        CLASS_IN,
        60,
        &[198, 51, 100, 9],
    );

    let answer = parse_response(&msg, "www.example.com").unwrap();
    assert_eq!(answer.rcode, RCODE_NOERROR);
    assert_eq!(answer.answer_count, 4);
    assert_eq!(answer.answer_ttl, Some(45));
    assert_eq!(
        answer.addresses,
        vec![
            (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 45),
            (IpAddr::V6(ipv6), 90),
        ]
    );
}

#[test]
fn soa_minimum_and_ttl_determine_negative_cache_lifetime() {
    let mut msg = Vec::new();
    msg.extend_from_slice(&0x0001u16.to_be_bytes());
    msg.extend_from_slice(&[0x81, 0x83, 0, 1, 0, 0, 0, 1, 0, 0]);
    append_name(&mut msg, "missing.example.com");
    msg.extend_from_slice(&TYPE_A.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());

    let mut rdata = Vec::new();
    append_name(&mut rdata, "ns1.example.com");
    append_name(&mut rdata, "hostmaster.example.com");
    for field in [1u32, 3600, 600, 86400, 20] {
        rdata.extend_from_slice(&field.to_be_bytes());
    }
    let mut zone = Vec::new();
    append_name(&mut zone, "example.com");
    append_record(&mut msg, &zone, TYPE_SOA, CLASS_IN, 300, &rdata);

    let answer = parse_response(&msg, "missing.example.com").unwrap();
    assert_eq!(answer.rcode, RCODE_NXDOMAIN);
    assert_eq!(answer.negative_ttl, Some(20));
}

#[test]
fn rewriting_ttls_updates_records_without_touching_opt() {
    let mut msg = build_a_response(1, "www.example.com", Ipv4Addr::new(192, 0, 2, 7), 100);
    msg[11] = 1;
    append_record(&mut msg, &[0], TYPE_OPT, 1232, DNSSEC_OK, &[]);

    rewrite_ttls(&mut msg, |ttl| ttl.saturating_sub(25)).unwrap();

    let answer = parse_response(&msg, "www.example.com").unwrap();
    assert_eq!(answer.answer_ttl, Some(75));

    let parsed_layout = layout(&msg).unwrap();
    let opt = parsed_layout
        .records
        .iter()
        .find(|record| record.rtype == TYPE_OPT)
        .unwrap();
    assert_eq!(opt.ttl, DNSSEC_OK);
}

#[test]
fn truncated_and_looping_pointer_messages_fail_without_panicking() {
    // Self-looping pointer in answer owner name.
    let mut self_loop = Vec::new();
    self_loop.extend_from_slice(&[0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    append_name(&mut self_loop, "www.example.com");
    self_loop.extend_from_slice(&[0, 1, 0, 1]);
    let owner_pos = self_loop.len();
    let ptr = (0xc000u16 | u16::try_from(owner_pos).unwrap()).to_be_bytes();
    append_record(&mut self_loop, &ptr, TYPE_A, CLASS_IN, 60, &[192, 0, 2, 1]);

    // Mutual two-step pointer loop in CNAME target.
    let mut mutual_loop = Vec::new();
    mutual_loop.extend_from_slice(&[0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    append_name(&mut mutual_loop, "a.example.com");
    mutual_loop.extend_from_slice(&[0, 1, 0, 1]);
    // Pointer to header offset 12 (valid), followed by a forward pointer inside CNAME rdata.
    let forward_rdata = [0xc0, 0xff];
    append_record(
        &mut mutual_loop,
        &[0xc0, 0x0c],
        TYPE_CNAME,
        CLASS_IN,
        60,
        &forward_rdata,
    );

    // Query containing a pointer (disallowed in plain question).
    let mut query_ptr = vec![0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query_ptr.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);

    let cases: &[&[u8]] = &[
        b"",
        b"\x00\x01",
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",
        b"\x00\x01\x01\x00\xff\xff\x00\x00\x00\x00\x00\x00",
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x3fshort",
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x80\x00\x00\x01\x00\x01",
        b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00\x01\xc0",
        &query_ptr,
    ];

    for raw in cases {
        let _ = parse_query(raw);
        let _ = parse_response(raw, "www.example.com");
        let _ = error_response(raw, RCODE_FORMERR);
        let _ = truncated_response(raw);
    }

    // Both looping/forward pointer responses must not panic and must yield no bogus addresses.
    let self_ans = parse_response(&self_loop, "www.example.com").unwrap();
    assert!(self_ans.addresses.is_empty());

    let forward_ans = parse_response(&mutual_loop, "a.example.com").unwrap();
    assert!(forward_ans.addresses.is_empty());

    assert_eq!(parse_query(&query_ptr), Err(WireError::BadPointer));
}

#[test]
fn local_answer_and_truncated_response_preserve_question_and_flags() {
    let query = build_query(0xabcd, "doh.example.com", TYPE_A).unwrap();
    let parsed = parse_query(&query).unwrap();
    let reply = local_answer(
        &query,
        &parsed,
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))),
        30,
    );
    let answer = parse_response(&reply, "doh.example.com").unwrap();
    assert_eq!(message_id(&reply), Some(0xabcd));
    assert_eq!(
        answer.addresses,
        vec![(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 30)]
    );

    let truncated = truncated_response(&reply);
    let trunc_answer = parse_response(&truncated, "doh.example.com").unwrap();
    assert!(trunc_answer.truncated);
    assert_eq!(trunc_answer.answer_count, 0);
    assert_eq!(message_id(&truncated), Some(0xabcd));
}

#[test]
fn debug_output_hides_query_names_and_answer_addresses() {
    let query = build_query(1, "secret.example.com", TYPE_A).unwrap();
    let parsed = parse_query(&query).unwrap();
    let q_debug = format!("{:?}", parsed.question);
    assert!(!q_debug.contains("secret"));
    assert!(!q_debug.contains("example"));

    let resp = build_a_response(1, "secret.example.com", Ipv4Addr::new(192, 0, 2, 99), 60);
    let answer = parse_response(&resp, "secret.example.com").unwrap();
    let a_debug = format!("{answer:?}");
    assert!(!a_debug.contains("192.0.2.99"));
}
