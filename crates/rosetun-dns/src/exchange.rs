//! One question to one server: A and AAAA over UDP, TCP for a truncated reply.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::wire::{self, Answer, RCODE_NXDOMAIN, TYPE_A, TYPE_AAAA};

/// What one server said about a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Addresses(Vec<IpAddr>),
    /// The CNAME chain ends at a name the server gave no address for.
    Alias(String),
    /// The name exists but has neither A nor AAAA records.
    NoData,
    NotFound,
    /// No usable answer: timeout, refusal, server failure.
    Failed,
}

pub(crate) fn random_id() -> u16 {
    RandomState::new().build_hasher().finish() as u16
}

pub(crate) fn local_address(server: SocketAddr) -> SocketAddr {
    if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    }
}

pub(crate) fn ask(server: SocketAddr, name: &str, labels: &[&[u8]], timeout: Duration) -> Outcome {
    let deadline = Instant::now() + timeout;
    let id = random_id();
    let questions = [
        wire::query(id, labels, TYPE_A),
        wire::query(id.wrapping_add(1), labels, TYPE_AAAA),
    ];
    let mut answers: [Option<Option<Answer>>; 2] = [None, None];

    // A connected socket takes replies from this server only.
    let socket = match UdpSocket::bind(local_address(server)).and_then(|socket| {
        socket.connect(server)?;
        Ok(socket)
    }) {
        Ok(socket) => socket,
        Err(_) => return Outcome::Failed,
    };
    for question in &questions {
        if socket.send(question).is_err() {
            return Outcome::Failed;
        }
    }

    let mut buffer = [0u8; 4096];
    while answers.iter().any(Option::is_none) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || socket.set_read_timeout(Some(remaining)).is_err() {
            break;
        }
        match socket.recv(&mut buffer) {
            Ok(length) => {
                for (slot, question) in answers.iter_mut().zip(&questions) {
                    if slot.is_none()
                        && let Some(answer) = wire::parse_answer(&buffer[..length], question)
                    {
                        *slot = Some(if answer.truncated {
                            over_tcp(server, question, deadline)
                        } else {
                            Some(answer)
                        });
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) => {}
            // An ICMP port unreachable shows up as a reset on Windows.
            Err(_) => break,
        }
    }

    decide(name, &answers)
}

fn decide(name: &str, answers: &[Option<Option<Answer>>; 2]) -> Outcome {
    let mut addresses = Vec::new();
    let mut alias = None;
    let mut empty = 0;
    for answer in answers.iter().flatten().flatten() {
        match answer.rcode {
            RCODE_NXDOMAIN => return Outcome::NotFound,
            0 => {
                let (found, end) = wire::follow(&answer.records, name);
                if found.is_empty() {
                    if end != name {
                        alias = Some(end);
                    }
                    empty += 1;
                }
                for address in found {
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
            }
            _ => {}
        }
    }
    if !addresses.is_empty() {
        addresses.sort_by_key(IpAddr::is_ipv6);
        Outcome::Addresses(addresses)
    } else if let Some(alias) = alias {
        Outcome::Alias(alias)
    } else if empty == answers.len() {
        Outcome::NoData
    } else {
        Outcome::Failed
    }
}

/// RFC 7766: the same question with a two-byte length prefix.
fn over_tcp(server: SocketAddr, question: &[u8], deadline: Instant) -> Option<Answer> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }
    let mut stream = TcpStream::connect_timeout(&server, remaining).ok()?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }
    stream.set_read_timeout(Some(remaining)).ok()?;
    stream.set_write_timeout(Some(remaining)).ok()?;
    let mut message = u16::try_from(question.len()).ok()?.to_be_bytes().to_vec();
    message.extend_from_slice(question);
    stream.write_all(&message).ok()?;

    let mut length = [0u8; 2];
    stream.read_exact(&mut length).ok()?;
    let mut reply = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut reply).ok()?;
    wire::parse_answer(&reply, question).filter(|answer| !answer.truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::test_support::{a, aaaa, cname, reply};

    fn answer(
        question_name: &str,
        kind: u16,
        flags: u16,
        records: &[(&str, u16, Vec<u8>)],
    ) -> Answer {
        let question = wire::query(1, &wire::labels(question_name).unwrap(), kind);
        wire::parse_answer(&reply(&question, flags, records), &question).unwrap()
    }

    #[test]
    fn both_families_are_combined_ipv4_first() {
        let v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let answers = [
            Some(Some(answer(
                "n.example.com",
                TYPE_AAAA,
                0x8180,
                &[aaaa("n.example.com", v6)],
            ))),
            Some(Some(answer(
                "n.example.com",
                TYPE_A,
                0x8180,
                &[a("n.example.com", [192, 0, 2, 1])],
            ))),
        ];
        assert_eq!(
            decide("n.example.com", &answers),
            Outcome::Addresses(vec![IpAddr::from([192, 0, 2, 1]), IpAddr::from(v6)])
        );
    }

    #[test]
    fn one_family_is_enough_but_silence_is_not_an_empty_answer() {
        let found = answer(
            "n.example.com",
            TYPE_A,
            0x8180,
            &[a("n.example.com", [192, 0, 2, 1])],
        );
        let empty = answer("n.example.com", TYPE_AAAA, 0x8180, &[]);
        assert_eq!(
            decide("n.example.com", &[Some(Some(found)), None]),
            Outcome::Addresses(vec![IpAddr::from([192, 0, 2, 1])])
        );
        assert_eq!(
            decide("n.example.com", &[Some(Some(empty.clone())), None]),
            Outcome::Failed
        );
        assert_eq!(
            decide(
                "n.example.com",
                &[Some(Some(empty.clone())), Some(Some(empty))]
            ),
            Outcome::NoData
        );
    }

    #[test]
    fn nxdomain_wins_and_an_unfinished_chain_is_an_alias() {
        let missing = answer("n.example.com", TYPE_A, 0x8183, &[]);
        assert_eq!(
            decide("n.example.com", &[Some(Some(missing)), None]),
            Outcome::NotFound
        );
        let chain = answer(
            "n.example.com",
            TYPE_A,
            0x8180,
            &[cname("n.example.com", "cdn.example.net")],
        );
        assert_eq!(
            decide("n.example.com", &[Some(Some(chain)), None]),
            Outcome::Alias("cdn.example.net".to_owned())
        );
        let refused = answer("n.example.com", TYPE_A, 0x8185, &[]);
        assert_eq!(
            decide("n.example.com", &[Some(Some(refused)), Some(None)]),
            Outcome::Failed
        );
    }
}
