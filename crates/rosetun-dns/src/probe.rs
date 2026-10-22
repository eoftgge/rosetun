//! One question of any type and class to one server over a chosen
//! transport, for checking the network rather than looking a name up.
//! `resolve` does not use it.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::exchange::{local_address, random_id};
use crate::wire::{self, TextAnswer};

/// A larger UDP reply is dropped; a TCP reply is limited to 64 KiB by its
/// length prefix.
const MAX_UDP_REPLY: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// What the server answered to our question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub rcode: u8,
    /// TXT strings of the asked name and class, at most `wire::MAX_TEXTS`
    /// of up to 255 bytes each.
    pub texts: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskError {
    InvalidName,
    /// The reply did not fit; asking over TCP is the caller's choice.
    Truncated,
    /// Nothing that answers our question came back in time.
    NoReply,
}

/// Asks `server` one question over `transport` within `timeout`. Replies
/// with another ID or to another question are ignored.
pub fn ask(
    server: SocketAddr,
    transport: Transport,
    name: &str,
    kind: u16,
    class: u16,
    timeout: Duration,
) -> Result<Reply, AskError> {
    let deadline = Instant::now() + timeout;
    let labels = wire::labels(name.trim_end_matches('.')).ok_or(AskError::InvalidName)?;
    let question = wire::query_in_class(random_id(), &labels, kind, class);
    let answer = match transport {
        Transport::Udp => over_udp(server, &question, deadline),
        Transport::Tcp => over_tcp(server, &question, deadline),
    }
    .ok_or(AskError::NoReply)?;
    if answer.truncated {
        return Err(AskError::Truncated);
    }
    Ok(Reply {
        rcode: answer.rcode,
        texts: answer.texts,
    })
}

fn over_udp(server: SocketAddr, question: &[u8], deadline: Instant) -> Option<TextAnswer> {
    let socket = UdpSocket::bind(local_address(server)).ok()?;
    socket.connect(server).ok()?;
    socket.send(question).ok()?;
    let mut buffer = [0u8; MAX_UDP_REPLY];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        socket.set_read_timeout(Some(remaining)).ok()?;
        match socket.recv(&mut buffer) {
            Ok(length) => {
                if let Some(answer) = wire::parse_text_answer(&buffer[..length], question) {
                    return Some(answer);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return None,
        }
    }
}

/// RFC 7766: the question with a two-byte length prefix, one reply.
fn over_tcp(server: SocketAddr, question: &[u8], deadline: Instant) -> Option<TextAnswer> {
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
    wire::parse_text_answer(&reply, question)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;

    use super::*;
    use crate::wire::test_support::encode;
    use crate::wire::{CLASS_CH, CLASS_IN, RCODE_REFUSED, TYPE_TXT};

    const NAME: &str = "whoami.example";
    const WAIT: Duration = Duration::from_millis(500);

    /// What a fake server sends back for one question: zero or more
    /// packets (TCP sends only the first).
    type Respond = fn(&[u8]) -> Vec<Vec<u8>>;

    /// A reply to `question` from its header and question section, with
    /// TXT records `(owner, class, strings)`.
    fn txt_reply(question: &[u8], flags: u16, records: &[(&str, u16, &[&str])]) -> Vec<u8> {
        let mut packet = question[..2].to_vec();
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&question[12..]);
        for (owner, class, strings) in records {
            let mut data = Vec::new();
            for text in *strings {
                data.push(u8::try_from(text.len()).unwrap());
                data.extend_from_slice(text.as_bytes());
            }
            packet.extend(encode(owner));
            packet.extend_from_slice(&TYPE_TXT.to_be_bytes());
            packet.extend_from_slice(&class.to_be_bytes());
            packet.extend_from_slice(&0u32.to_be_bytes());
            packet.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            packet.extend_from_slice(&data);
        }
        packet
    }

    fn udp_server(respond: Respond) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        thread::spawn(move || {
            let mut buffer = [0u8; 512];
            while let Ok((length, peer)) = socket.recv_from(&mut buffer) {
                for packet in respond(&buffer[..length]) {
                    let _ = socket.send_to(&packet, peer);
                }
            }
        });
        address
    }

    fn tcp_server(respond: Respond) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut length = [0u8; 2];
                if stream.read_exact(&mut length).is_err() {
                    continue;
                }
                let mut packet = vec![0u8; usize::from(u16::from_be_bytes(length))];
                if stream.read_exact(&mut packet).is_err() {
                    continue;
                }
                let replies = respond(&packet);
                if let Some(reply) = replies.first() {
                    let mut message = u16::try_from(reply.len()).unwrap().to_be_bytes().to_vec();
                    message.extend_from_slice(reply);
                    let _ = stream.write_all(&message);
                }
                // Keep a silent connection open until the client gives up.
                let _ = stream.read(&mut [0u8; 1]);
            }
        });
        address
    }

    fn both(respond: Respond) -> [(SocketAddr, Transport); 2] {
        [
            (udp_server(respond), Transport::Udp),
            (tcp_server(respond), Transport::Tcp),
        ]
    }

    fn ask_ch(server: SocketAddr, transport: Transport) -> Result<Reply, AskError> {
        ask(server, transport, NAME, TYPE_TXT, CLASS_CH, WAIT)
    }

    fn whoami(question: &[u8]) -> Vec<Vec<u8>> {
        vec![txt_reply(
            question,
            0x8400,
            &[
                (NAME, CLASS_CH, &["192.0.2.1"]),
                (NAME, CLASS_IN, &["198.51.100.1"]),
                ("other.example", CLASS_CH, &["203.0.113.1"]),
            ],
        )]
    }

    #[test]
    fn a_chaos_txt_answer_comes_back_over_udp_and_tcp() {
        for (server, transport) in both(whoami) {
            assert_eq!(
                ask_ch(server, transport),
                Ok(Reply {
                    rcode: 0,
                    texts: vec!["192.0.2.1".to_owned()]
                }),
                "{transport:?}"
            );
        }
    }

    #[test]
    fn a_refusal_is_a_reply_without_texts() {
        for (server, transport) in both(|question| vec![txt_reply(question, 0x8105, &[])]) {
            assert_eq!(
                ask_ch(server, transport),
                Ok(Reply {
                    rcode: RCODE_REFUSED,
                    texts: Vec::new()
                }),
                "{transport:?}"
            );
        }
    }

    #[test]
    fn a_truncated_reply_is_reported() {
        let server = udp_server(|question| vec![txt_reply(question, 0x8600, &[])]);
        assert_eq!(
            ask_ch(server, Transport::Udp),
            Err(AskError::Truncated)
        );
    }

    #[test]
    fn a_reply_with_another_id_is_ignored() {
        fn other_id(question: &[u8]) -> Vec<Vec<u8>> {
            let mut spoofed = whoami(question).remove(0);
            spoofed[1] ^= 1;
            vec![spoofed]
        }
        for (server, transport) in both(other_id) {
            assert_eq!(
                ask_ch(server, transport),
                Err(AskError::NoReply),
                "{transport:?}"
            );
        }

        // Over UDP the real reply after a spoofed one still counts.
        let server = udp_server(|question| {
            let mut replies = other_id(question);
            replies.extend(whoami(question));
            replies
        });
        assert_eq!(
            ask_ch(server, Transport::Udp).map(|reply| reply.texts),
            Ok(vec!["192.0.2.1".to_owned()])
        );
    }

    #[test]
    fn a_reply_to_another_question_is_ignored() {
        fn other_name(question: &[u8]) -> Vec<Vec<u8>> {
            let other = wire::query_in_class(
                u16::from_be_bytes([question[0], question[1]]),
                &wire::labels("other.example").unwrap(),
                TYPE_TXT,
                CLASS_CH,
            );
            vec![txt_reply(&other, 0x8400, &[("other.example", CLASS_CH, &["x"])])]
        }
        fn other_class(question: &[u8]) -> Vec<Vec<u8>> {
            let mut in_class = question.to_vec();
            let end = in_class.len();
            in_class[end - 2..].copy_from_slice(&CLASS_IN.to_be_bytes());
            vec![txt_reply(&in_class, 0x8400, &[(NAME, CLASS_IN, &["x"])])]
        }
        for respond in [other_name as Respond, other_class] {
            for (server, transport) in both(respond) {
                assert_eq!(
                    ask_ch(server, transport),
                    Err(AskError::NoReply),
                    "{transport:?}"
                );
            }
        }
    }

    #[test]
    fn silence_ends_at_the_timeout() {
        for (server, transport) in both(|_| Vec::new()) {
            let started = Instant::now();
            assert_eq!(
                ask_ch(server, transport),
                Err(AskError::NoReply),
                "{transport:?}"
            );
            assert!(started.elapsed() < WAIT * 3, "{transport:?}");
        }
    }

    #[test]
    fn texts_are_capped_and_bad_names_are_not_sent() {
        let server = udp_server(|question| {
            let many = ["t"; 20];
            vec![txt_reply(question, 0x8400, &[(NAME, CLASS_CH, &many)])]
        });
        assert_eq!(
            ask_ch(server, Transport::Udp).map(|reply| reply.texts.len()),
            Ok(wire::MAX_TEXTS)
        );
        assert_eq!(
            ask(
                server,
                Transport::Udp,
                "bad name.example",
                TYPE_TXT,
                CLASS_CH,
                WAIT
            ),
            Err(AskError::InvalidName)
        );
    }
}
