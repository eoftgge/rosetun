//! The SOCKS5 server side: method negotiation, optional user/password
//! (RFC 1929), CONNECT and UDP ASSOCIATE.

use std::hint::black_box;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::atomic::AtomicBool;

use super::router::{ConnectError, Router};
use super::{Verdict, udp};
use crate::conntable::ConnectionTable;
use crate::net::Target;

const VERSION: u8 = 5;
const METHOD_NONE: u8 = 0x00;
const METHOD_PASSWORD: u8 = 0x02;
const METHOD_REFUSED: u8 = 0xff;
const REPLY_OK: u8 = 0x00;
const REPLY_FAILURE: u8 = 0x01;
const REPLY_NOT_ALLOWED: u8 = 0x02;
const REPLY_HOST_UNREACHABLE: u8 = 0x04;
const REPLY_REFUSED: u8 = 0x05;
const REPLY_TTL_EXPIRED: u8 = 0x06;
const REPLY_COMMAND_UNSUPPORTED: u8 = 0x07;

/// One account of an authenticated entry and the outbound it reaches.
#[derive(Clone)]
pub(crate) struct Account {
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) verdict: Verdict,
}

/// Who may use a SOCKS5 listener.
#[derive(Clone)]
pub(crate) enum Access {
    /// The user's own local proxy: no credentials, rules decide.
    Open,
    /// An internal entry: an account picks the outbound, rules are skipped,
    /// TCP only.
    Accounts(Vec<Account>),
}

/// Serves one SOCKS5 client; the greeting is the next thing on `stream`.
pub(crate) fn serve(
    router: &Router,
    mut stream: TcpStream,
    access: &Access,
    table: &ConnectionTable,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let timeout = router.config().handshake_timeout;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut head = [0u8; 2];
    stream.read_exact(&mut head)?;
    if head[0] != VERSION {
        return Ok(());
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods)?;
    let wanted = match access {
        Access::Open => METHOD_NONE,
        Access::Accounts(_) => METHOD_PASSWORD,
    };
    if !methods.contains(&wanted) {
        stream.write_all(&[VERSION, METHOD_REFUSED])?;
        return Ok(());
    }
    stream.write_all(&[VERSION, wanted])?;
    let forced = match access {
        Access::Open => None,
        Access::Accounts(accounts) => match authenticate(&mut stream, accounts)? {
            Some(verdict) => Some(verdict),
            None => return Ok(()),
        },
    };

    let mut request = [0u8; 4];
    stream.read_exact(&mut request)?;
    let command = request[1];
    let Some(target) = read_target(&mut stream, request[3])? else {
        reply_code(&mut stream, 0x08)?;
        return Ok(());
    };
    match command {
        1 => {
            stream.set_read_timeout(None)?;
            stream.set_write_timeout(None)?;
            let mut reply = |client: &mut TcpStream, outcome: Result<(), ConnectError>| {
                reply_code(client, code_for(outcome))
            };
            router.tcp_flow_in(
                table,
                stream,
                &target,
                forced.as_ref(),
                None,
                &[],
                &mut reply,
            )
        }
        3 if forced.is_none() => {
            let (Ok(local), Ok(peer)) = (stream.local_addr(), stream.peer_addr()) else {
                return Ok(());
            };
            udp::associate(router, stream, local.ip(), peer.ip(), shutdown)
        }
        _ => reply_code(&mut stream, REPLY_COMMAND_UNSUPPORTED),
    }
}

/// The RFC 1929 exchange; the account's verdict, or `None` after a refusal.
fn authenticate(stream: &mut TcpStream, accounts: &[Account]) -> io::Result<Option<Verdict>> {
    let mut version = [0u8; 2];
    stream.read_exact(&mut version)?;
    if version[0] != 1 {
        return Ok(None);
    }
    let mut username = vec![0u8; usize::from(version[1])];
    stream.read_exact(&mut username)?;
    let mut length = [0u8; 1];
    stream.read_exact(&mut length)?;
    let mut password = vec![0u8; usize::from(length[0])];
    stream.read_exact(&mut password)?;
    // Every account is compared, so the time does not tell which one exists.
    let mut found = None;
    for account in accounts {
        let user = constant_time_eq(account.username.as_bytes(), &username);
        let pass = constant_time_eq(account.password.as_bytes(), &password);
        if user && pass && found.is_none() {
            found = Some(account.verdict.clone());
        }
    }
    stream.write_all(&[1, u8::from(found.is_none())])?;
    Ok(found)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = usize::from(a.len() != b.len());
    let max_len = a.len().max(b.len());
    for index in 0..max_len {
        let left = a.get(index).copied().unwrap_or(0);
        let right = b.get(index).copied().unwrap_or(0);
        diff |= usize::from(black_box(left ^ right));
    }
    black_box(diff) == 0
}

/// The destination of a request whose ATYP is `atyp`; `None` for an address
/// type the server does not know.
fn read_target(stream: &mut TcpStream, atyp: u8) -> io::Result<Option<Target>> {
    let host = match atyp {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets)?;
            crate::net::Host::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets)?;
            crate::net::Host::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length)?;
            let mut name = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut name)?;
            let Ok(name) = String::from_utf8(name) else {
                return Ok(None);
            };
            let Some(host) = crate::net::normalize_host(&name) else {
                return Ok(None);
            };
            host
        }
        _ => return Ok(None),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    Ok(Some(Target {
        host,
        port: u16::from_be_bytes(port),
    }))
}

fn code_for(outcome: Result<(), ConnectError>) -> u8 {
    match outcome {
        Ok(()) => REPLY_OK,
        Err(ConnectError::Blocked) => REPLY_NOT_ALLOWED,
        Err(ConnectError::Busy) => REPLY_FAILURE,
        Err(ConnectError::Unreachable(kind)) => match kind {
            io::ErrorKind::ConnectionRefused => REPLY_REFUSED,
            io::ErrorKind::TimedOut => REPLY_TTL_EXPIRED,
            io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NotFound => REPLY_HOST_UNREACHABLE,
            _ => REPLY_FAILURE,
        },
    }
}

/// A reply with an all-zero bound address.
fn reply_code(stream: &mut TcpStream, code: u8) -> io::Result<()> {
    write_reply(stream, code, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
}

pub(crate) fn write_reply(stream: &mut TcpStream, code: u8, bound: SocketAddr) -> io::Result<()> {
    let mut reply = vec![VERSION, code, 0];
    crate::net::write_address(&mut reply, &Target::socket(bound))?;
    stream.write_all(&reply)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_codes_follow_the_failure_kind() {
        assert_eq!(code_for(Ok(())), REPLY_OK);
        assert_eq!(code_for(Err(ConnectError::Blocked)), REPLY_NOT_ALLOWED);
        assert_eq!(
            code_for(Err(ConnectError::Unreachable(
                io::ErrorKind::ConnectionRefused
            ))),
            REPLY_REFUSED
        );
        assert_eq!(
            code_for(Err(ConnectError::Unreachable(io::ErrorKind::TimedOut))),
            REPLY_TTL_EXPIRED
        );
        assert_eq!(
            code_for(Err(ConnectError::Unreachable(io::ErrorKind::NotFound))),
            REPLY_HOST_UNREACHABLE
        );
        assert_eq!(code_for(Err(ConnectError::Busy)), REPLY_FAILURE);
    }
}
