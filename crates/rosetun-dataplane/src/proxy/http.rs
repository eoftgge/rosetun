//! The HTTP proxy side: `CONNECT` tunnels and plain absolute-form requests.
//!
//! A plain request is forwarded as one request per connection: its head is
//! rewritten to origin form with `Connection: close`, so each request is
//! routed on its own and clients simply open a new connection for the next.

use std::io::{self, Read};
use std::net::{IpAddr, TcpStream};

use super::router::{ConnectError, Router};
use crate::net::{Host, Target, normalize_host};

const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Serves one HTTP client; its request is the next thing on `stream`.
pub(crate) fn serve(router: &Router, mut stream: TcpStream) -> io::Result<()> {
    let timeout = router.config().handshake_timeout;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let Some((head, extra)) = read_head(&mut stream)? else {
        return bad_request(&mut stream);
    };
    let Some(request) = parse_request(&head) else {
        return bad_request(&mut stream);
    };
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    match request {
        Request::Connect(target) => {
            let mut reply = |client: &mut TcpStream, outcome: Result<(), ConnectError>| {
                let bytes: &[u8] = match outcome {
                    Ok(()) => b"HTTP/1.1 200 Connection Established\r\n\r\n",
                    Err(error) => status_response(error),
                };
                Router::write_all(client, bytes)
            };
            let mut preface = extra;
            // Bytes behind the request line of a CONNECT belong to the tunnel.
            router.tcp_flow(
                stream,
                &target,
                None,
                None,
                &preface.split_off(0),
                &mut reply,
            )
        }
        Request::Forward {
            target,
            head,
            host_domain,
        } => {
            let mut preface = head;
            preface.extend_from_slice(&extra);
            let mut reply =
                |client: &mut TcpStream, outcome: Result<(), ConnectError>| match outcome {
                    Ok(()) => Ok(()),
                    Err(error) => Router::write_all(client, status_response(error)),
                };
            router.tcp_flow(
                stream,
                &target,
                None,
                host_domain.as_deref(),
                &preface,
                &mut reply,
            )
        }
    }
}

enum Request {
    Connect(Target),
    Forward {
        target: Target,
        head: Vec<u8>,
        host_domain: Option<String>,
    },
}

fn status_response(error: ConnectError) -> &'static [u8] {
    match error {
        ConnectError::Blocked => {
            b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        }
        ConnectError::Busy => {
            b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        }
        ConnectError::Unreachable(io::ErrorKind::TimedOut) => {
            b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        }
        ConnectError::Unreachable(_) => {
            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        }
    }
}

fn bad_request(stream: &mut TcpStream) -> io::Result<()> {
    Router::write_all(
        stream,
        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    )
}

/// The request head (through the blank line) and whatever followed it in
/// the same reads; `None` when the head is too long or the client left.
fn read_head(stream: &mut TcpStream) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = find_head_end(&buffer) {
            let extra = buffer.split_off(position);
            return Ok(Some((buffer, extra)));
        }
        if buffer.len() > MAX_HEAD_BYTES {
            return Ok(None);
        }
    }
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_valid_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
}

fn is_valid_request_target(path: &str) -> bool {
    !path.is_empty() && path.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn parse_request(head: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(head).ok()?;
    let trimmed = text.strip_suffix("\r\n\r\n")?;
    let mut lines = trimmed.split("\r\n");
    let line = lines.next()?;
    if line.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return None;
    }
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let uri = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some()
        || !is_http_token(method)
        || !matches!(version, "HTTP/1.1" | "HTTP/1.0")
    {
        return None;
    }

    // Validate all header lines up front so malformed/smuggled CONNECT or
    // forward requests are rejected uniformly with 400 Bad Request.
    let mut headers = Vec::new();
    for header in lines {
        if header.is_empty() || header.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return None;
        }
        let (name, value) = header.split_once(':')?;
        if !is_http_token(name) || !is_valid_header_value(value) {
            return None;
        }
        headers.push((name, header));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        return parse_authority(uri, None).map(Request::Connect);
    }
    let rest = uri
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
        .map(|_| &uri[7..])?;
    let (authority, path) = match rest.find(['/', '?']) {
        Some(index) if rest.as_bytes()[index] == b'/' => (&rest[..index], rest[index..].to_owned()),
        Some(index) => (&rest[..index], format!("/{}", &rest[index..])),
        None => (rest, "/".to_owned()),
    };
    if !is_valid_request_target(&path) {
        return None;
    }
    let target = parse_authority(authority, Some(80))?;

    let mut host_domain = None;
    let mut rewritten = format!("{method} {path} HTTP/1.1\r\n");
    for (name, header) in headers {
        if name.eq_ignore_ascii_case("host")
            && matches!(target.host, Host::Ip(_))
            && host_domain.is_none()
            && let Some((_, raw_val)) = header.split_once(':')
            && let Some(parsed) = parse_authority(raw_val.trim(), Some(80))
            && let Host::Domain(domain) = parsed.host
        {
            host_domain = Some(domain);
        }
        if [
            "proxy-connection",
            "proxy-authorization",
            "connection",
            "keep-alive",
        ]
        .iter()
        .any(|dropped| name.eq_ignore_ascii_case(dropped))
        {
            continue;
        }
        rewritten.push_str(header);
        rewritten.push_str("\r\n");
    }
    rewritten.push_str("Connection: close\r\n\r\n");
    Some(Request::Forward {
        target,
        head: rewritten.into_bytes(),
        host_domain,
    })
}

/// `host[:port]` or `[v6][:port]` as a destination; `default_port` stands in
/// for a missing port, and without one a missing port is an error.
fn parse_authority(text: &str, default_port: Option<u16>) -> Option<Target> {
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let (address, after) = rest.split_once(']')?;
        let ip = address.parse::<IpAddr>().ok().filter(IpAddr::is_ipv6)?;
        let port = match after.strip_prefix(':') {
            Some(port) => Some(port.parse().ok()?),
            None if after.is_empty() => None,
            None => return None,
        };
        let port = port.or(default_port).filter(|port| *port != 0)?;
        return Some(Target::ip(ip, port));
    } else {
        match text.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, Some(port.parse().ok()?)),
            Some(_) => return None,
            None => (text, None),
        }
    };
    let port = port.or(default_port).filter(|port| *port != 0)?;
    let host = normalize_host(host)?;
    Some(Target { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forward(head: &str) -> (Target, String, Option<String>) {
        match parse_request(head.as_bytes()).unwrap() {
            Request::Forward {
                target,
                head,
                host_domain,
            } => (target, String::from_utf8(head).unwrap(), host_domain),
            Request::Connect(_) => panic!("expected a plain request"),
        }
    }

    #[test]
    fn connect_requires_a_port() {
        assert!(matches!(
            parse_request(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n"),
            Some(Request::Connect(target)) if target == Target::domain("example.com", 443)
        ));
        assert!(parse_request(b"CONNECT example.com HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn authorities_cover_names_addresses_and_brackets() {
        assert_eq!(
            parse_authority("[2001:db8::1]:8443", None),
            Some(Target::ip("2001:db8::1".parse().unwrap(), 8443))
        );
        assert_eq!(
            parse_authority("192.0.2.1", Some(80)),
            Some(Target::ip("192.0.2.1".parse().unwrap(), 80))
        );
        assert_eq!(
            parse_authority("Example.COM.:81", None),
            Some(Target::domain("example.com", 81))
        );
        assert!(parse_authority("2001:db8::1", Some(80)).is_none());
        assert!(parse_authority("host:0", None).is_none());
        assert!(parse_authority(":80", None).is_none());
        assert!(parse_authority(".:443", None).is_none());
        assert!(parse_authority("...:443", None).is_none());
    }

    #[test]
    fn a_plain_request_is_rewritten_to_origin_form_without_proxy_headers() {
        let (target, head, host_domain) = forward(
            "GET http://example.com/a/b?c=d HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic x\r\nAccept: */*\r\n\r\n",
        );
        assert_eq!(target, Target::domain("example.com", 80));
        assert_eq!(host_domain, None);
        assert_eq!(
            head,
            "GET /a/b?c=d HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn a_plain_request_to_an_ip_extracts_the_host_header_domain() {
        let (target, _, host_domain) =
            forward("GET http://192.0.2.5/hello HTTP/1.1\r\nHost: Site.Example.COM.:80\r\n\r\n");
        assert_eq!(target, Target::ip("192.0.2.5".parse().unwrap(), 80));
        assert_eq!(host_domain.as_deref(), Some("site.example.com"));
    }

    #[test]
    fn a_query_without_a_path_gets_a_root_path() {
        let (_, head, _) = forward("GET http://example.com:8080?x=1 HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(head.starts_with("GET /?x=1 HTTP/1.1\r\n"));
    }

    #[test]
    fn requests_that_are_not_proxy_requests_are_refused() {
        assert!(parse_request(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n").is_none());
        assert!(parse_request(b"GET https://example.com/ HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_request(b"GET http://example.com/ HTTP/2\r\n\r\n").is_none());
        assert!(parse_request(b"\xff\xfe").is_none());
    }

    #[test]
    fn malformed_or_smuggled_http_requests_are_rejected() {
        assert!(
            parse_request(
                b"GET http://example.com/ok\nInjected: 1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
            )
            .is_none()
        );
        assert!(
            parse_request(
                b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\nEvil: 1\r\n\r\n"
            )
            .is_none()
        );
        assert!(
            parse_request(
                b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\rEvil: 1\r\n\r\n"
            )
            .is_none()
        );
        assert!(
            parse_request(b"GET http://example.com/ HTTP/1.1\r\nBad Header: 1\r\n\r\n").is_none()
        );
        assert!(
            parse_request(b"GET http://example.com/ HTTP/1.1\r\nNoColonLine\r\n\r\n").is_none()
        );
        assert!(
            parse_request(b"G\x00ET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .is_none()
        );
    }
}
