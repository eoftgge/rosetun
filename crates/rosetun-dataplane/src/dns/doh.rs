//! DNS-over-HTTPS (RFC 8484) client over hand-rolled HTTP/1.1 + `rustls`.
//!
//! Connects exclusively to the literal resolver IP via the configured
//! [`Dialer`] and verifies TLS against `settings.server_name`, so no DNS
//! lookup is ever triggered when reaching the upstream. Keeps one idle
//! keep-alive connection and retries once on a stale pooled stream.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use rosetun_config::DnsSettings;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use super::{DnsError, wire};
use crate::net::{Dialer, Target};

const DEFAULT_PORT: u16 = 443;
const DEFAULT_PATH: &str = "/dns-query";
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 1024;

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

struct PooledConnection {
    generation: u64,
    stream: TlsStream,
}

struct DialerState {
    dialer: Arc<dyn Dialer>,
    generation: u64,
}

/// Upstream DNS-over-HTTPS client backed by a [`Dialer`].
pub struct DohClient {
    server_ip: IpAddr,
    port: u16,
    server_name: ServerName<'static>,
    host_header: String,
    path: String,
    timeout: Duration,
    tls_config: Arc<ClientConfig>,
    dialer: RwLock<DialerState>,
    pool: Mutex<Option<PooledConnection>>,
}

impl fmt::Debug for DohClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DohClient")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl DohClient {
    pub(crate) fn new(
        settings: &DnsSettings,
        dialer: Arc<dyn Dialer>,
        timeout: Duration,
    ) -> Result<Self, DnsError> {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_root_store(settings, dialer, timeout, roots)
    }

    pub(crate) fn with_roots(
        settings: &DnsSettings,
        dialer: Arc<dyn Dialer>,
        timeout: Duration,
        roots: Vec<CertificateDer<'static>>,
    ) -> Result<Self, DnsError> {
        if roots.is_empty() {
            return Err(DnsError::InvalidRootCertificate);
        }
        let mut store = RootCertStore::empty();
        for cert in roots {
            store
                .add(cert)
                .map_err(|_| DnsError::InvalidRootCertificate)?;
        }
        Self::with_root_store(settings, dialer, timeout, store)
    }

    fn with_root_store(
        settings: &DnsSettings,
        dialer: Arc<dyn Dialer>,
        timeout: Duration,
        root_store: RootCertStore,
    ) -> Result<Self, DnsError> {
        let trimmed_name = settings.server_name.trim().trim_end_matches('.');
        if trimmed_name.is_empty() || contains_http_control(trimmed_name) {
            return Err(DnsError::InvalidServerName);
        }
        let server_name = ServerName::try_from(trimmed_name.to_owned())
            .map_err(|_| DnsError::InvalidServerName)?;
        let port = settings.port.unwrap_or(DEFAULT_PORT);
        let path = settings.path.as_deref().unwrap_or(DEFAULT_PATH).to_owned();
        if !path.starts_with('/') || contains_http_control(&path) {
            return Err(DnsError::InvalidPath);
        }
        let host_header = format_host_header(trimmed_name, port);

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| DnsError::TlsConfig)?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Self {
            server_ip: settings.server,
            port,
            server_name,
            host_header,
            path,
            timeout,
            tls_config: Arc::new(tls_config),
            dialer: RwLock::new(DialerState {
                dialer,
                generation: 0,
            }),
            pool: Mutex::new(None),
        })
    }

    pub(crate) fn set_dialer(&self, dialer: Arc<dyn Dialer>) {
        if let Ok(mut state) = self.dialer.write() {
            state.dialer = dialer;
            state.generation = state.generation.wrapping_add(1);
        }
        if let Ok(mut slot) = self.pool.lock() {
            *slot = None;
        }
    }

    /// Sends one wire-format DNS query over HTTPS and returns the wire-format
    /// response with the caller's original message ID restored.
    pub(crate) fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, DnsError> {
        let original_id = wire::message_id(query).ok_or(DnsError::InvalidQuery)?;
        let mut wire_query = query.to_vec();
        // RFC 8484 §4.1 recommends zeroing the DNS ID for HTTP cacheability.
        wire::set_id(&mut wire_query, 0);

        let (dialer, generation) = {
            let state = self
                .dialer
                .read()
                .map_err(|_| DnsError::Io(io::Error::other("dialer lock poisoned")))?;
            (Arc::clone(&state.dialer), state.generation)
        };

        let pooled = self.take_pooled(generation);
        let mut response = if let Some(stream) = pooled {
            match self.round_trip(stream, &wire_query, generation) {
                Ok(body) => body,
                Err(_) => {
                    let fresh = self.connect(&dialer)?;
                    self.round_trip(fresh, &wire_query, generation)?
                }
            }
        } else {
            let fresh = self.connect(&dialer)?;
            self.round_trip(fresh, &wire_query, generation)?
        };

        if response.len() < wire::HEADER_LEN {
            return Err(DnsError::BadResponse);
        }
        wire::set_id(&mut response, original_id);
        Ok(response)
    }

    fn take_pooled(&self, generation: u64) -> Option<TlsStream> {
        let mut slot = self.pool.lock().ok()?;
        let conn = slot.take()?;
        if conn.generation == generation {
            Some(conn.stream)
        } else {
            None
        }
    }

    fn put_pooled(&self, stream: TlsStream, generation: u64) {
        let current_gen = self
            .dialer
            .read()
            .map_or_else(|_| generation.wrapping_add(1), |state| state.generation);
        if current_gen != generation {
            return;
        }
        if let Ok(mut slot) = self.pool.lock()
            && slot.is_none()
        {
            *slot = Some(PooledConnection { generation, stream });
        }
    }

    fn connect(&self, dialer: &Arc<dyn Dialer>) -> Result<TlsStream, DnsError> {
        // Always dial the literal IP address so connecting never invokes DNS.
        let target = Target::ip(self.server_ip, self.port);
        let tcp = dialer
            .connect(&target, self.timeout)
            .map_err(DnsError::Dial)?;
        tcp.set_nodelay(true).ok();
        tcp.set_read_timeout(Some(self.timeout))
            .map_err(DnsError::Io)?;
        tcp.set_write_timeout(Some(self.timeout))
            .map_err(DnsError::Io)?;
        let conn = ClientConnection::new(Arc::clone(&self.tls_config), self.server_name.clone())
            .map_err(|_| DnsError::TlsConfig)?;
        Ok(StreamOwned::new(conn, tcp))
    }

    fn round_trip(
        &self,
        mut stream: TlsStream,
        wire_query: &[u8],
        generation: u64,
    ) -> Result<Vec<u8>, DnsError> {
        let deadline = Instant::now() + self.timeout;
        apply_remaining_timeout(stream.get_ref(), deadline)?;

        let mut request = Vec::with_capacity(256 + wire_query.len());
        let _ = write!(
            request,
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/dns-message\r\n\
             Accept: application/dns-message\r\n\
             Content-Length: {}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            self.path,
            self.host_header,
            wire_query.len(),
        );
        request.extend_from_slice(wire_query);

        stream.write_all(&request).map_err(DnsError::Io)?;
        stream.flush().map_err(DnsError::Io)?;

        let (body, reusable) = read_http_response(&mut stream, deadline)?;
        if reusable {
            self.put_pooled(stream, generation);
        }
        Ok(body)
    }
}

fn contains_http_control(value: &str) -> bool {
    value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
}

fn format_host_header(server_name: &str, port: u16) -> String {
    let bracketed = if server_name.contains(':') && !server_name.starts_with('[') {
        format!("[{server_name}]")
    } else {
        server_name.to_owned()
    };
    if port == DEFAULT_PORT {
        bracketed
    } else {
        format!("{bracketed}:{port}")
    }
}

fn apply_remaining_timeout(tcp: &TcpStream, deadline: Instant) -> Result<(), DnsError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            DnsError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "exchange timed out",
            ))
        })?;
    tcp.set_read_timeout(Some(remaining))
        .map_err(DnsError::Io)?;
    tcp.set_write_timeout(Some(remaining))
        .map_err(DnsError::Io)?;
    Ok(())
}

struct HttpReader<'a> {
    stream: &'a mut TlsStream,
    deadline: Instant,
    buf: Vec<u8>,
    pos: usize,
}

impl<'a> HttpReader<'a> {
    fn new(stream: &'a mut TlsStream, deadline: Instant) -> Self {
        Self {
            stream,
            deadline,
            buf: Vec::with_capacity(1024),
            pos: 0,
        }
    }

    fn buffered(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn read_more(&mut self) -> Result<usize, DnsError> {
        apply_remaining_timeout(self.stream.get_ref(), self.deadline)?;
        let mut chunk = [0u8; 2048];
        let count = self.stream.read(&mut chunk).map_err(DnsError::Io)?;
        if count > 0 {
            self.buf.extend_from_slice(&chunk[..count]);
        }
        Ok(count)
    }

    fn read_headers(&mut self) -> Result<Vec<u8>, DnsError> {
        loop {
            if let Some(end) = find_crlf_crlf(self.buffered()) {
                let header_bytes = self.buf[self.pos..self.pos + end].to_vec();
                self.pos += end + 4;
                return Ok(header_bytes);
            }
            if self.buffered().len() > MAX_HEADER_BYTES {
                return Err(DnsError::BadHttpResponse);
            }
            let count = self.read_more()?;
            if count == 0 {
                return Err(DnsError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before response headers",
                )));
            }
        }
    }

    fn read_exact_bytes(&mut self, len: usize) -> Result<Vec<u8>, DnsError> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let available = self.buffered();
            if !available.is_empty() {
                let take = available.len().min(len - out.len());
                out.extend_from_slice(&available[..take]);
                self.pos += take;
                continue;
            }
            self.buf.clear();
            self.pos = 0;
            let count = self.read_more()?;
            if count == 0 {
                return Err(DnsError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed mid-body",
                )));
            }
        }
        Ok(out)
    }

    fn read_line(&mut self, max_len: usize) -> Result<Vec<u8>, DnsError> {
        loop {
            if let Some(pos) = find_crlf(self.buffered()) {
                if pos > max_len {
                    return Err(DnsError::BadHttpResponse);
                }
                let line = self.buf[self.pos..self.pos + pos].to_vec();
                self.pos += pos + 2;
                return Ok(line);
            }
            if self.buffered().len() > max_len + 2 {
                return Err(DnsError::BadHttpResponse);
            }
            if self.pos > 0 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            let count = self.read_more()?;
            if count == 0 {
                return Err(DnsError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed in chunked body",
                )));
            }
        }
    }

    fn read_to_eof_bounded(&mut self, max_len: usize) -> Result<Vec<u8>, DnsError> {
        let mut out = Vec::new();
        if !self.buffered().is_empty() {
            if self.buffered().len() > max_len {
                return Err(DnsError::ResponseTooLarge);
            }
            out.extend_from_slice(self.buffered());
            self.buf.clear();
            self.pos = 0;
        }
        loop {
            apply_remaining_timeout(self.stream.get_ref(), self.deadline)?;
            let mut chunk = [0u8; 2048];
            let count = self.stream.read(&mut chunk).map_err(DnsError::Io)?;
            if count == 0 {
                return Ok(out);
            }
            if out.len() + count > max_len {
                return Err(DnsError::ResponseTooLarge);
            }
            out.extend_from_slice(&chunk[..count]);
        }
    }
}

fn find_crlf_crlf(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|window| window == b"\r\n")
}

fn read_http_response(
    stream: &mut TlsStream,
    deadline: Instant,
) -> Result<(Vec<u8>, bool), DnsError> {
    let mut reader = HttpReader::new(stream, deadline);
    let raw_headers = reader.read_headers()?;
    let header_text = std::str::from_utf8(&raw_headers).map_err(|_| DnsError::BadHttpResponse)?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or(DnsError::BadHttpResponse)?;

    let (http_11, status_code) = parse_status_line(status_line)?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut connection_close = false;
    let mut connection_keep_alive = false;

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(DnsError::BadHttpResponse);
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .parse::<usize>()
                .map_err(|_| DnsError::BadHttpResponse)?;
            if let Some(prev) = content_length
                && prev != parsed
            {
                return Err(DnsError::BadHttpResponse);
            }
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
            {
                chunked = true;
            }
        } else if name.eq_ignore_ascii_case("connection") {
            for token in value.split(',') {
                let token = token.trim();
                if token.eq_ignore_ascii_case("close") {
                    connection_close = true;
                } else if token.eq_ignore_ascii_case("keep-alive") {
                    connection_keep_alive = true;
                }
            }
        }
    }

    if status_code != 200 {
        return Err(DnsError::HttpStatus(status_code));
    }

    let mut reusable = if http_11 {
        !connection_close
    } else {
        connection_keep_alive && !connection_close
    };

    let body = if chunked {
        read_chunked_body(&mut reader)?
    } else if let Some(len) = content_length {
        if len > MAX_BODY_BYTES {
            return Err(DnsError::ResponseTooLarge);
        }
        reader.read_exact_bytes(len)?
    } else {
        reusable = false;
        reader.read_to_eof_bounded(MAX_BODY_BYTES)?
    };

    // Unconsumed bytes after a complete message mean the framing is out of sync.
    if !reader.buffered().is_empty() {
        reusable = false;
    }

    Ok((body, reusable))
}

fn parse_status_line(line: &str) -> Result<(bool, u16), DnsError> {
    let mut parts = line.split_ascii_whitespace();
    let version = parts.next().ok_or(DnsError::BadHttpResponse)?;
    let http_11 = match version {
        "HTTP/1.1" => true,
        "HTTP/1.0" => false,
        _ => return Err(DnsError::BadHttpResponse),
    };
    let code_str = parts.next().ok_or(DnsError::BadHttpResponse)?;
    if code_str.len() != 3 {
        return Err(DnsError::BadHttpResponse);
    }
    let code = code_str
        .parse::<u16>()
        .map_err(|_| DnsError::BadHttpResponse)?;
    Ok((http_11, code))
}

fn read_chunked_body(reader: &mut HttpReader<'_>) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::new();
    loop {
        let size_line = reader.read_line(MAX_CHUNK_LINE_BYTES)?;
        let size_str = std::str::from_utf8(&size_line).map_err(|_| DnsError::BadHttpResponse)?;
        let hex_part = size_str.split(';').next().unwrap_or("").trim();
        if hex_part.is_empty() {
            return Err(DnsError::BadHttpResponse);
        }
        let chunk_size =
            usize::from_str_radix(hex_part, 16).map_err(|_| DnsError::BadHttpResponse)?;
        if chunk_size == 0 {
            // Drain any trailer lines until the terminating empty line.
            let mut trailer_bytes = 0usize;
            loop {
                let trailer = reader.read_line(MAX_CHUNK_LINE_BYTES)?;
                if trailer.is_empty() {
                    return Ok(out);
                }
                trailer_bytes += trailer.len() + 2;
                if trailer_bytes > MAX_HEADER_BYTES {
                    return Err(DnsError::BadHttpResponse);
                }
            }
        }
        if out.len().saturating_add(chunk_size) > MAX_BODY_BYTES {
            return Err(DnsError::ResponseTooLarge);
        }
        let chunk = reader.read_exact_bytes(chunk_size)?;
        out.extend_from_slice(&chunk);
        let crlf = reader.read_exact_bytes(2)?;
        if crlf != b"\r\n" {
            return Err(DnsError::BadHttpResponse);
        }
    }
}
