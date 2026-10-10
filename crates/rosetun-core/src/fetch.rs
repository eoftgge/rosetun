use std::fmt;
use std::io::Read;
use std::time::Duration;

use rosetun_config::Subscription;
use rosetun_hwid::{DeviceInfo, sanitize_header_value};
use rosetun_subscription::{ParseError, Parsed};
use ureq::tls::{RootCerts, TlsConfig};
use url::Url;

pub(crate) const MAX_BODY_BYTES: u64 = 5 * 1024 * 1024;
pub(crate) const MAX_LIST_BYTES: u64 = crate::MAX_LIST_BYTES as u64;
pub(crate) const DEFAULT_USER_AGENT: &str = concat!("Rosetun/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub connect: Duration,
    pub global: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            global: Duration::from_secs(30),
        }
    }
}

#[derive(Debug)]
pub enum FetchError {
    InvalidUrl,
    InvalidUserAgent,
    InvalidDeviceId,
    RequestFailed,
    Timeout,
    HostNotFound,
    ConnectionFailed,
    TooManyRedirects,
    InsecureRedirect,
    Tls(String),
    ResponseTooLarge,
    BodyReadFailed,
    NotFound { sent_hwid: bool },
    AccessDenied,
    HttpStatus(u16),
    Parse(ParseError),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl => f.write_str("invalid subscription URL"),
            Self::InvalidUserAgent => {
                f.write_str("User-Agent must contain printable ASCII characters")
            }
            Self::InvalidDeviceId => f.write_str("device ID has an invalid format"),
            Self::RequestFailed => f.write_str("subscription request failed"),
            Self::Timeout => f.write_str("subscription server did not respond in time"),
            Self::HostNotFound => f.write_str("subscription server name could not be resolved"),
            Self::ConnectionFailed => f.write_str("could not connect to the subscription server"),
            Self::TooManyRedirects => f.write_str("too many redirects"),
            Self::InsecureRedirect => {
                f.write_str("the server redirected to an unencrypted http:// address; refused")
            }
            Self::Tls(detail) => write!(
                f,
                "TLS error: {detail}; HTTPS inspection by an antivirus or a wrong system clock can cause this"
            ),
            Self::ResponseTooLarge => f.write_str("response too large"),
            Self::BodyReadFailed => f.write_str("could not read the subscription response"),
            Self::NotFound { sent_hwid } => {
                f.write_str(
                    "subscription not found; panels with a device limit also answer 404 when no device ID is sent",
                )?;
                if !sent_hwid {
                    f.write_str("; enable HWID for this subscription and try again")?;
                }
                Ok(())
            }
            Self::AccessDenied => {
                f.write_str("access denied; the panel may only serve specific client apps")
            }
            Self::HttpStatus(status) => {
                write!(f, "subscription server returned HTTP {status}")
            }
            Self::Parse(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for FetchError {}

pub(crate) fn fetch_list_bytes(url: &str, timeouts: Timeouts) -> Result<Vec<u8>, FetchError> {
    let url = parse_url(url)?;
    let agent = agent_for(&url, timeouts);
    let mut response = agent
        .get(url.as_str())
        .header("User-Agent", DEFAULT_USER_AGENT)
        .header("Accept", "*/*")
        .call()
        .map_err(classify_request_error)?;

    let status = response.status().as_u16();
    if !(200..=299).contains(&status) {
        return Err(FetchError::HttpStatus(status));
    }

    read_bounded_body(&mut response, MAX_LIST_BYTES)
}

pub fn fetch(subscription: &Subscription, timeouts: Timeouts) -> Result<Parsed, FetchError> {
    let device = if subscription.send_hwid {
        match rosetun_hwid::device_info() {
            Ok(device) => Some(device),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "device information unavailable; sending subscription request without HWID"
                );
                None
            }
        }
    } else {
        None
    };

    fetch_with_device(subscription, timeouts, device.as_ref())
}

fn parse_url(url: &str) -> Result<Url, FetchError> {
    let url = Url::parse(url).map_err(|_| FetchError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(FetchError::InvalidUrl);
    }
    Ok(url)
}

fn agent_for(url: &Url, timeouts: Timeouts) -> ureq::Agent {
    // Platform trust includes antivirus HTTPS-inspection and corporate proxy roots;
    // a fixed webpki root set would reject certificates trusted by Windows.
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build();

    ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_connect(Some(timeouts.connect))
        .timeout_global(Some(timeouts.global))
        .max_redirects(5)
        .https_only(url.scheme() == "https")
        .http_status_as_error(false)
        .build()
        .into()
}

fn classify_request_error(error: ureq::Error) -> FetchError {
    // ureq errors can embed the request URI, so only their kind is kept;
    // rustls errors describe the certificate problem and carry no URI.
    match error {
        ureq::Error::Timeout(_) => FetchError::Timeout,
        ureq::Error::HostNotFound => FetchError::HostNotFound,
        ureq::Error::ConnectionFailed => FetchError::ConnectionFailed,
        ureq::Error::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::AddrNotAvailable
                    | std::io::ErrorKind::NetworkUnreachable
                    | std::io::ErrorKind::HostUnreachable
            ) =>
        {
            FetchError::ConnectionFailed
        }
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => FetchError::TooManyRedirects,
        ureq::Error::RequireHttpsOnly(_) => FetchError::InsecureRedirect,
        ureq::Error::Rustls(error) => FetchError::Tls(error.to_string()),
        _ => FetchError::RequestFailed,
    }
}

fn read_bounded_body(
    response: &mut ureq::http::Response<ureq::Body>,
    max_bytes: u64,
) -> Result<Vec<u8>, FetchError> {
    // as_reader() streams the decoded body. Read at most one byte beyond
    // the allowed size, without rejecting gzip by its encoded Content-Length.
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(max_bytes + 1)
        .read_to_end(&mut body)
        .map_err(|_| FetchError::BodyReadFailed)?;

    if body.len() as u64 > max_bytes {
        return Err(FetchError::ResponseTooLarge);
    }

    Ok(body)
}

fn fetch_with_device(
    subscription: &Subscription,
    timeouts: Timeouts,
    device: Option<&DeviceInfo>,
) -> Result<Parsed, FetchError> {
    let url = parse_url(&subscription.url)?;

    let user_agent = subscription
        .user_agent
        .as_deref()
        .unwrap_or(DEFAULT_USER_AGENT);

    if user_agent.is_empty() || !user_agent.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(FetchError::InvalidUserAgent);
    }

    let agent = agent_for(&url, timeouts);

    let device = device.filter(|_| subscription.send_hwid);
    let mut request = agent
        .get(url.as_str())
        .header("User-Agent", user_agent)
        .header("Accept", "*/*");

    if let Some(device) = device {
        let hwid = device.hwid.as_str();
        if !(10..=64).contains(&hwid.len())
            || !hwid
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'=' | b'-'))
        {
            return Err(FetchError::InvalidDeviceId);
        }

        request = request
            .header("x-hwid", hwid)
            .header("x-device-os", sanitize_header_value(device.os))
            .header("x-ver-os", sanitize_header_value(&device.os_version))
            .header("x-device-model", sanitize_header_value(&device.model));
    }

    let mut response = request.call().map_err(classify_request_error)?;

    let status = response.status().as_u16();
    match status {
        200..=299 => {}
        404 => {
            return Err(FetchError::NotFound {
                sent_hwid: device.is_some(),
            });
        }
        403 => return Err(FetchError::AccessDenied),
        status => return Err(FetchError::HttpStatus(status)),
    }

    let headers = response.headers().clone();

    let body = read_bounded_body(&mut response, MAX_BODY_BYTES)?;

    rosetun_subscription::parse(&body, &|name| {
        headers
            .get(name)
            .and_then(|value| std::str::from_utf8(value.as_bytes()).ok())
            .map(str::to_owned)
    })
    .map_err(FetchError::Parse)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};

    use rosetun_config::SubscriptionId;
    use rosetun_hwid::Hwid;

    use super::*;

    const NODE: &str = "trojan://secret@node.example.com:443#Example";
    const SECRET_SUFFIX: &str = "/private-token?key=query-secret";

    #[derive(Debug)]
    struct CapturedRequest {
        target: String,
        headers: BTreeMap<String, String>,
    }

    #[derive(Debug)]
    struct Reply {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        delay: Duration,
    }

    impl Reply {
        fn ok(body: impl Into<Vec<u8>>) -> Self {
            Self {
                status: 200,
                headers: Vec::new(),
                body: body.into(),
                delay: Duration::ZERO,
            }
        }

        fn status(status: u16) -> Self {
            Self {
                status,
                ..Self::ok(Vec::new())
            }
        }

        fn header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_owned(), value.to_owned()));
            self
        }
    }

    #[derive(Debug)]
    struct Server {
        url: String,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        thread: Option<JoinHandle<()>>,
    }

    impl Server {
        fn start(replies: Vec<Reply>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();

            let requests = Arc::new(Mutex::new(Vec::new()));
            let captured = Arc::clone(&requests);

            let thread = thread::spawn(move || {
                for reply in replies {
                    let deadline = std::time::Instant::now() + Duration::from_secs(3);
                    let mut stream = loop {
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                if std::time::Instant::now() >= deadline {
                                    return;
                                }
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(error) => panic!("test server accept failed: {error}"),
                        }
                    };

                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();

                    let mut bytes = Vec::new();
                    let mut buffer = [0u8; 1024];
                    while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                        let count = stream.read(&mut buffer).unwrap();
                        assert_ne!(count, 0);
                        bytes.extend_from_slice(&buffer[..count]);
                        assert!(bytes.len() <= 64 * 1024);
                    }

                    let text = std::str::from_utf8(&bytes).unwrap();
                    let mut lines = text.split("\r\n");
                    let target = lines
                        .next()
                        .unwrap()
                        .split_whitespace()
                        .nth(1)
                        .unwrap()
                        .to_owned();

                    let mut headers = BTreeMap::new();
                    for line in lines.take_while(|line| !line.is_empty()) {
                        let (name, value) = line.split_once(':').unwrap();
                        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                    }
                    captured
                        .lock()
                        .unwrap()
                        .push(CapturedRequest { target, headers });

                    thread::sleep(reply.delay);

                    let mut head = format!(
                        "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n",
                        reply.status,
                        reply.body.len()
                    );
                    for (name, value) in reply.headers {
                        head.push_str(&format!("{name}: {value}\r\n"));
                    }
                    head.push_str("\r\n");

                    if stream.write_all(head.as_bytes()).is_ok() {
                        let _ = stream.write_all(&reply.body);
                    }
                }
            });

            Self {
                url: format!("http://{address}{SECRET_SUFFIX}"),
                requests,
                thread: Some(thread),
            }
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    fn subscription(url: &str) -> Subscription {
        Subscription {
            id: SubscriptionId::new("1"),
            name: "Test".to_owned(),
            url: url.to_owned(),
            nodes: Vec::new(),
            auto_update: false,
            updated_at_unix: None,
            user_agent: None,
            send_hwid: true,
            info: None,
            update_interval_hours: None,
            support_url: None,
            web_page_url: None,
            announce: None,
            notices: Vec::new(),
        }
    }

    fn device() -> DeviceInfo {
        DeviceInfo {
            hwid: Hwid::new("0123456789abcdef0123456789abcdef"),
            os: "Windows",
            os_version: "10.0.26100".to_owned(),
            model: "Test PC".to_owned(),
        }
    }

    fn timeouts() -> Timeouts {
        Timeouts {
            connect: Duration::from_secs(1),
            global: Duration::from_secs(2),
        }
    }

    fn assert_redacted(error: &FetchError) {
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains("private-token"));
            assert!(!text.contains("query-secret"));
        }
    }

    #[derive(Default)]
    struct BitWriter {
        bytes: Vec<u8>,
        current: u8,
        bit_count: u8,
    }

    impl BitWriter {
        fn write_bits(&mut self, mut value: u32, bit_count: u8) {
            for _ in 0..bit_count {
                self.current |= ((value & 1) as u8) << self.bit_count;
                self.bit_count += 1;
                value >>= 1;

                if self.bit_count == 8 {
                    self.bytes.push(self.current);
                    self.current = 0;
                    self.bit_count = 0;
                }
            }
        }

        fn write_fixed_symbol(&mut self, symbol: u16) {
            let (code, bit_count) = match symbol {
                0..=143 => (0x30 + symbol, 8),
                144..=255 => (0x190 + symbol - 144, 9),
                256..=279 => (symbol - 256, 7),
                280..=287 => (0xc0 + symbol - 280, 8),
                _ => panic!("invalid fixed-Huffman symbol"),
            };
            self.write_bits(
                u32::from(code.reverse_bits() >> (u16::BITS - bit_count as u32)),
                bit_count,
            );
        }

        fn into_bytes(mut self) -> Vec<u8> {
            if self.bit_count != 0 {
                self.bytes.push(self.current);
            }
            self.bytes
        }
    }

    fn write_length_distance(writer: &mut BitWriter, length: usize) {
        let (symbol, extra_bits, extra) = match length {
            3..=10 => (257 + (length - 3) as u16, 0, 0),
            11..=12 => (265, 1, length - 11),
            13..=14 => (266, 1, length - 13),
            15..=16 => (267, 1, length - 15),
            17..=18 => (268, 1, length - 17),
            19..=22 => (269, 2, length - 19),
            23..=26 => (270, 2, length - 23),
            27..=30 => (271, 2, length - 27),
            31..=34 => (272, 2, length - 31),
            35..=42 => (273, 3, length - 35),
            43..=50 => (274, 3, length - 43),
            51..=58 => (275, 3, length - 51),
            59..=66 => (276, 3, length - 59),
            67..=82 => (277, 4, length - 67),
            83..=98 => (278, 4, length - 83),
            99..=114 => (279, 4, length - 99),
            115..=130 => (280, 4, length - 115),
            131..=162 => (281, 5, length - 131),
            163..=194 => (282, 5, length - 163),
            195..=226 => (283, 5, length - 195),
            227..=257 => (284, 5, length - 227),
            258 => (285, 0, 0),
            _ => panic!("invalid DEFLATE match length"),
        };

        writer.write_fixed_symbol(symbol);
        writer.write_bits(extra as u32, extra_bits);
        writer.write_bits(0, 5);
    }

    fn crc32_repeated(byte: u8, length: usize) -> u32 {
        let mut table = [0u32; 256];
        for (index, entry) in table.iter_mut().enumerate() {
            let mut value = index as u32;
            for _ in 0..8 {
                value = (value >> 1) ^ (0xedb8_8320 * (value & 1));
            }
            *entry = value;
        }

        let mut crc = !0u32;
        for _ in 0..length {
            crc = table[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
        }
        !crc
    }

    fn gzip_repeated(byte: u8, length: usize) -> Vec<u8> {
        assert!(length >= 3);

        let mut writer = BitWriter::default();
        writer.write_bits(0b011, 3);
        writer.write_fixed_symbol(u16::from(byte));

        let mut remaining = length - 1;
        while remaining != 0 {
            let match_length = remaining.min(258);
            write_length_distance(&mut writer, match_length);
            remaining -= match_length;
        }
        writer.write_fixed_symbol(256);

        let mut gzip = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        gzip.extend(writer.into_bytes());
        gzip.extend(crc32_repeated(byte, length).to_le_bytes());
        gzip.extend((length as u32).to_le_bytes());
        gzip
    }

    #[test]
    fn list_fetch_returns_bytes_and_default_headers() {
        let server = Server::start(vec![Reply::ok(b"example.com\n".to_vec())]);

        let body = fetch_list_bytes(&server.url, timeouts()).unwrap();

        assert_eq!(body, b"example.com\n");
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests[0].target, SECRET_SUFFIX);
        assert_eq!(requests[0].headers["user-agent"], DEFAULT_USER_AGENT);
        assert_eq!(requests[0].headers["accept"], "*/*");
    }

    #[test]
    fn gzip_list_over_decoded_limit_is_rejected_without_url() {
        let server = Server::start(vec![
            Reply::ok(gzip_repeated(b'a', MAX_LIST_BYTES as usize + 1))
                .header("Content-Encoding", "gzip"),
        ]);

        let error = fetch_list_bytes(&server.url, timeouts()).unwrap_err();

        assert!(matches!(error, FetchError::ResponseTooLarge));
        assert_eq!(error.to_string(), "response too large");
        assert_redacted(&error);
    }

    #[test]
    fn success_parses_nodes_metadata_and_default_headers() {
        let server = Server::start(vec![
            Reply::ok(NODE.as_bytes().to_vec())
                .header("PrOfIlE-TiTlE", "Example subscription")
                .header(
                    "Subscription-Userinfo",
                    "upload=10; download=20; total=100; expire=200",
                )
                .header("Profile-Update-Interval", "12"),
        ]);

        let parsed =
            fetch_with_device(&subscription(&server.url), timeouts(), Some(&device())).unwrap();

        assert_eq!(parsed.nodes.len(), 1);
        assert_eq!(parsed.meta.title.as_deref(), Some("Example subscription"));
        assert_eq!(parsed.meta.update_interval_hours, Some(12));
        let info = parsed.meta.info.unwrap();
        assert_eq!(info.upload, 10);
        assert_eq!(info.download, 20);
        assert_eq!(info.total, Some(100));
        assert_eq!(info.expire_unix, Some(200));

        let requests = server.requests.lock().unwrap();
        let request = &requests[0];
        assert_eq!(request.target, SECRET_SUFFIX);
        assert_eq!(request.headers["user-agent"], DEFAULT_USER_AGENT);
        assert_eq!(request.headers["accept"], "*/*");
        assert_eq!(
            request.headers["x-hwid"],
            "0123456789abcdef0123456789abcdef"
        );
        assert_eq!(request.headers["x-device-os"], "Windows");
        assert_eq!(request.headers["x-ver-os"], "10.0.26100");
        assert_eq!(request.headers["x-device-model"], "Test PC");
    }

    #[test]
    fn custom_user_agent_and_no_hwid_are_respected() {
        let server = Server::start(vec![Reply::ok(NODE.as_bytes().to_vec())]);
        let mut subscription = subscription(&server.url);
        subscription.user_agent = Some("CustomClient/1".to_owned());
        subscription.send_hwid = false;

        fetch_with_device(&subscription, timeouts(), Some(&device())).unwrap();

        let requests = server.requests.lock().unwrap();
        let headers = &requests[0].headers;
        assert_eq!(headers["user-agent"], "CustomClient/1");
        assert_eq!(headers["accept"], "*/*");
        for name in ["x-hwid", "x-device-os", "x-ver-os", "x-device-model"] {
            assert!(!headers.contains_key(name));
        }
    }

    #[test]
    fn unavailable_device_omits_all_device_headers() {
        let server = Server::start(vec![Reply::ok(NODE.as_bytes().to_vec())]);

        fetch_with_device(&subscription(&server.url), timeouts(), None).unwrap();

        let requests = server.requests.lock().unwrap();
        for name in ["x-hwid", "x-device-os", "x-ver-os", "x-device-model"] {
            assert!(!requests[0].headers.contains_key(name));
        }
    }

    #[test]
    fn device_header_values_are_sanitized() {
        let server = Server::start(vec![Reply::ok(NODE.as_bytes().to_vec())]);
        let mut device = device();
        device.os_version = "10\r\n中".to_owned();
        device.model = "é".repeat(100);

        fetch_with_device(&subscription(&server.url), timeouts(), Some(&device)).unwrap();

        let requests = server.requests.lock().unwrap();
        assert_eq!(requests[0].headers["x-ver-os"], "10???");
        assert_eq!(requests[0].headers["x-device-model"], "?".repeat(64));
    }

    #[test]
    fn not_found_and_access_denied_have_specific_messages() {
        for status in [404, 403, 500] {
            let server = Server::start(vec![Reply::status(status)]);
            let error =
                fetch_with_device(&subscription(&server.url), timeouts(), None).unwrap_err();

            let message = error.to_string();
            match status {
                404 => {
                    assert!(message.contains("subscription not found"));
                    assert!(message.contains("enable HWID"));
                }
                403 => assert!(message.contains("access denied")),
                _ => assert!(message.contains("HTTP 500")),
            }
            assert_redacted(&error);
        }
    }

    #[test]
    fn not_found_with_hwid_does_not_suggest_enabling_it() {
        let server = Server::start(vec![Reply::status(404)]);
        let error =
            fetch_with_device(&subscription(&server.url), timeouts(), Some(&device())).unwrap_err();

        assert!(!error.to_string().contains("enable HWID"));
        assert_redacted(&error);
    }

    #[test]
    fn redirect_is_followed() {
        let server = Server::start(vec![
            Reply::status(302).header("Location", "/redirected"),
            Reply::ok(NODE.as_bytes().to_vec()),
        ]);

        let parsed = fetch_with_device(&subscription(&server.url), timeouts(), None).unwrap();

        assert_eq!(parsed.nodes.len(), 1);
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].target, "/redirected");
    }

    #[test]
    fn six_redirects_are_rejected() {
        let replies = (0..6)
            .map(|index| Reply::status(302).header("Location", &format!("/redirect-{index}")))
            .collect();
        let server = Server::start(replies);

        let error = fetch_with_device(&subscription(&server.url), timeouts(), None).unwrap_err();

        assert!(matches!(error, FetchError::TooManyRedirects));
        assert_eq!(error.to_string(), "too many redirects");
        assert_redacted(&error);
    }

    #[test]
    fn oversized_response_is_rejected() {
        let server = Server::start(vec![Reply::ok(vec![b'a'; MAX_BODY_BYTES as usize + 1])]);

        let error = fetch_with_device(&subscription(&server.url), timeouts(), None).unwrap_err();

        assert!(matches!(error, FetchError::ResponseTooLarge));
        assert_eq!(error.to_string(), "response too large");
        assert_redacted(&error);
    }

    #[test]
    fn silent_server_hits_global_timeout() {
        let mut reply = Reply::ok(NODE.as_bytes().to_vec());
        reply.delay = Duration::from_millis(300);
        let server = Server::start(vec![reply]);

        let error = fetch_with_device(
            &subscription(&server.url),
            Timeouts {
                connect: Duration::from_millis(100),
                global: Duration::from_millis(50),
            },
            None,
        )
        .unwrap_err();

        assert!(matches!(error, FetchError::Timeout));
        assert_eq!(
            error.to_string(),
            "subscription server did not respond in time"
        );
        assert_redacted(&error);
    }

    #[test]
    fn closed_port_reports_connection_failure_without_url() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let url = format!("http://{address}{SECRET_SUFFIX}");
        let error = fetch_with_device(
            &subscription(&url),
            Timeouts {
                connect: Duration::from_secs(5),
                global: Duration::from_secs(10),
            },
            None,
        )
        .unwrap_err();

        assert_redacted(&error);
        assert!(
            matches!(error, FetchError::ConnectionFailed),
            "expected ConnectionFailed, got {error:?}"
        );
        assert_eq!(
            error.to_string(),
            "could not connect to the subscription server"
        );
    }

    #[test]
    fn device_limit_headers_override_node_body() {
        let server = Server::start(vec![
            Reply::ok(NODE.as_bytes().to_vec())
                .header("x-hwid-max-devices-reached", "true")
                .header("announce", "Remove an old device"),
        ]);

        let error = fetch_with_device(&subscription(&server.url), timeouts(), None).unwrap_err();

        assert!(matches!(
            &error,
            FetchError::Parse(ParseError::DeviceLimit {
                max_devices_reached: true,
                not_supported: false,
                announce: Some(message),
            }) if message == "Remove an old device"
        ));
        assert_redacted(&error);
    }

    #[test]
    fn invalid_user_agent_is_rejected_without_echoing_it() {
        let mut subscription = subscription("http://127.0.0.1:1/private-token?key=query-secret");
        subscription.user_agent = Some("private-token\r\nquery-secret".to_owned());

        let error = fetch_with_device(&subscription, timeouts(), None).unwrap_err();

        assert!(matches!(error, FetchError::InvalidUserAgent));
        assert_redacted(&error);
    }
}
