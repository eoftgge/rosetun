use std::fmt;
use std::io::Read;
use std::time::Duration;

use rosetun_config::Subscription;
use rosetun_hwid::{DeviceInfo, sanitize_header_value};
use rosetun_subscription::{ParseError, Parsed};
use ureq::tls::{RootCerts, TlsConfig};
use url::Url;

const MAX_BODY_BYTES: u64 = 5 * 1024 * 1024;
const DEFAULT_USER_AGENT: &str = concat!("Rosetun/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, Copy)]
pub(crate) struct Timeouts {
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
pub(crate) enum FetchError {
    InvalidUrl,
    InvalidUserAgent,
    InvalidDeviceId,
    RequestFailed,
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
            Self::InvalidUrl => {
                f.write_str("invalid subscription URL")
            }
            Self::InvalidUserAgent => {
                f.write_str("User-Agent must contain printable ASCII characters")
            }
            Self::InvalidDeviceId => {
                f.write_str("device ID has an invalid format")
            }
            Self::RequestFailed => {
                f.write_str(
                    "subscription request failed; check connectivity, TLS certificates, redirects and timeouts",
                )
            }
            Self::ResponseTooLarge => {
                f.write_str("response too large")
            }
            Self::BodyReadFailed => {
                f.write_str("could not read the subscription response")
            }
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
                f.write_str(
                    "access denied; the panel may only serve specific client apps",
                )
            }
            Self::HttpStatus(status) => {
                write!(f, "subscription server returned HTTP {status}")
            }
            Self::Parse(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for FetchError {}

pub(crate) fn fetch(subscription: &Subscription, timeouts: Timeouts) -> Result<Parsed, FetchError> {
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

fn fetch_with_device(
    subscription: &Subscription,
    timeouts: Timeouts,
    device: Option<&DeviceInfo>,
) -> Result<Parsed, FetchError> {
    let url = Url::parse(&subscription.url).map_err(|_| FetchError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(FetchError::InvalidUrl);
    }

    let user_agent = subscription
        .user_agent
        .as_deref()
        .unwrap_or(DEFAULT_USER_AGENT);

    if user_agent.is_empty() || !user_agent.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(FetchError::InvalidUserAgent);
    }

    // Platform trust includes antivirus HTTPS-inspection and corporate proxy roots;
    // a fixed webpki root set would reject certificates trusted by Windows.
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build();

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_connect(Some(timeouts.connect))
        .timeout_global(Some(timeouts.global))
        .max_redirects(5)
        .https_only(url.scheme() == "https")
        .http_status_as_error(false)
        .build()
        .into();

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

    // Network errors can embed the request URI, so their Display, Debug and
    // source chain are deliberately not retained in our diagnostic type.
    let mut response = request.call().map_err(|_| FetchError::RequestFailed)?;

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

    // as_reader() streams the decoded body. Read at most one byte beyond
    // the allowed size, without rejecting gzip by its encoded Content-Length.
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(MAX_BODY_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| FetchError::BodyReadFailed)?;

    if body.len() as u64 > MAX_BODY_BYTES {
        return Err(FetchError::ResponseTooLarge);
    }

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

        assert!(matches!(error, FetchError::RequestFailed));
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

        assert!(matches!(error, FetchError::RequestFailed));
        assert_redacted(&error);
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
