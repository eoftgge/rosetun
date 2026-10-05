use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const NODE: &str = "trojan://secret@node.example.com:443#Example";
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rosetun-cli-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("could not create test directory: {error}"),
            }
        }
    }

    fn config_path(&self) -> PathBuf {
        self.0.join("config.json")
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_rosetun"))
            .args(arguments)
            .env("ROSETUN_CONFIG", self.config_path())
            .env("ROSETUN_LOG", "trace")
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("ALL_PROXY")
            .env_remove("http_proxy")
            .env_remove("https_proxy")
            .env_remove("all_proxy")
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .output()
            .expect("could not run the CLI")
    }

    fn read_config(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.config_path()).unwrap()).unwrap()
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Server {
    url: String,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    fn start(status: u16, headers: &[u8], body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let headers = headers.to_vec();

        let thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "CLI did not contact the server");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("test server accept failed: {error}"),
                }
            };

            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&buffer[..count]);
                assert!(request.len() <= 64 * 1024);
            }

            let mut response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            )
                .into_bytes();
            response.extend_from_slice(&headers);
            response.extend_from_slice(b"\r\n");

            if stream.write_all(&response).is_ok() {
                let _ = stream.write_all(&body);
            }
        });

        Self {
            url: format!("http://{address}/private-token?key=query-secret"),
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

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_safe(output: &Output) {
    let text = text(output);
    for secret in ["private-token", "query-secret", "trojan://secret@"] {
        assert!(!text.contains(secret), "CLI output exposed {secret}");
    }
}

fn assert_success(output: &Output) {
    assert_safe(output);
    assert!(output.status.success(), "{}", text(output));
}

fn base64(input: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    for chunk in input.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[usize::from(a >> 2)]);
        output.push(ALPHABET[usize::from(((a & 3) << 4) | (b >> 4))]);
        output.push(if chunk.len() > 1 {
            ALPHABET[usize::from(((b & 15) << 2) | (c >> 6))]
        } else {
            b'='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[usize::from(c & 63)]
        } else {
            b'='
        });
    }
    output
}

fn gzip_stored(input: &[u8]) -> Vec<u8> {
    assert!(!input.is_empty());
    let mut output = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    let mut chunks = input.chunks(usize::from(u16::MAX)).peekable();
    while let Some(chunk) = chunks.next() {
        output.push(u8::from(chunks.peek().is_none()));
        let length = u16::try_from(chunk.len()).unwrap();
        output.extend_from_slice(&length.to_le_bytes());
        output.extend_from_slice(&(!length).to_le_bytes());
        output.extend_from_slice(chunk);
    }

    let mut crc = u32::MAX;
    for byte in input {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    output.extend_from_slice(&(!crc).to_le_bytes());
    output.extend_from_slice(&u32::try_from(input.len()).unwrap().to_le_bytes());
    output
}

fn subscription_body(length: usize) -> Vec<u8> {
    let mut body = format!("{NODE}\n#").into_bytes();
    assert!(length >= body.len());
    body.resize(length, b' ');
    body
}

#[test]
fn base64_add_select_and_remove_preserve_independent_rules() {
    let directory = TestDirectory::new();
    let server = Server::start(
        200,
        b"Profile-Title: Provider name\r\n",
        base64(NODE.as_bytes()),
    );

    assert_success(&directory.run(&[
        "sub", "add", &server.url, "--name", "Chosen name", "--no-hwid",
    ]));

    let mut config = directory.read_config();
    assert_eq!(config["subscriptions"][0]["name"], "Chosen name");
    assert_eq!(config["subscriptions"][0]["send_hwid"], false);
    let node_id = config["subscriptions"][0]["nodes"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    config["rule_sets"] = serde_json::json!([{
        "id": "independent",
        "name": "Independent",
        "default_target": "proxy",
        "rules": []
    }]);
    fs::write(
        directory.config_path(),
        serde_json::to_vec(&config).unwrap(),
    ).unwrap();

    assert_success(&directory.run(&["select", "1", &node_id]));
    assert_success(&directory.run(&["nodes", "1"]));
    assert_success(&directory.run(&["sub", "list"]));
    assert_success(&directory.run(&["sub", "remove", "1"]));

    let saved = directory.read_config();
    assert_eq!(saved["subscriptions"], serde_json::json!([]));
    assert!(saved.get("active").is_none_or(serde_json::Value::is_null));
    assert_eq!(saved["rule_sets"], config["rule_sets"]);
}

#[test]
fn rejected_add_preserves_existing_configuration_bytes() {
    let directory = TestDirectory::new();
    let original = b"{}\n";
    fs::write(directory.config_path(), original).unwrap();

    for (status, headers, body) in [
        (403, &b""[..], Vec::new()),
        (
            200,
            &b"x-hwid-max-devices-reached: true\r\n"[..],
            NODE.as_bytes().to_vec(),
        ),
        (200, &b""[..], b"<!doctype html><html>Denied</html>".to_vec()),
    ] {
        let server = Server::start(status, headers, body);
        let output = directory.run(&["sub", "add", &server.url, "--no-hwid"]);
        assert_eq!(output.status.code(), Some(1));
        assert_safe(&output);
        assert_eq!(fs::read(directory.config_path()).unwrap(), original);
        assert!(!directory.0.join("config.json.tmp").exists());
    }
}

#[test]
fn partial_update_returns_failure_but_persists_successful_subscription() {
    let directory = TestDirectory::new();
    let denied = Server::start(403, b"", Vec::new());
    let successful = Server::start(
        200,
        b"",
        b"trojan://new-secret@new.example.com:443#New".to_vec(),
    );

    let subscriptions: Vec<_> = [&denied.url, &successful.url]
        .iter()
        .enumerate()
        .map(|(index, url)| {
            serde_json::json!({
                "id": (index + 1).to_string(),
                "name": "Existing",
                "url": url,
                "send_hwid": false,
                "updated_at_unix": 1,
                "nodes": []
            })
        })
        .collect();
    let initial = serde_json::json!({ "subscriptions": subscriptions });
    fs::write(
        directory.config_path(),
        serde_json::to_vec(&initial).unwrap(),
    )
        .unwrap();

    let output = directory.run(&["sub", "update"]);
    assert_eq!(output.status.code(), Some(1));
    assert_safe(&output);

    let saved = directory.read_config();
    assert_eq!(saved["subscriptions"][0]["updated_at_unix"], 1);
    assert_eq!(saved["subscriptions"][0]["nodes"], serde_json::json!([]));
    assert!(saved["subscriptions"][1]["updated_at_unix"].as_u64().unwrap() > 1);
    assert_eq!(
        saved["subscriptions"][1]["nodes"][0]["server"],
        "new.example.com"
    );
}

#[test]
fn invalid_utf8_header_is_ignored_without_losing_valid_nodes() {
    let directory = TestDirectory::new();
    let server = Server::start(
        200,
        b"Profile-Title: \xff\r\n",
        NODE.as_bytes().to_vec(),
    );

    assert_success(&directory.run(&["sub", "add", &server.url, "--no-hwid"]));

    let config = directory.read_config();
    assert_eq!(config["subscriptions"][0]["name"], "127.0.0.1");
    assert_eq!(
        config["subscriptions"][0]["nodes"].as_array().unwrap().len(),
        1
    );
}

#[test]
fn gzip_limit_applies_to_decoded_body_not_wire_size() {
    let directory = TestDirectory::new();
    let body = gzip_stored(&subscription_body(MAX_BODY_BYTES));
    assert!(body.len() > MAX_BODY_BYTES);
    let server = Server::start(200, b"Content-Encoding: gzip\r\n", body);

    assert_success(&directory.run(&["sub", "add", &server.url, "--no-hwid"]));
    assert_eq!(
        directory.read_config()["subscriptions"][0]["nodes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn oversized_decoded_gzip_body_is_rejected_without_creating_config() {
    let directory = TestDirectory::new();
    let server = Server::start(
        200,
        b"Content-Encoding: gzip\r\n",
        gzip_stored(&subscription_body(MAX_BODY_BYTES + 1)),
    );

    let output = directory.run(&["sub", "add", &server.url, "--no-hwid"]);
    assert_eq!(output.status.code(), Some(1));
    assert_safe(&output);
    assert!(text(&output).contains("response too large"));
    assert!(!directory.config_path().exists());
}
