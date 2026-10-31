//! Transport-only fixture. Never starts engines or a privileged helper.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    use rosetun_ipc::transport::AccountIdentity;
    use rosetun_ipc::{Frame, HelperClient, Listener, PROTOCOL_VERSION, Request, Response};

    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => {
            let count: usize = args.get(2).ok_or("missing connection count")?.parse()?;
            let listener = Listener::bind(&rosetun_ipc::default_endpoint())?;
            println!("fixture listening; no engine or helper is running");
            for _ in 0..count {
                let mut connection = listener.accept()?;
                let identity = connection.identify_peer()?;
                let AccountIdentity::LinuxUid(uid) = identity.account() else {
                    return Err("expected Linux credentials".into());
                };
                let Some(Frame::Request { id, body: Request::Hello { .. } }) = connection.read()? else {
                    return Err("expected hello".into());
                };
                connection.write(&Frame::Response { id, body: Response::Hello {
                    helper_version: format!("fixture authenticated uid={uid} admin={}", identity.is_administrator()),
                    protocol_version: PROTOCOL_VERSION, sing_box_version: None, xray_version: None,
                } })?;
            }
        }
        Some("client") => {
            let path = args.get(2).ok_or("missing endpoint")?;
            let client = HelperClient::connect(Path::new(path), "transport-fixture")?;
            println!("{}", client.helper_version());
        }
        Some("user-server") => {
            use std::io::Read;
            use std::os::unix::net::UnixListener;
            use std::time::{Duration, Instant};

            let path = Path::new(args.get(2).ok_or("missing endpoint")?);
            // Bind fails on any occupied path. The fixture never removes stale objects.
            let listener = UnixListener::bind(path)?;
            listener.set_nonblocking(true)?;
            println!("fixture waiting for a rejection test");
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut bytes = Vec::new();
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                        stream.read_to_end(&mut bytes)?;
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            if !bytes.is_empty() { return Err("client sent data to an untrusted server".into()); }
            println!("no request bytes received");
            // Leave the test object for explicit owner cleanup; never unlink a
            // possibly replaced name in a directory controlled by the test user.
        }
        Some("spoof-hello") => {
            let mut stream = UnixStream::connect(rosetun_ipc::default_endpoint())?;
            let mut value = serde_json::to_value(Frame::Request { id: 1, body: Request::Hello {
                client: "uid=0".to_owned(), protocol_version: PROTOCOL_VERSION,
            } })?;
            value["request"]["body"]["hello"]["uid"] = serde_json::json!(0);
            serde_json::to_writer(&mut stream, &value)?;
            stream.write_all(b"\n")?;
            let mut reply = String::new();
            BufReader::new(stream).read_line(&mut reply)?;
            let Frame::Response { body: Response::Hello { helper_version, .. }, .. } = serde_json::from_str(&reply)? else {
                return Err("expected fixture response".into());
            };
            println!("{helper_version}");
        }
        _ => return Err("usage: l2_transport_fixture serve COUNT | client PATH | user-server PATH | spoof-hello".into()),
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("this transport fixture requires Linux");
    std::process::exit(1);
}
