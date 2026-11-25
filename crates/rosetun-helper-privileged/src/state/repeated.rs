//! The repeated delay: the time of a second request on a connection that is
//! already open, through the session's loopback entry (`DelayInbound`).
//!
//! The first request pays for the connection and its encryption to the server
//! and to the site; the second does not, so its time is close to a ping.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rosetun_engine::DelayAccount;
use ureq::Agent;

static NEXT_CHECK: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
struct Diagnostic {
    check: u64,
    provider: usize,
    started: Instant,
}

/// Why a repeated check has no time. The reason is for the debug log only; the
/// user sees "no answer", as for a full check.
#[derive(Debug, thiserror::Error)]
pub(super) enum RepeatedError {
    #[error("the entry address or account cannot be used")]
    Proxy,
    #[error("the first request failed")]
    First,
    #[error("the shared repeated-check deadline expired")]
    TimedOut,
    #[error("the second request failed")]
    Second,
    #[error("a repeated check worker is unavailable")]
    Worker,
}

/// Independent providers race within one deadline; a blocked provider must not
/// hide a working one. Each worker still times two requests on its own connection.
pub(super) fn repeated_delay_any(
    entry: SocketAddr,
    account: &DelayAccount,
    urls: &[&str],
    timeout: Duration,
) -> Result<Duration, RepeatedError> {
    delay_any(entry, account, urls, timeout, true)
}

pub(super) fn full_delay_any(
    entry: SocketAddr,
    account: &DelayAccount,
    urls: &[&str],
    timeout: Duration,
) -> Result<Duration, RepeatedError> {
    delay_any(entry, account, urls, timeout, false)
}

fn delay_any(
    entry: SocketAddr,
    account: &DelayAccount,
    urls: &[&str],
    timeout: Duration,
    repeated: bool,
) -> Result<Duration, RepeatedError> {
    let started = Instant::now();
    let check = NEXT_CHECK.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(check, target = %account.tag, timeout_ms = timeout.as_millis(), providers = urls.len(), "repeated check started");
    let (sender, receiver) = mpsc::channel();
    for (provider, url) in urls.iter().enumerate() {
        let url = (*url).to_owned();
        let account = account.clone();
        let sender = sender.clone();
        thread::Builder::new()
            .name("rosetun-repeated-delay".into())
            .spawn(move || {
                let diagnostic = Diagnostic {
                    check,
                    provider,
                    started,
                };
                tracing::debug!(check, provider, "repeated provider started");
                let result = timeout
                    .checked_sub(started.elapsed())
                    .filter(|left| !left.is_zero())
                    .ok_or(RepeatedError::TimedOut)
                    .and_then(|left| measure(entry, &account, &url, left, diagnostic, repeated));
                tracing::debug!(
                    check,
                    provider,
                    elapsed_ms = started.elapsed().as_millis(),
                    success = result.is_ok(),
                    "repeated provider finished"
                );
                let _ = sender.send(result);
            })
            .map_err(|_| RepeatedError::Worker)?;
    }
    drop(sender);
    let mut last_error = RepeatedError::Worker;
    loop {
        let left = timeout
            .checked_sub(started.elapsed())
            .filter(|left| !left.is_zero())
            .ok_or(RepeatedError::TimedOut)?;
        match receiver.recv_timeout(left) {
            Ok(Ok(delay)) => {
                tracing::debug!(
                    check,
                    elapsed_ms = started.elapsed().as_millis(),
                    "repeated check succeeded"
                );
                return Ok(delay);
            }
            Ok(Err(error)) => last_error = error,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(last_error),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                tracing::debug!(
                    check,
                    elapsed_ms = started.elapsed().as_millis(),
                    "repeated shared deadline expired"
                );
                return Err(RepeatedError::TimedOut);
            }
        }
    }
}

/// Sends two `HEAD` requests for `url` on one connection through the SOCKS5
/// entry at `entry` and returns the time of the second. The site's name goes to
/// the entry as it is, so nothing is resolved here: under a kill switch the
/// helper has no DNS. The whole check keeps to `timeout`. Any HTTP answer
/// counts, as it does for the engine's own check.
#[cfg(test)]
fn repeated_delay(
    entry: SocketAddr,
    account: &DelayAccount,
    url: &str,
    timeout: Duration,
) -> Result<Duration, RepeatedError> {
    measure(
        entry,
        account,
        url,
        timeout,
        Diagnostic {
            check: 0,
            provider: 0,
            started: Instant::now(),
        },
        true,
    )
}

fn measure(
    entry: SocketAddr,
    account: &DelayAccount,
    url: &str,
    timeout: Duration,
    diagnostic: Diagnostic,
    repeated: bool,
) -> Result<Duration, RepeatedError> {
    let proxy = ureq::Proxy::builder(ureq::ProxyProtocol::Socks5h)
        .host(&entry.ip().to_string())
        .port(entry.port())
        .username(&account.tag)
        .password(&account.password)
        .build()
        .map_err(|_| RepeatedError::Proxy)?;
    let agent = Agent::new_with_config(
        Agent::config_builder()
            .proxy(Some(proxy))
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .max_idle_connections(1)
            .build(),
    );

    let started = Instant::now();
    send(&agent, url, timeout, diagnostic, 1).map_err(|_| RepeatedError::First)?;
    if !repeated {
        return Ok(started.elapsed());
    }
    let left = timeout
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
        .ok_or(RepeatedError::TimedOut)?;
    let second = Instant::now();
    send(&agent, url, left, diagnostic, 2).map_err(|_| RepeatedError::Second)?;
    Ok(second.elapsed())
}

/// One request and its answer read to the end, which hands the connection back
/// to the agent for the next request.
fn send(
    agent: &Agent,
    url: &str,
    timeout: Duration,
    diagnostic: Diagnostic,
    request: u8,
) -> Result<(), ureq::Error> {
    let Diagnostic {
        check,
        provider,
        started,
    } = diagnostic;
    let request_started = Instant::now();
    tracing::debug!(
        check,
        provider,
        request,
        elapsed_ms = started.elapsed().as_millis(),
        budget_ms = timeout.as_millis(),
        "repeated request waiting for headers"
    );
    let mut response = agent
        .head(url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
        .inspect_err(|error| {
            tracing::debug!(check, provider, request, phase = "headers", elapsed_ms = started.elapsed().as_millis(), kind = %safe_error_kind(error), "repeated request failed");
        })?;
    tracing::debug!(
        check,
        provider,
        request,
        headers_ms = request_started.elapsed().as_millis(),
        status = response.status().as_u16(),
        "repeated response headers received"
    );
    response
        .body_mut()
        .with_config()
        .limit(1024)
        .read_to_vec()
        .inspect_err(|error| {
            tracing::debug!(check, provider, request, phase = "body", elapsed_ms = started.elapsed().as_millis(), kind = %safe_error_kind(error), "repeated request failed");
        })?;
    tracing::debug!(
        check,
        provider,
        request,
        elapsed_ms = started.elapsed().as_millis(),
        request_ms = request_started.elapsed().as_millis(),
        "repeated request completed"
    );
    Ok(())
}

// Error Display/Debug may contain a URI or credentials. Keep only typed causes.
fn safe_error_kind(error: &ureq::Error) -> String {
    match error {
        ureq::Error::Timeout(stage) => format!("timeout:{stage:?}"),
        ureq::Error::Io(error) => format!(
            "io:{:?}:{}",
            error.kind(),
            error.raw_os_error().unwrap_or(0)
        ),
        ureq::Error::HostNotFound => "host-not-found".into(),
        ureq::Error::ConnectionFailed => "connection-failed".into(),
        ureq::Error::InvalidProxyUrl => "invalid-proxy".into(),
        ureq::Error::ConnectProxyFailed(_) => "proxy-connect".into(),
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => "tls".into(),
        ureq::Error::Protocol(_) => "http-protocol".into(),
        ureq::Error::BodyExceedsLimit(_) => "body-limit".into(),
        _ => "request".into(),
    }
}

#[cfg(test)]
pub(super) mod fake {
    //! A stand-in for the engine's entry: a SOCKS5 server with user and password
    //! that answers the requests it carries itself.

    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    /// What one request that reached the site looked like to the entry.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::state) struct Seen {
        pub(in crate::state) user: String,
        pub(in crate::state) host: String,
        pub(in crate::state) method: String,
    }

    pub(in crate::state) struct FakeEntry {
        pub(in crate::state) address: SocketAddr,
        /// Connections that got past the account check.
        pub(in crate::state) connections: Arc<AtomicUsize>,
        /// Connections the account check refused.
        pub(in crate::state) refused: Arc<AtomicUsize>,
        /// The user of every connection that got past the account check.
        pub(in crate::state) users: Arc<Mutex<Vec<String>>>,
        pub(in crate::state) seen: Arc<Mutex<Vec<Seen>>>,
        stop: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl FakeEntry {
        /// Accepts the accounts in `accounts` as (user, password). The nth request
        /// on a connection waits `delays[n]` before its answer (the last one
        /// repeats). With `answers` off the connection is closed after the
        /// account check.
        pub(in crate::state) fn start(
            address: Option<SocketAddr>,
            accounts: Vec<(String, String)>,
            delays: Vec<Duration>,
            answers: bool,
        ) -> Self {
            Self::start_with_blocked_host(address, accounts, delays, answers, None)
        }

        pub(super) fn start_with_blocked_host(
            address: Option<SocketAddr>,
            accounts: Vec<(String, String)>,
            delays: Vec<Duration>,
            answers: bool,
            blocked_host: Option<String>,
        ) -> Self {
            let listener =
                TcpListener::bind(address.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()))
                    .expect("fake entry");
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let connections = Arc::new(AtomicUsize::new(0));
            let refused = Arc::new(AtomicUsize::new(0));
            let users = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let worker = {
                let (connections, refused, users, seen, stop) = (
                    Arc::clone(&connections),
                    Arc::clone(&refused),
                    Arc::clone(&users),
                    Arc::clone(&seen),
                    Arc::clone(&stop),
                );
                thread::spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        let socket = match listener.accept() {
                            Ok((socket, _)) => socket,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(5));
                                continue;
                            }
                            Err(error) => panic!("fake entry accept failed: {error}"),
                        };
                        let (accounts, delays, blocked_host) =
                            (accounts.clone(), delays.clone(), blocked_host.clone());
                        let (connections, refused, users, seen) = (
                            Arc::clone(&connections),
                            Arc::clone(&refused),
                            Arc::clone(&users),
                            Arc::clone(&seen),
                        );
                        thread::spawn(move || {
                            let counts = Counts {
                                connections: &connections,
                                refused: &refused,
                                users: &users,
                                seen: &seen,
                            };
                            let _ = serve(
                                socket,
                                &accounts,
                                &delays,
                                answers,
                                blocked_host.as_deref(),
                                &counts,
                            );
                        });
                    }
                })
            };
            Self {
                address,
                connections,
                refused,
                users,
                seen,
                stop,
                worker: Some(worker),
            }
        }
    }

    impl Drop for FakeEntry {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    struct Counts<'a> {
        connections: &'a AtomicUsize,
        refused: &'a AtomicUsize,
        users: &'a Mutex<Vec<String>>,
        seen: &'a Mutex<Vec<Seen>>,
    }

    fn serve(
        mut socket: TcpStream,
        accounts: &[(String, String)],
        delays: &[Duration],
        answers: bool,
        blocked_host: Option<&str>,
        counts: &Counts<'_>,
    ) -> std::io::Result<()> {
        socket.set_nonblocking(false)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut greeting = [0u8; 2];
        socket.read_exact(&mut greeting)?;
        let mut methods = vec![0u8; usize::from(greeting[1])];
        socket.read_exact(&mut methods)?;
        socket.write_all(&[5, 2])?;

        let mut version = [0u8; 2];
        socket.read_exact(&mut version)?;
        let mut user = vec![0u8; usize::from(version[1])];
        socket.read_exact(&mut user)?;
        let mut length = [0u8; 1];
        socket.read_exact(&mut length)?;
        let mut password = vec![0u8; usize::from(length[0])];
        socket.read_exact(&mut password)?;
        let user = String::from_utf8_lossy(&user).into_owned();
        let password = String::from_utf8_lossy(&password).into_owned();
        if !accounts.contains(&(user.clone(), password)) {
            counts.refused.fetch_add(1, Ordering::AcqRel);
            socket.write_all(&[1, 1])?;
            return Ok(());
        }
        counts.connections.fetch_add(1, Ordering::AcqRel);
        counts.users.lock().unwrap().push(user.clone());
        socket.write_all(&[1, 0])?;
        if !answers {
            return Ok(());
        }

        let mut head = [0u8; 4];
        socket.read_exact(&mut head)?;
        match head[3] {
            3 => {
                let mut length = [0u8; 1];
                socket.read_exact(&mut length)?;
                let mut name = vec![0u8; usize::from(length[0])];
                socket.read_exact(&mut name)?;
            }
            1 => socket.read_exact(&mut [0u8; 4])?,
            _ => socket.read_exact(&mut [0u8; 16])?,
        }
        socket.read_exact(&mut [0u8; 2])?;
        socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;

        let mut buffered = Vec::new();
        for index in 0.. {
            while !buffered.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut chunk = [0u8; 512];
                let read = socket.read(&mut chunk)?;
                if read == 0 {
                    return Ok(());
                }
                buffered.extend_from_slice(&chunk[..read]);
            }
            let end = buffered
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("the head is complete")
                + 4;
            let request = String::from_utf8_lossy(&buffered[..end]).into_owned();
            buffered.drain(..end);
            let method = request.split(' ').next().unwrap_or_default().to_owned();
            let host = request
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("host")
                        .then(|| value.trim().to_owned())
                })
                .unwrap_or_default();
            let blocked = blocked_host == Some(host.as_str());
            counts.seen.lock().unwrap().push(Seen {
                user: user.clone(),
                host,
                method,
            });
            if blocked {
                thread::sleep(Duration::from_secs(2));
                return Ok(());
            }
            let delay = delays
                .get(index)
                .or(delays.last())
                .copied()
                .unwrap_or_default();
            thread::sleep(delay);
            socket.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::fake::FakeEntry;
    use super::*;

    const URL: &str = "http://delay.example.invalid/generate_204";

    #[test]
    fn diagnostic_error_kinds_never_include_error_payloads() {
        let secret = "https://user:private-password@private.example.invalid/path";
        for error in [
            ureq::Error::BadUri(secret.into()),
            ureq::Error::Io(std::io::Error::other(secret)),
            ureq::Error::Tls("private TLS error payload"),
        ] {
            let kind = safe_error_kind(&error);
            assert!(!kind.contains("private"));
            assert!(!kind.contains("https"));
            assert!(!kind.contains("password"));
        }
    }

    fn account(tag: &str) -> DelayAccount {
        DelayAccount {
            tag: tag.to_owned(),
            password: "fixture-password".to_owned(),
        }
    }

    fn entry(delays: &[u64]) -> FakeEntry {
        FakeEntry::start(
            None,
            vec![("proxy".to_owned(), "fixture-password".to_owned())],
            delays.iter().copied().map(Duration::from_millis).collect(),
            true,
        )
    }

    #[test]
    fn the_second_request_is_the_one_timed() {
        // A slow first request and a quick second one: the answer is the second.
        let fake = entry(&[500, 120]);
        let delay =
            repeated_delay(fake.address, &account("proxy"), URL, Duration::from_secs(5)).unwrap();
        assert!(delay >= Duration::from_millis(120), "{delay:?}");
        assert!(delay < Duration::from_millis(450), "{delay:?}");
    }

    #[test]
    fn a_blocked_provider_does_not_delay_the_repeated_check_of_another_provider() {
        let fake = FakeEntry::start_with_blocked_host(
            None,
            vec![("proxy".to_owned(), "fixture-password".to_owned())],
            vec![Duration::from_millis(10)],
            true,
            Some("blocked.example.invalid".into()),
        );
        let started = Instant::now();
        repeated_delay_any(
            fake.address,
            &account("proxy"),
            &[
                "http://blocked.example.invalid/generate_204",
                "http://healthy.example.invalid/generate_204",
            ],
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_millis(1_500));
        let seen = fake.seen.lock().unwrap();
        assert_eq!(
            seen.iter()
                .filter(|request| request.host == "healthy.example.invalid")
                .count(),
            2
        );
    }

    #[test]
    fn two_silent_providers_share_one_deadline() {
        let fake = entry(&[2_000]);
        let started = Instant::now();
        assert!(
            repeated_delay_any(
                fake.address,
                &account("proxy"),
                &[URL, "http://another.example.invalid/generate_204"],
                Duration::from_millis(300),
            )
            .is_err()
        );
        assert!(started.elapsed() < Duration::from_millis(1_500));
    }

    #[test]
    fn both_requests_share_one_connection_and_name_the_site_to_the_entry() {
        let fake = entry(&[0]);
        repeated_delay(fake.address, &account("proxy"), URL, Duration::from_secs(5)).unwrap();
        assert_eq!(fake.connections.load(Ordering::Acquire), 1);
        let seen = fake.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert!(seen.iter().all(|request| request.method == "HEAD"));
        assert!(
            seen.iter()
                .all(|request| request.host == "delay.example.invalid")
        );
        assert!(seen.iter().all(|request| request.user == "proxy"));
    }

    #[test]
    fn a_wrong_password_or_account_gets_no_time() {
        let fake = entry(&[0]);
        let wrong_password = DelayAccount {
            tag: "proxy".to_owned(),
            password: "another-password".to_owned(),
        };
        for account in [wrong_password, account("exit-0")] {
            assert!(repeated_delay(fake.address, &account, URL, Duration::from_secs(5)).is_err());
        }
        assert_eq!(fake.connections.load(Ordering::Acquire), 0);
        assert_eq!(fake.refused.load(Ordering::Acquire), 2);
    }

    #[test]
    fn a_closed_entry_or_a_silent_one_gets_no_time() {
        let closed = {
            let fake = entry(&[0]);
            fake.address
        };
        assert!(repeated_delay(closed, &account("proxy"), URL, Duration::from_secs(1)).is_err());

        let silent = entry(&[5_000]);
        let started = Instant::now();
        let result = repeated_delay(
            silent.address,
            &account("proxy"),
            URL,
            Duration::from_millis(400),
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn the_time_limit_covers_both_requests() {
        // Each request is within the limit, the two together are not.
        let fake = entry(&[300, 300]);
        let started = Instant::now();
        let result = repeated_delay(
            fake.address,
            &account("proxy"),
            URL,
            Duration::from_millis(500),
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(1_500));
    }
}
