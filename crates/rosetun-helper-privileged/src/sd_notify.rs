//! systemd service notifications (`sd_notify`) without libsystemd: one
//! datagram to the socket named by `NOTIFY_SOCKET`.

use std::ffi::OsStr;
use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

pub(crate) const READY: &str = "READY=1";
pub(crate) const STOPPING: &str = "STOPPING=1";

#[derive(Debug)]
pub(crate) struct Notifier {
    socket: UnixDatagram,
    address: SocketAddr,
}

impl Notifier {
    /// `None` outside systemd (no `NOTIFY_SOCKET`): nothing is sent then.
    pub(crate) fn from_env() -> Option<io::Result<Self>> {
        std::env::var_os("NOTIFY_SOCKET").map(|address| Self::new(&address))
    }

    /// A filesystem path, or an abstract name written with a leading `@`.
    fn new(address: &OsStr) -> io::Result<Self> {
        let bytes = address.as_bytes();
        let address = match bytes.first() {
            Some(b'@') => SocketAddr::from_abstract_name(&bytes[1..])?,
            Some(b'/') => SocketAddr::from_pathname(address)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported NOTIFY_SOCKET address",
                ));
            }
        };
        Ok(Self {
            socket: UnixDatagram::unbound()?,
            address,
        })
    }

    pub(crate) fn notify(&self, state: &str) -> io::Result<()> {
        let sent = self.socket.send_to_addr(state.as_bytes(), &self.address)?;
        if sent != state.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short systemd notification",
            ));
        }
        Ok(())
    }
}

/// Sends `state` if the notifier exists, and logs a failure: the service
/// keeps running either way, and systemd reports a missed `READY=1` itself.
pub(crate) fn send(notifier: Option<&Notifier>, state: &str) {
    if let Some(notifier) = notifier
        && let Err(error) = notifier.notify(state)
    {
        tracing::error!(%error, state, "cannot notify systemd");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn unique() -> String {
        format!(
            "rosetun-notify-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn received(socket: &UnixDatagram) -> String {
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buffer = [0u8; 64];
        let length = socket.recv(&mut buffer).unwrap();
        String::from_utf8(buffer[..length].to_vec()).unwrap()
    }

    #[test]
    fn ready_and_stopping_reach_a_path_socket() {
        let directory = std::env::temp_dir().join(unique());
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("notify");
        let systemd = UnixDatagram::bind(&path).unwrap();
        let notifier = Notifier::new(path.as_os_str()).unwrap();
        send(Some(&notifier), READY);
        assert_eq!(received(&systemd), "READY=1");
        send(Some(&notifier), STOPPING);
        assert_eq!(received(&systemd), "STOPPING=1");
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn an_abstract_address_starts_with_at() {
        let name = unique();
        let systemd =
            UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes()).unwrap())
                .unwrap();
        let notifier = Notifier::new(OsStr::new(&format!("@{name}"))).unwrap();
        notifier.notify(READY).unwrap();
        assert_eq!(received(&systemd), "READY=1");
    }

    #[test]
    fn relative_and_empty_addresses_are_refused() {
        for address in ["", "notify", "vsock:2:1"] {
            let error = Notifier::new(OsStr::new(address)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{address}");
        }
    }

    #[test]
    fn a_missing_socket_is_an_error_not_a_panic() {
        let path = std::env::temp_dir().join(unique()).join("missing");
        let notifier = Notifier::new(path.as_os_str()).unwrap();
        assert!(notifier.notify(READY).is_err());
        send(Some(&notifier), READY);
        send(None, READY);
    }
}
