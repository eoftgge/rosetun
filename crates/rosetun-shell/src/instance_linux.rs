//! One GUI per user on Linux: the first run holds a lock and listens on a
//! socket in the private runtime folder, a later run hands it what it was
//! started for and exits. A link is as secret as the subscription, so both
//! ends check who is on the other side.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::link_frame::{encode_link, read_link};

const LOCK_FILE: &str = "rosetun-gui.lock";
const SOCKET_FILE: &str = "rosetun-gui.sock";
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_millis(50);
const TAG_SHOW: u8 = 1;
const TAG_AFTER_UPGRADE: u8 = 2;
const TAG_OPEN_LINK: u8 = 3;

/// What a later run asks the first one to do.
#[derive(Clone, PartialEq, Eq)]
pub enum InstanceMessage {
    Show,
    /// The package was upgraded with the network held: connect.
    AfterUpgrade,
    OpenLink(String),
}

impl std::fmt::Debug for InstanceMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Show => "Show",
            Self::AfterUpgrade => "AfterUpgrade",
            Self::OpenLink(_) => "OpenLink([redacted])",
        })
    }
}

#[derive(Debug)]
pub enum Instance {
    /// No other run holds the lock; later ones reach this one through it.
    First(Activation),
    Other,
}

/// The first run's end. The socket is bound before the settings load, so a
/// later run's message waits in its queue.
#[derive(Debug)]
pub struct Activation {
    listener: UnixListener,
    /// Held until the process ends; the kernel drops it after a crash too.
    _lock: File,
}

impl Activation {
    /// Blocks, handing every message from a run of this user to `handler`.
    /// A malformed message closes that connection and waits for the next one.
    pub fn serve(self, mut handler: impl FnMut(InstanceMessage)) -> io::Result<()> {
        loop {
            let mut stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if peer_of_this_user(&stream).is_err()
                || stream.set_read_timeout(Some(READ_TIMEOUT)).is_err()
            {
                continue;
            }
            if let Some(message) = read_message(&mut stream) {
                handler(message);
            }
        }
    }
}

/// Takes the session's GUI slot. An error means the check could not be made
/// (no private runtime folder, say), not that another run exists.
pub fn acquire() -> io::Result<Instance> {
    acquire_in(&runtime_dir(std::env::var_os("XDG_RUNTIME_DIR"))?)
}

/// Hands `message` to the first run, waiting up to 5 s while it starts.
/// Nothing is sent unless the socket's server is this same program of this user.
pub fn send_to_first(message: &InstanceMessage) -> io::Result<()> {
    send_in(
        &runtime_dir(std::env::var_os("XDG_RUNTIME_DIR"))?,
        message,
        &std::env::current_exe()?,
    )
}

fn acquire_in(dir: &Path) -> io::Result<Instance> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(LOCK_FILE))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Ok(Instance::Other),
        Err(TryLockError::Error(error)) => return Err(error),
    }
    let socket = dir.join(SOCKET_FILE);
    // The lock is ours, so this is what a crashed run left behind.
    match fs::remove_file(&socket) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    Ok(Instance::First(Activation {
        listener,
        _lock: lock,
    }))
}

fn send_in(dir: &Path, message: &InstanceMessage, exe: &Path) -> io::Result<()> {
    let bytes = encode_message(message)?;
    let mut stream = connect(&dir.join(SOCKET_FILE))?;
    let pid = peer_of_this_user(&stream)?;
    let server = fs::read_link(format!("/proc/{pid}/exe"))?;
    if !same_program(&server, exe) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the socket belongs to another program",
        ));
    }
    stream.set_write_timeout(Some(SEND_TIMEOUT))?;
    stream.write_all(&bytes)
}

fn connect(socket: &Path) -> io::Result<UnixStream> {
    let deadline = Instant::now() + SEND_TIMEOUT;
    loop {
        match UnixStream::connect(socket) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if Instant::now() < deadline
                    && matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
            {
                std::thread::sleep(RETRY_DELAY);
            }
            Err(error) => return Err(error),
        }
    }
}

fn encode_message(message: &InstanceMessage) -> io::Result<Vec<u8>> {
    Ok(match message {
        InstanceMessage::Show => vec![TAG_SHOW],
        InstanceMessage::AfterUpgrade => vec![TAG_AFTER_UPGRADE],
        InstanceMessage::OpenLink(link) => {
            let mut bytes = vec![TAG_OPEN_LINK];
            bytes.extend(encode_link(link)?);
            bytes
        }
    })
}

fn read_message(reader: &mut impl Read) -> Option<InstanceMessage> {
    let mut tag = [0];
    reader.read_exact(&mut tag).ok()?;
    match tag[0] {
        TAG_SHOW => Some(InstanceMessage::Show),
        TAG_AFTER_UPGRADE => Some(InstanceMessage::AfterUpgrade),
        TAG_OPEN_LINK => read_link(reader).map(InstanceMessage::OpenLink),
        _ => None,
    }
}

/// The runtime folder from `value`, only if it can hold a secret: absolute,
/// a real folder of this user, closed to everyone else. No fallback to a
/// shared folder such as `/tmp`.
fn runtime_dir(value: Option<OsString>) -> io::Result<PathBuf> {
    let dir = value
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "XDG_RUNTIME_DIR is not set"))?;
    let metadata = fs::symlink_metadata(&dir)?;
    if !metadata.is_dir() || metadata.uid() != current_uid() || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "XDG_RUNTIME_DIR is not private to this user",
        ));
    }
    Ok(dir)
}

/// The peer's process ID, when the peer is this user.
fn peer_of_this_user(stream: &UnixStream) -> io::Result<i32> {
    let peer = peer_credentials(stream)?;
    if peer.uid != current_uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the peer is another user",
        ));
    }
    Ok(peer.pid)
}

fn peer_credentials(stream: &UnixStream) -> io::Result<libc::ucred> {
    let mut peer = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: The socket stays open for the call; `peer` and `length` are
    // live, writable and describe a buffer of exactly `ucred`'s size, which
    // the kernel fills with the credentials taken at connect time.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut peer).cast(),
            &raw mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(peer)
}

fn current_uid() -> u32 {
    // SAFETY: Takes nothing, touches no memory and cannot fail.
    unsafe { libc::geteuid() }
}

/// Whether a `/proc/<pid>/exe` target is `exe`. The kernel marks a file
/// replaced since it started, as a package upgrade does, with ` (deleted)`.
fn same_program(server: &Path, exe: &Path) -> bool {
    let live = |path: &Path| -> OsString {
        let bytes = path.as_os_str().as_bytes();
        OsStr::from_bytes(bytes.strip_suffix(b" (deleted)").unwrap_or(bytes)).to_owned()
    };
    live(server) == live(exe)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    use super::*;

    fn private_dir(test: &str) -> PathBuf {
        static DIRS: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rosetun-instance-{test}-{}-{}",
            std::process::id(),
            DIRS.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn first(dir: &Path) -> Activation {
        match acquire_in(dir).unwrap() {
            Instance::First(activation) => activation,
            Instance::Other => panic!("the first run should take the slot"),
        }
    }

    #[test]
    fn a_later_run_is_told_apart_and_its_messages_reach_the_first() {
        let dir = private_dir("messages");
        let activation = first(&dir);
        assert!(matches!(acquire_in(&dir).unwrap(), Instance::Other));
        let (sender, messages) = mpsc::channel();
        std::thread::spawn(move || activation.serve(|message| sender.send(message).unwrap()));
        let exe = std::env::current_exe().unwrap();
        let link = InstanceMessage::OpenLink("rosetun://add/https://example.com/token".into());
        for message in [InstanceMessage::Show, InstanceMessage::AfterUpgrade, link] {
            send_in(&dir, &message, &exe).unwrap();
            assert_eq!(
                messages.recv_timeout(Duration::from_secs(5)).unwrap(),
                message
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_socket_and_the_lock_are_closed_to_others() {
        let dir = private_dir("modes");
        let _activation = first(&dir);
        for name in [SOCKET_FILE, LOCK_FILE] {
            let mode = fs::metadata(dir.join(name)).unwrap().mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_socket_left_by_a_crash_does_not_stop_the_next_run() {
        let dir = private_dir("stale");
        drop(first(&dir));
        assert!(dir.join(SOCKET_FILE).exists(), "nothing removes it on exit");
        drop(first(&dir));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn nothing_is_sent_to_another_program() {
        let dir = private_dir("program");
        let _activation = first(&dir);
        let error = send_in(
            &dir,
            &InstanceMessage::OpenLink("rosetun://add/https://example.com/token".into()),
            Path::new("/nonexistent/rosetun-gui"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_program_replaced_on_disk_is_still_the_same() {
        let exe = Path::new("/usr/bin/rosetun-gui");
        assert!(same_program(exe, exe));
        assert!(same_program(
            Path::new("/usr/bin/rosetun-gui (deleted)"),
            exe
        ));
        assert!(!same_program(Path::new("/usr/bin/other"), exe));
        assert!(!same_program(Path::new("/opt/rosetun-gui"), exe));
    }

    #[test]
    fn only_a_private_absolute_folder_is_a_runtime_folder() {
        assert!(runtime_dir(None).is_err());
        assert!(runtime_dir(Some("relative/run".into())).is_err());
        let dir = private_dir("runtime");
        assert_eq!(runtime_dir(Some(dir.clone().into())).unwrap(), dir);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            runtime_dir(Some(dir.clone().into())).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let link = dir.with_extension("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(runtime_dir(Some(link.clone().into())).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_malformed_message_is_dropped() {
        assert_eq!(read_message(&mut [].as_slice()), None);
        assert_eq!(read_message(&mut [9u8].as_slice()), None);
        assert_eq!(read_message(&mut [TAG_OPEN_LINK, 1].as_slice()), None);
        let too_long = (crate::link_frame::MAX_LINK_BYTES as u32 + 1).to_le_bytes();
        let mut bytes = vec![TAG_OPEN_LINK];
        bytes.extend(too_long);
        assert_eq!(read_message(&mut bytes.as_slice()), None);
    }

    #[test]
    fn a_link_is_not_in_the_debug_text() {
        let message = InstanceMessage::OpenLink("rosetun://add/private-token".into());
        assert!(!format!("{message:?}").contains("private-token"));
    }
}
