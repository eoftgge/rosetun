//! macOS credentials and descriptor-anchored service paths.

#![expect(
    unsafe_code,
    reason = "macOS libc calls use owned descriptors and checked ABI buffers"
)]

use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File, Metadata, OpenOptions};
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);

const CLIENT_GROUP: &CStr = c"staff";
const SOCKET_NAME: &CStr = c"helper.sock";
const STAGE_SOCKET_NAME: &CStr = c"s";
const SERVICE_RUN_DIR: &str = "/private/var/run/rosetun";
const SERVICE_DATA_DIR: &str = "/Library/Application Support/Rosetun";
const SERVICE_LISTS_DIR: &str = "/Library/Application Support/Rosetun/lists";
const SERVICE_PRIVATE_DIRS: [&str; 3] = [
    "/private/var/run/rosetun/private",
    "/private/var/run/rosetun/private/sing-box",
    "/private/var/run/rosetun/private/xray",
];

fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

pub(super) fn identify_peer(stream: &UnixStream) -> io::Result<PeerIdentity> {
    let mut uid: libc::uid_t = u32::MAX;
    let mut gid: libc::gid_t = u32::MAX;
    // SAFETY: getpeereid writes the peer effective UID and GID into valid
    // local storage. The stream owns the descriptor for the entire call.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut pid: libc::pid_t = 0;
    let mut length = size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: SOL_LOCAL/LOCAL_PEERPID writes a pid_t into the correctly sized
    // local buffer. The stream owns the descriptor for the entire call.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::pid_t>() {
        return Err(denied("invalid LOCAL_PEERPID length"));
    }
    if pid <= 0 || uid == u32::MAX {
        return Err(denied("unavailable peer credentials"));
    }
    Ok(PeerIdentity {
        account: AccountIdentity::MacOsUid(uid),
        administrator: uid == 0,
    })
}

fn group_id() -> io::Result<u32> {
    let mut group = MaybeUninit::<libc::group>::uninit();
    let mut buffer = vec![0u8; 1024];
    loop {
        let mut found = std::ptr::null_mut();
        // SAFETY: getgrnam_r borrows the NUL-terminated name and writable buffers
        // for this call only. The returned group points into buffer, which stays alive.
        let result = unsafe {
            libc::getgrnam_r(
                CLIENT_GROUP.as_ptr(),
                group.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if result == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        if found.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "required group 'staff' is missing",
            ));
        }
        // SAFETY: Successful getgrnam_r with non-null found initialized group.
        return Ok(unsafe { group.assume_init() }.gr_gid);
    }
}

fn c_component(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn open_directory_at(parent: &File, name: &CStr) -> io::Result<File> {
    // SAFETY: parent is an open directory descriptor, name is NUL-terminated,
    // and O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC never creates files.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful openat returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn mkdir_at(parent: &File, name: &CStr, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: parent is an open directory descriptor and name is NUL-terminated.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn stat_at(parent: &File, name: &CStr) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent is an open directory descriptor, name is NUL-terminated,
    // and stat points to valid writable storage.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful fstatat initialized stat.
    Ok(unsafe { stat.assume_init() })
}

fn unlink_at(parent: &File, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: parent is an open directory descriptor and name is NUL-terminated.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Stock macOS directories that are root-owned with group-write for a trusted
/// system group (`/private/var/run` is `root:daemon 0775`; `/Library/Application Support`
/// may be `root:admin 0775`). Rosetun-owned leaf directories never permit group write.
fn system_group_write_gids(prefix: &Path) -> Option<&'static [u32]> {
    if prefix == Path::new("/private/var/run") {
        Some(&[0, 1])
    } else if prefix == Path::new("/Library/Application Support") {
        Some(&[0, 80])
    } else {
        None
    }
}

fn directory_is_safe(
    is_dir: bool,
    owner: u32,
    group: u32,
    mode: u32,
    expected_uid: u32,
    private: bool,
    allowed_group_write: Option<&[u32]>,
) -> bool {
    let group_write_ok = mode & 0o020 == 0
        || (!private && allowed_group_write.is_some_and(|gids| gids.contains(&group)));
    is_dir
        && owner == expected_uid
        && mode & 0o002 == 0
        && group_write_ok
        && (!private || mode & 0o077 == 0)
}

fn validate_directory(
    metadata: &Metadata,
    uid: u32,
    private: bool,
    allowed_group_write: Option<&[u32]>,
) -> io::Result<()> {
    if !directory_is_safe(
        metadata.is_dir(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        uid,
        private,
        allowed_group_write,
    ) {
        return Err(denied(
            "service directory has an unsafe type, owner or mode",
        ));
    }
    Ok(())
}

fn root_directory(path: &Path, create_mode: Option<libc::mode_t>) -> io::Result<File> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(denied("service path must be absolute"));
    }
    let mut directory = open_directory(Path::new("/"))?;
    validate_directory(&directory.metadata()?, 0, false, None)?;
    let components: Vec<_> = path.components().collect();
    let mut prefix = PathBuf::from("/");
    for (index, component) in components.iter().enumerate().skip(1) {
        let Component::Normal(name) = component else {
            return Err(denied("non-normal service path component"));
        };
        prefix.push(name);
        let name_c = c_component(name)?;
        let last = index + 1 == components.len();
        if last && let Some(mode) = create_mode {
            match mkdir_at(&directory, &name_c, mode) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        directory = open_directory_at(&directory, &name_c)?;
        validate_directory(
            &directory.metadata()?,
            0,
            last && create_mode == Some(0o700),
            if last {
                None
            } else {
                system_group_write_gids(&prefix)
            },
        )?;
    }
    Ok(directory)
}

/// Prepare fixed root-only state and secret configuration directories.
/// Existing objects are validated, never repaired or migrated.
pub fn prepare_service_directories() -> io::Result<()> {
    root_directory(Path::new(SERVICE_DATA_DIR), Some(0o700))?;
    root_directory(Path::new(SERVICE_LISTS_DIR), Some(0o700))?;
    for path in SERVICE_PRIVATE_DIRS {
        root_directory(Path::new(path), Some(0o700))?;
    }
    Ok(())
}

fn validate_socket_stat(stat: &libc::stat, uid: u32, gid: u32) -> io::Result<()> {
    let mode = u32::from(stat.st_mode);
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFSOCK
        || stat.st_uid != uid
        || stat.st_gid != gid
        || mode & 0o7777 != 0o660
    {
        return Err(denied(
            "helper socket must have the trusted owner, group and mode 0660",
        ));
    }
    Ok(())
}

fn verify_server(stream: &UnixStream) -> io::Result<()> {
    if identify_peer(stream)?.account != AccountIdentity::MacOsUid(0) {
        return Err(denied("helper server must run as root"));
    }
    Ok(())
}

pub fn connect(endpoint: &Path) -> io::Result<Connection> {
    let parent = endpoint
        .parent()
        .ok_or_else(|| denied("missing endpoint directory"))?;
    let name = endpoint
        .file_name()
        .ok_or_else(|| denied("missing endpoint name"))?;
    let directory = root_directory(parent, None)?;
    let name_c = c_component(name)?;
    let gid = group_id()?;
    let before = stat_at(&directory, &name_c)?;
    validate_socket_stat(&before, 0, gid)?;
    let stream = UnixStream::connect(endpoint)?;
    // No protocol byte is written before BOTH endpoint and peer checks pass.
    verify_server(&stream)?;
    let after = stat_at(&directory, &name_c)?;
    validate_socket_stat(&after, 0, gid)?;
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) {
        return Err(denied("helper endpoint changed during connection"));
    }
    let path_meta = fs::symlink_metadata(endpoint)?;
    if path_meta.dev() as libc::dev_t != after.st_dev || path_meta.ino() != after.st_ino {
        return Err(denied("helper endpoint changed during connection"));
    }
    Connection::from_unix_stream(stream)
}

#[derive(Debug)]
struct WakePipe {
    read: OwnedFd,
    write: OwnedFd,
}

impl WakePipe {
    fn new() -> io::Result<Self> {
        let mut fds = [-1 as libc::c_int; 2];
        // SAFETY: pipe writes two new file descriptors into fds.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Successful pipe returned two newly owned descriptors.
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: Successful pipe returned two newly owned descriptors.
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        for fd in [read.as_raw_fd(), write.as_raw_fd()] {
            // SAFETY: fd is an open pipe descriptor owned above.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd is an open pipe descriptor owned above.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd is an open pipe descriptor owned above.
            if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self { read, write })
    }

    fn wake(&self) -> io::Result<()> {
        let byte = [1u8];
        loop {
            // SAFETY: write borrows self.write and a 1-byte buffer for this call.
            let written =
                unsafe { libc::write(self.write.as_raw_fd(), byte.as_ptr().cast(), byte.len()) };
            if written >= 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return Ok(()),
                _ => return Err(error),
            }
        }
    }
}

#[derive(Debug)]
pub struct Listener {
    inner: UnixListener,
    wake: WakePipe,
    path: PathBuf,
    owned: Option<OwnedEndpoint>,
}

#[derive(Debug)]
struct OwnedEndpoint {
    directory: File,
    // XNU holds a vnode reference for the bound socket as long as `inner` is open.
    // `Drop::drop` verifies `(dev, ino)` before `inner` is dropped, preventing
    // inode reuse from making a replacement look like the socket we created.
    dev: libc::dev_t,
    ino: libc::ino_t,
    uid: u32,
    gid: u32,
}

impl Listener {
    pub fn bind(endpoint: &Path) -> io::Result<Self> {
        if endpoint != Path::new(UNIX_ENDPOINT) {
            return Err(denied(
                "macOS helper requires /private/var/run/rosetun/helper.sock",
            ));
        }
        // SAFETY: geteuid has no arguments or ownership/lifetime requirements.
        if unsafe { libc::geteuid() } != 0 {
            return Err(denied("macOS helper must run as root"));
        }
        let gid = group_id()?;
        let directory = root_directory(Path::new(SERVICE_RUN_DIR), Some(0o755))?;
        Self::bind_in(directory, endpoint.to_owned(), 0, gid)
    }

    fn bind_in(directory: File, path: PathBuf, uid: u32, gid: u32) -> io::Result<Self> {
        validate_directory(&directory.metadata()?, uid, false, None)?;
        match stat_at(&directory, SOCKET_NAME) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "helper endpoint exists; administrator must inspect and remove a stale socket while helper is stopped",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let stage_name = format!(
            ".s-{}-{}",
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
        );
        let stage_name_c = CString::new(stage_name.as_str())?;
        mkdir_at(&directory, &stage_name_c, 0o700)?;
        let mut stage = Stage {
            parent: &directory,
            name: stage_name_c.clone(),
            dir: None,
        };
        let stage_dir = open_directory_at(&directory, &stage_name_c)?;
        validate_directory(&stage_dir.metadata()?, uid, true, None)?;
        stage.dir = Some(stage_dir);
        let stage_dir = stage.dir.as_ref().expect("staging directory is open");

        let parent_path = path
            .parent()
            .ok_or_else(|| denied("missing endpoint directory"))?;
        let socket_path = parent_path.join(&stage_name).join("s");
        let inner = UnixListener::bind(&socket_path)?;
        inner.set_nonblocking(true)?;

        // The socket is inaccessible inside a newly created 0700 directory until
        // publication. No process-wide umask changes or world-accessible window.
        // SAFETY: stage_dir is an open directory descriptor, STAGE_SOCKET_NAME is
        // NUL-terminated, and AT_SYMLINK_NOFOLLOW prevents symlink following.
        if unsafe {
            libc::fchownat(
                stage_dir.as_raw_fd(),
                STAGE_SOCKET_NAME.as_ptr(),
                uid,
                gid,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: stage_dir is an open directory descriptor, STAGE_SOCKET_NAME is
        // NUL-terminated, and AT_SYMLINK_NOFOLLOW prevents symlink following.
        if unsafe {
            libc::fchmodat(
                stage_dir.as_raw_fd(),
                STAGE_SOCKET_NAME.as_ptr(),
                0o660,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let socket_stat = stat_at(stage_dir, STAGE_SOCKET_NAME)?;
        validate_socket_stat(&socket_stat, uid, gid)?;

        // SAFETY: Both directory descriptors are open and both names are
        // NUL-terminated. RENAME_EXCL publishes our private socket atomically
        // and never overwrites an existing entry.
        if unsafe {
            libc::renameatx_np(
                stage_dir.as_raw_fd(),
                STAGE_SOCKET_NAME.as_ptr(),
                directory.as_raw_fd(),
                SOCKET_NAME.as_ptr(),
                libc::RENAME_EXCL,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let wake = WakePipe::new()?;
        drop(stage);

        Ok(Self {
            inner,
            wake,
            path,
            owned: Some(OwnedEndpoint {
                directory,
                dev: socket_stat.st_dev,
                ino: socket_stat.st_ino,
                uid,
                gid,
            }),
        })
    }

    pub fn accept(&self) -> io::Result<Connection> {
        loop {
            let mut fds = [
                libc::pollfd {
                    fd: self.inner.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.wake.read.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: Both descriptors are owned by self for the entire call,
            // and fds is a valid 2-element array.
            let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if fds[1].revents != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "listener accept interrupted",
                ));
            }
            if fds[0].revents != 0 {
                match self.inner.accept() {
                    Ok((stream, _)) => {
                        // Darwin accepted sockets inherit O_NONBLOCK from the listener.
                        stream.set_nonblocking(false)?;
                        return Connection::from_unix_stream(stream);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }

    /// Wake a blocked or upcoming accept without connecting through its path.
    /// The caller must stop its accept loop before interrupting and then join it.
    pub fn interrupt_accept(&self, _thread: &std::thread::JoinHandle<()>) -> io::Result<()> {
        self.wake.wake()
    }

    /// Bind an owned fixture in a private directory belonging to the test user.
    /// Production bind and client server-verification policy remain unchanged.
    #[cfg(feature = "test-support")]
    pub fn bind_test_fixture(directory: &Path) -> io::Result<Self> {
        let opened = open_directory(directory)?;
        // SAFETY: geteuid and getegid have no arguments, ownership or lifetime requirements.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let metadata = opened.metadata()?;
        validate_directory(&metadata, uid, true, None)?;
        Self::bind_in(opened, directory.join("helper.sock"), uid, gid)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(owned) = &self.owned {
            // Pinned root-owned directories exclude mutation by the client group.
            // As with the rest of the service, trusted root is outside the threat
            // model. If root widened directory permissions, leave the path alone.
            let safe_directory = owned
                .directory
                .metadata()
                .and_then(|m| validate_directory(&m, owned.uid, false, None));
            if safe_directory.is_ok()
                && stat_at(&owned.directory, SOCKET_NAME).is_ok_and(|m| {
                    validate_socket_stat(&m, owned.uid, owned.gid).is_ok()
                        && (m.st_dev, m.st_ino) == (owned.dev, owned.ino)
                })
            {
                let _ = unlink_at(&owned.directory, SOCKET_NAME, 0);
            }
        }
    }
}

struct Stage<'a> {
    parent: &'a File,
    name: CString,
    dir: Option<File>,
}

impl Drop for Stage<'_> {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            let _ = unlink_at(&dir, STAGE_SOCKET_NAME, 0);
        }
        let _ = unlink_at(self.parent, &self.name, libc::AT_REMOVEDIR);
    }
}

#[cfg(test)]
mod tests {
    use std::fs::DirBuilder;
    use std::io::Read;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::process::Command;

    use super::*;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rt-{}-{}",
                std::process::id(),
                NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn bind(&self) -> io::Result<Listener> {
            // SAFETY: geteuid and getegid have no arguments or invariants.
            let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
            Listener::bind_in(
                open_directory(&self.0)?,
                self.0.join("helper.sock"),
                uid,
                gid,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn credentials_are_read_from_a_real_socket_pair() {
        let (stream, other) = UnixStream::pair().unwrap();
        let connection = Connection::from_unix_stream(stream).unwrap();
        // SAFETY: geteuid has no arguments or invariants.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            connection.identify_peer().unwrap().account(),
            &AccountIdentity::MacOsUid(uid)
        );
        assert_eq!(identify_peer(&other).unwrap().is_administrator(), uid == 0);
    }

    #[test]
    fn peer_credentials_reject_an_ordinary_server_before_any_write() {
        let (stream, mut server) = UnixStream::pair().unwrap();
        // SAFETY: geteuid has no arguments or invariants.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(verify_server(&stream).is_ok(), uid == 0);
        drop(stream);
        let mut data = Vec::new();
        server.read_to_end(&mut data).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn arbitrary_streams_do_not_have_credentials() {
        let connection = Connection::new(Box::new(io::empty()), Box::new(io::sink()));
        assert!(connection.identify_peer().is_err());
    }

    #[test]
    fn another_process_of_the_same_uid_has_the_same_account() {
        const CHILD_PATH: &str = "ROSETUN_TEST_CHILD_SOCKET";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let mut stream = UnixStream::connect(path).unwrap();
            let value = serde_json::json!({"request": {"id": 1, "body": {"hello": {
                "client": "uid=0", "protocol_version": crate::PROTOCOL_VERSION, "uid": 0
            }}}});
            serde_json::to_writer(&mut stream, &value).unwrap();
            stream.write_all(b"\n").unwrap();
            // Keep the socket connected until the parent finishes checking peer
            // credentials: XNU returns ENOTCONN once the remote peer closes.
            let mut eof = [0u8; 1];
            let _ = stream.read(&mut eof);
            return;
        }
        let fixture = Fixture::new();
        let listener = fixture.bind().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "transport::platform::tests::another_process_of_the_same_uid_has_the_same_account",
            ])
            .env(CHILD_PATH, listener.path())
            .spawn()
            .unwrap();
        let mut accepted = listener.accept().unwrap();
        let (same_uid, _other) = UnixStream::pair().unwrap();
        assert_eq!(
            accepted.identify_peer().unwrap().account(),
            identify_peer(&same_uid).unwrap().account()
        );
        // A claimed JSON uid is merely data, not the source of identity.
        let before = accepted.identify_peer().unwrap();
        assert!(matches!(
            accepted.read().unwrap(),
            Some(crate::Frame::Request {
                body: crate::Request::Hello { .. },
                ..
            })
        ));
        assert_eq!(
            accepted.identify_peer().unwrap().account(),
            before.account()
        );
        drop(accepted);
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn a_user_endpoint_is_rejected_before_hello() {
        let fixture = Fixture::new();
        let path = fixture.0.join("helper.sock");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(crate::HelperClient::connect(&path, "fixture").is_err());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn a_second_bind_preserves_the_working_endpoint() {
        let fixture = Fixture::new();
        let listener = fixture.bind().unwrap();
        let original = fs::symlink_metadata(listener.path()).unwrap();
        assert!(fixture.bind().is_err());
        let mut stream = UnixStream::connect(listener.path()).unwrap();
        stream.write_all(b"x").unwrap();
        let mut accepted = listener.accept().unwrap();
        let mut byte = [0];
        accepted.reader.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");
        assert_eq!(fs::metadata(listener.path()).unwrap().ino(), original.ino());
        assert_eq!(original.mode() & 0o7777, 0o660);
    }

    #[test]
    fn occupied_files_symlinks_and_stale_sockets_are_never_removed() {
        let fixture = Fixture::new();
        let path = fixture.0.join("helper.sock");
        fs::write(&path, b"fixture").unwrap();
        assert!(fixture.bind().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"fixture");
        fs::remove_file(&path).unwrap();
        symlink("missing", &path).unwrap();
        assert!(fixture.bind().is_err());
        assert_eq!(fs::read_link(&path).unwrap(), Path::new("missing"));
        fs::remove_file(&path).unwrap();
        drop(UnixListener::bind(&path).unwrap());
        let original = fs::metadata(&path).unwrap();
        assert!(fixture.bind().is_err());
        assert_eq!(fs::metadata(&path).unwrap().ino(), original.ino());
    }

    #[test]
    fn drop_preserves_a_replacement_endpoint() {
        let fixture = Fixture::new();
        let listener = fixture.bind().unwrap();
        fs::remove_file(listener.path()).unwrap();
        fs::write(listener.path(), b"replacement").unwrap();
        drop(listener);
        assert_eq!(
            fs::read(fixture.0.join("helper.sock")).unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn drop_preserves_symlinks_and_other_sockets() {
        let fixture = Fixture::new();
        let listener = fixture.bind().unwrap();
        fs::remove_file(listener.path()).unwrap();
        symlink("missing", listener.path()).unwrap();
        drop(listener);
        let path = fixture.0.join("helper.sock");
        assert_eq!(fs::read_link(&path).unwrap(), Path::new("missing"));
        fs::remove_file(&path).unwrap();
        let listener = fixture.bind().unwrap();
        fs::remove_file(&path).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        drop(listener);
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
        drop(replacement);
    }

    #[test]
    fn symlink_directories_are_not_followed() {
        let fixture = Fixture::new();
        let link = fixture.0.join("link");
        symlink(&fixture.0, &link).unwrap();
        assert!(open_directory(&link).is_err());
        assert_eq!(fs::read_link(&link).unwrap(), fixture.0);
    }

    #[test]
    fn unsafe_directories_and_socket_modes_are_rejected_without_repair() {
        let fixture = Fixture::new();
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(fixture.bind().is_err());
        assert_eq!(fs::metadata(&fixture.0).unwrap().mode() & 0o777, 0o777);
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
        let path = fixture.0.join("helper.sock");
        let _socket = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let dir = open_directory(&fixture.0).unwrap();
        let original = stat_at(&dir, SOCKET_NAME).unwrap();
        assert!(validate_socket_stat(&original, original.st_uid, original.st_gid).is_err());
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o666);
        assert!(
            validate_socket_stat(&original, original.st_uid.wrapping_add(1), original.st_gid)
                .is_err()
        );
        assert!(root_directory(&fixture.0, None).is_err());
    }

    #[test]
    fn production_bind_rejects_custom_paths_without_creating_objects() {
        let fixture = Fixture::new();
        assert!(Listener::bind(&fixture.0.join("helper.sock")).is_err());
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
    }

    #[test]
    fn macos_system_parent_group_write_policy_only_allows_known_system_groups() {
        let var_run_groups = system_group_write_gids(Path::new("/private/var/run"));
        assert!(directory_is_safe(
            true,
            0,
            1,
            0o775,
            0,
            false,
            var_run_groups
        ));
        assert!(!directory_is_safe(
            true,
            0,
            20,
            0o775,
            0,
            false,
            var_run_groups
        ));
        assert!(!directory_is_safe(
            true,
            0,
            1,
            0o777,
            0,
            false,
            var_run_groups
        ));
        assert!(!directory_is_safe(
            true,
            0,
            1,
            0o775,
            0,
            true,
            var_run_groups
        ));
        // Rosetun's own directory never permits group write.
        assert_eq!(system_group_write_gids(Path::new(SERVICE_RUN_DIR)), None);
        assert!(!directory_is_safe(true, 0, 1, 0o775, 0, false, None));
        assert!(directory_is_safe(true, 0, 0, 0o755, 0, false, None));
    }

    #[test]
    fn interrupt_accept_wakes_both_blocked_and_upcoming_accepts() {
        use std::sync::{Arc, mpsc};

        let fixture = Fixture::new();
        let listener = Arc::new(fixture.bind().unwrap());
        let accept_listener = Arc::clone(&listener);
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = tx.send(accept_listener.accept());
        });
        std::thread::sleep(Duration::from_millis(20));
        listener.interrupt_accept(&worker).unwrap();
        worker.join().unwrap();
        let error = rx.recv().unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        // Subsequent accept also returns immediately because the wake byte remains readable.
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
    }
}
