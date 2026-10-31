//! Linux credentials and descriptor-anchored service paths.

#![expect(unsafe_code, reason = "Linux libc calls use owned descriptors and checked ABI buffers")]

use std::ffi::CString;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::mem::{MaybeUninit, size_of};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

const ENDPOINT: &str = "/run/rosetun/helper.sock";
static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);

fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

pub(super) fn identify_peer(stream: &UnixStream) -> io::Result<PeerIdentity> {
    let mut credentials = MaybeUninit::<libc::ucred>::uninit();
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: Linux SO_PEERCRED writes a ucred into the correctly sized output.
    // The stream owns the descriptor for the entire call; no ownership is transferred.
    let result = unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(), &mut length)
    };
    if result != 0 { return Err(io::Error::last_os_error()); }
    if length as usize != size_of::<libc::ucred>() {
        return Err(denied("invalid SO_PEERCRED length"));
    }
    // SAFETY: A successful getsockopt initialized the complete Linux ucred above.
    let credentials = unsafe { credentials.assume_init() };
    if credentials.pid <= 0 || credentials.uid == u32::MAX {
        return Err(denied("unavailable peer credentials"));
    }
    Ok(PeerIdentity {
        account: AccountIdentity::LinuxUid(credentials.uid),
        administrator: credentials.uid == 0,
    })
}

fn group_id() -> io::Result<u32> {
    let mut group = MaybeUninit::<libc::group>::uninit();
    let mut buffer = vec![0u8; 1024];
    loop {
        let mut found = std::ptr::null_mut();
        // SAFETY: getgrnam_r borrows the NUL-terminated name and writable buffers
        // for this call only. The returned group points into buffer, which stays alive.
        let result = unsafe { libc::getgrnam_r(c"rosetun".as_ptr(), group.as_mut_ptr(),
            buffer.as_mut_ptr().cast(), buffer.len(), &mut found) };
        if result == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if result != 0 { return Err(io::Error::from_raw_os_error(result)); }
        if found.is_null() {
            return Err(io::Error::new(io::ErrorKind::NotFound,
                "required group 'rosetun' is missing; ask an administrator to provision it"));
        }
        // SAFETY: Successful getgrnam_r with non-null found initialized group.
        return Ok(unsafe { group.assume_init() }.gr_gid);
    }
}

fn fd_path(file: &File) -> PathBuf {
    // This intentional procfs link pins the already opened directory, unlike
    // reopening an untrusted pathname. The owning File outlives every operation.
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn validate_directory(metadata: &Metadata, uid: u32, private: bool) -> io::Result<()> {
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0
        || (private && metadata.mode() & 0o077 != 0) {
        return Err(denied("service directory has an unsafe type, owner or mode"));
    }
    Ok(())
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path)
}

fn root_directory(path: &Path, create_mode: Option<u32>) -> io::Result<File> {
    use std::path::Component;

    if !path.is_absolute() { return Err(denied("service path must be absolute")); }
    let mut directory = open_directory(Path::new("/"))?;
    validate_directory(&directory.metadata()?, 0, false)?;
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate().skip(1) {
        let Component::Normal(name) = component else {
            return Err(denied("non-normal service path component"));
        };
        let next = fd_path(&directory).join(name);
        let last = index + 1 == components.len();
        if last && let Some(mode) = create_mode {
            match DirBuilder::new().mode(mode).create(&next) {
                Ok(()) => {},
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
                Err(error) => return Err(error),
            }
        }
        directory = open_directory(&next)?;
        validate_directory(&directory.metadata()?, 0, last && create_mode == Some(0o700))?;
    }
    Ok(directory)
}

/// Prepare fixed root-only state and secret configuration directories.
/// Existing objects are validated, never repaired or migrated.
pub fn prepare_service_directories() -> io::Result<()> {
    root_directory(Path::new("/var/lib/rosetun"), Some(0o700))?;
    root_directory(Path::new("/var/lib/rosetun/lists"), Some(0o700))?;
    root_directory(Path::new("/run/rosetun/private"), Some(0o700))?;
    root_directory(Path::new("/run/rosetun/private/sing-box"), Some(0o700))?;
    root_directory(Path::new("/run/rosetun/private/xray"), Some(0o700))?;
    Ok(())
}

fn validate_socket(metadata: &Metadata, uid: u32, gid: u32) -> io::Result<()> {
    if !metadata.file_type().is_socket() || metadata.uid() != uid
        || metadata.gid() != gid || metadata.mode() & 0o7777 != 0o660 {
        return Err(denied("helper socket must have the trusted owner, group and mode 0660"));
    }
    Ok(())
}

fn verify_server(stream: &UnixStream) -> io::Result<()> {
    if identify_peer(stream)?.account != AccountIdentity::LinuxUid(0) {
        return Err(denied("helper server must run as root"));
    }
    Ok(())
}

pub fn connect(endpoint: &Path) -> io::Result<Connection> {
    let parent = endpoint.parent().ok_or_else(|| denied("missing endpoint directory"))?;
    let name = endpoint.file_name().ok_or_else(|| denied("missing endpoint name"))?;
    let directory = root_directory(parent, None)?;
    let path = fd_path(&directory).join(name);
    let gid = group_id()?;
    let before = fs::symlink_metadata(&path)?;
    validate_socket(&before, 0, gid)?;
    let stream = UnixStream::connect(&path)?;
    // No protocol byte is written before BOTH endpoint and peer checks pass.
    verify_server(&stream)?;
    let after = fs::symlink_metadata(&path)?;
    validate_socket(&after, 0, gid)?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err(denied("helper endpoint changed during connection"));
    }
    Connection::from_unix_stream(stream)
}

#[derive(Debug)]
pub struct Listener {
    inner: UnixListener,
    path: PathBuf,
    owned: Option<OwnedEndpoint>,
}

#[derive(Debug)]
struct OwnedEndpoint {
    directory: File,
    // O_PATH pins the filesystem inode even if its name is unlinked, preventing
    // inode reuse from making a replacement look like the socket we created.
    socket: File,
    uid: u32,
    gid: u32,
}

impl Listener {
    pub fn bind(endpoint: &Path) -> io::Result<Self> {
        if endpoint != Path::new(ENDPOINT) {
            return Err(denied("Linux helper requires /run/rosetun/helper.sock"));
        }
        // SAFETY: geteuid has no arguments or ownership/lifetime requirements.
        if unsafe { libc::geteuid() } != 0 {
            return Err(denied("Linux helper must run as root"));
        }
        let gid = group_id()?;
        let directory = root_directory(Path::new("/run/rosetun"), Some(0o755))?;
        Self::bind_in(directory, endpoint.to_owned(), 0, gid)
    }

    fn bind_in(directory: File, path: PathBuf, uid: u32, gid: u32) -> io::Result<Self> {
        validate_directory(&directory.metadata()?, uid, false)?;
        let destination = fd_path(&directory).join("helper.sock");
        match fs::symlink_metadata(&destination) {
            Ok(_) => return Err(io::Error::new(io::ErrorKind::AddrInUse,
                "helper endpoint exists; administrator must inspect and remove a stale socket while helper is stopped")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(error),
        }
        let stage_name = format!(".socket-{}-{}", std::process::id(), NEXT_STAGE.fetch_add(1, Ordering::Relaxed));
        let stage_path = fd_path(&directory).join(&stage_name);
        DirBuilder::new().mode(0o700).create(&stage_path)?;
        let stage = Stage(stage_path);
        let socket_path = stage.0.join("socket");
        let inner = UnixListener::bind(&socket_path)?;
        // The socket is inaccessible inside a newly created 0700 directory until
        // publication. No process-wide umask changes or world-accessible window.
        let socket_c = CString::new(socket_path.as_os_str().as_encoded_bytes())?;
        // SAFETY: chown borrows a NUL-terminated path to our new private socket.
        // No descriptor ownership is transferred; stage remains alive throughout.
        if unsafe { libc::chown(socket_c.as_ptr(), uid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))?;
        let socket = OpenOptions::new().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW).open(&socket_path)?;
        let metadata = socket.metadata()?;
        validate_socket(&metadata, uid, gid)?;
        let destination_c = CString::new(destination.as_os_str().as_encoded_bytes())?;
        // SAFETY: Both C strings remain alive; syscall arguments match the Linux
        // renameat2 ABI (descriptor integers, path pointers, flags). NOREPLACE
        // publishes our private inode atomically and never overwrites any endpoint.
        if unsafe { libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD as libc::c_long, socket_c.as_ptr(),
            libc::AT_FDCWD as libc::c_long, destination_c.as_ptr(), libc::RENAME_NOREPLACE as libc::c_long) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { inner, path, owned: Some(OwnedEndpoint { directory, socket, uid, gid }) })
    }

    /// Adopt an already bound listener without claiming ownership of its path.
    /// This does not weaken client verification or manufacture peer credentials.
    pub fn from_unix_listener(inner: UnixListener, path: PathBuf) -> Self {
        Self { inner, path, owned: None }
    }

    pub fn accept(&self) -> io::Result<Connection> {
        Connection::from_unix_stream(self.inner.accept()?.0)
    }

    pub fn path(&self) -> &Path { &self.path }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(owned) = &self.owned {
            let path = fd_path(&owned.directory).join("helper.sock");
            // Pinned root-owned directories exclude mutation by the client group.
            // As with the rest of the service, trusted root is outside the threat
            // model. If root widened directory permissions, leave the path alone.
            let safe_directory = owned.directory.metadata().and_then(|m| validate_directory(&m, owned.uid, false));
            if safe_directory.is_ok() && let Ok(original) = owned.socket.metadata()
                && fs::symlink_metadata(&path).is_ok_and(|m|
                    validate_socket(&m, owned.uid, owned.gid).is_ok()
                    && (m.dev(), m.ino()) == (original.dev(), original.ino())) {
                let _ = fs::remove_file(path);
            }
        }
    }
}

struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("socket"));
        let _ = fs::remove_dir(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("rosetun-l2-{}-{}",
                std::process::id(), NEXT_STAGE.fetch_add(1, Ordering::Relaxed)));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn bind(&self) -> io::Result<Listener> {
            let metadata = fs::metadata(&self.0)?;
            Listener::bind_in(open_directory(&self.0)?, self.0.join("helper.sock"), metadata.uid(), metadata.gid())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
    }

    #[test]
    fn credentials_are_read_from_a_real_socket_pair() {
        let (stream, other) = UnixStream::pair().unwrap();
        let connection = Connection::from_unix_stream(stream).unwrap();
        let uid = fs::metadata("/proc/self").unwrap().uid();
        assert_eq!(connection.identify_peer().unwrap().account(), &AccountIdentity::LinuxUid(uid));
        assert_eq!(identify_peer(&other).unwrap().is_administrator(), uid == 0);
    }

    #[test]
    fn peer_credentials_reject_an_ordinary_server_before_any_write() {
        let (stream, mut server) = UnixStream::pair().unwrap();
        let uid = fs::metadata("/proc/self").unwrap().uid();
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
            return;
        }
        let fixture = Fixture::new();
        let listener = fixture.bind().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "transport::platform::tests::another_process_of_the_same_uid_has_the_same_account"])
            .env(CHILD_PATH, listener.path()).spawn().unwrap();
        let mut accepted = listener.accept().unwrap();
        let (same_uid, _other) = UnixStream::pair().unwrap();
        assert_eq!(accepted.identify_peer().unwrap().account(), identify_peer(&same_uid).unwrap().account());
        // A claimed JSON uid is merely data, not the source of identity.
        let before = accepted.identify_peer().unwrap();
        assert!(matches!(accepted.read().unwrap(), Some(crate::Frame::Request {
            body: crate::Request::Hello { .. }, ..
        })));
        assert_eq!(accepted.identify_peer().unwrap().account(), before.account());
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn a_user_endpoint_is_rejected_before_hello() {
        let fixture = Fixture::new();
        let path = fixture.0.join("helper.sock");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(crate::HelperClient::connect(&path, "fixture").is_err());
        assert_eq!(listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
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
        assert_eq!(fs::read(fixture.0.join("helper.sock")).unwrap(), b"replacement");
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
        let original = fs::metadata(&path).unwrap();
        assert!(validate_socket(&original, original.uid(), original.gid()).is_err());
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o666);
        assert!(validate_socket(&original, original.uid().wrapping_add(1), original.gid()).is_err());
        assert!(root_directory(&fixture.0, None).is_err());
    }

    #[test]
    fn production_bind_rejects_custom_paths_without_creating_objects() {
        let fixture = Fixture::new();
        assert!(Listener::bind(&fixture.0.join("helper.sock")).is_err());
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
    }
}
