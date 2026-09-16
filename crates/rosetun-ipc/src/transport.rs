use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

pub const ENDPOINT_ENV: &str = "ROSETUN_HELPER_ENDPOINT";

pub fn default_endpoint() -> PathBuf {
    if let Some(custom) = std::env::var_os(ENDPOINT_ENV) {
        return PathBuf::from(custom);
    }
    #[cfg(unix)]
    {
        PathBuf::from("/run/rosetun/helper.sock")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"\\.\pipe\rosetun-helper")
    }
}

pub struct Connection {
    reader: BufReader<Box<dyn Read + Send>>,
    writer: Box<dyn Write + Send>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Connection")
    }
}

impl Connection {
    pub fn new(reader: Box<dyn Read + Send>, writer: Box<dyn Write + Send>) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
        }
    }

    pub fn read(&mut self) -> Result<Option<crate::Frame>, crate::CodecError> {
        crate::read_frame(&mut self.reader)
    }

    pub fn write(&mut self, frame: &crate::Frame) -> Result<(), crate::CodecError> {
        crate::write_frame(&mut self.writer, frame)
    }
}

#[cfg(unix)]
mod platform {
    use std::os::unix::net::{UnixListener, UnixStream};

    use super::*;

    pub fn connect(endpoint: &Path) -> io::Result<Connection> {
        let stream = UnixStream::connect(endpoint)?;
        let writer = stream.try_clone()?;
        Ok(Connection::new(Box::new(stream), Box::new(writer)))
    }

    #[derive(Debug)]
    pub struct Listener {
        inner: UnixListener,
        path: PathBuf,
    }

    impl Listener {
        pub fn bind(endpoint: &Path) -> io::Result<Self> {
            if let Some(parent) = endpoint.parent() {
                std::fs::create_dir_all(parent)?;
            }
            match std::fs::remove_file(endpoint) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let inner = UnixListener::bind(endpoint)?;
            Ok(Self {
                inner,
                path: endpoint.to_path_buf(),
            })
        }

        pub fn accept(&self) -> io::Result<Connection> {
            let (stream, _addr) = self.inner.accept()?;
            let writer = stream.try_clone()?;
            Ok(Connection::new(Box::new(stream), Box::new(writer)))
        }

        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod platform {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::sync::Mutex;

    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE,
        GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, WaitNamedPipeW,
    };

    use super::*;

    const BUFFER_SIZE: u32 = 64 * 1024;
    const CONNECT_ATTEMPTS: u32 = 3;
    const CONNECT_WAIT_MS: u32 = 2_000;

    // The transport is local-only and must not use the permissive default pipe
    // DACL. A later IPC authentication phase can narrow this further to the
    // launching user when the helper becomes a long-lived service.
    const SECURITY_DESCRIPTOR_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn ConnectNamedPipe(named_pipe: HANDLE, overlapped: *mut c_void) -> i32;
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn wide_string(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_error() -> io::Error {
        io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
    }

    fn security_descriptor() -> io::Result<*mut c_void> {
        let sddl = wide_string(SECURITY_DESCRIPTOR_SDDL);
        let mut descriptor = std::ptr::null_mut();

        let result = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            return Err(last_error());
        }

        Ok(descriptor)
    }

    fn create_instance(name: &[u16], first: bool) -> io::Result<OwnedHandle> {
        let mut open_mode = PIPE_ACCESS_DUPLEX;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }

        let descriptor = if first {
            Some(security_descriptor()?)
        } else {
            None
        };
        let attributes = descriptor.map(|descriptor| SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        });
        let attributes = attributes.as_ref().map_or(std::ptr::null(), |value| value);

        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                attributes,
            )
        };

        if let Some(descriptor) = descriptor {
            unsafe {
                LocalFree(descriptor);
            }
        }

        if handle == INVALID_HANDLE_VALUE {
            let error = last_error();
            if first && error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "a named pipe with this endpoint already exists",
                ));
            }
            return Err(error);
        }

        Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
    }

    fn wait_for_connection(handle: &OwnedHandle) -> io::Result<()> {
        let handle = handle.as_raw_handle() as HANDLE;
        let result = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
        if result != 0 {
            return Ok(());
        }

        let error = last_error();
        if error.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn connection_from_handle(handle: OwnedHandle) -> io::Result<Connection> {
        let reader = std::fs::File::from(handle);
        let writer = reader.try_clone()?;

        Ok(Connection::new(Box::new(reader), Box::new(writer)))
    }

    pub fn connect(endpoint: &Path) -> io::Result<Connection> {
        let name = wide_path(endpoint);

        for attempt in 0..CONNECT_ATTEMPTS {
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };

            if handle != INVALID_HANDLE_VALUE {
                let handle = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
                return connection_from_handle(handle);
            }

            let error = last_error();
            if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32)
                || attempt + 1 == CONNECT_ATTEMPTS
            {
                return Err(error);
            }

            let available = unsafe { WaitNamedPipeW(name.as_ptr(), CONNECT_WAIT_MS) };
            if available == 0 {
                return Err(last_error());
            }
        }

        unreachable!("connection attempts always return or succeed")
    }

    #[derive(Debug)]
    pub struct Listener {
        name: Vec<u16>,
        path: PathBuf,
        pending: Mutex<Option<OwnedHandle>>,
    }

    impl Listener {
        pub fn bind(endpoint: &Path) -> io::Result<Self> {
            let name = wide_path(endpoint);
            let pending = create_instance(&name, true)?;

            Ok(Self {
                name,
                path: endpoint.to_path_buf(),
                pending: Mutex::new(Some(pending)),
            })
        }

        pub fn accept(&self) -> io::Result<Connection> {
            let pending = self
                .pending
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .take()
                .unwrap_or(create_instance(&self.name, false)?);

            wait_for_connection(&pending)?;

            let replacement = create_instance(&self.name, false)?;
            let mut slot = self
                .pending
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            *slot = Some(replacement);
            drop(slot);

            connection_from_handle(pending)
        }

        pub fn path(&self) -> &Path {
            &self.path
        }
    }
}

pub use platform::{Listener, connect};

#[cfg(all(test, windows))]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;

    use crate::{Connection, Frame, Listener, Request, Response, connect};

    static NEXT_ENDPOINT_ID: AtomicU64 = AtomicU64::new(0);

    fn test_endpoint() -> PathBuf {
        let id = NEXT_ENDPOINT_ID.fetch_add(1, Ordering::Relaxed);
        PathBuf::from(format!(
            r"\\.\pipe\rosetun-ipc-test-{}-{id}",
            std::process::id()
        ))
    }

    fn roundtrip(connection: &mut Connection, id: u64) {
        let request = Frame::Request {
            id,
            body: Request::Hello {
                client: "rosetun-ipc-test".to_owned(),
                protocol_version: 1,
            },
        };
        connection.write(&request).expect("request is written");

        assert_eq!(
            connection.read().expect("response is read"),
            Some(Frame::Response {
                id,
                body: Response::Hello {
                    helper_version: "test".to_owned(),
                    protocol_version: 1,
                },
            })
        );
    }

    #[test]
    fn listener_accepts_sequential_clients_without_mixing_frames() {
        let endpoint = test_endpoint();
        let listener = Listener::bind(&endpoint).expect("listener is bound");

        let server = std::thread::spawn(move || {
            for id in [1, 2] {
                let mut connection = listener.accept().expect("client is accepted");

                assert_eq!(
                    connection.read().expect("request is read"),
                    Some(Frame::Request {
                        id,
                        body: Request::Hello {
                            client: "rosetun-ipc-test".to_owned(),
                            protocol_version: 1,
                        },
                    })
                );

                connection
                    .write(&Frame::Response {
                        id,
                        body: Response::Hello {
                            helper_version: "test".to_owned(),
                            protocol_version: 1,
                        },
                    })
                    .expect("response is written");
            }
        });

        let mut first = connect(&endpoint).expect("first client connects");
        roundtrip(&mut first, 1);
        drop(first);

        let mut second = connect(&endpoint).expect("second client connects");
        roundtrip(&mut second, 2);
        drop(second);

        server.join().expect("server thread completes");
    }

    #[test]
    fn disconnected_client_does_not_stop_the_listener() {
        let endpoint = test_endpoint();
        let listener = Listener::bind(&endpoint).expect("listener is bound");
        let (first_accept_failed, first_accept_failed_rx) = mpsc::channel();

        let server = std::thread::spawn(move || {
            let error = listener
                .accept()
                .expect_err("closed client causes the first accept to fail");
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
            first_accept_failed
                .send(())
                .expect("test observes the failed accept");

            let mut second = listener.accept().expect("second client is accepted");
            assert_eq!(
                second.read().expect("second request is read"),
                Some(Frame::Request {
                    id: 2,
                    body: Request::Hello {
                        client: "rosetun-ipc-test".to_owned(),
                        protocol_version: 1,
                    },
                })
            );
            second
                .write(&Frame::Response {
                    id: 2,
                    body: Response::Hello {
                        helper_version: "test".to_owned(),
                        protocol_version: 1,
                    },
                })
                .expect("second response is written");
        });

        drop(connect(&endpoint).expect("first client connects"));
        first_accept_failed_rx
            .recv()
            .expect("server observed the failed first accept");

        let mut second = connect(&endpoint).expect("second client connects");
        roundtrip(&mut second, 2);
        drop(second);

        server.join().expect("server thread completes");
    }
}
