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
mod platform {
    use super::*;

    /// TODO
    pub fn connect(_endpoint: &Path) -> io::Result<Connection> {
        Err(io::Error::other(
            "transport for windows is not yet implemented",
        ))
    }

    #[derive(Debug)]
    pub struct Listener;

    impl Listener {
        pub fn bind(_endpoint: &Path) -> io::Result<Self> {
            Err(io::Error::other(
                "transport for windows is not yet implemented",
            ))
        }

        pub fn accept(&self) -> io::Result<Connection> {
            Err(io::Error::other(
                "transport for windows is not yet implemented",
            ))
        }

        pub fn path(&self) -> &Path {
            Path::new("")
        }
    }
}

pub use platform::{Listener, connect};