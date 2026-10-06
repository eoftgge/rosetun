use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub(crate) const LOG_LIMIT: u64 = 10 * 1024 * 1024;

/// Keeps the previous run in `helper.previous.log` and rotates `helper.log`
/// when it exceeds the limit.
pub(crate) struct RotatingFile {
    path: PathBuf,
    previous: PathBuf,
    file: File,
    written: u64,
    limit: u64,
}

impl RotatingFile {
    pub(crate) fn open(dir: &Path, limit: u64) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let path = dir.join("helper.log");
        let previous = dir.join("helper.previous.log");
        let (file, written) = if path.exists() && fs::rename(&path, &previous).is_err() {
            let file = OpenOptions::new().create(true).append(true).open(&path)?;
            let written = file.metadata()?.len();
            (file, written)
        } else {
            (File::create(&path)?, 0)
        };
        Ok(Self {
            path,
            previous,
            file,
            written,
            limit,
        })
    }

    fn rotate(&mut self) {
        // Keeping the log writable matters more than bounding its size when a file is held open.
        if fs::rename(&self.path, &self.previous).is_ok()
            && let Ok(file) = File::create(&self.path)
        {
            self.file = file;
        }
        self.written = 0;
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written > 0 && self.written.saturating_add(buf.len() as u64) > self.limit {
            self.rotate();
        }
        let count = self.file.write(buf)?;
        self.written += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("rosetun-log-{}-{id}", std::process::id()));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove test directory");
        }
    }

    #[test]
    fn open_saves_the_last_run() {
        let dir = TestDir::new();
        fs::write(dir.0.join("helper.log"), b"earlier run").unwrap();
        let mut log = RotatingFile::open(&dir.0, 20).unwrap();
        log.write_all(b"new run").unwrap();
        drop(log);
        assert_eq!(
            fs::read(dir.0.join("helper.previous.log")).unwrap(),
            b"earlier run"
        );
        assert_eq!(fs::read(dir.0.join("helper.log")).unwrap(), b"new run");
    }

    #[test]
    fn open_appends_when_the_existing_log_is_held_open() {
        let dir = TestDir::new();
        let path = dir.0.join("helper.log");
        fs::write(&path, b"earlier").unwrap();
        let _reader = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path)
            .unwrap();

        let mut log = RotatingFile::open(&dir.0, 20).unwrap();
        log.write_all(b"later").unwrap();
        drop(log);
        assert_eq!(fs::read(path).unwrap(), b"earlierlater");
        assert!(!dir.0.join("helper.previous.log").exists());
    }

    #[test]
    fn crossing_limit_rotates_before_writing() {
        let dir = TestDir::new();
        let mut log = RotatingFile::open(&dir.0, 5).unwrap();
        log.write_all(b"first").unwrap();
        log.write_all(b"second").unwrap();
        drop(log);
        assert_eq!(
            fs::read(dir.0.join("helper.previous.log")).unwrap(),
            b"first"
        );
        assert_eq!(fs::read(dir.0.join("helper.log")).unwrap(), b"second");
    }

    #[test]
    fn rotation_keeps_writing_when_the_log_is_held_open() {
        let dir = TestDir::new();
        let path = dir.0.join("helper.log");
        let mut log = RotatingFile::open(&dir.0, 5).unwrap();
        log.write_all(b"first").unwrap();
        let _reader = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path)
            .unwrap();

        log.write_all(b"second").unwrap();
        drop(log);
        assert_eq!(fs::read(path).unwrap(), b"firstsecond");
        assert!(!dir.0.join("helper.previous.log").exists());
    }

    #[test]
    fn first_write_may_exceed_limit() {
        let dir = TestDir::new();
        let mut log = RotatingFile::open(&dir.0, 5).unwrap();
        log.write_all(b"long first write").unwrap();
        drop(log);
        assert!(!dir.0.join("helper.previous.log").exists());
        assert_eq!(
            fs::read(dir.0.join("helper.log")).unwrap(),
            b"long first write"
        );
    }
}
