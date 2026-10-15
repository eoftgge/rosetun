use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE};

pub(crate) const LOG_LIMIT: u64 = 10 * 1024 * 1024;
pub(crate) const REPORT_LOG_LIMIT: usize = 1024 * 1024;

pub(crate) fn report_tail(dir: &Path) -> io::Result<String> {
    let current = read_tail(&dir.join("helper.log"), REPORT_LOG_LIMIT)?;
    let previous = read_tail(
        &dir.join("helper.previous.log"),
        REPORT_LOG_LIMIT.saturating_sub(current.len() + usize::from(!current.is_empty())),
    )?;
    let mut combined = previous;
    if !combined.is_empty() && !current.is_empty() {
        combined.push(b'\n');
    }
    combined.extend_from_slice(&current);
    Ok(String::from_utf8_lossy(&combined).into_owned())
}

fn read_tail(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut file = match OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let length = file.metadata()?.len();
    let count = length.min(limit as u64) as usize;
    file.seek(SeekFrom::Start(length - count as u64))?;
    let mut tail = Vec::with_capacity(count);
    file.take(count as u64).read_to_end(&mut tail)?;
    Ok(tail)
}

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
    fn report_tail_keeps_only_the_latest_megabyte_across_both_files() {
        let dir = TestDir::new();
        fs::write(dir.0.join("helper.previous.log"), vec![b'p'; REPORT_LOG_LIMIT]).unwrap();
        fs::write(dir.0.join("helper.log"), vec![b'c'; 32]).unwrap();
        let text = report_tail(&dir.0).unwrap();
        assert_eq!(text.len(), REPORT_LOG_LIMIT);
        assert!(text.starts_with('p'));
        assert!(text.ends_with(&"c".repeat(32)));

        fs::write(dir.0.join("helper.log"), vec![b'n'; REPORT_LOG_LIMIT + 32]).unwrap();
        let text = report_tail(&dir.0).unwrap();
        assert_eq!(text, "n".repeat(REPORT_LOG_LIMIT));
    }

    #[test]
    fn report_tail_reads_current_open_log_and_missing_previous() {
        let dir = TestDir::new();
        let mut log = RotatingFile::open(&dir.0, LOG_LIMIT).unwrap();
        log.write_all(b"2001:db8::1\n").unwrap();
        assert_eq!(report_tail(&dir.0).unwrap(), "2001:db8::1\n");
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
