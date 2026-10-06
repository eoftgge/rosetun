use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub(crate) const LOG_LIMIT: u64 = 10 * 1024 * 1024;

/// Keeps the previous run in `helper.previous.log` and rotates `helper.log`
/// when it exceeds the limit.
pub(crate) struct RotatingFile {
    path: PathBuf,
    previous: PathBuf,
    file: Option<File>,
    written: u64,
    limit: u64,
}

impl RotatingFile {
    pub(crate) fn open(dir: &Path, limit: u64) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let path = dir.join("helper.log");
        let previous = dir.join("helper.previous.log");
        if path.exists() {
            fs::rename(&path, &previous)?;
        }
        let file = File::create(&path)?;
        Ok(Self {
            path,
            previous,
            file: Some(file),
            written: 0,
            limit,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        drop(self.file.take());
        fs::rename(&self.path, &self.previous)?;
        self.file = Some(File::create(&self.path)?);
        self.written = 0;
        Ok(())
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written > 0 && self.written.saturating_add(buf.len() as u64) > self.limit {
            self.rotate()?;
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("helper log file is unavailable"))?;
        let count = file.write(buf)?;
        self.written += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("helper log file is unavailable"))?
            .flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

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
