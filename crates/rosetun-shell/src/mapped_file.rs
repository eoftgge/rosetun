use std::fs::File;
use std::io;
use std::path::Path;

/// A file mapped read-only into memory, for system files that only an administrator can change,
/// such as fonts: the pages are shared with other processes and loaded only when read.
#[derive(Debug)]
pub struct MappedFile {
    map: memmap2::Mmap,
    /// Kept open with the map: on Windows its sharing mode denies writing, truncating and
    /// deleting the file while it is mapped.
    _file: File,
}

impl AsRef<[u8]> for MappedFile {
    fn as_ref(&self) -> &[u8] {
        &self.map
    }
}

/// Maps `path` when nobody but an administrator can change it while it is mapped; `None` when
/// someone could, so the caller reads it into memory instead.
///
/// A mapped file that shrinks under the mapping crashes the process (SIGBUS), and one that
/// changes breaks the promise of immutable bytes. On Windows the handle is opened without write
/// or delete sharing, so no one can open the file to change it while it is mapped. On Linux
/// the file must be a regular file owned by root and writable by no one else: root replaces
/// such files by rename (package updates), which leaves the mapped inode as it was.
pub fn map_protected_file(path: &Path) -> io::Result<Option<MappedFile>> {
    let Some(file) = open_protected(path)? else {
        return Ok(None);
    };
    // SAFETY: `open_protected` returned the file only when no unprivileged process can write
    // to or truncate it during the mapping (see above). The map is read-only, owned by
    // `MappedFile` together with the file, and unmapped when it is dropped, so no slice from
    // `as_ref` outlives it.
    let map = unsafe { memmap2::Mmap::map(&file) }?;
    Ok(Some(MappedFile { map, _file: file }))
}

#[cfg(windows)]
fn open_protected(path: &Path) -> io::Result<Option<File>> {
    use std::os::windows::fs::OpenOptionsExt as _;

    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    match std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        // Someone has it open for writing: read it instead.
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(not(windows))]
fn open_protected(path: &Path) -> io::Result<Option<File>> {
    use std::os::unix::fs::MetadataExt as _;

    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let protected = metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0;
    Ok(protected.then_some(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("rosetun-mapped-{name}-{}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[cfg(windows)]
    #[test]
    fn a_mapped_file_has_its_bytes_and_cannot_be_changed_while_mapped() {
        let path = temp_file("locked", b"font bytes");
        let mapped = map_protected_file(&path).unwrap().unwrap();
        assert_eq!(mapped.as_ref(), b"font bytes");
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::remove_file(&path).is_err());
        drop(mapped);
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn a_file_open_for_writing_is_not_mapped() {
        let path = temp_file("writer", b"font bytes");
        let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert!(map_protected_file(&path).unwrap().is_none());
        drop(writer);
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn a_file_the_user_can_change_is_not_mapped() {
        let path = temp_file("user", b"font bytes");
        let mapped = map_protected_file(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        // Tests do not run as root, so the file is the user's.
        assert!(mapped.is_none());
    }

    #[test]
    fn a_missing_file_is_not_found() {
        let path = std::env::temp_dir().join("rosetun-mapped-missing.ttf");
        let error = map_protected_file(&path).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
