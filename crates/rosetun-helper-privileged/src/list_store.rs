use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use rosetun_config::{ListRef, UploadedListFormat as ListFormat};
use rosetun_ipc::{ErrorCode, HelperError, MAX_LIST_CHUNK_BYTES, MAX_LIST_PAYLOAD_BYTES};
use sha2::{Digest, Sha256};

const MAX_STORE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_IN_PROGRESS: usize = 4;
const MAX_STORED_FILES: usize = 4096;
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_REFERENCES: usize = 256;
static NEXT_UPLOAD: AtomicU64 = AtomicU64::new(0);

type ObjectKey = (String, ListFormat);
type UploadKey = (u64, String, ListFormat);

struct Upload {
    file: File,
    path: PathBuf,
    total_size: u64,
    received: u64,
    last_chunk: Instant,
}

struct Stored {
    size: u64,
    last_used: SystemTime,
}

pub(crate) struct ListStore {
    directory: PathBuf,
    objects: HashMap<ObjectKey, Stored>,
    uploads: HashMap<UploadKey, Upload>,
    pinned: HashSet<ObjectKey>,
    used_bytes: u64,
}

impl std::fmt::Debug for ListStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListStore")
            .field("object_count", &self.objects.len())
            .field("upload_count", &self.uploads.len())
            .field("used_bytes", &self.used_bytes)
            .finish()
    }
}

fn invalid(message: &'static str) -> HelperError {
    HelperError::new(ErrorCode::InvalidState, message)
}

fn internal() -> HelperError {
    HelperError::new(
        ErrorCode::Internal,
        "could not access the service list store",
    )
}

fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_LIST_PAYLOAD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LIST_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "list is too large",
        ));
    }
    Ok(bytes)
}

pub(crate) fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

impl ListStore {
    pub(crate) fn open(directory: PathBuf) -> io::Result<Self> {
        #[cfg(windows)]
        crate::data_dir::secure(&directory)?;
        #[cfg(not(windows))]
        fs::create_dir_all(&directory)?;
        Self::load(directory)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(directory: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&directory)?;
        Self::load(directory)
    }

    fn load(directory: PathBuf) -> io::Result<Self> {
        let mut store = Self {
            directory,
            objects: HashMap::new(),
            uploads: HashMap::new(),
            pinned: HashSet::new(),
            used_bytes: 0,
        };
        for entry in fs::read_dir(&store.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".upload-") && name.ends_with(".part") {
                fs::remove_file(entry.path())?;
                continue;
            }
            let Some((hash, extension)) = name.rsplit_once('.') else {
                continue;
            };
            let format = match extension {
                "srs" => ListFormat::Binary,
                "json" => ListFormat::Source,
                _ => continue,
            };
            if !valid_hash(hash) || !entry.file_type()?.is_file() {
                continue;
            }
            let metadata = entry.metadata()?;
            store.used_bytes = store.used_bytes.saturating_add(metadata.len());
            store.objects.insert(
                (hash.to_owned(), format),
                Stored {
                    size: metadata.len(),
                    last_used: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                },
            );
        }
        store
            .make_room(0, false)
            .map_err(|_| io::Error::other("could not enforce the list storage quota"))?;
        while store.objects.len() > MAX_STORED_FILES {
            store
                .make_room(0, true)
                .map_err(|_| io::Error::other("could not enforce the list storage quota"))?;
        }
        Ok(store)
    }

    fn object_path(&self, hash: &str, format: ListFormat) -> PathBuf {
        self.directory
            .join(format!("{hash}.{}", format.extension()))
    }

    pub(crate) fn status(
        &mut self,
        hashes: &[String],
        now: Instant,
    ) -> Result<Vec<String>, HelperError> {
        self.expire(now);
        if hashes.len() > MAX_REFERENCES || hashes.iter().any(|hash| !valid_hash(hash)) {
            return Err(invalid("invalid list hashes"));
        }
        let mut missing = Vec::new();
        let mut seen = HashSet::new();
        for hash in hashes {
            if !seen.insert(hash) {
                continue;
            }
            let formats: Vec<_> = self
                .objects
                .keys()
                .filter(|(stored, _)| stored == hash)
                .map(|(_, format)| *format)
                .collect();
            let mut present = false;
            for format in formats {
                let reference = ListRef {
                    tag: "list-status".to_owned(),
                    sha256: hash.clone(),
                    format,
                };
                if self.verified_path(&reference).is_ok() {
                    present = true;
                    continue;
                }
                let path = self.object_path(hash, format);
                if let Err(error) = fs::remove_file(path)
                    && error.kind() != io::ErrorKind::NotFound
                {
                    return Err(internal());
                }
                let removed = self
                    .objects
                    .remove(&(hash.clone(), format))
                    .expect("indexed list exists");
                self.used_bytes -= removed.size;
                tracing::warn!(hash = %&hash[..12], ?format, bytes = removed.size, "invalid list removed");
            }
            if !present {
                missing.push(hash.clone());
            }
        }
        Ok(missing)
    }

    pub(crate) fn put_chunk(
        &mut self,
        owner: u64,
        hash: &str,
        format: ListFormat,
        total_size: u64,
        offset: u64,
        encoded: &str,
        now: Instant,
    ) -> Result<(), HelperError> {
        self.expire(now);
        let result = self.put_inner(owner, hash, format, total_size, offset, encoded, now);
        if result.is_err() {
            self.abort_owner(owner);
        }
        result
    }

    fn put_inner(
        &mut self,
        owner: u64,
        hash: &str,
        format: ListFormat,
        total_size: u64,
        offset: u64,
        encoded: &str,
        now: Instant,
    ) -> Result<(), HelperError> {
        if !valid_hash(hash) || total_size == 0 || total_size > MAX_LIST_PAYLOAD_BYTES {
            return Err(invalid("invalid list hash or size"));
        }
        if encoded.len() > 4 * MAX_LIST_CHUNK_BYTES.div_ceil(3) {
            return Err(invalid("list chunk exceeds the 1 MiB limit"));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid("invalid list chunk encoding"))?;
        if bytes.is_empty() || bytes.len() > MAX_LIST_CHUNK_BYTES {
            return Err(invalid("list chunk is empty or exceeds the 1 MiB limit"));
        }
        let key = (owner, hash.to_owned(), format);
        if !self.uploads.contains_key(&key) {
            if offset != 0 || self.uploads.len() >= MAX_IN_PROGRESS {
                return Err(invalid("invalid list offset or too many uploads"));
            }
            let path = self.directory.join(format!(
                ".upload-{}-{}.part",
                std::process::id(),
                NEXT_UPLOAD.fetch_add(1, Ordering::Relaxed)
            ));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|_| internal())?;
            self.uploads.insert(
                key.clone(),
                Upload {
                    file,
                    path,
                    total_size,
                    received: 0,
                    last_chunk: now,
                },
            );
        }
        let upload = self.uploads.get(&key).expect("upload was just created");
        if upload.received != offset
            || upload.total_size != total_size
            || offset
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > total_size)
        {
            return Err(invalid("list chunk has an invalid offset or size"));
        }
        self.make_room(bytes.len() as u64, false)?;
        let upload = self.uploads.get_mut(&key).expect("upload exists");
        upload.file.write_all(&bytes).map_err(|_| internal())?;
        upload.received += bytes.len() as u64;
        upload.last_chunk = now;
        self.used_bytes += bytes.len() as u64;
        if upload.received == total_size {
            self.complete(key)?;
        }
        Ok(())
    }

    fn complete(&mut self, key: UploadKey) -> Result<(), HelperError> {
        let mut upload = self.uploads.remove(&key).expect("completed upload exists");
        let result = (|| {
            upload.file.flush().map_err(|_| internal())?;
            upload.file.sync_all().map_err(|_| internal())?;
            let bytes = fs::read(&upload.path).map_err(|_| internal())?;
            if bytes.len() as u64 != upload.total_size
                || format!("{:x}", Sha256::digest(&bytes)) != key.1
            {
                return Err(invalid("list size or SHA-256 does not match"));
            }
            match key.2 {
                ListFormat::Binary => rosetun_config::validate_srs(&bytes)
                    .map_err(|_| invalid("invalid binary list"))?,
                ListFormat::Source => {
                    let normalized = rosetun_config::normalize_source(&bytes)
                        .map_err(|_| invalid("invalid source list"))?;
                    if normalized != bytes {
                        return Err(invalid("source list must use canonical JSON"));
                    }
                }
            }
            let destination = self.object_path(&key.1, key.2);
            if destination.exists() {
                let existing = read_bounded(&destination).map_err(|_| internal())?;
                if existing != bytes {
                    return Err(invalid("stored list does not match its hash"));
                }
                fs::remove_file(&upload.path).map_err(|_| internal())?;
                self.used_bytes -= upload.received;
            } else {
                self.make_room(0, true)?;
                fs::rename(&upload.path, &destination).map_err(|_| internal())?;
                self.objects.insert(
                    (key.1.clone(), key.2),
                    Stored {
                        size: upload.received,
                        last_used: SystemTime::now(),
                    },
                );
            }
            tracing::info!(hash = %&key.1[..12], format = ?key.2, bytes = upload.received, "list stored");
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&upload.path);
            self.used_bytes -= upload.received;
        }
        result
    }

    fn make_room(&mut self, extra: u64, new_object: bool) -> Result<(), HelperError> {
        while self.used_bytes.saturating_add(extra) > MAX_STORE_BYTES
            || (new_object && self.objects.len() >= MAX_STORED_FILES)
        {
            let Some(key) = self
                .objects
                .iter()
                .filter(|(key, _)| !self.pinned.contains(*key))
                .min_by_key(|(_, object)| object.last_used)
                .map(|(key, _)| key.clone())
            else {
                return Err(invalid("list storage quota is full"));
            };
            fs::remove_file(self.object_path(&key.0, key.1)).map_err(|_| internal())?;
            let old = self.objects.remove(&key).expect("evicted object exists");
            self.used_bytes -= old.size;
            tracing::info!(hash = %&key.0[..12], format = ?key.1, bytes = old.size, "list evicted");
        }
        Ok(())
    }

    pub(crate) fn expire(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .uploads
            .iter()
            .filter(|(_, upload)| now.saturating_duration_since(upload.last_chunk) >= IDLE_TIMEOUT)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.remove_upload(&key);
        }
    }

    pub(crate) fn abort_owner(&mut self, owner: u64) {
        let keys: Vec<_> = self
            .uploads
            .keys()
            .filter(|(current, _, _)| *current == owner)
            .cloned()
            .collect();
        for key in keys {
            self.remove_upload(&key);
        }
    }

    fn remove_upload(&mut self, key: &UploadKey) {
        if let Some(upload) = self.uploads.remove(key) {
            drop(upload.file);
            self.used_bytes -= upload.received;
            if let Err(error) = fs::remove_file(upload.path)
                && error.kind() != io::ErrorKind::NotFound
            {
                tracing::warn!(hash = %&key.1[..12], format = ?key.2, "could not remove partial list");
            }
        }
    }

    pub(crate) fn pin(&mut self, refs: &[ListRef]) {
        self.pinned = refs
            .iter()
            .map(|item| (item.sha256.clone(), item.format))
            .collect();
        let now = SystemTime::now();
        for key in &self.pinned {
            if let Some(object) = self.objects.get_mut(key) {
                object.last_used = now;
            }
        }
    }

    pub(crate) fn verified_path(&mut self, reference: &ListRef) -> Result<PathBuf, HelperError> {
        if !valid_hash(&reference.sha256) || !valid_tag(&reference.tag) {
            return Err(invalid("invalid list reference"));
        }
        let key = (reference.sha256.clone(), reference.format);
        let path = self.object_path(&reference.sha256, reference.format);
        let Some(object) = self.objects.get_mut(&key) else {
            return Err(HelperError::new(
                ErrorCode::ListMissing,
                "a required list is unavailable",
            ));
        };
        let bytes = read_bounded(&path).map_err(|_| {
            HelperError::new(ErrorCode::ListMissing, "a required list is unavailable")
        })?;
        if bytes.len() as u64 != object.size
            || bytes.len() as u64 > MAX_LIST_PAYLOAD_BYTES
            || format!("{:x}", Sha256::digest(&bytes)) != reference.sha256
        {
            return Err(HelperError::new(
                ErrorCode::ListMissing,
                "a required list is invalid",
            ));
        }
        object.last_used = SystemTime::now();
        Ok(path)
    }
}

#[cfg(test)]
mod tests;
