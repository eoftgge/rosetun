use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rosetun-helper-lists-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn store(&self) -> ListStore {
        ListStore::open_for_test(self.0.clone()).unwrap()
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn chunk(
    store: &mut ListStore,
    owner: u64,
    hash: &str,
    format: ListFormat,
    bytes: &[u8],
    offset: u64,
    total: u64,
    now: Instant,
) -> Result<(), HelperError> {
    store.put_chunk(
        owner,
        hash,
        format,
        total,
        offset,
        &base64::engine::general_purpose::STANDARD.encode(bytes),
        now,
    )
}

#[test]
fn chunks_are_sequential_verified_and_persist_after_restart() {
    let directory = TestDirectory::new();
    let mut store = directory.store();
    let bytes = b"SRS\x05example";
    let digest = hash(bytes);
    let now = Instant::now();
    assert_eq!(
        store.status(std::slice::from_ref(&digest), now).unwrap(),
        [digest.clone()]
    );
    chunk(
        &mut store,
        1,
        &digest,
        ListFormat::Binary,
        &bytes[..5],
        0,
        bytes.len() as u64,
        now,
    )
    .unwrap();
    assert_eq!(store.uploads.len(), 1);
    chunk(
        &mut store,
        1,
        &digest,
        ListFormat::Binary,
        &bytes[5..],
        5,
        bytes.len() as u64,
        now,
    )
    .unwrap();
    assert!(store.uploads.is_empty());
    assert!(
        store
            .status(std::slice::from_ref(&digest), now)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fs::read(store.object_path(&digest, ListFormat::Binary)).unwrap(),
        bytes
    );
    drop(store);
    let mut restarted = directory.store();
    assert!(restarted.status(&[digest], now).unwrap().is_empty());
}

#[test]
fn bad_offset_and_hash_remove_partial_files() {
    let directory = TestDirectory::new();
    let mut store = directory.store();
    let now = Instant::now();
    let bytes = b"SRS\x05example";
    let digest = hash(bytes);
    chunk(
        &mut store,
        1,
        &digest,
        ListFormat::Binary,
        &bytes[..5],
        0,
        bytes.len() as u64,
        now,
    )
    .unwrap();
    let partial = store.uploads.values().next().unwrap().path.clone();
    assert!(
        chunk(
            &mut store,
            1,
            &digest,
            ListFormat::Binary,
            &bytes[5..],
            4,
            bytes.len() as u64,
            now
        )
        .is_err()
    );
    assert!(store.uploads.is_empty());
    assert!(!partial.exists());
    assert_eq!(store.used_bytes, 0);

    assert!(
        chunk(
            &mut store,
            1,
            &"0".repeat(64),
            ListFormat::Binary,
            bytes,
            0,
            bytes.len() as u64,
            now
        )
        .is_err()
    );
    assert!(store.uploads.is_empty());
    assert!(store.status(&[digest], now).unwrap().len() == 1);
}

#[test]
fn invalid_source_never_becomes_an_object() {
    let directory = TestDirectory::new();
    let mut store = directory.store();
    let now = Instant::now();
    for bytes in [
        br#"{"version":3,"rules":[{"unknown":["example.com"]}]}"#.as_slice(),
        br#"{"rules":[{"domain":["example.com"]}],"version":3} "#.as_slice(),
    ] {
        let digest = hash(bytes);
        assert!(
            chunk(
                &mut store,
                1,
                &digest,
                ListFormat::Source,
                bytes,
                0,
                bytes.len() as u64,
                now
            )
            .is_err()
        );
        assert!(!store.object_path(&digest, ListFormat::Source).exists());
        assert!(store.uploads.is_empty());
    }
}

#[test]
fn upload_limit_and_idle_expiry_free_partial_files() {
    let directory = TestDirectory::new();
    let mut store = directory.store();
    let now = Instant::now();
    for owner in 0..4 {
        chunk(
            &mut store,
            owner,
            &format!("{owner:064x}"),
            ListFormat::Binary,
            b"S",
            0,
            4,
            now,
        )
        .unwrap();
    }
    assert!(
        chunk(
            &mut store,
            5,
            &"5".repeat(64),
            ListFormat::Binary,
            b"S",
            0,
            4,
            now
        )
        .is_err()
    );
    assert_eq!(store.uploads.len(), 4);
    store.expire(now + IDLE_TIMEOUT);
    assert!(store.uploads.is_empty());
    assert_eq!(store.used_bytes, 0);
}

#[test]
fn pinned_objects_are_not_evicted() {
    let directory = TestDirectory::new();
    let mut store = directory.store();
    let key = ("a".repeat(64), ListFormat::Binary);
    let path = store.object_path(&key.0, key.1);
    fs::write(&path, b"SRS\x05").unwrap();
    store.objects.insert(
        key.clone(),
        Stored {
            size: MAX_STORE_BYTES,
            last_used: SystemTime::UNIX_EPOCH,
        },
    );
    store.used_bytes = MAX_STORE_BYTES;
    store.pin(&[ListRef {
        tag: "list-test".into(),
        sha256: key.0.clone(),
        format: key.1,
    }]);
    assert!(store.make_room(1, false).is_err());
    assert!(path.exists());
    store.pin(&[]);
    store.make_room(1, false).unwrap();
    assert!(!path.exists());
}

#[test]
fn startup_removes_only_incomplete_upload_files() {
    let directory = TestDirectory::new();
    fs::write(directory.0.join(".upload-1-1.part"), b"secret").unwrap();
    fs::write(directory.0.join("unrelated.txt"), b"keep").unwrap();
    let store = directory.store();
    assert!(!directory.0.join(".upload-1-1.part").exists());
    assert!(directory.0.join("unrelated.txt").exists());
    assert_eq!(store.used_bytes, 0);
}
