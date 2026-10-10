mod formats;
mod prepare;

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rosetun_config::{List, ListCategoryError, ListId, ListSource, RuleMatcher};
use sha2::{Digest, Sha256};

use crate::{FetchError, Store, StoreError, Timeouts};

pub use formats::{ListParseError, ListPayload, PayloadFormat};
pub use prepare::{
    ListOperation, ListPreparationError, PreparedConnection, PreparedListPayload, prepare_lists,
    send_prepared,
};

pub const MAX_LIST_BYTES: usize = 32 * 1024 * 1024;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum ListError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("invalid list URL")]
    InvalidUrl,
    #[error("list name must not be empty")]
    EmptyName,
    #[error("local file name must not be empty")]
    EmptyFileName,
    #[error("list does not exist")]
    NotFound,
    #[error("this list URL has already been added")]
    AlreadyExists,
    #[error("this list needs a new local file to update")]
    FileRequired,
    #[error("this update does not match the list source")]
    WrongSource,
    #[error("list source or contents changed while the update was being prepared; retry")]
    ChangedDuringUpdate,
    #[error("list is used by rule sets: {}", .sets.join(", "))]
    InUse { sets: Vec<String> },
    #[error("list exceeds the 32 MiB size limit")]
    TooLarge,
    #[error("the stored list does not match its saved checksum and size")]
    Integrity,
    #[error(transparent)]
    Category(#[from] ListCategoryError),
    #[error(transparent)]
    Parse(#[from] ListParseError),
    #[error("list request failed: {0}")]
    Fetch(#[from] FetchError),
    #[error("could not access list data: {0}")]
    Io(#[from] io::Error),
    #[error("system clock is before the Unix epoch")]
    Clock(#[from] std::time::SystemTimeError),
}

pub type UpdateListError = ListError;
pub type ListUpdateResult = (ListId, Result<List, UpdateListError>);

struct CommittedList {
    current: List,
    previous: Option<List>,
}

fn list_dir(store: &Store) -> Result<PathBuf, ListError> {
    let parent = store.path().parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration path has no directory",
        )
    })?;
    Ok(parent.join("lists"))
}

fn list_path(directory: &Path, list: &List) -> PathBuf {
    directory.join(format!("{}.{}", list.id, list.format.extension()))
}

fn previous_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".previous");
    PathBuf::from(name)
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(
        ".tmp-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    PathBuf::from(name)
}

fn checksum(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_verified(directory: &Path, list: &List) -> Result<Vec<u8>, ListError> {
    let mut bytes = Vec::new();
    fs::File::open(list_path(directory, list))?
        .take(MAX_LIST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_LIST_BYTES
        || list.size != Some(bytes.len() as u64)
        || list.sha256.as_deref() != Some(checksum(&bytes).as_str())
    {
        return Err(ListError::Integrity);
    }
    Ok(bytes)
}

fn current_time() -> Result<u64, ListError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn file_name(name: &str) -> Result<String, ListError> {
    let name = name.rsplit(['/', '\\']).next().unwrap_or("").trim();
    if name.is_empty() || matches!(name, "." | "..") {
        return Err(ListError::EmptyFileName);
    }
    Ok(name.to_owned())
}

fn next_id(config: &rosetun_config::AppConfig) -> ListId {
    let occupied: HashSet<_> = config.lists.iter().map(|list| list.id.as_str()).collect();
    let mut value = 1_u64;
    loop {
        let id = value.to_string();
        if !occupied.contains(id.as_str()) {
            return ListId::new(id);
        }
        value += 1;
    }
}

fn publish_file(directory: &Path, change: &CommittedList, bytes: &[u8]) -> Result<(), ListError> {
    fs::create_dir_all(directory)?;
    let destination = list_path(directory, &change.current);
    let temp = temporary_path(&destination);
    let result = (|| -> Result<(), ListError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);

        let old = change
            .previous
            .as_ref()
            .map(|list| list_path(directory, list));
        if old.as_ref() != Some(&destination) && destination.exists() {
            return Err(
                io::Error::new(io::ErrorKind::AlreadyExists, "list path already exists").into(),
            );
        }
        let old_exists = match old.as_deref().map(fs::symlink_metadata) {
            Some(Ok(_)) => true,
            Some(Err(error)) if error.kind() == io::ErrorKind::NotFound => false,
            Some(Err(error)) => return Err(error.into()),
            None => false,
        };
        if let Some(old) = old.as_ref().filter(|_| old_exists) {
            let backup = previous_path(old);
            if backup.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "list backup already exists",
                )
                .into());
            }
            fs::rename(old, &backup)?;
        }
        if let Err(error) = fs::rename(&temp, &destination) {
            if let Some(old) = old.filter(|_| old_exists) {
                fs::rename(previous_path(&old), old)?;
            }
            return Err(error.into());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn rollback_file(directory: &Path, change: &CommittedList) -> Result<(), ListError> {
    let current = list_path(directory, &change.current);
    fs::remove_file(current)?;
    if let Some(previous) = &change.previous {
        let old = list_path(directory, previous);
        let backup = previous_path(&old);
        if backup.exists() {
            fs::rename(backup, old)?;
        }
    }
    Ok(())
}

fn cleanup_previous(directory: &Path, previous: Option<&List>) {
    if let Some(previous) = previous {
        let path = previous_path(&list_path(directory, previous));
        if let Err(error) = fs::remove_file(path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(%error, "could not remove previous list data");
        }
    }
}

fn commit_list(
    store: &Store,
    requested: Option<&List>,
    name: String,
    source: ListSource,
    inspected: formats::InspectedList,
    updated_at: u64,
) -> Result<List, ListError> {
    let directory = list_dir(store)?;
    let size = inspected.bytes.len() as u64;
    let sha256 = checksum(&inspected.bytes);
    let formats::InspectedList {
        format,
        categories,
        bytes,
    } = inspected;
    let change = store.modify_with_sidecar(
        |config| {
            let previous = if let Some(requested) = requested {
                let current = config
                    .lists
                    .iter()
                    .find(|item| item.id == requested.id)
                    .ok_or(ListError::NotFound)?;
                if current.source != requested.source
                    || current.sha256 != requested.sha256
                    || current.size != requested.size
                {
                    return Err(ListError::ChangedDuringUpdate);
                }
                Some(current.clone())
            } else {
                if let ListSource::Url(url) = &source
                    && config
                        .lists
                        .iter()
                        .any(|item| item.source == ListSource::Url(url.clone()))
                {
                    return Err(ListError::AlreadyExists);
                }
                None
            };
            let id = previous
                .as_ref()
                .map_or_else(|| next_id(config), |item| item.id.clone());
            let name = previous.as_ref().map_or(name, |item| item.name.clone());
            let current = List {
                id,
                name,
                source,
                format,
                updated_at: Some(updated_at),
                size: Some(size),
                sha256: Some(sha256),
                categories,
            };
            if let Some(previous) = &previous {
                let index = config
                    .lists
                    .iter()
                    .position(|item| item.id == previous.id)
                    .expect("list exists");
                config.lists[index] = current.clone();
            } else {
                config.lists.push(current.clone());
            }
            Ok::<_, ListError>(CommittedList { current, previous })
        },
        |change| publish_file(&directory, change, &bytes),
        |change| rollback_file(&directory, change),
        |change| cleanup_previous(&directory, change.previous.as_ref()),
    )?;
    Ok(change.current)
}

pub fn add_list_from_url(
    store: &Store,
    input: &str,
    name: &str,
    timeouts: Timeouts,
) -> Result<List, ListError> {
    let parsed = url::Url::parse(input.trim()).map_err(|_| ListError::InvalidUrl)?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(ListError::InvalidUrl);
    }
    let name = if name.trim().is_empty() {
        parsed.host_str().ok_or(ListError::InvalidUrl)?.to_owned()
    } else {
        name.trim().to_owned()
    };
    let bytes = crate::fetch::fetch_list_bytes(parsed.as_str(), timeouts)?;
    let inspected = formats::inspect(&bytes, Some(parsed.path()))?;
    commit_list(
        store,
        None,
        name,
        ListSource::Url(parsed.to_string()),
        inspected,
        current_time()?,
    )
}

pub fn add_list_from_bytes(
    store: &Store,
    name: &str,
    original_name: &str,
    bytes: &[u8],
) -> Result<List, ListError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ListError::EmptyName);
    }
    if bytes.len() > MAX_LIST_BYTES {
        return Err(ListError::TooLarge);
    }
    let original_name = file_name(original_name)?;
    let inspected = formats::inspect(bytes, Some(&original_name))?;
    commit_list(
        store,
        None,
        name.to_owned(),
        ListSource::File { original_name },
        inspected,
        current_time()?,
    )
}

pub fn update_list(
    store: &Store,
    id: &ListId,
    replacement: Option<(&str, &[u8])>,
    timeouts: Timeouts,
) -> Result<List, UpdateListError> {
    update_list_with(
        store,
        id,
        replacement,
        timeouts,
        &mut crate::fetch::fetch_list_bytes,
    )
}

fn update_list_with(
    store: &Store,
    id: &ListId,
    replacement: Option<(&str, &[u8])>,
    timeouts: Timeouts,
    fetch: &mut impl FnMut(&str, Timeouts) -> Result<Vec<u8>, FetchError>,
) -> Result<List, UpdateListError> {
    let requested = store
        .load()?
        .lists
        .into_iter()
        .find(|item| &item.id == id)
        .ok_or(ListError::NotFound)?;
    let (bytes, name, source) = match (&requested.source, replacement) {
        (ListSource::Url(url), None) => (
            fetch(url, timeouts)?,
            url::Url::parse(url)
                .map_err(|_| ListError::InvalidUrl)?
                .path()
                .to_owned(),
            requested.source.clone(),
        ),
        (ListSource::File { .. }, Some((original_name, bytes))) => {
            if bytes.len() > MAX_LIST_BYTES {
                return Err(ListError::TooLarge);
            }
            let original_name = file_name(original_name)?;
            (
                bytes.to_vec(),
                original_name.clone(),
                ListSource::File { original_name },
            )
        }
        (ListSource::File { .. }, None) => return Err(ListError::FileRequired),
        (ListSource::Url(_), Some(_)) => return Err(ListError::WrongSource),
    };
    let inspected = formats::inspect(&bytes, Some(&name))?;
    commit_list(
        store,
        Some(&requested),
        requested.name.clone(),
        source,
        inspected,
        current_time()?,
    )
}

pub fn update_all_lists(
    store: &Store,
    timeouts: Timeouts,
) -> Result<Vec<ListUpdateResult>, StoreError> {
    update_all_lists_with(store, timeouts, &mut crate::fetch::fetch_list_bytes)
}

fn update_all_lists_with(
    store: &Store,
    timeouts: Timeouts,
    fetch: &mut impl FnMut(&str, Timeouts) -> Result<Vec<u8>, FetchError>,
) -> Result<Vec<ListUpdateResult>, StoreError> {
    let ids: Vec<_> = store
        .load()?
        .lists
        .into_iter()
        .filter(|list| matches!(list.source, ListSource::Url(_)))
        .map(|list| list.id)
        .collect();
    Ok(ids
        .into_iter()
        .map(|id| {
            let result = update_list_with(store, &id, None, timeouts, fetch);
            (id, result)
        })
        .collect())
}

pub fn rename_list(store: &Store, id: &ListId, name: &str) -> Result<List, ListError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ListError::EmptyName);
    }
    store.modify(|config| {
        let list = config
            .lists
            .iter_mut()
            .find(|item| &item.id == id)
            .ok_or(ListError::NotFound)?;
        list.name = name.to_owned();
        Ok(list.clone())
    })
}

pub fn remove_list(store: &Store, id: &ListId) -> Result<(), ListError> {
    let directory = list_dir(store)?;
    store.modify_with_sidecar(
        |config| {
            let sets: Vec<_> = config
                .rule_sets
                .iter()
                .filter(|set| set.rules.iter().any(|rule| matches!(&rule.matcher, RuleMatcher::List { list, .. } if list == id)))
                .map(|set| set.name.clone())
                .collect();
            if !sets.is_empty() {
                return Err(ListError::InUse { sets });
            }
            let index = config.lists.iter().position(|item| &item.id == id).ok_or(ListError::NotFound)?;
            Ok::<_, ListError>(config.lists.remove(index))
        },
        |list| {
            let path = list_path(&directory, list);
            fs::rename(&path, previous_path(&path)).map_err(ListError::from)
        },
        |list| {
            let path = list_path(&directory, list);
            fs::rename(previous_path(&path), path).map_err(ListError::from)
        },
        |list| cleanup_previous(&directory, Some(list)),
    )?;
    Ok(())
}

pub fn list_payload(
    store: &Store,
    id: &ListId,
    category: Option<&str>,
) -> Result<ListPayload, ListError> {
    let list = store
        .load()?
        .lists
        .into_iter()
        .find(|item| &item.id == id)
        .ok_or(ListError::NotFound)?;
    list.validate_category(category)?;
    let bytes = read_verified(&list_dir(store)?, &list)?;
    Ok(formats::payload(&bytes, list.format, category)?)
}

pub fn reconcile_lists(store: &Store) -> Result<(), ListError> {
    let directory = list_dir(store)?;
    store.with_config(|config| {
        if !directory.exists() {
            return Ok(());
        }
        let mut active = HashSet::new();
        for list in &config.lists {
            let path = list_path(&directory, list);
            let backup = previous_path(&path);
            if backup.exists() {
                if read_verified(&directory, list).is_ok() {
                    fs::remove_file(&backup)?;
                } else {
                    let mut bytes = Vec::new();
                    fs::File::open(&backup)?
                        .take(MAX_LIST_BYTES as u64 + 1)
                        .read_to_end(&mut bytes)?;
                    if bytes.len() > MAX_LIST_BYTES
                        || list.size != Some(bytes.len() as u64)
                        || list.sha256.as_deref() != Some(checksum(&bytes).as_str())
                    {
                        return Err(ListError::Integrity);
                    }
                    if path.exists() {
                        fs::remove_file(&path)?;
                    }
                    fs::rename(&backup, &path)?;
                }
            }
            read_verified(&directory, list)?;
            active.insert(
                path.file_name()
                    .expect("list path has a name")
                    .to_os_string(),
            );
        }
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(text) = name.to_str() else { continue };
            if active.contains(&name) {
                continue;
            }
            let final_name = text.strip_suffix(".previous").unwrap_or(text);
            let Some((id, extension)) = final_name.split_once('.') else {
                continue;
            };
            if !id.is_empty()
                && id.bytes().all(|byte| byte.is_ascii_digit())
                && matches!(extension, "srs" | "json" | "dat" | "txt")
            {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests;
