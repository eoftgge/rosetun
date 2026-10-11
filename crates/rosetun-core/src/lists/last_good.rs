use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rosetun_config::ListFormat;

use super::{ListError, ListPayload, PayloadFormat, formats, list_dir, temporary_path};
use crate::Store;

fn directory(store: &Store) -> Result<PathBuf, ListError> {
    Ok(list_dir(store)?.join("last-good"))
}

fn extension(format: PayloadFormat) -> &'static str {
    match format {
        PayloadFormat::Binary => "srs",
        PayloadFormat::Source => "json",
    }
}

fn path(directory: &Path, tag: &str, format: PayloadFormat) -> PathBuf {
    directory.join(format!("{tag}.{}", extension(format)))
}

fn discard_corrupt(tag: &str, paths: &[&Path]) -> Result<(), ListError> {
    for path in paths {
        if let Err(error) = fs::remove_file(path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(error.into());
        }
    }
    tracing::warn!(
        tag,
        "damaged last good list copy removed; category rule skipped"
    );
    Ok(())
}

pub(super) fn load(store: &Store, tag: &str) -> Result<Option<ListPayload>, ListError> {
    let directory = directory(store)?;
    let binary = path(&directory, tag, PayloadFormat::Binary);
    let source = path(&directory, tag, PayloadFormat::Source);
    let (format, selected) = match (binary.try_exists()?, source.try_exists()?) {
        (false, false) => return Ok(None),
        (true, false) => (ListFormat::SingBoxBinary, binary),
        (false, true) => (ListFormat::SingBoxSource, source),
        (true, true) => {
            discard_corrupt(tag, &[&binary, &source])?;
            return Ok(None);
        }
    };
    let mut bytes = Vec::new();
    let file = match File::open(&selected) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    file.take(rosetun_config::MAX_UPLOADED_LIST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > rosetun_config::MAX_UPLOADED_LIST_BYTES {
        discard_corrupt(tag, &[&selected])?;
        return Ok(None);
    }
    let payload = match formats::payload(&bytes, format, None) {
        Ok(payload) => payload,
        Err(_) => {
            discard_corrupt(tag, &[&selected])?;
            return Ok(None);
        }
    };
    if payload.bytes != bytes {
        discard_corrupt(tag, &[&selected])?;
        return Ok(None);
    }
    Ok(Some(payload))
}

pub(super) fn save(
    store: &Store,
    tag: &str,
    format: PayloadFormat,
    bytes: &[u8],
) -> Result<(), ListError> {
    let directory = directory(store)?;
    fs::create_dir_all(&directory)?;
    let destination = path(&directory, tag, format);
    let temporary = temporary_path(&destination);
    let result = (|| -> Result<(), ListError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &destination)?;
        let other_format = match format {
            PayloadFormat::Binary => PayloadFormat::Source,
            PayloadFormat::Source => PayloadFormat::Binary,
        };
        let other = path(&directory, tag, other_format);
        if let Err(error) = fs::remove_file(other)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(error.into());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub(super) fn prune(store: &Store, referenced: &HashSet<String>) -> Result<(), ListError> {
    let directory = directory(store)?;
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some((tag, extension)) = name.rsplit_once('.') else {
            continue;
        };
        if matches!(extension, "srs" | "json")
            && tag.starts_with("list-")
            && tag.len() == 53
            && tag[5..].bytes().all(|byte| byte.is_ascii_hexdigit())
            && !referenced.contains(tag)
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}
