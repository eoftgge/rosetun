use std::collections::{HashMap, HashSet};
use std::fmt;

use base64::Engine as _;
use rosetun_config::{
    ListCategoryError, ListFormat as StoredFormat, ListId, ListRef, RuleId, RuleMatcher,
    RuleTarget, UploadedListFormat, list_tag,
};
use rosetun_ipc::{
    ClientError, ConnectRequest, ErrorCode, HelperClient, ListFormat, MAX_LIST_CHUNK_BYTES,
    MAX_LIST_PAYLOAD_BYTES,
};
use sha2::{Digest, Sha256};

use super::{ListError, ListParseError, PayloadFormat, list_payload};
use crate::{Store, StoreError};

const MAX_PREPARED_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REFERENCES: usize = 256;

pub struct PreparedListPayload {
    pub sha256: String,
    pub format: UploadedListFormat,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for PreparedListPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedListPayload")
            .field("sha256", &self.sha256)
            .field("format", &self.format)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

pub struct PreparedConnection {
    pub request: ConnectRequest,
    pub payloads: Vec<PreparedListPayload>,
    pub missing_categories: Vec<RuleId>,
}

impl fmt::Debug for PreparedConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedConnection")
            .field("list_count", &self.request.lists.len())
            .field("payload_count", &self.payloads.len())
            .field("missing_category_count", &self.missing_categories.len())
            .finish()
    }
}

#[derive(thiserror::Error)]
pub enum ListPreparationError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("could not prepare a referenced list: {0}")]
    List(#[from] ListError),
    #[error("connection lists exceed the service's storage limits")]
    TooMany,
}

impl fmt::Debug for ListPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Store(_) => "ListPreparationError::Store(<redacted>)",
            Self::List(_) => "ListPreparationError::List(<redacted>)",
            Self::TooMany => "ListPreparationError::TooMany",
        })
    }
}

pub fn prepare_lists(
    store: &Store,
    mut request: ConnectRequest,
) -> Result<PreparedConnection, ListPreparationError> {
    let config = store.load()?;
    let mut selected = HashMap::<(ListId, Option<String>), Option<ListRef>>::new();
    let mut references = Vec::new();
    let mut payloads = Vec::<PreparedListPayload>::new();
    let mut missing_categories = Vec::new();
    let mut total_bytes = 0_u64;
    request.lists.clear();
    request.fallback_block_rules.clear();

    for rule in request
        .temporary_rules
        .iter_mut()
        .chain(request.rule_set.rules.iter_mut())
        .filter(|rule| rule.enabled)
    {
        let RuleMatcher::List { list, category } = &rule.matcher else {
            continue;
        };
        let key = (list.clone(), category.clone());
        let reference = if let Some(cached) = selected.get(&key) {
            cached.clone()
        } else {
            let stored = config.lists.iter().find(|item| &item.id == list);
            let dat = stored.is_some_and(|item| {
                matches!(item.format, StoredFormat::GeoSite | StoredFormat::GeoIp)
            });
            let value = match list_payload(store, list, category.as_deref()) {
                Ok(payload) => {
                    let format = match payload.format {
                        PayloadFormat::Binary => UploadedListFormat::Binary,
                        PayloadFormat::Source => UploadedListFormat::Source,
                    };
                    let sha256 = format!("{:x}", Sha256::digest(&payload.bytes));
                    let reference = ListRef {
                        tag: list_tag(list, category.as_deref()),
                        sha256: sha256.clone(),
                        format,
                    };
                    if !payloads.iter().any(|item| item.sha256 == sha256 && item.format == format) {
                        let size = payload.bytes.len() as u64;
                        total_bytes = total_bytes
                            .checked_add(size)
                            .filter(|total| *total <= MAX_PREPARED_BYTES)
                            .ok_or(ListPreparationError::TooMany)?;
                        if size > MAX_LIST_PAYLOAD_BYTES {
                            return Err(ListPreparationError::TooMany);
                        }
                        payloads.push(PreparedListPayload {
                            sha256,
                            format,
                            bytes: payload.bytes,
                        });
                    }
                    references.push(reference.clone());
                    Some(reference)
                }
                Err(ListError::Category(ListCategoryError::Unknown)) if dat => None,
                Err(ListError::Parse(ListParseError::EmptyResult)) if dat && category.is_some() => None,
                Err(error) => return Err(error.into()),
            };
            selected.insert(key, value.clone());
            value
        };
        if reference.is_none() {
            rule.target = RuleTarget::Block;
            if !request.fallback_block_rules.contains(&rule.id) {
                request.fallback_block_rules.push(rule.id.clone());
            }
            missing_categories.push(rule.id.clone());
        }
    }
    if references.len() > MAX_REFERENCES || request.fallback_block_rules.len() > MAX_REFERENCES {
        return Err(ListPreparationError::TooMany);
    }
    request.lists = references;
    Ok(PreparedConnection {
        request,
        payloads,
        missing_categories,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListOperation {
    Connect,
    Apply,
}

trait ListClient {
    fn list_status(&mut self, hashes: Vec<String>) -> Result<Vec<String>, ClientError>;
    fn put_chunk(
        &mut self,
        sha256: &str,
        format: ListFormat,
        total_size: u64,
        offset: u64,
        data: String,
    ) -> Result<(), ClientError>;
    fn connect(&mut self, request: ConnectRequest) -> Result<(), ClientError>;
    fn apply(&mut self, request: ConnectRequest) -> Result<(), ClientError>;
}

impl ListClient for HelperClient {
    fn list_status(&mut self, hashes: Vec<String>) -> Result<Vec<String>, ClientError> {
        HelperClient::list_status(self, hashes)
    }

    fn put_chunk(
        &mut self,
        sha256: &str,
        format: ListFormat,
        total_size: u64,
        offset: u64,
        data: String,
    ) -> Result<(), ClientError> {
        HelperClient::put_list_chunk(self, sha256, format, total_size, offset, data)
    }

    fn connect(&mut self, request: ConnectRequest) -> Result<(), ClientError> {
        HelperClient::connect_tunnel(self, request)
    }

    fn apply(&mut self, request: ConnectRequest) -> Result<(), ClientError> {
        HelperClient::apply_tunnel(self, request)
    }
}

pub fn send_prepared(
    client: &mut HelperClient,
    prepared: &PreparedConnection,
    operation: ListOperation,
) -> Result<(), ClientError> {
    send_with(client, prepared, operation)
}

fn send_with(
    client: &mut impl ListClient,
    prepared: &PreparedConnection,
    operation: ListOperation,
) -> Result<(), ClientError> {
    let mut retried = false;
    loop {
        upload_missing(client, prepared)?;
        let result = match operation {
            ListOperation::Connect => client.connect(prepared.request.clone()),
            ListOperation::Apply => client.apply(prepared.request.clone()),
        };
        match result {
            Err(ClientError::Helper(error)) if error.code == ErrorCode::ListMissing && !retried => {
                retried = true;
            }
            other => return other,
        }
    }
}

fn upload_missing(
    client: &mut impl ListClient,
    prepared: &PreparedConnection,
) -> Result<(), ClientError> {
    let hashes: Vec<_> = prepared
        .payloads
        .iter()
        .map(|payload| payload.sha256.clone())
        .collect();
    let missing = client.list_status(hashes)?;
    let mut seen = HashSet::new();
    for hash in missing {
        if !seen.insert(hash.clone()) {
            continue;
        }
        let payload = prepared
            .payloads
            .iter()
            .find(|payload| payload.sha256 == hash)
            .ok_or(ClientError::Unexpected)?;
        for (index, bytes) in payload.bytes.chunks(MAX_LIST_CHUNK_BYTES).enumerate() {
            client.put_chunk(
                &payload.sha256,
                payload.format,
                payload.bytes.len() as u64,
                (index * MAX_LIST_CHUNK_BYTES) as u64,
                base64::engine::general_purpose::STANDARD.encode(bytes),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
