use rosetun_config::ListFormat;

pub(crate) struct InspectedList {
    pub format: ListFormat,
    pub categories: Vec<String>,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFormat {
    Binary,
    Source,
}

pub struct ListPayload {
    pub format: PayloadFormat,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for ListPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListPayload")
            .field("format", &self.format)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ListParseError {
    #[error("list format is not supported yet")]
    Unsupported,
    #[error("invalid list data")]
    Invalid,
}

pub(crate) fn inspect(bytes: &[u8], hint: Option<&str>) -> Result<InspectedList, ListParseError> {
    if bytes.len() > super::MAX_LIST_BYTES {
        return Err(ListParseError::Invalid);
    }
    let format = if bytes.starts_with(b"SRS") {
        if bytes.len() < 4 || bytes[3] > 5 {
            return Err(ListParseError::Invalid);
        }
        ListFormat::SingBoxBinary
    } else if hint.is_some_and(|name| name.to_ascii_lowercase().ends_with(".dat")) {
        return Err(ListParseError::Unsupported);
    } else if bytes.first() == Some(&b'{') {
        let source: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ListParseError::Invalid)?;
        if !source.get("version").is_some_and(serde_json::Value::is_number)
            || !source.get("rules").is_some_and(serde_json::Value::is_array)
        {
            return Err(ListParseError::Invalid);
        }
        ListFormat::SingBoxSource
    } else {
        let text = std::str::from_utf8(bytes).map_err(|_| ListParseError::Invalid)?;
        if text.lines().all(|line| line.trim().is_empty() || line.trim_start().starts_with('#')) {
            return Err(ListParseError::Invalid);
        }
        ListFormat::Text
    };
    Ok(InspectedList {
        format,
        categories: Vec::new(),
        bytes: bytes.to_vec(),
    })
}

pub(crate) fn payload(
    bytes: &[u8],
    format: ListFormat,
    _category: Option<&str>,
) -> Result<ListPayload, ListParseError> {
    if format != ListFormat::SingBoxBinary || bytes.len() > 16 * 1024 * 1024 {
        return Err(ListParseError::Unsupported);
    }
    Ok(ListPayload {
        format: PayloadFormat::Binary,
        bytes: bytes.to_vec(),
    })
}
