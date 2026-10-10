use serde_json::Value;

pub const MAX_UPLOADED_LIST_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_UPLOADED_LIST_ENTRIES: usize = 1_000_000;
const ALLOWED_KEYS: [&str; 7] = [
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
    "process_name",
    "process_path",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListValidationError {
    #[error("list payload exceeds the 16 MiB limit")]
    TooLarge,
    #[error("list payload exceeds the 1,000,000 entry limit")]
    TooManyEntries,
    #[error("invalid sing-box binary header")]
    InvalidSrs,
    #[error("unsupported sing-box binary version {0}")]
    UnsupportedSrsVersion(u8),
    #[error("invalid sing-box source JSON")]
    InvalidJson,
    #[error("invalid sing-box source: {0}")]
    InvalidSource(&'static str),
    #[error("unsupported sing-box rule key: {0}")]
    UnsupportedRuleKey(String),
    #[error("the selected list contains no entries")]
    EmptyResult,
}

pub fn validate_srs(bytes: &[u8]) -> Result<(), ListValidationError> {
    if bytes.len() > MAX_UPLOADED_LIST_BYTES {
        return Err(ListValidationError::TooLarge);
    }
    if bytes.len() < 4 || &bytes[..3] != b"SRS" {
        return Err(ListValidationError::InvalidSrs);
    }
    if bytes[3] > 5 {
        return Err(ListValidationError::UnsupportedSrsVersion(bytes[3]));
    }
    Ok(())
}

pub fn normalize_source(bytes: &[u8]) -> Result<Vec<u8>, ListValidationError> {
    if bytes.len() > MAX_UPLOADED_LIST_BYTES {
        return Err(ListValidationError::TooLarge);
    }
    let source: Value =
        serde_json::from_slice(bytes).map_err(|_| ListValidationError::InvalidJson)?;
    let root = source
        .as_object()
        .ok_or(ListValidationError::InvalidSource("expected an object"))?;
    if root.len() != 2 || !root.contains_key("version") || !root.contains_key("rules") {
        return Err(ListValidationError::InvalidSource(
            "expected only version and rules at the root",
        ));
    }
    if root["version"].as_u64().is_none() {
        return Err(ListValidationError::InvalidSource(
            "version must be a nonnegative integer",
        ));
    }
    let rules = root["rules"]
        .as_array()
        .ok_or(ListValidationError::InvalidSource("rules must be an array"))?;
    let mut count = 0_usize;
    for rule in rules {
        let rule = rule.as_object().ok_or(ListValidationError::InvalidSource(
            "each rule must be an object",
        ))?;
        let before = count;
        for (key, values) in rule {
            if !ALLOWED_KEYS.contains(&key.as_str()) {
                return Err(ListValidationError::UnsupportedRuleKey(
                    safe_rule_key(key).to_owned(),
                ));
            }
            let values = values.as_array().ok_or(ListValidationError::InvalidSource(
                "rule conditions must be arrays of strings",
            ))?;
            for value in values {
                if value.as_str().is_none_or(|value| value.trim().is_empty()) {
                    return Err(ListValidationError::InvalidSource(
                        "rule conditions must contain nonempty strings",
                    ));
                }
                count += 1;
                if count > MAX_UPLOADED_LIST_ENTRIES {
                    return Err(ListValidationError::TooManyEntries);
                }
            }
        }
        if count == before {
            return Err(ListValidationError::InvalidSource(
                "a rule has no conditions",
            ));
        }
    }
    if count == 0 {
        return Err(ListValidationError::EmptyResult);
    }
    let output = serde_json::to_vec(&source).map_err(|_| ListValidationError::InvalidJson)?;
    if output.len() > MAX_UPLOADED_LIST_BYTES {
        return Err(ListValidationError::TooLarge);
    }
    Ok(output)
}

fn safe_rule_key(key: &str) -> &str {
    if !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        key
    } else {
        "<redacted>"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_rejects_unsafe_keys_and_empty_rules() {
        let unsafe_key = br#"{"version":3,"rules":[{"secret.example.com":["example.com"]}]}"#;
        let error = normalize_source(unsafe_key).unwrap_err();
        assert!(!format!("{error:?}").contains("secret.example.com"));
        assert_eq!(
            normalize_source(br#"{"version":3,"rules":[{}]}"#),
            Err(ListValidationError::InvalidSource(
                "a rule has no conditions"
            ))
        );
    }
}
