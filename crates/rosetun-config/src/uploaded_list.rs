use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ListId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadedListFormat {
    Binary,
    Source,
}

impl UploadedListFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Binary => "srs",
            Self::Source => "json",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRef {
    pub tag: String,
    pub sha256: String,
    pub format: UploadedListFormat,
}

impl fmt::Debug for ListRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListRef")
            .field("sha256", &self.sha256)
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

pub fn list_tag(id: &ListId, category: Option<&str>) -> String {
    let mut hash = Sha256::new();
    hash.update(id.as_str().as_bytes());
    hash.update([0]);
    match category {
        Some(category) => {
            hash.update([1]);
            hash.update(category.as_bytes());
        }
        None => hash.update([0]),
    }
    let digest = hash.finalize();
    let mut tag = String::from("list-");
    for byte in &digest[..24] {
        use std::fmt::Write;
        write!(&mut tag, "{byte:02x}").expect("writing to a string cannot fail");
    }
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_safe_and_distinguish_categories() {
        let id = ListId::new("user-list");
        let bare = list_tag(&id, None);
        let empty = list_tag(&id, Some(""));
        let filtered = list_tag(&id, Some("ads@!mobile"));
        assert_ne!(bare, empty);
        assert_ne!(bare, filtered);
        assert_eq!(filtered, list_tag(&id, Some("ads@!mobile")));
        assert!(filtered.len() <= 64);
        assert!(
            filtered
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        );
    }
}
