use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ListId, subscription::debug_host};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListSource {
    Url(String),
    File { original_name: String },
}

impl fmt::Debug for ListSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url(url) => {
                let host = debug_host(url);
                let safe = if host == "<redacted>" {
                    "<redacted>".to_owned()
                } else {
                    let scheme = url.split_once("://").map_or("", |(scheme, _)| scheme);
                    format!("{}://{host}", scheme.to_ascii_lowercase())
                };
                f.debug_tuple("Url").field(&safe).finish()
            }
            Self::File { original_name } => f
                .debug_struct("File")
                .field("original_name", original_name)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListFormat {
    SingBoxBinary,
    SingBoxSource,
    GeoSite,
    GeoIp,
    Text,
}

impl ListFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::SingBoxBinary => "srs",
            Self::SingBoxSource => "json",
            Self::GeoSite | Self::GeoIp => "dat",
            Self::Text => "txt",
        }
    }

    pub fn has_categories(self) -> bool {
        matches!(self, Self::GeoSite | Self::GeoIp)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct List {
    pub id: ListId,
    pub name: String,
    pub source: ListSource,
    pub format: ListFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default)]
    pub categories: Vec<String>,
}

impl fmt::Debug for List {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("List")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("source", &self.source)
            .field("format", &self.format)
            .field("updated_at", &self.updated_at)
            .field("size", &self.size)
            .field("sha256", &self.sha256)
            .field("categories", &self.categories)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ListCategoryError {
    #[error("this list requires a category")]
    Required,
    #[error("this list does not have categories")]
    Unexpected,
    #[error("the selected category does not exist")]
    Unknown,
    #[error("invalid category attribute filter")]
    InvalidFilter,
}

impl List {
    pub fn validate_category(&self, category: Option<&str>) -> Result<(), ListCategoryError> {
        if !self.format.has_categories() {
            return if category.is_some() {
                Err(ListCategoryError::Unexpected)
            } else {
                Ok(())
            };
        }
        let category = category.ok_or(ListCategoryError::Required)?;
        let (base, attribute) = match category.split_once('@') {
            Some((base, filter)) => (base, Some(filter)),
            None => (category, None),
        };
        if !self.categories.iter().any(|name| name == base) {
            return Err(ListCategoryError::Unknown);
        }
        if let Some(attribute) = attribute {
            let key = attribute.strip_prefix('!').unwrap_or(attribute);
            if self.format != ListFormat::GeoSite
                || key.is_empty()
                || !key.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'-')
                })
            {
                return Err(ListCategoryError::InvalidFilter);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example(format: ListFormat) -> List {
        List {
            id: ListId::new("1"),
            name: "Example".to_owned(),
            source: ListSource::Url(
                "https://user:secret@lists.example.com/private?token=secret".to_owned(),
            ),
            format,
            updated_at: None,
            size: None,
            sha256: None,
            categories: if format.has_categories() {
                vec!["example".to_owned()]
            } else {
                vec![]
            },
        }
    }

    #[test]
    fn list_and_source_debug_hide_url_secrets() {
        let list = example(ListFormat::GeoSite);
        for output in [format!("{list:?}"), format!("{:?}", list.source)] {
            assert!(output.contains("https://lists.example.com"));
            assert!(!output.contains("secret"));
            assert!(!output.contains("/private"));
        }
    }

    #[test]
    fn category_filters_are_only_valid_for_geosite() {
        let site = example(ListFormat::GeoSite);
        assert!(site.validate_category(Some("example@cn")).is_ok());
        assert!(site.validate_category(Some("example@!cn")).is_ok());
        assert_eq!(
            site.validate_category(None),
            Err(ListCategoryError::Required)
        );
        assert_eq!(
            site.validate_category(Some("example@")),
            Err(ListCategoryError::InvalidFilter)
        );
        assert_eq!(
            site.validate_category(Some("unknown")),
            Err(ListCategoryError::Unknown)
        );
        let ip = example(ListFormat::GeoIp);
        assert_eq!(
            ip.validate_category(Some("example@cn")),
            Err(ListCategoryError::InvalidFilter)
        );
        let text = example(ListFormat::Text);
        assert_eq!(
            text.validate_category(Some("example")),
            Err(ListCategoryError::Unexpected)
        );
    }
}
