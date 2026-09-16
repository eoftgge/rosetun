#![forbid(unsafe_code)]

/// Device fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hwid(String);

impl Hwid {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Hwid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
