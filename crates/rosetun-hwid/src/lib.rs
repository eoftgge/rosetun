#![deny(unsafe_code)]

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod registry;

use rosetun_config::digest_hex;
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Hwid(String);

impl std::fmt::Debug for Hwid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Hwid").field(&"[redacted]").finish()
    }
}

impl Hwid {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Which device ID a subscription request carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwidFor<'a> {
    /// The same ID for every subscription, as before 0.4.
    Machine,
    /// An ID of its own for one subscription server host.
    Provider(&'a str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub hwid: Hwid,
    pub os: &'static str,
    pub os_version: String,
    pub model: String,
}

#[derive(Debug, thiserror::Error)]
pub enum HwidError {
    #[error("device identifier is empty")]
    EmptyIdentifier,
    #[error("provider host is empty")]
    EmptyHost,
    #[error("could not read the system device identifier")]
    MachineIdUnavailable,
    #[error("registry read failed for {value} (Windows error {code})")]
    Registry { value: &'static str, code: u32 },
    #[error("registry value {value} has an invalid format")]
    InvalidRegistryValue { value: &'static str },
    #[error("registry value {value} is too large")]
    RegistryValueTooLarge { value: &'static str },
    #[error("registry value {value} changed repeatedly while being read")]
    RegistryValueUnstable { value: &'static str },
    #[error("device identification is not supported on this operating system")]
    UnsupportedPlatform,
}

pub fn hwid_from_machine_id(machine_id: &str) -> Result<Hwid, HwidError> {
    let normalized = machine_id.trim().to_lowercase();
    if normalized.is_empty() {
        return Err(HwidError::EmptyIdentifier);
    }

    // An app-scoped hash prevents exposing the system-wide identifier used
    // for cross-application correlation; nothing derived from a subscription is included.
    let mut hasher = Sha256::new();
    hasher.update(b"rosetun-hwid-v1:");
    hasher.update(normalized.as_bytes());
    let digest = hasher.finalize();

    Ok(Hwid(digest_hex(&digest[..16])))
}

pub fn hwid_for_provider(machine_id: &str, host: &str) -> Result<Hwid, HwidError> {
    let normalized = machine_id.trim().to_lowercase();
    if normalized.is_empty() {
        return Err(HwidError::EmptyIdentifier);
    }
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return Err(HwidError::EmptyHost);
    }

    // A separate prefix keeps v2 IDs apart from v1 ones even for the same input.
    // Only the host goes in: the path and query carry the provider's per-user
    // token, and the port does not make another provider.
    let mut hasher = Sha256::new();
    hasher.update(b"rosetun-hwid-v2:");
    hasher.update(normalized.as_bytes());
    hasher.update([0]);
    hasher.update(host.as_bytes());
    let digest = hasher.finalize();

    Ok(Hwid(digest_hex(&digest[..16])))
}

pub fn hwid_for(machine_id: &str, scope: HwidFor<'_>) -> Result<Hwid, HwidError> {
    match scope {
        HwidFor::Machine => hwid_from_machine_id(machine_id),
        HwidFor::Provider(host) => hwid_for_provider(machine_id, host),
    }
}

pub fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .take(64)
        .map(|character| {
            if (' '..='~').contains(&character) {
                character
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(windows)]
pub fn device_info(scope: HwidFor<'_>) -> Result<DeviceInfo, HwidError> {
    let machine_guid = registry::read_string(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid")?;
    let hwid = hwid_for(&machine_guid, scope)?;

    // Only the HWID is required: a panel with a device limit rejects requests
    // without it, while the version and model are informational.
    let os_version = windows_version().unwrap_or_else(|| "unknown".to_owned());

    let model = registry::read_string(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "PC".to_owned());

    Ok(DeviceInfo {
        hwid,
        os: "Windows",
        os_version: sanitize_header_value(&os_version),
        model: sanitize_header_value(model.trim()),
    })
}

#[cfg(windows)]
fn windows_version() -> Option<String> {
    let key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let major = registry::read_dword(key, "CurrentMajorVersionNumber").ok()?;
    let minor = registry::read_dword(key, "CurrentMinorVersionNumber").ok()?;
    let build = registry::read_string(key, "CurrentBuildNumber").ok()?;
    let build = build.trim();
    (!build.is_empty() && build.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| format!("{major}.{minor}.{build}"))
}

#[cfg(target_os = "linux")]
pub fn device_info(scope: HwidFor<'_>) -> Result<DeviceInfo, HwidError> {
    let machine_id =
        std::fs::read_to_string("/etc/machine-id").map_err(|_| HwidError::MachineIdUnavailable)?;
    let hwid = hwid_for(&machine_id, scope)?;

    let os_version = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_owned());

    Ok(DeviceInfo {
        hwid,
        os: "Linux",
        os_version: sanitize_header_value(os_version.trim()),
        model: "PC".to_owned(),
    })
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn device_info(_scope: HwidFor<'_>) -> Result<DeviceInfo, HwidError> {
    Err(HwidError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::{
        Hwid, HwidError, HwidFor, hwid_for, hwid_for_provider, hwid_from_machine_id,
        sanitize_header_value,
    };

    const MACHINE_ID: &str = "12345678-abcd-1234-abcd-123456789abc";

    fn assert_header_safe(hwid: &Hwid) {
        let value = hwid.as_str();
        assert!((10..=64).contains(&value.len()));
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'=' | b'-'))
        );
    }

    #[test]
    fn machine_hwid_is_unchanged_since_v1() {
        assert_eq!(
            hwid_from_machine_id(MACHINE_ID).unwrap().as_str(),
            "e781aff7d87a5c6fc260ff77072cea9f"
        );
        assert_eq!(
            hwid_for(MACHINE_ID, HwidFor::Machine).unwrap(),
            hwid_from_machine_id(MACHINE_ID).unwrap()
        );
    }

    #[test]
    fn provider_hwid_differs_between_hosts() {
        assert_ne!(
            hwid_for_provider(MACHINE_ID, "a.example.com").unwrap(),
            hwid_for_provider(MACHINE_ID, "b.example.com").unwrap()
        );
    }

    #[test]
    fn provider_hwid_ignores_host_case() {
        assert_eq!(
            hwid_for_provider(MACHINE_ID, "sub.example.com").unwrap(),
            hwid_for_provider(MACHINE_ID, "SUB.example.com").unwrap()
        );
    }

    #[test]
    fn provider_hwid_normalizes_the_machine_id_as_v1() {
        assert_eq!(
            hwid_for_provider(
                " ABCDEF-123456
",
                "sub.example.com"
            )
            .unwrap(),
            hwid_for_provider("abcdef-123456", "sub.example.com").unwrap()
        );
    }

    #[test]
    fn provider_hwid_is_not_the_machine_hwid() {
        let machine = hwid_from_machine_id(MACHINE_ID).unwrap();
        for host in ["sub.example.com", "192.0.2.1", "[2001:db8::1]"] {
            let provider = hwid_for(MACHINE_ID, HwidFor::Provider(host)).unwrap();
            assert_ne!(provider, machine);
            assert_header_safe(&provider);
            assert_eq!(provider.as_str().len(), 32);
        }
    }

    #[test]
    fn provider_hwid_needs_a_host() {
        for host in ["", " "] {
            assert!(matches!(
                hwid_for_provider(MACHINE_ID, host),
                Err(HwidError::EmptyHost)
            ));
        }
        assert!(matches!(
            hwid_for_provider(" ", "sub.example.com"),
            Err(HwidError::EmptyIdentifier)
        ));
    }

    #[test]
    fn same_machine_id_produces_same_hwid() {
        let first = hwid_from_machine_id("12345678-abcd-1234-abcd-123456789abc").unwrap();
        let second = hwid_from_machine_id("12345678-abcd-1234-abcd-123456789abc").unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn whitespace_and_case_are_normalized() {
        assert_eq!(
            hwid_from_machine_id(" \r\nABCDEF-123456\t ").unwrap(),
            hwid_from_machine_id("abcdef-123456").unwrap()
        );
    }

    #[test]
    fn different_machine_ids_produce_different_hwids() {
        assert_ne!(
            hwid_from_machine_id("machine-one").unwrap(),
            hwid_from_machine_id("machine-two").unwrap()
        );
    }

    #[test]
    fn hwid_matches_remnawave_character_and_length_requirements() {
        let hwid = hwid_from_machine_id("machine-one").unwrap();
        let value = hwid.as_str();

        assert!((10..=64).contains(&value.len()));
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'=' | b'-'))
        );
        assert_eq!(value.len(), 32);
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn empty_machine_id_is_rejected() {
        for input in ["", " ", "\r\n\t"] {
            assert!(matches!(
                hwid_from_machine_id(input),
                Err(HwidError::EmptyIdentifier)
            ));
        }
    }

    #[test]
    fn raw_machine_id_is_not_exposed_by_hwid() {
        let raw = "12345678-abcd-1234-abcd-123456789abc";
        let hwid = hwid_from_machine_id(raw).unwrap();

        assert!(!hwid.as_str().contains(raw));
        assert!(!format!("{hwid:?}").contains(raw));
    }

    #[test]
    fn hwid_debug_redacts_the_identifier() {
        let hwid = Hwid::new("known-secret");
        assert_eq!(hwid.as_str(), "known-secret");
        assert_eq!(format!("{hwid:?}"), "Hwid(\"[redacted]\")");
    }

    #[test]
    fn printable_ascii_is_preserved() {
        let value: String = (0x20u8..=0x7e).map(char::from).collect();
        let expected: String = value.chars().take(64).collect();

        assert_eq!(sanitize_header_value(&value), expected);
    }

    #[test]
    fn non_ascii_and_controls_are_replaced() {
        assert_eq!(
            sanitize_header_value("PC\r\n\t\0\u{7f}é中\u{202e}"),
            "PC????????"
        );
    }

    #[test]
    fn header_values_are_limited_to_64_ascii_characters() {
        for input in ["A".repeat(100), "中".repeat(100)] {
            let output = sanitize_header_value(&input);

            assert_eq!(output.len(), 64);
            assert!(output.bytes().all(|byte| (0x20..=0x7e).contains(&byte)));
        }
    }

    #[test]
    fn sanitizer_keeps_ascii_boundaries() {
        assert_eq!(sanitize_header_value("\u{1f} ~\u{7f}"), "? ~?");
    }
}
