//! Downloads a release's Windows installer and proves it is the one the
//! maintainer signed: the minisign signature over `SHA256SUMS.txt`, the
//! version in its trusted comment, then the installer's SHA-256 from that
//! list. Nothing is kept unless every step passes.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};
use ureq::tls::{RootCerts, TlsConfig};
use url::Url;

use crate::fetch::DEFAULT_USER_AGENT;

/// The maintainer's public key; the secret key never leaves the maintainer's computer.
const RELEASE_KEY: &str = include_str!("../keys/minisign.pub");
const DOWNLOAD_PREFIX: &str = "https://github.com/eoftgge/rosetun/releases/download/";
const SUMS_FILE: &str = "SHA256SUMS.txt";
const SIGNATURE_FILE: &str = "SHA256SUMS.txt.minisig";
/// GitHub answers a release asset with a redirect to its storage host.
const ASSET_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];
const MAX_REDIRECTS: usize = 4;
const MAX_SUMS_BYTES: u64 = 64 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 4 * 1024;
const MAX_INSTALLER_BYTES: u64 = 512 * 1024 * 1024;
const MAX_VERSION_CHARS: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// A stalled transfer ends the download; a slow one does not.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpdateDownloadError {
    #[error("the release version is not valid")]
    InvalidVersion,
    #[error("request failed")]
    Request,
    #[error("the request through the VPN failed")]
    VpnRequest,
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("the download was redirected to an unexpected address")]
    Redirect,
    #[error("the release is not signed")]
    Unsigned,
    #[error("the release signature is not valid")]
    BadSignature,
    #[error("the signature belongs to another version")]
    WrongVersion,
    #[error("the installer is missing from the signed list")]
    NotListed,
    #[error("the installer does not match the signed list")]
    Mismatch,
    #[error("the download is too large")]
    TooLarge,
    #[error("the download was cancelled")]
    Cancelled,
    #[error("the download could not be saved")]
    Save,
}

/// An installer that passed every check, with the hash it must still have when it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedUpdate {
    pub version: String,
    pub path: PathBuf,
    sha256: [u8; 32],
}

impl DownloadedUpdate {
    /// An update that never passed a check, for other crates' tests.
    #[cfg(feature = "test-support")]
    pub fn for_tests(version: &str, path: PathBuf) -> Self {
        Self {
            version: version.to_owned(),
            path,
            sha256: [0; 32],
        }
    }

    /// Hashes the file again right before it runs: another program of the
    /// same user may have replaced it since the download.
    pub fn verify(&self) -> Result<(), UpdateDownloadError> {
        let mut file = File::open(&self.path).map_err(|_| UpdateDownloadError::Mismatch)?;
        let digest = hash_copy(
            &mut file,
            None,
            MAX_INSTALLER_BYTES,
            &AtomicBool::new(false),
            |_| {},
        )
        .map_err(|_| UpdateDownloadError::Mismatch)?;
        if digest == self.sha256 {
            Ok(())
        } else {
            Err(UpdateDownloadError::Mismatch)
        }
    }
}

/// The Windows installer's file name in the release `version`.
pub fn installer_name(version: &str) -> Result<String, UpdateDownloadError> {
    let valid = !version.is_empty()
        && version.len() <= MAX_VERSION_CHARS
        && version.starts_with(|character: char| character.is_ascii_digit())
        && version
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-'));
    if valid {
        Ok(format!("rosetun-{version}-setup.exe"))
    } else {
        Err(UpdateDownloadError::InvalidVersion)
    }
}

/// Downloads the installer of `version` into `directory` and checks it.
/// With `via_vpn` and a connected session, every request goes through the
/// VPN and a failure there ends the download; there is no direct retry.
/// `progress` receives the bytes received and the size when the server gives it.
pub fn download_update(
    version: &str,
    directory: &Path,
    via_vpn: bool,
    cancelled: &AtomicBool,
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<DownloadedUpdate, UpdateDownloadError> {
    let name = installer_name(version)?;
    let vpn = if via_vpn {
        crate::fetch::helper_vpn_proxy("rosetun-update")
            .map_err(|_| UpdateDownloadError::VpnRequest)?
    } else {
        None
    };
    let through_vpn = vpn.is_some();
    let agent = agent(vpn.or_else(crate::resolve::agent_proxy));
    let network = |error| match error {
        UpdateDownloadError::Request if through_vpn => UpdateDownloadError::VpnRequest,
        other => other,
    };

    let signature = match get_small(
        &agent,
        &asset_url(version, SIGNATURE_FILE),
        MAX_SIGNATURE_BYTES,
    ) {
        Err(UpdateDownloadError::Status(404)) => return Err(UpdateDownloadError::Unsigned),
        result => result.map_err(network)?,
    };
    let signature = String::from_utf8(signature).map_err(|_| UpdateDownloadError::BadSignature)?;
    let sums =
        get_small(&agent, &asset_url(version, SUMS_FILE), MAX_SUMS_BYTES).map_err(network)?;
    verify_sums(&sums, &signature, RELEASE_KEY, version)?;
    let expected = listed_hash(&sums, &name)?;

    fs::create_dir_all(directory).map_err(|_| UpdateDownloadError::Save)?;
    remove_stale(directory, &name);
    let target = directory.join(&name);
    let partial = directory.join(format!("{name}.partial"));
    let result = (|| {
        let mut response = open(&agent, &asset_url(version, &name)).map_err(network)?;
        let total = response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if total.is_some_and(|total| total > MAX_INSTALLER_BYTES) {
            return Err(UpdateDownloadError::TooLarge);
        }
        let mut file = File::create(&partial).map_err(|_| UpdateDownloadError::Save)?;
        let digest = hash_copy(
            &mut response.body_mut().as_reader(),
            Some(&mut file),
            MAX_INSTALLER_BYTES,
            cancelled,
            |received| progress(received, total),
        )
        .map_err(network)?;
        file.sync_all().map_err(|_| UpdateDownloadError::Save)?;
        drop(file);
        if digest != expected {
            return Err(UpdateDownloadError::Mismatch);
        }
        fs::rename(&partial, &target).map_err(|_| UpdateDownloadError::Save)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result?;
    Ok(DownloadedUpdate {
        version: version.to_owned(),
        path: target,
        sha256: expected,
    })
}

fn asset_url(version: &str, file: &str) -> String {
    format!("{DOWNLOAD_PREFIX}v{version}/{file}")
}

fn agent(proxy: Option<ureq::Proxy>) -> ureq::Agent {
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build();
    crate::resolve::agent(
        ureq::Agent::config_builder()
            .proxy(proxy)
            .tls_config(tls)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_per_read(Some(READ_TIMEOUT))
            // Redirects are followed by hand, so each address is checked first.
            .max_redirects(0)
            .https_only(true)
            .http_status_as_error(false)
            .build(),
    )
}

fn allowed(url: &str) -> Result<Url, UpdateDownloadError> {
    let url = Url::parse(url).map_err(|_| UpdateDownloadError::Redirect)?;
    let host = url.host_str().unwrap_or_default();
    if url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && ASSET_HOSTS.contains(&host)
    {
        Ok(url)
    } else {
        Err(UpdateDownloadError::Redirect)
    }
}

fn open(
    agent: &ureq::Agent,
    url: &str,
) -> Result<ureq::http::Response<ureq::Body>, UpdateDownloadError> {
    let mut url = allowed(url)?;
    for _ in 0..=MAX_REDIRECTS {
        // ureq errors can contain the request URI; never forward them.
        let response = agent
            .get(url.as_str())
            .header("User-Agent", DEFAULT_USER_AGENT)
            .call()
            .map_err(|_| UpdateDownloadError::Request)?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            let location = response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .ok_or(UpdateDownloadError::Redirect)?;
            let next = url
                .join(location)
                .map_err(|_| UpdateDownloadError::Redirect)?;
            url = allowed(next.as_str())?;
            continue;
        }
        if status != 200 {
            return Err(UpdateDownloadError::Status(status));
        }
        return Ok(response);
    }
    Err(UpdateDownloadError::Redirect)
}

fn get_small(agent: &ureq::Agent, url: &str, limit: u64) -> Result<Vec<u8>, UpdateDownloadError> {
    let mut response = open(agent, url)?;
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(limit + 1)
        .read_to_end(&mut body)
        .map_err(|_| UpdateDownloadError::Request)?;
    if body.len() as u64 > limit {
        return Err(UpdateDownloadError::TooLarge);
    }
    Ok(body)
}

/// Checks the signature over `sums` and that it was made for `version`, so a
/// signed list of an older release cannot pass for a newer one.
fn verify_sums(
    sums: &[u8],
    signature: &str,
    key: &str,
    version: &str,
) -> Result<(), UpdateDownloadError> {
    let key = PublicKey::decode(key).map_err(|_| UpdateDownloadError::BadSignature)?;
    let signature = Signature::decode(signature).map_err(|_| UpdateDownloadError::BadSignature)?;
    key.verify(sums, &signature, false)
        .map_err(|_| UpdateDownloadError::BadSignature)?;
    if signature.trusted_comment() == format!("rosetun {version}") {
        Ok(())
    } else {
        Err(UpdateDownloadError::WrongVersion)
    }
}

/// The SHA-256 the signed list gives for `name`; a name listed twice is refused.
fn listed_hash(sums: &[u8], name: &str) -> Result<[u8; 32], UpdateDownloadError> {
    let sums = std::str::from_utf8(sums).map_err(|_| UpdateDownloadError::NotListed)?;
    let mut found = None;
    for line in sums.lines() {
        let Some((hash, listed)) = line.split_once(' ') else {
            continue;
        };
        // `sha256sum` writes two spaces, or a space and `*` in binary mode.
        let listed = listed
            .strip_prefix(' ')
            .or_else(|| listed.strip_prefix('*'))
            .unwrap_or(listed);
        if listed != name {
            continue;
        }
        if found.is_some() {
            return Err(UpdateDownloadError::NotListed);
        }
        found = Some(parse_hex(hash).ok_or(UpdateDownloadError::NotListed)?);
    }
    found.ok_or(UpdateDownloadError::NotListed)
}

fn parse_hex(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let digit = |byte: u8| char::from(byte).to_digit(16);
    let mut out = [0; 32];
    for (index, [high, low]) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let value = digit(*high)? * 16 + digit(*low)?;
        out[index] = u8::try_from(value).ok()?;
    }
    Some(out)
}

fn hash_copy(
    reader: &mut impl Read,
    mut sink: Option<&mut File>,
    limit: u64,
    cancelled: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Result<[u8; 32], UpdateDownloadError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; CHUNK_BYTES];
    let mut received = 0_u64;
    loop {
        if cancelled.load(Ordering::Relaxed) {
            return Err(UpdateDownloadError::Cancelled);
        }
        let read = reader
            .read(&mut buffer)
            .map_err(|_| UpdateDownloadError::Request)?;
        if read == 0 {
            break;
        }
        received += read as u64;
        if received > limit {
            return Err(UpdateDownloadError::TooLarge);
        }
        hasher.update(&buffer[..read]);
        if let Some(file) = sink.as_mut() {
            file.write_all(&buffer[..read])
                .map_err(|_| UpdateDownloadError::Save)?;
        }
        progress(received);
    }
    Ok(hasher.finalize().into())
}

/// Older installers and unfinished downloads in the folder are only Rosetun's own.
fn remove_stale(directory: &Path, keep: &str) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let ours = name.starts_with("rosetun-")
            && (name.ends_with("-setup.exe") || name.ends_with("-setup.exe.partial"));
        if ours && name != keep {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUMS: &[u8] = include_bytes!("../tests/fixtures/updater/SHA256SUMS.txt");
    const TEST_KEY: &str = include_str!("../tests/fixtures/updater/test.pub");
    const GOOD: &str = include_str!("../tests/fixtures/updater/good.minisig");
    const OLD: &str = include_str!("../tests/fixtures/updater/old.minisig");
    const FOREIGN: &str = include_str!("../tests/fixtures/updater/foreign.minisig");

    #[test]
    fn a_list_signed_for_this_version_passes() {
        assert_eq!(verify_sums(SUMS, GOOD, TEST_KEY, "0.7.0"), Ok(()));
    }

    #[test]
    fn a_signature_made_for_another_version_is_refused() {
        assert_eq!(
            verify_sums(SUMS, OLD, TEST_KEY, "0.7.0"),
            Err(UpdateDownloadError::WrongVersion)
        );
        assert_eq!(
            verify_sums(SUMS, GOOD, TEST_KEY, "0.8.0"),
            Err(UpdateDownloadError::WrongVersion)
        );
    }

    #[test]
    fn a_signature_by_another_key_is_refused() {
        assert_eq!(
            verify_sums(SUMS, FOREIGN, TEST_KEY, "0.7.0"),
            Err(UpdateDownloadError::BadSignature)
        );
    }

    #[test]
    fn a_changed_list_or_a_broken_signature_is_refused() {
        let mut changed = SUMS.to_vec();
        changed[0] = if changed[0] == b'0' { b'1' } else { b'0' };
        assert_eq!(
            verify_sums(&changed, GOOD, TEST_KEY, "0.7.0"),
            Err(UpdateDownloadError::BadSignature)
        );
        assert_eq!(
            verify_sums(
                SUMS,
                "untrusted comment: x\nnot a signature\n",
                TEST_KEY,
                "0.7.0"
            ),
            Err(UpdateDownloadError::BadSignature)
        );
        assert_eq!(
            verify_sums(SUMS, "", TEST_KEY, "0.7.0"),
            Err(UpdateDownloadError::BadSignature)
        );
    }

    #[test]
    fn the_test_signatures_do_not_pass_the_release_key() {
        assert!(PublicKey::decode(RELEASE_KEY).is_ok());
        assert_ne!(RELEASE_KEY.lines().nth(1), TEST_KEY.lines().nth(1));
        assert_eq!(
            verify_sums(SUMS, GOOD, RELEASE_KEY, "0.7.0"),
            Err(UpdateDownloadError::BadSignature)
        );
    }

    #[test]
    fn the_installer_hash_comes_from_its_own_line() {
        let installer: [u8; 32] = Sha256::digest(b"installer").into();
        assert_eq!(listed_hash(SUMS, "rosetun-0.7.0-setup.exe"), Ok(installer));
        assert_eq!(
            listed_hash(SUMS, "rosetun-0.7.0-setup"),
            Err(UpdateDownloadError::NotListed)
        );
        let binary = format!("{} *rosetun-0.7.0-setup.exe\n", "ab".repeat(32));
        assert_eq!(
            listed_hash(binary.as_bytes(), "rosetun-0.7.0-setup.exe"),
            Ok([0xab; 32])
        );
        let twice = format!("{0}  a.exe\n{0}  a.exe\n", "ab".repeat(32));
        assert_eq!(
            listed_hash(twice.as_bytes(), "a.exe"),
            Err(UpdateDownloadError::NotListed)
        );
        let short = "abcd  a.exe\n";
        assert_eq!(
            listed_hash(short.as_bytes(), "a.exe"),
            Err(UpdateDownloadError::NotListed)
        );
    }

    #[test]
    fn only_plain_release_versions_name_an_installer() {
        assert_eq!(
            installer_name("0.7.0-beta.1").as_deref(),
            Ok("rosetun-0.7.0-beta.1-setup.exe")
        );
        for version in ["", "v0.7.0", "0.7.0/../x", "0.7.0\\x", "0.7 0", "0.7.0?x"] {
            assert_eq!(
                installer_name(version),
                Err(UpdateDownloadError::InvalidVersion),
                "{version:?}"
            );
        }
    }

    #[test]
    fn downloads_and_redirects_stay_on_github_over_https() {
        for url in [
            "https://github.com/eoftgge/rosetun/releases/download/v0.7.0/a.exe",
            "https://objects.githubusercontent.com/github-production-release-asset/1",
            "https://release-assets.githubusercontent.com/github-production-release-asset/1",
        ] {
            assert!(allowed(url).is_ok(), "{url}");
        }
        for url in [
            "http://github.com/eoftgge/rosetun/releases/download/v0.7.0/a.exe",
            "https://github.com:8443/a.exe",
            "https://user@github.com/a.exe",
            "https://github.com.example.com/a.exe",
            "https://example.com/a.exe",
            "https://192.0.2.1/a.exe",
        ] {
            assert_eq!(allowed(url), Err(UpdateDownloadError::Redirect), "{url}");
        }
    }

    #[test]
    fn copying_stops_when_cancelled_or_over_the_limit() {
        let data = vec![7_u8; CHUNK_BYTES * 3];
        let cancelled = AtomicBool::new(true);
        assert_eq!(
            hash_copy(&mut data.as_slice(), None, u64::MAX, &cancelled, |_| {}),
            Err(UpdateDownloadError::Cancelled)
        );
        let running = AtomicBool::new(false);
        assert_eq!(
            hash_copy(&mut data.as_slice(), None, 10, &running, |_| {}),
            Err(UpdateDownloadError::TooLarge)
        );
        let mut seen = 0;
        let digest = hash_copy(&mut data.as_slice(), None, u64::MAX, &running, |received| {
            seen = received;
        });
        assert_eq!(digest, Ok(Sha256::digest(&data).into()));
        assert_eq!(seen, data.len() as u64);
    }

    #[test]
    fn a_replaced_file_fails_the_check_before_it_runs() {
        let directory =
            std::env::temp_dir().join(format!("rosetun-update-test-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("rosetun-0.7.0-setup.exe");
        fs::write(&path, b"installer").unwrap();
        let update = DownloadedUpdate {
            version: "0.7.0".to_owned(),
            path: path.clone(),
            sha256: Sha256::digest(b"installer").into(),
        };
        assert_eq!(update.verify(), Ok(()));
        fs::write(&path, b"replaced").unwrap();
        assert_eq!(update.verify(), Err(UpdateDownloadError::Mismatch));
        fs::remove_file(&path).unwrap();
        assert_eq!(update.verify(), Err(UpdateDownloadError::Mismatch));
        fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn only_old_rosetun_installers_are_cleaned_up() {
        let directory =
            std::env::temp_dir().join(format!("rosetun-update-clean-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        for name in [
            "rosetun-0.6.0-setup.exe",
            "rosetun-0.7.0-setup.exe.partial",
            "rosetun-0.7.0-setup.exe",
            "notes.txt",
        ] {
            fs::write(directory.join(name), b"x").unwrap();
        }
        remove_stale(&directory, "rosetun-0.7.0-setup.exe");
        let mut left: Vec<_> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["notes.txt", "rosetun-0.7.0-setup.exe"]);
        fs::remove_dir_all(&directory).unwrap();
    }
}
