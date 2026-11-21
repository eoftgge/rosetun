//! Flushes the Windows DNS client cache when the tunnel starts or stops
//! carrying traffic. Answers cached before connect (an ISP that substitutes
//! addresses of blocked sites, fake-ip ranges of another VPN client) would
//! otherwise outlive the switch until their TTL expires, and answers cached
//! through the tunnel would outlive a disconnect.

use rosetun_config::ConnectionState;

#[cfg(all(windows, not(test)))]
#[link(name = "dnsapi")]
unsafe extern "system" {
    // Not in windows-sys. Exported by dnsapi.dll since Windows 2000; takes
    // nothing and returns a BOOL.
    fn DnsFlushResolverCache() -> i32;
}

/// Whether a change of the connection state flushes the cache: on every
/// entry into `Connected` (connect, reconnect, apply with a restart) and into
/// `Disconnected` (after teardown removed the session's filters).
pub(super) fn flushes_dns_cache(previous: &ConnectionState, current: &ConnectionState) -> bool {
    match current {
        ConnectionState::Connected => !matches!(previous, ConnectionState::Connected),
        ConnectionState::Disconnected => !matches!(previous, ConnectionState::Disconnected),
        _ => false,
    }
}

#[cfg(all(windows, not(test)))]
pub(super) fn flush() {
    // SAFETY: the function takes no arguments, owns no caller memory and
    // only asks the local DNS client service over RPC to drop its cache;
    // the ABI is `system` with a 32-bit BOOL result.
    if unsafe { DnsFlushResolverCache() } != 0 {
        tracing::debug!("Windows DNS cache flushed");
    } else {
        let error = std::io::Error::last_os_error();
        tracing::warn!(%error, "could not flush the Windows DNS cache");
    }
}

#[cfg(all(target_os = "macos", not(test)))]
pub(super) fn flush() {
    use std::process::{Command, Stdio};

    match Command::new("/usr/bin/dscacheutil")
        .arg("-flushcache")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() => tracing::debug!("macOS Directory Service cache flushed"),
        Ok(status) => tracing::warn!(?status, "dscacheutil -flushcache exited with error"),
        Err(error) => tracing::warn!(%error, "could not run dscacheutil -flushcache"),
    }

    match Command::new("/usr/bin/killall")
        .args(["-HUP", "mDNSResponder"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() => tracing::debug!("mDNSResponder cache flushed"),
        Ok(status) => tracing::debug!(?status, "killall -HUP mDNSResponder exited with non-zero"),
        Err(error) => tracing::warn!(%error, "could not signal mDNSResponder"),
    }
}

// Tests never touch the machine's cache; elsewhere there is no system cache
// to flush.
#[cfg(any(not(any(windows, target_os = "macos")), test))]
pub(super) fn flush() {}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed() -> ConnectionState {
        ConnectionState::Failed {
            reason: "test".to_owned(),
            failure_kind: None,
        }
    }

    fn failed_protected() -> ConnectionState {
        ConnectionState::FailedProtected {
            reason: "test".to_owned(),
            failure_kind: None,
        }
    }

    #[test]
    fn becoming_connected_flushes_from_every_other_state() {
        for previous in [
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Reconnecting,
            failed(),
            failed_protected(),
        ] {
            assert!(
                flushes_dns_cache(&previous, &ConnectionState::Connected),
                "{previous:?}"
            );
        }
    }

    #[test]
    fn staying_connected_does_not_flush() {
        assert!(!flushes_dns_cache(
            &ConnectionState::Connected,
            &ConnectionState::Connected
        ));
    }

    #[test]
    fn becoming_disconnected_flushes_from_every_other_state() {
        for previous in [
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Reconnecting,
            failed(),
            failed_protected(),
        ] {
            assert!(
                flushes_dns_cache(&previous, &ConnectionState::Disconnected),
                "{previous:?}"
            );
        }
    }

    #[test]
    fn staying_disconnected_does_not_flush() {
        assert!(!flushes_dns_cache(
            &ConnectionState::Disconnected,
            &ConnectionState::Disconnected
        ));
    }

    #[test]
    fn connecting_reconnecting_and_failures_do_not_flush() {
        for current in [
            ConnectionState::Connecting,
            ConnectionState::Reconnecting,
            failed(),
            failed_protected(),
        ] {
            for previous in [
                ConnectionState::Disconnected,
                ConnectionState::Connecting,
                ConnectionState::Connected,
                ConnectionState::Reconnecting,
            ] {
                assert!(
                    !flushes_dns_cache(&previous, &current),
                    "{previous:?} -> {current:?}"
                );
            }
        }
    }
}
