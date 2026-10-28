//! When the tray says the tunnel dropped or came back, or that a new version
//! is out. The notices name no server and no address: Windows shows them on
//! the lock screen.

use std::collections::HashMap;
use std::mem::discriminant;
use std::time::{Duration, Instant};

use rosetun_config::ConnectionState;

/// The same notice is not repeated sooner than this.
pub(crate) const NOTICE_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Notice {
    /// The tunnel dropped and protection holds the traffic.
    DroppedBlocked,
    Dropped,
    Restored,
    ConnectFailed,
}

impl Notice {
    pub(crate) fn text(self) -> String {
        match self {
            Self::DroppedBlocked => tr!("notice-dropped-blocked"),
            Self::Dropped => tr!("notice-dropped"),
            Self::Restored => tr!("notice-restored"),
            Self::ConnectFailed => tr!("notice-connect-failed"),
        }
    }
}

/// The notice for one change of the connection state, if any. `previous` is
/// `None` for the first status after start; `by_user` means the user's own
/// disconnect, apply or reconnect caused the change; `last_shown` is when
/// the same notice was last shown.
pub(crate) fn notice(
    previous: Option<&ConnectionState>,
    next: &ConnectionState,
    by_user: bool,
    window_active: bool,
    last_shown: impl Fn(Notice) -> Option<Instant>,
    now: Instant,
) -> Option<Notice> {
    let previous = previous?;
    if discriminant(previous) == discriminant(next) || window_active {
        return None;
    }
    let notice = match (previous, next) {
        (
            ConnectionState::Connected,
            ConnectionState::FailedProtected { .. } | ConnectionState::Reconnecting,
        ) if !by_user => Notice::DroppedBlocked,
        (ConnectionState::Connected, ConnectionState::Failed { .. }) if !by_user => Notice::Dropped,
        (
            ConnectionState::Reconnecting | ConnectionState::FailedProtected { .. },
            ConnectionState::Connected,
        ) if !by_user => Notice::Restored,
        (ConnectionState::Connecting, ConnectionState::Failed { .. }) => Notice::ConnectFailed,
        _ => return None,
    };
    let recent = last_shown(notice)
        .is_some_and(|shown| now.saturating_duration_since(shown) < NOTICE_INTERVAL);
    (!recent).then_some(notice)
}

/// Whether the tray announces `found`, the offered version (`None` when
/// there is none). A version is announced once: `announced` is the one
/// announced last, and a skipped one is never announced.
pub(crate) fn announces_update(
    found: Option<&str>,
    announced: Option<&str>,
    skipped: Option<&str>,
    notifications: bool,
    window_active: bool,
) -> bool {
    found.is_some_and(|found| {
        notifications && !window_active && announced != Some(found) && skipped != Some(found)
    })
}

/// Follows the visible connection state between frames for `notice`.
#[derive(Default)]
pub(crate) struct Notices {
    previous: Option<ConnectionState>,
    /// The user started the current drop, so its end is theirs too.
    drop_by_user: bool,
    shown: HashMap<Notice, Instant>,
    /// Announced in this run: the saved record may still be on its way.
    announced_update: Option<String>,
}

impl Notices {
    /// `next` is `None` while the service is unreachable: its first status
    /// after that is a fresh start, not a change. `user_busy` is whether a
    /// disconnect, connect or apply of the user's is in flight.
    pub(crate) fn observe(
        &mut self,
        next: Option<&ConnectionState>,
        user_busy: bool,
        window_active: bool,
        now: Instant,
    ) -> Option<Notice> {
        let Some(next) = next else {
            self.previous = None;
            return None;
        };
        let by_user = match (&self.previous, next) {
            (Some(ConnectionState::Connected), ConnectionState::Connected) => user_busy,
            (Some(ConnectionState::Connected), _) => {
                self.drop_by_user = user_busy;
                user_busy
            }
            (
                Some(ConnectionState::Reconnecting | ConnectionState::FailedProtected { .. }),
                ConnectionState::Connected,
            ) => self.drop_by_user || user_busy,
            _ => user_busy,
        };
        let shown = &self.shown;
        let notice = notice(
            self.previous.as_ref(),
            next,
            by_user,
            window_active,
            |notice| shown.get(&notice).copied(),
            now,
        );
        if let Some(notice) = notice {
            self.shown.insert(notice, now);
        }
        self.previous = Some(next.clone());
        notice
    }

    /// The version to announce now, if any (see `announces_update`).
    pub(crate) fn observe_update(
        &mut self,
        found: Option<&str>,
        saved_announced: Option<&str>,
        skipped: Option<&str>,
        notifications: bool,
        window_active: bool,
    ) -> Option<String> {
        let announced = match self.announced_update.as_deref() {
            Some(version) if Some(version) == found => Some(version),
            _ => saved_announced,
        };
        if !announces_update(found, announced, skipped, notifications, window_active) {
            return None;
        }
        let found = found?.to_owned();
        self.announced_update = Some(found.clone());
        Some(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed() -> ConnectionState {
        ConnectionState::Failed {
            reason: "dial tcp 192.0.2.1:443".into(),
            failure_kind: None,
        }
    }

    fn protected() -> ConnectionState {
        ConnectionState::FailedProtected {
            reason: String::new(),
            failure_kind: None,
        }
    }

    fn change(previous: &ConnectionState, next: &ConnectionState, by_user: bool) -> Option<Notice> {
        notice(
            Some(previous),
            next,
            by_user,
            false,
            |_| None,
            Instant::now(),
        )
    }

    #[test]
    fn a_drop_from_connected_says_whether_the_internet_is_closed() {
        let connected = ConnectionState::Connected;
        assert_eq!(
            change(&connected, &protected(), false),
            Some(Notice::DroppedBlocked)
        );
        assert_eq!(
            change(&connected, &ConnectionState::Reconnecting, false),
            Some(Notice::DroppedBlocked)
        );
        assert_eq!(change(&connected, &failed(), false), Some(Notice::Dropped));
    }

    #[test]
    fn a_change_the_user_made_is_not_announced() {
        let connected = ConnectionState::Connected;
        for next in [protected(), ConnectionState::Reconnecting, failed()] {
            assert_eq!(change(&connected, &next, true), None, "{next:?}");
        }
        assert_eq!(
            change(&connected, &ConnectionState::Disconnected, false),
            None,
            "a disconnect"
        );
        assert_eq!(
            change(&ConnectionState::Reconnecting, &connected, true),
            None
        );
    }

    #[test]
    fn the_tunnel_coming_back_is_announced() {
        for previous in [ConnectionState::Reconnecting, protected()] {
            assert_eq!(
                change(&previous, &ConnectionState::Connected, false),
                Some(Notice::Restored),
                "{previous:?}"
            );
        }
        assert_eq!(
            change(
                &ConnectionState::Connecting,
                &ConnectionState::Connected,
                false
            ),
            None,
            "an ordinary connect"
        );
    }

    #[test]
    fn a_failed_connect_is_announced() {
        assert_eq!(
            change(&ConnectionState::Connecting, &failed(), true),
            Some(Notice::ConnectFailed)
        );
    }

    #[test]
    fn nothing_is_announced_for_a_repeat_the_first_status_or_an_active_window() {
        assert_eq!(change(&failed(), &failed(), false), None);
        assert_eq!(change(&protected(), &protected(), false), None);
        assert_eq!(
            notice(None, &failed(), false, false, |_| None, Instant::now()),
            None
        );
        assert_eq!(
            notice(
                Some(&ConnectionState::Connected),
                &protected(),
                false,
                true,
                |_| None,
                Instant::now()
            ),
            None
        );
    }

    #[test]
    fn the_same_notice_waits_thirty_seconds() {
        let now = Instant::now();
        let at = |shown: Instant| {
            notice(
                Some(&ConnectionState::Connected),
                &protected(),
                false,
                false,
                move |notice| (notice == Notice::DroppedBlocked).then_some(shown),
                now,
            )
        };
        assert_eq!(at(now - Duration::from_secs(29)), None);
        assert_eq!(at(now - NOTICE_INTERVAL), Some(Notice::DroppedBlocked));
        assert_eq!(
            notice(
                Some(&ConnectionState::Reconnecting),
                &ConnectionState::Connected,
                false,
                false,
                |notice| (notice == Notice::DroppedBlocked).then_some(now),
                now,
            ),
            Some(Notice::Restored),
            "another notice is not held back"
        );
    }

    #[test]
    fn a_drop_and_its_return_follow_who_started_it() {
        let now = Instant::now();
        let mut notices = Notices::default();
        let connected = ConnectionState::Connected;
        let reconnecting = ConnectionState::Reconnecting;
        assert_eq!(notices.observe(Some(&connected), false, false, now), None);
        assert_eq!(
            notices.observe(Some(&reconnecting), true, false, now),
            None,
            "a server switch"
        );
        assert_eq!(
            notices.observe(Some(&connected), false, false, now),
            None,
            "the switch is done"
        );
        assert_eq!(
            notices.observe(Some(&reconnecting), false, false, now),
            Some(Notice::DroppedBlocked)
        );
        assert_eq!(
            notices.observe(Some(&connected), false, false, now),
            Some(Notice::Restored)
        );
        assert_eq!(
            notices.observe(
                Some(&reconnecting),
                false,
                false,
                now + Duration::from_secs(5)
            ),
            None,
            "within 30 s"
        );
        assert_eq!(notices.observe(None, false, false, now), None);
        assert_eq!(
            notices.observe(Some(&connected), false, false, now + NOTICE_INTERVAL),
            None,
            "the first status after the service comes back"
        );
    }

    #[test]
    fn a_found_version_is_announced_while_the_window_is_away() {
        assert!(announces_update(Some("0.4.0"), None, None, true, false));
        assert!(announces_update(
            Some("0.4.0"),
            Some("0.3.1"),
            Some("0.3.1"),
            true,
            false
        ));
    }

    #[test]
    fn nothing_found_is_not_announced() {
        assert!(!announces_update(None, None, None, true, false));
    }

    #[test]
    fn an_announced_version_is_not_announced_again() {
        assert!(!announces_update(
            Some("0.4.0"),
            Some("0.4.0"),
            None,
            true,
            false
        ));
    }

    #[test]
    fn a_skipped_version_is_not_announced() {
        assert!(!announces_update(
            Some("0.4.0"),
            None,
            Some("0.4.0"),
            true,
            false
        ));
    }

    #[test]
    fn no_update_notice_with_notifications_off() {
        assert!(!announces_update(Some("0.4.0"), None, None, false, false));
    }

    #[test]
    fn no_update_notice_while_the_window_is_active() {
        assert!(!announces_update(Some("0.4.0"), None, None, true, true));
    }

    #[test]
    fn the_tracker_announces_once_before_the_record_is_saved() {
        let mut notices = Notices::default();
        assert_eq!(
            notices.observe_update(Some("0.4.0"), None, None, true, false),
            Some("0.4.0".to_owned())
        );
        assert_eq!(
            notices.observe_update(Some("0.4.0"), None, None, true, false),
            None
        );
        assert_eq!(
            notices.observe_update(Some("0.4.1"), Some("0.4.0"), None, true, false),
            Some("0.4.1".to_owned())
        );
    }
}
