//! The upgrade hold: Lockdown's persistent block, placed by the installer
//! while the kill switch is on, so the network stays closed between the old
//! service stopping and the new one connecting.
//!
//! The installer's new helper decides without talking to the old service,
//! which may speak another protocol: it reads the old session's filters in
//! WFP. Every release since 0.1 builds the kill switch's block-all the same
//! way, a block without conditions in the Rosetun sublayer at the outbound
//! connect layers, while the DNS lock blocks only port 53, always with
//! conditions. With "Local network" on, the kill switch also blocks DNS to
//! private ranges at weight 3, which nothing else in that sublayer uses.
//!
//! The hold is Lockdown's own set plus a marker that tells it apart from a
//! Lockdown the user turned on: a session under it puts its filters above the
//! block exactly as under Lockdown, and lifting it is turning Lockdown off.

use crate::{LockdownApps, LockdownStatus, RoutingError};

/// The private-DNS block's weight in the Rosetun sublayer, in every release.
const PRIVATE_DNS_BLOCK_WEIGHT: u8 = 3;

/// What telling the kill switch apart needs from one filter of the Rosetun
/// sublayer at the outbound connect layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionFilter {
    pub(crate) block: bool,
    pub(crate) conditions: u32,
    /// `None` when the weight is not a plain 8-bit value.
    pub(crate) weight: Option<u8>,
}

/// A running session's kill switch, as found in WFP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KillSwitch {
    pub allow_lan: bool,
}

/// What the installer does before stopping the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldDecision {
    /// The kill switch is on: hold the network closed with its LAN setting.
    Place { allow_lan: bool },
    /// A hold from an earlier, failed upgrade is still there.
    AlreadyHeld,
    /// The user's Lockdown already keeps the network closed.
    LockdownOn,
    /// No kill switch: nothing was closed, so nothing is held.
    NoKillSwitch,
}

/// Finds the kill switch among the session's filters: a block without
/// conditions. A DNS lock alone has none.
pub(crate) fn kill_switch_of(filters: &[SessionFilter]) -> Option<KillSwitch> {
    let block_all = filters
        .iter()
        .any(|filter| filter.block && filter.conditions == 0);
    block_all.then(|| KillSwitch {
        allow_lan: filters
            .iter()
            .any(|filter| filter.block && filter.weight == Some(PRIVATE_DNS_BLOCK_WEIGHT)),
    })
}

pub fn decide(lockdown: &LockdownStatus, kill_switch: Option<KillSwitch>) -> HoldDecision {
    if lockdown.enabled {
        return if lockdown.upgrade_hold {
            HoldDecision::AlreadyHeld
        } else {
            HoldDecision::LockdownOn
        };
    }
    match kill_switch {
        Some(kill_switch) => HoldDecision::Place {
            allow_lan: kill_switch.allow_lan,
        },
        None => HoldDecision::NoKillSwitch,
    }
}

/// The kill switch of the session running now, if any (administrator).
pub fn running_kill_switch() -> Result<Option<KillSwitch>, RoutingError> {
    crate::platform::session_filters().map(|filters| kill_switch_of(&filters))
}

/// Writes Lockdown's set with the hold's marker, in one transaction.
pub fn place(allow_lan: bool, apps: &LockdownApps) -> Result<LockdownStatus, RoutingError> {
    crate::platform::hold_place(allow_lan, apps)
}

/// Removes only the marker: Lockdown stays and is the user's from now on.
pub fn end() -> Result<(), RoutingError> {
    crate::platform::hold_end()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(conditions: u32, weight: u8) -> SessionFilter {
        SessionFilter {
            block: true,
            conditions,
            weight: Some(weight),
        }
    }

    fn permit(conditions: u32, weight: u8) -> SessionFilter {
        SessionFilter {
            block: false,
            conditions,
            weight: Some(weight),
        }
    }

    /// The filters of one family: engine and loopback permits, then the rest.
    fn kill_switch_filters(allow_lan: bool) -> Vec<SessionFilter> {
        let mut filters = vec![permit(2, 2), permit(1, 2), permit(2, 2)];
        if allow_lan {
            filters.extend([permit(1, 2), block(3, 3), block(3, 3)]);
        }
        filters.extend([block(0, 1), permit(1, 4)]);
        filters
    }

    fn dns_lock_filters() -> Vec<SessionFilter> {
        vec![
            permit(2, 2),
            permit(1, 2),
            block(2, 1),
            block(2, 1),
            permit(1, 4),
        ]
    }

    #[test]
    fn the_kill_switch_is_a_block_without_conditions() {
        assert_eq!(
            kill_switch_of(&kill_switch_filters(false)),
            Some(KillSwitch { allow_lan: false })
        );
        assert_eq!(
            kill_switch_of(&kill_switch_filters(true)),
            Some(KillSwitch { allow_lan: true })
        );
    }

    #[test]
    fn the_dns_lock_alone_is_not_a_kill_switch() {
        assert_eq!(kill_switch_of(&dns_lock_filters()), None);
        assert_eq!(kill_switch_of(&[]), None);
        assert_eq!(kill_switch_of(&[permit(0, 2)]), None);
    }

    #[test]
    fn an_unreadable_weight_holds_without_the_local_network() {
        let mut filters = kill_switch_filters(true);
        for filter in &mut filters {
            filter.weight = None;
        }
        assert_eq!(
            kill_switch_of(&filters),
            Some(KillSwitch { allow_lan: false })
        );
    }

    #[test]
    fn the_hold_follows_the_kill_switch_and_its_lan_setting() {
        let off = LockdownStatus::default();
        assert_eq!(
            decide(&off, Some(KillSwitch { allow_lan: true })),
            HoldDecision::Place { allow_lan: true }
        );
        assert_eq!(
            decide(&off, Some(KillSwitch { allow_lan: false })),
            HoldDecision::Place { allow_lan: false }
        );
        assert_eq!(decide(&off, None), HoldDecision::NoKillSwitch);
    }

    #[test]
    fn no_hold_is_placed_under_lockdown_or_twice() {
        let lockdown = LockdownStatus {
            enabled: true,
            complete: true,
            ..LockdownStatus::default()
        };
        assert_eq!(
            decide(&lockdown, Some(KillSwitch { allow_lan: false })),
            HoldDecision::LockdownOn
        );
        let held = LockdownStatus {
            upgrade_hold: true,
            ..lockdown
        };
        assert_eq!(
            decide(&held, Some(KillSwitch { allow_lan: false })),
            HoldDecision::AlreadyHeld
        );
        assert_eq!(decide(&held, None), HoldDecision::AlreadyHeld);
    }
}
