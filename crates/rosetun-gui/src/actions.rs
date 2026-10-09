use crate::strings::t;
use rosetun_config::{ConnectionState, Status};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrimaryAction {
    Disabled,
    Connect,
    Disconnect,
    Retry,
    Reconnect,
}

impl PrimaryAction {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Disabled => t().connecting_action,
            Self::Connect => t().connect,
            Self::Disconnect => t().disconnect,
            Self::Retry => t().retry,
            Self::Reconnect => t().reconnect,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtectionAction {
    None,
    ConfirmDisconnect,
}

pub(crate) fn primary_action(
    helper_available: bool,
    status: &Status,
    has_selected_node: bool,
    operation_in_flight: bool,
) -> PrimaryAction {
    if !helper_available || operation_in_flight {
        return PrimaryAction::Disabled;
    }

    match status.state {
        ConnectionState::Disconnected => {
            if has_selected_node {
                PrimaryAction::Connect
            } else {
                PrimaryAction::Disabled
            }
        }
        ConnectionState::Connecting => PrimaryAction::Disabled,
        ConnectionState::Connected | ConnectionState::Reconnecting => PrimaryAction::Disconnect,
        ConnectionState::Failed { .. } => PrimaryAction::Retry,
        ConnectionState::FailedProtected { .. } => PrimaryAction::Reconnect,
    }
}

pub(crate) fn protection_action(status: &Status, operation_in_flight: bool) -> ProtectionAction {
    if operation_in_flight {
        ProtectionAction::None
    } else if matches!(status.state, ConnectionState::FailedProtected { .. }) {
        ProtectionAction::ConfirmDisconnect
    } else {
        ProtectionAction::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosetun_config::{ConnectionState, Status};

    fn status(state: ConnectionState) -> Status {
        Status {
            state,
            ..Status::default()
        }
    }

    #[test]
    fn action_table_covers_helper_and_selection_states() {
        assert_eq!(
            primary_action(false, &status(ConnectionState::Disconnected), true, false),
            PrimaryAction::Disabled
        );
        assert_eq!(
            primary_action(true, &status(ConnectionState::Disconnected), false, false),
            PrimaryAction::Disabled
        );
        assert_eq!(
            primary_action(true, &status(ConnectionState::Disconnected), true, false),
            PrimaryAction::Connect
        );
        assert_eq!(
            primary_action(true, &status(ConnectionState::Connecting), true, false),
            PrimaryAction::Disabled
        );
        assert_eq!(
            primary_action(true, &status(ConnectionState::Reconnecting), true, false),
            PrimaryAction::Disconnect
        );
        assert_eq!(
            primary_action(true, &status(ConnectionState::Connected), true, false),
            PrimaryAction::Disconnect
        );
        assert_eq!(
            primary_action(
                true,
                &status(ConnectionState::Failed {
                    failure_kind: None,
                    reason: "broken".to_owned(),
                }),
                true,
                false,
            ),
            PrimaryAction::Retry
        );
        assert_eq!(
            primary_action(
                true,
                &status(ConnectionState::FailedProtected {
                    failure_kind: None,
                    reason: "blocked".to_owned(),
                }),
                true,
                false,
            ),
            PrimaryAction::Reconnect
        );
    }

    #[test]
    fn in_flight_commands_gate_every_primary_action() {
        for state in [
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Reconnecting,
            ConnectionState::Failed {
                failure_kind: None,
                reason: "broken".to_owned(),
            },
            ConnectionState::FailedProtected {
                failure_kind: None,
                reason: "blocked".to_owned(),
            },
        ] {
            assert_eq!(
                primary_action(true, &status(state), true, true),
                PrimaryAction::Disabled
            );
        }
        assert_eq!(
            protection_action(
                &status(ConnectionState::FailedProtected {
                    failure_kind: None,
                    reason: "blocked".to_owned(),
                }),
                false,
            ),
            ProtectionAction::ConfirmDisconnect
        );
        assert_eq!(
            protection_action(
                &status(ConnectionState::FailedProtected {
                    failure_kind: None,
                    reason: "blocked".to_owned(),
                }),
                true,
            ),
            ProtectionAction::None
        );
    }
}
