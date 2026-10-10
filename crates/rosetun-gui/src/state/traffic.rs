use std::collections::VecDeque;

use rosetun_config::{ConnectionState, Status};

use super::{Action, Job, Screen, State};

pub(super) const TRAFFIC_HISTORY: usize = 900;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum TrafficRange {
    #[default]
    OneMinute,
    FiveMinutes,
    FifteenMinutes,
}

impl TrafficRange {
    pub(crate) fn samples_per_bar(self) -> usize {
        match self {
            Self::OneMinute => 1,
            Self::FiveMinutes => 5,
            Self::FifteenMinutes => 15,
        }
    }
}

#[derive(Default)]
pub(crate) struct TrafficState {
    /// Rates of the last 15 minutes, one sample per status; newest last.
    pub(crate) traffic_history: VecDeque<(u64, u64)>,
    pub(crate) traffic_range: TrafficRange,
}

impl State {
    pub(super) fn reduce_traffic_status(&mut self, status: &Status) {
        if self.helper_available
            && matches!(
                status.state,
                ConnectionState::Connected | ConnectionState::Reconnecting
            )
        {
            self.traffic
                .traffic_history
                .push_back((status.traffic.down_bps, status.traffic.up_bps));
            if self.traffic.traffic_history.len() > TRAFFIC_HISTORY {
                self.traffic.traffic_history.pop_front();
            }
        } else {
            self.traffic.traffic_history.clear();
        }
    }

    pub(super) fn clear_traffic_history(&mut self) {
        self.traffic.traffic_history.clear();
    }

    pub(super) fn act_traffic(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::OpenTraffic => self.show_screen(Screen::Traffic),
            Action::SetTrafficRange(range) => {
                self.traffic.traffic_range = range;
                None
            }
            _ => unreachable!("only traffic actions are dispatched here"),
        }
    }
}
