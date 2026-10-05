use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui;
use rosetun_core::Store;

use crate::state::{Job, State};
use crate::worker::{self, WorkerDispatcher, WorkerEvent};
use crate::{theme, view};

pub(crate) struct App {
    state: State,
    events: Receiver<WorkerEvent>,
    workers: WorkerDispatcher,
    applied_scale: Option<u16>,
}

impl App {
    pub(crate) fn new(cc: &eframe::CreationContext<'_>, store: Store) -> Self {
        theme::apply(&cc.egui_ctx);
        let (tx, events) = mpsc::channel();
        let mut state = State::default();
        state.settings_screen.config_folder = store.path().parent().map(|path| path.to_owned());
        let workers = worker::start(store, tx, cc.egui_ctx.clone());
        Self {
            state,
            events,
            workers,
            applied_scale: None,
        }
    }

    fn dispatch(&self, job: Job) {
        match job {
            Job::Connect => self.workers.connect(),
            Job::Disconnect => self.workers.disconnect(),
            Job::SetInterfaceScale(percent) => self.workers.set_interface_scale(percent),
            Job::SetDns(dns) => self.workers.set_dns(dns),
            Job::SetEngineLogLevel(level) => self.workers.set_engine_log_level(level),
            #[cfg(windows)]
            Job::OpenConfigFolder(folder) => self.workers.open_config_folder(folder),
            Job::SelectNode(subscription, node) => self.workers.select_node(subscription, node),
            Job::SelectRuleSet(id) => self.workers.select_rule_set(id),
            Job::CreateRuleSet(name) => self.workers.create_rule_set(name),
            Job::RenameRuleSet(id, name) => self.workers.rename_rule_set(id, name),
            Job::DeleteRuleSet(id) => self.workers.delete_rule_set(id),
            Job::SetDefaultTarget(id, target) => self.workers.set_default_target(id, target),
            Job::LoadProcesses(request) => self.workers.load_processes(request),
            Job::AddRule(set, matcher, target) => self.workers.add_rule(set, matcher, target),
            Job::SetRuleTarget(set, rule, target) => {
                self.workers.set_rule_target(set, rule, target)
            }
            Job::SetRuleEnabled(set, rule, enabled) => {
                self.workers.set_rule_enabled(set, rule, enabled);
            }
            Job::MoveRule(set, rule, to_index) => self.workers.move_rule(set, rule, to_index),
            Job::RemoveRule(set, rule) => self.workers.remove_rule(set, rule),
            Job::SetKillSwitch(enabled) => self.workers.set_kill_switch(enabled),
            Job::Add { input, options } => self.workers.add(input, options),
            Job::Update(id) => self.workers.update(id),
            Job::UpdateAll => self.workers.update_all(),
            Job::Remove(id) => self.workers.remove(id),
            Job::MoveSubscription(id, to_index) => self.workers.move_subscription(id, to_index),
        }
    }
}

fn next_scale(applied: Option<u16>, configured: u16) -> Option<u16> {
    // The file can be edited by hand; an unknown scale must not make the window unusable.
    let percent = if rosetun_core::INTERFACE_SCALES.contains(&configured) {
        configured
    } else {
        rosetun_config::InterfaceSettings::default().scale_percent
    };
    (applied != Some(percent)).then_some(percent)
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.events.try_recv() {
            self.state.reduce(event);
        }
        if self.state.config_ready
            && let Some(percent) = next_scale(
                self.applied_scale,
                self.state.config.interface.scale_percent,
            )
        {
            ui.ctx().set_zoom_factor(f32::from(percent) / 100.0);
            self.applied_scale = Some(percent);
        }
        let actions = view::show(ui, &mut self.state);
        if !actions.is_empty() {
            ui.ctx().request_repaint();
        }
        for action in actions {
            if let Some(job) = self.state.act(action) {
                self.dispatch(job);
            }
        }
        ui.ctx().request_repaint_after(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::next_scale;

    #[test]
    fn scale_applies_on_first_config_and_on_change_only() {
        assert_eq!(next_scale(None, 100), Some(100));
        assert_eq!(next_scale(Some(100), 100), None);
        assert_eq!(next_scale(Some(100), 125), Some(125));
        assert_eq!(next_scale(Some(125), 125), None);
    }

    #[test]
    fn unsupported_scale_falls_back_to_default() {
        assert_eq!(next_scale(None, 1000), Some(100));
        assert_eq!(next_scale(Some(100), 0), None);
        assert_eq!(next_scale(Some(125), 95), Some(100));
    }
}
