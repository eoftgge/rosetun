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
}

impl App {
    pub(crate) fn new(cc: &eframe::CreationContext<'_>, store: Store) -> Self {
        theme::apply(&cc.egui_ctx);
        let (tx, events) = mpsc::channel();
        let workers = worker::start(store, tx, cc.egui_ctx.clone());
        Self {
            state: State::default(),
            events,
            workers,
        }
    }

    fn dispatch(&self, job: Job) {
        match job {
            Job::Connect => self.workers.connect(),
            Job::Disconnect => self.workers.disconnect(),
            Job::SelectNode(subscription, node) => self.workers.select_node(subscription, node),
            Job::SelectRuleSet(id) => self.workers.select_rule_set(id),
            Job::CreateRuleSet(name) => self.workers.create_rule_set(name),
            Job::RenameRuleSet(id, name) => self.workers.rename_rule_set(id, name),
            Job::DeleteRuleSet(id) => self.workers.delete_rule_set(id),
            Job::SetDefaultTarget(id, target) => self.workers.set_default_target(id, target),
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
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.events.try_recv() {
            self.state.reduce(event);
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
