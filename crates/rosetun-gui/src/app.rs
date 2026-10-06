use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui;
use rosetun_core::Store;

#[cfg(windows)]
use crate::state::Action;
use crate::state::{Job, State};
#[cfg(windows)]
use crate::tray;
use crate::worker::{self, WorkerDispatcher, WorkerEvent};
use crate::{theme, view};

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellEvent {
    Show,
    Primary,
    Quit,
}

pub(crate) struct App {
    state: State,
    events: Receiver<WorkerEvent>,
    workers: WorkerDispatcher,
    applied_scale: Option<u16>,
    #[cfg(windows)]
    shell_events: Option<Receiver<ShellEvent>>,
    #[cfg(windows)]
    tray: Option<tray::Tray>,
    #[cfg(windows)]
    quitting: bool,
}

impl App {
    pub(crate) fn new(cc: &eframe::CreationContext<'_>, store: Store) -> Self {
        theme::apply(&cc.egui_ctx);
        let applied_scale = initial_scale(&store);
        cc.egui_ctx
            .set_zoom_factor(f32::from(applied_scale) / 100.0);
        let (tx, events) = mpsc::channel();
        let mut state = State::default();
        state.settings_screen.config_folder = store.path().parent().map(|path| path.to_owned());
        let workers = worker::start(store, tx, cc.egui_ctx.clone());
        Self {
            state,
            events,
            workers,
            applied_scale: Some(applied_scale),
            #[cfg(windows)]
            shell_events: None,
            #[cfg(windows)]
            tray: None,
            #[cfg(windows)]
            quitting: false,
        }
    }

    #[cfg(windows)]
    pub(crate) fn with_shell(
        mut self,
        ctx: &egui::Context,
        activation: Option<rosetun_shell::Activation>,
    ) -> Self {
        let (sender, events) = mpsc::channel();
        self.shell_events = Some(events);
        self.tray = match tray::Tray::new(sender.clone(), ctx.clone()) {
            Ok(tray) => Some(tray),
            Err(error) => {
                tracing::warn!(%error, "Could not create tray icon");
                None
            }
        };
        if let Some(activation) = activation {
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                loop {
                    if let Err(error) = activation.wait() {
                        tracing::warn!(%error, "Could not wait for GUI activation");
                        break;
                    }
                    if sender.send(ShellEvent::Show).is_err() {
                        break;
                    }
                    ctx.request_repaint();
                }
            });
        }
        self
    }

    #[cfg(windows)]
    fn hides_on_close(&self) -> bool {
        self.tray.is_some() && !self.quitting
    }

    #[cfg(not(windows))]
    fn hides_on_close(&self) -> bool {
        false
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

fn initial_scale(store: &Store) -> u16 {
    store.load().map_or_else(
        |_| rosetun_config::InterfaceSettings::default().scale_percent,
        |config| supported_scale(config.interface.scale_percent),
    )
}

fn supported_scale(configured: u16) -> u16 {
    // The file can be edited by hand; an unknown scale must not make the window unusable.
    if rosetun_core::INTERFACE_SCALES.contains(&configured) {
        configured
    } else {
        rosetun_config::InterfaceSettings::default().scale_percent
    }
}

fn next_scale(applied: Option<u16>, configured: u16) -> Option<u16> {
    let percent = supported_scale(configured);
    (applied != Some(percent)).then_some(percent)
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.events.try_recv() {
            self.state.reduce(event);
        }
        #[cfg(windows)]
        {
            while let Some(event) = self
                .shell_events
                .as_ref()
                .and_then(|events| events.try_recv().ok())
            {
                match event {
                    ShellEvent::Show => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    }
                    ShellEvent::Primary => {
                        if let Some(job) = self.state.act(Action::Primary) {
                            self.dispatch(job);
                        }
                    }
                    ShellEvent::Quit => {
                        self.quitting = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
            if let Some(tray) = &mut self.tray {
                tray.sync(&tray::tray_view(&self.state));
            }
        }
        if ctx.input(|input| input.viewport().close_requested()) && self.hides_on_close() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
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
    use super::{initial_scale, next_scale};
    use rosetun_core::Store;
    use std::fs;

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

    #[test]
    fn initial_scale_uses_saved_value_before_config_event() {
        let path =
            std::env::temp_dir().join(format!("rosetun-gui-initial-scale-{}", std::process::id()));
        let store = Store::at(&path);
        assert_eq!(initial_scale(&store), 100);

        fs::write(&path, r#"{"interface":{"scale_percent":125}}"#).unwrap();
        let applied = initial_scale(&store);
        assert_eq!(applied, 125);
        assert_eq!(next_scale(Some(applied), 125), None);
        assert_eq!(next_scale(Some(applied), 100), Some(100));

        fs::write(&path, r#"{"interface":{"scale_percent":1000}}"#).unwrap();
        assert_eq!(initial_scale(&store), 100);
        fs::write(&path, "{invalid").unwrap();
        assert_eq!(initial_scale(&store), 100);
        fs::remove_file(path).unwrap();
    }
}
