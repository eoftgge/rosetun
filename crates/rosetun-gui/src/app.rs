use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui;
use rosetun_core::Store;

#[cfg(windows)]
use crate::state::Action;
use crate::state::{Job, State};
#[cfg(windows)]
use crate::tray;
#[cfg(windows)]
use crate::window_memory::WindowMemory;
use crate::worker::{self, WorkerDispatcher, WorkerEvent};
use crate::{display, strings, theme, view};

#[cfg(windows)]
/// Far outside every monitor: the first frame of a hidden start is drawn here.
pub(crate) const OFFSCREEN: egui::Pos2 = egui::pos2(-32000.0, -32000.0);

#[cfg(windows)]
fn centered_position(monitor: Option<egui::Vec2>, window: egui::Vec2) -> egui::Pos2 {
    monitor.map_or(egui::pos2(80.0, 80.0), |monitor| {
        egui::pos2(
            ((monitor.x - window.x) / 2.0).max(0.0),
            ((monitor.y - window.y) / 2.0).max(0.0),
        )
    })
}

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
    system_russian: bool,
    #[cfg(windows)]
    shell_events: Option<Receiver<ShellEvent>>,
    #[cfg(windows)]
    tray: Option<tray::Tray>,
    #[cfg(windows)]
    hide_on_start: bool,
    #[cfg(windows)]
    place_on_show: bool,
    #[cfg(windows)]
    window: Option<WindowMemory>,
    #[cfg(windows)]
    maximize_in: Option<u8>,
    #[cfg(windows)]
    quitting: bool,
}

impl App {
    pub(crate) fn new(cc: &eframe::CreationContext<'_>, store: Store) -> Self {
        theme::apply(&cc.egui_ctx);
        #[cfg(windows)]
        let system_russian = rosetun_shell::user_language_is_russian();
        #[cfg(not(windows))]
        let system_russian = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .into_iter()
            .filter_map(|key| std::env::var(key).ok())
            .find(|value| !value.trim().is_empty())
            .is_some_and(|value| locale_is_russian(&value));
        let setting = store
            .load()
            .map_or(rosetun_config::LanguageSetting::System, |config| {
                config.interface.language
            });
        strings::set_language(strings::resolve_language(setting, system_russian));
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
            system_russian,
            #[cfg(windows)]
            shell_events: None,
            #[cfg(windows)]
            tray: None,
            #[cfg(windows)]
            hide_on_start: false,
            #[cfg(windows)]
            place_on_show: false,
            #[cfg(windows)]
            window: None,
            #[cfg(windows)]
            maximize_in: None,
            #[cfg(windows)]
            quitting: false,
        }
    }

    #[cfg(windows)]
    pub(crate) fn with_shell(
        mut self,
        ctx: &egui::Context,
        activation: Option<rosetun_shell::Activation>,
        start_hidden: bool,
        window: Option<WindowMemory>,
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
        self.hide_on_start = start_hidden && self.tray.is_some();
        self.place_on_show = start_hidden;
        self.window = window;
        if !start_hidden
            && let Some(window) = &mut self.window
            && window.place()
        {
            self.maximize_in = Some(1);
        }
        if start_hidden && self.tray.is_none() {
            let _ = sender.send(ShellEvent::Show);
        }
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
    fn show_window(&mut self, ctx: &egui::Context) {
        if std::mem::take(&mut self.place_on_show) {
            if let Some(window) = &mut self.window {
                if window.place() {
                    self.maximize_in = Some(1);
                }
            } else {
                let (monitor, size) = ctx.input(|input| {
                    let viewport = input.viewport();
                    (
                        viewport.monitor_size,
                        viewport
                            .outer_rect
                            .map_or(egui::vec2(1200.0, 780.0), |rect| rect.size()),
                    )
                });
                ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(centered_position(
                    monitor, size,
                )));
            }
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    #[cfg(windows)]
    fn hides_on_close(&self) -> bool {
        self.tray.is_some()
            && !self.quitting
            && (!self.state.config_ready || self.state.config.interface.close_to_tray)
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
            Job::SetLanguage(language) => self.workers.set_language(language),
            Job::SetReduceMotion(enabled) => self.workers.set_reduce_motion(enabled),
            #[cfg(windows)]
            Job::LoadAutostart => self.workers.load_autostart(),
            #[cfg(windows)]
            Job::SetAutostart(enabled) => self.workers.set_autostart(enabled),
            #[cfg(windows)]
            Job::SetCloseToTray(enabled) => self.workers.set_close_to_tray(enabled),
            Job::SetConnectOnStart(enabled) => self.workers.set_connect_on_start(enabled),
            Job::SetAutoReconnect(enabled) => self.workers.set_auto_reconnect(enabled),
            Job::SetAutoUpdateSubscriptions(enabled) => {
                self.workers.set_auto_update_subscriptions(enabled)
            }
            Job::SetDns(dns) => self.workers.set_dns(dns),
            Job::SetVerboseLog(on) => self.workers.set_verbose_log(on),
            #[cfg(windows)]
            Job::OpenConfigFolder(folder) => self.workers.open_config_folder(folder),
            Job::SelectNode(subscription, node) => self.workers.select_node(subscription, node),
            Job::SelectRuleSet(id) => self.workers.select_rule_set(id),
            Job::CreateRuleSet(name) => self.workers.create_rule_set(name),
            Job::RenameRuleSet(id, name) => self.workers.rename_rule_set(id, name),
            Job::DeleteRuleSet(id) => self.workers.delete_rule_set(id),
            Job::SetDefaultTarget(id, target) => self.workers.set_default_target(id, target),
            Job::LoadProcesses(request) => self.workers.load_processes(request),
            #[cfg(windows)]
            Job::BrowseExecutable => self.workers.browse_executable(),
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
            Job::Ping(id) => self.workers.ping(id),
            Job::UpdateAll => self.workers.update_all(),
            Job::Remove(id) => self.workers.remove(id),
            Job::MoveSubscription(id, to_index) => self.workers.move_subscription(id, to_index),
        }
    }
}

#[cfg(any(not(windows), test))]
fn locale_is_russian(value: &str) -> bool {
    value.starts_with("ru")
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
        #[cfg(windows)]
        if let Some(frames) = self.maximize_in.as_mut() {
            if *frames == 0 {
                // Maximizing before the first onscreen frame can make Windows show it early.
                ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(true));
                self.maximize_in = None;
            } else {
                *frames -= 1;
                ctx.request_repaint();
            }
        }
        while let Ok(event) = self.events.try_recv() {
            self.state.reduce(event);
        }
        if let Some(job) = self.state.take_auto_connect() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_auto_update(display::now_unix()) {
            self.dispatch(job);
        }
        let language =
            strings::resolve_language(self.state.config.interface.language, self.system_russian);
        if self.state.config_ready && language != strings::language() {
            strings::set_language(language);
            ctx.request_repaint();
        }
        #[cfg(windows)]
        {
            if std::mem::take(&mut self.hide_on_start) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
            while let Some(event) = self
                .shell_events
                .as_ref()
                .and_then(|events| events.try_recv().ok())
            {
                match event {
                    ShellEvent::Show => self.show_window(ctx),
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
        if ctx.input(|input| input.viewport().close_requested()) {
            #[cfg(windows)]
            if let Some(window) = &self.window {
                window.save();
            }
            if self.hides_on_close() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
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
    #[cfg(windows)]
    use super::centered_position;
    use super::{initial_scale, locale_is_russian, next_scale};
    #[cfg(windows)]
    use eframe::egui;
    use rosetun_core::Store;
    use std::fs;

    #[cfg(windows)]
    #[test]
    fn window_is_centered_on_monitor() {
        assert_eq!(
            centered_position(Some(egui::vec2(1920.0, 1080.0)), egui::vec2(1200.0, 780.0)),
            egui::pos2(360.0, 150.0),
        );
    }

    #[cfg(windows)]
    #[test]
    fn window_does_not_start_above_or_left_of_a_small_monitor() {
        assert_eq!(
            centered_position(Some(egui::vec2(800.0, 600.0)), egui::vec2(1200.0, 780.0)),
            egui::pos2(0.0, 0.0),
        );
    }

    #[cfg(windows)]
    #[test]
    fn window_uses_fallback_position_without_monitor_size() {
        assert_eq!(
            centered_position(None, egui::vec2(1200.0, 780.0)),
            egui::pos2(80.0, 80.0),
        );
    }

    #[test]
    fn russian_locale_detection() {
        assert!(locale_is_russian("ru_RU.UTF-8"));
        assert!(locale_is_russian("ru"));
        assert!(!locale_is_russian("en_US.UTF-8"));
        assert!(!locale_is_russian(""));
    }

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
