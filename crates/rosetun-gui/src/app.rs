use std::sync::mpsc::{self, Receiver};
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;

use eframe::egui;
use rosetun_core::Store;

#[cfg(windows)]
use crate::notices::Notices;
#[cfg(windows)]
use crate::state::{Action, OpenedLink};
use crate::state::{Job, State};
#[cfg(windows)]
use crate::tray;
#[cfg(windows)]
use crate::window_memory::WindowMemory;
use crate::worker::{self, WorkerDispatcher, WorkerEvent};
use crate::{brand, display, i18n, motion, theme, view};

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
#[derive(Debug)]
pub(crate) enum ShellEvent {
    Show,
    OpenLink(OpenedLink),
    Hide,
    Primary,
    SelectServer(rosetun_config::Selection),
    ShowServers,
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
    notices: Notices,
    #[cfg(windows)]
    hide_on_start: bool,
    #[cfg(windows)]
    place_on_show: bool,
    #[cfg(windows)]
    window: Option<WindowMemory>,
    #[cfg(windows)]
    maximize_in: Option<u8>,
    #[cfg(windows)]
    window_minimized: bool,
    /// eframe on Windows cannot tell a window hidden in the tray from a shown one.
    #[cfg(windows)]
    window_hidden: bool,
    #[cfg(windows)]
    quitting: bool,
    #[cfg(windows)]
    quit_apply_deadline: Option<Instant>,
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
        i18n::set_language(i18n::resolve_language(setting, system_russian));
        let applied_scale = initial_scale(&store);
        cc.egui_ctx
            .set_zoom_factor(f32::from(applied_scale) / 100.0);
        let (tx, events) = mpsc::channel();
        let mut state = State::default();
        state.settings.screen.config_folder =
            store.path().parent().map(std::borrow::ToOwned::to_owned);
        state.settings.screen.licenses_folder = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("licenses")))
            .filter(|dir| dir.is_dir());
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
            notices: Notices::default(),
            #[cfg(windows)]
            hide_on_start: false,
            #[cfg(windows)]
            place_on_show: false,
            #[cfg(windows)]
            window: None,
            #[cfg(windows)]
            maximize_in: None,
            #[cfg(windows)]
            window_minimized: false,
            #[cfg(windows)]
            window_hidden: false,
            #[cfg(windows)]
            quitting: false,
            #[cfg(windows)]
            quit_apply_deadline: None,
        }
    }

    #[cfg(windows)]
    pub(crate) fn with_shell(
        mut self,
        ctx: &egui::Context,
        activation: Option<rosetun_shell::Activation>,
        links: Option<rosetun_shell::LinkListener>,
        open_link: Option<String>,
        start_hidden: bool,
        window: Option<WindowMemory>,
    ) -> Self {
        let (sender, events) = mpsc::channel();
        self.shell_events = Some(events);
        self.tray = match tray::Tray::new(sender.clone(), ctx.clone()) {
            Ok(tray) => Some(tray),
            Err(error) => {
                tracing::warn!(%error, "could not create tray icon");
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
        if let Some(link) = open_link {
            let _ = sender.send(ShellEvent::OpenLink(OpenedLink(link)));
        }
        if let Some(links) = links {
            let sender = sender.clone();
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                let served = links.serve(|link| {
                    let _ = sender.send(ShellEvent::OpenLink(OpenedLink(link)));
                    let _ = sender.send(ShellEvent::Show);
                    ctx.request_repaint();
                });
                if let Err(error) = served {
                    tracing::warn!(%error, "link pipe stopped");
                }
            });
        }
        if let Some(activation) = activation {
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                loop {
                    if let Err(error) = activation.wait() {
                        tracing::warn!(%error, "could not wait for GUI activation");
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
        self.window_hidden = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    #[cfg(windows)]
    fn hide_window(&mut self, ctx: &egui::Context) {
        if let Some(window) = &self.window {
            window.save();
        }
        if let Some(job) = self.state.apply_on_leave() {
            self.dispatch(job);
        }
        self.window_hidden = true;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
    }

    #[cfg(windows)]
    fn hides_on_close(&self) -> bool {
        self.tray.is_some() && !self.quitting && self.state.close_hides_window()
    }

    #[cfg(not(windows))]
    fn hides_on_close(&self) -> bool {
        false
    }

    #[cfg(windows)]
    fn window_hidden(&self) -> bool {
        self.window_hidden
    }

    #[cfg(not(windows))]
    fn window_hidden(&self) -> bool {
        false
    }

    fn dispatch(&self, job: Job) {
        match job {
            Job::Connect(inputs) => self.workers.connect(inputs),
            Job::CheckSystem {
                request,
                own_alias,
                guarded,
            } => self.workers.check_system(request, own_alias, guarded),
            Job::CheckFailureInterference { request, own_alias } => {
                self.workers.check_failure_interference(request, own_alias);
            }
            Job::Apply(request) => self.workers.apply(request),
            Job::RestoreApplied(snapshot) => self.workers.restore_applied(snapshot),
            Job::RestoreEdits(snapshot) => self.workers.restore_edits(snapshot),
            Job::LoadTemporaryRules(request) => self.workers.load_temporary_rules(request),
            Job::Disconnect => self.workers.disconnect(),
            Job::SetInterfaceScale(percent) => self.workers.set_interface_scale(percent),
            Job::SetLanguage(language) => self.workers.set_language(language),
            Job::SetAccent(accent) => self.workers.set_accent(accent),
            Job::Setting(change) => self.workers.change_setting(change),
            #[cfg(windows)]
            Job::LoadAutostart => self.workers.load_autostart(),
            #[cfg(windows)]
            Job::SetAutostart(enabled) => self.workers.set_autostart(enabled),
            Job::SkipVersion(version) => self.workers.skip_version(version),
            Job::CheckUpdates => self.workers.check_updates(),
            Job::SetDns(dns) => self.workers.set_dns(dns),
            Job::ResetSettings => self.workers.reset_settings(),
            Job::SetVerboseLog(on) => self.workers.set_verbose_log(on),
            #[cfg(windows)]
            Job::SaveReport {
                snapshot,
                own_alias,
            } => self.workers.save_report(snapshot, own_alias),
            #[cfg(windows)]
            Job::OpenFolder(folder) => self.workers.open_folder(folder),
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
            Job::AddRules(set, matchers, target) => self.workers.add_rules(set, matchers, target),
            Job::UpdateRule(set, rule, matcher, target) => {
                self.workers.update_rule(set, rule, matcher, target);
            }
            Job::SetRuleTarget(set, rule, target) => {
                self.workers.set_rule_target(set, rule, target);
            }
            Job::CreateExit(exit) => self.workers.create_exit(exit),
            Job::SaveExit { id, name, target } => self.workers.save_exit(id, name, target),
            Job::RenameExit(id, name) => self.workers.rename_exit(id, name),
            Job::DeleteExit(id) => self.workers.delete_exit(id),
            Job::SetRuleEnabled(set, rule, enabled) => {
                self.workers.set_rule_enabled(set, rule, enabled);
            }
            Job::MoveRule(set, rule, to_index) => self.workers.move_rule(set, rule, to_index),
            Job::MoveRules(set, rules, to_index) => self.workers.move_rules(set, rules, to_index),
            Job::RemoveRule(set, rule) => self.workers.remove_rule(set, rule),
            Job::RemoveRules(set, rules) => self.workers.remove_rules(set, rules),
            Job::SetKillSwitch(enabled) => self.workers.set_kill_switch(enabled),
            Job::SetLockdown(enabled) => self.workers.set_lockdown(enabled),
            Job::Add { input, options } => self.workers.add(input, options),
            Job::ReadQr { request, source } => self.workers.read_qr(request, source),
            Job::PollScreenClip { request, sequence } => {
                self.workers.poll_screen_clip(request, sequence);
            }
            Job::Update(id) => self.workers.update(id),
            Job::UpdateList(id) => self.workers.update_list(id),
            Job::UpdateListManual(id) => self.workers.update_list_manual(id),
            Job::UpdateListFile(id) => self.workers.update_list_file(id),
            Job::AddListUrl(url, name) => self.workers.add_list_url(url, name),
            Job::AddListFile(path, name) => self.workers.add_list_file(path, name),
            Job::BrowseListFile => self.workers.browse_list_file(),
            Job::InspectListCategories {
                revision,
                temporary,
            } => self.workers.inspect_list_categories(revision, temporary),
            Job::RenameList(id, name) => self.workers.rename_list(id, name),
            Job::RemoveList(id) => self.workers.remove_list(id),
            Job::Ping(id) => self.workers.ping(id, None),
            Job::PingNode(id, node) => self.workers.ping(id, Some(node)),
            Job::FullCheck(id) => self.workers.full_check(id, None),
            Job::FullCheckNode(id, node) => self.workers.full_check(id, Some(node)),
            Job::TunnelDelay => self.workers.tunnel_delay(),
            Job::Connections => self.workers.connections(),
            Job::ProgramNames(paths) => self.workers.program_names(paths),
            Job::SessionLists { request, session } => self.workers.session_lists(request, *session),
            Job::CloseConnection(id) => self.workers.close_connection(id),
            Job::LookupExit { generation, route } => self.workers.lookup_exit(generation, route),
            Job::UpdateAll => self.workers.update_all(),
            Job::Remove(id) => self.workers.remove(id),
            Job::RenameSubscription(id, name) => self.workers.rename_subscription(id, name),
            Job::MoveSubscription(id, to_index) => self.workers.move_subscription(id, to_index),
        }
    }
}

#[cfg(any(not(windows), test))]
fn locale_is_russian(value: &str) -> bool {
    value.starts_with("ru")
}

pub(crate) fn initial_accent(store: &Store) -> rosetun_config::AccentPreset {
    store
        .load()
        .map_or_else(|_| Default::default(), |config| config.interface.accent)
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
        self.state.set_frame_time(display::monotonic_ms());
        while let Ok(event) = self.events.try_recv() {
            self.state.reduce(event);
        }
        while let Some(job) = self.state.take_queued_setting() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_restore() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_auto_connect() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_choice_connect() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_xray_connect() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_temporary_load(display::now_unix()) {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_list_inspection() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_rule_resubmit() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_keep_apply() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_leave_apply() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_auto_update(display::now_unix()) {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_update_check(display::now_unix()) {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_apply() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_exit_lookup() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_failure_interference() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_system_check() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_tunnel_delay(display::now_unix()) {
            self.dispatch(job);
        }
        self.state.set_window_hidden(self.window_hidden());
        if let Some(job) = self.state.take_connections(display::now_unix()) {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_program_names() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_session_lists() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_lockdown_lan() {
            self.dispatch(job);
        }
        if let Some(job) = self.state.take_screen_clip_poll(display::now_unix()) {
            self.dispatch(job);
        }
        // A hidden window runs `logic` only, so the schedule must be requested here, not in `ui`.
        if let Some(delay) = repaint_delay(false, self.state.next_wake(display::now_unix())) {
            ctx.request_repaint_after(delay);
        }
        if let Some(delay) = self.state.settings_busy_wake() {
            ctx.request_repaint_after(delay);
        }
        let language =
            i18n::resolve_language(self.state.config.interface.language, self.system_russian);
        if self.state.config_ready && language != i18n::language() {
            i18n::set_language(language);
            ctx.request_repaint();
        }
        motion::set_reduced(self.state.config.interface.reduce_motion);
        if self.state.config_ready && theme::set_accent(self.state.config.interface.accent) {
            theme::apply_style(ctx);
            ctx.send_viewport_cmd(egui::ViewportCommand::Icon(Some(std::sync::Arc::new(
                brand::window_icon(theme::palette()),
            ))));
            #[cfg(windows)]
            if let Some(tray) = &mut self.tray {
                tray.forget_icons();
            }
            ctx.request_repaint();
        }
        #[cfg(windows)]
        {
            if std::mem::take(&mut self.hide_on_start) && !self.quitting {
                self.hide_window(ctx);
            }
            while let Some(event) = self
                .shell_events
                .as_ref()
                .and_then(|events| events.try_recv().ok())
            {
                if self.quitting {
                    continue;
                }
                // The event may make a `take_*` due on the next pass.
                ctx.request_repaint();
                match event {
                    ShellEvent::Show => self.show_window(ctx),
                    ShellEvent::OpenLink(link) => {
                        if let Some(job) = self.state.act(Action::OpenLink(link)) {
                            self.dispatch(job);
                        }
                    }
                    ShellEvent::Hide => self.hide_window(ctx),
                    ShellEvent::Primary => {
                        if let Some(job) = self.state.act(Action::Primary) {
                            self.dispatch(job);
                        }
                    }
                    ShellEvent::SelectServer(selection) => {
                        let action =
                            Action::SelectNodeFromTray(selection.subscription, selection.node);
                        if let Some(job) = self.state.act(action) {
                            self.dispatch(job);
                        }
                    }
                    ShellEvent::ShowServers => {
                        if let Some(job) = self.state.act(Action::ShowConnection) {
                            self.dispatch(job);
                        }
                        self.show_window(ctx);
                    }
                    ShellEvent::Quit => {
                        self.quitting = true;
                        if let Some(job) = self.state.apply_on_leave() {
                            self.dispatch(job);
                            if let Some(window) = &self.window {
                                window.save();
                            }
                            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                            self.quit_apply_deadline =
                                Some(Instant::now() + Duration::from_secs(10));
                            ctx.request_repaint_after(Duration::from_millis(100));
                        } else {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    }
                }
            }
            if let Some(deadline) = self.quit_apply_deadline {
                if !self.state.operations.helper || Instant::now() >= deadline {
                    self.quit_apply_deadline = None;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                } else {
                    ctx.request_repaint_after(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_millis(100)),
                    );
                }
            }
            let (minimized, focused) = ctx.input(|input| {
                let viewport = input.viewport();
                (
                    viewport.minimized.unwrap_or(false),
                    viewport.focused.unwrap_or(false),
                )
            });
            let window_shown = !self.window_hidden && !minimized;
            if let Some(tray) = &mut self.tray {
                tray.sync(&tray::tray_view(&self.state, window_shown));
            }
            let notice = self.notices.observe(
                self.state.visible_status().map(|status| &status.state),
                self.state.operations.helper,
                window_shown && focused,
                Instant::now(),
            );
            if let Some(notice) = notice
                && self.state.config.interface.notifications
                && let Some(tray) = &self.tray
            {
                tray.notify(notice);
            }
            if minimized
                && !self.window_minimized
                && !self.quitting
                && let Some(job) = self.state.apply_on_leave()
            {
                self.dispatch(job);
            }
            self.window_minimized = minimized;
        }
        if ctx.input(|input| input.viewport().close_requested()) {
            #[cfg(windows)]
            if self.quit_apply_deadline.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                return;
            }
            if self.hides_on_close() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                #[cfg(windows)]
                self.hide_window(ctx);
            } else {
                #[cfg(windows)]
                if let Some(window) = &self.window {
                    window.save();
                }
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // The root `Ui` copies the style before `logic` runs, so a new accent applied there
        // would otherwise paint one frame of old widget colours around the new palette.
        ui.set_style(ui.ctx().global_style());
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
            #[cfg(windows)]
            if matches!(action, Action::WindowMinimized) {
                self.window_minimized = true;
            }
            if let Some(job) = self.state.act(action) {
                self.dispatch(job);
            }
        }
        if let Some(delay) = repaint_delay(
            !self.window_hidden() && view::shows_clock(&self.state),
            self.state.next_wake(display::now_unix()),
        ) {
            ui.ctx().request_repaint_after(delay);
        }
    }
}

fn repaint_delay(clock_shown: bool, next_wake: Option<Duration>) -> Option<Duration> {
    let clock = clock_shown.then_some(Duration::from_secs(1));
    match (clock, next_wake) {
        (Some(clock), Some(wake)) => Some(clock.min(wake)),
        (clock, wake) => clock.or(wake),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::centered_position;
    use super::{initial_accent, initial_scale, locale_is_russian, next_scale};
    #[cfg(windows)]
    use eframe::egui;
    use rosetun_core::Store;
    use std::fs;
    use std::time::Duration;

    #[cfg(windows)]
    #[test]
    fn an_opened_link_is_not_in_shell_event_debug() {
        let event = super::ShellEvent::OpenLink(crate::state::OpenedLink(
            "rosetun://add/https://example.com/private-token".into(),
        ));

        let debug = format!("{event:?}");
        assert!(!debug.contains("private-token"));
        assert!(!debug.contains("example.com"));
    }

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

    #[test]
    fn initial_accent_uses_saved_preset_and_rose_without_one() {
        use rosetun_config::AccentPreset;

        let path =
            std::env::temp_dir().join(format!("rosetun-gui-initial-accent-{}", std::process::id()));
        let store = Store::at(&path);
        assert_eq!(initial_accent(&store), AccentPreset::Rose);

        fs::write(&path, r#"{"interface":{"accent":"teal"}}"#).unwrap();
        assert_eq!(initial_accent(&store), AccentPreset::Teal);
        fs::write(&path, r#"{"interface":{"scale_percent":125}}"#).unwrap();
        assert_eq!(initial_accent(&store), AccentPreset::Rose);
        fs::write(&path, r#"{"interface":{"accent":"violet"}}"#).unwrap();
        assert_eq!(initial_accent(&store), AccentPreset::Rose);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn hidden_window_without_deadlines_asks_for_no_frame() {
        let state = crate::state::State::default();
        assert_eq!(super::repaint_delay(false, state.next_wake(1_000)), None);
    }

    #[test]
    fn visible_window_ticks_only_with_a_clock_on_screen() {
        use rosetun_config::{ConnectionState, Status};

        let mut state = crate::state::State::default();
        state.reduce(crate::worker::WorkerEvent::HelperAvailable {
            version: "0.9.0".into(),
        });
        state.reduce(crate::worker::WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            since_unix: Some(1_000),
            ..Status::default()
        }));
        assert!(state.take_temporary_load(1_000).is_some());
        assert!(state.take_tunnel_delay(1_003).is_some());
        state.screen = crate::state::Screen::Rules;
        let rules = super::repaint_delay(crate::view::shows_clock(&state), state.next_wake(1_003));
        assert_eq!(rules, None);
        state.screen = crate::state::Screen::Connection;
        let session =
            super::repaint_delay(crate::view::shows_clock(&state), state.next_wake(1_003));
        assert_eq!(session, Some(Duration::from_secs(1)));
    }

    #[test]
    fn earlier_deadline_beats_the_clock() {
        assert_eq!(
            super::repaint_delay(true, Some(Duration::ZERO)),
            Some(Duration::ZERO)
        );
    }
}
