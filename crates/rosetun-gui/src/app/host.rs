//! The window's life on Linux.
//!
//! Wayland lets no program hide or raise its own window: winit's
//! `set_visible` and `focus_window` do nothing there. So a window "in the
//! tray" does not exist at all: eframe runs until the window closes, the
//! `App` lives on and runs `tick` without a window, and showing it again
//! runs eframe anew. X11 takes the same path, so there is one path to get
//! right, and a start from autostart never flashes a window.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::{self, Sender};
use std::time::{Duration, Instant};

use eframe::egui;
use rosetun_shell::{Activation, InstanceMessage};

use super::{App, Leave, ShellEvent};
use crate::repaint::Repaint;
use crate::state::OpenedLink;
use crate::{display, renderer, tray};

/// How long a start from autostart waits for the panel before it shows the
/// window after all: at sign-in the panel can come up after this program.
const HOST_WAIT: Duration = Duration::from_secs(10);
/// Without a window nothing is drawn; this only bounds a missed wake.
const IDLE_WAKE: Duration = Duration::from_secs(30);
const DEADLINE_WAKE: Duration = Duration::from_millis(100);

/// The window's size to bring back, in logical pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct WindowShape {
    pub(crate) size: Option<egui::Vec2>,
    pub(crate) maximized: bool,
}

pub(super) struct WindowLife {
    repaint: Repaint,
    has_window: bool,
    /// The window's next close request is ours, not the user's.
    leaving: bool,
    /// Open a new window once this one is gone.
    reopen: bool,
    /// Without a window: open one.
    wanted: bool,
    /// The program ends with the window.
    exit: bool,
    shape: WindowShape,
    host_wait_until: Option<Instant>,
    /// Waiting for a window that can open it.
    pending_web_link: Option<String>,
    logged_no_tray: bool,
}

impl WindowLife {
    pub(super) fn new(repaint: Repaint) -> Self {
        Self {
            repaint,
            has_window: false,
            leaving: false,
            reopen: false,
            wanted: false,
            exit: false,
            shape: WindowShape {
                size: None,
                maximized: false,
            },
            host_wait_until: None,
            pending_web_link: None,
            logged_no_tray: false,
        }
    }

    /// The close request is one this program asked for.
    pub(super) fn leaving(&self) -> bool {
        self.leaving
    }
}

/// What to do when the window should come to the front. A focused window is
/// there already; only Wayland needs a new window for it.
fn raise_needs_new_window(wayland: bool, focused: bool) -> bool {
    wayland && !focused
}

/// Ends with the program. `shape` makes the viewport of each new window.
pub(crate) fn run(
    app: App,
    viewport: impl Fn(WindowShape) -> egui::ViewportBuilder,
) -> eframe::Result {
    let home = Rc::new(RefCell::new(Some(app)));
    loop {
        let shape = {
            let mut slot = home.borrow_mut();
            let Some(app) = slot.as_mut() else {
                return Ok(());
            };
            if app.window_hidden && !app.run_windowless() {
                return Ok(());
            }
            app.life.shape
        };
        let creator_home = Rc::clone(&home);
        renderer::run(
            viewport(shape),
            Box::new(move |cc| {
                let mut app = creator_home
                    .borrow_mut()
                    .take()
                    .expect("the app is home between windows");
                app.attach(cc);
                Ok(Box::new(Hosted {
                    app: Some(app),
                    home: creator_home,
                }))
            }),
        )?;
        let mut slot = home.borrow_mut();
        let Some(app) = slot.as_mut() else {
            return Ok(());
        };
        app.window_closed();
        if app.life.exit {
            return Ok(());
        }
    }
}

/// Lends the `App` to one window and takes it back when eframe ends.
struct Hosted {
    app: Option<App>,
    home: Rc<RefCell<Option<App>>>,
}

impl eframe::App for Hosted {
    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        self.app
            .as_ref()
            .map_or([0.0; 4], |app| eframe::App::clear_color(app, visuals))
    }

    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if let Some(app) = &mut self.app {
            eframe::App::logic(app, ctx, frame);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        if let Some(app) = &mut self.app {
            eframe::App::ui(app, ui, frame);
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        *self.home.borrow_mut() = self.app.take();
    }
}

impl App {
    /// Serves later runs of the GUI and puts up the tray. `open_link` is what
    /// this run was started for.
    pub(crate) fn with_shell(
        mut self,
        activation: Option<Activation>,
        open_link: Option<String>,
        start_hidden: bool,
    ) -> Self {
        let (sender, events) = mpsc::channel();
        self.shell_events = Some(events);
        self.tray = Some(tray::Tray::new(sender.clone(), self.life.repaint.clone()));
        self.window_hidden = start_hidden;
        self.life.host_wait_until = start_hidden.then(|| Instant::now() + HOST_WAIT);
        if let Some(link) = open_link {
            let _ = sender.send(ShellEvent::OpenLink(OpenedLink(link)));
            let _ = sender.send(ShellEvent::Show);
        }
        if let Some(activation) = activation {
            serve_later_runs(activation, sender, self.life.repaint.clone());
        }
        self
    }

    /// A new window: eframe made a new context, so everything kept in the
    /// old one is set again.
    fn attach(&mut self, cc: &eframe::CreationContext<'_>) {
        Self::prepare_context(&cc.egui_ctx);
        if let Some(percent) = self.applied_scale {
            cc.egui_ctx.set_zoom_factor(f32::from(percent) / 100.0);
        }
        self.life.repaint.attach(cc.egui_ctx.clone());
        self.life.has_window = true;
        self.window_hidden = false;
        self.window_minimized = false;
    }

    fn window_closed(&mut self) {
        self.life.repaint.detach();
        self.life.has_window = false;
        if !std::mem::take(&mut self.life.leaving) {
            // The user closed it and nothing kept the program running.
            self.life.exit = true;
        }
        self.window_hidden = !std::mem::take(&mut self.life.reopen);
    }

    /// Runs `tick` until a window is wanted (`true`) or the program ends.
    fn run_windowless(&mut self) -> bool {
        // Never painted: `tick` only asks it about a window it does not
        // have, and what it is told to do goes nowhere.
        let ctx = egui::Context::default();
        loop {
            self.tick(&ctx);
            if self.life.exit {
                return false;
            }
            if std::mem::take(&mut self.life.wanted) {
                self.window_hidden = false;
                return true;
            }
            self.life.repaint.wait(self.windowless_wait());
        }
    }

    fn windowless_wait(&self) -> Duration {
        let deadline = (self.quit_apply_deadline.is_some() || self.life.host_wait_until.is_some())
            .then_some(DEADLINE_WAKE);
        [
            deadline,
            self.state.next_wake(display::now_unix()),
            self.state.settings_busy_wake(),
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(IDLE_WAKE)
    }

    /// A start from autostart stays out of sight only if the tray can bring it back.
    pub(super) fn wait_for_host(&mut self, ctx: &egui::Context) {
        let Some(until) = self.life.host_wait_until else {
            return;
        };
        if self.tray.as_ref().is_some_and(tray::Tray::available) {
            self.life.host_wait_until = None;
        } else if Instant::now() >= until {
            self.life.host_wait_until = None;
            self.log_no_tray();
            self.show_window(ctx);
        }
    }

    pub(super) fn show_window(&mut self, ctx: &egui::Context) {
        self.life.host_wait_until = None;
        self.window_hidden = false;
        if !self.life.has_window {
            self.life.wanted = true;
            return;
        }
        if self.life.leaving {
            self.life.reopen = true;
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        let focused = ctx.input(|input| input.viewport().focused.unwrap_or(false));
        if raise_needs_new_window(std::env::var_os("WAYLAND_DISPLAY").is_some(), focused) {
            self.remember_shape(ctx);
            self.life.reopen = true;
            self.leave_window(ctx, Leave::Hide);
        }
    }

    /// The window is closed for good or until the tray brings it back.
    pub(super) fn leave_window(&mut self, ctx: &egui::Context, how: Leave) {
        if how == Leave::Close {
            self.life.exit = true;
        }
        if self.life.has_window {
            self.life.leaving = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            ctx.request_repaint();
        }
    }

    pub(super) fn remember_shape(&mut self, ctx: &egui::Context) {
        if !self.life.has_window {
            return;
        }
        let (rect, maximized) = ctx.input(|input| {
            let viewport = input.viewport();
            (viewport.inner_rect, viewport.maximized.unwrap_or(false))
        });
        // The context's points include the interface scale, a new window's do not.
        let zoom = ctx.zoom_factor();
        self.life.shape = WindowShape {
            size: rect.map(|rect| rect.size() * zoom),
            maximized,
        };
    }

    /// Whether closing the window leaves the program in the tray. Says once
    /// why it does not when the tray is what is missing.
    pub(super) fn hides_on_close(&mut self) -> bool {
        if self.quitting || !self.state.close_hides_window() {
            return false;
        }
        let available = self.tray.as_ref().is_some_and(tray::Tray::available);
        if !available {
            self.log_no_tray();
        }
        available
    }

    fn log_no_tray(&mut self) {
        if std::mem::replace(&mut self.life.logged_no_tray, true) {
            return;
        }
        let reason = self
            .tray
            .as_ref()
            .and_then(tray::Tray::absent_reason)
            .unwrap_or_else(|| "the tray has not answered yet".to_owned());
        tracing::warn!(reason, "no tray: closing the window closes the program");
    }

    /// The release page opens through the window's context, so it may have to wait for one.
    pub(super) fn open_web_link(&mut self, ctx: &egui::Context, url: String) {
        if self.life.has_window {
            display::open_web_link(ctx, &url);
        } else {
            self.life.pending_web_link = Some(url);
            self.show_window(ctx);
        }
    }

    pub(super) fn open_pending_web_link(&mut self, ctx: &egui::Context) {
        if self.life.has_window
            && let Some(url) = self.life.pending_web_link.take()
        {
            display::open_web_link(ctx, &url);
        }
    }
}

fn serve_later_runs(activation: Activation, sender: Sender<ShellEvent>, repaint: Repaint) {
    std::thread::spawn(move || {
        let served = activation.serve(|message| {
            for event in instance_events(message) {
                let _ = sender.send(event);
            }
            repaint.request();
        });
        if let Err(error) = served {
            tracing::warn!(%error, "the instance socket stopped");
        }
    });
}

fn instance_events(message: InstanceMessage) -> Vec<ShellEvent> {
    match message {
        InstanceMessage::Show => vec![ShellEvent::Show],
        InstanceMessage::AfterUpgrade => vec![ShellEvent::AfterUpgrade],
        InstanceMessage::OpenLink(link) => {
            vec![ShellEvent::OpenLink(OpenedLink(link)), ShellEvent::Show]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosetun_core::Store;

    /// An app with its workers on an empty settings file, no window and
    /// a way to send it what the tray and later runs send.
    fn windowless(test: &str) -> (App, Sender<ShellEvent>) {
        let path =
            std::env::temp_dir().join(format!("rosetun-window-life-{test}-{}", std::process::id()));
        let mut app = App::without_window(Store::at(path), Repaint::default());
        let (sender, events) = mpsc::channel();
        app.shell_events = Some(events);
        app.window_hidden = true;
        (app, sender)
    }

    #[test]
    fn showing_a_hidden_app_asks_for_a_window() {
        let (mut app, sender) = windowless("show");
        sender.send(ShellEvent::Show).unwrap();
        assert!(app.run_windowless());
        assert!(!app.window_hidden);
    }

    #[test]
    fn quitting_without_a_window_ends_the_program() {
        let (mut app, sender) = windowless("quit");
        sender.send(ShellEvent::Quit).unwrap();
        assert!(!app.run_windowless());
    }

    #[test]
    fn a_hidden_start_without_a_host_opens_the_window_after_all() {
        let (mut app, _sender) = windowless("no-host");
        app.life.host_wait_until = Some(Instant::now());
        assert!(app.run_windowless());
        assert_eq!(app.life.host_wait_until, None);
        assert!(app.life.logged_no_tray);
    }

    #[test]
    fn a_link_for_the_browser_waits_for_a_window() {
        let (mut app, _sender) = windowless("web-link");
        app.open_web_link(&egui::Context::default(), "https://example.com/".to_owned());
        assert!(app.life.wanted);
        assert!(app.life.pending_web_link.is_some());
        let ctx = egui::Context::default();
        app.open_pending_web_link(&ctx);
        assert!(app.life.pending_web_link.is_some(), "still no window");
        app.life.has_window = true;
        app.open_pending_web_link(&ctx);
        assert_eq!(app.life.pending_web_link, None);
    }

    #[test]
    fn what_follows_a_closed_window_depends_on_who_closed_it() {
        let (mut app, _sender) = windowless("closed");
        app.life.has_window = true;
        app.life.leaving = true;
        app.window_closed();
        assert!(app.window_hidden, "to the tray");
        assert!(!app.life.exit);
        assert!(!app.life.leaving, "the next close is the user's again");

        app.life.has_window = true;
        app.life.leaving = true;
        app.life.reopen = true;
        app.window_closed();
        assert!(!app.window_hidden, "to come forward");
        assert!(!app.life.exit);

        app.life.has_window = true;
        app.window_closed();
        assert!(app.life.exit, "the user's close that nothing kept alive");
    }

    #[test]
    fn a_show_during_the_close_opens_the_window_again() {
        let (mut app, _sender) = windowless("show-while-closing");
        app.life.has_window = true;
        app.window_hidden = false;
        let ctx = egui::Context::default();
        app.leave_window(&ctx, Leave::Hide);
        assert!(app.life.leaving);
        app.show_window(&ctx);
        assert!(app.life.reopen);
        app.window_closed();
        assert!(!app.window_hidden);
    }

    #[test]
    fn without_a_tray_closing_the_window_closes_the_program() {
        let (mut app, _sender) = windowless("close-without-tray");
        app.state.config_ready = true;
        app.state.config.interface.close_to_tray = true;
        assert!(!app.hides_on_close());
        assert!(app.life.logged_no_tray);
    }

    #[test]
    fn only_an_unfocused_window_on_wayland_opens_anew_to_come_forward() {
        assert!(raise_needs_new_window(true, false));
        assert!(!raise_needs_new_window(true, true));
        assert!(!raise_needs_new_window(false, false));
        assert!(!raise_needs_new_window(false, true));
    }

    #[test]
    fn a_later_run_is_shown_a_window_except_for_the_upgrade_start() {
        let debug = |message| format!("{:?}", instance_events(message));
        assert_eq!(debug(InstanceMessage::Show), "[Show]");
        assert_eq!(debug(InstanceMessage::AfterUpgrade), "[AfterUpgrade]");
        let opened = debug(InstanceMessage::OpenLink(
            "rosetun://add/https://example.com/private-token".into(),
        ));
        assert!(opened.ends_with(", Show]"), "{opened}");
        assert!(!opened.contains("private-token"));
    }
}
