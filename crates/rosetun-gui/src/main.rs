#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]
#![forbid(unsafe_code)]

#[macro_use]
mod i18n;

mod actions;
mod app;
#[cfg(test)]
mod app_icon;
mod brand;
mod constants;
mod destinations;
mod display;
mod errors;
#[cfg(windows)]
mod frame_stats;
mod icons;
#[cfg(test)]
mod layout_fence;
mod logging;
mod motion;
#[cfg(any(windows, target_os = "linux"))]
mod notices;
mod program_icons;
mod programs;
mod qr;
mod renderer;
mod reorder;
mod repaint;
mod repaint_trace;
#[cfg(windows)]
mod report;
mod rose_icon;
mod rose_shape;
mod rules;
mod state;
mod system_fonts;
#[cfg(test)]
mod test_ui;
mod theme;
#[cfg(any(windows, target_os = "linux"))]
mod tray;
mod view;
mod widgets;
#[cfg(windows)]
mod window_memory;
#[cfg(test)]
#[path = "../../windows_resources.rs"]
mod windows_resources;
mod worker;

use std::fs::{self, OpenOptions};
use std::sync::Mutex;

use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::prelude::*;

#[cfg(any(windows, target_os = "linux"))]
/// Passed by autostart: start in the tray without showing the window.
pub(crate) const HIDDEN_ARG: &str = "--hidden";
#[cfg(any(windows, target_os = "linux"))]
/// Passed by the installer after an upgrade that held the network closed:
/// start in the tray and connect, whatever "Connect at startup" says.
const AFTER_UPGRADE_ARG: &str = "--after-upgrade";
#[cfg(any(windows, target_os = "linux"))]
/// Passed by the `rosetun://` scheme handler with the link that was opened.
const OPEN_URL_ARG: &str = "--open-url";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // First, before anything opens a socket: a socket keeps the cgroup it was
    // made in, and Lockdown permits the GUI by its scope.
    #[cfg(target_os = "linux")]
    let scope = rosetun_core::enter_scope(rosetun_core::ScopeProgram::Gui);
    #[cfg(any(windows, target_os = "linux"))]
    let open_link = open_url_arg(std::env::args_os());
    #[cfg(any(windows, target_os = "linux"))]
    let after_upgrade =
        open_link.is_none() && std::env::args_os().any(|arg| arg == AFTER_UPGRADE_ARG);
    #[cfg(any(windows, target_os = "linux"))]
    let start_hidden =
        after_upgrade || open_link.is_none() && std::env::args_os().any(|arg| arg == HIDDEN_ARG);
    #[cfg(windows)]
    let (activation, links) = match rosetun_shell::acquire(!start_hidden) {
        // Taken before the settings load, so a later instance's link
        // waits in the pipe instead of finding no server.
        Ok(rosetun_shell::Instance::First(activation)) => {
            (Ok(activation), Some(rosetun_shell::LinkListener::bind()))
        }
        Ok(rosetun_shell::Instance::Other) => {
            if let Some(link) = &open_link
                && let Err(error) = rosetun_shell::send_link(link)
            {
                tracing::warn!(%error, "could not pass the link to the running GUI");
            }
            return Ok(());
        }
        Err(error) => (Err(error), None),
    };
    #[cfg(target_os = "linux")]
    let activation = match rosetun_shell::acquire() {
        Ok(rosetun_shell::Instance::First(activation)) => Ok(activation),
        Ok(rosetun_shell::Instance::Other) => {
            if let Some(message) = message_to_first(open_link, after_upgrade, start_hidden)
                && let Err(error) = rosetun_shell::send_to_first(&message)
            {
                tracing::warn!(%error, "could not reach the running GUI");
            }
            return Ok(());
        }
        Err(error) => Err(error),
    };
    let store = rosetun_core::Store::open_default()?;
    #[cfg(windows)]
    let window_file = store.path().with_file_name("window.json");
    let log_file = store.path().parent().and_then(|directory| {
        fs::create_dir_all(directory)
            .and_then(|()| {
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(directory.join(constants::LOG_FILE_NAME))
            })
            .ok()
    });
    let log_to_file = log_file.is_some();
    let writer = match log_file {
        Some(file) => BoxMakeWriter::new(Mutex::new(file)),
        None => BoxMakeWriter::new(std::io::stderr),
    };
    let env_filter = tracing_subscriber::EnvFilter::try_from_env("ROSETUN_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    // HTTP diagnostics can contain credentials regardless of the selected level.
    let safe_targets = filter_fn(|metadata| logging::allows(metadata.target(), *metadata.level()));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_ansi(!log_to_file)
                .with_filter(safe_targets),
        )
        .init();

    #[cfg(target_os = "linux")]
    if let rosetun_core::Scope::Outside(reason) = &scope {
        tracing::warn!(
            reason,
            "the GUI runs outside its scope; under Lockdown it has no network without a session"
        );
    }

    #[cfg(any(windows, target_os = "linux"))]
    let activation = activation
        .inspect_err(|error| tracing::warn!(%error, "single-instance check failed"))
        .ok();
    #[cfg(windows)]
    let links = links.and_then(|links| {
        links
            .inspect_err(|error| tracing::warn!(%error, "could not open the link pipe"))
            .ok()
    });

    // Before the window and its icon exist, so a non-rose preset never flashes rose.
    theme::set_accent(app::initial_accent(&store));
    #[cfg(target_os = "linux")]
    app::host::run(
        app::App::without_window(store, repaint::Repaint::default())
            .outside_scope(scope != rosetun_core::Scope::Inside)
            .with_shell(activation, open_link, start_hidden)
            .after_upgrade(after_upgrade),
        window_viewport,
    )?;
    #[cfg(not(target_os = "linux"))]
    let viewport = base_viewport();
    #[cfg(windows)]
    let viewport = if start_hidden {
        // eframe shows the window after its first frame; keep that frame off every screen.
        viewport.with_position(app::OFFSCREEN).with_active(false)
    } else {
        viewport
    };
    #[cfg(not(target_os = "linux"))]
    renderer::run(
        viewport,
        Box::new(move |cc| {
            let app = app::App::new(cc, store);
            #[cfg(windows)]
            let app = app.with_shell(
                &cc.egui_ctx,
                activation,
                links,
                open_link,
                start_hidden,
                window_memory::WindowMemory::new(cc, window_file),
            );
            #[cfg(windows)]
            let app = app.after_upgrade(after_upgrade);
            Ok(Box::new(app))
        }),
    )?;
    Ok(())
}

fn base_viewport() -> eframe::egui::ViewportBuilder {
    eframe::egui::ViewportBuilder::default()
        .with_title(constants::TITLE)
        .with_icon(std::sync::Arc::new(brand::window_icon(theme::palette())))
        .with_decorations(!view::header::CUSTOM_FRAME)
        .with_inner_size([1200.0, 780.0])
        .with_min_inner_size([960.0, 640.0])
}

/// Each window the Linux GUI opens, the size of the last one if there was one.
///
/// Wayland has no window icon of a program's own: the compositor finds the menu
/// entry by this ID and shows the icon named there. The frame is the system's,
/// so the window moves and resizes as every other on the desktop.
#[cfg(target_os = "linux")]
fn window_viewport(shape: app::host::WindowShape) -> eframe::egui::ViewportBuilder {
    let viewport = base_viewport()
        .with_app_id("rosetun")
        .with_maximized(shape.maximized);
    match shape.size {
        Some(size) => viewport.with_inner_size(size),
        None => viewport,
    }
}

/// The link after `--open-url`. A missing or unreadable value is an empty
/// link, so the add dialog still opens and says it holds no subscription.
#[cfg(any(windows, target_os = "linux"))]
fn open_url_arg(args: impl Iterator<Item = std::ffi::OsString>) -> Option<String> {
    let mut args = args.skip_while(|arg| arg != OPEN_URL_ARG);
    args.next()?;
    Some(
        args.next()
            .and_then(|link| link.into_string().ok())
            .unwrap_or_default(),
    )
}

/// What a run that found another one asks of it. Autostart while the GUI
/// already runs asks nothing.
#[cfg(target_os = "linux")]
fn message_to_first(
    open_link: Option<String>,
    after_upgrade: bool,
    start_hidden: bool,
) -> Option<rosetun_shell::InstanceMessage> {
    use rosetun_shell::InstanceMessage;

    match (open_link, after_upgrade, start_hidden) {
        (Some(link), ..) => Some(InstanceMessage::OpenLink(link)),
        (None, true, _) => Some(InstanceMessage::AfterUpgrade),
        (None, false, true) => None,
        (None, false, false) => Some(InstanceMessage::Show),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use rosetun_shell::InstanceMessage;

    use super::{message_to_first, open_url_arg, window_viewport};

    #[test]
    fn a_window_names_its_menu_entry_and_comes_back_at_its_last_size() {
        let shape = crate::app::host::WindowShape {
            size: Some(eframe::egui::vec2(1000.0, 700.0)),
            maximized: true,
        };
        let viewport = window_viewport(shape);
        assert_eq!(viewport.app_id.as_deref(), Some("rosetun"));
        assert_eq!(viewport.decorations, Some(true), "the system's frame");
        assert_eq!(viewport.inner_size, Some(eframe::egui::vec2(1000.0, 700.0)));
        assert_eq!(viewport.maximized, Some(true));
        let first = window_viewport(crate::app::host::WindowShape {
            size: None,
            maximized: false,
        });
        assert_eq!(first.inner_size, Some(eframe::egui::vec2(1200.0, 780.0)));
    }

    #[test]
    fn a_later_run_asks_for_what_it_was_started_for() {
        let link = || Some("rosetun://add/https://example.com/token".to_owned());
        assert_eq!(
            message_to_first(link(), false, false),
            link().map(InstanceMessage::OpenLink)
        );
        assert_eq!(
            message_to_first(None, true, true),
            Some(InstanceMessage::AfterUpgrade)
        );
        assert_eq!(message_to_first(None, false, true), None);
        assert_eq!(
            message_to_first(None, false, false),
            Some(InstanceMessage::Show)
        );
    }

    #[test]
    fn the_link_is_the_argument_after_open_url() {
        let args = |list: &[&str]| {
            list.iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
                .into_iter()
        };
        assert_eq!(open_url_arg(args(&["rosetun-gui"])), None);
        assert_eq!(
            open_url_arg(args(&["rosetun-gui", "--open-url", "rosetun://add/x"])).as_deref(),
            Some("rosetun://add/x")
        );
        assert_eq!(
            open_url_arg(args(&["rosetun-gui", "--open-url"])).as_deref(),
            Some("")
        );
    }
}
