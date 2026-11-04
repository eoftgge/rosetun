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
mod icons;
#[cfg(test)]
mod layout_fence;
mod logging;
mod motion;
#[cfg(windows)]
mod notices;
mod program_icons;
mod programs;
mod qr;
mod renderer;
mod reorder;
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
#[cfg(windows)]
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

#[cfg(windows)]
/// Passed by autostart: start in the tray without showing the window.
pub(crate) const HIDDEN_ARG: &str = "--hidden";
#[cfg(windows)]
/// Passed by the installer after an upgrade that held the network closed:
/// start in the tray and connect, whatever "Connect at startup" says.
const AFTER_UPGRADE_ARG: &str = "--after-upgrade";
#[cfg(windows)]
/// Passed by the `rosetun://` scheme handler with the link that was opened.
const OPEN_URL_ARG: &str = "--open-url";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // First, before anything opens a socket: a socket keeps the cgroup it was
    // made in, and Lockdown permits the GUI by its scope.
    #[cfg(target_os = "linux")]
    let scope = rosetun_core::enter_scope(rosetun_core::ScopeProgram::Gui);
    #[cfg(windows)]
    let open_link = open_url_arg(std::env::args_os());
    #[cfg(windows)]
    let after_upgrade =
        open_link.is_none() && std::env::args_os().any(|arg| arg == AFTER_UPGRADE_ARG);
    #[cfg(windows)]
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

    #[cfg(windows)]
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
    let viewport = eframe::egui::ViewportBuilder::default()
        .with_title(constants::TITLE)
        .with_icon(std::sync::Arc::new(brand::window_icon(theme::palette())))
        .with_decorations(!view::header::CUSTOM_FRAME)
        .with_inner_size([1200.0, 780.0])
        .with_min_inner_size([960.0, 640.0]);
    #[cfg(windows)]
    let viewport = if start_hidden {
        // eframe shows the window after its first frame; keep that frame off every screen.
        viewport.with_position(app::OFFSCREEN).with_active(false)
    } else {
        viewport
    };
    renderer::run(
        viewport,
        Box::new(move |cc| {
            let app = app::App::new(cc, store);
            #[cfg(target_os = "linux")]
            let app = app.outside_scope(scope != rosetun_core::Scope::Inside);
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

/// The link after `--open-url`. A missing or unreadable value is an empty
/// link, so the add dialog still opens and says it holds no subscription.
#[cfg(windows)]
fn open_url_arg(args: impl Iterator<Item = std::ffi::OsString>) -> Option<String> {
    let mut args = args.skip_while(|arg| arg != OPEN_URL_ARG);
    args.next()?;
    Some(
        args.next()
            .and_then(|link| link.into_string().ok())
            .unwrap_or_default(),
    )
}
