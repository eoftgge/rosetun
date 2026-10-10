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
mod display;
mod errors;
#[cfg(test)]
#[path = "../build/icon_res.rs"]
mod icon_res;
mod icons;
mod reorder;
mod rose_icon;
mod rules;
mod state;
mod theme;
#[cfg(windows)]
mod tray;
mod view;
mod widgets;
#[cfg(windows)]
mod window_memory;
mod worker;

use std::fs::{self, OpenOptions};
use std::sync::Mutex;

use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::prelude::*;

#[cfg(windows)]
/// Passed by autostart: start in the tray without showing the window.
pub(crate) const HIDDEN_ARG: &str = "--hidden";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    let start_hidden = std::env::args_os().any(|arg| arg == HIDDEN_ARG);
    #[cfg(windows)]
    let activation = match rosetun_shell::acquire(!start_hidden) {
        Ok(rosetun_shell::Instance::First(activation)) => Ok(activation),
        Ok(rosetun_shell::Instance::Other) => return Ok(()),
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
    let safe_targets =
        filter_fn(|metadata| !rosetun_core::is_sensitive_log_target(metadata.target()));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_ansi(!log_to_file)
                .with_filter(safe_targets),
        )
        .init();

    #[cfg(windows)]
    let activation = activation
        .inspect_err(|error| tracing::warn!(%error, "Single-instance check failed"))
        .ok();

    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title(constants::TITLE)
        .with_icon(std::sync::Arc::new(eframe::egui::IconData {
            rgba: rose_icon::rose_icon_rgba(128, rose_icon::RoseIcon::Large),
            width: 128,
            height: 128,
        }))
        .with_decorations(!view::header::CUSTOM_FRAME)
        .with_inner_size([1200.0, 780.0])
        .with_min_inner_size([960.0, 640.0]);
    #[cfg(windows)]
    if start_hidden {
        // eframe shows the window after its first frame; keep that frame off every screen.
        viewport = viewport.with_position(app::OFFSCREEN).with_active(false);
    }
    let options = eframe::NativeOptions {
        viewport,
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        constants::TITLE,
        options,
        Box::new(move |cc| {
            let app = app::App::new(cc, store);
            #[cfg(windows)]
            let app = app.with_shell(
                &cc.egui_ctx,
                activation,
                start_hidden,
                window_memory::WindowMemory::new(cc, window_file),
            );
            Ok(Box::new(app))
        }),
    )?;
    Ok(())
}
