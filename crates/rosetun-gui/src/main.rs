#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]
#![forbid(unsafe_code)]

mod actions;
mod app;
mod display;
mod state;
mod strings;
mod theme;
mod view;
mod worker;

use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_env("ROSETUN_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    // HTTP diagnostics can contain credentials regardless of the selected level.
    let safe_targets =
        filter_fn(|metadata| !rosetun_core::is_sensitive_log_target(metadata.target()));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_filter(safe_targets))
        .init();

    let store = rosetun_core::Store::open_default()?;
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title(strings::TITLE)
            .with_inner_size([1200.0, 780.0])
            .with_min_inner_size([960.0, 640.0]),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        strings::TITLE,
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, store)))),
    )?;
    Ok(())
}
