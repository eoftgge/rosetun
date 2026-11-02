use std::cell::RefCell;
use std::rc::Rc;

use crate::constants;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Renderer {
    Glow,
    Wgpu,
}

fn select(windows: bool, value: Option<&str>) -> (Renderer, bool) {
    let default = if windows { Renderer::Wgpu } else { Renderer::Glow };
    match value {
        None => (default, false),
        Some(value) if value.eq_ignore_ascii_case("glow") => (Renderer::Glow, false),
        Some(value) if value.eq_ignore_ascii_case("wgpu") => (default, false),
        Some(_) => (default, true),
    }
}

fn should_fallback(renderer: Renderer, failed: bool, creator_available: bool) -> bool {
    renderer == Renderer::Wgpu && failed && creator_available
}

fn options(viewport: eframe::egui::ViewportBuilder, renderer: Renderer) -> eframe::NativeOptions {
    let mut options = eframe::NativeOptions {
        viewport: viewport.with_transparent(false),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    if renderer == Renderer::Wgpu {
        #[cfg(windows)]
        {
            use eframe::egui_wgpu::{WgpuSetup, WgpuSetupCreateNew};

            options.renderer = eframe::Renderer::Wgpu;
            let mut setup = WgpuSetupCreateNew::without_display_handle();
            setup.instance_descriptor = wgpu::InstanceDescriptor::new_without_display_handle();
            setup.instance_descriptor.backends = wgpu::Backends::DX12;
            setup.instance_descriptor.backend_options.dx12.shader_compiler = wgpu::Dx12Compiler::Fxc;
            setup.instance_descriptor.backend_options.dx12.presentation_system = wgpu::Dx12SwapchainKind::DxgiFromVisual;
            setup.power_preference = wgpu::PowerPreference::LowPower;
            options.wgpu_options.wgpu_setup = WgpuSetup::CreateNew(setup);
            options.wgpu_options.surface.present_mode = wgpu::PresentMode::AutoVsync;
        }
    }
    options.glow_options.vsync = true;
    options
}

pub(crate) fn run(viewport: eframe::egui::ViewportBuilder, creator: eframe::AppCreator<'_>) -> eframe::Result {
    let value = std::env::var_os("ROSETUN_RENDERER");
    let (renderer, invalid) = select(cfg!(windows), value.as_ref().map(|v| v.to_str().unwrap_or("")));
    if invalid {
        tracing::warn!("unknown ROSETUN_RENDERER value; using the default renderer");
    }
    // eframe initializes the renderer before calling the creator and shows the
    // window after painting. Keep the single-use application inputs for a retry.
    // Once the creator is consumed, never restart an application with live workers.
    let creator = Rc::new(RefCell::new(Some(creator)));
    let attempt = |renderer, after_failure| {
        let creator = Rc::clone(&creator);
        eframe::run_native(constants::TITLE, options(viewport.clone(), renderer), Box::new(move |cc| {
            let label = match (renderer, after_failure) {
                (Renderer::Wgpu, _) => "wgpu dx12 visual",
                (Renderer::Glow, true) => "glow after wgpu failure",
                (Renderer::Glow, false) => "glow",
            };
            tracing::info!(renderer = label, "GUI renderer selected");
            #[cfg(windows)]
            if let Some(state) = &cc.wgpu_render_state {
                tracing::debug!(adapter = %state.adapter.get_info().name, "GUI graphics adapter");
            }
            let create = creator.borrow_mut().take().expect("eframe calls the app creator once");
            create(cc)
        }))
    };
    let result = attempt(renderer, false);
    if should_fallback(renderer, result.is_err(), creator.borrow().is_some()) {
        // Driver errors may include local paths; record only the error category.
        tracing::warn!(error = failure_kind(result.as_ref().err()), "wgpu initialization failed before application creation; trying glow");
        attempt(Renderer::Glow, true)
    } else {
        result
    }
}

fn failure_kind(error: Option<&eframe::Error>) -> &'static str {
    match error {
        #[cfg(windows)]
        Some(eframe::Error::Wgpu(error)) => match error {
            eframe::egui_wgpu::WgpuError::RequestAdapterError(_) => "adapter unavailable",
            eframe::egui_wgpu::WgpuError::RequestDeviceError(_) => "device creation failed",
            eframe::egui_wgpu::WgpuError::CreateSurfaceError(_) => "surface creation failed",
            eframe::egui_wgpu::WgpuError::NoSurfaceFormatsAvailable => "surface format unavailable",
            _ => "graphics initialization failed",
        },
        _ => "window initialization failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_obeys_platform_and_case_insensitive_overrides() {
        for windows in [false, true] {
            let default = if windows { Renderer::Wgpu } else { Renderer::Glow };
            assert_eq!(select(windows, None), (default, false));
            for value in ["wgpu", "WGPU", "WgPu"] {
                assert_eq!(select(windows, Some(value)), (default, false));
            }
            for value in ["glow", "GLOW", "GlOw"] {
                assert_eq!(select(windows, Some(value)), (Renderer::Glow, false));
            }
            for value in ["", "unknown", " glow "] {
                assert_eq!(select(windows, Some(value)), (default, true));
            }
        }
    }

    #[test]
    fn fallback_requires_failure_before_the_application_is_created() {
        for renderer in [Renderer::Glow, Renderer::Wgpu] {
            for failed in [false, true] {
                for creator_available in [false, true] {
                    assert_eq!(should_fallback(renderer, failed, creator_available), renderer == Renderer::Wgpu && failed && creator_available);
                }
            }
        }
    }
}
