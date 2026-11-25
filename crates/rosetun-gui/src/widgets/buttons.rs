use eframe::egui::{self, Color32, RichText, Stroke};

use crate::icons::{self, Icon};
use crate::theme;

/// What the chevron of a menu button takes of its width.
const CHEVRON_WIDTH: f32 = 8.0;

fn primary_fill(enabled: bool) -> Color32 {
    if enabled {
        theme::palette().accent_base
    } else {
        theme::palette()
            .accent_dark
            .gamma_multiply(theme::alpha::MUTED)
    }
}

fn primary_foreground(enabled: bool) -> Color32 {
    let palette = theme::palette();
    if enabled {
        palette.on_accent
    } else if palette.on_accent == palette.text {
        palette.text_muted
    } else {
        palette.on_accent.gamma_multiply(theme::alpha::MUTED)
    }
}

pub(crate) fn button_fill(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    enabled: bool,
) -> egui::Response {
    ui.scope(|ui| {
        ui.visuals_mut().override_text_color = Some(primary_foreground(enabled));
        ui.add_enabled(enabled, egui::Button::new(text).fill(primary_fill(enabled)))
    })
    .inner
}

/// A square primary filled button carrying only `icon`, as high as a field.
/// `label` is spoken to assistive tools and shown on hover.
pub(crate) fn button_fill_icon(
    ui: &mut egui::Ui,
    icon: Icon,
    label: &str,
    enabled: bool,
) -> egui::Response {
    let side = super::text_field::field_height(ui);
    let enabled = enabled && ui.is_enabled();
    let response = ui
        .scope(|ui| {
            ui.spacing_mut().button_padding = egui::Vec2::ZERO;
            ui.spacing_mut().interact_size = egui::vec2(side, side);
            ui.add_enabled(
                enabled,
                egui::Button::new("")
                    .min_size(egui::vec2(side, side))
                    .fill(primary_fill(enabled)),
            )
        })
        .inner;
    if ui.is_rect_visible(response.rect) {
        icons::paint(
            ui.painter(),
            response.rect.center(),
            icon,
            primary_foreground(enabled),
        );
    }
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, enabled, label));
    response.on_hover_text(label).on_disabled_hover_text(label)
}

pub(crate) fn outline_button(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    enabled: bool,
) -> egui::Response {
    let button = egui::Button::new(text)
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(
            theme::stroke::HAIRLINE,
            if enabled {
                theme::palette().border_strong
            } else {
                theme::palette().border
            },
        ));
    ui.scope(|ui| {
        // egui sizes a button by its state's stroke width; match hover's 1 px so it keeps its size.
        ui.visuals_mut().widgets.inactive.bg_stroke.width = 1.0;
        ui.add_enabled(enabled, button)
    })
    .inner
}

/// A square outlined button carrying only `icon`, as high as a field.
/// `label` is spoken to assistive tools and shown on hover.
pub(crate) fn outline_button_icon(
    ui: &mut egui::Ui,
    icon: Icon,
    label: &str,
    enabled: bool,
) -> egui::Response {
    let side = super::text_field::field_height(ui);
    let enabled = enabled && ui.is_enabled();
    let response = ui
        .scope(|ui| {
            ui.spacing_mut().button_padding = egui::Vec2::ZERO;
            ui.spacing_mut().interact_size = egui::vec2(side, side);
            ui.visuals_mut().widgets.inactive.bg_stroke.width = 1.0;
            ui.add_enabled(
                enabled,
                egui::Button::new("")
                    .min_size(egui::vec2(side, side))
                    .fill(Color32::TRANSPARENT)
                    .stroke(Stroke::new(
                        theme::stroke::HAIRLINE,
                        if enabled {
                            theme::palette().border_strong
                        } else {
                            theme::palette().border
                        },
                    )),
            )
        })
        .inner;
    if ui.is_rect_visible(response.rect) {
        let color = if enabled {
            theme::palette().text_muted
        } else {
            theme::disabled()
        };
        icons::paint(ui.painter(), response.rect.center(), icon, color);
    }
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, enabled, label));
    response.on_hover_text(label).on_disabled_hover_text(label)
}

/// An outlined button that opens a menu: the chevron stands inside the button, after the text.
pub(crate) fn outline_button_menu(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    enabled: bool,
) -> egui::Response {
    let id = egui::IdSalt::new("menu_button_chevron");
    let button = egui::Button::new((
        text.into(),
        egui::Atom::custom(id, egui::vec2(CHEVRON_WIDTH, 0.0)),
    ))
    .fill(Color32::TRANSPARENT)
    .gap(theme::space::S)
    .stroke(Stroke::new(
        theme::stroke::HAIRLINE,
        if enabled {
            theme::palette().border_strong
        } else {
            theme::palette().border
        },
    ));
    let shown = ui
        .scope(|ui| {
            ui.visuals_mut().widgets.inactive.bg_stroke.width = 1.0;
            ui.add_enabled_ui(enabled, |ui| button.atom_ui(ui)).inner
        })
        .inner;
    if let Some(slot) = shown.rect(id) {
        icons::paint(
            ui.painter(),
            slot.center(),
            Icon::Chevron { open: 1.0 },
            if enabled {
                theme::palette().text_dim
            } else {
                theme::palette().border_strong
            },
        );
    }
    shown.response
}

#[cfg(test)]
fn button_fill_compact(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    compact_button(ui, text, enabled, false, false)
}

pub(crate) fn outline_button_compact(
    ui: &mut egui::Ui,
    text: &str,
    enabled: bool,
) -> egui::Response {
    compact_button(ui, text, enabled, true, false)
}

/// A compact outlined button as wide as the space; a longer text ends in `…`.
pub(crate) fn outline_button_full(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    compact_button(ui, text, enabled, true, true)
}

fn compact_button(
    ui: &mut egui::Ui,
    text: &str,
    enabled: bool,
    outlined: bool,
    full_width: bool,
) -> egui::Response {
    let font = theme::font::semibold(theme::font::CAPTION);
    let button =
        egui::Button::new(egui::RichText::new(text).font(font)).min_size(egui::vec2(0.0, 28.0));
    let button = if full_width {
        button
            .min_size(egui::vec2(ui.available_width(), 28.0))
            .truncate()
    } else {
        button
    };
    let button = if outlined {
        button.fill(Color32::TRANSPARENT).stroke(Stroke::new(
            theme::stroke::HAIRLINE,
            if enabled {
                theme::palette().border_strong
            } else {
                theme::palette().border
            },
        ))
    } else {
        button.fill(primary_fill(enabled))
    };
    ui.scope(|ui| {
        ui.spacing_mut().button_padding = egui::vec2(12.0, 4.0);
        ui.spacing_mut().interact_size.y = 28.0;
        if outlined {
            ui.visuals_mut().widgets.inactive.bg_stroke.width = 1.0;
        } else {
            ui.visuals_mut().override_text_color = Some(primary_foreground(enabled));
        }
        ui.add_enabled(enabled, button)
    })
    .inner
}

pub(crate) fn link(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    link_styled(ui, RichText::new(text).small(), enabled)
}

pub(crate) fn link_body(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    link_styled(
        ui,
        RichText::new(text).font(theme::font::semibold(theme::font::BODY)),
        enabled,
    )
}

fn link_styled(ui: &mut egui::Ui, text: RichText, enabled: bool) -> egui::Response {
    let response = ui.add(
        egui::Label::new(text.color(if enabled {
            theme::palette().accent_light
        } else {
            theme::palette().text_dim
        }))
        .sense(if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        }),
    );
    if enabled && response.hovered() {
        ui.painter().line_segment(
            [
                response.rect.left_bottom() + egui::vec2(0.0, -1.0),
                response.rect.right_bottom() + egui::vec2(0.0, -1.0),
            ],
            Stroke::new(theme::stroke::HAIRLINE, theme::palette().accent_light),
        );
    }
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_primary_keeps_its_size_and_rose_fill() {
        assert_eq!(primary_fill(true), theme::palette().accent_base);
        assert_ne!(primary_fill(false), theme::palette().card);
        assert_eq!(
            primary_fill(false),
            theme::palette()
                .accent_dark
                .gamma_multiply(theme::alpha::MUTED)
        );
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let enabled = button_fill(ui, "Add", true);
                let disabled = button_fill(ui, "Add", false);
                assert_eq!(enabled.rect.size(), disabled.rect.size());
                assert!(!disabled.enabled());
            });
        });
        output.textures_delta.clear();
    }

    #[test]
    fn compact_buttons_are_28_points_high() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let filled = button_fill_compact(ui, "Add", true);
                let outlined = outline_button_compact(ui, "Added", true);
                assert_eq!(filled.rect.height(), 28.0);
                assert_eq!(outlined.rect.height(), 28.0);
            });
        });
        output.textures_delta.clear();
    }

    #[test]
    fn a_menu_button_is_as_high_as_an_outlined_one() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let plain = outline_button(ui, "QR code", true);
                let menu = outline_button_menu(ui, "QR code", true);
                let disabled = outline_button_menu(ui, "QR code", false);
                assert_eq!(menu.rect.height(), plain.rect.height());
                assert_eq!(disabled.rect.size(), menu.rect.size());
                assert!(menu.rect.width() > plain.rect.width());
                assert!(menu.sense.senses_click() && !disabled.enabled());
            });
        });
        output.textures_delta.clear();
    }

    #[test]
    fn an_icon_fill_button_is_square_as_high_as_a_field_and_keeps_its_size_when_disabled() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let height = super::super::text_field::field_height(ui);
                let enabled = button_fill_icon(ui, Icon::Plus, "Add rule", true);
                let disabled = button_fill_icon(ui, Icon::Plus, "Add rule", false);
                assert_eq!(enabled.rect.height(), height);
                assert_eq!(enabled.rect.width(), height);
                assert_eq!(disabled.rect.size(), enabled.rect.size());
                assert!(!disabled.enabled());
            });
        });
        output.textures_delta.clear();
    }
}
