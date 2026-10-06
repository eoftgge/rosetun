use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Shadow, Stroke, Style, TextStyle, Visuals,
};

pub(crate) const BRAND_FONT: &str = "brand";
pub(crate) const UI_SEMIBOLD: &str = "ui-semibold";

fn fonts() -> egui::FontDefinitions {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "manrope-regular".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
            "../assets/fonts/Manrope-Regular.ttf"
        ))),
    );
    fonts.font_data.insert(
        "manrope-semibold".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
            "../assets/fonts/Manrope-SemiBold.ttf"
        ))),
    );
    let proportional = fonts
        .families
        .get_mut(&FontFamily::Proportional)
        .expect("default proportional font family");
    let mut semibold = vec!["manrope-semibold".to_owned()];
    semibold.extend(proportional.iter().cloned());
    proportional.insert(0, "manrope-regular".to_owned());
    fonts
        .families
        .insert(FontFamily::Name(UI_SEMIBOLD.into()), semibold);
    fonts.font_data.insert(
        "cormorant-garamond-semibold".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
            "../assets/fonts/CormorantGaramond-SemiBold.ttf"
        ))),
    );
    fonts.families.insert(
        egui::FontFamily::Name(BRAND_FONT.into()),
        vec!["cormorant-garamond-semibold".to_owned()],
    );
    fonts
}

pub(crate) const BG: Color32 = Color32::from_rgb(0x17, 0x10, 0x14);
pub(crate) const PANEL: Color32 = Color32::from_rgb(0x1B, 0x14, 0x18);
pub(crate) const CARD: Color32 = Color32::from_rgb(0x1F, 0x15, 0x19);
pub(crate) const MODAL: Color32 = Color32::from_rgb(0x21, 0x15, 0x19);
pub(crate) const INPUT: Color32 = Color32::from_rgb(0x2B, 0x1D, 0x23);
pub(crate) const BORDER: Color32 = Color32::from_rgb(0x33, 0x23, 0x2A);
pub(crate) const BORDER_STRONG: Color32 = Color32::from_rgb(0x43, 0x2D, 0x36);
pub(crate) const TEXT: Color32 = Color32::from_rgb(0xF3, 0xEC, 0xEE);
pub(crate) const TEXT_MUTED: Color32 = Color32::from_rgb(0xB9, 0xA9, 0xAF);
pub(crate) const TEXT_DIM: Color32 = Color32::from_rgb(0x93, 0x7F, 0x88);
pub(crate) const DISABLED: Color32 = Color32::from_rgb(0x5C, 0x4D, 0x54);
pub(crate) const ROSE_DARK: Color32 = Color32::from_rgb(0x8C, 0x23, 0x38);
pub(crate) const ROSE: Color32 = Color32::from_rgb(0xC2, 0x37, 0x4F);
pub(crate) const ROSE_BRIGHT: Color32 = Color32::from_rgb(0xD9, 0x47, 0x5F);
pub(crate) const ROSE_LIGHT: Color32 = Color32::from_rgb(0xE8, 0x6A, 0x80);
pub(crate) const CONNECTED: Color32 = Color32::from_rgb(0xE0, 0x70, 0x5B);
pub(crate) const DISCONNECTED: Color32 = Color32::from_rgb(0x8C, 0x81, 0x89);
pub(crate) const ERROR: Color32 = Color32::from_rgb(0xFF, 0x6A, 0x2A);

pub(crate) fn apply(ctx: &egui::Context) {
    ctx.set_fonts(fonts());
    ctx.set_theme(egui::Theme::Dark);

    let mut visuals = Visuals::dark();
    visuals.override_text_color = Some(TEXT);
    visuals.window_fill = MODAL;
    visuals.panel_fill = PANEL;
    visuals.faint_bg_color = CARD;
    visuals.extreme_bg_color = INPUT;
    visuals.window_stroke = Stroke::new(1.0, BORDER_STRONG);
    visuals.widgets.noninteractive.bg_fill = CARD;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_MUTED);
    visuals.widgets.inactive.bg_fill = INPUT;
    visuals.widgets.inactive.weak_bg_fill = CARD;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_MUTED);
    visuals.widgets.hovered.bg_fill = BORDER;
    visuals.widgets.hovered.weak_bg_fill = BORDER;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.active.bg_fill = ROSE_DARK;
    visuals.widgets.active.weak_bg_fill = ROSE_DARK;
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.selection.bg_fill = ROSE;
    visuals.selection.stroke = Stroke::new(1.0, TEXT);
    visuals.window_corner_radius = CornerRadius::same(2);
    visuals.menu_corner_radius = CornerRadius::same(2);
    visuals.window_shadow = Shadow::NONE;
    visuals.popup_shadow = Shadow::NONE;
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(2);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(2);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(2);
    visuals.widgets.active.corner_radius = CornerRadius::same(2);

    let mut style = Style::default();
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.window_margin = egui::Margin::same(20);
    style.text_styles = [
        (
            TextStyle::Small,
            FontId::new(12.0, FontFamily::Proportional),
        ),
        (TextStyle::Body, FontId::new(15.0, FontFamily::Proportional)),
        (
            TextStyle::Button,
            FontId::new(15.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Monospace,
            FontId::new(14.0, FontFamily::Monospace),
        ),
        (
            TextStyle::Heading,
            FontId::new(24.0, FontFamily::Name(UI_SEMIBOLD.into())),
        ),
    ]
    .into();
    style.visuals = visuals;
    ctx.set_global_style(style);
}

pub(crate) fn card_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(2))
        .inner_margin(egui::Margin::same(16))
}

pub(crate) fn modal_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(MODAL)
        .stroke(Stroke::new(1.0, BORDER_STRONG))
        .corner_radius(CornerRadius::same(2))
        .inner_margin(egui::Margin::same(24))
}

pub(crate) fn button_fill(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    enabled: bool,
) -> egui::Response {
    let button = egui::Button::new(text).fill(if enabled { ROSE } else { CARD });
    ui.add_enabled(enabled, button)
}

pub(crate) fn outline_button(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    enabled: bool,
) -> egui::Response {
    let button = egui::Button::new(text)
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(
            1.0,
            if enabled { BORDER_STRONG } else { BORDER },
        ));
    ui.scope(|ui| {
        // egui sizes a button by its state's stroke width; match hover's 1 px so it keeps its size.
        ui.visuals_mut().widgets.inactive.bg_stroke.width = 1.0;
        ui.add_enabled(enabled, button)
    })
    .inner
}

pub(crate) const TOGGLE_SIZE: egui::Vec2 = egui::vec2(38.0, 22.0);

/// An on/off switch in the brand colours. Returns a response that is
/// `changed()` when the user flips it.
pub(crate) fn toggle(ui: &mut egui::Ui, on: &mut bool, enabled: bool) -> egui::Response {
    let enabled = enabled && ui.is_enabled();
    let (rect, mut response) = ui.allocate_exact_size(
        TOGGLE_SIZE,
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    let next = toggled_value(*on, response.clicked(), enabled);
    if next != *on {
        *on = next;
        response.mark_changed();
    }
    response
        .widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Checkbox, enabled, *on, ""));
    let progress = ui.ctx().animate_bool_with_time(response.id, *on, 0.1);
    if ui.is_rect_visible(rect) {
        let faded = |color: Color32| {
            if enabled {
                color
            } else {
                Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 128)
            }
        };
        ui.painter().rect(
            rect,
            CornerRadius::same(11),
            faded(if *on { ROSE } else { INPUT }),
            if *on {
                Stroke::NONE
            } else {
                Stroke::new(1.0, faded(BORDER_STRONG))
            },
            egui::StrokeKind::Inside,
        );
        ui.painter().circle_filled(
            egui::pos2(rect.left() + 11.0 + 16.0 * progress, rect.center().y),
            8.0,
            faded(if *on { TEXT } else { TEXT_MUTED }),
        );
    }
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// A title, a muted detail below it and a toggle to the right, centred on both lines.
pub(crate) fn switch_row(
    ui: &mut egui::Ui,
    title: &str,
    detail: &str,
    on: &mut bool,
    enabled: bool,
) -> egui::Response {
    ui.horizontal(|ui| {
        let text_width = ui.available_width() - TOGGLE_SIZE.x - ui.spacing().item_spacing.x;
        ui.vertical(|ui| {
            ui.set_max_width(text_width);
            ui.label(title);
            ui.add(egui::Label::new(egui::RichText::new(detail).small().color(TEXT_MUTED)).wrap());
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            toggle(ui, on, enabled)
        })
        .inner
    })
    .inner
}

fn toggled_value(on: bool, clicked: bool, enabled: bool) -> bool {
    if clicked && enabled { !on } else { on }
}

pub(crate) fn dismissible_error(ui: &mut egui::Ui, message: &str) -> bool {
    card_frame()
        .show(ui, |ui| {
            egui::Sides::new()
                .shrink_left()
                .wrap()
                .spacing(16.0)
                .show(
                    ui,
                    |ui| {
                        ui.colored_label(ERROR, crate::strings::ERROR_MARK);
                        ui.add(egui::Label::new(message).wrap());
                    },
                    |ui| ui.button(crate::strings::DISMISS).clicked(),
                )
                .1
        })
        .inner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_flips_only_when_enabled_and_clicked() {
        assert!(toggled_value(false, true, true));
        assert!(!toggled_value(true, true, true));
        assert!(toggled_value(true, true, false));
        assert!(!toggled_value(false, true, false));
        assert!(toggled_value(true, false, true));
        assert!(!toggled_value(false, false, true));
    }
}
