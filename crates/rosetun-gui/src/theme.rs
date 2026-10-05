use eframe::egui::{self, Color32, CornerRadius, Shadow, Stroke, Style, Visuals};

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
    ui.add_enabled(enabled, button)
}

pub(crate) fn dismissible_error(ui: &mut egui::Ui, message: &str) -> bool {
    card_frame()
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.colored_label(ERROR, crate::strings::ERROR_MARK);
                ui.add(egui::Label::new(message).wrap());
                ui.add_space(8.0);
                ui.button(crate::strings::DISMISS).clicked()
            })
            .inner
        })
        .inner
}
