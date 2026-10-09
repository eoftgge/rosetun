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
pub(crate) const WARNING: Color32 = Color32::from_rgb(0xE8, 0xB4, 0x57);
pub(crate) const EXPIRED: Color32 = Color32::from_rgb(0xEF, 0x62, 0x62);

/// Gap between blocks on the connection tab.
pub(crate) const SECTION_GAP: f32 = 16.0;
pub(crate) const SERVER_ROW: f32 = 40.0;
pub(crate) const RULE_ROW: f32 = 58.0;

/// Cards, buttons, fields, modals and menus.
pub(crate) const RADIUS: u8 = 6;
/// Buttons inside a segmented control.
pub(crate) const RADIUS_INNER: u8 = 4;
/// The toggle track: half its height.
pub(crate) const RADIUS_TOGGLE: u8 = 11;

pub(crate) fn apply(ctx: &egui::Context) {
    ctx.set_fonts(fonts());
    ctx.set_theme(egui::Theme::Dark);

    let mut visuals = Visuals::dark();
    visuals.override_text_color = Some(TEXT);
    visuals.hyperlink_color = ROSE_LIGHT;
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
    visuals.window_corner_radius = CornerRadius::same(RADIUS);
    visuals.menu_corner_radius = CornerRadius::same(RADIUS);
    visuals.window_shadow = Shadow::NONE;
    visuals.popup_shadow = Shadow::NONE;
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(RADIUS);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(RADIUS);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(RADIUS);
    visuals.widgets.active.corner_radius = CornerRadius::same(RADIUS);

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
