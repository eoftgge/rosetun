use std::sync::atomic::{AtomicU8, Ordering};

use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Shadow, Stroke, Style, TextStyle, Visuals,
};
use rosetun_config::AccentPreset;

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

/// The colours an accent preset changes: the accent family and the surfaces
/// tinted to match it. State colours below are the same in every preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Palette {
    pub(crate) bg: Color32,
    pub(crate) panel: Color32,
    pub(crate) card: Color32,
    pub(crate) modal: Color32,
    pub(crate) input: Color32,
    pub(crate) border: Color32,
    pub(crate) border_strong: Color32,
    pub(crate) text: Color32,
    pub(crate) text_muted: Color32,
    pub(crate) text_dim: Color32,
    pub(crate) accent_dark: Color32,
    pub(crate) accent_base: Color32,
    pub(crate) accent_bright: Color32,
    pub(crate) accent_light: Color32,
    /// The light core of the bloomed rose on the connect button.
    pub(crate) accent_pale: Color32,
}

impl Palette {
    pub(crate) const ROSE: Self = Self {
        bg: rgb(0x171014),
        panel: rgb(0x1B1418),
        card: rgb(0x1F1519),
        modal: rgb(0x211519),
        input: rgb(0x2B1D23),
        border: rgb(0x33232A),
        border_strong: rgb(0x432D36),
        text: rgb(0xF3ECEE),
        text_muted: rgb(0xB9A9AF),
        text_dim: rgb(0x937F88),
        accent_dark: rgb(0x8C2338),
        accent_base: rgb(0xC2374F),
        accent_bright: rgb(0xD9475F),
        accent_light: rgb(0xE86A80),
        accent_pale: rgb(0xF4B6C1),
    };
    pub(crate) const LILAC: Self = Self {
        bg: rgb(0x120F17),
        panel: rgb(0x16121B),
        card: rgb(0x1B1622),
        modal: rgb(0x1D1724),
        input: rgb(0x261F30),
        border: rgb(0x2E2639),
        border_strong: rgb(0x3D324B),
        text: rgb(0xEFEBF3),
        text_muted: rgb(0xB3ABBF),
        text_dim: rgb(0x9A90A8),
        accent_dark: rgb(0x4E3178),
        accent_base: rgb(0x7A4DB8),
        accent_bright: rgb(0x8C60CC),
        accent_light: rgb(0xB48CE8),
        accent_pale: rgb(0xDCC6F4),
    };
    pub(crate) const TEAL: Self = Self {
        bg: rgb(0x0D1414),
        panel: rgb(0x111818),
        card: rgb(0x141D1E),
        modal: rgb(0x151F20),
        input: rgb(0x1C2829),
        border: rgb(0x233132),
        border_strong: rgb(0x2F4142),
        text: rgb(0xEAF2F1),
        text_muted: rgb(0xA6B8B6),
        text_dim: rgb(0x859896),
        accent_dark: rgb(0x134A45),
        accent_base: rgb(0x1E7870),
        accent_bright: rgb(0x279086),
        accent_light: rgb(0x5FC4B9),
        accent_pale: rgb(0xB5EAE4),
    };
    /// Neutral surfaces with the rose accent.
    pub(crate) const GRAPHITE: Self = Self {
        bg: rgb(0x121214),
        panel: rgb(0x161618),
        card: rgb(0x1A1A1D),
        modal: rgb(0x1C1C1F),
        input: rgb(0x242428),
        border: rgb(0x2C2C31),
        border_strong: rgb(0x3A3A41),
        text: rgb(0xEEEEF0),
        text_muted: rgb(0xB1B1B9),
        text_dim: rgb(0x8F8F99),
        accent_dark: rgb(0x8C2338),
        accent_base: rgb(0xC2374F),
        accent_bright: rgb(0xD9475F),
        accent_light: rgb(0xE86A80),
        accent_pale: rgb(0xF4B6C1),
    };
    /// Warm dark greys with a muted cocoa rose.
    pub(crate) const COCOA: Self = Self {
        bg: rgb(0x141211),
        panel: rgb(0x181615),
        card: rgb(0x1C1A18),
        modal: rgb(0x1E1C1A),
        input: rgb(0x262320),
        border: rgb(0x2F2B28),
        border_strong: rgb(0x3D3834),
        text: rgb(0xF0ECE9),
        text_muted: rgb(0xB6AEA8),
        text_dim: rgb(0x958C85),
        accent_dark: rgb(0x5A3A30),
        accent_base: rgb(0x8A5646),
        accent_bright: rgb(0x9E6656),
        accent_light: rgb(0xC99A88),
        accent_pale: rgb(0xE8D2C8),
    };
    pub(crate) const AMBER: Self = Self {
        bg: rgb(0x15100B),
        panel: rgb(0x19140E),
        card: rgb(0x1F1912),
        modal: rgb(0x211A13),
        input: rgb(0x2B2219),
        border: rgb(0x352A1F),
        border_strong: rgb(0x45372A),
        text: rgb(0xF4EEE6),
        text_muted: rgb(0xBEB1A1),
        text_dim: rgb(0x9C8D7B),
        accent_dark: rgb(0x6B4210),
        accent_base: rgb(0x99601A),
        accent_bright: rgb(0xB37224),
        accent_light: rgb(0xE3A04A),
        accent_pale: rgb(0xF6DAA8),
    };
}

/// In the order of `AccentPreset::ALL`.
static PALETTES: [Palette; 6] = [
    Palette::ROSE,
    Palette::GRAPHITE,
    Palette::COCOA,
    Palette::LILAC,
    Palette::TEAL,
    Palette::AMBER,
];

/// Index into `PALETTES`; changed between frames, read on every paint.
static CURRENT: AtomicU8 = AtomicU8::new(0);

/// The palette of the chosen accent preset.
pub(crate) fn palette() -> &'static Palette {
    PALETTES
        .get(usize::from(CURRENT.load(Ordering::Relaxed)))
        .unwrap_or(&PALETTES[0])
}

pub(crate) fn palette_of(accent: AccentPreset) -> &'static Palette {
    &PALETTES[usize::from(palette_index(accent))]
}

fn palette_index(accent: AccentPreset) -> u8 {
    match accent {
        AccentPreset::Rose => 0,
        AccentPreset::Graphite => 1,
        AccentPreset::Cocoa => 2,
        AccentPreset::Lilac => 3,
        AccentPreset::Teal => 4,
        AccentPreset::Amber => 5,
    }
}

pub(crate) fn accent() -> AccentPreset {
    AccentPreset::ALL
        .get(usize::from(CURRENT.load(Ordering::Relaxed)))
        .copied()
        .unwrap_or_default()
}

/// Switches the palette for the next frame; true when it changed.
pub(crate) fn set_accent(accent: AccentPreset) -> bool {
    let index = palette_index(accent);
    CURRENT.swap(index, Ordering::Relaxed) != index
}

const fn rgb(value: u32) -> Color32 {
    Color32::from_rgb((value >> 16) as u8, (value >> 8) as u8, value as u8)
}

pub(crate) const DISABLED: Color32 = Color32::from_rgb(0x5C, 0x4D, 0x54);
/// Lighter than `ERROR`, so connected and failed differ without hue.
pub(crate) const CONNECTED: Color32 = Color32::from_rgb(0x5F, 0xD3, 0x9A);
pub(crate) const DISCONNECTED: Color32 = Color32::from_rgb(0x8C, 0x81, 0x89);
pub(crate) const ERROR: Color32 = Color32::from_rgb(0xFF, 0x6A, 0x2A);
pub(crate) const WARNING: Color32 = Color32::from_rgb(0xE8, 0xB4, 0x57);
/// Rules through an exit: apart from the rose of the main VPN and the orange of Block.
pub(crate) const EXIT: Color32 = Color32::from_rgb(0x8F, 0xB4, 0xE8);
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
    apply_style(ctx);
}

/// The style in the colours of the current palette; called again when the preset changes.
pub(crate) fn apply_style(ctx: &egui::Context) {
    let palette = palette();
    let mut visuals = Visuals::dark();
    visuals.override_text_color = Some(palette.text);
    visuals.hyperlink_color = palette.accent_light;
    visuals.window_fill = palette.modal;
    visuals.panel_fill = palette.panel;
    visuals.faint_bg_color = palette.card;
    visuals.extreme_bg_color = palette.input;
    visuals.window_stroke = Stroke::new(1.0, palette.border_strong);
    visuals.widgets.noninteractive.bg_fill = palette.card;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, palette.text_muted);
    visuals.widgets.inactive.bg_fill = palette.input;
    visuals.widgets.inactive.weak_bg_fill = palette.card;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, palette.text_muted);
    visuals.widgets.hovered.bg_fill = palette.border;
    visuals.widgets.hovered.weak_bg_fill = palette.border;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, palette.text);
    visuals.widgets.active.bg_fill = palette.accent_dark;
    visuals.widgets.active.weak_bg_fill = palette.accent_dark;
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, palette.text);
    visuals.selection.bg_fill = palette.accent_base;
    visuals.selection.stroke = Stroke::new(1.0, palette.text);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn luminance(color: Color32) -> f64 {
        let channel = |value: u8| {
            let value = f64::from(value) / 255.0;
            if value <= 0.04045 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(color.r()) + 0.7152 * channel(color.g()) + 0.0722 * channel(color.b())
    }

    fn contrast(a: Color32, b: Color32) -> f64 {
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    #[test]
    fn the_rose_palette_keeps_the_colours_from_before_presets() {
        let rose = Palette::ROSE;
        let expected = [
            (rose.bg, [0x17, 0x10, 0x14]),
            (rose.panel, [0x1B, 0x14, 0x18]),
            (rose.card, [0x1F, 0x15, 0x19]),
            (rose.modal, [0x21, 0x15, 0x19]),
            (rose.input, [0x2B, 0x1D, 0x23]),
            (rose.border, [0x33, 0x23, 0x2A]),
            (rose.border_strong, [0x43, 0x2D, 0x36]),
            (rose.text, [0xF3, 0xEC, 0xEE]),
            (rose.text_muted, [0xB9, 0xA9, 0xAF]),
            (rose.text_dim, [0x93, 0x7F, 0x88]),
            (rose.accent_dark, [0x8C, 0x23, 0x38]),
            (rose.accent_base, [0xC2, 0x37, 0x4F]),
            (rose.accent_bright, [0xD9, 0x47, 0x5F]),
            (rose.accent_light, [0xE8, 0x6A, 0x80]),
            (rose.accent_pale, [0xF4, 0xB6, 0xC1]),
        ];
        for (actual, [r, g, b]) in expected {
            assert_eq!(actual, Color32::from_rgb(r, g, b));
        }
        assert_eq!(palette_of(AccentPreset::default()), &Palette::ROSE);
    }

    #[test]
    fn every_preset_has_its_own_palette_in_order() {
        for (index, accent) in AccentPreset::ALL.into_iter().enumerate() {
            assert_eq!(usize::from(palette_index(accent)), index);
            assert!(std::ptr::eq(palette_of(accent), &PALETTES[index]));
        }
        assert_eq!(palette_of(AccentPreset::Teal), &Palette::TEAL);
        assert_eq!(palette_of(AccentPreset::Cocoa), &Palette::COCOA);
        assert_eq!(palette_of(AccentPreset::Amber), &Palette::AMBER);
    }

    #[test]
    fn connected_is_lighter_than_error() {
        assert!(luminance(CONNECTED) > luminance(ERROR) * 1.3);
    }

    #[test]
    fn every_palette_keeps_text_readable() {
        for palette in &PALETTES {
            let on_accent = contrast(palette.text, palette.accent_base);
            assert!(on_accent >= 4.5, "text on accent {on_accent:.2} in {palette:?}");
            for surface in [palette.card, palette.panel] {
                let dim = contrast(palette.text_dim, surface);
                assert!(dim >= 4.5, "dim text {dim:.2} in {palette:?}");
            }
        }
    }
}
