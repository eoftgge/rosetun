use eframe::egui::{self, CornerRadius, Stroke};

use crate::theme::{self, RADIUS};

/// The height of a field and of an outlined button, so a field and a button share a row.
pub(crate) fn field_height(ui: &egui::Ui) -> f32 {
    let font = egui::TextStyle::Button.resolve(ui.style());
    // A button measures its text as laid out, which rounds up to whole pixels.
    let text = ui
        .painter()
        .layout_no_wrap("M".to_owned(), font, egui::Color32::PLACEHOLDER)
        .size()
        .y;
    (text + 2.0 * ui.spacing().button_padding.y).max(ui.spacing().interact_size.y)
}

/// A one-line input on the palette's field colour with a hairline border, red when the
/// value is not acceptable.
#[must_use = "a field does nothing until it is added to a Ui"]
pub(crate) struct TextField<'a> {
    text: &'a mut String,
    hint: &'a str,
    password: bool,
    invalid: bool,
    enabled: bool,
    width: f32,
    id: Option<egui::Id>,
}

impl<'a> TextField<'a> {
    pub(crate) fn new(text: &'a mut String) -> Self {
        Self {
            text,
            hint: "",
            password: false,
            invalid: false,
            enabled: true,
            width: f32::INFINITY,
            id: None,
        }
    }

    /// A fixed id, for a field the caller moves focus to.
    pub(crate) fn id(mut self, id: egui::Id) -> Self {
        self.id = Some(id);
        self
    }

    pub(crate) fn hint(mut self, hint: &'a str) -> Self {
        self.hint = hint;
        self
    }

    /// Dots instead of characters; the value never shows on screen.
    pub(crate) fn password(mut self, password: bool) -> Self {
        self.password = password;
        self
    }

    pub(crate) fn invalid(mut self, invalid: bool) -> Self {
        self.invalid = invalid;
        self
    }

    /// A field that is not enabled shows its value and takes no input.
    pub(crate) fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// The width of the field; the whole row by default.
    pub(crate) fn width(mut self, width: f32) -> Self {
        self.width = width;
        self
    }
}

impl egui::Widget for TextField<'_> {
    fn ui(self, ui: &mut egui::Ui) -> egui::Response {
        let palette = theme::palette();
        let height = field_height(ui);
        let width = if self.width.is_finite() {
            self.width
        } else {
            ui.available_width()
        };
        let horizontal = theme::space::M as i8;
        let vertical = ((height
            - ui.fonts_mut(|fonts| fonts.row_height(&egui::TextStyle::Body.resolve(ui.style()))))
            / 2.0)
            .max(0.0) as i8;
        ui.scope(|ui| {
            let rest = if self.invalid {
                theme::ERROR
            } else {
                palette.border_strong
            };
            let raised = if self.invalid {
                theme::ERROR
            } else {
                palette.text_dim
            };
            let focused = if self.invalid {
                theme::ERROR
            } else {
                palette.accent_base
            };
            let visuals = ui.visuals_mut();
            visuals.extreme_bg_color = palette.input;
            visuals.widgets.inactive.bg_stroke = Stroke::new(theme::stroke::HAIRLINE, rest);
            visuals.widgets.hovered.bg_stroke = Stroke::new(theme::stroke::HAIRLINE, raised);
            visuals.widgets.active.bg_stroke = Stroke::new(theme::stroke::HAIRLINE, raised);
            visuals.selection.stroke = Stroke::new(theme::stroke::HAIRLINE, focused);
            for state in [
                &mut visuals.widgets.inactive,
                &mut visuals.widgets.hovered,
                &mut visuals.widgets.active,
            ] {
                state.corner_radius = CornerRadius::same(RADIUS);
            }
            let edit = egui::TextEdit::singleline(self.text)
                .hint_text(self.hint)
                .password(self.password)
                .desired_width(width)
                .min_size(egui::vec2(width, height))
                .margin(egui::Margin::symmetric(horizontal, vertical));
            ui.add_enabled(
                self.enabled,
                match self.id {
                    Some(id) => edit.id(id),
                    None => edit,
                },
            )
        })
        .inner
    }
}

/// A row as high as a field: the buttons first, from the right edge, then the field in the
/// width they leave. `field` gets that width. Returns what each of the two returned.
pub(crate) fn field_row<B, R>(
    ui: &mut egui::Ui,
    buttons: impl FnOnce(&mut egui::Ui) -> B,
    field: impl FnOnce(&mut egui::Ui, f32) -> R,
) -> (B, R) {
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), field_height(ui)),
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
            let buttons = buttons(ui);
            let width = ui.available_width();
            (buttons, field(ui, width))
        },
    )
    .inner
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(read: impl FnOnce(&mut egui::Ui)) {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut read = Some(read);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                if let Some(read) = read.take() {
                    read(ui);
                }
            });
        });
        output.textures_delta.clear();
    }

    #[test]
    fn a_field_is_as_high_as_an_outlined_button() {
        run(|ui| {
            let button = crate::widgets::outline_button(ui, "Add", true);
            let mut text = String::from("192.0.2.1");
            let field = ui.add(TextField::new(&mut text));
            let mut empty = String::new();
            let hinted = ui.add(TextField::new(&mut empty).hint("SOCKS5").password(true));
            assert_eq!(field.rect.height(), button.rect.height());
            assert_eq!(hinted.rect.height(), button.rect.height());
            assert_eq!(field_height(ui), button.rect.height());
        });
    }

    #[test]
    fn a_field_takes_the_width_it_is_given() {
        run(|ui| {
            let mut text = String::new();
            let narrow = ui.add(TextField::new(&mut text).width(96.0));
            assert!(
                (narrow.rect.width() - 96.0).abs() < 1.0,
                "{}",
                narrow.rect.width()
            );
            let full = ui.add(TextField::new(&mut text));
            assert!(full.rect.width() > 96.0);
        });
    }

    #[test]
    fn a_disabled_field_keeps_its_size_and_takes_no_input() {
        run(|ui| {
            let mut text = String::from("192.0.2.1");
            let enabled = ui.add(TextField::new(&mut text).width(200.0));
            let disabled = ui.add(TextField::new(&mut text).width(200.0).enabled(false));
            assert!(enabled.enabled());
            assert!(!disabled.enabled());
            assert_eq!(enabled.rect.size(), disabled.rect.size());
        });
    }

    #[test]
    fn a_field_row_puts_the_field_between_the_edge_and_the_buttons() {
        run(|ui| {
            let left = ui.available_rect_before_wrap().left();
            let right = ui.available_rect_before_wrap().right();
            let gap = ui.spacing().item_spacing.x;
            let mut text = String::new();
            let (button, field) = field_row(
                ui,
                |ui| crate::widgets::outline_button(ui, "Paste", true),
                |ui, width| ui.add(TextField::new(&mut text).width(width)),
            );
            assert_eq!(button.rect.right(), right);
            assert!((field.rect.right() + gap - button.rect.left()).abs() < 0.5);
            assert!((field.rect.left() - left).abs() < 0.5);
            assert_eq!(field.rect.height(), button.rect.height());
        });
    }
}
