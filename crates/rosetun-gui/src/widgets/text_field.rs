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

/// The space above and below a field's text, so a line of text stands in the middle of a field
/// `height` high.
pub(crate) fn field_vertical_margin(ui: &egui::Ui, height: f32) -> i8 {
    ((height - ui.fonts_mut(|fonts| fonts.row_height(&egui::TextStyle::Body.resolve(ui.style()))))
        / 2.0)
        .max(0.0) as i8
}

/// Gives the text inputs in `ui` the look of a field: the palette's field colour, a hairline
/// border that rises on hover, rounded corners, and red when the value is not acceptable. A
/// search field and a field in a form take their look from here, and their frame from
/// `field_frame`.
pub(crate) fn style_field(ui: &mut egui::Ui, invalid: bool) {
    let palette = theme::palette();
    let (rest, raised) = if invalid {
        (theme::ERROR, theme::ERROR)
    } else {
        (palette.border_strong, palette.text_dim)
    };
    let visuals = ui.visuals_mut();
    visuals.extreme_bg_color = palette.input;
    visuals.widgets.inactive.bg_stroke = Stroke::new(theme::stroke::HAIRLINE, rest);
    visuals.widgets.hovered.bg_stroke = Stroke::new(theme::stroke::HAIRLINE, raised);
    visuals.widgets.active.bg_stroke = Stroke::new(theme::stroke::HAIRLINE, raised);
    for state in [
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
    ] {
        state.corner_radius = CornerRadius::same(RADIUS);
    }
}

/// The frame of the text input `id` in a `ui` given its look by `style_field`, around text
/// `margin` away from the edge. egui outlines a focused input in the colour of selected
/// text, so the input gets this frame instead: the accent (red when `invalid`) around a
/// focused field, and selected text stays in the text colour.
pub(crate) fn field_frame(
    ui: &egui::Ui,
    id: egui::Id,
    invalid: bool,
    margin: egui::Margin,
) -> egui::Frame {
    // The state of the previous pass, as egui styles its own input.
    let state = match ui.ctx().read_response(id) {
        Some(response) => response.widget_state(),
        None => {
            ui.ctx().request_repaint();
            egui::widget_style::WidgetState::default()
        }
    };
    let visuals = ui.visuals();
    let look = visuals.widgets.state(state);
    let stroke = if state == egui::widget_style::WidgetState::Active {
        let focused = if invalid {
            theme::ERROR
        } else {
            theme::palette().accent_base
        };
        Stroke::new(theme::stroke::HAIRLINE, focused)
    } else {
        look.bg_stroke
    };
    egui::Frame::new()
        .fill(visuals.text_edit_bg_color())
        .corner_radius(look.corner_radius)
        .apply_stroke_and_expansion_without_layout_shift(stroke, look.expansion)
        .inner_margin(margin - egui::Margin::from(stroke.width))
}

/// An input on the palette's field colour with a hairline border, red when the value is not
/// acceptable.
#[must_use = "a field does nothing until it is added to a Ui"]
pub(crate) struct TextField<'a> {
    text: &'a mut String,
    hint: &'a str,
    password: bool,
    invalid: bool,
    enabled: bool,
    width: f32,
    id: Option<egui::Id>,
    char_limit: Option<usize>,
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
            char_limit: None,
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

    /// The most characters the field takes.
    pub(crate) fn char_limit(mut self, limit: usize) -> Self {
        self.char_limit = Some(limit);
        self
    }
}

impl egui::Widget for TextField<'_> {
    fn ui(self, ui: &mut egui::Ui) -> egui::Response {
        let height = field_height(ui);
        let width = if self.width.is_finite() {
            self.width
        } else {
            ui.available_width()
        };
        let horizontal = theme::space::M as i8;
        let vertical = field_vertical_margin(ui, height);
        ui.scope(|ui| {
            style_field(ui, self.invalid);
            let id = self.id.unwrap_or_else(|| {
                let id = ui.next_auto_id();
                ui.skip_ahead_auto_ids(1);
                id
            });
            let margin = egui::Margin::symmetric(horizontal, vertical);
            let edit = egui::TextEdit::singleline(self.text)
                .id(id)
                .frame(field_frame(ui, id, self.invalid, margin))
                .hint_text(self.hint)
                .password(self.password)
                .desired_width(width)
                .min_size(egui::vec2(width, height));
            let edit = match self.char_limit {
                Some(limit) => edit.char_limit(limit),
                None => edit,
            };
            ui.add_enabled(self.enabled, edit)
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

    /// What a field looks like once painted: the fill, border and corners of the shape that
    /// frames `rect`.
    #[derive(Debug, PartialEq)]
    struct Frame {
        fill: egui::Color32,
        stroke: egui::epaint::Stroke,
        corner_radius: CornerRadius,
    }

    fn painted_frames(shapes: &[egui::epaint::ClippedShape], rects: &[egui::Rect]) -> Vec<Frame> {
        fn collect(shape: &egui::Shape, out: &mut Vec<egui::epaint::RectShape>) {
            match shape {
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, out)),
                egui::Shape::Rect(rect) => out.push(rect.clone()),
                _ => {}
            }
        }
        let mut found = Vec::new();
        for clipped in shapes {
            collect(&clipped.shape, &mut found);
        }
        rects
            .iter()
            .map(|rect| {
                let shape = found
                    .iter()
                    .find(|shape| {
                        (shape.rect.min - rect.min).length() < 1.5
                            && (shape.rect.max - rect.max).length() < 1.5
                            && shape.stroke.width > 0.0
                    })
                    .unwrap_or_else(|| panic!("no frame painted around {rect:?}"));
                Frame {
                    fill: shape.fill,
                    stroke: shape.stroke,
                    corner_radius: shape.corner_radius,
                }
            })
            .collect()
    }

    fn laid_out(
        add: impl FnOnce(&mut egui::Ui) -> Vec<egui::Rect>,
    ) -> (Vec<egui::Rect>, Vec<egui::epaint::ClippedShape>) {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut rects = Vec::new();
        let mut add = Some(add);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                if let Some(add) = add.take() {
                    rects = add(ui);
                }
            });
        });
        output.textures_delta.clear();
        (rects, output.shapes)
    }

    /// The colour selected letters and the selection behind them end up with, as the
    /// tessellator paints the text shapes of a frame.
    fn selection_colours(shapes: &[egui::epaint::ClippedShape]) -> Vec<(egui::Color32, egui::Color32)> {
        fn collect(shape: &egui::Shape, out: &mut Vec<egui::epaint::TextShape>) {
            match shape {
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, out)),
                egui::Shape::Text(text) => out.push(text.clone()),
                _ => {}
            }
        }
        let mut texts = Vec::new();
        for clipped in shapes {
            collect(&clipped.shape, &mut texts);
        }
        let mut found = Vec::new();
        for text in texts {
            let fade = |color: egui::Color32| {
                if text.opacity_factor < 1.0 {
                    color.gamma_multiply(text.opacity_factor)
                } else {
                    color
                }
            };
            for row in &text.galley.rows {
                let visuals = &row.row.visuals;
                let glyphs = visuals.glyph_vertex_range.clone();
                // The selection is the one rectangle egui adds after the glyphs.
                if visuals.mesh.vertices.len() < glyphs.end + 4 {
                    continue;
                }
                let wash = fade(visuals.mesh.vertices[glyphs.end].color);
                for vertex in &visuals.mesh.vertices[glyphs] {
                    let letter = match text.override_text_color {
                        Some(color) => color,
                        None if vertex.color == egui::Color32::PLACEHOLDER => text.fallback_color,
                        None => vertex.color,
                    };
                    found.push((fade(letter), wash));
                }
            }
        }
        found
    }

    #[test]
    fn selected_text_in_a_field_keeps_the_text_colour_and_the_border_the_accent() {
        for invalid in [false, true] {
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let id = egui::Id::unique(("selected", invalid));
            let mut text = String::from("example.com");
            let select_all = egui::Event::Key {
                key: egui::Key::A,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::COMMAND,
            };
            let mut field = None;
            let mut shapes = Vec::new();
            for events in [Vec::new(), vec![select_all], Vec::new()] {
                if events.is_empty() && field.is_none() {
                    ctx.memory_mut(|memory| memory.request_focus(id));
                }
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        events,
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            let response = ui.add(
                                TextField::new(&mut text)
                                    .id(id)
                                    .invalid(invalid)
                                    .width(260.0),
                            );
                            field = Some(response.rect);
                        });
                    },
                );
                output.textures_delta.clear();
                shapes = output.shapes;
            }
            let selection = ctx.global_style().visuals.selection;
            let colours = selection_colours(&shapes);
            assert_eq!(colours.len(), 4 * "example.com".len(), "{invalid}: {colours:?}");
            for (letter, wash) in colours {
                assert_eq!(wash, selection.bg_fill);
                assert_eq!(letter, theme::palette().text);
                assert_ne!(letter, wash);
            }
            let focused = if invalid {
                theme::ERROR
            } else {
                theme::palette().accent_base
            };
            let rect = field.expect("the field was shown");
            let frame = &painted_frames(&shapes, &[rect])[0];
            assert_eq!(
                frame.stroke,
                egui::epaint::Stroke::new(theme::stroke::HAIRLINE, focused)
            );
        }
    }

    #[test]
    fn a_field_at_rest_keeps_the_look_and_text_place_of_an_egui_framed_input() {
        let text_pos = |shapes: &[egui::epaint::ClippedShape]| {
            shapes
                .iter()
                .find_map(|clipped| match &clipped.shape {
                    egui::Shape::Text(text) => Some(text.pos),
                    _ => None,
                })
                .expect("the field painted its text")
        };
        for invalid in [false, true] {
            let (ours, ours_shapes) = laid_out(|ui| {
                let mut text = String::from("192.0.2.1");
                vec![ui.add(TextField::new(&mut text).invalid(invalid).width(260.0)).rect]
            });
            let (egui_own, egui_shapes) = laid_out(|ui| {
                let mut text = String::from("192.0.2.1");
                ui.scope(|ui| {
                    style_field(ui, invalid);
                    let height = field_height(ui);
                    let vertical = field_vertical_margin(ui, height);
                    let edit = egui::TextEdit::singleline(&mut text)
                        .desired_width(260.0)
                        .min_size(egui::vec2(260.0, height))
                        .margin(egui::Margin::symmetric(theme::space::M as i8, vertical));
                    vec![ui.add(edit).rect]
                })
                .inner
            });
            assert_eq!(ours, egui_own);
            assert_eq!(text_pos(&ours_shapes), text_pos(&egui_shapes));
            let frame = &painted_frames(&ours_shapes, &ours)[0];
            assert_eq!(
                frame,
                &painted_frames(&egui_shapes, &egui_own)[0],
                "{invalid}"
            );
            let rest = if invalid {
                theme::ERROR
            } else {
                theme::palette().border_strong
            };
            assert_eq!(frame.fill, theme::palette().input);
            assert_eq!(frame.stroke.color, rest);
            assert_eq!(frame.corner_radius, CornerRadius::same(RADIUS));
        }
    }

    #[test]
    fn every_field_selects_text_as_the_rest_of_the_window() {
        run(|ui| {
            let global = ui.ctx().global_style().visuals.selection;
            for invalid in [false, true] {
                ui.scope(|ui| {
                    style_field(ui, invalid);
                    assert_eq!(ui.visuals().selection, global);
                });
            }
            assert_eq!(global, theme::text_selection(theme::palette()));
        });
    }

    #[test]
    fn a_field_takes_no_more_characters_than_its_limit() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let id = egui::Id::unique("limited");
        let mut text = String::new();
        for events in [Vec::new(), vec![egui::Event::Text("abcdefgh".to_owned())]] {
            if events.is_empty() {
                ctx.memory_mut(|memory| memory.request_focus(id));
            }
            let mut output = ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.add(TextField::new(&mut text).id(id).char_limit(4));
                    });
                },
            );
            output.textures_delta.clear();
        }
        assert_eq!(text, "abcd");
    }

    #[test]
    fn a_search_field_is_framed_and_as_high_as_a_text_field() {
        let (rects, shapes) = laid_out(|ui| {
            let mut text = String::new();
            let field = ui.add(TextField::new(&mut text).width(260.0));
            let mut query = String::new();
            let search = crate::widgets::search_field(ui, &mut query, "Search", 260.0);
            vec![field.rect, search.rect]
        });
        assert_eq!(rects[0].size(), rects[1].size());
        let frames = painted_frames(&shapes, &rects);
        assert_eq!(frames[0], frames[1]);
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
