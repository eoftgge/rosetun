//! A field of chips: the items typed so far stand in it as chips, the text being typed after
//! them. It grows a row at a time up to a limit, then scrolls.

use eframe::egui::{self, CornerRadius, Stroke};

use crate::icons::{self, Icon};
use crate::theme;

use super::text_field::field_height;

/// The characters that end an item, as typed or pasted.
const SEPARATORS: [char; 6] = [' ', ',', ';', '\n', '\r', '\t'];
const CHIP_HEIGHT: f32 = 24.0;
/// Between chips, and between their rows.
const CHIP_GAP: f32 = theme::space::XS;
/// Inside a chip, at its ends and between its parts.
const CHIP_PADDING: f32 = theme::space::S;
const CHIP_ICON: f32 = 14.0;
const CHIP_CLOSE: f32 = CROSS_BUTTON;
/// The side of a cross that removes something.
pub(crate) const CROSS_BUTTON: f32 = 14.0;
/// The half-length of the arms of a chip's cross.
const CLOSE_ARM: f32 = 3.5;
/// The space at the field's edges.
const FIELD_PADDING: f32 = theme::space::S;
/// The least room the text being typed keeps at the end of a row.
const MIN_INPUT_WIDTH: f32 = 120.0;

/// One item in the field.
pub(crate) struct Chip<'a> {
    pub(crate) label: &'a str,
    pub(crate) icon: Icon,
    /// Why the item cannot be used: the chip is red and says so on hover.
    pub(crate) error: Option<&'a str>,
}

/// What the user did in the field this frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChipsEvent {
    /// Text that ended in a separator, Enter or a paste, or that was left when the field lost
    /// focus: one item or several, still to be split at the separators.
    Add(String),
    /// The cross of the chip at this index.
    Remove(usize),
    /// Backspace in an empty input.
    RemoveLast,
}

#[must_use = "a field does nothing until it is shown"]
pub(crate) struct ChipsField<'a> {
    id_salt: &'static str,
    chips: &'a [Chip<'a>],
    input: &'a mut String,
    hint: &'a str,
    enabled: bool,
    accepts_input: bool,
    max_rows: usize,
    width: f32,
}

pub(crate) struct ChipsOutput {
    pub(crate) events: Vec<ChipsEvent>,
    /// The text input, for focus; `None` when the field takes no more items.
    pub(crate) input: Option<egui::Response>,
}

/// The id of the input of the field shown with `id_salt`.
pub(crate) fn chips_input_id(id_salt: &str) -> egui::Id {
    egui::Id::unique(("chips_field_input", id_salt))
}

impl<'a> ChipsField<'a> {
    pub(crate) fn new(id_salt: &'static str, chips: &'a [Chip<'a>], input: &'a mut String) -> Self {
        Self {
            id_salt,
            chips,
            input,
            hint: "",
            enabled: true,
            accepts_input: true,
            max_rows: 4,
            width: f32::INFINITY,
        }
    }

    pub(crate) fn hint(mut self, hint: &'a str) -> Self {
        self.hint = hint;
        self
    }

    pub(crate) fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Whether the field takes another item: without it, only its chips show.
    pub(crate) fn accepts_input(mut self, accepts_input: bool) -> Self {
        self.accepts_input = accepts_input;
        self
    }

    /// The rows of chips the field grows to before it scrolls.
    pub(crate) fn max_rows(mut self, rows: usize) -> Self {
        self.max_rows = rows.max(1);
        self
    }

    pub(crate) fn width(mut self, width: f32) -> Self {
        self.width = width;
        self
    }

    pub(crate) fn show(self, ui: &mut egui::Ui) -> ChipsOutput {
        let enabled = self.enabled && ui.is_enabled();
        let width = if self.width.is_finite() {
            self.width
        } else {
            ui.available_width()
        };
        let inner_width = (width - 2.0 * FIELD_PADDING).max(MIN_INPUT_WIDTH);
        let font = egui::TextStyle::Body.resolve(ui.style());
        let galleys: Vec<_> = self
            .chips
            .iter()
            .map(|chip| {
                ui.painter().layout_no_wrap(
                    chip.label.to_owned(),
                    font.clone(),
                    theme::palette().text,
                )
            })
            .collect();
        let chip_width = |text: f32| {
            (CHIP_PADDING
                + CHIP_ICON
                + CHIP_PADDING / 2.0
                + text
                + CHIP_PADDING / 2.0
                + CHIP_CLOSE
                + CHIP_PADDING)
                .min(inner_width)
        };
        let mut places = Vec::with_capacity(galleys.len());
        let (mut x, mut row) = (0.0, 0_usize);
        for galley in &galleys {
            let width = chip_width(galley.size().x);
            if x > 0.0 && x + width > inner_width {
                row += 1;
                x = 0.0;
            }
            places.push((x, row, width));
            x += width + CHIP_GAP;
        }
        let input_place = self.accepts_input.then(|| {
            if x > 0.0 && inner_width - x < MIN_INPUT_WIDTH {
                row += 1;
                x = 0.0;
            }
            (x, row, inner_width - x)
        });
        let rows = row + 1;
        let rows_height = |rows: usize| rows as f32 * CHIP_HEIGHT + (rows - 1) as f32 * CHIP_GAP;
        let content_height = rows_height(rows);
        let visible_height = content_height.min(rows_height(self.max_rows));
        let height = (visible_height + 2.0 * FIELD_PADDING).max(field_height(ui));
        let vertical_padding = (height - visible_height) / 2.0;

        let input_id = chips_input_id(self.id_salt);
        let focused = enabled && ui.memory(|memory| memory.has_focus(input_id));
        let mut events = Vec::new();
        if focused && input_place.is_some() {
            let mut pasted = String::new();
            let (enter, backspace) = ui.input_mut(|input| {
                input.events.retain(|event| match event {
                    egui::Event::Paste(text) => {
                        pasted.push_str(text);
                        false
                    }
                    _ => true,
                });
                (
                    input.consume_key(egui::Modifiers::NONE, egui::Key::Enter),
                    self.input.is_empty()
                        && input.consume_key(egui::Modifiers::NONE, egui::Key::Backspace),
                )
            });
            if !pasted.is_empty() {
                events.push(ChipsEvent::Add(std::mem::take(self.input) + &pasted));
            } else if enter && !self.input.trim().is_empty() {
                events.push(ChipsEvent::Add(std::mem::take(self.input)));
            } else if backspace && !self.chips.is_empty() {
                events.push(ChipsEvent::RemoveLast);
            }
        }

        let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
        let invalid = self.chips.iter().any(|chip| chip.error.is_some());
        let palette = theme::palette();
        let border = if invalid {
            theme::ERROR
        } else if focused {
            palette.accent_base
        } else {
            palette.border_strong
        };
        ui.painter().rect(
            rect,
            CornerRadius::same(theme::RADIUS),
            palette.input,
            Stroke::new(theme::stroke::HAIRLINE, border),
            egui::StrokeKind::Inside,
        );
        let inner = egui::Rect::from_min_size(
            rect.min + egui::vec2(FIELD_PADDING, vertical_padding),
            egui::vec2(inner_width, visible_height),
        );
        let mut input = None;
        let id = egui::Id::unique(("chips_field", self.id_salt));
        ui.scope_builder(egui::UiBuilder::new().max_rect(inner), |ui| {
            egui::ScrollArea::vertical()
                .id_salt(id)
                .max_height(visible_height)
                .auto_shrink([false, true])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    let (content, _) = ui.allocate_exact_size(
                        egui::vec2(inner_width, content_height),
                        egui::Sense::hover(),
                    );
                    let row_top =
                        |row: usize| content.top() + row as f32 * (CHIP_HEIGHT + CHIP_GAP);
                    for (index, ((chip, galley), (x, row, width))) in
                        self.chips.iter().zip(galleys).zip(places).enumerate()
                    {
                        let chip_rect = egui::Rect::from_min_size(
                            egui::pos2(content.left() + x, row_top(row)),
                            egui::vec2(width, CHIP_HEIGHT),
                        );
                        if paint_chip(ui, id.with(index), chip_rect, chip, galley, enabled) {
                            events.push(ChipsEvent::Remove(index));
                        }
                    }
                    if let Some((x, row, width)) = input_place {
                        let input_rect = egui::Rect::from_min_size(
                            egui::pos2(content.left() + x, row_top(row)),
                            egui::vec2(width, CHIP_HEIGHT),
                        );
                        let response = ui.put(
                            input_rect,
                            egui::TextEdit::singleline(self.input)
                                .id(input_id)
                                .frame(egui::Frame::NONE)
                                .hint_text(if self.chips.is_empty() { self.hint } else { "" })
                                .desired_width(width)
                                .margin(egui::Margin::ZERO)
                                .align(egui::Align2::LEFT_CENTER)
                                .interactive(enabled),
                        );
                        input = Some(response);
                    }
                });
        });
        if let Some(response) = &input {
            if response.changed()
                && let Some(end) = self.input.rfind(SEPARATORS)
            {
                let rest = self.input.split_off(end + 1);
                events.push(ChipsEvent::Add(std::mem::replace(self.input, rest)));
            }
            if response.lost_focus() && !self.input.trim().is_empty() {
                events.push(ChipsEvent::Add(std::mem::take(self.input)));
            }
        }
        // A click on the field's empty part puts the cursor in the input.
        let background = ui.interact(rect, id.with("background"), egui::Sense::click());
        if background.clicked() && input.is_some() {
            ui.memory_mut(|memory| memory.request_focus(input_id));
        }
        if enabled && input.is_some() {
            background.on_hover_cursor(egui::CursorIcon::Text);
        }
        ChipsOutput { events, input }
    }
}

/// Paints one chip and answers whether its cross was clicked.
fn paint_chip(
    ui: &mut egui::Ui,
    id: egui::Id,
    rect: egui::Rect,
    chip: &Chip<'_>,
    galley: std::sync::Arc<egui::Galley>,
    enabled: bool,
) -> bool {
    let palette = theme::palette();
    let (fill, stroke, text) = match chip.error {
        Some(_) => (
            theme::ERROR.gamma_multiply(theme::alpha::TINT),
            theme::ERROR,
            theme::ERROR,
        ),
        None => (palette.card, palette.border, palette.text),
    };
    let (fill, stroke, text) = if enabled {
        (fill, stroke, text)
    } else {
        (fill, stroke, theme::DISABLED)
    };
    let painter = ui.painter_at(rect);
    painter.rect(
        rect,
        CornerRadius::same(theme::RADIUS_INNER),
        fill,
        Stroke::new(theme::stroke::HAIRLINE, stroke),
        egui::StrokeKind::Inside,
    );
    let icon_center = egui::pos2(
        rect.left() + CHIP_PADDING + CHIP_ICON / 2.0,
        rect.center().y,
    );
    icons::paint(&painter, icon_center, chip.icon, text);
    let text_left = rect.left() + CHIP_PADDING + CHIP_ICON + CHIP_PADDING / 2.0;
    let close_center = egui::pos2(
        rect.right() - CHIP_PADDING - CHIP_CLOSE / 2.0,
        rect.center().y,
    );
    let text_painter = painter.with_clip_rect(egui::Rect::from_x_y_ranges(
        text_left..=close_center.x - CHIP_CLOSE / 2.0 - CHIP_PADDING / 2.0,
        rect.y_range(),
    ));
    text_painter.galley(
        egui::pos2(text_left, rect.center().y - galley.size().y / 2.0),
        galley,
        text,
    );
    if let Some(error) = chip.error {
        ui.interact(rect, id.with("chip"), egui::Sense::hover())
            .on_hover_text(error);
    }
    cross_button(ui, id.with("close"), close_center, enabled).clicked()
}

/// A small cross centred on `center` that removes what it stands on.
pub(crate) fn cross_button(
    ui: &mut egui::Ui,
    id: egui::Id,
    center: egui::Pos2,
    enabled: bool,
) -> egui::Response {
    let rect = egui::Rect::from_center_size(center, egui::Vec2::splat(CROSS_BUTTON));
    let response = ui.interact(
        rect,
        id,
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    let palette = theme::palette();
    let color = if !enabled {
        theme::DISABLED
    } else if response.hovered() {
        palette.text
    } else {
        palette.text_dim
    };
    let stroke = Stroke::new(theme::stroke::GLYPH, color);
    let arm = egui::Vec2::splat(CLOSE_ARM);
    let painter = ui.painter();
    painter.line_segment([center - arm, center + arm], stroke);
    painter.line_segment(
        [
            center + egui::vec2(-CLOSE_ARM, CLOSE_ARM),
            center + egui::vec2(CLOSE_ARM, -CLOSE_ARM),
        ],
        stroke,
    );
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "test_chips";

    /// Runs one frame of a field with `chips` and `input`, after `events`, with the input focused
    /// when `focus`. Returns what the field reported and every rectangle it painted.
    fn collect(shape: &egui::Shape, out: &mut Vec<egui::epaint::RectShape>) {
        match shape {
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, out)),
            egui::Shape::Rect(rect) => out.push(rect.clone()),
            _ => {}
        }
    }

    /// What one frame of the field reported, the rectangle it took and every rectangle it
    /// painted.
    struct Frame {
        output: ChipsOutput,
        rect: egui::Rect,
        painted: Vec<egui::epaint::RectShape>,
    }

    fn frame(
        ctx: &egui::Context,
        chips: &[Chip<'_>],
        input: &mut String,
        events: Vec<egui::Event>,
        focus: bool,
    ) -> Frame {
        if focus {
            ctx.memory_mut(|memory| memory.request_focus(chips_input_id(ID)));
        }
        let mut output = None;
        let mut full = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(800.0, 600.0),
                )),
                events,
                ..egui::RawInput::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.set_width(400.0);
                    let shown =
                        ui.scope(|ui| ChipsField::new(ID, chips, input).max_rows(3).show(ui));
                    output = Some((shown.inner, shown.response.rect));
                });
            },
        );
        full.textures_delta.clear();
        let mut painted = Vec::new();
        for clipped in &full.shapes {
            collect(&clipped.shape, &mut painted);
        }
        let (output, rect) = output.expect("the field is shown");
        Frame {
            output,
            rect,
            painted,
        }
    }

    fn context() -> egui::Context {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        ctx
    }

    fn chip(label: &str) -> Chip<'_> {
        Chip {
            label,
            icon: Icon::Globe,
            error: None,
        }
    }

    #[test]
    fn a_paste_becomes_one_add_with_what_was_typed_before_it() {
        let ctx = context();
        let mut input = "you".to_owned();
        frame(&ctx, &[], &mut input, Vec::new(), true);
        let shown = frame(
            &ctx,
            &[],
            &mut input,
            vec![egui::Event::Paste("tube.com, 192.0.2.1\n".into())],
            true,
        );
        assert_eq!(
            shown.output.events,
            [ChipsEvent::Add("youtube.com, 192.0.2.1\n".into())]
        );
        assert!(input.is_empty());
    }

    #[test]
    fn a_separator_ends_an_item_and_enter_ends_the_last() {
        let ctx = context();
        let mut input = String::new();
        frame(&ctx, &[], &mut input, Vec::new(), true);
        let shown = frame(
            &ctx,
            &[],
            &mut input,
            vec![egui::Event::Text("example.com,exa".into())],
            true,
        );
        assert_eq!(
            shown.output.events,
            [ChipsEvent::Add("example.com,".into())]
        );
        assert_eq!(input, "exa");
        let enter = egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        };
        let shown = frame(&ctx, &[], &mut input, vec![enter], true);
        assert_eq!(shown.output.events, [ChipsEvent::Add("exa".into())]);
        assert!(input.is_empty());
    }

    #[test]
    fn backspace_in_an_empty_input_removes_the_last_chip_only_then() {
        let ctx = context();
        let chips = [chip("example.com"), chip("example.org")];
        let backspace = || egui::Event::Key {
            key: egui::Key::Backspace,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        };
        let mut input = "ab".to_owned();
        frame(&ctx, &chips, &mut input, Vec::new(), true);
        let shown = frame(&ctx, &chips, &mut input, vec![backspace()], true);
        assert!(shown.output.events.is_empty(), "{:?}", shown.output.events);
        assert_eq!(input, "a");
        input.clear();
        let shown = frame(&ctx, &chips, &mut input, vec![backspace()], true);
        assert_eq!(shown.output.events, [ChipsEvent::RemoveLast]);
    }

    #[test]
    fn a_bad_chip_and_the_field_around_it_are_red() {
        let ctx = context();
        let chips = [
            chip("example.com"),
            Chip {
                label: "bad..domain",
                icon: Icon::Globe,
                error: Some("enter a domain"),
            },
        ];
        let shown = frame(&ctx, &chips, &mut String::new(), Vec::new(), false);
        assert!(
            shown
                .painted
                .iter()
                .any(|rect| rect.rect == shown.rect && rect.stroke.color == theme::ERROR)
        );
        assert_eq!(
            shown
                .painted
                .iter()
                .filter(
                    |rect| rect.rect.height() == CHIP_HEIGHT && rect.stroke.color == theme::ERROR
                )
                .count(),
            1
        );
        let shown = frame(&ctx, &chips[..1], &mut String::new(), Vec::new(), false);
        assert!(shown.painted.iter().any(|rect| rect.rect == shown.rect
            && rect.stroke.color != theme::ERROR
            && rect.fill == theme::palette().input));
    }

    #[test]
    fn the_field_grows_a_row_at_a_time_up_to_its_limit() {
        let ctx = context();
        let labels: Vec<String> = (0..40)
            .map(|index| format!("site{index}.example"))
            .collect();
        let mut heights = Vec::new();
        for count in [0, 2, 6, 12, 40] {
            let chips: Vec<_> = labels[..count].iter().map(|label| chip(label)).collect();
            let shown = frame(&ctx, &chips, &mut String::new(), Vec::new(), false);
            heights.push(shown.rect.height());
        }
        assert_eq!(heights[0], heights[1], "{heights:?}");
        assert!(
            heights[1] < heights[2] && heights[2] < heights[3],
            "{heights:?}"
        );
        assert_eq!(heights[3], heights[4], "{heights:?}");
        assert_eq!(
            heights[4],
            3.0 * CHIP_HEIGHT + 2.0 * CHIP_GAP + 2.0 * FIELD_PADDING
        );
    }

    #[test]
    fn a_field_that_takes_no_more_items_has_no_input() {
        let ctx = context();
        let chips = [chip("example.com")];
        let mut input = String::new();
        let field = |ui: &mut egui::Ui, input: &mut String| {
            ChipsField::new(ID, &chips, input)
                .accepts_input(false)
                .show(ui)
        };
        let mut shown = None;
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| shown = Some(field(ui, &mut input)));
        });
        output.textures_delta.clear();
        assert!(shown.unwrap().input.is_none());
    }
}
