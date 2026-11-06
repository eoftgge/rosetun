use eframe::egui::{self, Align, Layout, RichText, Stroke, emath::GuiRounding, text::LayoutJob};

use super::tag::title_with_tag;
use super::text_field::field_height;
use super::toggle::{TOGGLE_SIZE, paint_toggle};
use crate::theme::{self, RADIUS};

/// A card of setting rows separated by 1 px theme::palette().border lines.
pub(crate) fn settings_card(ui: &mut egui::Ui, add_rows: impl FnOnce(&mut SettingsCard<'_>)) {
    let width = ui.available_width();
    egui::Frame::new()
        .fill(theme::palette().card)
        .stroke(Stroke::new(
            theme::stroke::HAIRLINE,
            theme::palette().border,
        ))
        .corner_radius(RADIUS)
        .inner_margin(0)
        .show(ui, |ui| {
            ui.set_min_width(width);
            ui.spacing_mut().item_spacing.y = 0.0;
            add_rows(&mut SettingsCard { ui, rows: 0 });
        });
}

/// A row's caption. While the change waits for a new connection, the caption says so after its
/// last word, in the same type and in a quiet colour: this is news, not a fault.
pub(crate) fn row_detail(ui: &mut egui::Ui, detail: &str, pending: bool) {
    let mut job = LayoutJob::default();
    let valign = ui.text_valign();
    let mut append = |text: RichText| {
        text.small()
            .append_to(&mut job, ui.style(), egui::FontSelection::Default, valign);
    };
    append(RichText::new(detail).color(theme::palette().text_dim));
    if pending {
        let note = format!(" {}", tr!("next-connect-note"));
        append(RichText::new(note).color(theme::palette().text_muted));
    }
    ui.add(egui::Label::new(job).wrap());
}

/// What a row may ask for beyond its title, caption and control.
#[derive(Clone, Copy, Default)]
pub(crate) struct RowOptions {
    /// The change waits for a new connection; see `row_detail`.
    pub(crate) pending: bool,
    /// The setting belongs to the row above: no line or top padding parts them, its text steps
    /// in behind a guide line and its control keeps the column.
    pub(crate) nested: bool,
    /// A control taller than a switch: the row centres its text on this height,
    /// or the two would sit apart.
    pub(crate) control_height: Option<f32>,
}

pub(crate) struct SettingsCard<'a> {
    ui: &'a mut egui::Ui,
    rows: usize,
}

impl SettingsCard<'_> {
    /// Title and detail on the left, the control on the right; at least 64
    /// high, padding 16 by 20.
    pub(crate) fn row(
        &mut self,
        title: impl AsRef<str>,
        detail: Option<&str>,
        control: impl FnOnce(&mut egui::Ui),
    ) {
        self.row_inner(title.as_ref(), None, detail, RowOptions::default(), control);
    }

    /// `row` with `RowOptions`.
    pub(crate) fn row_with(
        &mut self,
        title: impl AsRef<str>,
        detail: Option<&str>,
        options: RowOptions,
        control: impl FnOnce(&mut egui::Ui),
    ) {
        self.row_inner(title.as_ref(), None, detail, options, control);
    }

    /// `row` whose control is a text field.
    pub(crate) fn field_row(
        &mut self,
        title: impl AsRef<str>,
        detail: Option<&str>,
        control: impl FnOnce(&mut egui::Ui),
    ) {
        let options = RowOptions {
            control_height: Some(field_height(self.ui)),
            ..RowOptions::default()
        };
        self.row_inner(title.as_ref(), None, detail, options, control);
    }

    fn row_inner(
        &mut self,
        title: &str,
        tag: Option<&str>,
        detail: Option<&str>,
        options: RowOptions,
        control: impl FnOnce(&mut egui::Ui),
    ) -> egui::Rect {
        self.row_parts(
            |ui| {
                title_with_tag(
                    ui,
                    RichText::new(title).color(theme::palette().text).into(),
                    tag,
                );
            },
            detail,
            options,
            control,
        )
    }

    pub(crate) fn row_with_title(
        &mut self,
        title: impl FnOnce(&mut egui::Ui),
        detail: Option<&str>,
        control: impl FnOnce(&mut egui::Ui),
    ) -> egui::Rect {
        self.row_parts(title, detail, RowOptions::default(), control)
    }

    fn row_parts(
        &mut self,
        title: impl FnOnce(&mut egui::Ui),
        detail: Option<&str>,
        options: RowOptions,
        control: impl FnOnce(&mut egui::Ui),
    ) -> egui::Rect {
        if self.rows > 0 && !options.nested {
            let (line, _) = self.ui.allocate_exact_size(
                egui::vec2(self.ui.available_width(), 1.0),
                egui::Sense::hover(),
            );
            self.ui.painter().hline(
                line.x_range(),
                line.center().y,
                (1.0, theme::palette().border),
            );
        }
        self.rows += 1;
        let width = self.ui.available_width();
        let height = options.control_height.unwrap_or(32.0);
        let (left, top) = if options.nested {
            (theme::space::L + theme::space::XL, 0.0)
        } else {
            (theme::space::L, theme::space::L)
        };
        let row = egui::Frame::new()
            .inner_margin(egui::Margin {
                left: theme::margin::side(left),
                right: theme::margin::side(theme::space::L),
                top: theme::margin::side(top),
                bottom: theme::margin::side(theme::space::L),
            })
            .show(self.ui, |ui| {
                ui.set_min_width((width - left - theme::space::L).max(0.0));
                ui.set_min_height(height);
                ui.spacing_mut().item_spacing.x = theme::space::L;
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), height),
                    Layout::right_to_left(Align::Center),
                    |ui| {
                        ui.scope(control);
                        let text_width = (ui.available_width() - 16.0).max(0.0);
                        ui.add_space(theme::space::L);
                        ui.allocate_ui_with_layout(
                            egui::vec2(text_width, height),
                            Layout::left_to_right(Align::Center),
                            |ui| {
                                ui.set_width(text_width);
                                let Some(detail) = detail else {
                                    // A vertical group would keep a lone title at the top,
                                    // off the line of its control.
                                    title(ui);
                                    return;
                                };
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = theme::space::XXS;
                                    title(ui);
                                    row_detail(ui, detail, options.pending);
                                });
                            },
                        );
                    },
                );
            })
            .response
            .rect;
        if options.nested {
            // Under the left edge of the parent's text, as high as this row's text.
            let x = (row.left() + theme::space::L)
                .round_to_pixel_center(self.ui.ctx().pixels_per_point());
            self.ui.painter().vline(
                x,
                row.top()..=row.bottom() - theme::space::L,
                Stroke::new(theme::stroke::HAIRLINE, theme::palette().border_strong),
            );
        }
        row
    }

    /// Shows `hint` while the pointer rests anywhere on the row at `rect`.
    pub(crate) fn hover_hint(&mut self, rect: egui::Rect, hint: &str) {
        let id = self.ui.scope_id().with(("row-hint", self.rows));
        self.ui
            .interact(rect, id, egui::Sense::hover())
            .on_hover_text(hint);
    }

    /// A row whose control is a toggle, with an optional tag after the
    /// title; the whole row is clickable.
    pub(crate) fn toggle(
        &mut self,
        title: impl AsRef<str>,
        tag: Option<&str>,
        detail: impl AsRef<str>,
        on: &mut bool,
        enabled: bool,
    ) -> egui::Response {
        self.toggle_with(title, tag, detail, RowOptions::default(), on, enabled)
    }

    /// `toggle` with `RowOptions`.
    pub(crate) fn toggle_with(
        &mut self,
        title: impl AsRef<str>,
        tag: Option<&str>,
        detail: impl AsRef<str>,
        options: RowOptions,
        on: &mut bool,
        enabled: bool,
    ) -> egui::Response {
        let title = title.as_ref();
        let detail = detail.as_ref();
        let enabled = enabled && self.ui.is_enabled();
        let id = self.ui.next_auto_id();
        let mut switch = egui::Rect::NOTHING;
        let row = self.row_inner(title, tag, Some(detail), options, |ui| {
            switch = ui.allocate_exact_size(TOGGLE_SIZE, egui::Sense::hover()).0;
        });
        let mut response = self.ui.interact(
            row,
            id,
            if enabled {
                egui::Sense::click()
            } else {
                egui::Sense::hover()
            },
        );
        if response.clicked() && enabled {
            *on = !*on;
            response.mark_changed();
        }
        response
            .widget_info(|| egui::WidgetInfo::selected(egui::Role::CheckBox, enabled, *on, title));
        let progress = self.ui.ctx().animate_bool_with_time(response.id, *on, 0.1);
        paint_toggle(self.ui, switch, *on, progress, enabled);
        if enabled {
            response.on_hover_cursor(egui::CursorIcon::PointingHand)
        } else {
            response
        }
    }

    /// Free content under the rows, with the same padding (DNS cards, the
    /// custom form).
    pub(crate) fn body(&mut self, add_contents: impl FnOnce(&mut egui::Ui)) {
        let width = self.ui.available_width();
        egui::Frame::new()
            .inner_margin(egui::Margin {
                left: theme::margin::side(theme::space::L),
                right: theme::margin::side(theme::space::L),
                top: theme::margin::side(theme::space::L),
                bottom: theme::margin::side(theme::space::L),
            })
            .show(self.ui, |ui| {
                ui.set_min_width((width - 2.0 * theme::space::L).max(0.0));
                add_contents(ui);
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_have_minimum_height_and_full_width_separators() {
        let ctx = egui::Context::default();
        let mut rects = Vec::new();
        let mut title_width = 0.0;
        let mut control_rect = egui::Rect::NOTHING;
        let mut tall_control = egui::Rect::NOTHING;
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(640.0, 480.0),
                )),
                ..egui::RawInput::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    settings_card(ui, |card| {
                        rects.push(card.row_with_title(
                            |ui| {
                                title_width = ui.available_width();
                                ui.label("Language");
                            },
                            None,
                            |ui| {
                                control_rect = ui
                                    .allocate_exact_size(
                                        egui::vec2(200.0, 32.0),
                                        egui::Sense::hover(),
                                    )
                                    .0;
                            },
                        ));
                        rects.push(card.row_inner(
                            "Motion",
                            None,
                            Some("A detail"),
                            RowOptions::default(),
                            |_| {},
                        ));
                        rects.push(card.row_with_title(
                            |ui| {
                                ui.label("Reconnect automatically");
                            },
                            Some("This detail wraps onto several lines when the window is narrow, so the control must stay centered vertically beside it."),
                            |ui| {
                                tall_control = ui.allocate_exact_size(TOGGLE_SIZE, egui::Sense::hover()).0;
                            },
                        ));
                    });
                });
            },
        );
        output.textures_delta.clear();
        assert!(rects.iter().all(|rect| rect.height() >= 64.0));
        assert!(rects[0].height() <= 96.0, "first row: {:?}", rects[0]);
        assert!(rects[1].height() <= 96.0, "second row: {:?}", rects[1]);
        assert_eq!(rects[1].top() - rects[0].bottom(), 1.0);
        assert_eq!(rects[0].width(), rects[1].width());
        assert!(title_width >= 200.0, "title width: {title_width}");
        assert!(control_rect.left() > rects[0].center().x);
        assert!((tall_control.center().y - rects[2].center().y).abs() <= 2.0);
    }

    #[test]
    fn a_nested_row_joins_the_row_above_and_the_next_row_is_parted_again() {
        let ctx = egui::Context::default();
        let mut rects = Vec::new();
        let nested = RowOptions {
            nested: true,
            ..RowOptions::default()
        };
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(640.0, 480.0),
                )),
                ..egui::RawInput::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    settings_card(ui, |card| {
                        let plain = RowOptions::default();
                        rects.push(card.row_inner("Parent", None, Some("A"), plain, |_| {}));
                        rects.push(card.row_inner("Child", None, Some("B"), nested, |_| {}));
                        rects.push(card.row_inner("Next", None, Some("C"), plain, |_| {}));
                    });
                });
            },
        );
        output.textures_delta.clear();
        assert_eq!(rects[1].top(), rects[0].bottom());
        assert_eq!(rects[2].top() - rects[1].bottom(), 1.0);
        assert_eq!(rects[1].height(), rects[0].height() - theme::space::L);
        assert_eq!(rects[1].width(), rects[0].width());

        let guides: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|clipped| match &clipped.shape {
                egui::Shape::LineSegment { points, stroke } if points[0].x == points[1].x => {
                    Some((*points, *stroke))
                }
                _ => None,
            })
            .collect();
        assert_eq!(guides.len(), 1, "only the nested row has a guide");
        let ([start, end], stroke) = guides[0];
        assert_eq!(start.y, rects[1].top());
        assert_eq!(end.y, rects[1].bottom() - theme::space::L);
        assert!((start.x - (rects[1].left() + theme::space::L)).abs() <= 0.5);
        assert_eq!(stroke.color, theme::palette().border_strong);
    }

    /// The text of a caption and the colour and size of each of its parts.
    fn caption_parts(pending: bool) -> (String, Vec<(egui::Color32, f32)>) {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| row_detail(ui, "Caption.", pending));
        });
        output.textures_delta.clear();
        let galley = output
            .shapes
            .iter()
            .find_map(|clipped| match &clipped.shape {
                egui::Shape::Text(text) => Some(text.galley.clone()),
                _ => None,
            })
            .expect("the caption is painted");
        let parts = galley
            .job
            .sections
            .iter()
            .map(|section| (section.format.color, section.format.font_id.size))
            .collect();
        (galley.text().to_owned(), parts)
    }

    #[test]
    fn the_note_stays_quiet_and_in_the_size_of_the_caption() {
        let (text, parts) = caption_parts(false);
        assert_eq!(text, "Caption.");
        assert_eq!(parts, [(theme::palette().text_dim, theme::font::CAPTION)]);

        let (text, parts) = caption_parts(true);
        assert_eq!(text, format!("Caption. {}", tr!("next-connect-note")));
        assert_eq!(
            parts,
            [
                (theme::palette().text_dim, theme::font::CAPTION),
                (theme::palette().text_muted, theme::font::CAPTION),
            ]
        );
        assert_ne!(parts[1].0, theme::palette().accent_light);
        assert_ne!(parts[1].0, theme::ERROR);
    }

    #[test]
    fn service_and_log_cards_stay_compact_in_a_scrolling_settings_panel() {
        for (width, height) in [(960.0, 640.0), (1200.0, 780.0)] {
            let ctx = egui::Context::default();
            let mut rows = Vec::new();
            let mut log_height = 0.0;
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, height),
                    )),
                    ..egui::RawInput::default()
                },
                |ctx| {
                    egui::Panel::left("settings_nav")
                        .exact_size(240.0)
                        .show(ctx, |_| {});
                    egui::CentralPanel::default()
                        .frame(egui::Frame::new().inner_margin(theme::margin::same(theme::space::XXL)))
                        .show(ctx, |ui| {
                            egui::ScrollArea::vertical().show(ui, |ui| {
                                settings_card(ui, |card| {
                                    rows.push(card.row_inner(
                                        "Rosetun service: not running",
                                        None,
                                        Some("The service runs the tunnel with system rights."),
                                        RowOptions::default(),
                                        |_| {},
                                    ));
                                });
                                ui.add_space(16.0);
                                let top = ui.cursor().top();
                                settings_card(ui, |card| {
                                    rows.push(card.row_inner(
                                        "Log",
                                        None,
                                        Some("Useful when something breaks and you contact support."),
                                        RowOptions::default(),
                                        |ui| {
                                            ui.allocate_exact_size(
                                                egui::vec2(130.0, 32.0),
                                                egui::Sense::hover(),
                                            );
                                        },
                                    ));
                                    rows.push(card.row_inner(
                                        "Verbose log",
                                        None,
                                        Some("Turns itself off after a day. While on, it records site addresses and applies on next connect."),
                                        RowOptions::default(),
                                        |ui| {
                                            ui.allocate_exact_size(TOGGLE_SIZE, egui::Sense::hover());
                                        },
                                    ));
                                });
                                log_height = ui.cursor().top() - top;
                            });
                        });
                },
            );
            output.textures_delta.clear();
            assert!(
                rows[0].height() <= 96.0,
                "service: {rows:?} at {width}×{height}"
            );
            assert!(
                rows[1].height() <= 96.0,
                "log: {rows:?} at {width}×{height}"
            );
            assert!(
                log_height <= 240.0,
                "log card: {log_height} at {width}×{height}"
            );
        }
    }
}
