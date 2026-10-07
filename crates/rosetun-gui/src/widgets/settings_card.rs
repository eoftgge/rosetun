use eframe::egui::{self, Align, Layout, RichText, Stroke};

use super::toggle::{TOGGLE_SIZE, paint_toggle};
use crate::theme::{BORDER, CARD, RADIUS, TEXT, TEXT_DIM};

/// A card of setting rows separated by 1 px BORDER lines.
pub(crate) fn settings_card(ui: &mut egui::Ui, add_rows: impl FnOnce(&mut SettingsCard<'_>)) {
    let width = ui.available_width();
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(RADIUS)
        .inner_margin(0)
        .show(ui, |ui| {
            ui.set_min_width(width);
            ui.spacing_mut().item_spacing.y = 0.0;
            add_rows(&mut SettingsCard { ui, rows: 0 });
        });
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
        title: &str,
        detail: Option<&str>,
        control: impl FnOnce(&mut egui::Ui),
    ) {
        self.row_inner(title, detail, control);
    }

    fn row_inner(
        &mut self,
        title: &str,
        detail: Option<&str>,
        control: impl FnOnce(&mut egui::Ui),
    ) -> egui::Rect {
        self.row_with_title(
            |ui| {
                ui.add(egui::Label::new(RichText::new(title).color(TEXT)).wrap());
            },
            detail,
            control,
        )
    }

    pub(crate) fn row_with_title(
        &mut self,
        title: impl FnOnce(&mut egui::Ui),
        detail: Option<&str>,
        control: impl FnOnce(&mut egui::Ui),
    ) -> egui::Rect {
        if self.rows > 0 {
            let (line, _) = self.ui.allocate_exact_size(
                egui::vec2(self.ui.available_width(), 1.0),
                egui::Sense::hover(),
            );
            self.ui
                .painter()
                .hline(line.x_range(), line.center().y, (1.0, BORDER));
        }
        self.rows += 1;
        let width = self.ui.available_width();
        egui::Frame::new()
            .inner_margin(egui::Margin {
                left: 20,
                right: 20,
                top: 16,
                bottom: 16,
            })
            .show(self.ui, |ui| {
                ui.set_min_width((width - 40.0).max(0.0));
                ui.set_min_height(32.0);
                ui.spacing_mut().item_spacing.x = 16.0;
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.scope(control);
                    let text_width = (ui.available_width() - 16.0).max(0.0);
                    ui.add_space(16.0);
                    ui.allocate_ui_with_layout(
                        egui::vec2(text_width, 32.0),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            ui.set_width(text_width);
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 2.0;
                                title(ui);
                                if let Some(detail) = detail {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(detail).small().color(TEXT_DIM),
                                        )
                                        .wrap(),
                                    );
                                }
                            });
                        },
                    );
                });
            })
            .response
            .rect
    }

    /// A row whose control is a toggle; the whole row is clickable.
    pub(crate) fn toggle(
        &mut self,
        title: &str,
        detail: &str,
        on: &mut bool,
        enabled: bool,
    ) -> egui::Response {
        let enabled = enabled && self.ui.is_enabled();
        let id = self.ui.next_auto_id();
        let mut switch = egui::Rect::NOTHING;
        let row = self.row_inner(title, Some(detail), |ui| {
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
        response.widget_info(|| {
            egui::WidgetInfo::selected(egui::WidgetType::Checkbox, enabled, *on, title)
        });
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
                left: 20,
                right: 20,
                top: 16,
                bottom: 16,
            })
            .show(self.ui, |ui| {
                ui.set_min_width((width - 40.0).max(0.0));
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
                        rects.push(card.row_inner("Motion", Some("A detail"), |_| {}));
                    });
                });
            },
        );
        output.textures_delta.clear();
        assert!(rects.iter().all(|rect| rect.height() >= 64.0));
        assert_eq!(rects[1].top() - rects[0].bottom(), 1.0);
        assert_eq!(rects[0].width(), rects[1].width());
        assert!(title_width >= 200.0, "title width: {title_width}");
        assert!(control_rect.left() > rects[0].center().x);
    }
}
