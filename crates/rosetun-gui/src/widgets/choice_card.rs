use std::hash::{Hash, Hasher};

use eframe::egui::{self, CornerRadius, Stroke, UiBuilder};

use crate::theme::{self, RADIUS};

/// One of a few choices: no fill and a theme::palette().border stroke at rest, an theme::palette().input fill
/// and a theme::palette().accent_base stroke when selected.
pub(crate) fn choice_card(
    ui: &mut egui::Ui,
    id_salt: impl Hash,
    width: f32,
    selected: bool,
    enabled: bool,
    label: &str,
    add_contents: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    let enabled = enabled && ui.is_enabled();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    id_salt.hash(&mut hasher);
    let response = ui
        .scope_builder(
            UiBuilder::new().id_salt(hasher.finish()).sense(if enabled {
                egui::Sense::click()
            } else {
                egui::Sense::hover()
            }),
            |ui| {
                ui.style_mut().interaction.selectable_labels = false;
                if !enabled {
                    ui.multiply_opacity(0.5);
                }
                let background = ui.painter().add(egui::Shape::Noop);
                ui.set_width(width - 24.0);
                egui::Frame::new()
                    .inner_margin(theme::margin::symmetric(theme::space::M, theme::space::S))
                    .show(ui, |ui| {
                        ui.set_width(width - 24.0);
                        ui.set_max_width(width - 24.0);
                        add_contents(ui);
                    });
                let response = ui.response();
                let fill = if selected {
                    theme::palette().input
                } else if response.hovered() && enabled {
                    theme::palette().border
                } else {
                    egui::Color32::TRANSPARENT
                };
                ui.painter().set(
                    background,
                    egui::Shape::rect_filled(response.rect, CornerRadius::same(RADIUS), fill),
                );
                ui.painter().rect_stroke(
                    response.rect,
                    CornerRadius::same(RADIUS),
                    Stroke::new(
                        theme::stroke::HAIRLINE,
                        if selected {
                            theme::palette().accent_base
                        } else {
                            theme::palette().border
                        },
                    ),
                    egui::StrokeKind::Inside,
                );
            },
        )
        .response;
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::Role::RadioButton, enabled, selected, label)
    });
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// A choice card with a radio mark on the left, centred on the height of the text beside it.
pub(crate) fn radio_card(
    ui: &mut egui::Ui,
    id_salt: impl Hash,
    width: f32,
    selected: bool,
    enabled: bool,
    label: &str,
    add_contents: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    choice_card(ui, id_salt, width, selected, enabled, label, |ui| {
        ui.horizontal_top(|ui| {
            let left = ui.cursor().left();
            ui.add_space(theme::radio::COLUMN + theme::space::S);
            // The height of the text is known only now, so the mark follows it.
            let text = ui.vertical(add_contents).response.rect;
            let center = egui::pos2(left + theme::radio::COLUMN / 2.0, text.center().y);
            radio_mark(ui, center, selected);
        });
    })
}

fn radio_mark(ui: &egui::Ui, center: egui::Pos2, selected: bool) {
    let color = if selected {
        theme::palette().accent_light
    } else {
        theme::palette().text_dim
    };
    ui.painter().circle_stroke(
        center,
        theme::radio::RING,
        Stroke::new(theme::stroke::GLYPH, color),
    );
    if selected {
        ui.painter().circle_filled(center, theme::radio::DOT, color);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_ui::TestScreen;

    const TITLE: &str = "A title";
    const SHORT: &str = "One line.";
    const LONG: &str = "A description long enough to take more than one line in a narrow card.";

    /// How many title heights the description takes, and how far the ring stands from the
    /// centre of the text.
    fn measure(size: egui::Vec2, detail: &str) -> (f32, f32) {
        let mut screen = TestScreen::new(size);
        let (texts, circles) = screen.settle_with_circles(|ui| {
            radio_card(ui, "card", 200.0, true, true, TITLE, |ui| {
                ui.label(TITLE);
                ui.add(egui::Label::new(egui::RichText::new(detail).small()).wrap());
            });
        });
        let rect_of = |wanted: &str| {
            texts
                .iter()
                .find(|(text, _)| text == wanted)
                .unwrap_or_else(|| panic!("no text {wanted:?}"))
                .1
        };
        let (title, description) = (rect_of(TITLE), rect_of(detail));
        let (ring, _) = circles
            .iter()
            .find(|(_, radius)| *radius == theme::radio::RING)
            .expect("the ring is painted");
        assert!(ring.x < title.left(), "the ring stands left of the text");
        (
            description.height() / title.height(),
            (ring.y - title.union(description).center().y).abs(),
        )
    }

    #[test]
    fn the_ring_stays_on_the_middle_of_a_one_or_two_line_description() {
        for size in [egui::vec2(960.0, 640.0), egui::vec2(1200.0, 780.0)] {
            let (rows, offset) = measure(size, SHORT);
            assert!(rows < 1.5, "{size:?}: {rows}");
            assert!(offset <= 1.0, "{size:?}, one line: {offset}");

            let (rows, offset) = measure(size, LONG);
            assert!(rows > 1.5, "{size:?}: {rows}");
            assert!(offset <= 1.0, "{size:?}, two lines: {offset}");
        }
    }
}
