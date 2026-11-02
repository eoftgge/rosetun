use eframe::egui::{self, RichText};

use crate::icons::{self, Icon};
use crate::theme;

use super::text_field::{field_height, style_field};

/// A drop-down as high as a field, in the field's fill, border and corners, with the chevron at
/// the right inside. `width` is its width, the whole row when `None`; `menu` adds the choices.
pub(crate) fn drop_down(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    width: Option<f32>,
    selected_text: impl Into<egui::WidgetText>,
    menu: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    let width = width.unwrap_or_else(|| ui.available_width());
    let height = field_height(ui);
    let palette = theme::palette();
    let chevron = if ui.is_enabled() {
        palette.text_dim
    } else {
        palette.border_strong
    };
    ui.scope(|ui| {
        ui.spacing_mut().interact_size.y = height;
        style_field(ui, false);
        let visuals = &mut ui.visuals_mut().widgets;
        for state in [&mut visuals.inactive, &mut visuals.open] {
            state.weak_bg_fill = palette.input;
        }
        for state in [&mut visuals.hovered, &mut visuals.active] {
            state.weak_bg_fill = palette.border;
        }
        visuals.open.bg_stroke = visuals.hovered.bg_stroke;
        ui.allocate_ui(egui::vec2(width, height), |ui| {
            ui.set_width(width);
            egui::ComboBox::from_id_salt(id_salt)
                .width(width)
                .truncate()
                .selected_text(selected_text)
                .icon(move |ui, rect, _, _| {
                    icons::paint(
                        ui.painter(),
                        rect.center(),
                        Icon::Chevron { open: 1.0 },
                        chevron,
                    );
                })
                .show_ui(ui, menu)
                .response
        })
        .inner
    })
    .inner
}

/// A drop-down for a filter row, with a hint. `menu` adds the choices.
pub(crate) fn filter_combo(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    width: f32,
    selected_text: RichText,
    hover: String,
    menu: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    drop_down(ui, id_salt, Some(width), selected_text, menu).on_hover_text(hover)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_ui::TestScreen;
    use crate::widgets::TextField;

    fn screen() -> TestScreen {
        TestScreen::new(egui::vec2(800.0, 600.0))
    }

    #[test]
    fn a_drop_down_is_as_high_as_a_field_and_as_wide_as_it_is_told() {
        let mut screen = screen();
        let mut sizes = Vec::new();
        screen.run(Vec::new(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                let mut text = String::new();
                let field = ui.add(TextField::new(&mut text).width(200.0));
                let narrow = drop_down(ui, "narrow", Some(200.0), "English", |_| {});
                let whole = drop_down(ui, "whole", None, "English", |_| {});
                let filter = filter_combo(
                    ui,
                    "filter",
                    SEARCH_WIDTH_FOR_TEST,
                    RichText::new("Any"),
                    String::new(),
                    |_| {},
                );
                sizes = vec![field.rect, narrow.rect, whole.rect, filter.rect];
                assert_eq!(whole.rect.width(), ui.max_rect().width());
            });
        });
        for rect in &sizes[1..] {
            assert_eq!(rect.height(), sizes[0].height(), "{rect:?}");
        }
        assert_eq!(sizes[1].width(), sizes[0].width());
        assert_eq!(sizes[3].width(), SEARCH_WIDTH_FOR_TEST);
    }

    const SEARCH_WIDTH_FOR_TEST: f32 = 180.0;

    #[test]
    fn a_drop_down_has_the_fill_border_and_corners_of_a_field() {
        use eframe::egui::epaint::RectShape;

        fn frames(shape: &egui::Shape, out: &mut Vec<RectShape>) {
            match shape {
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| frames(shape, out)),
                egui::Shape::Rect(rect) => out.push(rect.clone()),
                _ => {}
            }
        }

        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut rects = Vec::new();
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let mut text = String::new();
                let field = ui.add(TextField::new(&mut text).width(200.0));
                let combo = drop_down(ui, "combo", Some(200.0), "English", |_| {});
                rects = vec![field.rect, combo.rect];
            });
        });
        output.textures_delta.clear();
        let mut shapes = Vec::new();
        for clipped in &output.shapes {
            frames(&clipped.shape, &mut shapes);
        }
        let around = |rect: egui::Rect| {
            shapes
                .iter()
                .find(|shape| {
                    (shape.rect.min - rect.min).length() < 1.5
                        && (shape.rect.max - rect.max).length() < 1.5
                        && shape.stroke.width > 0.0
                })
                .unwrap_or_else(|| panic!("no frame around {rect:?}"))
        };
        let (field, combo) = (around(rects[0]), around(rects[1]));
        assert_eq!(field.fill, combo.fill);
        assert_eq!(field.stroke, combo.stroke);
        assert_eq!(field.corner_radius, combo.corner_radius);
    }

    #[test]
    fn choosing_a_value_in_a_drop_down_picks_it() {
        let mut screen = screen();
        let mut picked = String::from("English");
        let show = |picked: &mut String, ui: &mut egui::Ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                let shown = picked.clone();
                drop_down(ui, "language", Some(200.0), shown, |ui| {
                    for name in ["English", "Русский"] {
                        ui.selectable_value(picked, name.to_owned(), name);
                    }
                });
            });
        };
        let open = screen.click_text("English", |ui| show(&mut picked, ui));
        assert!(open.iter().any(|(text, _)| text == "Русский"), "{open:?}");
        screen.click_text("Русский", |ui| show(&mut picked, ui));
        assert_eq!(picked, "Русский");
    }
}
