use eframe::egui::{self, Color32, RichText};

use crate::icons::{self, Icon};
use crate::theme;

use super::menu::menu_popup;
use super::text_field::{field_height, style_field};

/// Radius of the active-filter mark in the corner of a compact filter button.
const ACTIVE_DOT_RADIUS: f32 = 2.5;

/// A drop-down as high as a field, in the field's fill, border and corners, with the chevron at
/// the right inside. `width` is its width, the whole row when `None`; `menu` adds the choices.
pub(crate) fn drop_down<'a>(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    width: Option<f32>,
    selected_text: impl egui::IntoAtoms<'a>,
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
                .show_ui(ui, |ui| {
                    // The combo's scroll area starts a new layout. Full-width menu rows
                    // need its content width before the first item is placed.
                    ui.set_min_width(ui.available_width());
                    // A chosen item is filled with the accent itself, not the faint wash
                    // behind selected text.
                    let visuals = ui.visuals_mut();
                    visuals.override_text_color = None;
                    visuals.widgets.inactive.fg_stroke.color = palette.text;
                    visuals.widgets.hovered.fg_stroke.color = palette.text;
                    visuals.widgets.active.fg_stroke.color = palette.on_accent;
                    visuals.selection.bg_fill = palette.accent_base;
                    visuals.selection.stroke =
                        egui::Stroke::new(theme::stroke::HAIRLINE, palette.on_accent);
                    menu(ui);
                })
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

/// A square icon button for a filter row when width is tight, as high as a field.
/// Opens the same choices in a popup `popup_width` wide; `active_color` marks a non-default
/// filter with colour and a corner dot so active filtering stays visible without text.
pub(crate) fn filter_combo_icon(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    popup_width: f32,
    active_color: Option<Color32>,
    hover: String,
    menu: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    ui.push_id(id_salt, |ui| {
        let side = field_height(ui);
        let enabled = ui.is_enabled();
        let sense = if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        };
        let (rect, response) = ui.allocate_exact_size(egui::vec2(side, side), sense);
        let popup = menu_popup(&response);
        let open = popup.is_open();
        let palette = theme::palette();
        if ui.is_rect_visible(rect) {
            let fill = if enabled && (response.hovered() || response.is_pointer_button_down_on()) {
                palette.border
            } else {
                palette.input
            };
            let border = if enabled && (response.hovered() || open || response.has_focus()) {
                palette.text_dim
            } else {
                palette.border_strong
            };
            ui.painter().rect(
                rect,
                egui::CornerRadius::same(theme::RADIUS),
                fill,
                egui::Stroke::new(theme::stroke::HAIRLINE, border),
                egui::StrokeKind::Inside,
            );
            let icon_color = if !enabled {
                palette.border_strong
            } else if let Some(color) = active_color {
                color
            } else if response.hovered() || open {
                palette.text
            } else {
                palette.text_muted
            };
            icons::paint(ui.painter(), rect.center(), Icon::Filter, icon_color);
            if let Some(color) = active_color {
                let dot = if enabled {
                    color
                } else {
                    palette.border_strong
                };
                ui.painter().circle_filled(
                    egui::pos2(
                        rect.right() - theme::space::XS - ACTIVE_DOT_RADIUS,
                        rect.top() + theme::space::XS + ACTIVE_DOT_RADIUS,
                    ),
                    ACTIVE_DOT_RADIUS,
                    dot,
                );
            }
        }
        response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::ComboBox, enabled, &hover));
        if enabled {
            let max_height = ui.spacing().combo_height;
            popup.show(|ui| {
                egui::ScrollArea::vertical()
                    .max_height(max_height)
                    .show(ui, |ui| {
                        ui.with_layout(egui::Layout::top_down_justified(egui::Align::LEFT), |ui| {
                            ui.set_min_width(popup_width);
                            let visuals = ui.visuals_mut();
                            visuals.override_text_color = None;
                            visuals.widgets.inactive.fg_stroke.color = palette.text;
                            visuals.widgets.hovered.fg_stroke.color = palette.text;
                            visuals.widgets.active.fg_stroke.color = palette.on_accent;
                            visuals.selection.bg_fill = palette.accent_base;
                            visuals.selection.stroke =
                                egui::Stroke::new(theme::stroke::HAIRLINE, palette.on_accent);
                            menu(ui);
                        });
                    });
            });
        } else {
            drop(popup);
        }
        let response = if enabled {
            response.on_hover_cursor(egui::CursorIcon::PointingHand)
        } else {
            response
        };
        response.on_hover_text(hover)
    })
    .inner
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

    #[test]
    fn the_first_choice_row_leaves_room_for_its_label_and_check() {
        use crate::widgets::{MenuItem, menu_item};

        let mut screen = screen();
        let mut row = egui::Rect::NOTHING;
        let mut field = egui::Rect::NOTHING;
        let shown = screen.click_text("Current", |ui| {
            field = drop_down(ui, "choice", Some(200.0), "Current", |ui| {
                row = menu_item(
                    ui,
                    MenuItem {
                        label: "Selected choice",
                        enabled: true,
                        selected: true,
                        danger: false,
                        note: None,
                    },
                )
                .rect;
            })
            .rect;
        });
        let label = shown
            .iter()
            .find(|(label, _)| label == "Selected choice")
            .unwrap()
            .1;
        assert!(row.left() >= field.left());
        assert!(row.right() <= field.right());
        assert!(row.right() > label.right() + 24.0);
    }

    #[test]
    fn a_drop_down_popup_keeps_its_field_width_in_a_wide_parent() {
        for width in [180.0, 400.0] {
            let mut screen = TestScreen::new(egui::vec2(1200.0, 800.0));
            let mut item_widths = Vec::new();
            screen.click_text("English", |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    ui.with_layout(egui::Layout::top_down_justified(egui::Align::Min), |ui| {
                        drop_down(ui, "language", Some(width), "English", |ui| {
                            for label in ["English", "Русский"] {
                                item_widths.push(ui.selectable_label(false, label).rect.width());
                            }
                        });
                    });
                });
            });
            assert!(!item_widths.is_empty());
            assert!(
                item_widths.iter().all(|item| *item <= width + 12.0),
                "{item_widths:?}"
            );
        }
    }

    #[test]
    fn a_compact_filter_combo_is_square_and_opens_a_full_width_choice_menu() {
        let mut screen = screen();
        let mut picked = String::from("Any route");
        let mut button_rect = egui::Rect::NOTHING;
        let mut height = 0.0;
        let mut item_width = 0.0;
        let show = |picked: &mut String,
                    button_rect: &mut egui::Rect,
                    height: &mut f32,
                    item_width: &mut f32,
                    ui: &mut egui::Ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                *height = field_height(ui);
                let active = (picked != "Any route").then_some(theme::palette().accent_light);
                *button_rect = filter_combo_icon(
                    ui,
                    "compact_filter",
                    SEARCH_WIDTH_FOR_TEST,
                    active,
                    picked.clone(),
                    |ui| {
                        for name in ["Any route", "Through VPN", "Direct"] {
                            let item = ui.selectable_label(picked == name, name);
                            *item_width = (*item_width).max(item.rect.width());
                            if item.clicked() {
                                *picked = name.to_owned();
                            }
                        }
                    },
                )
                .rect;
            });
        };
        let (texts, circles) = screen.settle_with_circles(|ui| {
            show(
                &mut picked,
                &mut button_rect,
                &mut height,
                &mut item_width,
                ui,
            );
        });
        assert!(
            texts.is_empty(),
            "compact button should paint no text: {texts:?}"
        );
        assert!(
            circles.is_empty(),
            "inactive filter should paint no active dot: {circles:?}"
        );
        assert_eq!(button_rect.size(), egui::vec2(height, height));

        let pos = button_rect.center();
        let button = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        screen.run(vec![egui::Event::PointerMoved(pos), button(true)], |ui| {
            show(
                &mut picked,
                &mut button_rect,
                &mut height,
                &mut item_width,
                ui,
            );
        });
        screen.run(vec![button(false)], |ui| {
            show(
                &mut picked,
                &mut button_rect,
                &mut height,
                &mut item_width,
                ui,
            );
        });
        let open = screen.settle(|ui| {
            show(
                &mut picked,
                &mut button_rect,
                &mut height,
                &mut item_width,
                ui,
            );
        });
        assert!(
            open.iter().any(|(text, _)| text == "Through VPN"),
            "{open:?}"
        );
        assert!(
            item_width >= SEARCH_WIDTH_FOR_TEST,
            "popup item width {item_width} < {SEARCH_WIDTH_FOR_TEST}"
        );

        screen.click_text("Through VPN", |ui| {
            show(
                &mut picked,
                &mut button_rect,
                &mut height,
                &mut item_width,
                ui,
            );
        });
        assert_eq!(picked, "Through VPN");
        let (after_texts, after_circles) = screen.settle_with_circles(|ui| {
            show(
                &mut picked,
                &mut button_rect,
                &mut height,
                &mut item_width,
                ui,
            );
        });
        assert!(
            after_texts.is_empty(),
            "popup should close after selecting an item: {after_texts:?}"
        );
        assert!(
            !after_circles.is_empty(),
            "active filter should paint its corner indicator dot"
        );
    }
}
