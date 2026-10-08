use eframe::egui;

use crate::icons::{self, Icon};
use crate::theme;

const ITEM_RADIUS_PX: f32 = 4.0;

pub(crate) struct MenuItem<'a> {
    pub label: &'a str,
    pub enabled: bool,
    pub selected: bool,
    pub danger: bool,
    /// A short note drawn right-aligned in the item, such as "Active".
    pub note: Option<&'a str>,
}

pub(crate) fn menu_item(ui: &mut egui::Ui, item: MenuItem<'_>) -> egui::Response {
    let enabled = item.enabled && ui.is_enabled();
    let sense = if enabled {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    // Popup max rects span the viewport; the caller's minimum width is the menu width.
    let (rect, response) = ui.allocate_exact_size(egui::vec2(ui.min_rect().width(), 30.0), sense);
    if ui.is_rect_visible(rect) {
        let radius = item_radius(ui.ctx().pixels_per_point());
        let selected_fill = theme::ROSE_DARK.gamma_multiply(0.35);
        if enabled && item.danger && response.hovered() {
            ui.painter()
                .rect_filled(rect, radius, theme::ERROR.gamma_multiply(0.15));
        } else if item.selected {
            ui.painter().rect_filled(rect, radius, selected_fill);
        } else if enabled && response.hovered() {
            ui.painter().rect_filled(rect, radius, theme::BORDER);
        }
        let color = if !enabled {
            theme::DISABLED
        } else if item.danger {
            theme::ERROR
        } else {
            ui.visuals().override_text_color.unwrap_or(theme::TEXT)
        };
        let mut right = rect.right() - 10.0;
        if item.selected {
            icons::paint(
                ui.painter(),
                egui::pos2(right - 5.0, rect.center().y),
                Icon::Check,
                if enabled {
                    theme::TEXT
                } else {
                    theme::DISABLED
                },
            );
            right -= 24.0;
        }
        if let Some(note) = item.note {
            let font = egui::TextStyle::Small.resolve(ui.style());
            let width = ui
                .painter()
                .layout_no_wrap(note.to_owned(), font.clone(), theme::ROSE_LIGHT)
                .size()
                .x;
            ui.painter().text(
                egui::pos2(right, rect.center().y),
                egui::Align2::RIGHT_CENTER,
                note,
                font,
                if enabled {
                    theme::ROSE_LIGHT
                } else {
                    theme::DISABLED
                },
            );
            right -= width + 10.0;
        }
        let left = rect.left() + ui.spacing().button_padding.x.max(10.0);
        let galley = egui::WidgetText::from(egui::RichText::new(item.label).color(color))
            .into_galley(
                ui,
                Some(egui::TextWrapMode::Truncate),
                (right - left).max(0.0),
                egui::TextStyle::Button,
            );
        ui.painter().galley(
            egui::pos2(left, rect.center().y - galley.size().y / 2.0),
            galley,
            color,
        );
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            enabled,
            item.selected,
            item.label,
        )
    });
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

fn item_radius(pixels_per_point: f32) -> egui::CornerRadius {
    let points = (ITEM_RADIUS_PX / pixels_per_point).round().clamp(1.0, 4.0) as u8;
    egui::CornerRadius::same(points)
}

pub(crate) fn menu_popup(response: &egui::Response) -> egui::Popup<'_> {
    style_popup(egui::Popup::menu(response), response)
}

pub(crate) fn context_menu_popup(response: &egui::Response) -> egui::Popup<'_> {
    style_popup(egui::Popup::context_menu(response), response)
}

fn style_popup<'a>(popup: egui::Popup<'a>, response: &egui::Response) -> egui::Popup<'a> {
    let radius = item_radius(response.ctx.pixels_per_point());
    popup.style(move |style: &mut egui::Style| {
        egui::containers::menu::menu_style(style);
        style.spacing.button_padding = egui::vec2(10.0, 4.0);
        style.spacing.menu_margin = egui::Margin::same(4);
        let widgets = &mut style.visuals.widgets;
        widgets.inactive.corner_radius = radius;
        widgets.hovered.corner_radius = radius;
        widgets.active.corner_radius = radius;
        widgets.open.corner_radius = radius;
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_item_radius_tracks_physical_pixels() {
        assert_eq!(item_radius(1.0), egui::CornerRadius::same(4));
        assert_eq!(item_radius(1.25), egui::CornerRadius::same(3));
        assert_eq!(item_radius(1.5), egui::CornerRadius::same(3));
        assert_eq!(item_radius(2.0), egui::CornerRadius::same(2));
    }

    #[test]
    fn menu_popup_applies_compact_rectangular_item_style() {
        for width in [150.0, 180.0, 240.0] {
            let ctx = egui::Context::default();
            crate::theme::apply(&ctx);
            let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let trigger = ui.button("Menu");
                    let popup = menu_popup(&trigger)
                        .open(true)
                        .show(|ui| {
                            ui.set_min_width(width);
                            assert_eq!(ui.spacing().button_padding, egui::vec2(10.0, 4.0));
                            assert_eq!(ui.spacing().menu_margin, egui::Margin::same(4));
                            assert_eq!(
                                ui.visuals().widgets.hovered.corner_radius,
                                egui::CornerRadius::same(4)
                            );
                            let item = menu_item(
                                ui,
                                MenuItem {
                                    label: "Delete",
                                    enabled: true,
                                    selected: false,
                                    danger: true,
                                    note: None,
                                },
                            );
                            assert_eq!(item.rect.height(), 30.0);
                            assert_eq!(item.rect.width(), width);
                            assert!(ui.available_width() > item.rect.width());
                            let scoped_width = ui
                                .scope(|ui| {
                                    ui.set_min_width(width);
                                    ui.spacing_mut().button_padding.x = 26.0;
                                    menu_item(
                                        ui,
                                        MenuItem {
                                            label: "Direct",
                                            enabled: true,
                                            selected: true,
                                            danger: false,
                                            note: Some("Active"),
                                        },
                                    )
                                    .rect
                                    .width()
                                })
                                .inner;
                            assert_eq!(scoped_width, width);
                        })
                        .unwrap();
                    assert!(
                        popup.response.rect.width() <= width + 12.0,
                        "popup width {} for item width {width}",
                        popup.response.rect.width(),
                    );
                });
            });
            output.textures_delta.clear();
        }
    }

    #[test]
    fn context_menu_uses_the_same_item_style() {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let row = ui.button("Server");
                context_menu_popup(&row).open(true).show(|ui| {
                    ui.set_min_width(200.0);
                    assert_eq!(ui.spacing().button_padding, egui::vec2(10.0, 4.0));
                    assert_eq!(ui.spacing().menu_margin, egui::Margin::same(4));
                    assert_eq!(
                        ui.visuals().widgets.hovered.corner_radius,
                        egui::CornerRadius::same(4)
                    );
                    let item = menu_item(
                        ui,
                        MenuItem {
                            label: "Quick check",
                            enabled: true,
                            selected: false,
                            danger: false,
                            note: Some("TCP"),
                        },
                    );
                    assert_eq!(item.rect.height(), 30.0);
                    assert_eq!(item.rect.width(), 200.0);
                });
            });
        });
        output.textures_delta.clear();
    }

    #[test]
    fn popup_wraps_long_subscription_urls_to_its_width() {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let trigger = ui.button("Menu");
                menu_popup(&trigger).open(true).show(|ui| {
                    ui.set_width(180.0);
                    ui.add(
                        egui::Label::new("https://subscriptions.example.com/a/long/redacted/path")
                            .wrap(),
                    );
                    let item = menu_item(
                        ui,
                        MenuItem {
                            label: "Rename",
                            enabled: true,
                            selected: false,
                            danger: false,
                            note: None,
                        },
                    );
                    assert_eq!(item.rect.width(), 180.0);
                });
            });
        });
        output.textures_delta.clear();
    }
}
