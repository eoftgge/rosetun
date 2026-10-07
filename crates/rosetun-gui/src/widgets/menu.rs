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
    let (rect, response) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 30.0), sense);
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
    let radius = item_radius(response.ctx.pixels_per_point());
    egui::Popup::menu(response).style(move |style: &mut egui::Style| {
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
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let trigger = ui.button("Menu");
                menu_popup(&trigger).open(true).show(|ui| {
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
                    assert_eq!(item.rect.width(), ui.available_width());
                });
            });
        });
        output.textures_delta.clear();
    }
}
