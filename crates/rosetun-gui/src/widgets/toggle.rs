use eframe::egui::{self, Color32, CornerRadius, Stroke};

use crate::theme::{BORDER_STRONG, INPUT, RADIUS_TOGGLE, ROSE, TEXT, TEXT_DIM, TEXT_MUTED};

pub(crate) const TOGGLE_SIZE: egui::Vec2 = egui::vec2(38.0, 22.0);

/// An on/off switch in the brand colours. Returns a response that is
/// `changed()` when the user flips it.
pub(crate) fn toggle(ui: &mut egui::Ui, on: &mut bool, enabled: bool) -> egui::Response {
    let enabled = enabled && ui.is_enabled();
    let (rect, mut response) = ui.allocate_exact_size(
        TOGGLE_SIZE,
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    let next = toggled_value(*on, response.clicked(), enabled);
    if next != *on {
        *on = next;
        response.mark_changed();
    }
    response
        .widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Checkbox, enabled, *on, ""));
    let progress = ui.ctx().animate_bool_with_time(response.id, *on, 0.1);
    paint_toggle(ui, rect, *on, progress, enabled);
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

fn paint_toggle(ui: &egui::Ui, rect: egui::Rect, on: bool, progress: f32, enabled: bool) {
    if !ui.is_rect_visible(rect) {
        return;
    }
    let faded = |color: Color32| {
        if enabled {
            color
        } else {
            Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 128)
        }
    };
    ui.painter().rect(
        rect,
        CornerRadius::same(RADIUS_TOGGLE),
        faded(if on { ROSE } else { INPUT }),
        if on {
            Stroke::NONE
        } else {
            Stroke::new(1.0, faded(BORDER_STRONG))
        },
        egui::StrokeKind::Inside,
    );
    ui.painter().circle_filled(
        egui::pos2(rect.left() + 11.0 + 16.0 * progress, rect.center().y),
        8.0,
        faded(if on { TEXT } else { TEXT_MUTED }),
    );
}

/// A title, a muted detail below it and a toggle on the right. The whole row
/// flips the toggle, not only the switch.
pub(crate) fn toggle_row(
    ui: &mut egui::Ui,
    title: &str,
    detail: &str,
    on: &mut bool,
    enabled: bool,
) -> egui::Response {
    let enabled = enabled && ui.is_enabled();
    let id = ui.next_auto_id();
    let row = ui.horizontal(|ui| {
        let text_width = ui.available_width() - TOGGLE_SIZE.x - ui.spacing().item_spacing.x;
        ui.vertical(|ui| {
            ui.set_max_width(text_width);
            ui.label(title);
            ui.add(egui::Label::new(egui::RichText::new(detail).small().color(TEXT_DIM)).wrap());
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.allocate_space(TOGGLE_SIZE).1
        })
        .inner
    });
    let mut response = ui.interact(
        row.response.rect,
        id,
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    let next = toggled_value(*on, response.clicked(), enabled);
    if next != *on {
        *on = next;
        response.mark_changed();
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, enabled, *on, title)
    });
    let progress = ui.ctx().animate_bool_with_time(response.id, *on, 0.1);
    paint_toggle(ui, row.inner, *on, progress, enabled);
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

fn toggled_value(on: bool, clicked: bool, enabled: bool) -> bool {
    if clicked && enabled { !on } else { on }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_flips_only_when_enabled_and_clicked() {
        assert!(toggled_value(false, true, true));
        assert!(!toggled_value(true, true, true));
        assert!(toggled_value(true, true, false));
        assert!(!toggled_value(false, true, false));
        assert!(toggled_value(true, false, true));
        assert!(!toggled_value(false, false, true));
    }
}
