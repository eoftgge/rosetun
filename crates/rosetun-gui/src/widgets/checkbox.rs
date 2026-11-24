use eframe::egui::{self, Color32, CornerRadius, Stroke};

use crate::{motion, theme};

/// A check box in the brand colours, with an optional label to its right.
///
/// Drawn here rather than through `egui::Checkbox`, whose box follows the
/// spacing's icon width and whose tick is a thin glyph: the box is
/// `theme::CHECKBOX_SIDE` with a `GLYPH` border, the tick a `MARK` stroke, and
/// checking fades in over `motion::FAST`. The box and the label are one
/// target, centred on one line; a caller that sets `interact_size` (a list
/// row) gets that height with the box centred in it.
pub(crate) fn checkbox(
    ui: &mut egui::Ui,
    checked: &mut bool,
    label: impl Into<egui::WidgetText>,
    enabled: bool,
) -> egui::Response {
    let enabled = enabled && ui.is_enabled();
    let label: egui::WidgetText = label.into();
    let text = label.text().to_owned();
    let galley = (!text.is_empty()).then(|| {
        label.into_galley(
            ui,
            Some(egui::TextWrapMode::Extend),
            f32::INFINITY,
            egui::TextStyle::Body,
        )
    });
    let side = theme::CHECKBOX_SIDE;
    let width = side
        + galley
            .as_ref()
            .map_or(0.0, |galley| theme::space::S + galley.size().x);
    let height = side
        .max(galley.as_ref().map_or(0.0, |galley| galley.size().y))
        .max(ui.spacing().interact_size.y);
    let (rect, mut response) = ui.allocate_exact_size(
        egui::vec2(width, height),
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    if enabled && response.clicked() {
        *checked = !*checked;
        response.mark_changed();
    }
    response
        .widget_info(|| egui::WidgetInfo::selected(egui::Role::CheckBox, enabled, *checked, &text));
    let progress = ui.ctx().animate_bool_with_time(
        response.id,
        *checked,
        motion::duration(motion::FAST, motion::reduced()),
    );
    if ui.is_rect_visible(rect) {
        let box_rect = egui::Rect::from_center_size(
            egui::pos2(rect.left() + side / 2.0, rect.center().y),
            egui::Vec2::splat(side),
        );
        paint_box(
            ui,
            box_rect,
            motion::ease_out(progress),
            enabled,
            enabled && (response.hovered() || response.has_focus()),
        );
        if let Some(galley) = galley {
            let color = if enabled {
                theme::palette().text
            } else {
                theme::disabled()
            };
            let position = egui::pos2(
                box_rect.right() + theme::space::S,
                rect.center().y - galley.size().y / 2.0,
            );
            ui.painter().galley(position, galley, color);
        }
    }
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// The box: an input-coloured square with a border, the accent fill and a
/// white tick fading in as `progress` goes from 0 to 1.
fn paint_box(ui: &egui::Ui, rect: egui::Rect, progress: f32, enabled: bool, lit: bool) {
    let faded = |color: Color32| {
        if enabled {
            color
        } else {
            theme::alpha::fade(color, theme::alpha::DISABLED_ALPHA)
        }
    };
    let corner = CornerRadius::same(theme::RADIUS_CHECKBOX);
    let border = if lit {
        theme::palette().text_dim
    } else {
        theme::palette().border_strong
    };
    ui.painter().rect(
        rect,
        corner,
        faded(theme::palette().input),
        Stroke::new(theme::stroke::GLYPH, faded(border)),
        egui::StrokeKind::Inside,
    );
    if progress <= 0.0 {
        return;
    }
    let fill = if lit {
        theme::palette().accent_bright
    } else {
        theme::palette().accent_base
    };
    ui.painter()
        .rect_filled(rect, corner, faded(fill).gamma_multiply(progress));
    let palette = theme::palette();
    let tick = if palette.on_accent == palette.text {
        Color32::WHITE
    } else {
        palette.on_accent
    };
    let at = |x: f32, y: f32| rect.min + egui::vec2(rect.width() * x, rect.height() * y);
    ui.painter().add(egui::Shape::line(
        vec![at(0.26, 0.52), at(0.43, 0.68), at(0.75, 0.34)],
        Stroke::new(theme::stroke::MARK, faded(tick).gamma_multiply(progress)),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_ui::TestScreen;

    #[test]
    fn a_click_on_the_label_ticks_and_unticks_the_box() {
        let mut checked = false;
        let mut screen = TestScreen::new(egui::vec2(400.0, 200.0));
        let mut changes = 0;
        let mut show = |ui: &mut egui::Ui| {
            if checkbox(ui, &mut checked, "Temporary", true).changed() {
                changes += 1;
            }
        };
        screen.click_text("Temporary", &mut show);
        screen.click_text("Temporary", &mut show);
        drop(show);
        assert_eq!(changes, 2);
        assert!(!checked);
    }

    #[test]
    fn a_disabled_box_does_not_change() {
        let mut checked = true;
        let mut screen = TestScreen::new(egui::vec2(400.0, 200.0));
        screen.click_text("Temporary", |ui| {
            assert!(!checkbox(ui, &mut checked, "Temporary", false).changed());
        });
        assert!(checked);
    }

    #[test]
    fn the_label_is_centred_on_the_box() {
        let mut screen = TestScreen::new(egui::vec2(400.0, 200.0));
        let mut response = None;
        let texts = screen.settle(|ui| {
            response = Some(checkbox(ui, &mut false, "Temporary", true));
        });
        let response = response.unwrap();
        let (_, label) = texts.iter().find(|(text, _)| text == "Temporary").unwrap();
        assert!((label.center().y - response.rect.center().y).abs() <= 1.0);
        assert!(label.left() >= response.rect.left() + theme::CHECKBOX_SIDE);
    }
}
