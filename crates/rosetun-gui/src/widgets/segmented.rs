use eframe::egui::{self, Color32, CornerRadius, Stroke, TextStyle};

use crate::theme::{BG, BORDER, RADIUS, RADIUS_INNER, ROSE, TEXT, TEXT_MUTED};

/// Natural widths are the text plus 14 on each side. With `fill`, every
/// segment gets an equal share of the inner width, but never less than the
/// widest text needs.
fn segment_widths(natural: &[f32], fill: Option<f32>, gap: f32) -> Vec<f32> {
    let Some(inner) = fill else {
        return natural.to_vec();
    };
    if natural.is_empty() {
        return Vec::new();
    }
    let share = (inner - gap * natural.len().saturating_sub(1) as f32) / natural.len() as f32;
    let width = share.max(natural.iter().copied().fold(0.0, f32::max));
    vec![width; natural.len()]
}

/// Options side by side on one track. Returns the option the user clicked
/// when it differs from `selected`.
pub(crate) fn segmented<T: Copy + PartialEq, L: AsRef<str>>(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    selected: T,
    options: &[(T, L)],
    fill_width: bool,
    enabled: bool,
) -> Option<T> {
    if options.is_empty() {
        return None;
    }
    let enabled = enabled && ui.is_enabled();
    let font = TextStyle::Button.resolve(ui.style());
    let natural: Vec<_> = options
        .iter()
        .map(|(_, label)| {
            ui.painter()
                .layout_no_wrap(label.as_ref().to_owned(), font.clone(), TEXT)
                .size()
                .x
                + 28.0
        })
        .collect();
    let widths = segment_widths(
        &natural,
        fill_width.then(|| ui.available_width() - 8.0),
        2.0,
    );
    let width = widths.iter().sum::<f32>() + 2.0 * (options.len() - 1) as f32 + 8.0;
    let (track, _) = ui.allocate_exact_size(egui::vec2(width, 38.0), egui::Sense::hover());
    let faded = |color: Color32| {
        if enabled {
            color
        } else {
            Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 128)
        }
    };
    ui.painter().rect(
        track,
        CornerRadius::same(RADIUS),
        faded(BG),
        Stroke::new(1.0, faded(BORDER)),
        egui::StrokeKind::Inside,
    );
    let mut x = track.left() + 4.0;
    let id = ui.make_persistent_id(id_salt);
    let mut clicked = None;
    for (index, ((value, label), width)) in options.iter().zip(widths).enumerate() {
        let rect =
            egui::Rect::from_min_size(egui::pos2(x, track.top() + 4.0), egui::vec2(width, 30.0));
        let response = ui.interact(
            rect,
            id.with(index),
            if enabled {
                egui::Sense::click()
            } else {
                egui::Sense::hover()
            },
        );
        let active = *value == selected;
        response.widget_info(|| {
            egui::WidgetInfo::selected(
                egui::WidgetType::SelectableLabel,
                enabled,
                active,
                label.as_ref(),
            )
        });
        if enabled && response.clicked() && !active {
            clicked = Some(*value);
        }
        let hovered = enabled && response.hovered();
        if active || hovered {
            ui.painter().rect_filled(
                rect,
                CornerRadius::same(RADIUS_INNER),
                faded(if active { ROSE } else { BORDER }),
            );
        }
        if response.has_focus() {
            ui.painter().rect_stroke(
                rect,
                CornerRadius::same(RADIUS_INNER),
                Stroke::new(1.0, faded(TEXT)),
                egui::StrokeKind::Inside,
            );
        }
        let color = faded(if active || hovered { TEXT } else { TEXT_MUTED });
        let galley = ui
            .painter()
            .layout_no_wrap(label.as_ref().to_owned(), font.clone(), color);
        ui.painter()
            .galley(rect.center() - galley.size() / 2.0, galley, color);
        if enabled {
            response.on_hover_cursor(egui::CursorIcon::PointingHand);
        }
        x += width + 2.0;
    }
    clicked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn natural_widths_are_preserved_without_fill() {
        assert_eq!(
            segment_widths(&[40.0, 60.0, 50.0], None, 2.0),
            [40.0, 60.0, 50.0]
        );
    }

    #[test]
    fn fill_distributes_width_equally() {
        let share = (300.0 - 4.0) / 3.0;
        assert_eq!(
            segment_widths(&[40.0, 60.0, 50.0], Some(300.0), 2.0),
            [share; 3]
        );
    }

    #[test]
    fn fill_never_shrinks_below_the_widest_label() {
        assert_eq!(
            segment_widths(&[200.0, 60.0], Some(300.0), 2.0),
            [200.0, 200.0]
        );
    }
}
