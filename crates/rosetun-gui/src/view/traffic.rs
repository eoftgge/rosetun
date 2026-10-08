use std::collections::VecDeque;

use eframe::egui::{self, Color32, RichText};
use rosetun_config::ConnectionState;

use crate::state::State;
use crate::strings::t;
use crate::{theme, widgets};

pub(crate) fn show(ui: &mut egui::Ui, state: &State) {
    let traffic = state.visible_status().and_then(|status| {
        matches!(
            status.state,
            ConnectionState::Connected | ConnectionState::Reconnecting
        )
        .then_some(&status.traffic)
    });
    let (down, up, total) = traffic.map_or((0, 0, 0), |traffic| {
        (
            traffic.down_bps,
            traffic.up_bps,
            traffic.down_total.saturating_add(traffic.up_total),
        )
    });
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(180.0, 96.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.set_width(180.0);
                    traffic_row(
                        ui,
                        theme::ROSE_LIGHT,
                        t().traffic_down,
                        &t().rate(down),
                        traffic.is_some(),
                    );
                    traffic_row(
                        ui,
                        theme::ROSE_DARK,
                        t().traffic_up,
                        &t().rate(up),
                        traffic.is_some(),
                    );
                    ui.add_space(4.0);
                    let (line, _) =
                        ui.allocate_exact_size(egui::vec2(180.0, 1.0), egui::Sense::hover());
                    ui.painter().hline(
                        line.x_range(),
                        line.center().y,
                        egui::Stroke::new(1.0, theme::BORDER),
                    );
                    ui.add_space(4.0);
                    egui::Sides::new().shrink_left().show(
                        ui,
                        |ui| {
                            ui.label(
                                RichText::new(t().traffic_session)
                                    .small()
                                    .color(theme::TEXT_DIM),
                            );
                        },
                        |ui| {
                            ui.label(RichText::new(t().bytes(total)).strong().color(
                                if traffic.is_some() {
                                    theme::TEXT
                                } else {
                                    theme::TEXT_DIM
                                },
                            ));
                        },
                    );
                },
            );
            traffic_chart(ui, &state.traffic_history);
        });
    });
}

fn traffic_row(ui: &mut egui::Ui, color: Color32, label: &str, value: &str, connected: bool) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, 0.0, color);
        ui.label(RichText::new(label).small().color(theme::TEXT_DIM));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new(value).strong().color(if connected {
                theme::TEXT
            } else {
                theme::TEXT_DIM
            }));
        });
    });
}

fn chart_scale(history: &VecDeque<(u64, u64)>) -> u64 {
    history
        .iter()
        .map(|&(down, up)| down.max(up))
        .max()
        .unwrap_or(1)
        .max(1)
}

/// Pixel heights above and below the baseline.
fn bar_heights(down: u64, up: u64, scale: u64) -> (f32, f32) {
    let scale = scale.max(1) as f64;
    let height = |value: u64, maximum: f64| {
        if value == 0 {
            0.0
        } else {
            (maximum * value as f64 / scale).clamp(1.0, maximum) as f32
        }
    };
    (height(down, 58.0), height(up, 37.0))
}

fn traffic_chart(ui: &mut egui::Ui, history: &VecDeque<(u64, u64)>) {
    let width = ui.available_width().max(0.0);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 96.0), egui::Sense::hover());
    let baseline = rect.top() + 58.0;
    ui.painter().hline(
        rect.x_range(),
        baseline,
        egui::Stroke::new(1.0, theme::BORDER),
    );
    if history.is_empty() {
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            t().traffic_empty,
            egui::TextStyle::Small.resolve(ui.style()),
            theme::TEXT_DIM,
        );
        return;
    }
    let scale = chart_scale(history);
    let bar_width = ((width - 2.0 * 59.0) / 60.0).max(0.0);
    for (index, &(down, up)) in history.iter().enumerate() {
        let x = rect.right() - bar_width - (history.len() - 1 - index) as f32 * (bar_width + 2.0);
        let (down_height, up_height) = bar_heights(down, up, scale);
        if bar_width > 0.0 && down_height > 0.0 {
            ui.painter().rect_filled(
                egui::Rect::from_min_size(
                    egui::pos2(x, baseline - down_height),
                    egui::vec2(bar_width, down_height),
                ),
                0.0,
                theme::ROSE_LIGHT,
            );
        }
        if bar_width > 0.0 && up_height > 0.0 {
            ui.painter().rect_filled(
                egui::Rect::from_min_size(
                    egui::pos2(x, baseline + 1.0),
                    egui::vec2(bar_width, up_height),
                ),
                0.0,
                theme::ROSE_DARK,
            );
        }
    }
    ui.painter().text(
        rect.right_top(),
        egui::Align2::RIGHT_TOP,
        t().traffic_peak(&t().rate(scale)),
        egui::TextStyle::Small.resolve(ui.style()),
        theme::TEXT_DIM,
    );
    if let Some(pos) = response.hover_pos()
        && bar_width > 0.0
    {
        let slot = ((rect.right() - pos.x) / (bar_width + 2.0)).floor() as usize;
        if slot < history.len() {
            let (down, up) = history[history.len() - 1 - slot];
            response.on_hover_text(format!(
                "{}: {}\n{}: {}",
                t().traffic_down,
                t().rate(down),
                t().traffic_up,
                t().rate(up),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::{bar_heights, chart_scale};

    #[test]
    fn chart_scale_uses_largest_rate_or_one() {
        assert_eq!(chart_scale(&VecDeque::new()), 1);
        assert_eq!(chart_scale(&VecDeque::from([(12, 5), (3, 20)])), 20);
        assert_eq!(chart_scale(&VecDeque::from([(0, 0)])), 1);
    }

    #[test]
    fn bar_heights_scale_both_sides_and_keep_tiny_samples_visible() {
        assert_eq!(bar_heights(100, 0, 100), (58.0, 0.0));
        assert_eq!(bar_heights(0, 100, 100), (0.0, 37.0));
        assert_eq!(bar_heights(1, 1, 10_000), (1.0, 1.0));
        assert_eq!(bar_heights(0, 0, 1), (0.0, 0.0));
    }
}
