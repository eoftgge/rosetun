use std::collections::VecDeque;

use eframe::egui::{self, Color32, RichText};
use rosetun_config::{ConnectionRoute, ConnectionState, LiveConnection};

use crate::state::{Action, ConnectionsNotice, ConnectionsTab, State, TrafficRange};
use crate::{theme, widgets};

pub(crate) fn show(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let traffic = state.visible_status().and_then(|status| {
        matches!(
            status.state,
            ConnectionState::Connected | ConnectionState::Reconnecting
        )
        .then_some(&status.traffic)
    });
    let (down, up, down_total, up_total) = traffic.map_or((0, 0, 0, 0), |traffic| {
        (
            traffic.down_bps,
            traffic.up_bps,
            traffic.down_total,
            traffic.up_total,
        )
    });
    let columns = chart_columns(&state.traffic.traffic_history, state.traffic.traffic_range);
    let peak = chart_peak(&columns);
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        let narrow = ui.available_width() < 620.0;
        ui.with_layout(
            if narrow {
                egui::Layout::top_down(egui::Align::Min)
            } else {
                egui::Layout::left_to_right(egui::Align::Min)
            },
            |ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(232.0, 178.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_width(232.0);
                        traffic_row(
                            ui,
                            theme::ROSE_LIGHT,
                            &tr!("traffic-down"),
                            down,
                            traffic.is_some(),
                        );
                        ui.add_space(10.0);
                        traffic_row(
                            ui,
                            theme::ROSE_DARK,
                            &tr!("traffic-up"),
                            up,
                            traffic.is_some(),
                        );
                        ui.add_space(14.0);
                        let (line, _) =
                            ui.allocate_exact_size(egui::vec2(232.0, 1.0), egui::Sense::hover());
                        ui.painter().hline(
                            line.x_range(),
                            line.center().y,
                            egui::Stroke::new(1.0, theme::BORDER),
                        );
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(tr!("traffic-session"))
                                    .small()
                                    .color(theme::TEXT_DIM),
                            );
                            let totals = crate::i18n::traffic_rates(
                                &crate::i18n::bytes(down_total),
                                &crate::i18n::bytes(up_total),
                            );
                            ui.add(
                                egui::Label::new(RichText::new(&totals).small().color(
                                    if traffic.is_some() {
                                        theme::TEXT
                                    } else {
                                        theme::TEXT_DIM
                                    },
                                ))
                                .truncate(),
                            )
                            .on_hover_text(totals);
                        });
                    },
                );
                ui.add_space(if narrow { 12.0 } else { 24.0 });
                ui.vertical(|ui| {
                    ui.set_min_width(ui.available_width());
                    egui::Sides::new().shrink_left().wrap().show(
                        ui,
                        |ui| {
                            let range = match state.traffic.traffic_range {
                                TrafficRange::OneMinute => tr!("traffic-range-1m"),
                                TrafficRange::FiveMinutes => tr!("traffic-range-5m"),
                                TrafficRange::FifteenMinutes => tr!("traffic-range-15m"),
                            };
                            ui.label(
                                RichText::new(crate::i18n::traffic_chart_caption(
                                    &range,
                                    &crate::i18n::rate(peak),
                                ))
                                .small()
                                .color(theme::TEXT_DIM),
                            );
                        },
                        |ui| {
                            if let Some(range) = widgets::segmented(
                                ui,
                                "traffic_range",
                                state.traffic.traffic_range,
                                &[
                                    (TrafficRange::OneMinute, tr!("traffic-range-1m")),
                                    (TrafficRange::FiveMinutes, tr!("traffic-range-5m")),
                                    (TrafficRange::FifteenMinutes, tr!("traffic-range-15m")),
                                ],
                                false,
                                true,
                            ) {
                                actions.push(Action::SetTrafficRange(range));
                            }
                        },
                    );
                    ui.add_space(12.0);
                    traffic_chart(ui, &columns);
                });
            },
        );
    });
    ui.add_space(16.0);
    connections_card(ui, state, actions);
}

const CONNECTION_ROW_HEIGHT: f32 = 26.0;

fn connections_card(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let list = &state.traffic.connections;
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        egui::Sides::new().shrink_left().wrap().show(
            ui,
            |ui| {
                ui.label(RichText::new(tr!("connections-title")).strong());
            },
            |ui| {
                let options = [
                    (
                        ConnectionsTab::Active,
                        tr!("connections-active", n = list.active.len().to_string()),
                    ),
                    (
                        ConnectionsTab::Closed,
                        tr!("connections-closed", n = list.closed.len().to_string()),
                    ),
                ];
                if let Some(tab) = widgets::segmented(
                    ui,
                    "connections_tab",
                    list.tab,
                    &options,
                    false,
                    state.connections_available(),
                ) {
                    actions.push(Action::SetConnectionsTab(tab));
                }
            },
        );
        ui.add_space(10.0);
        let mut filter = list.filter.clone();
        widgets::search_field(
            ui,
            &mut filter,
            &tr!("connections-filter"),
            ui.available_width().min(360.0),
        );
        if filter != list.filter {
            actions.push(Action::SetConnectionsFilter(filter));
        }
        ui.add_space(10.0);

        let widths = column_widths(ui.available_width());
        connection_header(ui, &widths);
        let (line, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
        ui.painter().hline(
            line.x_range(),
            line.center().y,
            egui::Stroke::new(1.0, theme::BORDER),
        );
        if let Some(notice) = state.connections_notice() {
            let text = match notice {
                ConnectionsNotice::Disconnected => tr!("connections-disconnected"),
                ConnectionsNotice::Denied => tr!("connections-denied"),
                ConnectionsNotice::Loading => tr!("connections-loading"),
                ConnectionsNotice::Empty => match list.tab {
                    ConnectionsTab::Active => tr!("connections-empty"),
                    ConnectionsTab::Closed => tr!("connections-closed-empty"),
                },
                ConnectionsNotice::NoMatch => tr!("connections-no-match"),
            };
            ui.add_space(18.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(text).small().color(theme::TEXT_DIM));
            });
            ui.add_space(18.0);
        } else {
            let visible = list.visible();
            let now_ms = crate::display::now_unix().saturating_mul(1000);
            egui::ScrollArea::vertical()
                .id_salt("connections_rows")
                .max_height(360.0)
                .auto_shrink([false, true])
                .show_rows(ui, CONNECTION_ROW_HEIGHT, visible.len(), |ui, rows| {
                    for index in rows {
                        connection_row(ui, state, visible[index], &widths, now_ms);
                    }
                });
        }
        ui.add_space(10.0);
        ui.label(
            RichText::new(tr!("connections-note"))
                .small()
                .color(theme::TEXT_DIM),
        );
    });
}

/// Program, destination, route, down, up and time.
fn column_widths(available: f32) -> [f32; 6] {
    let spacing = 8.0 * 5.0;
    let fixed = [0.0, 0.0, 0.0, 76.0, 76.0, 64.0];
    let flexible = (available - spacing - fixed.iter().sum::<f32>()).max(120.0);
    [
        flexible * 0.32,
        flexible * 0.43,
        flexible * 0.25,
        fixed[3],
        fixed[4],
        fixed[5],
    ]
}

fn connection_header(ui: &mut egui::Ui, widths: &[f32; 6]) {
    let titles = [
        tr!("connections-program"),
        tr!("connections-destination"),
        tr!("connections-route"),
        crate::constants::DOWN_ARROW.to_owned(),
        crate::constants::UP_ARROW.to_owned(),
        tr!("connections-duration"),
    ];
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        for (title, width) in titles.into_iter().zip(widths) {
            cell(
                ui,
                *width,
                RichText::new(title).small().color(theme::TEXT_DIM),
                None,
            );
        }
    });
}

fn connection_row(
    ui: &mut egui::Ui,
    state: &State,
    connection: &LiveConnection,
    widths: &[f32; 6],
    now_ms: u64,
) {
    let program = crate::display::safe_text(
        &state
            .traffic
            .connections
            .programs
            .name(connection.process.as_deref()),
    );
    let path = connection.process.as_deref().map(crate::display::safe_text);
    let destination = crate::display::safe_text(&crate::i18n::connection_destination(
        &connection.host,
        connection.port,
    ));
    let route = state.connection_route_label(&connection.route);
    let route_hover = match &connection.route {
        ConnectionRoute::Exit(_) => Some(tr!("target-exit", name = route.clone())),
        _ => None,
    };
    let route_color = match connection.route {
        ConnectionRoute::Proxy => theme::ROSE_LIGHT,
        ConnectionRoute::Direct => theme::TEXT_MUTED,
        ConnectionRoute::Exit(_) => theme::EXIT,
        ConnectionRoute::Other => theme::TEXT_DIM,
    };
    let end = connection.end_unix_ms.unwrap_or(now_ms);
    let duration =
        crate::i18n::connection_duration(end.saturating_sub(connection.start_unix_ms) / 1000);
    ui.horizontal(|ui| {
        ui.set_height(CONNECTION_ROW_HEIGHT);
        ui.spacing_mut().item_spacing.x = 8.0;
        cell(
            ui,
            widths[0],
            RichText::new(&program).small().color(theme::TEXT),
            path.as_deref(),
        );
        cell(
            ui,
            widths[1],
            RichText::new(&destination).small().color(theme::TEXT),
            Some(&destination),
        );
        cell(
            ui,
            widths[2],
            RichText::new(&route).small().color(route_color),
            route_hover.as_deref(),
        );
        for (value, width) in [
            (connection.download, widths[3]),
            (connection.upload, widths[4]),
        ] {
            cell(
                ui,
                width,
                RichText::new(crate::i18n::bytes(value))
                    .small()
                    .monospace()
                    .color(theme::TEXT_MUTED),
                None,
            );
        }
        cell(
            ui,
            widths[5],
            RichText::new(duration)
                .small()
                .monospace()
                .color(theme::TEXT_MUTED),
            None,
        );
    });
}

fn cell(ui: &mut egui::Ui, width: f32, text: RichText, hover: Option<&str>) {
    ui.allocate_ui_with_layout(
        egui::vec2(width, CONNECTION_ROW_HEIGHT),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.set_width(width);
            let response = ui.add(egui::Label::new(text).truncate());
            if let Some(hover) = hover {
                response.on_hover_text(hover);
            }
        },
    );
}

fn traffic_row(ui: &mut egui::Ui, color: Color32, label: &str, rate: u64, connected: bool) {
    let formatted = crate::i18n::rate(rate);
    let (number, unit) = formatted.split_once(' ').unwrap_or((&formatted, ""));
    let text_color = if connected {
        theme::TEXT
    } else {
        theme::TEXT_DIM
    };
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, 0.0, color);
        ui.label(RichText::new(label).small().color(theme::TEXT_DIM));
    });
    ui.horizontal(|ui| {
        ui.add_space(16.0);
        ui.label(
            RichText::new(number)
                .size(24.0)
                .strong()
                .monospace()
                .color(text_color),
        );
        ui.label(RichText::new(unit).small().color(theme::TEXT_DIM));
    });
}

fn chart_columns(history: &VecDeque<(u64, u64)>, range: TrafficRange) -> Vec<(u64, u64)> {
    let samples = range.samples_per_bar();
    let mut visible: Vec<_> = history.iter().rev().take(60 * samples).copied().collect();
    visible.reverse();
    visible
        .chunks(samples)
        .map(|chunk| {
            let (down, up) = chunk.iter().fold((0_u128, 0_u128), |(down, up), &(d, u)| {
                (down + u128::from(d), up + u128::from(u))
            });
            (
                (down / chunk.len() as u128) as u64,
                (up / chunk.len() as u128) as u64,
            )
        })
        .collect()
}

fn chart_peak(columns: &[(u64, u64)]) -> u64 {
    columns
        .iter()
        .map(|&(down, up)| down.max(up))
        .max()
        .unwrap_or(0)
}

fn chart_scale(columns: &[(u64, u64)]) -> u64 {
    chart_peak(columns).max(1)
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
    (height(down, 74.0), height(up, 45.0))
}

fn traffic_chart(ui: &mut egui::Ui, columns: &[(u64, u64)]) {
    let width = ui.available_width().max(0.0);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 120.0), egui::Sense::hover());
    let baseline = rect.top() + 74.0;
    ui.painter().hline(
        rect.x_range(),
        baseline,
        egui::Stroke::new(1.0, theme::BORDER),
    );
    if columns.is_empty() {
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            tr!("traffic-empty"),
            egui::TextStyle::Small.resolve(ui.style()),
            theme::TEXT_DIM,
        );
        return;
    }
    let scale = chart_scale(columns);
    let bar_width = ((width - 2.0 * 59.0) / 60.0).max(0.0);
    for (index, &(down, up)) in columns.iter().enumerate() {
        let x = rect.right() - bar_width - (columns.len() - 1 - index) as f32 * (bar_width + 2.0);
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
    if let Some(pos) = response.hover_pos()
        && bar_width > 0.0
    {
        let slot = ((rect.right() - pos.x) / (bar_width + 2.0)).floor() as usize;
        if slot < columns.len() {
            let (down, up) = columns[columns.len() - 1 - slot];
            response.on_hover_text(format!(
                "{}: {}\n{}: {}",
                tr!("traffic-down"),
                crate::i18n::rate(down),
                tr!("traffic-up"),
                crate::i18n::rate(up),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::{bar_heights, chart_columns, chart_peak, chart_scale};
    use crate::state::TrafficRange;

    #[test]
    fn chart_scale_uses_largest_rate_or_one() {
        assert_eq!(chart_peak(&[]), 0);
        assert_eq!(chart_scale(&[]), 1);
        assert_eq!(chart_scale(&[(12, 5), (3, 20)]), 20);
        assert_eq!(chart_scale(&[(0, 0)]), 1);
    }

    #[test]
    fn bar_heights_scale_both_sides_and_keep_tiny_samples_visible() {
        assert_eq!(bar_heights(100, 0, 100), (74.0, 0.0));
        assert_eq!(bar_heights(0, 100, 100), (0.0, 45.0));
        assert_eq!(bar_heights(1, 1, 10_000), (1.0, 1.0));
        assert_eq!(bar_heights(0, 0, 1), (0.0, 0.0));
    }

    #[test]
    fn every_range_displays_60_columns_of_its_visible_history() {
        let history = VecDeque::from_iter((0..900).map(|n| (n, n + 1)));
        for (range, first, last) in [
            (TrafficRange::OneMinute, (840, 841), (899, 900)),
            (TrafficRange::FiveMinutes, (602, 603), (897, 898)),
            (TrafficRange::FifteenMinutes, (7, 8), (892, 893)),
        ] {
            let columns = chart_columns(&history, range);
            assert_eq!(columns.len(), 60);
            assert_eq!(columns.first(), Some(&first));
            assert_eq!(columns.last(), Some(&last));
        }
    }

    #[test]
    fn averages_both_rates_and_handles_incomplete_last_interval() {
        let history = VecDeque::from([(10, 50), (20, 40), (30, 30), (40, 20), (50, 10), (90, 180)]);
        assert_eq!(
            chart_columns(&history, TrafficRange::FiveMinutes),
            [(30, 30), (90, 180)]
        );
        assert_eq!(
            chart_columns(&history, TrafficRange::FifteenMinutes),
            [(40, 55)]
        );
        let history = VecDeque::from_iter((0..16).map(|n| (n, 2 * n)));
        assert_eq!(
            chart_columns(&history, TrafficRange::FifteenMinutes),
            [(7, 14), (15, 30)]
        );
    }

    #[test]
    fn caption_peak_is_the_largest_visible_averaged_column() {
        let history = VecDeque::from_iter(
            std::iter::repeat_n((10, 20), 900)
                .enumerate()
                .map(|(index, value)| if index == 700 { (1000, 0) } else { value }),
        );
        assert_eq!(
            chart_peak(&chart_columns(&history, TrafficRange::OneMinute)),
            20
        );
        assert_eq!(
            chart_peak(&chart_columns(&history, TrafficRange::FiveMinutes)),
            208
        );
        assert_eq!(
            chart_peak(&chart_columns(&history, TrafficRange::FifteenMinutes)),
            76
        );
    }
}
