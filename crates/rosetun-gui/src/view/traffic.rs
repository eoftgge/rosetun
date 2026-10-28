use std::collections::VecDeque;
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use rosetun_config::ConnectionState;

use crate::state::{Action, State, TrafficRange};
use crate::{motion, theme, widgets};

const CHART_COLUMNS: usize = 60;
const COLUMN_GAP: f32 = 2.0;
/// Until two samples have arrived, the chart assumes the service's pace.
const DEFAULT_SAMPLE_INTERVAL_MS: u64 = 1_000;

/// What the chart draws in one frame.
struct Chart {
    /// Oldest first; one more than fits while the columns move, for the one
    /// sliding out on the left.
    columns: Vec<(u64, u64)>,
    scale: u64,
    range: TrafficRange,
    /// How far the columns have moved toward their places, `None` while they stand still.
    travel: Option<f32>,
    samples_taken: u64,
    reduce_motion: bool,
    /// The pace of continuous frames, `None` when nobody sees the chart move.
    frame: Option<Duration>,
}

/// Displayed column heights, kept between frames so they ease to new values.
#[derive(Clone, Default)]
struct ChartMotion {
    range: Option<TrafficRange>,
    bars: Vec<BarMotion>,
}

#[derive(Clone, Copy)]
struct BarMotion {
    key: u64,
    from: (f32, f32),
    to: (f32, f32),
    started: f64,
}

impl BarMotion {
    fn at(&self, now: f64) -> (f32, f32) {
        let progress = motion::ease_out(((now - self.started) / f64::from(motion::NORMAL)) as f32);
        (
            self.from.0 + (self.to.0 - self.from.0) * progress,
            self.from.1 + (self.to.1 - self.from.1) * progress,
        )
    }

    fn settled(&self, now: f64) -> bool {
        now - self.started >= f64::from(motion::NORMAL)
    }
}

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
    let range = state.traffic.traffic_range;
    let reduce_motion = state.config.interface.reduce_motion;
    let travel = (!reduce_motion)
        .then(|| {
            chart_travel(
                range,
                state
                    .traffic
                    .sample_arrived_ms
                    .map(|arrived| state.frame_time().saturating_sub(arrived)),
                state
                    .traffic
                    .sample_interval_ms
                    .unwrap_or(DEFAULT_SAMPLE_INTERVAL_MS),
            )
        })
        .flatten();
    let columns = chart_columns(
        &state.traffic.traffic_history,
        range,
        CHART_COLUMNS + usize::from(travel.is_some()),
    );
    let visible = &columns[columns.len().saturating_sub(CHART_COLUMNS)..];
    let peak = chart_peak(visible);
    let scale = chart_scale(visible);
    let chart = Chart {
        columns,
        scale,
        range,
        travel,
        samples_taken: state.traffic.samples_taken,
        reduce_motion,
        frame: traffic.and_then(|_| {
            motion::continuous_frame(
                motion::WindowView::of(ui.ctx(), state.window_hidden()),
                reduce_motion,
            )
        }),
    };
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
                            theme::palette().accent_light,
                            &tr!("traffic-down"),
                            down,
                            traffic.is_some(),
                        );
                        ui.add_space(10.0);
                        traffic_row(
                            ui,
                            theme::palette().accent_dark,
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
                            egui::Stroke::new(1.0, theme::palette().border),
                        );
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(tr!("traffic-session"))
                                    .small()
                                    .color(theme::palette().text_dim),
                            );
                            let totals = crate::i18n::traffic_rates(
                                &crate::i18n::bytes(down_total),
                                &crate::i18n::bytes(up_total),
                            );
                            ui.add(
                                egui::Label::new(RichText::new(&totals).small().color(
                                    if traffic.is_some() {
                                        theme::palette().text
                                    } else {
                                        theme::palette().text_dim
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
                                .color(theme::palette().text_dim),
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
                    traffic_chart(ui, &chart);
                });
            },
        );
    });
    ui.add_space(16.0);
    super::connections::section(ui, state, actions);
}

fn traffic_row(ui: &mut egui::Ui, color: Color32, label: &str, rate: u64, connected: bool) {
    let formatted = crate::i18n::rate(rate);
    let (number, unit) = formatted.split_once(' ').unwrap_or((&formatted, ""));
    let text_color = if connected {
        theme::palette().text
    } else {
        theme::palette().text_dim
    };
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, 0.0, color);
        ui.label(
            RichText::new(label)
                .small()
                .color(theme::palette().text_dim),
        );
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
        ui.label(RichText::new(unit).small().color(theme::palette().text_dim));
    });
}

/// The newest `count` columns of `history`, oldest first.
fn chart_columns(
    history: &VecDeque<(u64, u64)>,
    range: TrafficRange,
    count: usize,
) -> Vec<(u64, u64)> {
    let samples = range.samples_per_bar();
    let mut visible: Vec<_> = history
        .iter()
        .rev()
        .take(count * samples)
        .copied()
        .collect();
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

/// How far, from 0 to 1 column, the columns have moved left toward their
/// places since the newest sample arrived `since_sample_ms` ago. Only where a
/// column is one sample: wider columns stand still and change height only.
fn chart_travel(
    range: TrafficRange,
    since_sample_ms: Option<u64>,
    interval_ms: u64,
) -> Option<f32> {
    (range.samples_per_bar() == 1).then(|| {
        since_sample_ms.map_or(1.0, |since| {
            (since as f32 / interval_ms.max(1) as f32).min(1.0)
        })
    })
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

fn traffic_chart(ui: &mut egui::Ui, chart: &Chart) {
    let columns = chart.columns.as_slice();
    let width = ui.available_width().max(0.0);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 120.0), egui::Sense::hover());
    let baseline = rect.top() + 74.0;
    ui.painter().hline(
        rect.x_range(),
        baseline,
        egui::Stroke::new(1.0, theme::palette().border),
    );
    if columns.is_empty() {
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            tr!("traffic-empty"),
            egui::TextStyle::Small.resolve(ui.style()),
            theme::palette().text_dim,
        );
        return;
    }
    let bar_width =
        ((width - COLUMN_GAP * (CHART_COLUMNS - 1) as f32) / CHART_COLUMNS as f32).max(0.0);
    let stride = bar_width + COLUMN_GAP;
    // The newest column starts a whole column right of its place, past the edge.
    let shift = chart.travel.map_or(0.0, |travel| (1.0 - travel) * stride);
    let heights = displayed_heights(ui.ctx(), chart);
    let painter = ui.painter_at(rect);
    for (from_right, &(down_height, up_height)) in heights.iter().rev().enumerate() {
        let x = rect.right() - bar_width - from_right as f32 * stride + shift;
        if bar_width > 0.0 && down_height > 0.0 {
            painter.rect_filled(
                egui::Rect::from_min_size(
                    egui::pos2(x, baseline - down_height),
                    egui::vec2(bar_width, down_height),
                ),
                0.0,
                theme::palette().accent_light,
            );
        }
        if bar_width > 0.0 && up_height > 0.0 {
            painter.rect_filled(
                egui::Rect::from_min_size(
                    egui::pos2(x, baseline + 1.0),
                    egui::vec2(bar_width, up_height),
                ),
                0.0,
                theme::palette().accent_dark,
            );
        }
    }
    if let Some(pos) = response.hover_pos()
        && bar_width > 0.0
    {
        let slot = ((rect.right() + shift - pos.x) / stride).floor() as usize;
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

/// Column heights eased toward their real values, oldest first. Columns
/// that move are told apart by their sample, fixed ones by their place.
fn displayed_heights(ctx: &egui::Context, chart: &Chart) -> Vec<(f32, f32)> {
    let id = egui::Id::new("traffic_chart_motion");
    let now = ctx.input(|input| input.time);
    let mut motion = ctx.data_mut(|data| data.get_temp::<ChartMotion>(id).unwrap_or_default());
    if motion.range != Some(chart.range) {
        motion.bars.clear();
    }
    let newest = chart.columns.len().saturating_sub(1);
    let mut bars = Vec::with_capacity(chart.columns.len());
    let mut heights = Vec::with_capacity(chart.columns.len());
    for (index, &(down, up)) in chart.columns.iter().enumerate() {
        let from_right = (newest - index) as u64;
        let key = if chart.travel.is_some() {
            chart.samples_taken.wrapping_sub(from_right)
        } else {
            from_right
        };
        let target = bar_heights(down, up, chart.scale);
        let bar = match motion.bars.iter().find(|bar| bar.key == key) {
            Some(bar) if bar.to == target => *bar,
            Some(bar) if !chart.reduce_motion => BarMotion {
                key,
                from: bar.at(now),
                to: target,
                started: now,
            },
            _ => BarMotion {
                key,
                from: target,
                to: target,
                started: f64::NEG_INFINITY,
            },
        };
        heights.push(bar.at(now));
        bars.push(bar);
    }
    let settling = bars.iter().any(|bar| !bar.settled(now));
    if let Some(frame) = chart.frame
        && (settling || chart.travel.is_some())
    {
        ctx.request_repaint_after(frame);
    }
    ctx.data_mut(|data| {
        data.insert_temp(
            id,
            ChartMotion {
                range: Some(chart.range),
                bars,
            },
        );
    });
    heights
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::{CHART_COLUMNS, bar_heights, chart_columns, chart_peak, chart_scale, chart_travel};
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
            let columns = chart_columns(&history, range, CHART_COLUMNS);
            assert_eq!(columns.len(), 60);
            assert_eq!(columns.first(), Some(&first));
            assert_eq!(columns.last(), Some(&last));
        }
    }

    #[test]
    fn moving_columns_take_one_more_from_history_for_the_left_edge() {
        let history = VecDeque::from_iter((0..900).map(|n| (n, n)));
        let columns = chart_columns(&history, TrafficRange::OneMinute, CHART_COLUMNS + 1);
        assert_eq!(columns.len(), 61);
        assert_eq!(columns.first(), Some(&(839, 839)));
        assert_eq!(columns.last(), Some(&(899, 899)));
    }

    #[test]
    fn one_second_columns_travel_one_column_between_samples_and_start_over() {
        let range = TrafficRange::OneMinute;
        assert_eq!(chart_travel(range, Some(0), 1_000), Some(0.0));
        assert_eq!(chart_travel(range, Some(250), 1_000), Some(0.25));
        assert_eq!(chart_travel(range, Some(1_000), 1_000), Some(1.0));
        assert_eq!(chart_travel(range, Some(1_700), 1_000), Some(1.0));
        assert_eq!(chart_travel(range, Some(600), 1_200), Some(0.5));
        assert_eq!(chart_travel(range, Some(0), 1_000), Some(0.0), "new sample");
        assert_eq!(chart_travel(range, None, 1_000), Some(1.0));
    }

    #[test]
    fn wider_columns_stand_still() {
        for range in [TrafficRange::FiveMinutes, TrafficRange::FifteenMinutes] {
            assert_eq!(chart_travel(range, Some(400), 1_000), None);
            assert_eq!(chart_travel(range, None, 1_000), None);
        }
    }

    #[test]
    fn averages_both_rates_and_handles_incomplete_last_interval() {
        let history = VecDeque::from([(10, 50), (20, 40), (30, 30), (40, 20), (50, 10), (90, 180)]);
        assert_eq!(
            chart_columns(&history, TrafficRange::FiveMinutes, CHART_COLUMNS),
            [(30, 30), (90, 180)]
        );
        assert_eq!(
            chart_columns(&history, TrafficRange::FifteenMinutes, CHART_COLUMNS),
            [(40, 55)]
        );
        let history = VecDeque::from_iter((0..16).map(|n| (n, 2 * n)));
        assert_eq!(
            chart_columns(&history, TrafficRange::FifteenMinutes, CHART_COLUMNS),
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
            chart_peak(&chart_columns(
                &history,
                TrafficRange::OneMinute,
                CHART_COLUMNS
            )),
            20
        );
        assert_eq!(
            chart_peak(&chart_columns(
                &history,
                TrafficRange::FiveMinutes,
                CHART_COLUMNS
            )),
            208
        );
        assert_eq!(
            chart_peak(&chart_columns(
                &history,
                TrafficRange::FifteenMinutes,
                CHART_COLUMNS
            )),
            76
        );
    }
}
