use std::time::Duration;

use eframe::egui::{
    self, Align, Color32, FontFamily, FontId, Id, Layout, PointerButton, Rect, Response, Sense,
    Shape, Stroke, TextFormat, ViewportCommand, WidgetInfo, WidgetType, text::LayoutJob,
};
use rosetun_config::ConnectionState;

use crate::brand;
use crate::state::{Action, ExitLookup, ExitRoute, Screen, State};
use crate::{constants, theme, widgets};

/// The window draws its own title bar on Windows; elsewhere the system frame stays.
pub(crate) const CUSTOM_FRAME: bool = cfg!(windows);

const INTRO_DURATION: f64 = 2.7;

#[derive(Clone, Copy)]
enum WindowButton {
    Minimize,
    Maximize,
    Restore,
    Close,
}

#[derive(Clone, Copy)]
enum TabIcon {
    Connection,
    Traffic,
    Rules,
    Settings,
}

pub(crate) fn show(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let rect = ui.max_rect();
    let drag = ui.interact(rect, Id::new("header_drag"), Sense::click_and_drag());
    if CUSTOM_FRAME {
        let maximized = ui.input(|input| input.viewport().maximized.unwrap_or(false));
        if drag.drag_started_by(PointerButton::Primary) {
            ui.ctx().send_viewport_cmd(ViewportCommand::StartDrag);
        }
        if drag.double_clicked() {
            ui.ctx()
                .send_viewport_cmd(ViewportCommand::Maximized(!maximized));
        }
    }
    let time = ui.input(|input| input.time);
    // Startup work can delay the first frame past the intro's duration.
    let started_at = ui.ctx().data_mut(|data| {
        let id = Id::new("header_intro_start");
        if let Some(start) = data.get_temp::<f64>(id) {
            start
        } else {
            data.insert_temp(id, time);
            time
        }
    });
    let reduce_motion = state.config.interface.reduce_motion;
    let progress = intro_progress(time, started_at);
    let intro = if reduce_motion {
        1.0
    } else {
        1.0 - (1.0 - progress).powi(3)
    };
    let status = state.visible_status();
    let connected = status.is_some_and(|status| matches!(status.state, ConnectionState::Connected));
    let transitional = status.is_some_and(|status| status.state.is_transitional());
    let settled = ui.ctx().animate_bool_with_time(
        Id::new("header_bloom"),
        connected,
        if reduce_motion { 0.0 } else { 0.8 },
    );
    let bloom = if reduce_motion {
        settled
    } else {
        brand::bloom(settled, transitional, time)
    };
    if !reduce_motion && (progress < 1.0 || transitional) {
        ui.ctx().request_repaint_after(Duration::from_millis(33));
    }

    brand::paint_petals(ui.painter(), rect, bloom, intro);
    ui.painter().line_segment(
        [
            egui::pos2(rect.left(), rect.bottom() - 0.5),
            egui::pos2(rect.right(), rect.bottom() - 0.5),
        ],
        Stroke::new(1.0, theme::BORDER),
    );

    ui.spacing_mut().item_spacing.x = 0.0;
    let selected_rect = ui
        .with_layout(Layout::left_to_right(Align::Center), |ui| {
            ui.add_space(22.0);
            paint_brand(ui, bloom);
            ui.add_space(44.0);

            let mut selected_rect = None;
            for (index, (icon, label, screen, action)) in [
                (
                    TabIcon::Connection,
                    tr!("connection"),
                    Screen::Connection,
                    Action::ShowConnection,
                ),
                (
                    TabIcon::Traffic,
                    tr!("traffic"),
                    Screen::Traffic,
                    Action::OpenTraffic,
                ),
                (
                    TabIcon::Rules,
                    tr!("rules"),
                    Screen::Rules,
                    Action::OpenRules,
                ),
                (
                    TabIcon::Settings,
                    tr!("settings"),
                    Screen::Settings,
                    Action::OpenSettings,
                ),
            ]
            .into_iter()
            .enumerate()
            {
                if index != 0 {
                    ui.add_space(4.0);
                }
                let selected = state.screen == screen;
                let response = tab(ui, icon, &label, selected, reduce_motion);
                if screen == Screen::Settings && state.available_update().is_some() {
                    ui.painter().circle_filled(
                        egui::pos2(response.rect.right() - 8.0, response.rect.top() + 10.0),
                        3.0,
                        theme::ROSE_LIGHT,
                    );
                }
                if selected {
                    selected_rect = Some(response.rect);
                } else if response.clicked() {
                    actions.push(action);
                }
            }

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(18.0);
                if CUSTOM_FRAME {
                    if window_button(ui, WindowButton::Close, reduce_motion).clicked() {
                        ui.ctx().send_viewport_cmd(ViewportCommand::Close);
                    }
                    let maximized = ui.input(|input| input.viewport().maximized.unwrap_or(false));
                    let kind = if maximized {
                        WindowButton::Restore
                    } else {
                        WindowButton::Maximize
                    };
                    if window_button(ui, kind, reduce_motion).clicked() {
                        ui.ctx()
                            .send_viewport_cmd(ViewportCommand::Maximized(!maximized));
                    }
                    if window_button(ui, WindowButton::Minimize, reduce_motion).clicked() {
                        actions.push(Action::WindowMinimized);
                        ui.ctx().send_viewport_cmd(ViewportCommand::Minimized(true));
                    }
                    ui.add_space(12.0);
                }
                let (text, color) = header_status(state);
                let response = widgets::status_pill(ui, &text, color);
                let response = if state.helper_available {
                    response
                } else {
                    response.on_hover_text(tr!("helper-unavailable-detail"))
                };
                if response.clicked() {
                    actions.push(Action::ShowConnection);
                }
            });
            selected_rect
        })
        .inner;

    if let Some(tab_rect) = selected_rect {
        let duration = if reduce_motion { 0.0 } else { 0.2 };
        let left = ui.ctx().animate_value_with_time(
            Id::new("header_tab_underline_left"),
            tab_rect.left(),
            duration,
        );
        let width = ui.ctx().animate_value_with_time(
            Id::new("header_tab_underline_width"),
            tab_rect.width(),
            duration,
        );
        ui.painter().rect_filled(
            Rect::from_min_size(
                egui::pos2(left, rect.bottom() - 2.0),
                egui::vec2(width, 2.0),
            ),
            0.0,
            theme::ROSE,
        );
    }
}

fn header_status(state: &State) -> (String, Color32) {
    let country = match &state.exit {
        ExitLookup::Known {
            route: ExitRoute::Tunnel,
            info,
        } => info.country.as_deref(),
        _ => None,
    };
    header_status_for(
        state.helper_available,
        state.visible_status().map(|status| &status.state),
        country,
    )
}

fn header_status_for(
    helper_available: bool,
    connection: Option<&ConnectionState>,
    country: Option<&str>,
) -> (String, Color32) {
    if !helper_available {
        return (tr!("helper-unavailable").to_owned(), theme::ERROR);
    }
    let (label, color) = match connection {
        None | Some(ConnectionState::Disconnected) => (tr!("disconnected"), theme::DISCONNECTED),
        Some(ConnectionState::Connecting) => (tr!("connecting-action"), theme::ROSE_BRIGHT),
        Some(ConnectionState::Reconnecting) => (tr!("reconnecting-action"), theme::ROSE_BRIGHT),
        Some(ConnectionState::Connected) => {
            return (
                country.map_or_else(|| tr!("connected"), crate::i18n::connected_in),
                theme::CONNECTED,
            );
        }
        Some(ConnectionState::Failed { .. }) => (tr!("failed"), theme::ERROR),
        Some(ConnectionState::FailedProtected { .. }) => (tr!("traffic-blocked"), theme::ERROR),
    };
    (label.to_owned(), color)
}

fn intro_progress(time: f64, started_at: f64) -> f32 {
    ((time - started_at) / INTRO_DURATION).clamp(0.0, 1.0) as f32
}

fn paint_brand(ui: &mut egui::Ui, bloom: f32) {
    let mut name = LayoutJob::default();
    name.append(
        constants::BRAND,
        0.0,
        TextFormat {
            font_id: FontId::new(25.0, FontFamily::Name(theme::BRAND_FONT.into())),
            color: theme::TEXT,
            extra_letter_spacing: 6.0,
            ..Default::default()
        },
    );
    let name = ui.painter().layout_job(name);

    let mut tagline = LayoutJob::default();
    tagline.append(
        &constants::TAGLINE.to_uppercase(),
        0.0,
        TextFormat {
            font_id: FontId::new(10.5, FontFamily::Proportional),
            color: theme::TEXT_DIM,
            extra_letter_spacing: 2.3,
            ..Default::default()
        },
    );
    let tagline = ui.painter().layout_job(tagline);

    let width = 40.0 + 12.0 + name.size().x.max(tagline.size().x);
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(width, ui.max_rect().height()), Sense::hover());
    let emblem = Rect::from_center_size(
        egui::pos2(rect.left() + 20.0, rect.center().y),
        egui::vec2(40.0, 40.0),
    );
    brand::paint_emblem(ui.painter(), emblem, bloom);
    let top = rect.center().y - (name.size().y + 1.0 + tagline.size().y) / 2.0;
    let x = rect.left() + 52.0;
    ui.painter()
        .galley(egui::pos2(x, top), name.clone(), theme::TEXT);
    ui.painter().galley(
        egui::pos2(x, top + name.size().y + 1.0),
        tagline,
        theme::TEXT_DIM,
    );
}

fn window_button(ui: &mut egui::Ui, kind: WindowButton, reduce_motion: bool) -> Response {
    let label = match kind {
        WindowButton::Minimize => tr!("minimize"),
        WindowButton::Maximize => tr!("maximize"),
        WindowButton::Restore => tr!("restore"),
        WindowButton::Close => tr!("close-window"),
    };
    let (rect, response) = ui.allocate_exact_size(egui::vec2(38.0, 32.0), Sense::click());
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, true, label.as_str()));
    let hover = ui.ctx().animate_bool_with_time(
        response.id,
        response.hovered(),
        if reduce_motion { 0.0 } else { 0.1 },
    );
    if ui.is_rect_visible(rect) {
        let background = if matches!(kind, WindowButton::Close) {
            theme::ROSE
        } else {
            theme::INPUT
        };
        if hover > 0.0 {
            ui.painter().rect_filled(
                rect,
                0.0,
                Color32::TRANSPARENT.lerp_to_gamma(background, hover),
            );
        }
        let color = if matches!(kind, WindowButton::Close) {
            theme::TEXT_MUTED
        } else {
            theme::TEXT_DIM
        }
        .lerp_to_gamma(theme::TEXT, hover);
        let glyph = Rect::from_center_size(rect.center(), egui::vec2(14.0, 14.0));
        let point = |x: f32, y: f32| glyph.min + egui::vec2(x, y);
        let stroke = Stroke::new(1.3, color);
        let line = |a: (f32, f32), b: (f32, f32)| {
            ui.painter()
                .line_segment([point(a.0, a.1), point(b.0, b.1)], stroke);
        };
        let square = |min: (f32, f32), max: (f32, f32)| {
            ui.painter().add(Shape::closed_line(
                vec![
                    point(min.0, min.1),
                    point(max.0, min.1),
                    point(max.0, max.1),
                    point(min.0, max.1),
                ],
                stroke,
            ));
        };
        match kind {
            WindowButton::Minimize => line((2.0, 7.0), (12.0, 7.0)),
            WindowButton::Maximize => square((2.5, 2.5), (11.5, 11.5)),
            WindowButton::Restore => {
                line((4.5, 2.5), (11.5, 2.5));
                line((11.5, 2.5), (11.5, 9.5));
                square((2.5, 4.5), (9.5, 11.5));
            }
            WindowButton::Close => {
                line((3.0, 3.0), (11.0, 11.0));
                line((11.0, 3.0), (3.0, 11.0));
            }
        }
    }
    response
        .on_hover_text(label)
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn tab(
    ui: &mut egui::Ui,
    icon: TabIcon,
    label: &str,
    selected: bool,
    reduce_motion: bool,
) -> Response {
    let font_id = FontId::new(15.0, FontFamily::Proportional);
    let text_width = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font_id.clone(), theme::TEXT)
        .size()
        .x;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(
            18.0 + 18.0 + 9.0 + text_width + 18.0,
            ui.max_rect().height(),
        ),
        Sense::click(),
    );
    response
        .widget_info(|| WidgetInfo::selected(WidgetType::SelectableLabel, true, selected, label));
    let t = ui.ctx().animate_bool_with_time(
        response.id,
        selected || response.hovered(),
        if reduce_motion { 0.0 } else { 0.12 },
    );
    let text_color = theme::TEXT_MUTED.lerp_to_gamma(theme::TEXT, t);
    let icon_color = theme::TEXT_DIM.lerp_to_gamma(theme::ROSE, t);
    if ui.is_rect_visible(rect) {
        paint_tab_icon(
            ui.painter(),
            Rect::from_center_size(
                egui::pos2(rect.left() + 27.0, rect.center().y),
                egui::vec2(18.0, 18.0),
            ),
            icon,
            icon_color,
        );
        ui.painter().text(
            egui::pos2(rect.left() + 45.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            label,
            font_id,
            text_color,
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn paint_tab_icon(painter: &egui::Painter, rect: Rect, icon: TabIcon, color: Color32) {
    let scale = rect.width() / 20.0;
    let point = |x: f32, y: f32| rect.min + egui::vec2(x * scale, y * scale);
    let stroke = Stroke::new(1.5 * scale, color);
    let line = |points: &[(f32, f32)]| {
        painter.add(Shape::line(
            points.iter().map(|&(x, y)| point(x, y)).collect(),
            stroke,
        ));
    };
    match icon {
        TabIcon::Connection => {
            painter.add(Shape::closed_line(
                [
                    (10.0, 2.0),
                    (17.0, 5.5),
                    (17.0, 10.5),
                    (10.0, 18.0),
                    (3.0, 10.5),
                    (3.0, 5.5),
                ]
                .map(|(x, y)| point(x, y))
                .to_vec(),
                stroke,
            ));
            line(&[(10.0, 6.0), (10.0, 11.0)]);
            line(&[(7.5, 9.0), (10.0, 6.0), (12.5, 9.0)]);
        }
        TabIcon::Traffic => {
            line(&[
                (2.0, 15.0),
                (6.5, 9.5),
                (10.0, 12.5),
                (14.0, 5.5),
                (18.0, 9.0),
            ]);
            line(&[(2.0, 18.0), (18.0, 18.0)]);
        }
        TabIcon::Rules => {
            line(&[(2.0, 10.0), (7.0, 10.0), (12.0, 4.5), (18.0, 4.5)]);
            line(&[(7.0, 10.0), (12.0, 15.5)]);
            line(&[(12.0, 15.5), (18.0, 15.5)]);
            line(&[(15.5, 2.5), (18.0, 4.5), (15.5, 6.5)]);
            line(&[(15.5, 13.5), (18.0, 15.5), (15.5, 17.5)]);
        }
        TabIcon::Settings => {
            line(&[(2.0, 6.5), (18.0, 6.5)]);
            line(&[(2.0, 13.5), (18.0, 13.5)]);
            for points in [
                [(7.0, 4.0), (9.5, 6.5), (7.0, 9.0), (4.5, 6.5)],
                [(13.0, 11.0), (15.5, 13.5), (13.0, 16.0), (10.5, 13.5)],
            ] {
                painter.add(Shape::convex_polygon(
                    points.map(|(x, y)| point(x, y)).to_vec(),
                    color,
                    Stroke::NONE,
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{header_status_for, intro_progress};
    use crate::theme;
    use rosetun_config::ConnectionState;

    #[test]
    fn header_status_shows_all_connection_states() {
        let states = [
            (
                ConnectionState::Disconnected,
                (tr!("disconnected"), theme::DISCONNECTED),
            ),
            (
                ConnectionState::Connecting,
                (tr!("connecting-action"), theme::ROSE_BRIGHT),
            ),
            (
                ConnectionState::Reconnecting,
                (tr!("reconnecting-action"), theme::ROSE_BRIGHT),
            ),
            (
                ConnectionState::Connected,
                (tr!("connected"), theme::CONNECTED),
            ),
            (
                ConnectionState::Failed {
                    failure_kind: None,
                    reason: String::new(),
                },
                (tr!("failed"), theme::ERROR),
            ),
            (
                ConnectionState::FailedProtected {
                    failure_kind: None,
                    reason: String::new(),
                },
                (tr!("traffic-blocked"), theme::ERROR),
            ),
        ];
        for (state, expected) in &states {
            assert_eq!(
                header_status_for(true, Some(state), None),
                (expected.0.to_owned(), expected.1),
            );
            assert_eq!(
                header_status_for(false, Some(state), Some("NL")),
                (tr!("helper-unavailable").to_owned(), theme::ERROR),
            );
            if !matches!(state, ConnectionState::Connected) {
                assert_eq!(
                    header_status_for(true, Some(state), Some("NL")),
                    (expected.0.to_owned(), expected.1),
                );
            }
        }
        assert_eq!(
            header_status_for(true, Some(&ConnectionState::Connected), Some("NL")),
            ("Connected · NL".to_owned(), theme::CONNECTED),
        );
        assert_eq!(
            header_status_for(true, None, Some("NL")),
            (tr!("disconnected").to_owned(), theme::DISCONNECTED)
        );
        assert_eq!(
            header_status_for(false, None, Some("NL")),
            (tr!("helper-unavailable").to_owned(), theme::ERROR),
        );
        let mut args = fluent_bundle::FluentArgs::new();
        args.set("code", "NL");
        assert_eq!(
            crate::i18n::tr_in(
                crate::i18n::Language::Russian,
                "connected-in-template",
                &args
            ),
            "Подключено · NL"
        );
    }

    #[test]
    fn intro_starts_with_first_header_frame_even_after_startup_delay() {
        assert_eq!(intro_progress(12.0, 12.0), 0.0);
        assert!((intro_progress(13.35, 12.0) - 0.5).abs() < 0.001);
        assert!((intro_progress(14.7, 12.0) - 1.0).abs() < 0.001);
        assert_eq!(intro_progress(15.0, 12.0), 1.0);
    }
}
