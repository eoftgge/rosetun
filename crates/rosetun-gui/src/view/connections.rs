use eframe::egui::{self, Color32, RichText};
use rosetun_config::{ConnectionNetwork, ConnectionRoute, LiveConnection};

use crate::icons::{self, Icon};
use crate::state::{
    Action, ConnectionRow, ConnectionsNotice, ConnectionsTab, ConnectionsView, ProgramGroup,
    RouteFilter, State,
};
use crate::{theme, widgets};

const GAP: f32 = 8.0;
const TABLE_ROW_HEIGHT: f32 = 26.0;
/// Program rows and the connection rows under them share one height, as
/// `ScrollArea::show_rows` needs.
const PROGRAM_ROW_HEIGHT: f32 = 34.0;
/// Right of the name: connections or network, routes, speed, transferred or time.
const PROGRAM_COLUMNS: [f32; 4] = [96.0, 56.0, 92.0, 76.0];
/// Chevron and letter tile with their gaps; connection rows start after it.
const PROGRAM_LEAD: f32 = 16.0 + GAP + 24.0 + GAP;
const ROUTE_FILTER_WIDTH: f32 = 180.0;
const SEARCH_WIDTH: f32 = 240.0;
const LIST_HEIGHT: f32 = 360.0;
const DETAILS_WIDTH: f32 = 300.0;
/// Narrower content puts the details under the list, so that the list keeps
/// its columns at their least width.
const DETAILS_BESIDE_FROM: f32 = 1040.0;
const DETAIL_LABEL_WIDTH: f32 = 88.0;
/// Longer hosts and names are cut in the rule buttons; the full text is on hover.
const BUTTON_TEXT_CHARS: usize = 28;

/// The list, and the selected connection's details beside it or under it.
pub(super) fn section(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let Some(connection) = state.traffic.connections.selected_connection() else {
        card(ui, state, actions);
        return;
    };
    if ui.input(|input| input.key_pressed(egui::Key::Escape)) {
        actions.push(Action::SelectConnection(None));
    }
    let available = ui.available_width();
    if available > DETAILS_BESIDE_FROM {
        let list_width = available - DETAILS_WIDTH - theme::SECTION_GAP;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = theme::SECTION_GAP;
            ui.allocate_ui_with_layout(
                egui::vec2(list_width, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.set_width(list_width);
                    card(ui, state, actions);
                },
            );
            ui.allocate_ui_with_layout(
                egui::vec2(DETAILS_WIDTH, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.set_width(DETAILS_WIDTH);
                    details(ui, state, connection, actions);
                },
            );
        });
    } else {
        card(ui, state, actions);
        ui.add_space(theme::SECTION_GAP);
        details(ui, state, connection, actions);
    }
}

fn details(
    ui: &mut egui::Ui,
    state: &State,
    connection: &LiveConnection,
    actions: &mut Vec<Action>,
) {
    let list = &state.traffic.connections;
    let name = crate::display::safe_text(&list.programs.name(connection.process.as_deref()));
    let path = connection.process.as_deref().map(crate::display::safe_text);
    let host = crate::display::safe_text(&connection.host);
    let destination = crate::display::safe_text(&crate::i18n::connection_destination(
        &connection.host,
        connection.port,
    ));
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.horizontal(|ui| {
            let close = 22.0;
            ui.add_sized(
                egui::vec2((ui.available_width() - close - GAP).max(0.0), close),
                egui::Label::new(RichText::new(&destination).strong()).truncate(),
            )
            .on_hover_text(&destination);
            if close_button(ui, close)
                .on_hover_text(tr!("connections-details-close"))
                .clicked()
            {
                actions.push(Action::SelectConnection(None));
            }
        });
        ui.add_space(10.0);
        detail_row(ui, &tr!("connections-route"), |ui| {
            ui.label(
                RichText::new(state.connection_route_label(&connection.route))
                    .color(route_color(&connection.route)),
            );
        });
        detail_row(ui, &tr!("connections-network"), |ui| {
            ui.label(RichText::new(network_label(connection.network)).color(theme::TEXT));
        });
        detail_row(ui, &tr!("connections-address"), |ui| {
            ui.add(
                egui::Label::new(RichText::new(&destination).monospace().color(theme::TEXT))
                    .selectable(true)
                    .wrap(),
            );
        });
        detail_row(ui, &tr!("connections-program"), |ui| {
            ui.add(egui::Label::new(RichText::new(&name).color(theme::TEXT)).wrap());
            if let Some(path) = &path {
                ui.add(
                    egui::Label::new(RichText::new(path).small().color(theme::TEXT_DIM))
                        .selectable(true)
                        .wrap(),
                );
            }
        });
        let now = crate::display::now_unix();
        detail_row(ui, &tr!("connections-started"), |ui| {
            ui.label(
                RichText::new(crate::i18n::updated_ago(
                    connection.start_unix_ms / 1000,
                    now,
                ))
                .color(theme::TEXT),
            );
        });
        detail_row(ui, &tr!("connections-transferred"), |ui| {
            ui.label(
                RichText::new(crate::i18n::traffic_rates(
                    &crate::i18n::bytes(connection.download),
                    &crate::i18n::bytes(connection.upload),
                ))
                .monospace()
                .color(theme::TEXT),
            );
        });
        detail_row(ui, &tr!("connections-speed"), |ui| {
            let speed = list.rate(connection).map_or_else(
                || "·".to_owned(),
                |(down, up)| {
                    crate::i18n::traffic_rates(&crate::i18n::rate(down), &crate::i18n::rate(up))
                },
            );
            ui.label(RichText::new(speed).monospace().color(theme::TEXT));
        });

        ui.add_space(6.0);
        divider(ui);
        ui.add_space(10.0);
        ui.label(
            RichText::new(tr!("connections-create-rule"))
                .small()
                .color(theme::TEXT_DIM),
        );
        ui.add_space(6.0);
        let can_add = state.can_edit_rules();
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(GAP, GAP);
            let site = tr!("connections-rule-site", host = shortened(&host));
            if widgets::outline_button_compact(ui, &site, can_add)
                .on_hover_text(&host)
                .clicked()
            {
                actions.push(Action::OpenAddRuleFor(crate::state::site_rule(
                    &connection.host,
                )));
            }
            if let Some(process) = connection.process.as_deref() {
                let program = tr!("connections-rule-program", name = shortened(&name));
                if widgets::outline_button_compact(ui, &program, can_add)
                    .on_hover_text(path.as_deref().unwrap_or_default())
                    .clicked()
                {
                    actions.push(Action::OpenAddRuleFor(crate::state::program_rule(process)));
                }
            }
        });

        if connection.end_unix_ms.is_none() {
            ui.add_space(12.0);
            let closing = list.closing.as_deref() == Some(connection.id.as_str());
            let label = if closing {
                tr!("connections-closing")
            } else {
                tr!("connections-close")
            };
            let enabled = list.closing.is_none()
                && !connection.id.is_empty()
                && state.connections_available();
            if widgets::outline_button(ui, label, enabled).clicked() {
                actions.push(Action::CloseConnection(connection.id.clone()));
            }
            ui.add_space(4.0);
            ui.label(
                RichText::new(tr!("connections-close-note"))
                    .small()
                    .color(theme::TEXT_DIM),
            );
        }
    });
}

fn detail_row(ui: &mut egui::Ui, label: &str, value: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(
            egui::vec2(DETAIL_LABEL_WIDTH, 18.0),
            egui::Layout::left_to_right(egui::Align::Min),
            |ui| {
                ui.set_width(DETAIL_LABEL_WIDTH);
                ui.add(
                    egui::Label::new(RichText::new(label).small().color(theme::TEXT_DIM))
                        .truncate(),
                );
            },
        );
        ui.vertical(|ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 2.0;
            value(ui);
        });
    });
    ui.add_space(6.0);
}

fn close_button(ui: &mut egui::Ui, size: f32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::click());
    if response.hovered() {
        ui.painter()
            .rect_filled(rect, theme::RADIUS_INNER, theme::INPUT);
    }
    let color = if response.hovered() {
        theme::TEXT
    } else {
        theme::TEXT_DIM
    };
    let half = 4.5;
    let center = rect.center();
    for (from, to) in [
        (egui::vec2(-half, -half), egui::vec2(half, half)),
        (egui::vec2(-half, half), egui::vec2(half, -half)),
    ] {
        ui.painter().line_segment(
            [center + from, center + to],
            egui::Stroke::new(1.5, color),
        );
    }
    response
}

fn shortened(text: &str) -> String {
    if text.chars().count() <= BUTTON_TEXT_CHARS {
        return text.to_owned();
    }
    let mut short: String = text.chars().take(BUTTON_TEXT_CHARS - 1).collect();
    short.push('…');
    short
}

fn card(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let list = &state.traffic.connections;
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.label(RichText::new(tr!("connections-title")).strong());
        ui.add_space(10.0);
        toolbar(ui, state, actions);
        ui.add_space(10.0);
        let widths = table_widths(ui.available_width());
        if list.view == ConnectionsView::All {
            table_header(ui, &widths);
        }
        divider(ui);
        if let Some(notice) = state.connections_notice() {
            let text = match notice {
                ConnectionsNotice::Disconnected => tr!("connections-disconnected"),
                ConnectionsNotice::Denied => tr!("connections-denied"),
                ConnectionsNotice::Loading => tr!("connections-loading"),
                ConnectionsNotice::Empty => match list.tab {
                    ConnectionsTab::Active => tr!("connections-empty"),
                    ConnectionsTab::Closed => tr!("connections-closed-empty"),
                },
                ConnectionsNotice::NoRouteMatch => tr!("connections-no-route-match"),
                ConnectionsNotice::NoMatch => tr!("connections-no-match"),
            };
            ui.add_space(18.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(text).small().color(theme::TEXT_DIM));
            });
            ui.add_space(18.0);
        } else {
            let now_ms = crate::display::now_unix().saturating_mul(1000);
            match list.view {
                ConnectionsView::ByProgram => program_list(ui, state, now_ms, actions),
                ConnectionsView::All => table(ui, state, &widths, now_ms, actions),
            }
        }
        ui.add_space(10.0);
        ui.label(
            RichText::new(tr!("connections-note"))
                .small()
                .color(theme::TEXT_DIM),
        );
    });
}

fn toolbar(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let list = &state.traffic.connections;
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = egui::vec2(GAP, GAP);
        if let Some(view) = widgets::segmented(
            ui,
            "connections_view",
            list.view,
            &[
                (ConnectionsView::ByProgram, tr!("connections-by-program")),
                (ConnectionsView::All, tr!("connections-all")),
            ],
            false,
            true,
        ) {
            actions.push(Action::SetConnectionsView(view));
        }
        if let Some(tab) = widgets::segmented(
            ui,
            "connections_tab",
            list.tab,
            &[
                (
                    ConnectionsTab::Active,
                    tr!("connections-active", n = list.active.len().to_string()),
                ),
                (
                    ConnectionsTab::Closed,
                    tr!("connections-closed", n = list.closed.len().to_string()),
                ),
            ],
            false,
            state.connections_available(),
        ) {
            actions.push(Action::SetConnectionsTab(tab));
        }
        route_filter(ui, state, actions);
        let mut filter = list.filter.clone();
        widgets::search_field(ui, &mut filter, &tr!("connections-filter"), SEARCH_WIDTH);
        if filter != list.filter {
            actions.push(Action::SetConnectionsFilter(filter));
        }
    });
}

fn route_filter(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let selected = &state.traffic.connections.route;
    let label = |filter: &RouteFilter| match filter {
        RouteFilter::Any => tr!("connections-route-any"),
        RouteFilter::Proxy => tr!("proxy"),
        RouteFilter::Direct => tr!("direct"),
        RouteFilter::Exit(id) => state.connection_route_label(&ConnectionRoute::Exit(id.clone())),
    };
    let text = |filter: &RouteFilter| {
        let text = RichText::new(label(filter));
        match filter {
            RouteFilter::Any => text,
            RouteFilter::Proxy => text.color(route_color(&ConnectionRoute::Proxy)),
            RouteFilter::Direct => text.color(route_color(&ConnectionRoute::Direct)),
            RouteFilter::Exit(id) => text.color(route_color(&ConnectionRoute::Exit(id.clone()))),
        }
    };
    let mut choice = None;
    widgets::filter_combo(
        ui,
        "connections_route_filter",
        ROUTE_FILTER_WIDTH,
        text(selected),
        label(selected),
        |ui| {
            let options = [RouteFilter::Any, RouteFilter::Proxy, RouteFilter::Direct]
                .into_iter()
                .chain(
                    state
                        .config
                        .exits
                        .iter()
                        .map(|exit| RouteFilter::Exit(exit.id.clone())),
                );
            for option in options {
                if ui.selectable_label(&option == selected, text(&option)).clicked() {
                    choice = Some(option);
                }
            }
        },
    );
    if let Some(choice) = choice
        && &choice != selected
    {
        actions.push(Action::SetConnectionsRoute(choice));
    }
}

pub(super) fn route_color(route: &ConnectionRoute) -> Color32 {
    match route {
        ConnectionRoute::Proxy => theme::ROSE_LIGHT,
        ConnectionRoute::Direct => theme::TEXT_MUTED,
        ConnectionRoute::Exit(_) => theme::EXIT,
        ConnectionRoute::Other => theme::TEXT_DIM,
    }
}

/// "Through VPN · <exit>" on hover for an exit, otherwise the label itself.
fn route_hover(state: &State, route: &ConnectionRoute) -> String {
    let label = state.connection_route_label(route);
    match route {
        ConnectionRoute::Exit(_) => tr!("target-exit", name = label),
        _ => label,
    }
}

fn divider(ui: &mut egui::Ui) {
    let (line, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
    ui.painter().hline(
        line.x_range(),
        line.center().y,
        egui::Stroke::new(1.0, theme::BORDER),
    );
}

fn program_list(ui: &mut egui::Ui, state: &State, now_ms: u64, actions: &mut Vec<Action>) {
    let rows = state.traffic.connections.rows();
    egui::ScrollArea::vertical()
        .id_salt("connection_programs")
        .max_height(LIST_HEIGHT)
        .auto_shrink([false, true])
        .show_rows(ui, PROGRAM_ROW_HEIGHT, rows.len(), |ui, range| {
            for row in &rows[range] {
                match row {
                    ConnectionRow::Program { group, expanded } => {
                        program_row(ui, state, group, *expanded, actions);
                    }
                    ConnectionRow::Connection(connection) => {
                        program_connection_row(ui, state, connection, now_ms, actions);
                    }
                }
            }
        });
}

/// A full-width row that highlights under the pointer.
fn row_frame(
    ui: &mut egui::Ui,
    height: f32,
    selected: bool,
    add: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    ui.scope_builder(
        egui::UiBuilder::new().sense(egui::Sense::click()),
        |ui| {
            ui.style_mut().interaction.selectable_labels = false;
            let rect = egui::Rect::from_min_size(
                ui.cursor().min,
                egui::vec2(ui.available_width(), height),
            );
            let fill = if selected {
                Some(theme::BORDER)
            } else if ui.response().hovered() {
                Some(theme::INPUT)
            } else {
                None
            };
            if let Some(fill) = fill {
                ui.painter().rect_filled(rect, theme::RADIUS_INNER, fill);
            }
            ui.horizontal(|ui| {
                ui.set_height(height);
                ui.spacing_mut().item_spacing.x = GAP;
                add(ui);
            });
        },
    )
    .response
}

/// The name's share of a grouped row once the fixed columns are placed.
fn program_name_width(ui: &egui::Ui) -> f32 {
    (ui.available_width() - PROGRAM_COLUMNS.iter().sum::<f32>() - GAP * 4.0).max(80.0)
}

fn program_row(
    ui: &mut egui::Ui,
    state: &State,
    group: &ProgramGroup<'_>,
    expanded: bool,
    actions: &mut Vec<Action>,
) {
    let list = &state.traffic.connections;
    let name = crate::display::safe_text(&list.programs.name(group.path));
    let path = group.path.map(crate::display::safe_text);
    let measured = group
        .connections
        .iter()
        .any(|connection| list.rate(connection).is_some());
    let response = row_frame(ui, PROGRAM_ROW_HEIGHT, false, |ui| {
        let (chevron, _) =
            ui.allocate_exact_size(egui::vec2(16.0, PROGRAM_ROW_HEIGHT), egui::Sense::hover());
        icons::paint(
            ui.painter(),
            chevron.center(),
            Icon::Chevron { open: expanded },
            theme::TEXT_DIM,
        );
        letter_tile(ui, &name);
        let width = program_name_width(ui);
        ui.allocate_ui_with_layout(
            egui::vec2(width, PROGRAM_ROW_HEIGHT),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_width(width);
                ui.spacing_mut().item_spacing.x = 6.0;
                let response =
                    ui.add(egui::Label::new(RichText::new(&name).color(theme::TEXT)).truncate());
                if let Some(path) = &path {
                    response.on_hover_text(path);
                    ui.add(
                        egui::Label::new(
                            RichText::new(crate::programs::file_name(path))
                                .small()
                                .color(theme::TEXT_DIM),
                        )
                        .truncate(),
                    );
                }
            },
        );
        let count = group.connections.len();
        cell(
            ui,
            PROGRAM_COLUMNS[0],
            PROGRAM_ROW_HEIGHT,
            RichText::new(tr!("connections-count", count = count, n = count.to_string()))
                .small()
                .color(theme::TEXT_MUTED),
            None,
        );
        route_dots(ui, state, &group.routes);
        cell(
            ui,
            PROGRAM_COLUMNS[2],
            PROGRAM_ROW_HEIGHT,
            mono(&speed_text(measured.then_some(group.down_rate))),
            None,
        );
        cell(
            ui,
            PROGRAM_COLUMNS[3],
            PROGRAM_ROW_HEIGHT,
            mono(&crate::i18n::bytes(group.transferred)),
            None,
        );
    });
    if response.clicked() {
        actions.push(Action::ToggleProgramGroup(group.path.map(str::to_owned)));
    }
}

fn program_connection_row(
    ui: &mut egui::Ui,
    state: &State,
    connection: &LiveConnection,
    now_ms: u64,
    actions: &mut Vec<Action>,
) {
    let list = &state.traffic.connections;
    let destination = crate::display::safe_text(&crate::i18n::connection_destination(
        &connection.host,
        connection.port,
    ));
    let response = row_frame(ui, PROGRAM_ROW_HEIGHT, is_selected(state, connection), |ui| {
        ui.add_space(PROGRAM_LEAD);
        cell(
            ui,
            program_name_width(ui),
            PROGRAM_ROW_HEIGHT,
            RichText::new(&destination)
                .small()
                .monospace()
                .color(theme::TEXT),
            Some(&destination),
        );
        cell(
            ui,
            PROGRAM_COLUMNS[0],
            PROGRAM_ROW_HEIGHT,
            RichText::new(network_label(connection.network))
                .small()
                .color(theme::TEXT_MUTED),
            None,
        );
        route_dots(ui, state, &[&connection.route]);
        cell(
            ui,
            PROGRAM_COLUMNS[2],
            PROGRAM_ROW_HEIGHT,
            mono(&speed_text(list.rate(connection).map(|(down, _)| down))),
            None,
        );
        cell(
            ui,
            PROGRAM_COLUMNS[3],
            PROGRAM_ROW_HEIGHT,
            mono(&duration(connection, now_ms)),
            None,
        );
    });
    select_on_click(&response, connection, actions);
}

fn is_selected(state: &State, connection: &LiveConnection) -> bool {
    !connection.id.is_empty()
        && state.traffic.connections.selected.as_deref() == Some(connection.id.as_str())
}

fn select_on_click(
    response: &egui::Response,
    connection: &LiveConnection,
    actions: &mut Vec<Action>,
) {
    if response.clicked() && !connection.id.is_empty() {
        actions.push(Action::SelectConnection(Some(connection.id.clone())));
    }
}

fn letter_tile(ui: &mut egui::Ui, name: &str) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(24.0, 24.0), egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, theme::RADIUS_INNER, theme::INPUT);
    let letter: String = name
        .chars()
        .find(|character| character.is_alphanumeric())
        .map(|character| character.to_uppercase().collect())
        .unwrap_or_default();
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        letter,
        egui::FontId::proportional(13.0),
        theme::TEXT_MUTED,
    );
}

fn route_dots(ui: &mut egui::Ui, state: &State, routes: &[&ConnectionRoute]) {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(PROGRAM_COLUMNS[1], PROGRAM_ROW_HEIGHT),
        egui::Sense::hover(),
    );
    for (index, route) in routes.iter().enumerate() {
        let x = rect.left() + 4.0 + index as f32 * 12.0;
        if x + 4.0 > rect.right() {
            break;
        }
        ui.painter()
            .circle_filled(egui::pos2(x, rect.center().y), 4.0, route_color(route));
    }
    if !routes.is_empty() {
        response.on_hover_text(
            routes
                .iter()
                .map(|route| route_hover(state, route))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
}

fn network_label(network: ConnectionNetwork) -> &'static str {
    match network {
        ConnectionNetwork::Tcp => "TCP",
        ConnectionNetwork::Udp => "UDP",
    }
}

/// "·" until the connection was in two answers.
fn speed_text(down: Option<u64>) -> String {
    down.map_or_else(
        || "·".to_owned(),
        |down| {
            format!(
                "{} {}",
                crate::constants::DOWN_ARROW,
                crate::i18n::rate(down)
            )
        },
    )
}

fn duration(connection: &LiveConnection, now_ms: u64) -> String {
    let end = connection.end_unix_ms.unwrap_or(now_ms);
    crate::i18n::connection_duration(end.saturating_sub(connection.start_unix_ms) / 1000)
}

fn mono(text: &str) -> RichText {
    RichText::new(text)
        .small()
        .monospace()
        .color(theme::TEXT_MUTED)
}

/// Program, destination, route, speed, down, up and time.
fn table_widths(available: f32) -> [f32; 7] {
    let spacing = GAP * 6.0;
    let fixed = [92.0, 76.0, 76.0, 64.0];
    let flexible = (available - spacing - fixed.iter().sum::<f32>()).max(120.0);
    [
        flexible * 0.32,
        flexible * 0.43,
        flexible * 0.25,
        fixed[0],
        fixed[1],
        fixed[2],
        fixed[3],
    ]
}

fn table_header(ui: &mut egui::Ui, widths: &[f32; 7]) {
    let titles = [
        tr!("connections-program"),
        tr!("connections-destination"),
        tr!("connections-route"),
        tr!("connections-speed"),
        crate::constants::DOWN_ARROW.to_owned(),
        crate::constants::UP_ARROW.to_owned(),
        tr!("connections-duration"),
    ];
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = GAP;
        for (title, width) in titles.into_iter().zip(widths) {
            cell(
                ui,
                *width,
                TABLE_ROW_HEIGHT,
                RichText::new(title).small().color(theme::TEXT_DIM),
                None,
            );
        }
    });
}

fn table(
    ui: &mut egui::Ui,
    state: &State,
    widths: &[f32; 7],
    now_ms: u64,
    actions: &mut Vec<Action>,
) {
    let visible = state.traffic.connections.visible();
    egui::ScrollArea::vertical()
        .id_salt("connections_rows")
        .max_height(LIST_HEIGHT)
        .auto_shrink([false, true])
        .show_rows(ui, TABLE_ROW_HEIGHT, visible.len(), |ui, rows| {
            for index in rows {
                table_row(ui, state, visible[index], widths, now_ms, actions);
            }
        });
}

fn table_row(
    ui: &mut egui::Ui,
    state: &State,
    connection: &LiveConnection,
    widths: &[f32; 7],
    now_ms: u64,
    actions: &mut Vec<Action>,
) {
    let list = &state.traffic.connections;
    let program = crate::display::safe_text(&list.programs.name(connection.process.as_deref()));
    let path = connection.process.as_deref().map(crate::display::safe_text);
    let destination = crate::display::safe_text(&crate::i18n::connection_destination(
        &connection.host,
        connection.port,
    ));
    let route = state.connection_route_label(&connection.route);
    let response = row_frame(ui, TABLE_ROW_HEIGHT, is_selected(state, connection), |ui| {
        cell(
            ui,
            widths[0],
            TABLE_ROW_HEIGHT,
            RichText::new(&program).small().color(theme::TEXT),
            path.as_deref(),
        );
        cell(
            ui,
            widths[1],
            TABLE_ROW_HEIGHT,
            RichText::new(&destination).small().color(theme::TEXT),
            Some(&destination),
        );
        cell(
            ui,
            widths[2],
            TABLE_ROW_HEIGHT,
            RichText::new(&route)
                .small()
                .color(route_color(&connection.route)),
            Some(&route_hover(state, &connection.route)),
        );
        cell(
            ui,
            widths[3],
            TABLE_ROW_HEIGHT,
            mono(&speed_text(list.rate(connection).map(|(down, _)| down))),
            None,
        );
        for (value, width) in [
            (connection.download, widths[4]),
            (connection.upload, widths[5]),
        ] {
            cell(
                ui,
                width,
                TABLE_ROW_HEIGHT,
                mono(&crate::i18n::bytes(value)),
                None,
            );
        }
        cell(
            ui,
            widths[6],
            TABLE_ROW_HEIGHT,
            mono(&duration(connection, now_ms)),
            None,
        );
    });
    select_on_click(&response, connection, actions);
}

fn cell(ui: &mut egui::Ui, width: f32, height: f32, text: RichText, hover: Option<&str>) {
    ui.allocate_ui_with_layout(
        egui::vec2(width, height),
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
