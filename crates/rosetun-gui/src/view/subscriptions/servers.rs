use super::*;

const ROW_PADDING: f32 = 10.0;
const FLAG_WIDTH: f32 = 38.0;
/// Between the name (or the Xray badge) and the check result.
const RESULT_GAP: f32 = 10.0;
/// The quality bars and their gap to the latency.
const BARS_WIDTH: f32 = 13.0 + 8.0;
const BADGE_GAP: f32 = 8.0;
const BADGE_PADDING: f32 = 14.0;

/// What every row of one subscription card shares.
#[derive(Clone, Copy)]
pub(super) struct CardColumns {
    pub(super) flags: bool,
    /// Width of the latency column once any server of the card has a check result.
    pub(super) ping_width: Option<f32>,
    /// False when every server goes through Xray: the line under the list says so once.
    pub(super) xray_badges: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum XrayBadge {
    Full,
    Short,
}

/// What a server row has to show besides the name.
#[derive(Clone, Copy)]
struct RowNeeds {
    width: f32,
    flag: bool,
    /// Widths of the full and the short Xray badge, when the row shows one.
    xray: Option<(f32, f32)>,
    /// Width of the latency column, when the row has a check result.
    ping: Option<f32>,
}

#[derive(Debug, PartialEq)]
struct RowLayout {
    bars: bool,
    xray: Option<XrayBadge>,
    name_width: f32,
}

fn row_layout(needs: RowNeeds) -> RowLayout {
    let mut room = needs.width - 2.0 * ROW_PADDING;
    if needs.flag {
        room -= FLAG_WIDTH;
    }
    if let Some(ping) = needs.ping {
        room -= ping + RESULT_GAP;
    }
    let badge = |kind| {
        needs.xray.map_or(0.0, |(full, short)| match kind {
            XrayBadge::Full => full + BADGE_GAP,
            XrayBadge::Short => short + BADGE_GAP,
        })
    };
    let bars_width = if needs.ping.is_some() { BARS_WIDTH } else { 0.0 };
    let layout = |bars: bool, kind| RowLayout {
        bars: bars && needs.ping.is_some(),
        xray: needs.xray.map(|_| kind),
        name_width: (room - if bars { bars_width } else { 0.0 } - badge(kind)).max(0.0),
    };
    [
        (true, XrayBadge::Full),
        (false, XrayBadge::Full),
        (false, XrayBadge::Short),
    ]
    .into_iter()
    .map(|(bars, kind)| layout(bars, kind))
    .find(|layout| layout.name_width >= theme::SERVER_NAME_MIN)
    .unwrap_or_else(|| layout(false, XrayBadge::Short))
}

/// Every server through Xray is said once under the list, not on each row.
pub(super) fn xray_badges(through_xray: usize, servers: usize) -> bool {
    through_xray < servers
}

fn ping_quality(result: PingResult) -> u8 {
    match result {
        PingResult::Answered(elapsed) | PingResult::Works(elapsed) => match ping_millis(elapsed) {
            0..80 => 3,
            80..=150 => 2,
            _ => 1,
        },
        PingResult::NoAnswer
        | PingResult::Fails
        | PingResult::Unresolved
        | PingResult::Unsupported
        | PingResult::Pending => 0,
    }
}

pub(super) fn ping_label(
    result: PingResult,
    is_hysteria2: bool,
) -> (String, Color32, Option<String>) {
    match result {
        PingResult::Answered(elapsed) => (
            tr!("ping-ms", ms = ping_millis(elapsed).to_string()),
            theme::palette().text_dim,
            Some(tr!("ping-tcp-hint")),
        ),
        PingResult::Works(elapsed) => (
            tr!("ping-ms", ms = ping_millis(elapsed).to_string()),
            theme::palette().text_dim,
            Some(tr!("ping-full-hint")),
        ),
        PingResult::NoAnswer => (tr!("ping-no-answer"), theme::ERROR, None),
        PingResult::Fails => (
            tr!("ping-fails"),
            theme::ERROR,
            Some(tr!("ping-fails-hint")),
        ),
        PingResult::Unresolved => (
            tr!("ping-unresolved"),
            theme::palette().text_dim,
            Some(tr!("ping-unresolved-hint")),
        ),
        PingResult::Unsupported => (
            tr!("ping-unsupported"),
            theme::palette().text_dim,
            is_hysteria2.then(|| tr!("ping-udp-hint")),
        ),
        PingResult::Pending => (tr!("ping-pending"), theme::palette().text_dim, None),
    }
}

fn hover_ping_hint(
    result: Option<PingResult>,
    pointer: Option<egui::Pos2>,
    region: Option<egui::Rect>,
    is_hysteria2: bool,
) -> Option<String> {
    if !pointer
        .zip(region)
        .is_some_and(|(point, rect)| rect.contains(point))
    {
        return None;
    }
    ping_label(result?, is_hysteria2).2
}

pub(super) fn check_menu_items(
    ui: &mut egui::Ui,
    state: &State,
    subscription: &Subscription,
    node: Option<&NodeId>,
    available: bool,
    actions: &mut Vec<Action>,
) {
    ui.set_min_width(200.0);
    let can_ping = state.can_ping();
    let ping = widgets::menu_item(
        ui,
        widgets::MenuItem {
            label: &tr!("check-quick"),
            enabled: available && can_ping,
            selected: false,
            danger: false,
            note: None,
        },
    );
    let ping = if matches!(state.status.state, ConnectionState::Connected) {
        ping.on_disabled_hover_text(tr!("ping-while-connected"))
    } else {
        ping
    };
    if ping.clicked() {
        actions.push(match node {
            Some(node) => Action::PingNode(subscription.id.clone(), node.clone()),
            None => Action::Ping(subscription.id.clone()),
        });
        ui.close();
    }
    if widgets::menu_item(
        ui,
        widgets::MenuItem {
            label: &tr!("check-full"),
            enabled: available && state.can_full_check(),
            selected: false,
            danger: false,
            note: None,
        },
    )
    .clicked()
    {
        actions.push(match node {
            Some(node) => Action::FullCheckNode(subscription.id.clone(), node.clone()),
            None => Action::FullCheck(subscription.id.clone()),
        });
        ui.close();
    }
}

pub(super) fn server_row(
    ui: &mut egui::Ui,
    state: &State,
    subscription: &Subscription,
    node: &Node,
    columns: CardColumns,
    actions: &mut Vec<Action>,
) {
    let enabled = state.config_ready && !state.operations.selection && !state.operations.helper;
    let selected = state.config.active.as_ref().is_some_and(|selection| {
        selection.subscription == subscription.id && selection.node == node.id
    });
    let sense = if state.config_ready {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), theme::SERVER_ROW), sense);
    let (code, remainder) = display::leading_flag(&node.name);
    let name = provider_text(ui, state, remainder, egui::TextStyle::Body);
    let full_name = state.text(&node.name);
    let ping_result = state
        .subscriptions
        .pings
        .get(&(subscription.id.clone(), node.id.clone()))
        .copied();
    let uses_xray = rosetun_core::uses_xray(node, state.config.settings.xray);
    let small = egui::TextStyle::Small.resolve(ui.style());
    let badge_width = |label: String| {
        ui.painter()
            .layout_no_wrap(label, small.clone(), theme::palette().accent_light)
            .size()
            .x
            + BADGE_PADDING
    };
    let layout = row_layout(RowNeeds {
        width: rect.width(),
        flag: columns.flags,
        xray: (uses_xray && columns.xray_badges).then(|| {
            (
                badge_width(tr!("xray-badge")),
                badge_width(tr!("xray-badge-short")),
            )
        }),
        ping: columns.ping_width.filter(|_| ping_result.is_some()),
    });
    let right = rect.right() - ROW_PADDING;
    let ping_left = columns
        .ping_width
        .filter(|_| ping_result.is_some())
        .map(|width| right - width);
    let ping_region = ping_left.map(|left| {
        egui::Rect::from_min_max(
            egui::pos2(left, rect.top()),
            egui::pos2(right, rect.bottom()),
        )
    });
    let response = if let Some(hint) = hover_ping_hint(
        ping_result,
        ui.ctx().pointer_hover_pos(),
        ping_region,
        matches!(&node.outbound, Outbound::Hysteria2(_)),
    ) {
        response.on_hover_text(hint)
    } else {
        let details = i18n::node_details(
            rosetun_core::node_protocol(node),
            rosetun_core::node_tls(node),
            rosetun_core::node_transport(node),
        );
        let details = if uses_xray {
            tr!("server-details-xray", details = details)
        } else {
            details
        };
        response.on_hover_text(i18n::server_tooltip(
            &full_name,
            &details,
            &state.text(&rosetun_core::node_address(node)),
        ))
    };
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            enabled,
            selected,
            &full_name,
        )
    });
    let response = if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    };
    if state
        .subscriptions
        .reveal
        .as_ref()
        .is_some_and(|(id, selected)| id == &subscription.id && selected == &node.id)
    {
        response.scroll_to_me(Some(egui::Align::Center));
        actions.push(Action::RevealDone);
    }
    if enabled && response.clicked() {
        actions.push(Action::SelectNode(subscription.id.clone(), node.id.clone()));
    }
    let available = state.config_ready
        && !state.operations.pinging.contains(&subscription.id)
        && !state.subscription_busy(&subscription.id);
    widgets::context_menu_popup(&response).show(|ui| {
        check_menu_items(ui, state, subscription, Some(&node.id), available, actions);
    });
    if !ui.is_rect_visible(rect) {
        return;
    }
    let painter = ui.painter();
    let background = if enabled && response.is_pointer_button_down_on() {
        Some(theme::palette().accent_dark)
    } else if enabled && response.hovered() {
        Some(theme::palette().border)
    } else if selected {
        Some(theme::palette().input)
    } else {
        None
    };
    if let Some(color) = background {
        painter.rect_filled(rect, theme::RADIUS_INNER, color);
    }
    let mut name_left = rect.left() + ROW_PADDING;
    if columns.flags {
        if let Some(code) = code {
            let badge = egui::Rect::from_min_size(
                egui::pos2(name_left, rect.center().y - 10.0),
                egui::vec2(28.0, 20.0),
            );
            painter.rect_stroke(
                badge,
                theme::RADIUS_INNER,
                Stroke::new(1.0, theme::palette().border_strong),
                egui::StrokeKind::Inside,
            );
            painter.text(
                badge.center(),
                egui::Align2::CENTER_CENTER,
                code,
                egui::FontId::monospace(11.0),
                theme::palette().text_muted,
            );
        }
        name_left += FLAG_WIDTH;
    }
    let mut name_right = right;
    if let Some((ping_left, result)) = ping_left.zip(ping_result) {
        name_right = ping_left - RESULT_GAP;
        if layout.bars {
            let bars_left = ping_left - BARS_WIDTH;
            name_right = bars_left - RESULT_GAP;
            let quality = ping_quality(result);
            let bottom = rect.center().y + 5.5;
            for (index, height) in [4.0, 7.0, 11.0].into_iter().enumerate() {
                painter.rect_filled(
                    egui::Rect::from_min_size(
                        egui::pos2(bars_left + index as f32 * 5.0, bottom - height),
                        egui::vec2(3.0, height),
                    ),
                    1.0,
                    if index < quality as usize {
                        theme::palette().text_muted
                    } else {
                        theme::palette().border_strong
                    },
                );
            }
        }
        let (ping_text, color, _) =
            ping_label(result, matches!(&node.outbound, Outbound::Hysteria2(_)));
        painter.text(
            egui::pos2(right, rect.center().y),
            egui::Align2::RIGHT_CENTER,
            ping_text,
            small.clone(),
            color,
        );
    }
    if let Some(kind) = layout.xray {
        let label = match kind {
            XrayBadge::Full => tr!("xray-badge"),
            XrayBadge::Short => tr!("xray-badge-short"),
        };
        let width = badge_width(label.clone());
        let badge = egui::Rect::from_center_size(
            egui::pos2(name_right - width / 2.0, rect.center().y),
            egui::vec2(width, 20.0),
        );
        painter.rect_stroke(
            badge,
            theme::RADIUS_INNER,
            Stroke::new(1.0, theme::palette().accent_light),
            egui::StrokeKind::Inside,
        );
        painter.text(
            badge.center(),
            egui::Align2::CENTER_CENTER,
            label,
            small.clone(),
            theme::palette().accent_light,
        );
        name_right -= width + BADGE_GAP;
    }
    let name_color = if selected {
        theme::palette().accent_light
    } else {
        theme::palette().text
    };
    let text = RichText::new(name).color(name_color).font(if selected {
        egui::FontId::new(
            egui::TextStyle::Body.resolve(ui.style()).size,
            egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
        )
    } else {
        egui::TextStyle::Body.resolve(ui.style())
    });
    let galley = egui::WidgetText::from(text).into_galley(
        ui,
        Some(egui::TextWrapMode::Truncate),
        (name_right - name_left).max(0.0),
        egui::TextStyle::Body,
    );
    painter.galley(
        egui::pos2(name_left, rect.center().y - galley.size().y / 2.0),
        galley,
        name_color,
    );
}

pub(super) fn ping_millis(elapsed: Duration) -> u128 {
    elapsed
        .as_millis()
        .saturating_add(u128::from(
            !elapsed.subsec_nanos().is_multiple_of(1_000_000),
        ))
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_BADGE: f32 = 38.0;
    const SHORT_BADGE: f32 = 21.0;
    /// The subscription card of the owner's screenshot: about 340 points wide.
    const NARROW_ROW: f32 = 314.0;

    fn needs(width: f32, xray: bool, ping: Option<f32>) -> RowNeeds {
        RowNeeds {
            width,
            flag: true,
            xray: xray.then_some((FULL_BADGE, SHORT_BADGE)),
            ping,
        }
    }

    #[test]
    fn a_narrow_card_keeps_the_name_its_room_after_a_check() {
        let all_through_xray = row_layout(needs(NARROW_ROW, false, Some(110.0)));
        assert!(all_through_xray.name_width >= theme::SERVER_NAME_MIN);
        assert_eq!(all_through_xray.xray, None);

        let latency = row_layout(needs(NARROW_ROW, true, Some(70.0)));
        assert!(latency.name_width >= theme::SERVER_NAME_MIN);
        assert!(!latency.bars);
        assert_eq!(latency.xray, Some(XrayBadge::Full));

        let long_result = row_layout(needs(NARROW_ROW, true, Some(95.0)));
        assert!(long_result.name_width >= theme::SERVER_NAME_MIN);
        assert!(!long_result.bars);
        assert_eq!(long_result.xray, Some(XrayBadge::Short));
    }

    #[test]
    fn the_name_is_truncated_only_once_bars_and_the_full_badge_are_gone() {
        let layout = row_layout(needs(260.0, true, Some(70.0)));
        assert!(!layout.bars);
        assert_eq!(layout.xray, Some(XrayBadge::Short));
        assert!(layout.name_width < theme::SERVER_NAME_MIN);
        assert_eq!(row_layout(needs(40.0, true, Some(70.0))).name_width, 0.0);
    }

    #[test]
    fn a_wide_card_shows_everything_as_before() {
        let layout = row_layout(needs(600.0, true, Some(70.0)));
        assert_eq!(
            layout,
            RowLayout {
                bars: true,
                xray: Some(XrayBadge::Full),
                name_width: 600.0 - 20.0 - 38.0 - 80.0 - 21.0 - 46.0,
            }
        );
    }

    #[test]
    fn a_row_without_a_result_reserves_no_latency_column() {
        let layout = row_layout(needs(NARROW_ROW, true, None));
        assert!(!layout.bars);
        assert_eq!(layout.xray, Some(XrayBadge::Full));
        assert_eq!(layout.name_width, NARROW_ROW - 20.0 - 38.0 - 46.0);
    }

    #[test]
    fn xray_badges_show_only_when_some_servers_go_without_xray() {
        assert!(!xray_badges(6, 6));
        assert!(xray_badges(2, 6));
        assert!(xray_badges(0, 6));
        assert!(!xray_badges(0, 0));
    }

    #[test]
    fn ping_milliseconds_round_up_and_never_show_zero() {
        assert_eq!(ping_millis(Duration::ZERO), 1);
        assert_eq!(ping_millis(Duration::from_nanos(1)), 1);
        assert_eq!(ping_millis(Duration::from_millis(1)), 1);
        assert_eq!(ping_millis(Duration::from_micros(1_001)), 2);
        assert_eq!(ping_millis(Duration::from_millis(118)), 118);
    }

    #[test]
    fn result_hint_replaces_server_tooltip_only_over_the_result() {
        let rect = egui::Rect::from_min_max(egui::pos2(80.0, 0.0), egui::pos2(150.0, 30.0));
        let latency = Some(PingResult::Answered(Duration::from_millis(85)));
        let works = Some(PingResult::Works(Duration::from_millis(85)));
        let inside = Some(egui::pos2(100.0, 15.0));
        assert_eq!(
            hover_ping_hint(latency, inside, Some(rect), false),
            Some(tr!("ping-tcp-hint"))
        );
        assert_eq!(
            hover_ping_hint(works, inside, Some(rect), false),
            Some(tr!("ping-full-hint"))
        );
        assert_eq!(
            hover_ping_hint(Some(PingResult::Fails), inside, Some(rect), false),
            Some(tr!("ping-fails-hint"))
        );
        assert_eq!(
            hover_ping_hint(Some(PingResult::Unresolved), inside, Some(rect), false),
            Some(tr!("ping-unresolved-hint"))
        );
        assert_eq!(
            hover_ping_hint(latency, Some(egui::pos2(30.0, 15.0)), Some(rect), false),
            None
        );
        assert_eq!(hover_ping_hint(latency, inside, None, false), None);
        assert_eq!(hover_ping_hint(latency, None, Some(rect), false), None);
        assert_eq!(
            hover_ping_hint(Some(PingResult::Pending), inside, Some(rect), false),
            None
        );
        assert_eq!(
            hover_ping_hint(Some(PingResult::Unsupported), inside, Some(rect), true),
            Some(tr!("ping-udp-hint"))
        );
        assert_eq!(
            hover_ping_hint(Some(PingResult::Unsupported), inside, Some(rect), false),
            None
        );
    }

    #[test]
    fn ping_bars_reflect_latency_and_missing_answers() {
        for (result, expected) in [
            (PingResult::Answered(Duration::from_millis(79)), 3),
            (PingResult::Answered(Duration::from_millis(80)), 2),
            (PingResult::Answered(Duration::from_millis(150)), 2),
            (PingResult::Answered(Duration::from_millis(151)), 1),
            (PingResult::Works(Duration::from_millis(79)), 3),
            (PingResult::Works(Duration::from_millis(150)), 2),
            (PingResult::Works(Duration::from_millis(151)), 1),
            (PingResult::Fails, 0),
            (PingResult::Unresolved, 0),
            (PingResult::Unsupported, 0),
            (PingResult::NoAnswer, 0),
            (PingResult::Pending, 0),
        ] {
            assert_eq!(ping_quality(result), expected);
        }
    }

    #[test]
    fn ping_labels_match_results_and_hints() {
        let elapsed = Duration::from_millis(85);
        let ms = tr!("ping-ms", ms = "85");
        for (result, label, color, hint) in [
            (
                PingResult::Answered(elapsed),
                ms.clone(),
                theme::palette().text_dim,
                Some(tr!("ping-tcp-hint")),
            ),
            (
                PingResult::Works(elapsed),
                ms,
                theme::palette().text_dim,
                Some(tr!("ping-full-hint")),
            ),
            (
                PingResult::NoAnswer,
                tr!("ping-no-answer").to_owned(),
                theme::ERROR,
                None,
            ),
            (
                PingResult::Fails,
                tr!("ping-fails").to_owned(),
                theme::ERROR,
                Some(tr!("ping-fails-hint")),
            ),
            (
                PingResult::Unresolved,
                tr!("ping-unresolved").to_owned(),
                theme::palette().text_dim,
                Some(tr!("ping-unresolved-hint")),
            ),
            (
                PingResult::Unsupported,
                tr!("ping-unsupported").to_owned(),
                theme::palette().text_dim,
                None,
            ),
            (
                PingResult::Pending,
                tr!("ping-pending").to_owned(),
                theme::palette().text_dim,
                None,
            ),
        ] {
            assert_eq!(ping_label(result, false), (label, color, hint));
        }
    }
}
