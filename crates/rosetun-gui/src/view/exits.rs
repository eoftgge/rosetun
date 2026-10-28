use eframe::egui::{self, RichText, Stroke};
use rosetun_config::{AppConfig, CountryCode, Exit, ExitTarget, Selection};

use crate::destinations::{self, ExitNow};
use crate::display;
use crate::icons::{self, Icon};
use crate::state::{Action, ExitDialog, ExitKind, State};
use crate::{i18n, theme, widgets};

const CARD_HEIGHT: f32 = theme::RULE_ROW;
// Two border pixels plus 5 and 6 points of vertical margin, as on the Lists tab.
const CARD_CONTENT_HEIGHT: f32 = CARD_HEIGHT - 13.0;
const RIGHT_WIDTH: f32 = 230.0;
const DIALOG_WIDTH: f32 = 520.0;
const MAX_NODE_LIST: f32 = 168.0;
const MIN_NODE_LIST: f32 = 66.0;
// Everything else in the node form at its tallest, plus room above and below the dialog.
const NODE_FORM_REST: f32 = 540.0;

pub(crate) fn exit_title(exit: &Exit) -> String {
    let name = display::safe_text(&exit.name);
    match destinations::exit_country(exit) {
        Some(code) => format!("{name} · {}", code.as_str()),
        None => name,
    }
}

/// The second line of a row and whether it is a warning.
fn exit_detail(config: &AppConfig, exit: &Exit, resolved: Option<&Selection>) -> (String, bool) {
    let kind = match exit.target {
        ExitTarget::Country(_) => tr!("exit-kind-country"),
        ExitTarget::Node { .. } => tr!("exit-kind-node"),
    };
    let (now, warning) = match destinations::exit_now(config, exit, resolved) {
        ExitNow::Node(name) => (tr!("exit-now", node = display::safe_text(name)), false),
        ExitNow::Fallback(code) => (
            tr!("exit-now-fallback", country = i18n::country_name(code)),
            false,
        ),
        ExitNow::NodeGone => (tr!("exit-now-gone"), true),
        ExitNow::NoCountryNodes(code) => (
            tr!("exit-now-no-nodes", country = i18n::country_name(code)),
            true,
        ),
    };
    (format!("{kind} · {now}"), warning)
}

fn header_has_add_button(state: &State) -> bool {
    state.config_ready && !state.config.exits.is_empty()
}

pub(crate) fn show(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let can_add = state.can_edit_rules() && !destinations::exits_full(&state.config);
    egui::Sides::new().shrink_left().wrap().show(
        ui,
        |ui| {
            ui.vertical(|ui| {
                ui.heading(tr!("exits-title"));
                ui.add(
                    egui::Label::new(RichText::new(tr!("exits-subtitle")).color(theme::palette().text_muted))
                        .wrap(),
                );
            });
        },
        |ui| {
            if header_has_add_button(state) {
                let button = widgets::button_fill(ui, tr!("new-exit-button"), can_add);
                if destinations::exits_full(&state.config) {
                    button.on_disabled_hover_text(tr!(
                        "where-exits-full",
                        count = rosetun_ipc::MAX_EXTRA_NODES.to_string()
                    ));
                } else if button.clicked() {
                    actions.push(Action::OpenNewExit);
                }
            }
        },
    );
    ui.add_space(8.0);
    if !state.config_ready {
        ui.colored_label(theme::palette().text_dim, tr!("loading"));
        return;
    }
    if state.config.exits.is_empty() {
        ui.add_space(12.0);
        widgets::card_frame().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.vertical_centered(|ui| {
                ui.add_space(16.0);
                icons::icon_badge(ui, Icon::Globe, 40.0);
                ui.add_space(8.0);
                ui.add(egui::Label::new(tr!("exits-empty")).wrap());
                ui.add_space(12.0);
                if widgets::button_fill(ui, tr!("new-exit-button"), can_add).clicked() {
                    actions.push(Action::OpenNewExit);
                }
                ui.add_space(16.0);
            });
        });
        return;
    }
    ui.add_space(12.0);
    let resolved = state.resolved_exits();
    egui::ScrollArea::vertical()
        .id_salt("exit_cards")
        .max_height(ui.available_height().max(320.0))
        .show_rows(ui, CARD_HEIGHT, state.config.exits.len(), |ui, rows| {
            for index in rows {
                let exit = &state.config.exits[index];
                let node = resolved
                    .iter()
                    .find(|(id, _)| id == &exit.id)
                    .and_then(|(_, node)| node.as_ref());
                ui.push_id(&exit.id, |ui| {
                    exit_row(ui, state, exit, node, actions);
                });
            }
        });
}

fn exit_row(
    ui: &mut egui::Ui,
    state: &State,
    exit: &Exit,
    resolved: Option<&Selection>,
    actions: &mut Vec<Action>,
) -> egui::Response {
    let title = exit_title(exit);
    let (detail, warning) = exit_detail(&state.config, exit, resolved);
    let rules = state.exit_rules(&exit.id);
    let can_edit = state.can_edit_rules();
    widgets::card_frame()
        .stroke(Stroke::new(1.0, theme::palette().border))
        .inner_margin(egui::Margin {
            left: 12,
            right: 12,
            top: 5,
            bottom: 6,
        })
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.set_min_height(CARD_CONTENT_HEIGHT);
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), CARD_CONTENT_HEIGHT),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.set_min_height(CARD_CONTENT_HEIGHT);
                    ui.spacing_mut().item_spacing.x = 10.0;
                    icons::icon_badge_colored(ui, Icon::Globe, 32.0, theme::EXIT);
                    let width = (ui.available_width() - RIGHT_WIDTH).max(100.0);
                    ui.allocate_ui_with_layout(
                        egui::vec2(width, 40.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_width(width);
                            ui.spacing_mut().item_spacing.y = 0.0;
                            ui.add(egui::Label::new(RichText::new(&title).strong()).truncate())
                                .on_hover_text(&title);
                            ui.add(
                                egui::Label::new(RichText::new(&detail).small().color(
                                    if warning {
                                        theme::WARNING
                                    } else {
                                        theme::palette().text_muted
                                    },
                                ))
                                .truncate(),
                            )
                            .on_hover_text(&detail);
                        },
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        exit_menu(ui, exit, can_edit, actions);
                        if widgets::outline_button_compact(ui, &tr!("edit"), can_edit).clicked() {
                            actions.push(Action::OpenEditExit(exit.id.clone()));
                        }
                        if rules == 0 {
                            ui.label(
                                RichText::new(tr!("exit-no-rules"))
                                    .small()
                                    .color(theme::palette().text_dim),
                            );
                        } else {
                            let label = tr!("exit-rules", count = rules, n = rules.to_string());
                            if widgets::link(ui, &label, true)
                                .on_hover_text(tr!("exit-rules-hint"))
                                .clicked()
                            {
                                actions.push(Action::ShowExitRules(exit.id.clone()));
                            }
                        }
                    });
                },
            );
        })
        .response
}

fn exit_menu(ui: &mut egui::Ui, exit: &Exit, can_edit: bool, actions: &mut Vec<Action>) {
    let menu =
        icons::icon_button_sized(ui, Icon::More, true, 28.0).on_hover_text(tr!("more-actions"));
    widgets::menu_popup(&menu).show(|ui| {
        ui.set_width(210.0);
        for (label, danger, action) in [
            (
                tr!("rename"),
                false,
                Action::OpenRenameExit(exit.id.clone()),
            ),
            (
                tr!("delete"),
                true,
                Action::RequestDeleteExit(exit.id.clone()),
            ),
        ] {
            if widgets::menu_item(
                ui,
                widgets::MenuItem {
                    label: &label,
                    enabled: can_edit,
                    selected: false,
                    danger,
                    note: None,
                },
            )
            .clicked()
            {
                actions.push(action);
                ui.close();
            }
        }
    });
}

/// Countries the dialog offers: those without a country exit, plus the edited exit's own.
fn dialog_countries(config: &AppConfig, dialog: &ExitDialog) -> Vec<CountryCode> {
    let mut countries = destinations::new_countries(config);
    let own = dialog
        .editing
        .as_ref()
        .and_then(|id| config.exits.iter().find(|exit| &exit.id == id))
        .and_then(|exit| match &exit.target {
            ExitTarget::Country(code) => Some(code.clone()),
            ExitTarget::Node { .. } => None,
        });
    for code in own.into_iter().chain(dialog.country.clone()) {
        if !countries.contains(&code) {
            countries.push(code);
        }
    }
    countries.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    countries
}

fn country_label(code: &CountryCode) -> String {
    format!("{} · {}", i18n::country_name(code), code.as_str())
}

fn note(ui: &mut egui::Ui, text: String, color: egui::Color32) {
    ui.add(egui::Label::new(RichText::new(text).small().color(color)).wrap());
}

fn country_picker(ui: &mut egui::Ui, dialog: &mut ExitDialog, config: &AppConfig, busy: bool) {
    ui.label(tr!("exit-country"));
    let countries = dialog_countries(config, dialog);
    let selected = dialog
        .country
        .as_ref()
        .map_or_else(|| tr!("exit-country-pick"), country_label);
    ui.add_enabled_ui(!busy, |ui| {
        egui::ComboBox::from_id_salt("exit_country")
            .width(ui.available_width())
            .selected_text(selected)
            .show_ui(ui, |ui| {
                for code in countries {
                    let label = country_label(&code);
                    let picked = dialog.country.as_ref() == Some(&code);
                    if ui.selectable_label(picked, label).clicked() {
                        dialog.country = Some(code);
                        dialog.error = None;
                    }
                }
            });
    });
    ui.add_space(8.0);
    note(ui, tr!("exit-country-hint"), theme::palette().text_muted);
}

fn node_picker(ui: &mut egui::Ui, dialog: &mut ExitDialog, config: &AppConfig, busy: bool) {
    ui.label(tr!("exit-node"));
    ui.add_enabled(
        !busy,
        egui::TextEdit::singleline(&mut dialog.node_search)
            .desired_width(f32::INFINITY)
            .hint_text(tr!("where-node-search")),
    );
    let nodes = destinations::matching_nodes(config, &dialog.node_search);
    let mut picked = None;
    egui::ScrollArea::vertical()
        .id_salt("exit_nodes")
        .max_height(
            (ui.ctx().content_rect().height() - NODE_FORM_REST).clamp(MIN_NODE_LIST, MAX_NODE_LIST),
        )
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            if nodes.is_empty() {
                note(ui, tr!("where-node-none"), theme::palette().text_muted);
            }
            for node in &nodes {
                let taken = node
                    .exit
                    .filter(|id| dialog.editing.as_ref() != Some(*id))
                    .and_then(|id| config.exits.iter().find(|exit| &exit.id == id));
                let selected = dialog.node.as_ref() == Some(&node.selection);
                let response = ui.add_enabled(
                    !busy && taken.is_none(),
                    egui::Button::selectable(selected, display::safe_text(node.name))
                        .min_size(egui::vec2(ui.available_width(), 0.0)),
                );
                if let Some(exit) = taken {
                    response.on_disabled_hover_text(tr!(
                        "exit-node-taken",
                        name = display::safe_text(&exit.name)
                    ));
                } else if response.clicked() {
                    picked = Some(node.selection.clone());
                }
            }
        });
    if let Some(selection) = picked {
        dialog.pick_node(config, selection);
    }
    let gone = dialog.node.as_ref().is_some_and(|selection| {
        !config.subscriptions.iter().any(|subscription| {
            subscription.id == selection.subscription
                && subscription.node(&selection.node).is_some()
        })
    });
    if gone {
        note(ui, tr!("exit-node-gone-pick"), theme::WARNING);
    }
    ui.add_space(8.0);
    let country = dialog.fallback_country.clone();
    ui.horizontal(|ui| {
        let mut on = dialog.fallback && country.is_some();
        let label = match &country {
            Some(code) => tr!("exit-fallback", country = i18n::country_name(code)),
            None => tr!("exit-fallback-off"),
        };
        let toggle = widgets::toggle(ui, &mut on, !busy && country.is_some());
        let text = ui.add(
            egui::Label::new(RichText::new(&label).color(if country.is_some() {
                theme::palette().text
            } else {
                theme::palette().text_dim
            }))
            .wrap(),
        );
        if country.is_none() {
            toggle.on_hover_text(tr!("exit-fallback-no-country"));
            text.on_hover_text(tr!("exit-fallback-no-country"));
        } else if on != dialog.fallback {
            dialog.fallback = on;
        }
    });
    if country.is_none() && dialog.node.is_some() {
        note(ui, tr!("exit-fallback-no-country"), theme::palette().text_dim);
    }
}

pub(crate) fn exit_dialog(ctx: &egui::Context, state: &mut State, actions: &mut Vec<Action>) {
    let full = destinations::exits_full(&state.config);
    let config = &state.config;
    let Some(dialog) = &mut state.exits.dialog else {
        return;
    };
    let busy = dialog.busy;
    let response = egui::Modal::new(egui::Id::new("exit_dialog"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(DIALOG_WIDTH);
            ui.heading(if dialog.editing.is_some() {
                tr!("edit-exit")
            } else {
                tr!("new-exit")
            });
            ui.add_space(14.0);
            ui.label(tr!("exit-name"));
            let input = ui.add_enabled(
                !busy,
                egui::TextEdit::singleline(&mut dialog.name).desired_width(f32::INFINITY),
            );
            if dialog.focus {
                input.request_focus();
                dialog.focus = false;
            }
            if input.changed() {
                dialog.error = None;
            }
            ui.add_space(12.0);
            if let Some(kind) = widgets::segmented(
                ui,
                "exit_kind",
                dialog.kind,
                &[
                    (ExitKind::Country, tr!("exit-kind-country")),
                    (ExitKind::Node, tr!("exit-kind-node")),
                ],
                true,
                !busy,
            ) {
                dialog.kind = kind;
                dialog.error = None;
            }
            ui.add_space(12.0);
            match dialog.kind {
                ExitKind::Country => country_picker(ui, dialog, config, busy),
                ExitKind::Node => node_picker(ui, dialog, config, busy),
            }
            if dialog.editing.is_none() && full {
                ui.add_space(8.0);
                note(
                    ui,
                    tr!(
                        "where-exits-full",
                        count = rosetun_ipc::MAX_EXTRA_NODES.to_string()
                    ),
                    theme::WARNING,
                );
            }
            if let Some(error) = &dialog.error {
                ui.add_space(8.0);
                ui.add(egui::Label::new(RichText::new(error).color(theme::ERROR)).wrap());
            }
            ui.add_space(18.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::button_fill(ui, tr!("save"), dialog.can_save(full)).clicked() {
                    actions.push(Action::SubmitExitDialog);
                }
                if widgets::outline_button(ui, tr!("cancel"), !busy).clicked() {
                    actions.push(Action::CancelExitDialog);
                }
            });
        });
    if !busy && response.should_close() {
        actions.push(Action::CancelExitDialog);
    }
}

pub(crate) fn rename_dialog(ctx: &egui::Context, state: &mut State, actions: &mut Vec<Action>) {
    let Some(dialog) = &mut state.exits.rename else {
        return;
    };
    let choice = widgets::name_modal(
        ctx,
        widgets::NameModal {
            id: "rename_exit",
            title: tr!("rename-exit"),
            label: tr!("exit-name"),
            submit: tr!("rename"),
            name: &mut dialog.name,
            focus: &mut dialog.focus,
            error: &mut dialog.error,
            busy: dialog.busy,
            char_limit: None,
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelRenameExit),
        widgets::ModalChoice::Confirm => actions.push(Action::SubmitRenameExit),
        widgets::ModalChoice::None => {}
    }
}

pub(crate) fn delete_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let Some(dialog) = &state.exits.delete else {
        return;
    };
    let choice = widgets::confirm_modal(
        ctx,
        widgets::ConfirmModal {
            id: "delete_exit",
            title: tr!("delete-exit"),
            cancel: tr!("cancel"),
            confirm: tr!("delete"),
            busy: dialog.busy,
            confirm_enabled: !dialog.busy,
            button_gap: 20.0,
        },
        |ui| {
            if let Some(exit) = state.config.exits.iter().find(|exit| exit.id == dialog.id) {
                ui.label(exit_title(exit));
            }
            ui.add_space(12.0);
            ui.add(
                egui::Label::new(tr!("delete-exit-detail", n = dialog.rules.to_string())).wrap(),
            );
            if let Some(error) = &dialog.error {
                ui.add(egui::Label::new(RichText::new(error).color(theme::ERROR)).wrap());
            }
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelDeleteExit),
        widgets::ModalChoice::Confirm => actions.push(Action::ConfirmDeleteExit),
        widgets::ModalChoice::None => {}
    }
}

#[cfg(test)]
mod tests {
    use fluent_bundle::FluentArgs;
    use rosetun_config::{
        DomainMatch, ExitId, NodeId, Rule, RuleId, RuleMatcher, RuleSet, RuleSetId, RuleTarget,
        SubscriptionId,
    };

    use super::*;
    use crate::destinations::tests::{config, exit};
    use crate::i18n::{Language, tr_in};

    fn country(code: &str) -> CountryCode {
        CountryCode::parse(code).unwrap()
    }

    fn selection(node: &str) -> Selection {
        Selection {
            subscription: SubscriptionId::new("sub"),
            node: NodeId::new(node),
        }
    }

    fn node_exit(id: &str, node: &str, fallback: Option<CountryCode>) -> Exit {
        exit(
            id,
            ExitTarget::Node {
                selection: selection(node),
                fallback,
            },
        )
    }

    fn state() -> State {
        let mut config = config(
            &[("nl", "NL One"), ("plain", "Plain")],
            vec![
                exit("1", ExitTarget::Country(country("NL"))),
                node_exit("2", "nl", Some(country("NL"))),
                node_exit("3", "gone", Some(country("NL"))),
                node_exit("4", "gone", None),
            ],
        );
        let mut set = RuleSet::new(RuleSetId::new("set"), "Set", RuleTarget::Proxy);
        set.rules.push(Rule {
            id: RuleId::new("r"),
            enabled: true,
            matcher: RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
            target: RuleTarget::Exit,
            exit: Some(ExitId::new("1")),
        });
        config.rule_sets.push(set);
        let mut state = State::default();
        state.config_ready = true;
        state.config = config;
        state
    }

    fn input(width: f32, height: f32) -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(width, height),
            )),
            ..egui::RawInput::default()
        }
    }

    #[test]
    fn rows_show_each_type_and_state_with_the_rule_count() {
        let state = state();
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(input(1200.0, 780.0), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| show(ui, &state, &mut Vec::new()));
        });
        output.textures_delta.clear();
        let texts: Vec<(String, egui::Color32)> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) => Some((
                    text.galley.text().to_owned(),
                    text.galley.job.sections[0].format.color,
                )),
                _ => None,
            })
            .collect();
        let country_kind = tr!("exit-kind-country");
        let node_kind = tr!("exit-kind-node");
        let netherlands = i18n::country_name(&country("NL"));
        for (expected, color) in [
            (
                format!("{country_kind} · {}", tr!("exit-now", node = "NL One")),
                theme::palette().text_muted,
            ),
            (
                format!("{node_kind} · {}", tr!("exit-now", node = "NL One")),
                theme::palette().text_muted,
            ),
            (
                format!(
                    "{node_kind} · {}",
                    tr!("exit-now-fallback", country = netherlands.clone())
                ),
                theme::palette().text_muted,
            ),
            (
                format!("{node_kind} · {}", tr!("exit-now-gone")),
                theme::WARNING,
            ),
            (tr!("exit-rules", count = 1, n = "1"), theme::palette().accent_light),
            (tr!("exit-no-rules"), theme::palette().text_dim),
        ] {
            assert!(
                texts
                    .iter()
                    .any(|(text, found)| text == &expected && *found == color),
                "{expected} in {texts:?}"
            );
        }
    }

    #[test]
    fn empty_tab_explains_where_exits_come_from() {
        let mut state = state();
        state.config.exits.clear();
        assert!(!header_has_add_button(&state));
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(input(960.0, 640.0), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| show(ui, &state, &mut Vec::new()));
        });
        output.textures_delta.clear();
        assert!(output.shapes.iter().any(|shape| matches!(
            &shape.shape,
            egui::Shape::Text(text) if text.galley.text() == tr!("exits-empty")
        )));
    }

    #[test]
    fn row_keeps_rule_row_height_in_a_narrow_window() {
        let state = state();
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        for width in [520.0, 800.0] {
            let mut rect = egui::Rect::NOTHING;
            let mut output = ctx.run_ui(input(width + 40.0, 640.0), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.allocate_ui(egui::vec2(width, 200.0), |ui| {
                        let exit = &state.config.exits[2];
                        rect = exit_row(ui, &state, exit, None, &mut Vec::new()).rect;
                    });
                });
            });
            output.textures_delta.clear();
            assert_eq!(rect.height(), theme::RULE_ROW, "{width}");
            assert!(rect.width() <= width + 0.5, "{rect:?} in {width}");
        }
    }

    #[test]
    fn exit_dialog_fits_a_compact_window() {
        let mut base = state();
        let template = base.config.subscriptions[0].nodes[1].clone();
        base.config.subscriptions[0]
            .nodes
            .extend((0..30).map(|index| {
                let mut node = template.clone();
                node.id = NodeId::new(format!("n{index}"));
                node.name = format!("Plain {index}");
                node
            }));
        base.config.exits.extend(
            (4..rosetun_ipc::MAX_EXTRA_NODES)
                .map(|index| exit(&format!("x{index}"), ExitTarget::Country(country("DE")))),
        );
        for (kind, scale) in [
            (ExitKind::Country, 1.0),
            (ExitKind::Node, 1.0),
            (ExitKind::Country, 1.5),
            (ExitKind::Node, 1.5),
        ] {
            let (width, height) = (960.0 / scale, 640.0 / scale);
            let mut state = State::default();
            state.config_ready = true;
            state.config = base.config.clone();
            state.act(Action::OpenNewExit);
            let dialog = state.exits.dialog.as_mut().unwrap();
            dialog.kind = kind;
            dialog.country = Some(country("NL"));
            dialog.pick_node(&state.config, selection("plain"));
            dialog.error = Some("Example error".into());
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            for _ in 0..2 {
                let mut output = ctx.run_ui(input(width, height), |ctx| {
                    exit_dialog(ctx, &mut state, &mut Vec::new());
                });
                output.textures_delta.clear();
            }
            let rect = ctx
                .memory(|memory| memory.area_rect(egui::Id::new("exit_dialog")))
                .unwrap();
            // As for the add-rule dialog, the smallest window is checked at 100 % only for height.
            if scale == 1.0 {
                assert!(
                    rect.top() >= 0.0 && rect.bottom() <= height,
                    "{kind:?} {rect:?} in {width}×{height}"
                );
            }
            assert!(
                rect.left() >= 0.0 && rect.right() <= width,
                "{kind:?} {rect:?} in {width}×{height}"
            );
        }
    }

    #[test]
    fn tab_title_matches_the_picker_hints() {
        for (language, quoted) in [(Language::English, "{} tab"), (Language::Russian, "«{}»")] {
            let title = tr_in(language, "exits-title", &FluentArgs::new());
            let expected = quoted.replace("{}", &title);
            let mut args = FluentArgs::new();
            args.set("name", "Example");
            args.set("count", "16");
            for hint in [
                tr_in(language, "where-new-exit", &args),
                tr_in(language, "where-exits-full", &args),
            ] {
                assert!(hint.contains(&expected), "{language:?}: {hint}");
            }
        }
    }
}
