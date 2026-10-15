use eframe::egui::{self, Color32, FontFamily, FontId, RichText, Stroke};
use rosetun_config::{AppConfig, ExitTarget, List, ListId, ProcessMatch, RuleTarget};
use rosetun_core::{NewExit, RuleDestination};

use crate::display;
use crate::errors;
use crate::icons::{self, Icon};
use crate::rules::{ProcessMatchMode, process_matches_filter, update_process_match_mode};
use crate::state::{Action, AddRuleDialog, RuleInputKind};
use crate::view::rules::{destination_color, destination_label, target_color, target_label};
use crate::{constants, destinations, i18n, theme, widgets};

const DIALOG_WIDTH: f32 = 640.0;
const DIALOG_TOP: f32 = 100.0;
const COMPACT_DIALOG_HEIGHT: f32 = 632.0;
const ERROR_HEIGHT: f32 = 28.0;
const PROCESS_ROW_HEIGHT: f32 = 44.0;
const PROCESS_ROW_GAP: f32 = 4.0;
const CATEGORY_ROW_HEIGHT: f32 = 22.0;
const CATEGORY_VIEW_HEIGHT: f32 = 120.0;
const MIN_PROCESS_LIST: f32 = 2.0 * PROCESS_ROW_HEIGHT + PROCESS_ROW_GAP;
const MAX_PROCESS_LIST: f32 = 5.0 * PROCESS_ROW_HEIGHT + 4.0 * PROCESS_ROW_GAP;
const PROCESS_FOOTER_HEIGHT: f32 = 80.0;
const BUTTON_ROW_HEIGHT: f32 = 40.0;
const ADVANCED_HEADER_HEIGHT: f32 = 32.0;
const ADVANCED_ROW_HEIGHT: f32 = 44.0;
const DIVIDER_HEIGHT: f32 = 16.0;
const BOTTOM_GAP: f32 = 24.0;
const DESTINATION_HEIGHT: f32 = 36.0;
const DESTINATION_HINT_HEIGHT: f32 = 18.0;
const DESTINATION_POPUP_MARGIN: f32 = 24.0;
const MIN_DESTINATION_POPUP: f32 = 120.0;

fn process_body_height(top: f32, limit: f32, advanced: bool) -> f32 {
    let min_list = if advanced {
        PROCESS_ROW_HEIGHT
    } else {
        MIN_PROCESS_LIST
    };
    (limit - top).clamp(
        PROCESS_FOOTER_HEIGHT + min_list,
        PROCESS_FOOTER_HEIGHT + MAX_PROCESS_LIST,
    )
}

fn has_advanced(dialog: &AddRuleDialog) -> bool {
    dialog.kind == RuleInputKind::Process || dialog.editing.is_none()
}

fn advanced_height(dialog: &AddRuleDialog) -> f32 {
    if !has_advanced(dialog) {
        0.0
    } else {
        ADVANCED_HEADER_HEIGHT
            + if dialog.advanced {
                ADVANCED_ROW_HEIGHT
                    * (usize::from(dialog.kind == RuleInputKind::Process)
                        + usize::from(dialog.editing.is_none())) as f32
            } else {
                0.0
            }
    }
}

fn footer_buttons(
    ui: &mut egui::Ui,
    label: &str,
    can_submit: bool,
    can_cancel: bool,
    reason: Option<&str>,
) -> (egui::Response, egui::Response) {
    ui.horizontal(|ui| {
        let cancel = widgets::outline_button(ui, tr!("cancel"), can_cancel);
        let submit = widgets::button_fill(ui, label, can_submit);
        let submit = if let Some(reason) = reason {
            submit.on_disabled_hover_text(reason)
        } else {
            submit
        };
        (submit, cancel)
    })
    .inner
}

pub(crate) fn show(
    ctx: &egui::Context,
    dialog: &mut AddRuleDialog,
    config: &AppConfig,
    can_temporary: bool,
    existing_list_rules: usize,
    actions: &mut Vec<Action>,
) {
    let lists = &config.lists;
    if !can_temporary {
        dialog.temporary_only = false;
    }
    let id = egui::Id::new("add_rule");
    let error_height = if dialog.error.is_some() {
        ERROR_HEIGHT
    } else {
        0.0
    } + destination_hint_height(dialog);
    let top = DIALOG_TOP
        .min((ctx.content_rect().height() - COMPACT_DIALOG_HEIGHT - error_height).max(8.0));
    let dialog_width = DIALOG_WIDTH.min((ctx.content_rect().width() - 144.0).max(320.0));
    let response = egui::Modal::new(id)
        .area(egui::Modal::default_area(id).anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, top)))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(dialog_width);
            ui.set_max_width(dialog_width);
            ui.spacing_mut().item_spacing.y = 4.0;
            ui.heading(if dialog.editing.is_some() {
                tr!("edit-rule")
            } else {
                tr!("new-rule")
            });
            ui.label(
                RichText::new(if dialog.editing.is_some() {
                    tr!("edit-rule-subtitle")
                } else {
                    tr!("new-rule-subtitle")
                })
                .small()
                .color(theme::TEXT_MUTED),
            );
            ui.add_space(2.0);
            ui.label(
                RichText::new(tr!("what-to-route"))
                    .small()
                    .color(theme::TEXT_DIM),
            );
            if let Some(kind) = widgets::segmented(
                ui,
                "rule_input_kind",
                dialog.kind,
                &[
                    (RuleInputKind::Process, tr!("rule-kind-app")),
                    (RuleInputKind::Domain, tr!("rule-kind-site")),
                    (RuleInputKind::List, tr!("rule-kind-list")),
                    (RuleInputKind::Ip, tr!("rule-kind-ip")),
                ],
                true,
                !dialog.busy && dialog.editing.is_none(),
            ) {
                actions.push(Action::SelectRuleInput(kind));
            }
            ui.add_space(2.0);
            let valid = match dialog.kind {
                RuleInputKind::Process => {
                    let frame = widgets::modal_frame();
                    let limit = ui.ctx().content_rect().bottom()
                        - BOTTOM_GAP
                        - (frame.inner_margin.bottom as f32 + frame.stroke.width)
                        - BUTTON_ROW_HEIGHT
                        - DIVIDER_HEIGHT
                        - 104.0
                        - advanced_height(dialog)
                        - destination_hint_height(dialog)
                        - if dialog.error.is_some() {
                            ERROR_HEIGHT
                        } else {
                            0.0
                        };
                    let height = process_body_height(ui.cursor().top(), limit, dialog.advanced);
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_min_size(egui::vec2(dialog_width, height));
                            process_input(ui, dialog, actions)
                        },
                    )
                    .inner
                }
                RuleInputKind::Domain => domain_input(ui, dialog),
                RuleInputKind::List => list_input(ui, dialog, lists, actions),
                RuleInputKind::Ip => ip_input(ui, dialog, actions),
            };
            ui.add_space(0.0);
            ui.label(
                RichText::new(tr!("where-to-route"))
                    .small()
                    .color(theme::TEXT_DIM),
            );
            destination_picker(ui, dialog, config);
            if has_advanced(dialog) {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let chevron = icons::icon_button_sized(
                        ui,
                        Icon::Chevron {
                            open: dialog.advanced,
                        },
                        !dialog.busy,
                        20.0,
                    );
                    let label = if !dialog.advanced && dialog.temporary_only {
                        tr!("advanced-temporary")
                    } else {
                        tr!("advanced")
                    };
                    let color = if !dialog.advanced && dialog.temporary_only {
                        theme::ROSE_LIGHT
                    } else {
                        theme::TEXT_MUTED
                    };
                    let link = ui.add_enabled(
                        !dialog.busy,
                        egui::Button::new(RichText::new(label).color(color)).frame(false),
                    );
                    if chevron.clicked() || link.clicked() {
                        dialog.advanced = !dialog.advanced;
                    }
                });
                if dialog.advanced && dialog.kind == RuleInputKind::Process {
                    let available = full_path_available(dialog);
                    let mut match_path = dialog.match_mode == ProcessMatchMode::Path;
                    let response = widgets::toggle_row(
                        ui,
                        tr!("match-by-full-path"),
                        tr!("full-path-detail"),
                        &mut match_path,
                        available && !dialog.busy,
                    );
                    if !available {
                        response.on_hover_text(tr!("path-unavailable"));
                    }
                    if match_path != (dialog.match_mode == ProcessMatchMode::Path) {
                        dialog.set_process_match_mode(if match_path {
                            ProcessMatchMode::Path
                        } else {
                            ProcessMatchMode::Name
                        });
                    }
                }
                if dialog.advanced && dialog.editing.is_none() {
                    let response = widgets::toggle_row(
                        ui,
                        tr!("temporary-only"),
                        tr!("temporary-dialog-hint"),
                        &mut dialog.temporary_only,
                        can_temporary && !dialog.busy,
                    );
                    if !can_temporary {
                        response.on_hover_text(tr!("temporary-needs-connection"));
                    }
                }
            }
            if let Some(error) = &dialog.error {
                ui.add_space(6.0);
                ui.add(egui::Label::new(RichText::new(error).color(theme::ERROR)).wrap());
            }
            ui.add_space(8.0);
            let (divider, _) =
                ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
            ui.painter().hline(
                divider.x_range(),
                divider.center().y,
                Stroke::new(1.0, theme::BORDER),
            );
            ui.add_space(8.0);
            let exceeds_list_limit = dialog.kind == RuleInputKind::List
                && dialog
                    .list
                    .as_ref()
                    .and_then(|id| lists.iter().find(|list| &list.id == id))
                    .is_some_and(|list| {
                        dialog.exceeds_list_limit(existing_list_rules, list.format.has_categories())
                    });
            let can_submit = valid
                && !exceeds_list_limit
                && !dialog.busy
                && (!dialog.temporary_only || can_temporary);
            let reason = if dialog.busy || dialog.error.is_some() || can_submit {
                None
            } else if exceeds_list_limit {
                Some(tr!("list-rule-limit"))
            } else if dialog.temporary_only && !can_temporary {
                Some(tr!("temporary-needs-connection"))
            } else {
                Some(match dialog.kind {
                    RuleInputKind::Process => tr!("choose-program"),
                    RuleInputKind::Domain => tr!("enter-site"),
                    RuleInputKind::List => tr!("choose-list-category"),
                    RuleInputKind::Ip => tr!("enter-ip"),
                })
            };
            egui::Sides::new().show(
                ui,
                |ui| {
                    if let Some(reason) = &reason {
                        ui.label(RichText::new(reason).small().color(theme::TEXT_DIM));
                    }
                },
                |ui| {
                    let label = if dialog.busy {
                        if dialog.editing.is_some() {
                            tr!("saving").to_owned()
                        } else {
                            tr!("adding-rule").to_owned()
                        }
                    } else if dialog.editing.is_some() {
                        tr!("save").to_owned()
                    } else if dialog.kind == RuleInputKind::Domain {
                        let domains =
                            rosetun_core::parse_domain_lines(&dialog.domains, dialog.subdomains);
                        crate::i18n::add_rules(domains.domains.len())
                    } else if dialog.kind == RuleInputKind::Ip {
                        let ips = rosetun_core::parse_ip_lines(&dialog.ips);
                        crate::i18n::add_rules(ips.addresses.len())
                    } else if dialog.kind == RuleInputKind::List
                        && dialog.selected_categories.len() > 1
                    {
                        crate::i18n::add_rules(dialog.selected_categories.len())
                    } else {
                        tr!("add-rule").to_owned()
                    };
                    let (submit, cancel) =
                        footer_buttons(ui, &label, can_submit, !dialog.busy, reason.as_deref());
                    if submit.clicked() {
                        actions.push(Action::SubmitAddRule);
                    }
                    if cancel.clicked() {
                        actions.push(Action::CancelAddRule);
                    }
                },
            );
        });
    if !dialog.busy && response.should_close() {
        actions.push(Action::CancelAddRule);
    }
}

fn category_matches<'a>(categories: &'a [String], query: &'a str) -> Vec<&'a str> {
    let query = query.trim();
    let custom = query.contains('@');
    let base = query.split_once('@').map_or(query, |(base, _)| base);
    let filter = base.to_ascii_lowercase();
    std::iter::once(query)
        .filter(|_| custom)
        .chain(categories.iter().filter_map(|category| {
            (category.to_ascii_lowercase().contains(&filter)
                && (!custom || !category.eq_ignore_ascii_case(query)))
            .then_some(category.as_str())
        }))
        .collect()
}

fn list_picker(
    ui: &mut egui::Ui,
    selected: &List,
    lists: &[List],
    choice: &mut Option<ListId>,
    enabled: bool,
) {
    let name = display::safe_text(&selected.name);
    let format = super::lists::format_name(selected.format);
    let detail = if selected.format.has_categories() {
        tr!(
            "list-added-categories",
            format = &format,
            count = selected.categories.len(),
            n = selected.categories.len().to_string()
        )
    } else {
        format
    };
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 38.0),
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::ComboBox, enabled, &name));
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect(
            rect,
            theme::RADIUS,
            theme::INPUT,
            Stroke::new(
                1.0,
                if response.hovered() && enabled {
                    theme::BORDER_STRONG
                } else {
                    theme::BORDER
                },
            ),
            egui::StrokeKind::Inside,
        );
        let detail_font = egui::TextStyle::Small.resolve(ui.style());
        let detail_galley = egui::WidgetText::from(
            RichText::new(&detail)
                .font(detail_font)
                .color(theme::TEXT_DIM),
        )
        .into_galley(
            ui,
            Some(egui::TextWrapMode::Truncate),
            (rect.width() * 0.45).max(40.0),
            egui::TextStyle::Small,
        );
        let detail_right = rect.right() - 34.0;
        let detail_width = detail_galley.size().x;
        painter.galley(
            egui::pos2(
                detail_right - detail_width,
                rect.center().y - detail_galley.size().y / 2.0,
            ),
            detail_galley,
            theme::TEXT_DIM,
        );
        let name_width = (rect.width() - 58.0 - detail_width).max(40.0);
        let name_galley = egui::WidgetText::from(RichText::new(name).strong()).into_galley(
            ui,
            Some(egui::TextWrapMode::Truncate),
            name_width,
            egui::TextStyle::Body,
        );
        painter.galley(
            egui::pos2(
                rect.left() + 12.0,
                rect.center().y - name_galley.size().y / 2.0,
            ),
            name_galley,
            theme::TEXT,
        );
        icons::paint(
            painter,
            egui::pos2(rect.right() - 16.0, rect.center().y),
            Icon::Chevron { open: true },
            theme::TEXT_DIM,
        );
    }
    let response = if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    };
    widgets::menu_popup(&response).show(|ui| {
        ui.set_min_width(rect.width());
        egui::ScrollArea::vertical()
            .max_height(240.0)
            .show(ui, |ui| {
                // `menu_item` takes its width from the ui's current extent; inside
                // the scroll area that starts empty, so the first row (the
                // selected list) was squeezed to nothing.
                ui.set_min_width(ui.available_width());
                for list in lists {
                    let note = super::lists::format_name(list.format);
                    if widgets::menu_item(
                        ui,
                        widgets::MenuItem {
                            label: &display::safe_text(&list.name),
                            enabled,
                            selected: selected.id == list.id,
                            danger: false,
                            note: Some(&note),
                        },
                    )
                    .clicked()
                    {
                        *choice = Some(list.id.clone());
                        ui.close();
                    }
                }
            });
    });
}

fn category_checkbox(
    ui: &mut egui::Ui,
    checked: &mut bool,
    label: &str,
    enabled: bool,
) -> egui::Response {
    ui.scope(|ui| {
        ui.spacing_mut().interact_size.y = CATEGORY_ROW_HEIGHT;
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
        let fill = if *checked { theme::ROSE } else { theme::CARD };
        let border = if *checked {
            theme::ROSE
        } else {
            theme::BORDER_STRONG
        };
        let check = if *checked {
            Color32::WHITE
        } else {
            theme::TEXT_MUTED
        };
        let widgets = &mut ui.visuals_mut().widgets;
        for visuals in [
            &mut widgets.noninteractive,
            &mut widgets.inactive,
            &mut widgets.hovered,
            &mut widgets.active,
        ] {
            visuals.corner_radius = egui::CornerRadius::same(0);
            visuals.bg_fill = fill;
            visuals.bg_stroke = Stroke::new(1.0, border);
            visuals.fg_stroke = Stroke::new(1.5, check);
        }
        ui.add_enabled(enabled, egui::Checkbox::new(checked, label))
    })
    .inner
}

fn category_row(ui: &mut egui::Ui, dialog: &mut AddRuleDialog, category: &str, attribute: bool) {
    let selected = dialog
        .selected_categories
        .iter()
        .any(|item| item == category);
    let mut checked = selected;
    let response = egui::Frame::new()
        .fill(if selected { theme::INPUT } else { theme::CARD })
        .corner_radius(theme::RADIUS_INNER)
        .inner_margin(egui::Margin::symmetric(4, 0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.set_min_height(CATEGORY_ROW_HEIGHT);
            ui.horizontal(|ui| {
                let response = category_checkbox(
                    ui,
                    &mut checked,
                    &display::safe_text(category),
                    !dialog.busy,
                );
                if attribute {
                    ui.label(
                        RichText::new(tr!("rule-list-attribute"))
                            .small()
                            .color(theme::TEXT_DIM),
                    );
                }
                response
            })
            .inner
        })
        .inner;
    if response.changed() {
        dialog.toggle_category(category);
    }
}

fn category_view(
    ui: &mut egui::Ui,
    dialog: &mut AddRuleDialog,
    matches: &[&str],
    custom: bool,
) -> egui::Response {
    egui::Frame::new()
        .fill(theme::CARD)
        .stroke(Stroke::new(1.0, theme::BORDER))
        .corner_radius(theme::RADIUS)
        .inner_margin(egui::Margin::same(4))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;
            egui::ScrollArea::vertical()
                .id_salt("rule_list_categories")
                .max_height(CATEGORY_VIEW_HEIGHT - 10.0)
                .auto_shrink([false, false])
                .show_rows(ui, CATEGORY_ROW_HEIGHT, matches.len(), |ui, rows| {
                    for index in rows {
                        category_row(ui, dialog, matches[index], custom && index == 0);
                    }
                });
        })
        .response
}

fn list_input(
    ui: &mut egui::Ui,
    dialog: &mut AddRuleDialog,
    lists: &[List],
    actions: &mut Vec<Action>,
) -> bool {
    if lists.is_empty() {
        ui.add(egui::Label::new(tr!("rule-list-empty")).wrap());
        if widgets::outline_button(ui, tr!("add-list"), !dialog.busy).clicked() {
            actions.push(Action::CancelAddRule);
            actions.push(Action::ShowLists);
            actions.push(Action::OpenAddList);
        }
        return false;
    }
    if dialog
        .list
        .as_ref()
        .is_none_or(|id| !lists.iter().any(|list| &list.id == id))
    {
        dialog.select_list(lists[0].id.clone());
    }
    let mut choice = dialog.list.clone();
    let selected = lists
        .iter()
        .find(|list| Some(&list.id) == dialog.list.as_ref())
        .unwrap_or(&lists[0]);
    ui.label(
        RichText::new(tr!("rule-list-select"))
            .small()
            .color(theme::TEXT_DIM),
    );
    list_picker(ui, selected, lists, &mut choice, !dialog.busy);
    if let Some(choice) = choice {
        dialog.select_list(choice);
    }
    let selected = lists
        .iter()
        .find(|list| Some(&list.id) == dialog.list.as_ref())
        .unwrap_or(&lists[0]);
    if selected.format.has_categories() {
        ui.add_space(8.0);
        let selected_count = dialog.selected_categories.len();
        egui::Sides::new().show(
            ui,
            |ui| {
                ui.label(
                    RichText::new(tr!("rule-list-categories"))
                        .small()
                        .color(theme::TEXT_DIM),
                );
            },
            |ui| {
                if selected_count == 0 {
                    ui.label(
                        RichText::new(tr!("rule-list-none-selected"))
                            .small()
                            .color(theme::TEXT_DIM),
                    );
                } else {
                    ui.horizontal(|ui| {
                        if widgets::link(ui, &tr!("rule-list-clear"), !dialog.busy).clicked() {
                            dialog.selected_categories.clear();
                            dialog.error = None;
                        }
                        ui.label(
                            RichText::new(tr!(
                                "rule-list-selected",
                                n = selected_count.to_string()
                            ))
                            .small()
                            .color(theme::ROSE_LIGHT),
                        );
                    });
                }
            },
        );
        let input = dialog.category_filter.trim().to_owned();
        let custom = input.contains('@');
        let matches = category_matches(&selected.categories, &input);
        let count = tr!(
            "rule-list-match-count",
            shown = matches.len() - usize::from(custom),
            total = selected.categories.len()
        );
        ui.add_enabled_ui(!dialog.busy, |ui| {
            let width = ui.available_width();
            widgets::search_field_with_suffix(
                ui,
                &mut dialog.category_filter,
                &tr!("rule-list-category-search-hint"),
                width,
                &count,
            )
        });
        category_view(ui, dialog, &matches, custom);
        ui.label(
            RichText::new(tr!("rule-list-per-category"))
                .small()
                .color(theme::TEXT_DIM),
        );
        ui.add_space(8.0);
    } else {
        dialog.selected_categories.clear();
    }
    !selected.format.has_categories() || !dialog.selected_categories.is_empty()
}

fn ip_input(ui: &mut egui::Ui, dialog: &mut AddRuleDialog, actions: &mut Vec<Action>) -> bool {
    ui.label(
        RichText::new(tr!("ip-label"))
            .small()
            .color(theme::TEXT_DIM),
    );
    let input = if dialog.editing.is_some() {
        ui.add_enabled(
            !dialog.busy,
            egui::TextEdit::singleline(&mut dialog.ips).desired_width(ui.available_width()),
        )
    } else {
        ui.add_enabled(
            !dialog.busy,
            egui::TextEdit::multiline(&mut dialog.ips)
                .desired_width(ui.available_width())
                .desired_rows(4)
                .font(FontId::monospace(14.0))
                .hint_text(tr!("ip-example")),
        )
    };
    if dialog.focus_input {
        input.request_focus();
        dialog.focus_input = false;
    }
    if input.changed() {
        dialog.error = None;
    }
    let parsed = rosetun_core::parse_ip_lines(&dialog.ips);
    if !parsed.errors.is_empty() {
        egui::ScrollArea::vertical()
            .id_salt("ip_line_errors")
            .max_height(92.0)
            .show(ui, |ui| {
                for error in parsed.errors.iter().take(3) {
                    let message = match &error.error {
                        rosetun_core::IpCidrError::Invalid => tr!("ip-invalid"),
                        rosetun_core::IpCidrError::HostBits { corrected } => {
                            tr!("ip-host-bits", corrected = corrected)
                        }
                    };
                    ui.label(
                        RichText::new(crate::i18n::line_error(error.line, &message))
                            .small()
                            .color(theme::ERROR),
                    );
                }
                if parsed.errors.len() > 3 {
                    ui.label(
                        RichText::new(crate::i18n::more_errors(parsed.errors.len() - 3))
                            .small()
                            .color(theme::ERROR),
                    );
                }
                if parsed
                    .errors
                    .iter()
                    .any(|error| matches!(error.error, rosetun_core::IpCidrError::HostBits { .. }))
                    && widgets::link(ui, &tr!("ip-fix"), !dialog.busy).clicked()
                {
                    actions.push(Action::CorrectRuleIps);
                }
            });
    }
    if dialog.local_ip_warning() {
        ui.add(
            egui::Label::new(
                RichText::new(tr!("ip-local-warning"))
                    .small()
                    .color(theme::ROSE_LIGHT),
            )
            .wrap(),
        );
        if widgets::link(ui, &tr!("allow-lan"), !dialog.busy).clicked() {
            actions.push(Action::OpenLanSettings);
        }
    }
    !parsed.addresses.is_empty()
        && parsed.errors.is_empty()
        && (dialog.editing.is_none() || parsed.addresses.len() == 1)
}

fn domain_input(ui: &mut egui::Ui, dialog: &mut AddRuleDialog) -> bool {
    ui.label(
        RichText::new(tr!("sites-label"))
            .small()
            .color(theme::TEXT_DIM),
    );
    let input = if dialog.editing.is_some() {
        ui.add_enabled(
            !dialog.busy,
            egui::TextEdit::singleline(&mut dialog.domains).desired_width(ui.available_width()),
        )
    } else {
        ui.add_enabled(
            !dialog.busy,
            egui::TextEdit::multiline(&mut dialog.domains)
                .desired_width(ui.available_width())
                .desired_rows(5)
                .font(FontId::monospace(14.0))
                .hint_text(constants::SITES_EXAMPLE),
        )
    };
    if dialog.focus_input {
        input.request_focus();
        dialog.focus_input = false;
    }
    if input.changed() {
        dialog.error = None;
    }
    widgets::toggle_row(
        ui,
        tr!("include-subdomains"),
        tr!("include-subdomains-detail"),
        &mut dialog.subdomains,
        !dialog.busy,
    );
    let parsed = rosetun_core::parse_domain_lines(&dialog.domains, dialog.subdomains);
    if dialog.unchanged_domain().is_some() {
        return true;
    }
    for error in parsed.errors.iter().take(3) {
        let message = errors::rule_input(crate::i18n::language(), &error.error);
        ui.label(
            RichText::new(crate::i18n::line_error(error.line, &message))
                .small()
                .color(theme::ERROR),
        );
    }
    if parsed.errors.len() > 3 {
        ui.label(
            RichText::new(crate::i18n::more_errors(parsed.errors.len() - 3))
                .small()
                .color(theme::ERROR),
        );
    }
    !parsed.domains.is_empty()
        && parsed.errors.is_empty()
        && (dialog.editing.is_none() || parsed.domains.len() == 1)
}

fn process_input(ui: &mut egui::Ui, dialog: &mut AddRuleDialog, actions: &mut Vec<Action>) -> bool {
    ui.horizontal(|ui| {
        let width = ui.available_width() - 38.0 - ui.spacing().item_spacing.x;
        let input = ui
            .add_enabled_ui(!dialog.busy, |ui| {
                widgets::search_field(ui, &mut dialog.process_filter, &tr!("find-app"), width)
            })
            .inner;
        if dialog.focus_input {
            input.request_focus();
            dialog.focus_input = false;
        }
        if input.changed() {
            dialog.selected_process = None;
            dialog.process.clear();
            #[cfg(windows)]
            {
                dialog.browsed = None;
            }
            update_process_match_mode(&mut dialog.match_mode, &dialog.process_filter);
            dialog.advanced |= dialog.match_mode == ProcessMatchMode::Path;
            dialog.error = None;
        }
        if icons::icon_button_sized(
            ui,
            Icon::Refresh,
            !dialog.busy && dialog.load_request.is_none(),
            38.0,
        )
        .on_hover_text(tr!("refresh"))
        .clicked()
        {
            actions.push(Action::RefreshProcesses);
        }
    });
    if let Some(error) = &dialog.processes_error {
        ui.label(RichText::new(error).small().color(theme::ERROR));
    }
    if dialog.load_request.is_some() {
        ui.label(
            RichText::new(tr!("loading-processes"))
                .small()
                .color(theme::TEXT_DIM),
        );
    }
    let total: usize = dialog.processes.iter().map(|group| group.count).sum();
    let filtering = !dialog.process_filter.trim().is_empty();
    if !filtering {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 16.0;
            if process_tab(ui, &tr!("open-tab"), !dialog.show_all, !dialog.busy).clicked() {
                dialog.show_all = false;
            }
            if process_tab(
                ui,
                &crate::i18n::all_processes(total),
                dialog.show_all,
                !dialog.busy,
            )
            .clicked()
            {
                dialog.show_all = true;
            }
        });
    }
    let shown: usize = dialog
        .processes
        .iter()
        .filter(|group| {
            if filtering {
                process_matches_filter(group, &dialog.process_filter)
            } else {
                dialog.show_all || group.windowed
            }
        })
        .map(|group| group.count)
        .sum();
    if filtering {
        ui.label(
            RichText::new(crate::i18n::found(shown))
                .small()
                .color(theme::TEXT_DIM),
        );
    }
    let list_height = (ui.available_height() - 36.0).clamp(0.0, MAX_PROCESS_LIST);
    egui::ScrollArea::vertical()
        .id_salt("running_processes")
        .max_height(list_height)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = PROCESS_ROW_GAP;
            let typed = dialog.process_filter.trim();
            let manual = filtering
                && rosetun_core::parse_process_input(typed).is_ok()
                && (dialog.editing.is_some()
                    || (dialog.selected_process.is_none() && !dialog.process.is_empty())
                    || !dialog
                        .processes
                        .iter()
                        .any(|group| group.name.eq_ignore_ascii_case(typed)));
            if manual {
                let selected = dialog.selected_process.is_none() && !dialog.process.is_empty();
                let response = process_row(
                    ui,
                    &display::safe_text(typed),
                    &tr!("typed-process"),
                    "+",
                    theme::BORDER_STRONG,
                    selected,
                    !dialog.busy,
                );
                if response.clicked() && !dialog.busy {
                    #[cfg(windows)]
                    let chosen = if dialog.match_mode == ProcessMatchMode::Path {
                        dialog
                            .browsed
                            .as_ref()
                            .map(|path| path.to_string_lossy().into_owned())
                            .unwrap_or_else(|| typed.to_owned())
                    } else {
                        typed.to_owned()
                    };
                    #[cfg(not(windows))]
                    let chosen = typed.to_owned();
                    dialog.process = chosen;
                    dialog.selected_process = None;
                    update_process_match_mode(&mut dialog.match_mode, &dialog.process);
                    dialog.advanced |= dialog.match_mode == ProcessMatchMode::Path;
                    dialog.error = None;
                }
            }
            let mut selection = None;
            for (index, group) in dialog.processes.iter().enumerate() {
                if !process_matches_filter(group, &dialog.process_filter)
                    || (!filtering && !dialog.show_all && !group.windowed)
                {
                    continue;
                }
                let path = group.path.as_ref().map_or_else(
                    || tr!("path-unavailable").to_owned(),
                    |path| path.to_string_lossy().into_owned(),
                );
                let name = if group.count > 1 {
                    i18n::process_copies(&display::safe_text(&group.name), group.count)
                } else {
                    display::safe_text(&group.name)
                };
                let tile = group
                    .name
                    .chars()
                    .next()
                    .unwrap_or('?')
                    .to_uppercase()
                    .to_string();
                let response = process_row(
                    ui,
                    &name,
                    &display::safe_text(&path),
                    &display::safe_text(&tile),
                    tile_color(&group.name),
                    dialog.selected_process == Some(index),
                    !dialog.busy,
                );
                if response.clicked() && !dialog.busy {
                    selection = Some(index);
                }
            }
            if let Some(index) = selection {
                select_process(dialog, index);
            }
            if shown == 0 && !manual && dialog.processes_loaded {
                ui.label(
                    RichText::new(if filtering {
                        tr!("no-processes-match")
                    } else {
                        tr!("no-running-processes")
                    })
                    .color(theme::TEXT_DIM),
                );
            }
        });
    egui::Sides::new().show(
        ui,
        |_| {},
        |ui| {
            #[cfg(windows)]
            {
                ui.spacing_mut().interact_size.y = 32.0;
                if widgets::outline_button(ui, tr!("browse"), !dialog.busy && !dialog.browsing)
                    .clicked()
                {
                    actions.push(Action::BrowseExecutable);
                }
            }
            #[cfg(not(windows))]
            let _ = (ui, actions);
        },
    );
    rosetun_core::parse_process_input(&dialog.process).is_ok()
}

fn process_tab(ui: &mut egui::Ui, label: &str, selected: bool, enabled: bool) -> egui::Response {
    let enabled = enabled && ui.is_enabled();
    let sense = if enabled {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let font = egui::TextStyle::Body.resolve(ui.style());
    let width = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font.clone(), theme::TEXT)
        .size()
        .x;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(width, ui.text_style_height(&egui::TextStyle::Body) + 8.0),
        sense,
    );
    if ui.is_rect_visible(rect) {
        let color = if !enabled {
            theme::DISABLED
        } else if selected {
            theme::TEXT
        } else if response.hovered() {
            theme::TEXT_MUTED
        } else {
            theme::TEXT_DIM
        };
        ui.painter().text(
            rect.min + egui::vec2(0.0, 2.0),
            egui::Align2::LEFT_TOP,
            label,
            font,
            color,
        );
        if selected {
            ui.painter().rect_filled(
                egui::Rect::from_min_size(
                    egui::pos2(rect.left(), rect.bottom() - 2.0),
                    egui::vec2(width, 2.0),
                ),
                0.0,
                theme::ROSE,
            );
        }
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, enabled, selected, label)
    });
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

fn select_process(dialog: &mut AddRuleDialog, index: usize) {
    let group = &dialog.processes[index];
    dialog.selected_process = Some(index);
    #[cfg(windows)]
    {
        dialog.browsed = None;
    }
    if dialog.match_mode == ProcessMatchMode::Path && group.path.is_none() {
        dialog.match_mode = ProcessMatchMode::Name;
    }
    dialog.process = match dialog.match_mode {
        ProcessMatchMode::Name => group.name.clone(),
        ProcessMatchMode::Path => group.path.as_ref().unwrap().to_string_lossy().into_owned(),
    };
    dialog.error = None;
}

fn process_row(
    ui: &mut egui::Ui,
    name: &str,
    detail: &str,
    tile: &str,
    tile_fill: Color32,
    selected: bool,
    enabled: bool,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), PROCESS_ROW_HEIGHT),
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    let fill = if selected {
        theme::INPUT
    } else if response.hovered() && enabled {
        theme::BORDER
    } else {
        Color32::TRANSPARENT
    };
    ui.painter().rect(
        rect,
        egui::CornerRadius::same(theme::RADIUS),
        fill,
        Stroke::new(
            1.0,
            if selected {
                theme::ROSE_DARK
            } else {
                theme::BORDER
            },
        ),
        egui::StrokeKind::Inside,
    );
    let tile_rect = egui::Rect::from_min_size(
        egui::pos2(rect.left() + 10.0, rect.center().y - 14.0),
        egui::vec2(28.0, 28.0),
    );
    ui.painter().rect_filled(
        tile_rect,
        egui::CornerRadius::same(theme::RADIUS),
        tile_fill,
    );
    let semibold = FontFamily::Name(theme::UI_SEMIBOLD.into());
    ui.painter().text(
        tile_rect.center(),
        egui::Align2::CENTER_CENTER,
        tile,
        FontId::new(13.0, semibold.clone()),
        theme::TEXT,
    );
    let text_painter = ui.painter().with_clip_rect(egui::Rect::from_min_max(
        egui::pos2(tile_rect.right() + 10.0, rect.top()),
        egui::pos2(rect.right() - 10.0, rect.bottom()),
    ));
    text_painter.text(
        egui::pos2(tile_rect.right() + 10.0, rect.top() + 13.0),
        egui::Align2::LEFT_CENTER,
        name,
        FontId::new(13.0, semibold),
        if selected {
            theme::ROSE_LIGHT
        } else {
            theme::TEXT
        },
    );
    text_painter.text(
        egui::pos2(tile_rect.right() + 10.0, rect.top() + 31.0),
        egui::Align2::LEFT_CENTER,
        detail,
        egui::TextStyle::Small.resolve(ui.style()).clone(),
        theme::TEXT_DIM,
    );
    let response = response.on_hover_text(display::safe_text(detail));
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// A muted tile colour picked from the name, so a process keeps its colour.
fn tile_color(name: &str) -> Color32 {
    let palette = [
        Color32::from_rgb(0x4A, 0x3A, 0x6B),
        Color32::from_rgb(0x3A, 0x5A, 0x4A),
        Color32::from_rgb(0x2E, 0x40, 0x58),
        Color32::from_rgb(0x5A, 0x3A, 0x44),
    ];
    let index = name
        .chars()
        .flat_map(char::to_lowercase)
        .fold(0_usize, |sum, ch| (sum + ch as usize) % palette.len());
    palette[index]
}

fn full_path_available(dialog: &AddRuleDialog) -> bool {
    let available = dialog
        .selected_process
        .and_then(|index| dialog.processes.get(index))
        .and_then(|group| group.path.as_ref())
        .is_some()
        || matches!(
            rosetun_core::parse_process_input(&dialog.process),
            Ok(ProcessMatch::Path(_))
        )
        || matches!(
            rosetun_core::parse_process_input(&dialog.process_filter),
            Ok(ProcessMatch::Path(_))
        );
    #[cfg(windows)]
    let available = available || dialog.browsed.is_some();
    available
}

fn destination_hint_height(dialog: &AddRuleDialog) -> f32 {
    if matches!(dialog.target, RuleDestination::NewExit(_)) {
        DESTINATION_HINT_HEIGHT
    } else {
        0.0
    }
}

/// "Where to send it": one field whose list opens over the dialog.
fn destination_picker(ui: &mut egui::Ui, dialog: &mut AddRuleDialog, config: &AppConfig) {
    let enabled = !dialog.busy && ui.is_enabled();
    let label = if dialog.target == RuleDestination::Proxy {
        tr!("where-proxy-main")
    } else {
        destination_label(&dialog.target, &config.exits)
    };
    let color = if enabled {
        destination_color(&dialog.target)
    } else {
        theme::DISABLED
    };
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), DESTINATION_HEIGHT),
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::ComboBox, enabled, &label));
    let open = egui::Popup::is_id_open(ui.ctx(), destination_popup_id());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect(
            rect,
            theme::RADIUS,
            theme::INPUT,
            Stroke::new(
                1.0,
                if open {
                    theme::ROSE
                } else if response.hovered() && enabled {
                    theme::BORDER_STRONG
                } else {
                    theme::BORDER
                },
            ),
            egui::StrokeKind::Inside,
        );
        painter.circle_filled(egui::pos2(rect.left() + 14.0, rect.center().y), 3.5, color);
        let galley = egui::WidgetText::from(RichText::new(&label).color(color)).into_galley(
            ui,
            Some(egui::TextWrapMode::Truncate),
            (rect.width() - 62.0).max(40.0),
            egui::TextStyle::Body,
        );
        painter.galley(
            egui::pos2(rect.left() + 26.0, rect.center().y - galley.size().y / 2.0),
            galley,
            color,
        );
        icons::paint(
            painter,
            egui::pos2(rect.right() - 16.0, rect.center().y),
            Icon::Chevron { open: true },
            if enabled {
                theme::TEXT_DIM
            } else {
                theme::DISABLED
            },
        );
    }
    if let RuleDestination::NewExit(NewExit::Country { name, .. } | NewExit::Node { name, .. }) =
        &dialog.target
    {
        let hint = tr!("where-new-exit", name = display::safe_text(name));
        ui.add(egui::Label::new(RichText::new(&hint).small().color(theme::TEXT_DIM)).truncate())
            .on_hover_text(hint);
    }
    if !enabled {
        return;
    }
    let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
    let screen = ui.ctx().content_rect();
    let room = (screen.bottom() - rect.bottom()).max(rect.top() - screen.top());
    let mut chosen = None;
    widgets::menu_popup(&response)
        .id(destination_popup_id())
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
        .width(rect.width())
        .show(|ui| {
            ui.set_min_width(rect.width());
            egui::ScrollArea::vertical()
                .max_height((room - DESTINATION_POPUP_MARGIN).max(MIN_DESTINATION_POPUP))
                .show(ui, |ui| {
                    // As in `list_picker`: `menu_item` takes the width the ui already spans.
                    ui.set_min_width(ui.available_width());
                    chosen = destination_menu(ui, dialog, config);
                });
        });
    if let Some(destination) = chosen {
        dialog.target = destination;
        dialog.error = None;
    }
}

pub(crate) fn destination_popup_id() -> egui::Id {
    egui::Id::new("rule_destination")
}

fn destination_item(
    ui: &mut egui::Ui,
    label: &str,
    color: Color32,
    enabled: bool,
    selected: bool,
) -> bool {
    // `menu_item` takes the width its ui already spans, and a scope starts empty.
    let width = ui.min_rect().width().max(ui.available_width());
    let item = ui
        .scope(|ui| {
            ui.set_min_width(width);
            ui.spacing_mut().button_padding.x = 26.0;
            ui.visuals_mut().override_text_color = Some(color);
            widgets::menu_item(
                ui,
                widgets::MenuItem {
                    label,
                    enabled,
                    selected,
                    danger: false,
                    note: None,
                },
            )
        })
        .inner;
    if ui.is_rect_visible(item.rect) {
        ui.painter().circle_filled(
            egui::pos2(item.rect.left() + 14.0, item.rect.center().y),
            3.5,
            if enabled { color } else { theme::DISABLED },
        );
    }
    if item.clicked() {
        ui.close();
        return true;
    }
    false
}

fn destination_section(ui: &mut egui::Ui, title: String) {
    ui.add_space(4.0);
    ui.separator();
    ui.label(RichText::new(title).small().color(theme::TEXT_DIM));
}

fn destination_note(ui: &mut egui::Ui, note: String) {
    ui.add(egui::Label::new(RichText::new(note).small().color(theme::TEXT_MUTED)).wrap());
}

fn exits_full_note(ui: &mut egui::Ui) {
    destination_note(
        ui,
        tr!(
            "where-exits-full",
            count = rosetun_ipc::MAX_EXTRA_NODES.to_string()
        ),
    );
}

fn destination_menu(
    ui: &mut egui::Ui,
    dialog: &mut AddRuleDialog,
    config: &AppConfig,
) -> Option<RuleDestination> {
    let mut chosen = None;
    for target in [RuleTarget::Proxy, RuleTarget::Direct, RuleTarget::Block] {
        let destination = RuleDestination::from(target);
        let selected = dialog.target == destination;
        if destination_item(
            ui,
            &target_label(target),
            target_color(target),
            true,
            selected,
        ) {
            chosen = Some(destination);
        }
    }
    if !config.exits.is_empty() {
        destination_section(ui, tr!("where-section-exits"));
        for exit in &config.exits {
            let name = display::safe_text(&exit.name);
            let label = match destinations::exit_country(exit) {
                Some(code) => format!("{name} · {}", code.as_str()),
                None => name,
            };
            let destination = RuleDestination::Exit(exit.id.clone());
            let selected = dialog.target == destination;
            if destination_item(ui, &label, theme::EXIT, true, selected) {
                chosen = Some(destination);
            }
        }
    }
    let full = destinations::exits_full(config);
    let countries = destinations::new_countries(config);
    let has_country_exit = config
        .exits
        .iter()
        .any(|exit| matches!(exit.target, ExitTarget::Country(_)));
    if !countries.is_empty() || has_country_exit {
        destination_section(ui, tr!("where-section-country"));
        if full {
            exits_full_note(ui);
        }
        if countries.is_empty() {
            destination_note(ui, tr!("where-country-none"));
        }
        for code in countries {
            let name = i18n::country_name(&code);
            let selected = matches!(
                &dialog.target,
                RuleDestination::NewExit(NewExit::Country { code: picked, .. }) if picked == &code
            );
            let label = format!("{name} · {}", code.as_str());
            if destination_item(ui, &label, theme::EXIT, !full, selected) {
                chosen = Some(RuleDestination::NewExit(NewExit::Country { code, name }));
            }
        }
    }
    if config
        .subscriptions
        .iter()
        .any(|subscription| !subscription.nodes.is_empty())
    {
        destination_section(ui, tr!("where-section-node"));
        if full {
            exits_full_note(ui);
        }
        ui.add_enabled(
            !full,
            egui::TextEdit::singleline(&mut dialog.node_search)
                .desired_width(ui.available_width())
                .hint_text(tr!("where-node-search")),
        );
        let nodes = destinations::matching_nodes(config, &dialog.node_search);
        if nodes.is_empty() {
            destination_note(ui, tr!("where-node-none"));
        }
        for node in nodes {
            let selected = match (&dialog.target, node.exit) {
                (RuleDestination::Exit(picked), Some(exit)) => picked == exit,
                (RuleDestination::NewExit(NewExit::Node { selection, .. }), _) => {
                    selection == &node.selection
                }
                _ => false,
            };
            let enabled = !full || node.exit.is_some();
            let label = display::safe_text(node.name);
            if destination_item(ui, &label, theme::EXIT, enabled, selected) {
                chosen = Some(match node.exit {
                    Some(exit) => RuleDestination::Exit(exit.clone()),
                    None => RuleDestination::NewExit(NewExit::Node {
                        selection: node.selection,
                        name: node.name.to_owned(),
                    }),
                });
            }
        }
    }
    chosen
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PROCESS_LIST, MIN_PROCESS_LIST, PROCESS_FOOTER_HEIGHT, process_body_height, tile_color,
    };

    #[test]
    fn process_body_fits_available_space_with_bounds() {
        assert_eq!(process_body_height(250.0, 500.0, false), 250.0);
        assert_eq!(
            process_body_height(250.0, 900.0, false),
            PROCESS_FOOTER_HEIGHT + MAX_PROCESS_LIST
        );
        assert_eq!(
            process_body_height(250.0, 300.0, false),
            PROCESS_FOOTER_HEIGHT + MIN_PROCESS_LIST
        );
        assert_eq!(
            process_body_height(250.0, 300.0, true),
            PROCESS_FOOTER_HEIGHT + 44.0
        );
    }

    #[test]
    fn modal_fits_compact_and_standard_windows() {
        use super::*;
        use rosetun_config::{RuleId, RuleSetId};

        for (width, height, advanced, site, can_temporary, temporary, editing, error) in [
            (960.0, 640.0, false, false, true, true, false, false),
            (960.0, 640.0, true, false, true, true, false, false),
            (960.0, 640.0, false, true, true, true, false, false),
            (960.0, 640.0, true, true, true, true, false, false),
            (960.0, 640.0, true, false, false, true, false, false),
            (960.0, 640.0, false, false, true, true, false, true),
            (960.0, 640.0, true, false, true, false, true, false),
            (1200.0, 780.0, false, false, true, false, false, false),
            (1200.0, 780.0, true, false, true, true, false, false),
            (1200.0, 780.0, false, true, false, true, false, false),
        ] {
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
            dialog.advanced = advanced;
            dialog.temporary_only = temporary;
            if error {
                dialog.error = Some("This rule is already in the set.".into());
            }
            if editing {
                dialog.editing = Some(RuleId::new("1"));
            }
            if site {
                dialog.kind = RuleInputKind::Domain;
                dialog.domains = "youtube.com\n192.168.1.1\nru\n127.0.0.1\ninvalid host".into();
            } else {
                dialog.process = r"C:\Apps\Tool.exe".into();
                dialog.match_mode = ProcessMatchMode::Path;
            }
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, height),
                    )),
                    ..egui::RawInput::default()
                },
                |ctx| {
                    show(
                        ctx,
                        &mut dialog,
                        &AppConfig::default(),
                        can_temporary,
                        0,
                        &mut Vec::new(),
                    )
                },
            );
            output.textures_delta.clear();
            assert_eq!(dialog.temporary_only, can_temporary && temporary);
            let rect = ctx
                .memory(|memory| memory.area_rect(egui::Id::new("add_rule")))
                .unwrap();
            assert!(rect.top() >= 0.0, "{rect:?} in {width}×{height}");
            assert!(rect.bottom() <= height, "{rect:?} in {width}×{height}");
        }
    }

    #[test]
    fn list_dialog_fits_compact_window_with_many_categories() {
        use super::*;
        use rosetun_config::{List, ListFormat, ListId, ListSource, RuleSetId};

        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
        dialog.kind = RuleInputKind::List;
        dialog.advanced = true;
        dialog.selected_categories = ["category1", "category2", "category3"]
            .map(str::to_owned)
            .to_vec();
        dialog.category_filter = "category@cn".into();
        let list = List {
            id: ListId::new("1"),
            name: "Example".into(),
            source: ListSource::File {
                original_name: "geosite.dat".into(),
            },
            format: ListFormat::GeoSite,
            updated_at: None,
            size: None,
            sha256: None,
            categories: (0..1_000).map(|index| format!("category{index}")).collect(),
        };
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(960.0, 640.0),
                )),
                ..egui::RawInput::default()
            },
            |ctx| {
                show(
                    ctx,
                    &mut dialog,
                    &AppConfig {
                        lists: vec![list.clone()],
                        ..AppConfig::default()
                    },
                    true,
                    0,
                    &mut Vec::new(),
                )
            },
        );
        output.textures_delta.clear();
        let rect = ctx
            .memory(|memory| memory.area_rect(egui::Id::new("add_rule")))
            .unwrap();
        assert!(rect.top() >= 0.0 && rect.bottom() <= 640.0, "{rect:?}");
    }

    #[test]
    fn ip_modal_fits_compact_window_with_errors() {
        use super::*;
        use rosetun_config::RuleSetId;

        for advanced in [false, true] {
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
            dialog.kind = RuleInputKind::Ip;
            dialog.advanced = advanced;
            dialog.ips = "192.0.2.5/24\nexample.com\n2001:db8::1/32\n198.51.100.0/33".into();
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(960.0, 640.0),
                    )),
                    ..egui::RawInput::default()
                },
                |ctx| {
                    show(
                        ctx,
                        &mut dialog,
                        &AppConfig::default(),
                        true,
                        0,
                        &mut Vec::new(),
                    )
                },
            );
            output.textures_delta.clear();
            let rect = ctx
                .memory(|memory| memory.area_rect(egui::Id::new("add_rule")))
                .unwrap();
            assert!(rect.top() >= 0.0 && rect.bottom() <= 640.0, "{rect:?}");
        }
    }

    #[test]
    fn modal_fits_compact_window_with_open_destination_list() {
        use super::*;
        use crate::destinations::tests::{config, exit};
        use rosetun_config::{CountryCode, RuleSetId};

        let names: Vec<(String, String)> = ["NL", "DE", "JP", "US", "GB", "FR", "SE", "FI"]
            .iter()
            .flat_map(|code| {
                (0..4).map(move |index| (format!("{code}{index}"), format!("{code} {index}")))
            })
            .collect();
        let nodes: Vec<(&str, &str)> = names
            .iter()
            .map(|(id, name)| (id.as_str(), name.as_str()))
            .collect();
        let exits = (0..6)
            .map(|index| {
                exit(
                    &index.to_string(),
                    ExitTarget::Country(CountryCode::parse("NL").unwrap()),
                )
            })
            .collect();
        let config = config(&nodes, exits);
        for (width, height) in [(960.0, 640.0), (1200.0, 780.0)] {
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
            dialog.kind = RuleInputKind::Domain;
            dialog.target = RuleDestination::NewExit(NewExit::Country {
                code: CountryCode::parse("DE").unwrap(),
                name: "Germany".into(),
            });
            let input = || egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, height),
                )),
                ..egui::RawInput::default()
            };
            let run = |dialog: &mut AddRuleDialog| {
                let mut output = ctx.run_ui(input(), |ctx| {
                    show(ctx, dialog, &config, false, 0, &mut Vec::new())
                });
                output.textures_delta.clear();
            };
            run(&mut dialog);
            egui::Popup::open_id(&ctx, destination_popup_id());
            for _ in 0..3 {
                run(&mut dialog);
            }
            let modal = ctx
                .memory(|memory| memory.area_rect(egui::Id::new("add_rule")))
                .unwrap();
            let popup = ctx
                .memory(|memory| memory.area_rect(destination_popup_id()))
                .expect("the destination list is open");
            for rect in [modal, popup] {
                assert!(rect.top() >= 0.0, "{rect:?} in {width}×{height}");
                assert!(rect.bottom() <= height, "{rect:?} in {width}×{height}");
            }
            assert!(egui::Popup::is_id_open(&ctx, destination_popup_id()));
        }
    }

    #[test]
    fn destination_items_span_the_open_menu() {
        use super::*;
        use crate::destinations::tests::{config, exit};
        use rosetun_config::{CountryCode, RuleSetId};

        let nodes = [("nl", "NL One"), ("de", "DE Two"), ("plain", "Plain")];
        let exits = vec![exit(
            "1",
            ExitTarget::Country(CountryCode::parse("NL").unwrap()),
        )];
        let config = config(&nodes, exits);
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
        dialog.kind = RuleInputKind::Domain;
        let run = |dialog: &mut AddRuleDialog| {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1200.0, 900.0),
                )),
                ..egui::RawInput::default()
            };
            let mut output = ctx.run_ui(input, |ctx| {
                show(ctx, dialog, &config, false, 0, &mut Vec::new())
            });
            output.textures_delta.clear();
            output.shapes
        };
        run(&mut dialog);
        egui::Popup::open_id(&ctx, destination_popup_id());
        let mut shapes = Vec::new();
        for _ in 0..3 {
            shapes = run(&mut dialog);
        }
        let menu = ctx
            .memory(|memory| memory.area_rect(destination_popup_id()))
            .expect("the destination list is open");
        // The frame takes a 4-point margin and a 1-point stroke on each side.
        let content = menu.shrink(5.0);
        let mut selected = Vec::new();
        let mut texts = Vec::new();
        for shape in &shapes {
            match &shape.shape {
                // Only the selected item fills its rect while nothing is hovered.
                egui::Shape::Rect(rect)
                    if rect.rect.height() == 30.0 && menu.contains_rect(rect.rect) =>
                {
                    selected.push(rect.rect);
                }
                egui::Shape::Text(text) if menu.contains(text.pos) => {
                    texts.push(text.galley.text().to_owned());
                }
                _ => {}
            }
        }
        // The selected item paints its whole rect; a zero-width item painted nothing visible.
        assert_eq!(selected.len(), 1, "{selected:?}");
        assert_eq!(selected[0].x_range(), content.x_range(), "{menu:?}");
        assert!(!texts.iter().any(|text| text.contains('…')), "{texts:?}");
        for label in [
            target_label(RuleTarget::Proxy),
            target_label(RuleTarget::Direct),
            target_label(RuleTarget::Block),
            "Example exit · NL".to_owned(),
            format!("{} · DE", i18n::country_name(&CountryCode::parse("DE").unwrap())),
            "NL One".to_owned(),
        ] {
            assert!(texts.contains(&label), "{label} in {texts:?}");
        }
    }

    #[test]
    fn modal_fits_width_at_minimum_window_scales() {
        use super::*;
        use rosetun_config::RuleSetId;

        for scale in [1.0, 1.25, 1.5] {
            let width = 960.0 / scale;
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
            dialog.kind = RuleInputKind::Domain;
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 640.0 / scale),
                    )),
                    ..egui::RawInput::default()
                },
                |ctx| {
                    show(
                        ctx,
                        &mut dialog,
                        &AppConfig::default(),
                        false,
                        0,
                        &mut Vec::new(),
                    )
                },
            );
            output.textures_delta.clear();
            let rect = ctx
                .memory(|memory| memory.area_rect(egui::Id::new("add_rule")))
                .unwrap();
            assert!(
                rect.left() >= 0.0 && rect.right() <= width,
                "{scale}: {rect:?}"
            );
        }
    }

    #[test]
    fn category_view_has_fixed_framed_height() {
        use super::*;
        use rosetun_config::RuleSetId;

        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
        let categories: Vec<_> = (0..1_000).map(|index| format!("category{index}")).collect();
        let matches: Vec<_> = categories.iter().map(String::as_str).collect();
        let mut height = 0.0;
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.set_width(DIALOG_WIDTH);
                height = category_view(ui, &mut dialog, &matches, false)
                    .rect
                    .height();
            });
        });
        output.textures_delta.clear();
        assert_eq!(height, CATEGORY_VIEW_HEIGHT);
    }

    #[test]
    fn category_checkboxes_are_square_with_distinct_selection_colours() {
        use super::*;

        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut unchecked = false;
        let mut checked = true;
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                category_checkbox(ui, &mut unchecked, "alpha", true);
                category_checkbox(ui, &mut checked, "beta", true);
            });
        });
        let rectangles: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Rect(rect) => Some(rect),
                _ => None,
            })
            .collect();
        assert!(rectangles.iter().any(|rect| {
            rect.corner_radius == egui::CornerRadius::same(0)
                && rect.fill == theme::CARD
                && rect.stroke.color == theme::BORDER_STRONG
        }));
        assert!(rectangles.iter().any(|rect| {
            rect.corner_radius == egui::CornerRadius::same(0) && rect.fill == theme::ROSE
        }));
        assert!(output.shapes.iter().any(|shape| matches!(
            &shape.shape,
            egui::Shape::Path(path) if path.stroke.color == egui::epaint::ColorMode::Solid(Color32::WHITE)
        )));
        output.textures_delta.clear();
    }

    #[test]
    fn selected_category_row_has_input_background() {
        use super::*;
        use rosetun_config::RuleSetId;

        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
        dialog.selected_categories.push("alpha".into());
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.set_width(DIALOG_WIDTH);
                category_row(ui, &mut dialog, "alpha", false);
            });
        });
        assert!(output.shapes.iter().any(|shape| matches!(
            &shape.shape,
            egui::Shape::Rect(rect) if rect.fill == theme::INPUT && rect.rect.width() > 100.0
        )));
        output.textures_delta.clear();
    }

    #[test]
    fn primary_action_precedes_cancel_visually() {
        use super::*;

        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let (_, (submit, cancel)) = egui::Sides::new().show(
                    ui,
                    |_| {},
                    |ui| footer_buttons(ui, &tr!("add-rule"), true, true, None),
                );
                assert!(submit.rect.right() < cancel.rect.left());
            });
        });
        output.textures_delta.clear();
    }

    #[test]
    fn category_search_keeps_all_matches_and_places_attribute_first() {
        use super::category_matches;

        let mut categories: Vec<_> = (0..1_500).map(|index| format!("google{index}")).collect();
        categories.push("google@cn".into());
        assert_eq!(category_matches(&categories, "").len(), 1_501);
        let matches = category_matches(&categories, "google@cn");
        assert_eq!(matches[0], "google@cn");
        assert_eq!(matches.len(), 1_501);
        assert_eq!(
            matches.iter().filter(|item| **item == "google@cn").count(),
            1
        );
    }

    #[test]
    fn advanced_is_available_only_when_options_exist() {
        use super::*;
        use rosetun_config::{RuleId, RuleSetId};

        let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
        for kind in [
            RuleInputKind::Process,
            RuleInputKind::Domain,
            RuleInputKind::List,
        ] {
            dialog.kind = kind;
            assert!(has_advanced(&dialog));
        }
        dialog.editing = Some(RuleId::new("rule"));
        assert!(!has_advanced(&dialog));
        dialog.kind = RuleInputKind::Domain;
        assert!(!has_advanced(&dialog));
        dialog.kind = RuleInputKind::Process;
        assert!(has_advanced(&dialog));
    }

    #[test]
    fn tile_colours_are_stable_and_case_insensitive() {
        assert_eq!(tile_color("Telegram.exe"), tile_color("Telegram.exe"));
        assert_eq!(tile_color("Telegram.exe"), tile_color("TELEGRAM.EXE"));
    }

    #[test]
    fn selecting_a_process_preserves_the_search_and_raw_matcher() {
        use super::select_process;
        use crate::rules::ProcessGroup;
        use rosetun_config::RuleSetId;

        let mut dialog = crate::state::AddRuleDialog::new(RuleSetId::new("set"));
        dialog.process_filter = "tele".into();
        dialog.processes.push(ProcessGroup {
            name: "Tele\u{202e}gram.exe".into(),
            path: None,
            count: 1,
            windowed: true,
        });
        select_process(&mut dialog, 0);
        assert_eq!(dialog.process_filter, "tele");
        assert_eq!(dialog.process, "Tele\u{202e}gram.exe");
        assert_eq!(dialog.selected_process, Some(0));
    }
}
