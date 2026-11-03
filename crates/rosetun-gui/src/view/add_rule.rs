use std::path::Path;

use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::{AppConfig, ExitTarget, List, ListId, ProcessMatch, RuleTarget};
use rosetun_core::{IpCidrError, NewExit, RuleDestination};

use crate::display;
use crate::errors;
use crate::icons::{self, Icon};
use crate::rules::{ProcessGroup, ProcessMatchMode, ProgramKey, process_matches_filter};
use crate::state::{
    Action, AddRuleDialog, AddressError, ChosenProgram, MAX_ADDRESSES, MAX_PROGRAMS, RecentSite,
    RuleInputKind,
};
use crate::view::rules::{destination_color, destination_label, target_color, target_label};
use crate::{constants, destinations, i18n, motion, theme, widgets};

const ERROR_HEIGHT: f32 = 28.0;
const PROCESS_ROW_HEIGHT: f32 = 40.0;
/// A row with the path under the name.
const PROCESS_ROW_HEIGHT_TWO_LINES: f32 = 48.0;
/// The room at a row's left and right edges and between its tile and its text.
const PROCESS_ROW_INSET: f32 = theme::space::M;
const PROCESS_TILE_SIDE: f32 = 28.0;
/// The tick box of a program row.
const PROCESS_TICK_SIDE: f32 = 20.0;
const PROCESS_ROW_GAP: f32 = theme::space::XS;
const CATEGORY_ROW_HEIGHT: f32 = 22.0;
const CATEGORY_VIEW_HEIGHT: f32 = 120.0;
/// The content area of every kind: the list kind with its categories is the tallest.
const CONTENT_HEIGHT: f32 = 300.0;
/// The least the content area shrinks to in a short window.
const MIN_CONTENT_HEIGHT: f32 = 160.0;
/// The rest of the dialog: its frame, the title, the kinds, the destination row and the
/// footer, with the gaps between them, and room above and below it.
const DIALOG_CHROME: f32 = 300.0;
/// The rows of chips the address field grows to before it scrolls.
const ADDRESS_ROWS: usize = 5;
/// The rows of chips the address field is tall enough for while it is empty.
const ADDRESS_MIN_ROWS: usize = 3;
const RECENT_CHIP_HEIGHT: f32 = 24.0;
/// Inside a recent site's button, at its ends.
const RECENT_CHIP_PADDING: f32 = theme::space::S;
const DESTINATION_POPUP_MARGIN: f32 = theme::space::XL;
const MIN_DESTINATION_POPUP: f32 = 120.0;

/// A process row's tile: the program's icon, else a letter on a colour.
struct ProcessTile<'a> {
    letter: &'a str,
    fill: Color32,
    icon: Option<&'a Path>,
}

/// The height of the content area in a window `window` points high: the same for every kind
/// and every state of the dialog, so the dialog never changes its height while it is open.
fn content_height(window: f32) -> f32 {
    (window - DIALOG_CHROME).clamp(MIN_CONTENT_HEIGHT, CONTENT_HEIGHT)
}

pub(crate) fn show(
    ctx: &egui::Context,
    dialog: &mut AddRuleDialog,
    config: &AppConfig,
    can_temporary: bool,
    existing_list_rules: usize,
    recent: &[RecentSite],
    actions: &mut Vec<Action>,
) {
    let lists = &config.lists;
    if !can_temporary {
        dialog.temporary_only = false;
    }
    let height = content_height(ctx.content_rect().height());
    let response = widgets::Dialog::new("add_rule", widgets::DialogWidth::Wide).show(ctx, |ui| {
        ui.spacing_mut().item_spacing.y = theme::space::XS;
        ui.heading(if dialog.editing.is_some() {
            tr!("edit-rule")
        } else {
            tr!("new-rule")
        });
        ui.add_space(theme::space::S);
        if let Some(kind) = widgets::segmented(
            ui,
            "rule_input_kind",
            dialog.kind,
            &[
                (RuleInputKind::Process, tr!("rule-kind-app")),
                (RuleInputKind::Address, tr!("rule-kind-address")),
                (RuleInputKind::List, tr!("rule-kind-list")),
            ],
            true,
            !dialog.busy && dialog.editing.is_none(),
        ) {
            actions.push(Action::SelectRuleInput(kind));
        }
        ui.add_space(theme::space::S);
        let error = dialog.error.clone();
        let kind_shown = kind_progress(ui.ctx(), dialog.kind, motion::reduced());
        let valid = content_area(ui, height, error.as_deref(), |ui| {
            widgets::appear(ui, kind_shown, |ui| match dialog.kind {
                RuleInputKind::Process => process_input(ui, dialog, actions),
                RuleInputKind::Address => {
                    scrolled(ui, |ui| address_input(ui, dialog, recent, actions))
                }
                RuleInputKind::List => scrolled(ui, |ui| list_input(ui, dialog, lists, actions)),
            })
        });
        ui.add_space(theme::space::S);
        destination_row(ui, dialog, config, can_temporary);
        let exceeds_list_limit = dialog.kind == RuleInputKind::List
            && dialog
                .list
                .as_ref()
                .and_then(|id| lists.iter().find(|list| &list.id == id))
                .is_some_and(|list| {
                    dialog.exceeds_list_limit(existing_list_rules, list.format.has_categories())
                });
        let too_many_programs = dialog.kind == RuleInputKind::Process && dialog.too_many_programs();
        let can_submit = valid
            && !exceeds_list_limit
            && !dialog.busy
            && (!dialog.temporary_only || can_temporary);
        let reason = if dialog.busy || dialog.error.is_some() || can_submit {
            None
        } else if exceeds_list_limit {
            Some(tr!("list-rule-limit"))
        } else if too_many_programs {
            Some(tr!("program-limit", n = MAX_PROGRAMS.to_string()))
        } else if dialog.temporary_only && !can_temporary {
            Some(tr!("temporary-needs-connection"))
        } else {
            Some(match dialog.kind {
                RuleInputKind::Process => tr!("choose-program"),
                RuleInputKind::Address => address_reason(dialog),
                RuleInputKind::List => tr!("choose-list-category"),
            })
        };
        let footer = widgets::DialogFooter::new(submit_label(dialog), tr!("cancel"))
            .primary_enabled(can_submit)
            .primary_hint(reason.as_deref())
            .busy(dialog.busy);
        match widgets::dialog_footer(ui, footer).choice() {
            widgets::FooterChoice::Primary => actions.push(Action::SubmitAddRule),
            widgets::FooterChoice::Cancel => actions.push(Action::CancelAddRule),
            widgets::FooterChoice::Other | widgets::FooterChoice::None => {}
        }
    });
    if !dialog.busy && response.should_close() {
        actions.push(Action::CancelAddRule);
    }
}

/// How far the content of `kind` has appeared: it fades in whenever another kind is chosen.
fn kind_progress(ctx: &egui::Context, kind: RuleInputKind, reduce_motion: bool) -> f32 {
    widgets::appear_progress(
        ctx,
        egui::Id::unique("rule_input_body"),
        kind,
        reduce_motion,
    )
}

/// "Add", "Add N rules" for several, "Save" for an edit.
fn submit_label(dialog: &AddRuleDialog) -> String {
    if dialog.busy {
        return if dialog.editing.is_some() {
            tr!("saving")
        } else {
            tr!("adding-rule")
        };
    }
    if dialog.editing.is_some() {
        return tr!("save");
    }
    let count = match dialog.kind {
        RuleInputKind::Process => dialog.process_rule_count(),
        RuleInputKind::Address => dialog.address_rule_count(),
        RuleInputKind::List => dialog.selected_categories.len(),
    };
    i18n::add_rules(count.max(1))
}

/// Why the address field adds nothing yet.
fn address_reason(dialog: &AddRuleDialog) -> String {
    if dialog.too_many_addresses() {
        return tr!("address-limit", n = MAX_ADDRESSES.to_string());
    }
    dialog.address_errors().into_iter().next().map_or_else(
        || tr!("enter-address"),
        |(item, error)| i18n::item_error(&item, &address_error_text(&error)),
    )
}

fn address_error_text(error: &AddressError) -> String {
    match error {
        AddressError::Domain(error) => errors::rule_input(i18n::language(), error),
        AddressError::Ip(IpCidrError::Invalid) => tr!("ip-invalid"),
        AddressError::Ip(IpCidrError::HostBits { corrected }) => {
            tr!("ip-host-bits", corrected = corrected)
        }
    }
}

/// The area under the kinds, `height` high whatever it holds, with the dialog's error at its
/// bottom.
fn content_area(
    ui: &mut egui::Ui,
    height: f32,
    error: Option<&str>,
    add: impl FnOnce(&mut egui::Ui) -> bool,
) -> bool {
    let width = ui.available_width();
    ui.allocate_ui_with_layout(
        egui::vec2(width, height),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_min_size(egui::vec2(width, height));
            ui.set_max_height(height);
            let body = height
                - if error.is_some() {
                    ERROR_HEIGHT + ui.spacing().item_spacing.y
                } else {
                    0.0
                };
            let valid = ui
                .allocate_ui_with_layout(
                    egui::vec2(width, body),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_min_size(egui::vec2(width, body));
                        ui.set_max_height(body);
                        add(ui)
                    },
                )
                .inner;
            if let Some(error) = error {
                ui.add_sized(
                    egui::vec2(width, ERROR_HEIGHT),
                    egui::Label::new(RichText::new(error).color(theme::ERROR)).truncate(),
                )
                .on_hover_text(error);
            }
            valid
        },
    )
    .inner
}

/// A kind's content that scrolls when it is taller than the content area.
fn scrolled(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> bool) -> bool {
    egui::ScrollArea::vertical()
        .id_salt("add_rule_content")
        .max_height(ui.available_height())
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// "Send to", the destination and, for a new rule, "Temporary" at the right edge.
fn destination_row(
    ui: &mut egui::Ui,
    dialog: &mut AddRuleDialog,
    config: &AppConfig,
    can_temporary: bool,
) {
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), widgets::field_height(ui)),
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
            if dialog.editing.is_none() {
                let response = widgets::checkbox(
                    ui,
                    &mut dialog.temporary_only,
                    tr!("temporary-only"),
                    can_temporary && !dialog.busy,
                );
                if can_temporary {
                    response.on_hover_text(tr!("temporary-dialog-hint"));
                } else {
                    response.on_disabled_hover_text(tr!("temporary-needs-connection"));
                }
                ui.add_space(theme::space::L);
            }
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.label(RichText::new(tr!("where-to-route")).color(theme::palette().text_muted));
                ui.add_space(theme::space::S);
                destination_picker(ui, dialog, config);
            });
        },
    );
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
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::ComboBox, enabled, &name));
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect(
            rect,
            theme::RADIUS,
            theme::palette().input,
            Stroke::new(
                theme::stroke::HAIRLINE,
                if response.hovered() && enabled {
                    theme::palette().border_strong
                } else {
                    theme::palette().border
                },
            ),
            egui::StrokeKind::Inside,
        );
        let detail_font = egui::TextStyle::Small.resolve(ui.style());
        let detail_galley = egui::WidgetText::from(
            RichText::new(&detail)
                .font(detail_font)
                .color(theme::palette().text_dim),
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
            theme::palette().text_dim,
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
            theme::palette().text,
        );
        icons::paint(
            painter,
            egui::pos2(rect.right() - 16.0, rect.center().y),
            Icon::Chevron { open: 1.0 },
            theme::palette().text_dim,
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
        widgets::checkbox(ui, checked, label, enabled)
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
        .fill(if selected {
            theme::palette().input
        } else {
            theme::palette().card
        })
        .corner_radius(theme::RADIUS_INNER)
        .inner_margin(theme::margin::symmetric(theme::space::XS, 0.0))
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
                            .color(theme::palette().text_dim),
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
        .fill(theme::palette().card)
        .stroke(Stroke::new(
            theme::stroke::HAIRLINE,
            theme::palette().border,
        ))
        .corner_radius(theme::RADIUS)
        .inner_margin(theme::margin::same(theme::space::XS))
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
            .color(theme::palette().text_dim),
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
        ui.add_space(theme::space::S);
        let selected_count = dialog.selected_categories.len();
        egui::Sides::new().show(
            ui,
            |ui| {
                ui.label(
                    RichText::new(tr!("rule-list-categories"))
                        .small()
                        .color(theme::palette().text_dim),
                );
            },
            |ui| {
                if selected_count == 0 {
                    ui.label(
                        RichText::new(tr!("rule-list-none-selected"))
                            .small()
                            .color(theme::palette().text_dim),
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
                            .color(theme::palette().accent_light),
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
                .color(theme::palette().text_dim),
        );
        ui.add_space(theme::space::S);
    } else {
        dialog.selected_categories.clear();
    }
    !selected.format.has_categories() || !dialog.selected_categories.is_empty()
}

fn address_input(
    ui: &mut egui::Ui,
    dialog: &mut AddRuleDialog,
    recent: &[RecentSite],
    actions: &mut Vec<Action>,
) -> bool {
    let subdomains = dialog.subdomains;
    let shown: Vec<(String, Icon, Option<String>)> = dialog
        .addresses
        .iter()
        .map(|chip| match &chip.parsed {
            Ok(address) => (
                display::safe_text(&address.label(subdomains)),
                address_icon(address.is_domain()),
                None,
            ),
            Err(error) => (
                display::safe_text(&chip.text),
                address_icon(matches!(error, AddressError::Domain(_))),
                Some(sentence(address_error_text(error))),
            ),
        })
        .collect();
    let chips: Vec<_> = shown
        .iter()
        .map(|(label, icon, error)| widgets::Chip {
            label,
            icon: *icon,
            error: error.as_deref(),
        })
        .collect();
    let hint = tr!("address-hint");
    let has_domain = dialog.has_domain();
    let accepts_input = dialog.editing.is_none() || dialog.addresses.is_empty();
    let busy = dialog.busy;
    let width = ui.available_width();
    let output = widgets::ChipsField::new("rule_addresses", &chips, &mut dialog.address_input)
        .hint(&hint)
        .enabled(!busy)
        .accepts_input(accepts_input)
        .min_rows(ADDRESS_MIN_ROWS)
        .max_rows(ADDRESS_ROWS)
        .width(width)
        .show(ui);
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), widgets::field_height(ui)),
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
            let response = widgets::checkbox(
                ui,
                &mut dialog.subdomains,
                tr!("include-subdomains"),
                has_domain && !busy,
            );
            if has_domain {
                response.on_hover_text(tr!("include-subdomains-detail"));
            } else {
                response.on_disabled_hover_text(tr!("include-subdomains-detail"));
            }
        },
    );
    if dialog.focus_input {
        if let Some(input) = &output.input {
            input.request_focus();
        }
        dialog.focus_input = false;
    }
    for event in output.events {
        match event {
            widgets::ChipsEvent::Add(text) => dialog.add_addresses(&text),
            widgets::ChipsEvent::Remove(index) => dialog.remove_address(index),
            widgets::ChipsEvent::RemoveLast => dialog.remove_last_address(),
        }
    }
    if dialog.too_many_addresses() {
        ui.label(
            RichText::new(tr!("address-limit", n = MAX_ADDRESSES.to_string()))
                .small()
                .color(theme::ERROR),
        );
    }
    if dialog
        .address_errors()
        .iter()
        .any(|(_, error)| matches!(error, AddressError::Ip(IpCidrError::HostBits { .. })))
        && widgets::link(ui, &tr!("ip-fix"), !dialog.busy).clicked()
    {
        actions.push(Action::CorrectRuleIps);
    }
    if dialog.local_ip_warning() {
        ui.add(
            egui::Label::new(
                RichText::new(tr!("ip-local-warning"))
                    .small()
                    .color(theme::palette().accent_light),
            )
            .wrap(),
        );
        if widgets::link(ui, &tr!("allow-lan"), !dialog.busy).clicked() {
            actions.push(Action::OpenLanSettings);
        }
    }
    let recent_shown = widgets::appear_progress(
        ui.ctx(),
        egui::Id::unique("rule_recent_sites"),
        recent.is_empty(),
        motion::reduced(),
    );
    if !recent.is_empty() {
        widgets::appear(ui, recent_shown, |ui| recent_sites(ui, dialog, recent));
    }
    dialog.address_rules().is_some()
}

/// The sites the tunnel carried lately, as buttons under the field: a click puts the site in
/// the field, another click takes it out. A site the set has a rule for is dimmed.
fn recent_sites(ui: &mut egui::Ui, dialog: &mut AddRuleDialog, sites: &[RecentSite]) {
    ui.add_space(theme::space::S);
    ui.label(
        RichText::new(tr!("recent-sites"))
            .small()
            .color(theme::palette().text_dim),
    );
    let enabled = !dialog.busy;
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = egui::Vec2::splat(theme::space::XS);
        for site in sites {
            let added = dialog.has_address(&site.address);
            let label = display::safe_text(&site.address);
            if recent_site_button(ui, &label, added, site.has_rule, enabled).clicked() {
                dialog.toggle_address(&site.address);
            }
        }
    });
}

fn recent_site_button(
    ui: &mut egui::Ui,
    label: &str,
    added: bool,
    has_rule: bool,
    enabled: bool,
) -> egui::Response {
    let palette = theme::palette();
    let color = if !enabled {
        theme::DISABLED
    } else if added {
        palette.accent_light
    } else if has_rule {
        palette.text_dim
    } else {
        palette.text
    };
    let galley = ui.painter().layout_no_wrap(
        label.to_owned(),
        egui::TextStyle::Body.resolve(ui.style()),
        color,
    );
    let size = egui::vec2(
        galley.size().x + 2.0 * RECENT_CHIP_PADDING,
        RECENT_CHIP_HEIGHT,
    );
    let (rect, response) = ui.allocate_exact_size(
        size,
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    let (fill, border) = if added {
        (palette.input, palette.accent_dark)
    } else if response.hovered() && enabled {
        (palette.border, palette.border_strong)
    } else {
        (palette.card, palette.border)
    };
    ui.painter().rect(
        rect,
        egui::CornerRadius::same(theme::RADIUS_INNER),
        fill,
        Stroke::new(theme::stroke::HAIRLINE, border),
        egui::StrokeKind::Inside,
    );
    ui.painter().galley(
        egui::pos2(
            rect.left() + RECENT_CHIP_PADDING,
            rect.center().y - galley.size().y / 2.0,
        ),
        galley,
        color,
    );
    let response = if has_rule {
        response.on_hover_text(tr!("recent-site-has-rule"))
    } else {
        response
    };
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// A domain's chip shows a globe, an address's the icon of IP rules.
fn address_icon(domain: bool) -> Icon {
    if domain { Icon::Globe } else { Icon::Stack }
}

/// An error message as a hint of its own: with a capital letter.
fn sentence(text: String) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => text,
    }
}

fn process_input(ui: &mut egui::Ui, dialog: &mut AddRuleDialog, actions: &mut Vec<Action>) -> bool {
    let width = ui.available_width();
    let input = ui
        .add_enabled_ui(!dialog.busy, |ui| {
            widgets::search_field(ui, &mut dialog.process_filter, &tr!("find-app"), width)
        })
        .inner;
    if dialog.focus_input {
        input.request_focus();
        dialog.focus_input = false;
    }
    let folder_id = egui::Id::unique("rule_folder_choice");
    let folder_shown = widgets::reveal_progress(
        ui.ctx(),
        folder_id,
        !dialog.chosen.is_empty(),
        motion::reduced(),
    );
    widgets::reveal(ui, folder_id, folder_shown, |ui| {
        widgets::appear(ui, folder_shown, |ui| match_mode_choice(ui, dialog));
    });
    chosen_header(ui, dialog);
    process_list(ui, dialog, actions);
    dialog.process_rules().is_some()
}

/// Above the list, at the right: how many programs are ticked and a link that unticks them.
fn chosen_header(ui: &mut egui::Ui, dialog: &mut AddRuleDialog) {
    let count = dialog.chosen.len();
    egui::Sides::new().show(
        ui,
        |_| {},
        |ui| {
            if count == 0 {
                ui.label(
                    RichText::new(tr!("rule-list-none-selected"))
                        .small()
                        .color(theme::palette().text_dim),
                );
                return;
            }
            if widgets::link(ui, &tr!("rule-list-clear"), !dialog.busy).clicked() {
                dialog.clear_chosen();
            }
            ui.label(
                RichText::new(tr!("rule-list-selected", n = count.to_string()))
                    .small()
                    .color(theme::palette().accent_light),
            );
        },
    );
}

/// "Any folder" or "Only this folder", one for every ticked program. A file chosen by its
/// path is always for that folder, so the choice shows "Only this folder" and is unavailable
/// while only files are ticked.
fn match_mode_choice(ui: &mut egui::Ui, dialog: &mut AddRuleDialog) {
    let applies = dialog.folder_setting_applies();
    let available = applies && dialog.full_path_available();
    let shown = if applies {
        dialog.match_mode
    } else {
        ProcessMatchMode::Path
    };
    let choice = ui.scope(|ui| {
        widgets::segmented(
            ui,
            "process_match_mode",
            shown,
            &[
                (ProcessMatchMode::Name, tr!("match-any-folder")),
                (ProcessMatchMode::Path, tr!("match-this-folder")),
            ],
            true,
            available && !dialog.busy,
        )
    });
    choice.response.on_hover_text(if !applies {
        tr!("match-file-detail")
    } else if available {
        tr!("full-path-detail")
    } else {
        tr!("path-unavailable")
    });
    if let Some(mode) = choice.inner {
        dialog.set_process_match_mode(mode);
    }
}

/// The ticked programs the list does not show, then the running programs with windows, then
/// the other processes, both narrowed by the search, and "Other program…" last.
fn process_list(ui: &mut egui::Ui, dialog: &mut AddRuleDialog, actions: &mut Vec<Action>) {
    let filter = dialog.process_filter.trim().to_owned();
    let shown: Vec<usize> = dialog
        .processes
        .iter()
        .enumerate()
        .filter(|(_, group)| process_matches_filter(group, &filter))
        .map(|(index, _)| index)
        .collect();
    let (running, other): (Vec<usize>, Vec<usize>) = shown
        .iter()
        .partition(|index| dialog.processes[**index].windowed);
    let typed_key = match rosetun_core::parse_process_input(&filter) {
        Ok(ProcessMatch::Name(name)) if !filter.is_empty() => Some(ProgramKey::of_name(&name)),
        Ok(ProcessMatch::Path(path)) if !filter.is_empty() => Some(ProgramKey::of_path(&path)),
        _ => None,
    };
    let manual = typed_key.as_ref().is_some_and(|key| !dialog.is_chosen(key))
        && !dialog
            .processes
            .iter()
            .any(|group| group.name.eq_ignore_ascii_case(&filter));
    let extras: Vec<&ChosenProgram> = dialog
        .chosen
        .iter()
        .filter(|program| {
            !dialog
                .processes
                .iter()
                .any(|group| group.key() == program.key)
        })
        .collect();
    let mut listed = None;
    let mut extra = None;
    let mut typed = false;
    #[cfg(windows)]
    let mut browse = false;
    egui::ScrollArea::vertical()
        .id_salt("running_processes")
        .max_height(ui.available_height())
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = PROCESS_ROW_GAP;
            if let Some(error) = &dialog.processes_error {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(error).small().color(theme::ERROR));
                    if widgets::link(ui, &tr!("retry"), !dialog.busy).clicked() {
                        actions.push(Action::RefreshProcesses);
                    }
                });
            }
            if dialog.load_request.is_some() {
                ui.label(
                    RichText::new(tr!("loading-processes"))
                        .small()
                        .color(theme::palette().text_dim),
                );
            }
            for program in &extras {
                if extra_row(ui, program, !dialog.busy).changed() {
                    extra = Some(program.key.clone());
                }
            }
            if manual {
                let response = process_row(
                    ui,
                    ProcessRow {
                        name: &display::safe_text(&filter),
                        detail: Some(&tr!("typed-process")),
                        hover: None,
                        tile: ProcessTile {
                            letter: constants::EXPAND,
                            fill: theme::palette().border_strong,
                            icon: None,
                        },
                        checked: Some(false),
                    },
                    !dialog.busy,
                );
                typed = response.changed() && !dialog.busy;
            }
            for (title, indices) in [
                (tr!("processes-running"), &running),
                (tr!("processes-other", n = other.len().to_string()), &other),
            ] {
                if indices.is_empty() {
                    continue;
                }
                ui.add_space(theme::space::XS);
                ui.label(
                    RichText::new(title)
                        .small()
                        .color(theme::palette().text_dim),
                );
                for &index in indices {
                    let group = &dialog.processes[index];
                    if group_row(ui, dialog, group).changed() && !dialog.busy {
                        listed = Some(index);
                    }
                }
            }
            if shown.is_empty() && !manual && extras.is_empty() && dialog.processes_loaded {
                ui.label(
                    RichText::new(if filter.is_empty() {
                        tr!("no-running-processes")
                    } else {
                        tr!("no-processes-match")
                    })
                    .color(theme::palette().text_dim),
                );
            }
            #[cfg(windows)]
            {
                ui.add_space(theme::space::XS);
                let enabled = !dialog.busy && !dialog.browsing;
                browse = process_row(
                    ui,
                    ProcessRow {
                        name: &tr!("other-program"),
                        detail: None,
                        hover: None,
                        tile: ProcessTile {
                            letter: constants::EXPAND,
                            fill: theme::palette().border,
                            icon: None,
                        },
                        checked: None,
                    },
                    enabled,
                )
                .clicked()
                    && enabled;
            }
        });
    if let Some(index) = listed {
        dialog.toggle_listed(index);
    }
    if let Some(key) = extra
        && let Some(program) = dialog.chosen.iter().find(|program| program.key == key)
    {
        let program = program.clone();
        dialog.toggle_program(program);
    }
    if typed {
        dialog.toggle_typed();
    }
    #[cfg(windows)]
    if browse {
        actions.push(Action::BrowseExecutable);
    }
}

/// A ticked program the list does not show: a file, a name typed in, or a program that has
/// closed since. A file shows its full path under the name, which says the rule is for
/// that file only.
fn extra_row(ui: &mut egui::Ui, program: &ChosenProgram, enabled: bool) -> egui::Response {
    let path = program
        .path
        .as_ref()
        .map(|path| display::safe_text(&path.to_string_lossy()));
    let detail = path.clone().unwrap_or_else(|| tr!("typed-process"));
    let name = display::safe_text(&program.name);
    let letter = display::safe_text(&tile_letter(&program.name));
    process_row(
        ui,
        ProcessRow {
            name: &name,
            detail: Some(&detail),
            hover: path.as_deref(),
            tile: ProcessTile {
                letter: &letter,
                fill: tile_color(&program.name),
                icon: program.path.as_deref(),
            },
            checked: Some(true),
        },
        enabled,
    )
}

/// One listed program: its name with the number of copies, and its path on hover. The path
/// is a second line only when another listed program has the same name.
fn group_row(ui: &mut egui::Ui, dialog: &AddRuleDialog, group: &ProcessGroup) -> egui::Response {
    let path = group.path.as_ref().map_or_else(
        || tr!("path-unavailable"),
        |path| display::safe_text(&path.to_string_lossy()),
    );
    let same_name = dialog
        .processes
        .iter()
        .filter(|other| other.name.eq_ignore_ascii_case(&group.name))
        .count()
        > 1;
    let name = if group.count > 1 {
        i18n::process_copies(&display::safe_text(&group.name), group.count)
    } else {
        display::safe_text(&group.name)
    };
    let letter = display::safe_text(&tile_letter(&group.name));
    let checked = dialog.is_chosen(&group.key());
    // Only this folder cannot take a program whose path is unknown.
    let allowed = group.path.is_some() || dialog.match_mode == ProcessMatchMode::Name || checked;
    process_row(
        ui,
        ProcessRow {
            name: &name,
            detail: (same_name || !allowed).then_some(path.as_str()),
            hover: Some(&path),
            tile: ProcessTile {
                letter: &letter,
                fill: tile_color(&group.name),
                icon: group.path.as_deref(),
            },
            checked: Some(checked),
        },
        !dialog.busy && allowed,
    )
}

/// What a row of the program list shows.
struct ProcessRow<'a> {
    name: &'a str,
    /// A second line under the name.
    detail: Option<&'a str>,
    hover: Option<&'a str>,
    tile: ProcessTile<'a>,
    /// A tick box at the row's left edge and the row lit as chosen; `None` for a row that
    /// is an action.
    checked: Option<bool>,
}

/// One row of the list. A click anywhere on a row with a tick box, or on the box, ticks it
/// or unticks it: the response then reports a change.
fn process_row(ui: &mut egui::Ui, row: ProcessRow<'_>, enabled: bool) -> egui::Response {
    let selected = row.checked == Some(true);
    let height = if row.detail.is_some() {
        PROCESS_ROW_HEIGHT_TWO_LINES
    } else {
        PROCESS_ROW_HEIGHT
    };
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    let fill = if selected {
        theme::palette().input
    } else if response.hovered() && enabled {
        theme::palette().border
    } else {
        Color32::TRANSPARENT
    };
    ui.painter().rect(
        rect,
        egui::CornerRadius::same(theme::RADIUS),
        fill,
        Stroke::new(
            theme::stroke::HAIRLINE,
            if selected {
                theme::palette().accent_dark
            } else {
                theme::palette().border
            },
        ),
        egui::StrokeKind::Inside,
    );
    let mut tile_left = rect.left() + PROCESS_ROW_INSET;
    let mut ticked = false;
    if let Some(mut checked) = row.checked {
        let tick_rect = egui::Rect::from_center_size(
            egui::pos2(tile_left + PROCESS_TICK_SIDE / 2.0, rect.center().y),
            egui::Vec2::splat(PROCESS_TICK_SIDE),
        );
        ticked = ui
            .scope_builder(egui::UiBuilder::new().max_rect(tick_rect), |ui| {
                ui.spacing_mut().interact_size = egui::Vec2::splat(PROCESS_TICK_SIDE);
                widgets::checkbox(ui, &mut checked, "", enabled).changed()
            })
            .inner;
        tile_left += PROCESS_TICK_SIDE + PROCESS_ROW_INSET;
    }
    let tile_rect = egui::Rect::from_min_size(
        egui::pos2(tile_left, rect.center().y - PROCESS_TILE_SIDE / 2.0),
        egui::Vec2::splat(PROCESS_TILE_SIDE),
    );
    if !row
        .tile
        .icon
        .is_some_and(|path| crate::program_icons::paint(ui, tile_rect, PROCESS_TILE_SIDE, path))
    {
        ui.painter().rect_filled(
            tile_rect,
            egui::CornerRadius::same(theme::RADIUS),
            row.tile.fill,
        );
        ui.painter().text(
            tile_rect.center(),
            egui::Align2::CENTER_CENTER,
            row.tile.letter,
            theme::font::semibold(theme::font::CAPTION),
            theme::palette().text,
        );
    }
    let text_left = tile_rect.right() + PROCESS_ROW_INSET;
    let text_painter = ui.painter().with_clip_rect(egui::Rect::from_min_max(
        egui::pos2(text_left, rect.top()),
        egui::pos2(rect.right() - PROCESS_ROW_INSET, rect.bottom()),
    ));
    let name_color = if !enabled {
        theme::DISABLED
    } else if selected {
        theme::palette().accent_light
    } else {
        theme::palette().text
    };
    match row.detail {
        Some(detail) => {
            text_painter.text(
                egui::pos2(text_left, rect.center().y - theme::space::XS),
                egui::Align2::LEFT_BOTTOM,
                row.name,
                theme::font::semibold(theme::font::CAPTION),
                name_color,
            );
            text_painter.text(
                egui::pos2(text_left, rect.center().y),
                egui::Align2::LEFT_TOP,
                detail,
                egui::TextStyle::Small.resolve(ui.style()),
                theme::palette().text_dim,
            );
        }
        None => {
            text_painter.text(
                egui::pos2(text_left, rect.center().y),
                egui::Align2::LEFT_CENTER,
                row.name,
                theme::font::semibold(theme::font::CAPTION),
                name_color,
            );
        }
    }
    let mut response = match row.hover {
        Some(hover) => response.on_hover_text(hover),
        None => response,
    };
    if row.checked.is_some() && enabled && (ticked || response.clicked()) {
        response.mark_changed();
    }
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

fn tile_letter(name: &str) -> String {
    name.chars()
        .next()
        .unwrap_or('?')
        .to_uppercase()
        .to_string()
}

/// A muted tile colour picked from the name, so a process keeps its colour.
fn tile_color(name: &str) -> Color32 {
    let palette = theme::PROGRAM_TILES;
    let index = name
        .chars()
        .flat_map(char::to_lowercase)
        .fold(0_usize, |sum, ch| (sum + ch as usize) % palette.len());
    palette[index]
}

/// "Send to": one field whose list opens over the dialog.
fn destination_picker(ui: &mut egui::Ui, dialog: &mut AddRuleDialog, config: &AppConfig) {
    let enabled = !dialog.busy && ui.is_enabled();
    let label = destination_label(&dialog.target, &config.exits);
    let color = if enabled {
        destination_color(&dialog.target)
    } else {
        theme::DISABLED
    };
    // Whole points, so the list that opens as wide as the field has whole-point items.
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width().floor(), widgets::field_height(ui)),
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::ComboBox, enabled, &label));
    let open = egui::Popup::is_id_open(ui.ctx(), destination_popup_id());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect(
            rect,
            theme::RADIUS,
            theme::palette().input,
            Stroke::new(
                theme::stroke::HAIRLINE,
                if open {
                    theme::palette().accent_base
                } else if response.hovered() && enabled {
                    theme::palette().border_strong
                } else {
                    theme::palette().border
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
            Icon::Chevron { open: 1.0 },
            if enabled {
                theme::palette().text_dim
            } else {
                theme::DISABLED
            },
        );
    }
    let response = match &dialog.target {
        RuleDestination::NewExit(NewExit::Country { name, .. } | NewExit::Node { name, .. }) => {
            response.on_hover_text(tr!("where-new-exit", name = display::safe_text(name)))
        }
        _ => response,
    };
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
    egui::Id::unique("rule_destination")
}

fn destination_item(
    ui: &mut egui::Ui,
    label: &str,
    color: Color32,
    enabled: bool,
    selected: bool,
    hint: Option<&str>,
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
    let item = match hint {
        Some(hint) => item.on_hover_text(hint),
        None => item,
    };
    if item.clicked() {
        ui.close();
        return true;
    }
    false
}

fn destination_section(ui: &mut egui::Ui, title: String) {
    ui.add_space(theme::space::XS);
    ui.separator();
    ui.label(
        RichText::new(title)
            .small()
            .color(theme::palette().text_dim),
    );
}

fn destination_note(ui: &mut egui::Ui, note: String) {
    ui.add(
        egui::Label::new(
            RichText::new(note)
                .small()
                .color(theme::palette().text_muted),
        )
        .wrap(),
    );
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
        let hint = (target == RuleTarget::Proxy).then(|| tr!("where-proxy-hint"));
        if destination_item(
            ui,
            &target_label(target),
            target_color(target),
            true,
            selected,
            hint.as_deref(),
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
            if destination_item(ui, &label, theme::EXIT, true, selected, None) {
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
            if destination_item(ui, &label, theme::EXIT, !full, selected, None) {
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
        let width = ui.available_width();
        ui.add_enabled_ui(!full, |ui| {
            widgets::search_field(
                ui,
                &mut dialog.node_search,
                &tr!("where-node-search"),
                width,
            )
        });
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
            if destination_item(ui, &label, theme::EXIT, enabled, selected, None) {
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
    use rosetun_config::{List, ListFormat, ListSource, RuleId, RuleSetId};

    use super::*;
    use crate::i18n::Language;
    use crate::rules::ProcessGroup;

    const COMPACT: egui::Vec2 = egui::vec2(960.0, 640.0);
    const REGULAR: egui::Vec2 = egui::vec2(1200.0, 780.0);

    /// The dialog after a few frames in a window of `size`: its area and every text it painted,
    /// with whether the text was cut short.
    fn shown(
        dialog: &mut AddRuleDialog,
        config: &AppConfig,
        can_temporary: bool,
        size: egui::Vec2,
    ) -> (egui::Rect, Vec<(String, bool)>) {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut shapes = Vec::new();
        for frame in 0..4 {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    time: Some(f64::from(frame) * 0.5),
                    ..egui::RawInput::default()
                },
                |ctx| show(ctx, dialog, config, can_temporary, 0, &[], &mut Vec::new()),
            );
            output.textures_delta.clear();
            shapes = output.shapes;
        }
        let area = ctx
            .memory(|memory| memory.area_rect(egui::Id::unique("add_rule")))
            .expect("the dialog is shown");
        let mut texts = Vec::new();
        for clipped in &shapes {
            collect_texts(&clipped.shape, &mut texts);
        }
        (area, texts)
    }

    fn collect_texts(shape: &egui::Shape, out: &mut Vec<(String, bool)>) {
        match shape {
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect_texts(shape, out)),
            egui::Shape::Text(text) => {
                out.push((text.galley.text().to_owned(), text.galley.elided));
            }
            _ => {}
        }
    }

    fn list(categories: usize) -> List {
        List {
            id: ListId::new("1"),
            name: "Example".into(),
            source: ListSource::File {
                original_name: "geosite.dat".into(),
            },
            format: ListFormat::GeoSite,
            updated_at: None,
            size: None,
            sha256: None,
            categories: (0..categories)
                .map(|index| format!("category{index}"))
                .collect(),
        }
    }

    fn processes(count: usize) -> Vec<ProcessGroup> {
        (0..count)
            .map(|index| ProcessGroup {
                name: format!("Program{index}.exe"),
                path: Some(format!(r"C:\Apps\Program{index}.exe").into()),
                count: 1 + index % 3,
                windowed: index % 2 == 0,
            })
            .collect()
    }

    /// Every kind in the states that used to change the dialog's height.
    fn variants() -> Vec<(&'static str, AddRuleDialog, AppConfig)> {
        let config = AppConfig {
            lists: vec![list(1_000)],
            ..AppConfig::default()
        };
        let new = || AddRuleDialog::new(RuleSetId::new("set"));
        let mut variants = Vec::new();
        variants.push(("program", new(), config.clone()));
        let mut dialog = new();
        dialog.processes = processes(30);
        dialog.processes_loaded = true;
        dialog.toggle_listed(2);
        dialog.match_mode = ProcessMatchMode::Path;
        dialog.error = Some("This rule is already in the set.".into());
        variants.push(("program chosen with an error", dialog, config.clone()));
        let mut dialog = new();
        dialog.processes_error = Some("The process list could not be read.".into());
        dialog.load_request = Some(1);
        dialog.process_filter = "Tool.exe".into();
        variants.push(("program list failed", dialog, config.clone()));
        let mut dialog = new();
        dialog.processes = processes(4);
        dialog.processes.push(ProcessGroup {
            name: "Program1.exe".into(),
            path: Some(r"C:\Other\Program1.exe".into()),
            count: 1,
            windowed: true,
        });
        dialog.processes_loaded = true;
        dialog.toggle_listed(1);
        variants.push(("program by name with a namesake", dialog, config.clone()));
        let mut dialog = new();
        dialog.kind = RuleInputKind::Address;
        variants.push(("address", dialog, config.clone()));
        let mut dialog = new();
        dialog.kind = RuleInputKind::Address;
        dialog.add_addresses(
            "youtube.com 192.168.1.5/24 ru bad..domain 198.51.100.0/33 example. 2001:db8::1/32",
        );
        dialog.address_input = "a..b".into();
        dialog.target = RuleDestination::NewExit(NewExit::Country {
            code: rosetun_config::CountryCode::parse("DE").unwrap(),
            name: "Germany".into(),
        });
        variants.push(("address with errors", dialog, config.clone()));
        let mut dialog = new();
        dialog.kind = RuleInputKind::Address;
        dialog.add_addresses(
            &(0..=MAX_ADDRESSES)
                .map(|index| format!("site{index}.example"))
                .collect::<Vec<_>>()
                .join(" "),
        );
        assert!(dialog.too_many_addresses());
        variants.push(("too many addresses", dialog, config.clone()));
        let mut dialog = new();
        dialog.kind = RuleInputKind::List;
        variants.push(("list", dialog, config.clone()));
        let mut dialog = new();
        dialog.kind = RuleInputKind::List;
        dialog.list = Some(ListId::new("1"));
        dialog.selected_categories = ["category1", "category2", "category3"]
            .map(str::to_owned)
            .to_vec();
        dialog.category_filter = "category@cn".into();
        dialog.error = Some("This rule is already in the set.".into());
        variants.push(("list with categories and an error", dialog, config.clone()));
        let mut dialog = new();
        dialog.kind = RuleInputKind::List;
        variants.push(("no lists", dialog, AppConfig::default()));
        let mut dialog = new();
        dialog.kind = RuleInputKind::Address;
        dialog.editing = Some(RuleId::new("1"));
        dialog.add_addresses("example.com example.org");
        assert_eq!(dialog.addresses.len(), 1, "an edit holds one item");
        variants.push(("editing an address", dialog, config));
        variants
    }

    #[test]
    fn the_dialog_keeps_one_height_for_every_kind_and_state_and_fits_the_window() {
        for size in [COMPACT, REGULAR] {
            for can_temporary in [false, true] {
                let mut heights = Vec::new();
                for (name, mut dialog, config) in variants() {
                    dialog.temporary_only = true;
                    let (area, _) = shown(&mut dialog, &config, can_temporary, size);
                    assert_eq!(dialog.temporary_only, can_temporary, "{name}");
                    assert!(
                        area.top() >= 0.0 && area.bottom() <= size.y,
                        "{name}: {area:?} in {size:?}"
                    );
                    heights.push((name, area.height()));
                }
                let first = heights[0].1;
                for (name, height) in &heights {
                    assert!(
                        (height - first).abs() < 0.5,
                        "{name} is {height} high, the program kind {first} in {size:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn no_text_of_the_dialog_is_cut_short_in_a_compact_window_in_both_languages() {
        for language in [Language::English, Language::Russian] {
            i18n::in_language(language, || {
                for (name, mut dialog, config) in variants() {
                    let (_, texts) = shown(&mut dialog, &config, true, COMPACT);
                    let cut: Vec<_> = texts
                        .iter()
                        .filter(|(text, elided)| *elided && !text.starts_with("category"))
                        .collect();
                    assert!(cut.is_empty(), "{name} {language:?}: {cut:?}");
                }
            });
        }
    }

    #[test]
    fn the_title_stands_alone_and_the_destination_says_only_through_vpn() {
        let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
        let (_, texts) = shown(&mut dialog, &AppConfig::default(), true, REGULAR);
        let texts: Vec<_> = texts.into_iter().map(|(text, _)| text).collect();
        for expected in [
            tr!("new-rule"),
            tr!("rule-kind-app"),
            tr!("rule-kind-address"),
            tr!("rule-kind-list"),
            tr!("where-to-route"),
            target_label(RuleTarget::Proxy),
            tr!("temporary-only"),
            tr!("add"),
            tr!("cancel"),
        ] {
            assert!(texts.contains(&expected), "{expected} in {texts:?}");
        }
        assert!(
            !texts
                .iter()
                .any(|text| text.contains(&tr!("where-proxy-hint"))),
            "{texts:?}"
        );
        dialog.editing = Some(RuleId::new("1"));
        let (_, texts) = shown(&mut dialog, &AppConfig::default(), true, REGULAR);
        let texts: Vec<_> = texts.into_iter().map(|(text, _)| text).collect();
        assert!(texts.contains(&tr!("edit-rule")));
        assert!(texts.contains(&tr!("save")));
        assert!(!texts.contains(&tr!("temporary-only")));
    }

    #[test]
    fn the_add_button_counts_the_rules_it_makes() {
        let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
        assert_eq!(submit_label(&dialog), tr!("add"));
        dialog.kind = RuleInputKind::Address;
        dialog.set_addresses("youtube.com www.youtube.com 192.0.2.1 bad..domain");
        assert_eq!(submit_label(&dialog), i18n::add_rules(2));
        dialog.subdomains = false;
        assert_eq!(submit_label(&dialog), i18n::add_rules(3));
        dialog.kind = RuleInputKind::List;
        dialog.selected_categories = vec!["a".into(), "b".into()];
        assert_eq!(submit_label(&dialog), i18n::add_rules(2));
        dialog.editing = Some(RuleId::new("1"));
        assert_eq!(submit_label(&dialog), tr!("save"));
    }

    #[test]
    fn the_add_button_counts_the_ticked_programs() {
        let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
        dialog.tick_program("Tool.exe");
        assert_eq!(submit_label(&dialog), tr!("add"));
        dialog.tick_program("Other.exe");
        dialog.tick_program("Curl.exe");
        assert_eq!(submit_label(&dialog), i18n::add_rules(3));
    }

    #[test]
    fn a_click_on_a_program_row_ticks_it_and_clear_selection_unticks_all() {
        use crate::test_ui::TestScreen;

        i18n::in_language(i18n::Language::English, || {
            let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
            dialog.processes = processes(4);
            dialog.processes_loaded = true;
            let config = AppConfig::default();
            let mut screen = TestScreen::new(COMPACT);
            macro_rules! frame {
                () => {
                    |ui: &mut egui::Ui| {
                        show(
                            ui.ctx(),
                            &mut dialog,
                            &config,
                            false,
                            0,
                            &[],
                            &mut Vec::new(),
                        )
                    }
                };
            }
            let none = tr!("rule-list-none-selected");
            let texts = screen.settle(frame!());
            assert!(texts.iter().any(|(text, _)| *text == none));
            assert!(
                !texts
                    .iter()
                    .any(|(text, _)| *text == tr!("match-any-folder"))
            );
            let texts = screen.click_text("Program0.exe", frame!());
            assert_eq!(dialog.chosen.len(), 1);
            assert!(
                texts
                    .iter()
                    .any(|(text, _)| *text == tr!("match-any-folder"))
            );
            assert!(
                texts
                    .iter()
                    .any(|(text, _)| *text == tr!("rule-list-selected", n = "1"))
            );
            screen.click_text("Program3.exe", frame!());
            assert_eq!(dialog.chosen.len(), 2);
            screen.click_text("Program0.exe", frame!());
            assert_eq!(dialog.chosen.len(), 1);
            screen.click_text(&tr!("rule-list-clear"), frame!());
            assert!(dialog.chosen.is_empty());
        });
    }

    #[test]
    fn a_paste_into_the_address_field_makes_one_chip_per_item_of_its_kind() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
        dialog.kind = RuleInputKind::Address;
        let run = |dialog: &mut AddRuleDialog, events: Vec<egui::Event>| {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, REGULAR)),
                    events,
                    ..egui::RawInput::default()
                },
                |ctx| {
                    show(
                        ctx,
                        dialog,
                        &AppConfig::default(),
                        true,
                        0,
                        &[],
                        &mut Vec::new(),
                    );
                },
            );
            output.textures_delta.clear();
        };
        run(&mut dialog, Vec::new());
        assert!(ctx.memory(|memory| memory.has_focus(widgets::chips_input_id("rule_addresses"))));
        run(
            &mut dialog,
            vec![egui::Event::Paste(
                "youtube.com, 192.0.2.1\n198.51.100.0/24; 2001:db8::1 https://www.example.com/path"
                    .into(),
            )],
        );
        let chips: Vec<_> = dialog
            .addresses
            .iter()
            .map(|chip| {
                let address = chip.parsed.as_ref().expect("every item is good");
                (address.is_domain(), address.label(dialog.subdomains))
            })
            .collect();
        assert_eq!(
            chips,
            [
                (true, "youtube.com".to_owned()),
                (false, "192.0.2.1".to_owned()),
                (false, "198.51.100.0/24".to_owned()),
                (false, "2001:db8::1".to_owned()),
                (true, "example.com".to_owned()),
            ]
        );
        assert!(dialog.address_input.is_empty());
        assert_eq!(submit_label(&dialog), i18n::add_rules(5));
    }

    #[test]
    fn a_bad_item_is_a_red_chip_and_keeps_add_disabled_with_its_reason() {
        let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
        dialog.kind = RuleInputKind::Address;
        dialog.add_addresses("youtube.com bad..domain youtube.com https://youtube.com/");
        assert_eq!(dialog.addresses.len(), 2, "the repeats are not added");
        assert!(dialog.addresses[1].parsed.is_err());
        assert!(dialog.address_rules().is_none());
        let reason = address_reason(&dialog);
        assert!(reason.starts_with("bad..domain: "), "{reason}");
        let (_, texts) = shown(&mut dialog, &AppConfig::default(), true, REGULAR);
        assert!(texts.iter().any(|(text, _)| text == "bad..domain"));
        dialog.remove_last_address();
        assert_eq!(dialog.addresses.len(), 1);
        assert!(dialog.address_rules().is_some());
        assert_eq!(submit_label(&dialog), tr!("add"));
    }

    #[test]
    fn subdomains_apply_only_when_the_field_has_a_domain() {
        let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
        dialog.kind = RuleInputKind::Address;
        dialog.add_addresses("192.0.2.1 198.51.100.0/24");
        assert!(!dialog.has_domain());
        dialog.add_addresses("example.com");
        assert!(dialog.has_domain());
    }

    #[test]
    fn one_program_list_shows_running_programs_first_and_a_path_only_for_namesakes() {
        let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
        dialog.processes = processes(4);
        dialog.processes.push(ProcessGroup {
            name: "Program1.exe".into(),
            path: Some(r"C:\Other\Program1.exe".into()),
            count: 1,
            windowed: true,
        });
        dialog.processes_loaded = true;
        let (_, texts) = shown(&mut dialog, &AppConfig::default(), true, REGULAR);
        let texts: Vec<_> = texts.into_iter().map(|(text, _)| text).collect();
        let position = |text: &str| {
            texts
                .iter()
                .position(|painted| painted == text)
                .unwrap_or_else(|| panic!("{text} in {texts:?}"))
        };
        let running = position(&tr!("processes-running"));
        let other = position(&tr!("processes-other", n = "2"));
        assert!(running < position("Program0.exe") && position("Program0.exe") < other);
        assert!(other < position("Program3.exe"));
        assert!(texts.contains(&r"C:\Other\Program1.exe".to_owned()));
        assert!(texts.contains(&r"C:\Apps\Program1.exe".to_owned()));
        assert!(!texts.contains(&r"C:\Apps\Program0.exe".to_owned()));
        #[cfg(windows)]
        assert!(position(&tr!("other-program")) > position("Program3.exe"));
        assert!(
            !texts.contains(&tr!("match-any-folder")),
            "no program is chosen"
        );

        dialog.toggle_listed(0);
        let (_, texts) = shown(&mut dialog, &AppConfig::default(), true, REGULAR);
        let texts: Vec<_> = texts.into_iter().map(|(text, _)| text).collect();
        assert!(texts.contains(&tr!("match-any-folder")));
        assert!(texts.contains(&tr!("match-this-folder")));
        assert_eq!(
            texts.iter().filter(|text| *text == "Program0.exe").count(),
            1,
            "no plaque above the list: the ticked program is its row"
        );
        assert!(texts.contains(&tr!("rule-list-selected", n = "1")));
        assert!(texts.contains(&tr!("rule-list-clear")));
    }

    #[test]
    fn the_content_area_shrinks_only_in_a_short_window() {
        assert_eq!(content_height(COMPACT.y), CONTENT_HEIGHT);
        assert_eq!(content_height(REGULAR.y), CONTENT_HEIGHT);
        assert_eq!(content_height(0.0), MIN_CONTENT_HEIGHT);
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
            dialog.kind = RuleInputKind::Address;
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
                    show(ctx, dialog, &config, false, 0, &[], &mut Vec::new());
                });
                output.textures_delta.clear();
            };
            run(&mut dialog);
            egui::Popup::open_id(&ctx, destination_popup_id());
            for _ in 0..3 {
                run(&mut dialog);
            }
            let modal = ctx
                .memory(|memory| memory.area_rect(egui::Id::unique("add_rule")))
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
        dialog.kind = RuleInputKind::Address;
        let run = |dialog: &mut AddRuleDialog| {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1200.0, 900.0),
                )),
                ..egui::RawInput::default()
            };
            let mut output = ctx.run_ui(input, |ctx| {
                show(ctx, dialog, &config, false, 0, &[], &mut Vec::new());
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
            format!(
                "{} · DE",
                i18n::country_name(&CountryCode::parse("DE").unwrap())
            ),
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
            dialog.kind = RuleInputKind::Address;
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
                        &[],
                        &mut Vec::new(),
                    );
                },
            );
            output.textures_delta.clear();
            let rect = ctx
                .memory(|memory| memory.area_rect(egui::Id::unique("add_rule")))
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
                ui.set_width(widgets::DialogWidth::Wide.points());
                height = category_view(ui, &mut dialog, &matches, false)
                    .rect
                    .height();
            });
        });
        output.textures_delta.clear();
        assert_eq!(height, CATEGORY_VIEW_HEIGHT);
    }

    #[test]
    fn category_checkboxes_have_rounded_corners_and_distinct_selection_colours() {
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
            rect.corner_radius == egui::CornerRadius::same(3)
                && rect.fill == theme::palette().card
                && rect.stroke.color == theme::palette().border_strong
        }));
        assert!(rectangles.iter().any(|rect| {
            rect.corner_radius == egui::CornerRadius::same(3)
                && rect.fill == theme::palette().accent_base
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
                ui.set_width(widgets::DialogWidth::Wide.points());
                category_row(ui, &mut dialog, "alpha", false);
            });
        });
        assert!(output.shapes.iter().any(|shape| matches!(
            &shape.shape,
            egui::Shape::Rect(rect) if rect.fill == theme::palette().input && rect.rect.width() > 100.0
        )));
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
    fn tile_colours_are_stable_and_case_insensitive() {
        assert_eq!(tile_color("Telegram.exe"), tile_color("Telegram.exe"));
        assert_eq!(tile_color("Telegram.exe"), tile_color("TELEGRAM.EXE"));
    }

    #[test]
    fn ticking_a_process_preserves_the_search_and_raw_matcher() {
        use crate::rules::ProcessGroup;
        use rosetun_config::{ProcessMatch, RuleSetId};

        let mut dialog = crate::state::AddRuleDialog::new(RuleSetId::new("set"));
        dialog.process_filter = "tele".into();
        dialog.processes.push(ProcessGroup {
            name: "Tele\u{202e}gram.exe".into(),
            path: None,
            count: 1,
            windowed: true,
        });
        dialog.toggle_listed(0);
        assert_eq!(dialog.process_filter, "tele");
        assert_eq!(
            dialog.process_rules(),
            Some(vec![rosetun_config::RuleMatcher::Process(
                ProcessMatch::Name("Tele\u{202e}gram.exe".into())
            )])
        );
    }

    /// The opacity of the first painted text equal to `text`, 0 to 255.
    fn text_alpha(shapes: &[egui::epaint::ClippedShape], text: &str) -> Option<u8> {
        fn find(shape: &egui::Shape, text: &str) -> Option<u8> {
            match shape {
                egui::Shape::Vec(shapes) => shapes.iter().find_map(|shape| find(shape, text)),
                egui::Shape::Text(shape) if shape.galley.text() == text => shape
                    .galley
                    .rows
                    .first()
                    .and_then(|row| row.row.visuals.mesh.vertices.first())
                    .map(|vertex| vertex.color.a()),
                _ => None,
            }
        }
        shapes.iter().find_map(|clipped| find(&clipped.shape, text))
    }

    /// Runs the dialog at `time` seconds and returns the opacity of `text`.
    fn alpha_at(
        ctx: &egui::Context,
        dialog: &mut AddRuleDialog,
        time: f64,
        text: &str,
    ) -> Option<u8> {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, COMPACT)),
                time: Some(time),
                ..egui::RawInput::default()
            },
            |ctx| {
                show(
                    ctx,
                    dialog,
                    &AppConfig::default(),
                    false,
                    0,
                    &[],
                    &mut Vec::new(),
                );
            },
        );
        output.textures_delta.clear();
        text_alpha(&output.shapes, text)
    }

    #[test]
    fn the_content_fades_in_when_another_kind_is_chosen() {
        i18n::in_language(i18n::Language::English, || {
            let hint = tr!("address-hint");
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
            for step in 0..6 {
                alpha_at(&ctx, &mut dialog, f64::from(step) * 0.1, &hint);
            }
            dialog.kind = RuleInputKind::Address;
            // Nothing is painted at zero opacity.
            let first = alpha_at(&ctx, &mut dialog, 1.0, &hint).unwrap_or(0);
            let midway = alpha_at(&ctx, &mut dialog, 1.05, &hint).expect("the hint is painted");
            let later = alpha_at(
                &ctx,
                &mut dialog,
                1.0 + f64::from(motion::FAST) + 0.01,
                &hint,
            )
            .expect("the hint is painted");
            let settled = alpha_at(&ctx, &mut dialog, 2.0, &hint).expect("the hint is painted");
            assert!(
                first < midway && midway < settled,
                "{first} {midway} {settled}"
            );
            assert_eq!(later, settled, "whole after FAST");
        });
    }

    #[test]
    fn reduced_motion_shows_the_chosen_kind_at_once() {
        let ctx = egui::Context::default();
        let progress = |time: f64, kind: RuleInputKind, reduce: bool| {
            let mut value = 0.0;
            let input = egui::RawInput {
                time: Some(time),
                ..egui::RawInput::default()
            };
            let mut output = ctx.run_ui(input, |ui| value = kind_progress(ui.ctx(), kind, reduce));
            output.textures_delta.clear();
            value
        };
        progress(0.0, RuleInputKind::Process, true);
        assert_eq!(progress(0.1, RuleInputKind::Address, true), 1.0);
        progress(0.2, RuleInputKind::Process, false);
        assert_eq!(progress(0.3, RuleInputKind::List, false), 0.0);
        assert_eq!(
            progress(0.3 + f64::from(motion::FAST), RuleInputKind::List, false),
            1.0
        );
    }

    fn recent_sites_of(addresses: &[(&str, bool)]) -> Vec<RecentSite> {
        addresses
            .iter()
            .map(|(address, has_rule)| RecentSite {
                address: (*address).to_owned(),
                has_rule: *has_rule,
            })
            .collect()
    }

    /// The colour of the last painted text equal to `text`: a recent site stands below the
    /// chip of the same name.
    fn text_color(shapes: &[egui::epaint::ClippedShape], text: &str) -> Option<egui::Color32> {
        fn find(shape: &egui::Shape, text: &str) -> Option<egui::Color32> {
            match shape {
                egui::Shape::Vec(shapes) => shapes.iter().rev().find_map(|shape| find(shape, text)),
                egui::Shape::Text(shape) if shape.galley.text() == text => shape
                    .galley
                    .rows
                    .first()
                    .and_then(|row| row.row.visuals.mesh.vertices.first())
                    .map(|vertex| vertex.color),
                _ => None,
            }
        }
        shapes
            .iter()
            .rev()
            .find_map(|clipped| find(&clipped.shape, text))
    }

    fn painted_names(shape: &egui::Shape, out: &mut Vec<String>) {
        match shape {
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| painted_names(shape, out)),
            egui::Shape::Text(text) => out.push(text.galley.text().to_owned()),
            _ => {}
        }
    }

    /// The address kind after a few frames, with `recent` offered: its area, its texts and
    /// the shapes it painted.
    fn address_shown(
        dialog: &mut AddRuleDialog,
        recent: &[RecentSite],
    ) -> (egui::Rect, Vec<String>, Vec<egui::epaint::ClippedShape>) {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut shapes = Vec::new();
        for frame in 0..4 {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, COMPACT)),
                    time: Some(f64::from(frame) * 0.5),
                    ..egui::RawInput::default()
                },
                |ctx| {
                    show(
                        ctx,
                        dialog,
                        &AppConfig::default(),
                        false,
                        0,
                        recent,
                        &mut Vec::new(),
                    );
                },
            );
            output.textures_delta.clear();
            shapes = output.shapes;
        }
        let area = ctx
            .memory(|memory| memory.area_rect(egui::Id::unique("add_rule")))
            .expect("the dialog is shown");
        let mut texts = Vec::new();
        for clipped in &shapes {
            painted_names(&clipped.shape, &mut texts);
        }
        (area, texts, shapes)
    }

    #[test]
    fn the_hint_shows_only_in_an_empty_field_and_the_field_keeps_its_height() {
        i18n::in_language(i18n::Language::English, || {
            let hint = tr!("address-hint");
            assert_eq!(hint.lines().count(), 2, "the hint takes two lines");
            let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
            dialog.kind = RuleInputKind::Address;
            let (area, texts, _) = address_shown(&mut dialog, &[]);
            assert!(texts.contains(&hint));
            dialog.add_addresses("example.com");
            let (filled_area, texts, _) = address_shown(&mut dialog, &[]);
            assert!(!texts.contains(&hint), "a chip is in the field");
            assert_eq!(filled_area.height(), area.height());

            dialog.addresses.clear();
            dialog.address_input = "typing".into();
            let (_, texts, _) = address_shown(&mut dialog, &[]);
            assert!(!texts.contains(&hint), "text is being typed");
        });
    }

    #[test]
    fn recent_sites_show_under_the_field_only_when_there_are_some() {
        i18n::in_language(i18n::Language::English, || {
            let title = tr!("recent-sites");
            let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
            dialog.kind = RuleInputKind::Address;
            let (without, texts, _) = address_shown(&mut dialog, &[]);
            assert!(!texts.contains(&title), "no placeholder without sites");
            let sites = recent_sites_of(&[
                ("example.com", false),
                ("example.org", true),
                ("192.0.2.7", false),
            ]);
            let (with, texts, shapes) = address_shown(&mut dialog, &sites);
            assert!(texts.contains(&title));
            for site in &sites {
                assert!(texts.contains(&site.address), "{}", site.address);
            }
            assert_eq!(
                with.height(),
                without.height(),
                "the dialog keeps its height"
            );
            assert_ne!(
                text_color(&shapes, "example.com"),
                text_color(&shapes, "example.org"),
                "a site with a rule is dimmed"
            );
            dialog.toggle_address("example.com");
            let (_, _, shapes) = address_shown(&mut dialog, &sites);
            assert_ne!(
                text_color(&shapes, "example.com"),
                text_color(&shapes, "192.0.2.7"),
                "an added site is lit"
            );
        });
    }

    #[test]
    fn twelve_recent_sites_fit_the_compact_dialog() {
        let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
        dialog.kind = RuleInputKind::Address;
        let (without, _, _) = address_shown(&mut dialog, &[]);
        let many: Vec<_> = (0..12)
            .map(|index| (format!("subdomain{index}.example.com"), index % 2 == 0))
            .collect();
        let many: Vec<_> = many.iter().map(|(a, r)| (a.as_str(), *r)).collect();
        let (with, _, _) = address_shown(&mut dialog, &recent_sites_of(&many));
        assert_eq!(with.height(), without.height());
        assert!(with.bottom() <= COMPACT.y);
    }

    #[test]
    fn a_click_on_a_recent_site_adds_its_chip_and_another_removes_it() {
        use crate::test_ui::TestScreen;

        i18n::in_language(i18n::Language::English, || {
            let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
            dialog.kind = RuleInputKind::Address;
            let sites = recent_sites_of(&[("example.com", false), ("example.org", true)]);
            let config = AppConfig::default();
            let mut screen = TestScreen::new(COMPACT);
            macro_rules! frame {
                () => {
                    |ui: &mut egui::Ui| {
                        show(
                            ui.ctx(),
                            &mut dialog,
                            &config,
                            false,
                            0,
                            &sites,
                            &mut Vec::new(),
                        )
                    }
                };
            }
            // A recent site stands below the chip of the same name.
            macro_rules! click_last {
                ($label:expr) => {{
                    let label: &str = $label;
                    let shown = screen.settle(frame!());
                    let (_, rect) = shown
                        .iter()
                        .rev()
                        .find(|(text, _)| text == label)
                        .unwrap_or_else(|| panic!("no text {label:?} on the screen"));
                    let pos = rect.center();
                    let button = |pressed| egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    };
                    screen.run(vec![egui::Event::PointerMoved(pos), button(true)], frame!());
                    screen.run(vec![button(false)], frame!());
                }};
            }
            click_last!("example.org");
            assert!(
                dialog.has_address("example.org"),
                "a dimmed site can be added"
            );
            click_last!("example.com");
            assert_eq!(dialog.addresses.len(), 2);
            click_last!("example.org");
            assert_eq!(dialog.addresses.len(), 1);
            assert!(dialog.has_address("example.com"));
        });
    }

    #[test]
    fn under_the_address_field_stand_subdomains_then_the_recent_sites_without_overlap() {
        use crate::test_ui::TestScreen;

        for language in [i18n::Language::English, i18n::Language::Russian] {
            i18n::in_language(language, || {
                let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
                dialog.kind = RuleInputKind::Address;
                let sites = recent_sites_of(&[("example.com", false)]);
                let config = AppConfig::default();
                let mut screen = TestScreen::new(COMPACT);
                let texts = screen.settle(|ui| {
                    show(
                        ui.ctx(),
                        &mut dialog,
                        &config,
                        false,
                        0,
                        &sites,
                        &mut Vec::new(),
                    );
                });
                let rect = |text: &str| {
                    texts
                        .iter()
                        .find(|(painted, _)| painted == text)
                        .unwrap_or_else(|| panic!("no text {text:?}"))
                        .1
                };
                let hint = rect(&tr!("address-hint"));
                let subdomains = rect(&tr!("include-subdomains"));
                let title = rect(&tr!("recent-sites"));
                let site = rect("example.com");
                // The field is three rows tall, so what follows starts below all of them.
                assert!(
                    subdomains.top() >= hint.top() + 3.0 * 24.0,
                    "{subdomains:?}"
                );
                assert!(
                    title.top() >= subdomains.bottom(),
                    "{title:?} {subdomains:?}"
                );
                assert!(site.top() >= title.bottom(), "{site:?} {title:?}");
            });
        }
    }
}
