use eframe::egui::{self, Color32, FontFamily, FontId, RichText, Stroke};
use rosetun_config::{ProcessMatch, RuleTarget};

use crate::display;
use crate::errors;
use crate::icons::{self, Icon};
use crate::rules::{ProcessMatchMode, process_matches_filter, update_process_match_mode};
use crate::state::{Action, AddRuleDialog, RuleInputKind};
use crate::strings::t;
use crate::view::rules::{target_color, target_label};
use crate::{strings, theme, widgets};

const DIALOG_WIDTH: f32 = 640.0;
const DIALOG_TOP: f32 = 100.0;
const PROCESS_ROW_HEIGHT: f32 = 44.0;
const PROCESS_ROW_GAP: f32 = 4.0;
const MIN_PROCESS_LIST: f32 = 2.0 * PROCESS_ROW_HEIGHT + PROCESS_ROW_GAP;
const MAX_PROCESS_LIST: f32 = 5.0 * PROCESS_ROW_HEIGHT + 4.0 * PROCESS_ROW_GAP;
const PROCESS_FOOTER_HEIGHT: f32 = 100.0;
const BUTTON_ROW_HEIGHT: f32 = 40.0;
const ACTIONS_GAP: f32 = 2.0;
const BOTTOM_GAP: f32 = 24.0;

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

pub(crate) fn show(ctx: &egui::Context, dialog: &mut AddRuleDialog, actions: &mut Vec<Action>) {
    let id = egui::Id::new("add_rule");
    let response = egui::Modal::new(id)
        .area(
            egui::Modal::default_area(id)
                .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, DIALOG_TOP)),
        )
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(DIALOG_WIDTH);
            ui.set_max_width(DIALOG_WIDTH);
            ui.spacing_mut().item_spacing.y = 4.0;
            ui.heading(if dialog.editing.is_some() {
                t().edit_rule
            } else {
                t().new_rule
            });
            ui.label(
                RichText::new(if dialog.editing.is_some() {
                    t().edit_rule_subtitle
                } else {
                    t().new_rule_subtitle
                })
                .small()
                .color(theme::TEXT_MUTED),
            );
            ui.add_space(2.0);
            ui.label(
                RichText::new(t().what_to_route)
                    .small()
                    .color(theme::TEXT_DIM),
            );
            if let Some(kind) = widgets::segmented(
                ui,
                "rule_input_kind",
                dialog.kind,
                &[
                    (RuleInputKind::Process, t().rule_kind_app),
                    (RuleInputKind::Domain, t().rule_kind_site),
                ],
                true,
                !dialog.busy && dialog.editing.is_none(),
            ) {
                actions.push(Action::SelectRuleInput(kind));
            }
            ui.add_space(2.0);
            let valid = if dialog.kind == RuleInputKind::Process {
                let frame = widgets::modal_frame();
                let advanced_height = if dialog.advanced { 52.0 } else { 0.0 };
                let limit = ui.ctx().content_rect().bottom()
                    - BOTTOM_GAP
                    - (frame.inner_margin.bottom as f32 + frame.stroke.width)
                    - BUTTON_ROW_HEIGHT
                    - ACTIONS_GAP
                    - 104.0
                    - advanced_height
                    - if dialog.error.is_some() { 28.0 } else { 0.0 };
                let height = process_body_height(ui.cursor().top(), limit, dialog.advanced);
                ui.allocate_ui_with_layout(
                    egui::vec2(DIALOG_WIDTH, height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_min_size(egui::vec2(DIALOG_WIDTH, height));
                        process_input(ui, dialog, actions)
                    },
                )
                .inner
            } else {
                domain_input(ui, dialog)
            };
            ui.add_space(0.0);
            ui.label(
                RichText::new(t().where_to_route)
                    .small()
                    .color(theme::TEXT_DIM),
            );
            target_cards(ui, dialog);
            if dialog.kind == RuleInputKind::Process {
                ui.add_space(4.0);
                if dialog.advanced {
                    let available = full_path_available(dialog);
                    let mut match_path = dialog.match_mode == ProcessMatchMode::Path;
                    let response = widgets::toggle_row(
                        ui,
                        t().match_by_full_path,
                        t().full_path_detail,
                        &mut match_path,
                        available && !dialog.busy,
                    );
                    if !available {
                        response.on_hover_text(t().path_unavailable);
                    }
                    if match_path != (dialog.match_mode == ProcessMatchMode::Path) {
                        dialog.set_process_match_mode(if match_path {
                            ProcessMatchMode::Path
                        } else {
                            ProcessMatchMode::Name
                        });
                    }
                }
            }
            if let Some(error) = &dialog.error {
                ui.add_space(6.0);
                ui.add(egui::Label::new(RichText::new(error).color(theme::ERROR)).wrap());
            }
            ui.add_space(ACTIONS_GAP);
            egui::Sides::new().show(
                ui,
                |ui| {
                    if dialog.kind == RuleInputKind::Process {
                        ui.horizontal(|ui| {
                            let chevron = icons::icon_button_sized(
                                ui,
                                Icon::Chevron {
                                    open: dialog.advanced,
                                },
                                !dialog.busy,
                                20.0,
                            );
                            let link = ui.add_enabled(
                                !dialog.busy,
                                egui::Button::new(
                                    RichText::new(t().advanced).color(theme::TEXT_MUTED),
                                )
                                .frame(false),
                            );
                            if chevron.clicked() || link.clicked() {
                                dialog.advanced = !dialog.advanced;
                            }
                        });
                    }
                },
                |ui| {
                    ui.horizontal(|ui| {
                        if widgets::outline_button(ui, t().cancel, !dialog.busy).clicked() {
                            actions.push(Action::CancelAddRule);
                        }
                        let label = if dialog.busy {
                            if dialog.editing.is_some() {
                                t().saving.to_owned()
                            } else {
                                t().adding_rule.to_owned()
                            }
                        } else if dialog.editing.is_some() {
                            t().save.to_owned()
                        } else if dialog.kind == RuleInputKind::Domain {
                            let domains = rosetun_core::parse_domain_lines(
                                &dialog.domains,
                                dialog.subdomains,
                            );
                            t().add_rules(domains.domains.len())
                        } else {
                            t().add_rule.to_owned()
                        };
                        if widgets::button_fill(ui, &label, valid && !dialog.busy).clicked() {
                            actions.push(Action::SubmitAddRule);
                        }
                    });
                },
            );
        });
    if !dialog.busy && response.should_close() {
        actions.push(Action::CancelAddRule);
    }
}

fn domain_input(ui: &mut egui::Ui, dialog: &mut AddRuleDialog) -> bool {
    ui.label(
        RichText::new(t().sites_label)
            .small()
            .color(theme::TEXT_DIM),
    );
    let input = if dialog.editing.is_some() {
        ui.add_enabled(
            !dialog.busy,
            egui::TextEdit::singleline(&mut dialog.domains).desired_width(DIALOG_WIDTH),
        )
    } else {
        ui.add_enabled(
            !dialog.busy,
            egui::TextEdit::multiline(&mut dialog.domains)
                .desired_width(DIALOG_WIDTH)
                .desired_rows(5)
                .font(FontId::monospace(14.0))
                .hint_text(strings::SITES_EXAMPLE),
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
        t().include_subdomains,
        t().include_subdomains_detail,
        &mut dialog.subdomains,
        !dialog.busy,
    );
    let parsed = rosetun_core::parse_domain_lines(&dialog.domains, dialog.subdomains);
    if dialog.unchanged_domain().is_some() {
        return true;
    }
    for error in parsed.errors.iter().take(3) {
        let message = errors::rule_input(t(), &error.error);
        ui.label(
            RichText::new(t().line_error(error.line, &message))
                .small()
                .color(theme::ERROR),
        );
    }
    if parsed.errors.len() > 3 {
        ui.label(
            RichText::new(t().more_errors(parsed.errors.len() - 3))
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
                widgets::search_field(ui, &mut dialog.process_filter, t().find_app, width)
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
        .on_hover_text(t().refresh)
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
            RichText::new(t().loading_processes)
                .small()
                .color(theme::TEXT_DIM),
        );
    }
    let total: usize = dialog.processes.iter().map(|group| group.count).sum();
    let filtering = !dialog.process_filter.trim().is_empty();
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
    let heading = if filtering {
        t().found(shown)
    } else if dialog.show_all {
        t().all_processes(total)
    } else {
        t().open_now.to_owned()
    };
    ui.label(RichText::new(heading).small().color(theme::TEXT_DIM));
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
                    t().typed_process,
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
                    || t().path_unavailable.to_owned(),
                    |path| path.to_string_lossy().into_owned(),
                );
                let name = if group.count > 1 {
                    strings::process_copies(&display::safe_text(&group.name), group.count)
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
                        t().no_processes_match
                    } else {
                        t().no_running_processes
                    })
                    .color(theme::TEXT_DIM),
                );
            }
        });
    egui::Sides::new().show(
        ui,
        |ui| {
            if !filtering {
                let label = if dialog.show_all {
                    t().show_open_only.to_owned()
                } else {
                    t().show_all_processes(total)
                };
                if ui
                    .add_enabled(
                        !dialog.busy,
                        egui::Button::new(RichText::new(label).color(theme::ROSE_LIGHT))
                            .frame(false),
                    )
                    .clicked()
                {
                    dialog.show_all = !dialog.show_all;
                }
            }
        },
        |ui| {
            #[cfg(windows)]
            {
                ui.spacing_mut().interact_size.y = 32.0;
                if widgets::outline_button(ui, t().browse, !dialog.busy && !dialog.browsing)
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

fn target_cards(ui: &mut egui::Ui, dialog: &mut AddRuleDialog) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        for (index, target) in [RuleTarget::Proxy, RuleTarget::Direct, RuleTarget::Block]
            .into_iter()
            .enumerate()
        {
            let width = (DIALOG_WIDTH - 16.0) / 3.0;
            let response = widgets::choice_card(
                ui,
                index,
                width,
                dialog.target == target,
                !dialog.busy,
                target_label(target),
                |ui| {
                    ui.vertical_centered(|ui| {
                        ui.label(
                            RichText::new(target_label(target))
                                .font(FontId::new(
                                    13.0,
                                    FontFamily::Name(theme::UI_SEMIBOLD.into()),
                                ))
                                .color(target_color(target)),
                        );
                    });
                },
            );
            if response.clicked() && !dialog.busy {
                dialog.target = target;
                dialog.error = None;
            }
        }
    });
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
        use rosetun_config::RuleSetId;

        for (width, height, advanced, site) in [
            (960.0, 640.0, false, false),
            (960.0, 640.0, true, false),
            (960.0, 640.0, false, true),
            (1200.0, 780.0, false, false),
            (1200.0, 780.0, true, false),
            (1200.0, 780.0, false, true),
        ] {
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
            if site {
                dialog.kind = RuleInputKind::Domain;
                dialog.domains = "youtube.com\n192.168.1.1\nru\n127.0.0.1\ninvalid host".into();
            } else {
                dialog.advanced = advanced;
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
                |ctx| show(ctx, &mut dialog, &mut Vec::new()),
            );
            output.textures_delta.clear();
            let rect = ctx
                .memory(|memory| memory.area_rect(egui::Id::new("add_rule")))
                .unwrap();
            assert!(rect.bottom() <= height, "{rect:?} in {width}×{height}");
        }
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
