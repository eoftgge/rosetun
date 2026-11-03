//! The dialogs side by side: one of three widths, and a footer of the same height at the
//! bottom of each.

use eframe::egui;
use rosetun_config::{ExitId, ListId, RuleSetId, SubscriptionId};

use super::*;
use crate::i18n::{self, Language};
use crate::state::{
    AddListDialog, DeleteExitDialog, NameDialog, NameDialogKind, RemoveDialog, RemoveListDialog,
    RenameDialog, RenameExitDialog, RenameListDialog,
};
use crate::widgets::DialogWidth;

const WINDOW: egui::Vec2 = egui::vec2(1440.0, 1000.0);

/// One dialog: its id, its width, the text of its Cancel button (none when it has no footer) and
/// how to open it on a state.
struct Case {
    id: &'static str,
    width: DialogWidth,
    cancel: Option<fn() -> String>,
    /// The title, for a dialog that must keep it on one line.
    title: Option<fn() -> String>,
    show: fn(&egui::Context, &mut State),
}

fn name_state(state: &mut State) {
    state.rules.screen.name = Some(NameDialog {
        kind: NameDialogKind::Create,
        name: String::from("Work"),
        error: None,
        focus: false,
    });
}

fn cases() -> Vec<Case> {
    let mut cases = vec![
        Case {
            id: "turn_off_protection",
            width: DialogWidth::Standard,
            cancel: Some(|| tr!("keep-blocked")),
            title: None,
            show: |ctx, state| connection::protection_dialog(ctx, state, &mut Vec::new()),
        },
        Case {
            id: "lockdown",
            width: DialogWidth::Standard,
            cancel: Some(|| tr!("cancel")),
            title: None,
            show: |ctx, state| {
                state.lockdown_confirmation = Some(true);
                connection::lockdown_dialog(ctx, state, &mut Vec::new());
            },
        },
        Case {
            id: "reset_settings",
            width: DialogWidth::Standard,
            cancel: Some(|| tr!("cancel")),
            title: None,
            show: |ctx, state| settings::reset_dialog(ctx, state, &mut Vec::new()),
        },
        Case {
            id: "rule_set_name",
            width: DialogWidth::Narrow,
            cancel: Some(|| tr!("cancel")),
            title: Some(|| tr!("create-rule-set")),
            show: |ctx, state| {
                name_state(state);
                rules::name_dialog(ctx, state, &mut Vec::new());
            },
        },
        Case {
            id: "delete_rules",
            width: DialogWidth::Standard,
            cancel: Some(|| tr!("cancel")),
            title: None,
            show: |ctx, state| {
                state.rules.screen.delete_set = Some(RuleSetId::new("set"));
                rules::delete_dialog(ctx, state, &mut Vec::new());
            },
        },
        Case {
            id: "rename_subscription",
            width: DialogWidth::Narrow,
            cancel: Some(|| tr!("cancel")),
            title: Some(|| tr!("rename-subscription")),
            show: |ctx, state| {
                state.subscriptions.rename = Some(RenameDialog {
                    id: SubscriptionId::new("sub"),
                    original: String::from("Work"),
                    name: String::from("Work"),
                    error: None,
                    focus: false,
                });
                subscriptions::rename_dialog(ctx, state, &mut Vec::new());
            },
        },
        Case {
            id: "remove_subscription",
            width: DialogWidth::Standard,
            cancel: Some(|| tr!("cancel")),
            title: None,
            show: |ctx, state| {
                state.subscriptions.remove = Some(RemoveDialog {
                    id: SubscriptionId::new("sub"),
                    error: None,
                });
                subscriptions::remove_dialog(ctx, state, &mut Vec::new());
            },
        },
        Case {
            id: "exit_dialog",
            width: DialogWidth::Standard,
            cancel: Some(|| tr!("cancel")),
            title: None,
            show: |ctx, state| {
                state.config_ready = true;
                state.act(crate::state::Action::OpenNewExit);
                exits::exit_dialog(ctx, state, &mut Vec::new());
            },
        },
        Case {
            id: "rename_exit",
            width: DialogWidth::Narrow,
            cancel: Some(|| tr!("cancel")),
            title: Some(|| tr!("rename-exit")),
            show: |ctx, state| {
                state.exits.rename = Some(RenameExitDialog {
                    id: ExitId::new("exit"),
                    name: String::from("Home"),
                    focus: false,
                    busy: false,
                    error: None,
                });
                exits::rename_dialog(ctx, state, &mut Vec::new());
            },
        },
        Case {
            id: "delete_exit",
            width: DialogWidth::Narrow,
            cancel: Some(|| tr!("cancel")),
            title: Some(|| tr!("delete-exit")),
            show: |ctx, state| {
                state.exits.delete = Some(DeleteExitDialog {
                    id: ExitId::new("exit"),
                    rules: 3,
                    busy: false,
                    error: None,
                });
                exits::delete_dialog(ctx, state, &mut Vec::new());
            },
        },
        Case {
            id: "add_list",
            width: DialogWidth::Standard,
            cancel: Some(|| tr!("cancel")),
            title: None,
            show: |ctx, _| lists::add_dialog(ctx, &mut AddListDialog::default(), &mut Vec::new()),
        },
        Case {
            id: "rename_list",
            width: DialogWidth::Narrow,
            cancel: Some(|| tr!("cancel")),
            title: Some(|| tr!("rename-list")),
            show: |ctx, state| {
                state.lists.rename = Some(RenameListDialog {
                    id: ListId::new("list"),
                    name: String::from("Ads"),
                    focus: false,
                    busy: false,
                    error: None,
                });
                lists::rename_dialog(ctx, state, &mut Vec::new());
            },
        },
        Case {
            id: "remove_list",
            width: DialogWidth::Standard,
            cancel: Some(|| tr!("cancel")),
            title: None,
            show: |ctx, state| {
                state.lists.remove = Some(RemoveListDialog {
                    id: ListId::new("list"),
                    busy: false,
                    error: None,
                });
                lists::remove_dialog(ctx, state, &mut Vec::new());
            },
        },
        Case {
            id: "add_subscription",
            width: DialogWidth::Standard,
            cancel: Some(|| tr!("cancel")),
            title: None,
            show: |ctx, state| {
                add_subscription::show(
                    ctx,
                    &state.config,
                    &mut crate::state::AddDialog::default(),
                    &mut Vec::new(),
                );
            },
        },
        Case {
            id: "add_rule",
            width: DialogWidth::Wide,
            cancel: Some(|| tr!("cancel")),
            title: None,
            show: |ctx, state| {
                add_rule::show(
                    ctx,
                    &mut crate::state::AddRuleDialog::new(RuleSetId::new("set")),
                    &state.config,
                    false,
                    0,
                    &[],
                    &mut Vec::new(),
                );
            },
        },
    ];
    cases.extend(windows_cases());
    cases
}

/// The dialogs only Windows has.
fn windows_cases() -> Vec<Case> {
    #[cfg(windows)]
    {
        vec![Case {
            id: "quit",
            width: DialogWidth::Standard,
            cancel: Some(|| tr!("cancel")),
            title: None,
            show: |ctx, state| connection::quit_dialog(ctx, state, &mut Vec::new()),
        }]
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

fn flatten(shape: &egui::Shape, out: &mut Vec<egui::Shape>) {
    if let egui::Shape::Vec(shapes) = shape {
        for shape in shapes {
            flatten(shape, out);
        }
    } else {
        out.push(shape.clone());
    }
}

/// One dialog after it has settled.
struct Shown {
    area: egui::Rect,
    /// The height of a field.
    field: f32,
    /// Every text painted, with the rows it takes.
    texts: Vec<(String, egui::Rect, usize)>,
}

impl Shown {
    fn text(&self, text: &str) -> (egui::Rect, usize) {
        let Some((_, rect, rows)) = self.texts.iter().find(|(painted, _, _)| painted == text)
        else {
            panic!("no text {text:?} in the dialog");
        };
        (*rect, *rows)
    }
}

fn settled(case: &Case, language: Language) -> Shown {
    i18n::in_language(language, || {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut state = State::default();
        let mut shapes = Vec::new();
        let mut field = 0.0;
        for frame in 1..=10 {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, WINDOW)),
                    time: Some(f64::from(frame) * 0.1),
                    ..Default::default()
                },
                |ui| {
                    field = widgets::field_height(ui);
                    (case.show)(ui.ctx(), &mut state);
                },
            );
            output.textures_delta.clear();
            shapes = output.shapes;
        }
        let area = ctx
            .memory(|memory| memory.area_rect(egui::Id::unique(case.id)))
            .unwrap_or_else(|| panic!("{}: not shown", case.id));
        let mut painted = Vec::new();
        for clipped in &shapes {
            flatten(&clipped.shape, &mut painted);
        }
        let texts = painted
            .iter()
            .filter_map(|shape| match shape {
                egui::Shape::Text(text) => Some((
                    text.galley.text().to_owned(),
                    text.visual_bounding_rect(),
                    text.galley.rows.len(),
                )),
                _ => None,
            })
            .collect();
        Shown { area, field, texts }
    })
}

#[test]
fn every_dialog_has_the_width_of_its_role_and_one_of_the_three() {
    let chrome = widgets::modal_frame().total_margin().sum().x;
    for case in cases() {
        let width = settled(&case, Language::English).area.width() - chrome;
        assert!(
            (width - case.width.points()).abs() < 0.5,
            "{}: {width} wide, expected {:?}",
            case.id,
            case.width
        );
        assert!(
            [400.0, 520.0, 640.0]
                .iter()
                .any(|points| (width - points).abs() < 0.5),
            "{}: {width} is none of the three widths",
            case.id
        );
    }
}

#[test]
fn every_dialog_ends_in_a_footer_a_field_high_in_both_languages() {
    let bottom = widgets::modal_frame().total_margin().bottom;
    for language in [Language::English, Language::Russian] {
        for case in cases().iter().filter(|case| case.cancel.is_some()) {
            let shown = settled(case, language);
            let (cancel, _) = shown.text(&i18n::in_language(language, case.cancel.unwrap()));
            let row_centre = shown.area.bottom() - bottom - shown.field / 2.0;
            // The text's own box sits a little off the middle of its button.
            assert!(
                (cancel.center().y - row_centre).abs() < 3.0,
                "{} {language:?}: Cancel at {} in a footer centred at {row_centre}",
                case.id,
                cancel.center().y
            );
        }
    }
}

#[test]
fn a_narrow_dialog_keeps_its_title_on_one_line_and_its_buttons_inside_in_both_languages() {
    let margin = widgets::modal_frame().total_margin();
    for language in [Language::English, Language::Russian] {
        for case in cases()
            .iter()
            .filter(|case| case.width == DialogWidth::Narrow)
        {
            let shown = settled(case, language);
            let (_, rows) = shown.text(&i18n::in_language(language, case.title.unwrap()));
            assert_eq!(rows, 1, "{} {language:?}: the title wraps", case.id);
            let (cancel, _) = shown.text(&i18n::in_language(language, case.cancel.unwrap()));
            assert!(
                cancel.left() >= shown.area.left() + margin.left,
                "{} {language:?}: the buttons leave the dialog on the left",
                case.id
            );
        }
    }
}

#[test]
fn the_added_list_dialog_ends_in_a_done_button_at_the_right_edge_in_both_languages() {
    let margin = widgets::modal_frame().total_margin();
    for language in [Language::English, Language::Russian] {
        let shown = i18n::in_language(language, || {
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let mut dialog = AddListDialog {
                result: Some((rosetun_config::ListFormat::Text, 0, Some(12))),
                ..AddListDialog::default()
            };
            let mut shapes = Vec::new();
            for frame in 1..=10 {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, WINDOW)),
                        time: Some(f64::from(frame) * 0.1),
                        ..Default::default()
                    },
                    |ui| lists::add_dialog(ui.ctx(), &mut dialog, &mut Vec::new()),
                );
                output.textures_delta.clear();
                shapes = output.shapes;
            }
            let area = ctx
                .memory(|memory| memory.area_rect(egui::Id::unique("add_list")))
                .expect("the dialog is shown");
            let mut painted = Vec::new();
            for clipped in &shapes {
                flatten(&clipped.shape, &mut painted);
            }
            let done = painted.iter().find_map(|shape| match shape {
                egui::Shape::Text(text) if text.galley.text() == tr!("done") => {
                    Some(text.visual_bounding_rect())
                }
                _ => None,
            });
            (area, done.expect("a Done button"))
        });
        let (area, done) = shown;
        let right = area.right() - margin.right;
        assert!(
            done.right() <= right && done.right() > right - 40.0,
            "{language:?}: Done ends at {} in a dialog whose content ends at {right}",
            done.right()
        );
    }
}
