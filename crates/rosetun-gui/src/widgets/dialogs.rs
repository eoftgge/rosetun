use eframe::egui;

use crate::theme;

use super::{button_fill, outline_button, show_modal};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModalChoice {
    None,
    Cancel,
    Confirm,
}

pub(crate) struct ConfirmModal {
    pub(crate) id: &'static str,
    pub(crate) title: String,
    pub(crate) cancel: String,
    pub(crate) confirm: String,
    pub(crate) busy: bool,
    pub(crate) confirm_enabled: bool,
    pub(crate) button_gap: f32,
}

pub(crate) fn confirm_modal(
    ctx: &egui::Context,
    options: ConfirmModal,
    body: impl FnOnce(&mut egui::Ui),
) -> ModalChoice {
    let mut choice = ModalChoice::None;
    let response = show_modal(ctx, egui::Modal::new(egui::Id::new(options.id)), |ui| {
        ui.set_width(480.0);
        ui.heading(options.title);
        body(ui);
        ui.add_space(options.button_gap);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if button_fill(ui, options.confirm, options.confirm_enabled).clicked() {
                choice = ModalChoice::Confirm;
            }
            if outline_button(ui, options.cancel, !options.busy).clicked() {
                choice = ModalChoice::Cancel;
            }
        });
    });
    if choice == ModalChoice::None && !options.busy && response.should_close() {
        ModalChoice::Cancel
    } else {
        choice
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreeWayChoice {
    None,
    Cancel,
    Other,
    Confirm,
}

/// A confirmation with a second way forward between Cancel and the main button.
pub(crate) struct ThreeWayModal {
    pub(crate) id: &'static str,
    pub(crate) title: String,
    pub(crate) cancel: String,
    pub(crate) other: String,
    pub(crate) confirm: String,
}

pub(crate) fn three_way_modal(
    ctx: &egui::Context,
    options: ThreeWayModal,
    body: impl FnOnce(&mut egui::Ui),
) -> ThreeWayChoice {
    let mut choice = ThreeWayChoice::None;
    let response = show_modal(ctx, egui::Modal::new(egui::Id::new(options.id)), |ui| {
        ui.set_width(520.0);
        ui.heading(options.title);
        body(ui);
        ui.add_space(20.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if button_fill(ui, options.confirm, true).clicked() {
                choice = ThreeWayChoice::Confirm;
            }
            if outline_button(ui, options.other, true).clicked() {
                choice = ThreeWayChoice::Other;
            }
            if outline_button(ui, options.cancel, true).clicked() {
                choice = ThreeWayChoice::Cancel;
            }
        });
    });
    if choice == ThreeWayChoice::None && response.should_close() {
        ThreeWayChoice::Cancel
    } else {
        choice
    }
}

pub(crate) struct NameModal<'a> {
    pub(crate) id: &'static str,
    pub(crate) title: String,
    pub(crate) label: String,
    pub(crate) submit: String,
    pub(crate) name: &'a mut String,
    pub(crate) focus: &'a mut bool,
    pub(crate) error: &'a mut Option<String>,
    pub(crate) busy: bool,
    pub(crate) char_limit: Option<usize>,
}

pub(crate) fn name_modal(ctx: &egui::Context, options: NameModal<'_>) -> ModalChoice {
    let mut choice = ModalChoice::None;
    let response = show_modal(ctx, egui::Modal::new(egui::Id::new(options.id)), |ui| {
        ui.set_width(400.0);
        ui.heading(options.title);
        ui.add_space(12.0);
        ui.label(options.label);
        let mut edit = egui::TextEdit::singleline(options.name).desired_width(f32::INFINITY);
        if let Some(limit) = options.char_limit {
            edit = edit.char_limit(limit);
        }
        let input = ui.add_enabled(!options.busy, edit);
        if *options.focus {
            input.request_focus();
            *options.focus = false;
        }
        if input.changed() {
            *options.error = None;
        }
        let valid = !options.busy && !options.name.trim().is_empty();
        if valid
            && (input.has_focus() || input.lost_focus())
            && ui.input(|input| input.key_pressed(egui::Key::Enter))
        {
            choice = ModalChoice::Confirm;
        }
        if let Some(error) = options.error.as_ref() {
            ui.colored_label(theme::ERROR, error);
        }
        ui.add_space(16.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if button_fill(ui, options.submit, valid).clicked() {
                choice = ModalChoice::Confirm;
            }
            if outline_button(ui, tr!("cancel"), !options.busy).clicked() {
                choice = ModalChoice::Cancel;
            }
        });
    });
    if choice == ModalChoice::None && !options.busy && response.should_close() {
        ModalChoice::Cancel
    } else {
        choice
    }
}
