//! The new-version offer's state line, buttons and install confirmation,
//! shared by the connection screen and Settings so both read the same.

use eframe::egui;
use rosetun_core::{Release, UpdateDownloadError};

use crate::display;
use crate::state::{Action, State, UpdateDownload, UpdateFailure};
use crate::theme;
use crate::widgets;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OfferButton {
    Download,
    Cancel,
    Install,
    OpenGithub,
    Skip,
}

/// The offer's buttons from left to right. The first is the main action,
/// filled, unless it is Cancel.
pub(crate) fn offer_buttons(state: &State) -> Vec<OfferButton> {
    let download = state.offer_download();
    let mut buttons = Vec::new();
    if State::can_install_updates() {
        match download {
            UpdateDownload::Idle | UpdateDownload::Failed { .. } => {
                buttons.push(OfferButton::Download);
            }
            UpdateDownload::Downloading { .. } => buttons.push(OfferButton::Cancel),
            UpdateDownload::Ready(_) => buttons.push(OfferButton::Install),
            UpdateDownload::Installing(_) => {}
        }
    }
    buttons.push(OfferButton::OpenGithub);
    if !matches!(
        download,
        UpdateDownload::Downloading { .. } | UpdateDownload::Installing(_)
    ) {
        buttons.push(OfferButton::Skip);
    }
    buttons
}

/// One button of the offer; `filled` for the main action. `compact` uses
/// the short Skip label of the strip on the connection screen.
pub(crate) fn offer_button(
    ui: &mut egui::Ui,
    state: &State,
    release: &Release,
    button: OfferButton,
    filled: bool,
    compact: bool,
    actions: &mut Vec<Action>,
) {
    let (label, enabled) = match button {
        OfferButton::Download => (tr!("update-download"), state.config_ready),
        OfferButton::Cancel => (tr!("cancel"), true),
        OfferButton::Install => (tr!("update-install"), true),
        OfferButton::OpenGithub => (tr!("update-open-github"), true),
        OfferButton::Skip if compact => (tr!("update-offer-skip"), state.can_edit_settings()),
        OfferButton::Skip => (tr!("update-skip"), state.can_edit_settings()),
    };
    let clicked = if filled && button != OfferButton::Cancel {
        widgets::button_fill(ui, label, enabled).clicked()
    } else {
        widgets::outline_button(ui, label, enabled).clicked()
    };
    if !clicked {
        return;
    }
    match button {
        OfferButton::Download => actions.push(Action::DownloadUpdate),
        OfferButton::Cancel => actions.push(Action::CancelUpdateDownload),
        OfferButton::Install => actions.push(Action::InstallUpdate),
        OfferButton::OpenGithub => {
            display::open_web_link(ui.ctx(), &release.url);
        }
        OfferButton::Skip => actions.push(Action::SkipVersion),
    }
}

/// What the download is doing, with its colour; nothing before the first click.
pub(crate) fn offer_status(state: &State) -> Option<(String, egui::Color32)> {
    let muted = theme::palette().text_muted;
    match state.offer_download() {
        UpdateDownload::Idle => None,
        UpdateDownload::Downloading {
            received, total, ..
        } => Some((
            match total {
                Some(total) if *total > 0 => tr!(
                    "update-downloading-percent",
                    percent = (received.saturating_mul(100) / total).min(100).to_string()
                ),
                _ => tr!("update-downloading"),
            },
            muted,
        )),
        UpdateDownload::Ready(_) => Some((tr!("update-ready"), muted)),
        UpdateDownload::Installing(_) => Some((tr!("update-installing"), muted)),
        UpdateDownload::Failed { failure, .. } => Some((failure_text(failure), theme::ERROR)),
    }
}

fn failure_text(failure: &UpdateFailure) -> String {
    match failure {
        UpdateFailure::Download(UpdateDownloadError::Request | UpdateDownloadError::Status(_)) => {
            tr!("update-error-network")
        }
        UpdateFailure::Download(UpdateDownloadError::VpnRequest) => tr!("update-error-vpn"),
        UpdateFailure::Download(UpdateDownloadError::Unsigned) => tr!("update-error-unsigned"),
        UpdateFailure::Download(UpdateDownloadError::Save | UpdateDownloadError::Cancelled) => {
            tr!("update-error-save")
        }
        UpdateFailure::Download(_) => tr!("update-error-check"),
        UpdateFailure::Declined | UpdateFailure::Installer(_) | UpdateFailure::Start => {
            tr!("update-install-failed")
        }
    }
}

/// Asked before the installer runs while a session is up: it ends the session.
pub(crate) fn install_dialog(ctx: &egui::Context, actions: &mut Vec<Action>) {
    let choice = widgets::confirm_modal(
        ctx,
        widgets::ConfirmModal {
            id: "install_update",
            title: tr!("update-install-confirm-title"),
            cancel: tr!("cancel"),
            confirm: tr!("update-install"),
            busy: false,
            confirm_enabled: true,
            width: widgets::DialogWidth::Standard,
        },
        |ui| {
            ui.add_space(theme::space::M);
            ui.add(egui::Label::new(tr!("update-install-confirm-body")).wrap());
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::ConfirmInstallUpdate(false)),
        widgets::ModalChoice::Confirm => actions.push(Action::ConfirmInstallUpdate(true)),
        widgets::ModalChoice::None => {}
    }
}
