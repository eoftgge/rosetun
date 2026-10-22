use eframe::egui::{self, RichText};
use rosetun_config::AppConfig;

use crate::errors;
use crate::icons::{self, Icon};
use crate::state::{Action, AddDialog, QrSource, QrStage, redact};
use crate::{constants, display, theme, widgets};

pub(crate) fn show(
    ctx: &egui::Context,
    config: &AppConfig,
    dialog: &mut AddDialog,
    actions: &mut Vec<Action>,
) {
    let response = egui::Modal::new(egui::Id::new("add_subscription"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(520.0);
            ui.heading(tr!("add-subscription"));
            ui.colored_label(theme::TEXT_MUTED, tr!("add-subtitle"));
            ui.add_space(18.0);
            ui.label(tr!("subscription-url"));
            let editable = !dialog.busy && !dialog.qr.busy();
            ui.horizontal(|ui| {
                let input = ui.add_enabled(
                    editable,
                    egui::TextEdit::singleline(&mut dialog.url)
                        .id(egui::Id::new("subscription_url_input"))
                        .hint_text(constants::URL_PLACEHOLDER)
                        .desired_width((ui.available_width() - 210.0).max(120.0)),
                );
                if dialog.focus_url {
                    input.request_focus();
                    dialog.focus_url = false;
                }
                if input.changed() {
                    dialog.error = None;
                    dialog.qr.error = None;
                }
                if widgets::outline_button(ui, tr!("paste"), editable).clicked() {
                    input.request_focus();
                    ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                }
                qr_menu(ui, dialog, editable, actions);
            });
            qr_status(ui, dialog, actions);
            ui.add(egui::Label::new(RichText::new(tr!("url-help")).color(theme::TEXT_DIM)).wrap());
            let normalized = rosetun_core::normalize_subscription_url(&dialog.url);
            if !dialog.url.trim().is_empty() {
                match &normalized {
                    Ok(url) if uses_plain_http(url) => {
                        ui.add(
                            egui::Label::new(
                                RichText::new(tr!("http-warning")).color(theme::ERROR),
                            )
                            .wrap(),
                        );
                    }
                    Err(error) => {
                        ui.add(
                            egui::Label::new(
                                RichText::new(form_error(
                                    config,
                                    dialog,
                                    &errors::subscription_url(crate::i18n::language(), error),
                                ))
                                .color(theme::ERROR),
                            )
                            .wrap(),
                        );
                    }
                    Ok(_) => {
                        if let Some(note) = assumed_https_note(&dialog.url) {
                            ui.add(
                                egui::Label::new(RichText::new(note).color(theme::TEXT_DIM)).wrap(),
                            );
                        }
                    }
                }
            }
            ui.add_space(16.0);
            ui.label(tr!("name"));
            if ui
                .add_enabled(
                    !dialog.busy,
                    egui::TextEdit::singleline(&mut dialog.name)
                        .hint_text(tr!("name-placeholder"))
                        .desired_width(f32::INFINITY),
                )
                .changed()
            {
                dialog.error = None;
            }
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                widgets::toggle(ui, &mut dialog.send_hwid, !dialog.busy);
                ui.label(tr!("send-device-id"));
            });
            ui.add(
                egui::Label::new(
                    RichText::new(tr!("device-id-explanation")).color(theme::TEXT_DIM),
                )
                .wrap(),
            );
            if let Some(error) = &dialog.error {
                ui.add_space(12.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(form_error(
                            config,
                            dialog,
                            &errors::add_subscription(crate::i18n::language(), error),
                        ))
                        .color(theme::ERROR),
                    )
                    .wrap(),
                );
            }
            ui.add_space(22.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::button_fill(
                    ui,
                    if dialog.busy {
                        tr!("adding")
                    } else {
                        tr!("add")
                    },
                    editable && normalized.is_ok(),
                )
                .clicked()
                {
                    actions.push(Action::SubmitAdd);
                }
                if widgets::outline_button(ui, tr!("cancel"), !dialog.busy).clicked() {
                    actions.push(Action::CancelAdd);
                }
            });
        });
    if !dialog.busy && response.should_close() {
        actions.push(Action::CancelAdd);
    }
}

fn qr_menu(ui: &mut egui::Ui, dialog: &AddDialog, enabled: bool, actions: &mut Vec<Action>) {
    let reading = dialog.qr.stage == QrStage::Reading;
    let label = if reading {
        tr!("qr-reading")
    } else {
        // Room for the chevron painted over the button's right edge.
        format!("{}     ", tr!("qr-code"))
    };
    let response = widgets::outline_button(ui, label, enabled);
    if !reading {
        icons::paint(
            ui.painter(),
            egui::pos2(response.rect.right() - 14.0, response.rect.center().y),
            Icon::Chevron { open: true },
            if enabled {
                theme::TEXT_DIM
            } else {
                theme::BORDER_STRONG
            },
        );
    }
    let mut sources = vec![
        (tr!("qr-from-file"), QrSource::File),
        (tr!("qr-from-clipboard"), QrSource::Clipboard),
    ];
    if cfg!(windows) {
        sources.push((tr!("qr-from-screen"), QrSource::ScreenClip));
    }
    widgets::menu_popup(&response).show(|ui| {
        ui.set_width(230.0);
        for (label, source) in sources {
            if widgets::menu_item(
                ui,
                widgets::MenuItem {
                    label: &label,
                    enabled,
                    selected: false,
                    danger: false,
                    note: None,
                },
            )
            .clicked()
            {
                actions.push(Action::ReadQr(source));
                ui.close();
            }
        }
    });
}

/// The screen clip wait, the links to choose from and a QR error, right under the link field.
fn qr_status(ui: &mut egui::Ui, dialog: &AddDialog, actions: &mut Vec<Action>) {
    if matches!(dialog.qr.stage, QrStage::ScreenClip(_)) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.colored_label(theme::TEXT_MUTED, tr!("qr-select-region"));
            if widgets::outline_button(ui, tr!("cancel"), true).clicked() {
                actions.push(Action::CancelQr);
            }
        });
    }
    if let Some(error) = dialog.qr.error {
        ui.add(
            egui::Label::new(
                RichText::new(errors::qr(crate::i18n::language(), error)).color(theme::ERROR),
            )
            .wrap(),
        );
    }
    if !dialog.qr.choices.is_empty() {
        ui.add_space(6.0);
        ui.colored_label(theme::TEXT_MUTED, tr!("qr-choose-link"));
        for (index, link) in dialog.qr.choices.iter().enumerate() {
            if widgets::outline_button(ui, choice_label(index, link), !dialog.busy).clicked() {
                actions.push(Action::ChooseQrLink(index));
            }
        }
    }
}

/// The host only: the path and query carry the subscription token.
fn choice_label(index: usize, link: &str) -> String {
    let host = rosetun_core::normalize_subscription_url(link)
        .map(|url| rosetun_core::redacted_subscription_url(&url))
        .unwrap_or_else(|_| "…".into());
    format!("{}. {host}", index + 1)
}

fn uses_plain_http(normalized: &str) -> bool {
    url::Url::parse(normalized).is_ok_and(|url| url.scheme() == "http")
}

fn assumed_https_note(input: &str) -> Option<String> {
    if !rosetun_core::subscription_url_assumes_https(input) {
        return None;
    }
    let url = rosetun_core::normalize_subscription_url(input).ok()?;
    Some(tr!(
        "url-assumed-https",
        url = rosetun_core::redacted_subscription_url(&url)
    ))
}

fn form_error(config: &AppConfig, dialog: &AddDialog, message: &str) -> String {
    let text = display::provider_multiline(&redact(config, message), &dialog.url);
    match rosetun_core::normalize_subscription_url(&dialog.url) {
        Ok(url) => display::provider_multiline(&text, &url),
        Err(_) => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_choices_show_the_host_and_hide_the_token() {
        let label = choice_label(1, "happ://add/https://sub.example.com/private-token?key=secret");
        assert_eq!(label, "2. https://sub.example.com/…");
        let label = choice_label(0, "sub.example.com/private-token");
        assert_eq!(label, "1. https://sub.example.com/…");
    }

    #[test]
    fn http_warning_uses_the_normalized_import_url() {
        let url =
            rosetun_core::normalize_subscription_url("happ://add/http://provider.example/sub")
                .unwrap();
        assert!(uses_plain_http(&url));
        assert!(!uses_plain_http("https://provider.example/sub"));
    }

    #[test]
    fn assumed_https_note_appears_only_without_a_scheme() {
        let note = assumed_https_note("sub.example.com/private-token?key=query-secret").unwrap();
        assert!(note.contains("https://sub.example.com/…"), "{note}");
        assert!(!note.contains("private-token") && !note.contains("query-secret"));
        assert_eq!(
            assumed_https_note("https://sub.example.com/private-token"),
            None
        );
        assert_eq!(
            assumed_https_note("http://sub.example.com/private-token"),
            None
        );
        assert_eq!(assumed_https_note("sub"), None);
    }

    #[test]
    fn add_errors_without_a_scheme_redact_the_pending_url() {
        let dialog = AddDialog {
            url: "provider.example/private-token?key=query-secret".into(),
            ..AddDialog::default()
        };
        let output = form_error(
            &AppConfig::default(),
            &dialog,
            "failure
https://provider.example/private-token?key=query-secret",
        );
        assert!(!output.contains("private-token"), "{output}");
        assert!(!output.contains("query-secret"), "{output}");
    }

    #[test]
    fn add_errors_redact_the_pending_url_before_it_is_stored() {
        let dialog = AddDialog {
            url: "https://provider.example/private-token?key=query-secret".into(),
            ..AddDialog::default()
        };
        let output = form_error(
            &AppConfig::default(),
            &dialog,
            &format!("failure\n{}", dialog.url),
        );
        assert_eq!(output, "failure\nhttps://provider.example/…");
    }
}
