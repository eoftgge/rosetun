use eframe::egui::{self, RichText};
use rosetun_config::AppConfig;

use crate::state::{Action, AddDialog, redact};
use crate::{display, strings, theme};

pub(crate) fn show(
    ctx: &egui::Context,
    config: &AppConfig,
    dialog: &mut AddDialog,
    actions: &mut Vec<Action>,
) {
    let response = egui::Modal::new(egui::Id::new("add_subscription"))
        .frame(theme::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(520.0);
            ui.heading(strings::ADD_SUBSCRIPTION);
            ui.colored_label(theme::TEXT_MUTED, strings::ADD_SUBTITLE);
            ui.add_space(18.0);
            ui.label(strings::SUBSCRIPTION_URL);
            ui.horizontal(|ui| {
                let input = ui.add_enabled(
                    !dialog.busy,
                    egui::TextEdit::singleline(&mut dialog.url)
                        .id(egui::Id::new("subscription_url_input"))
                        .hint_text(strings::URL_PLACEHOLDER)
                        .desired_width((ui.available_width() - 90.0).max(120.0)),
                );
                if dialog.focus_url {
                    input.request_focus();
                    dialog.focus_url = false;
                }
                if input.changed() {
                    dialog.error = None;
                }
                if theme::outline_button(ui, strings::PASTE, !dialog.busy).clicked() {
                    input.request_focus();
                    ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                }
            });
            ui.add(
                egui::Label::new(RichText::new(strings::URL_HELP).color(theme::TEXT_DIM)).wrap(),
            );
            let normalized = rosetun_core::normalize_subscription_url(&dialog.url);
            if !dialog.url.trim().is_empty() {
                match &normalized {
                    Ok(url) if uses_plain_http(url) => {
                        ui.add(
                            egui::Label::new(
                                RichText::new(strings::HTTP_WARNING).color(theme::ERROR),
                            )
                            .wrap(),
                        );
                    }
                    Err(message) => {
                        ui.add(
                            egui::Label::new(
                                RichText::new(form_error(config, dialog, message))
                                    .color(theme::ERROR),
                            )
                            .wrap(),
                        );
                    }
                    _ => {}
                }
            }
            ui.add_space(16.0);
            ui.label(strings::NAME);
            if ui
                .add_enabled(
                    !dialog.busy,
                    egui::TextEdit::singleline(&mut dialog.name)
                        .hint_text(strings::NAME_PLACEHOLDER)
                        .desired_width(f32::INFINITY),
                )
                .changed()
            {
                dialog.error = None;
            }
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                theme::toggle(ui, &mut dialog.send_hwid, !dialog.busy);
                ui.label(strings::SEND_DEVICE_ID);
            });
            ui.add(
                egui::Label::new(
                    RichText::new(strings::DEVICE_ID_EXPLANATION).color(theme::TEXT_DIM),
                )
                .wrap(),
            );
            if let Some(error) = &dialog.error {
                ui.add_space(12.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(form_error(config, dialog, &error.to_string()))
                            .color(theme::ERROR),
                    )
                    .wrap(),
                );
            }
            ui.add_space(22.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::button_fill(
                    ui,
                    if dialog.busy {
                        strings::ADDING
                    } else {
                        strings::ADD
                    },
                    !dialog.busy && normalized.is_ok(),
                )
                .clicked()
                {
                    actions.push(Action::SubmitAdd);
                }
                if theme::outline_button(ui, strings::CANCEL, !dialog.busy).clicked() {
                    actions.push(Action::CancelAdd);
                }
            });
        });
    if !dialog.busy && response.should_close() {
        actions.push(Action::CancelAdd);
    }
}

fn uses_plain_http(normalized: &str) -> bool {
    url::Url::parse(normalized).is_ok_and(|url| url.scheme() == "http")
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
    fn http_warning_uses_the_normalized_import_url() {
        let url =
            rosetun_core::normalize_subscription_url("happ://add/http://provider.example/sub")
                .unwrap();
        assert!(uses_plain_http(&url));
        assert!(!uses_plain_http("https://provider.example/sub"));
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
