use eframe::egui::{self, RichText};
use rosetun_config::AppConfig;

use crate::errors;
use crate::state::{Action, AddDialog, redact};
use crate::strings::t;
use crate::{display, strings, theme, widgets};

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
                if widgets::outline_button(ui, tr!("paste"), !dialog.busy).clicked() {
                    input.request_focus();
                    ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                }
            });
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
                                    &errors::subscription_url(t(), error),
                                ))
                                .color(theme::ERROR),
                            )
                            .wrap(),
                        );
                    }
                    _ => {}
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
                            &errors::add_subscription(t(), error),
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
                    !dialog.busy && normalized.is_ok(),
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
