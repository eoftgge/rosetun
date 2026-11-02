use eframe::egui::{self, RichText};
use rosetun_config::AppConfig;

use rosetun_config::{Node, Outbound, TlsMode, TlsParams};

use crate::errors;
use crate::state::{Action, AddDialog, QrSource, QrStage, redact};
use crate::{constants, display, i18n, theme, widgets};

use super::header;

const ACTION_ROW_HEIGHT: f32 = 40.0;
const SUBSCRIPTION_URL_ID: &str = "subscription_url_input";

pub(crate) fn show(
    ctx: &egui::Context,
    config: &AppConfig,
    dialog: &mut AddDialog,
    actions: &mut Vec<Action>,
) {
    let response = widgets::show_modal(
        ctx,
        egui::Modal::new(egui::Id::new("add_subscription")),
        |ui| {
            ui.set_width(520.0);
            ui.heading(if dialog.editing_proxy.is_some() {
                tr!("proxy-edit")
            } else {
                tr!("add-server")
            });
            import_tabs(ui, dialog);
            let shown = widgets::appear_progress(
                ui.ctx(),
                egui::Id::new("server_import_body"),
                dialog.proxy_tab,
                crate::motion::reduced(),
            );
            widgets::appear(ui, shown, |ui| {
                if dialog.proxy_tab {
                    proxy_body(ui, dialog, actions);
                } else {
                    subscription_body(ui, ctx, config, dialog, actions);
                }
            });
        },
    );
    if !dialog.busy && response.should_close() {
        actions.push(Action::CancelAdd);
    }
}

fn subscription_body(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    config: &AppConfig,
    dialog: &mut AddDialog,
    actions: &mut Vec<Action>,
) {
    // A label sits close to its field; the groups are set apart by the gaps below.
    ui.spacing_mut().item_spacing.y = theme::space::XS;
    if let Some(host) = &dialog.from_link {
        ui.colored_label(
            theme::palette().text_muted,
            tr!(
                "subscriptions-add-from-link",
                host = display::safe_text(host)
            ),
        );
    }
    ui.label(tr!("subscription-url"));
    let editable = !dialog.busy && !dialog.qr.busy();
    let reading = dialog.qr.stage == QrStage::Reading;
    let (paste, input) = widgets::field_row(
        ui,
        |ui| {
            qr_menu(ui, reading, editable, actions);
            widgets::outline_button(ui, tr!("paste"), editable).clicked()
        },
        |ui, width| {
            ui.add(
                widgets::TextField::new(&mut dialog.url)
                    .id(egui::Id::new(SUBSCRIPTION_URL_ID))
                    .hint(constants::URL_PLACEHOLDER)
                    .enabled(editable)
                    .width(width),
            )
        },
    );
    if dialog.focus_url {
        input.request_focus();
        dialog.focus_url = false;
    }
    if input.changed() {
        dialog.error = None;
        dialog.qr.error = None;
        dialog.link_error = false;
        // The host line names where the link came from, not what is typed now.
        dialog.from_link = None;
    }
    if paste {
        input.request_focus();
        ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
    }
    caption(ui, &tr!("url-help"));
    qr_status(ui, dialog, actions);
    if dialog.link_error {
        ui.add(
            egui::Label::new(RichText::new(tr!("error-open-link-invalid")).color(theme::ERROR))
                .wrap(),
        );
    }
    let normalized = rosetun_core::normalize_subscription_url(&dialog.url);
    if !dialog.url.trim().is_empty() {
        match &normalized {
            Ok(url) if uses_plain_http(url) => {
                ui.add(
                    egui::Label::new(RichText::new(tr!("http-warning")).color(theme::ERROR)).wrap(),
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
                        egui::Label::new(RichText::new(note).color(theme::palette().text_dim))
                            .wrap(),
                    );
                }
            }
        }
    }
    ui.add_space(theme::space::L);
    ui.label(tr!("import-name"));
    let placeholder = tr!("name-placeholder");
    if ui
        .add(
            widgets::TextField::new(&mut dialog.name)
                .hint(&placeholder)
                .enabled(!dialog.busy),
        )
        .changed()
    {
        dialog.error = None;
    }
    ui.add_space(theme::space::L);
    ui.horizontal(|ui| {
        widgets::toggle(ui, &mut dialog.send_hwid, !dialog.busy);
        ui.label(tr!("send-device-id"));
    });
    ui.add(
        egui::Label::new(
            RichText::new(tr!("device-id-explanation")).color(theme::palette().text_dim),
        )
        .wrap(),
    );
    if let Some(error) = &dialog.error {
        ui.add_space(theme::space::M);
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
    ui.add_space(theme::space::XL);
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), ACTION_ROW_HEIGHT),
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
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
        },
    );
}

fn import_tabs(ui: &mut egui::Ui, dialog: &mut AddDialog) {
    ui.add_space(theme::space::M);
    let selected = widgets::segmented(
        ui,
        "server_import_tabs",
        dialog.proxy_tab,
        &[
            (false, tr!("import-tab-subscription")),
            (true, tr!("import-tab-proxy")),
        ],
        true,
        !dialog.busy && !dialog.qr.busy() && dialog.editing_proxy.is_none(),
    );
    ui.add_space(theme::space::M);
    if let Some(proxy) = selected {
        dialog.select_proxy_tab(proxy);
    }
}

/// The proxy kinds the form offers; HTTPS is HTTP over TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyProtocol {
    Http,
    Https,
    Socks5,
}

impl ProxyProtocol {
    fn of(node: &Node) -> Self {
        match (&node.outbound, &node.stream.tls) {
            (Outbound::Socks5(_), _) => Self::Socks5,
            (_, TlsMode::Tls(_)) => Self::Https,
            _ => Self::Http,
        }
    }

    /// Switches the node to this protocol and keeps its login.
    fn apply(self, node: &mut Node) {
        let credentials = match &node.outbound {
            Outbound::Http(credentials) | Outbound::Socks5(credentials) => credentials.clone(),
            _ => Default::default(),
        };
        node.outbound = if self == Self::Socks5 {
            Outbound::Socks5(credentials)
        } else {
            Outbound::Http(credentials)
        };
        node.stream.tls = if self == Self::Https {
            TlsMode::Tls(TlsParams::default())
        } else {
            TlsMode::Plain
        };
    }

    /// What this protocol cannot carry, as one line under the form.
    fn note(self, language: i18n::Language) -> String {
        let args = fluent_bundle::FluentArgs::new();
        match self {
            Self::Http | Self::Https => i18n::tr_in(language, "proxy-note-tcp", &args),
            Self::Socks5 => i18n::tr_in(language, "proxy-note-socks5", &args),
        }
    }
}

/// What the dialog takes outside the scrolling form: its frame, the heading, the tabs, an error
/// of up to two lines and the buttons. Measured at 292 in Russian with a two-line error, kept
/// 4 above that; a test with the longest form fails when the dialog outgrows it.
const PROXY_DIALOG_CHROME: f32 = 296.0;
/// The form never scrolls in less than this, however small the window.
const MIN_PROXY_FORM: f32 = 160.0;
const PORT_FIELD_WIDTH: f32 = 96.0;
const PROXY_LINK_ID: &str = "proxy_link_input";

fn proxy_form_height(ctx: &egui::Context) -> f32 {
    (ctx.content_rect().height() - 2.0 * header::HEIGHT - PROXY_DIALOG_CHROME).max(MIN_PROXY_FORM)
}

fn proxy_body(ui: &mut egui::Ui, dialog: &mut AddDialog, actions: &mut Vec<Action>) {
    if dialog.proxy.is_none() {
        return;
    }
    let busy = dialog.busy;
    let height = proxy_form_height(ui.ctx());
    ui.add_enabled_ui(!busy, |ui| {
        egui::ScrollArea::vertical()
            .id_salt("proxy_form")
            .max_height(height)
            .auto_shrink([false, true])
            .show(ui, |ui| proxy_fields(ui, dialog));
    });
    let ready = dialog.proxy_ready();
    if let Some(error) = &dialog.error {
        ui.add_space(theme::space::S);
        ui.add(
            egui::Label::new(
                RichText::new(errors::add_subscription(crate::i18n::language(), error))
                    .color(theme::ERROR),
            )
            .wrap(),
        );
    }
    ui.add_space(theme::space::XL);
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), ACTION_ROW_HEIGHT),
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
            if widgets::button_fill(
                ui,
                if dialog.editing_proxy.is_some() {
                    tr!("save")
                } else {
                    tr!("add")
                },
                !busy && ready,
            )
            .clicked()
            {
                actions.push(Action::SubmitAdd);
            }
            if widgets::outline_button(ui, tr!("cancel"), !busy).clicked() {
                actions.push(Action::CancelAdd);
            }
        },
    );
}

fn proxy_fields(ui: &mut egui::Ui, dialog: &mut AddDialog) {
    // A label sits close to its field; the groups are set apart by the gaps below.
    ui.spacing_mut().item_spacing.y = theme::space::XS;
    proxy_link_row(ui, dialog);
    ui.add_space(theme::space::L);
    let port_invalid = dialog.proxy_port_value().is_none();
    let AddDialog {
        proxy: Some(node),
        proxy_port,
        error,
        ..
    } = dialog
    else {
        return;
    };
    let mut edited = false;

    ui.label(tr!("proxy-protocol"));
    let current = ProxyProtocol::of(node);
    let options = [
        (ProxyProtocol::Http, "HTTP"),
        (ProxyProtocol::Https, "HTTPS"),
        (ProxyProtocol::Socks5, "SOCKS5"),
    ];
    if let Some(chosen) = widgets::segmented(ui, "proxy_protocol", current, &options, true, true) {
        chosen.apply(node);
        edited = true;
    }
    ui.add_space(theme::space::L);

    let (server, port) = columns(
        ui,
        Some(PORT_FIELD_WIDTH),
        |ui, width| {
            ui.label(tr!("proxy-server"));
            ui.add(widgets::TextField::new(&mut node.server).width(width))
                .changed()
        },
        |ui, width| {
            ui.label(tr!("proxy-port"));
            ui.add(
                widgets::TextField::new(proxy_port)
                    .width(width)
                    .invalid(port_invalid),
            )
            .changed()
        },
    );
    edited |= server || port;
    if port {
        ui.ctx().request_repaint();
    }
    ui.add_space(theme::space::L);

    if let Outbound::Http(credentials) | Outbound::Socks5(credentials) = &mut node.outbound {
        let (username, password) = columns(
            ui,
            None,
            |ui, width| {
                ui.label(tr!("proxy-username"));
                ui.add(widgets::TextField::new(&mut credentials.username).width(width))
                    .changed()
            },
            |ui, width| {
                ui.label(tr!("proxy-password"));
                ui.add(
                    widgets::TextField::new(&mut credentials.password)
                        .password(true)
                        .width(width),
                )
                .changed()
            },
        );
        edited |= username || password;
        caption(ui, &tr!("proxy-credentials-note"));
        ui.add_space(theme::space::L);
    }

    if let TlsMode::Tls(tls) = &mut node.stream.tls {
        ui.label(tr!("proxy-sni"));
        let sni = tls.sni.get_or_insert_default();
        edited |= ui.add(widgets::TextField::new(sni)).changed();
        if sni.is_empty() {
            tls.sni = None;
        }
        caption(ui, &tr!("proxy-sni-note"));
        ui.add_space(theme::space::L);
    }

    // `save_proxy` names an unnamed proxy after its protocol, so that is what the field hints.
    let default_name = rosetun_core::node_protocol(node).to_ascii_uppercase();
    ui.label(tr!("import-name"));
    edited |= ui
        .add(widgets::TextField::new(&mut node.name).hint(&default_name))
        .changed();
    ui.add_space(theme::space::L);

    caption(ui, &ProxyProtocol::of(node).note(i18n::language()));
    if edited {
        *error = None;
    }
}

/// The link field with its button, and the line that points on to the fields. Enter in the
/// field does what the button does.
fn proxy_link_row(ui: &mut egui::Ui, dialog: &mut AddDialog) {
    ui.label(tr!("proxy-link"));
    let filled = !dialog.proxy_uri.trim().is_empty();
    let (mut fill, field) = widgets::field_row(
        ui,
        |ui| widgets::outline_button(ui, tr!("proxy-fill"), filled).clicked(),
        |ui, width| {
            ui.add(
                widgets::TextField::new(&mut dialog.proxy_uri)
                    .id(egui::Id::new(PROXY_LINK_ID))
                    .password(true)
                    .hint(constants::PROXY_URI_PLACEHOLDER)
                    .width(width),
            )
        },
    );
    if field.changed() {
        dialog.error = None;
    }
    fill |= field.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
    caption(ui, &tr!("proxy-or-fill"));
    if fill && !dialog.proxy_uri.trim().is_empty() {
        dialog.fill_from_proxy_uri();
    }
}

/// Two fields side by side, each under its own label. The right one is `right_width` wide, or
/// the row is split in half. Returns what each side returned.
fn columns<L, R>(
    ui: &mut egui::Ui,
    right_width: Option<f32>,
    left: impl FnOnce(&mut egui::Ui, f32) -> L,
    right: impl FnOnce(&mut egui::Ui, f32) -> R,
) -> (L, R) {
    let gap = ui.spacing().item_spacing.x;
    let total = ui.available_width();
    let right_width = right_width.unwrap_or((total - gap) / 2.0);
    let left_width = total - gap - right_width;
    let (mut left_out, mut right_out) = (None, None);
    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(
            egui::vec2(left_width, 0.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.set_width(left_width);
                left_out = Some(left(ui, left_width));
            },
        );
        ui.allocate_ui_with_layout(
            egui::vec2(right_width, 0.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.set_width(right_width);
                right_out = Some(right(ui, right_width));
            },
        );
    });
    (
        left_out.expect("the left column ran"),
        right_out.expect("the right column ran"),
    )
}

fn caption(ui: &mut egui::Ui, text: &str) {
    ui.add(egui::Label::new(RichText::new(text).small().color(theme::palette().text_dim)).wrap());
}

fn qr_menu(ui: &mut egui::Ui, reading: bool, enabled: bool, actions: &mut Vec<Action>) {
    // While it reads, the button names what happens and opens nothing.
    let response = if reading {
        widgets::outline_button(ui, tr!("qr-reading"), enabled)
    } else {
        widgets::outline_button_menu(ui, tr!("qr-code"), enabled)
    };
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

/// The screen clip wait, the links to choose from and a QR error, under the link field.
fn qr_status(ui: &mut egui::Ui, dialog: &AddDialog, actions: &mut Vec<Action>) {
    if matches!(dialog.qr.stage, QrStage::ScreenClip(_)) {
        ui.add_space(theme::space::XS);
        ui.horizontal(|ui| {
            ui.colored_label(theme::palette().text_muted, tr!("qr-select-region"));
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
        ui.add_space(theme::space::XS);
        ui.colored_label(theme::palette().text_muted, tr!("qr-choose-link"));
        for (index, link) in dialog.qr.choices.iter().enumerate() {
            if widgets::outline_button(ui, choice_label(index, link), !dialog.busy).clicked() {
                actions.push(Action::ChooseQrLink(index));
            }
        }
    }
}

/// The host only: the path and query carry the subscription token.
fn choice_label(index: usize, link: &str) -> String {
    let host = rosetun_core::normalize_subscription_url(link).map_or_else(
        |_| "…".into(),
        |url| rosetun_core::redacted_subscription_url(&url),
    );
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
    fn switching_import_tabs_restores_the_subscription_height() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut dialog = AddDialog::default();
        let config = AppConfig::default();
        let mut frame = 0;
        let mut height = |dialog: &mut AddDialog| {
            for _ in 0..8 {
                frame += 1;
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1440.0, 1000.0),
                        )),
                        time: Some(f64::from(frame) * 0.1),
                        ..Default::default()
                    },
                    |ui| show(ui.ctx(), &config, dialog, &mut Vec::new()),
                );
                output.textures_delta.clear();
            }
            ctx.memory(|memory| memory.area_rect(egui::Id::new("add_subscription")))
                .unwrap()
                .height()
        };
        let original = height(&mut dialog);
        for _ in 0..3 {
            assert!(dialog.select_proxy_tab(true));
            dialog.proxy.as_mut().unwrap().stream.tls =
                rosetun_config::TlsMode::Tls(Default::default());
            height(&mut dialog);
            assert!(dialog.select_proxy_tab(false));
            let restored = height(&mut dialog);
            assert!(
                (restored - original).abs() < 1.0,
                "subscription height grew from {original} to {restored}"
            );
        }
    }

    /// The height the proxy tab for HTTP had before the form was reworked.
    const OLD_HTTP_PROXY_HEIGHT: f32 = 841.0;

    fn show_frames(
        ctx: &egui::Context,
        dialog: &mut AddDialog,
        size: egui::Vec2,
        frames: std::ops::RangeInclusive<u32>,
        events: impl Fn(u32) -> Vec<egui::Event>,
    ) {
        let config = AppConfig::default();
        for frame in frames {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    time: Some(f64::from(frame) * 0.1),
                    events: events(frame),
                    ..Default::default()
                },
                |ui| show(ui.ctx(), &config, dialog, &mut Vec::new()),
            );
            output.textures_delta.clear();
        }
    }

    fn settled_area(dialog: &mut AddDialog, size: egui::Vec2) -> egui::Rect {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        show_frames(&ctx, dialog, size, 1..=10, |_| Vec::new());
        ctx.memory(|memory| memory.area_rect(egui::Id::new("add_subscription")))
            .unwrap()
    }

    fn proxy_dialog(uri: &str) -> AddDialog {
        let mut dialog = AddDialog {
            proxy_tab: true,
            ..AddDialog::default()
        };
        dialog.set_proxy(rosetun_core::parse_proxy_uri(uri).unwrap());
        dialog
    }

    /// The state of the last frame: the shapes it painted and the context that holds its
    /// widgets.
    fn settled_frame(
        dialog: &mut AddDialog,
        size: egui::Vec2,
    ) -> (egui::Context, Vec<egui::epaint::ClippedShape>) {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let config = AppConfig::default();
        let mut shapes = Vec::new();
        for frame in 1..=10 {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    time: Some(f64::from(frame) * 0.1),
                    ..Default::default()
                },
                |ui| show(ui.ctx(), &config, dialog, &mut Vec::new()),
            );
            output.textures_delta.clear();
            shapes = output.shapes;
        }
        (ctx, shapes)
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

    fn painted(shapes: &[egui::epaint::ClippedShape]) -> Vec<egui::Shape> {
        let mut out = Vec::new();
        for clipped in shapes {
            flatten(&clipped.shape, &mut out);
        }
        out
    }

    /// Where the link row of a tab ended up.
    struct LinkRow {
        field: egui::Rect,
        /// Left to right.
        buttons: Vec<egui::Rect>,
        /// The left edge of the form, as the widgets below the row start.
        form_left: f32,
        /// The right edge of the form, as the Add button's.
        form_right: f32,
    }

    fn link_row(ctx: &egui::Context, field_id: &str) -> LinkRow {
        let field_id = egui::Id::new(field_id);
        let field = ctx
            .read_response(field_id)
            .expect("the field was shown")
            .rect;
        let clickable: Vec<_> = ctx.viewport(|viewport| {
            viewport
                .prev_pass
                .widgets
                .layers()
                .flat_map(|(_, rects)| rects.iter().copied())
                .filter(|widget| widget.sense.senses_click() && widget.id != field_id)
                .collect()
        });
        let mut buttons: Vec<_> = clickable
            .iter()
            .filter(|widget| (widget.rect.center().y - field.center().y).abs() < 0.5)
            .map(|widget| widget.rect)
            .collect();
        buttons.sort_by(|a, b| a.left().total_cmp(&b.left()));
        let below = || {
            clickable
                .iter()
                .filter(|widget| widget.rect.top() > field.bottom())
        };
        let form_left = below()
            .map(|widget| widget.rect.left())
            .fold(f32::MAX, f32::min);
        let form_right = below()
            .map(|widget| widget.rect.right())
            .fold(f32::MIN, f32::max);
        LinkRow {
            field,
            buttons,
            form_left,
            form_right,
        }
    }

    fn check_link_row(row: &LinkRow, buttons: usize, gap: f32, what: &str) {
        assert_eq!(row.buttons.len(), buttons, "{what}: {:?}", row.buttons);
        for button in &row.buttons {
            assert!(
                (button.top() - row.field.top()).abs() <= 0.5
                    && (button.bottom() - row.field.bottom()).abs() <= 0.5,
                "{what}: field {:?}, button {button:?}",
                row.field
            );
        }
        assert!(
            (row.field.left() - row.form_left).abs() <= 0.5,
            "{what}: the field starts at {}, the form at {}",
            row.field.left(),
            row.form_left
        );
        let right = row.buttons.last().unwrap().right();
        assert!(
            (right - row.form_right).abs() <= 0.5,
            "{what}: the row ends at {right}, the form at {}",
            row.form_right
        );
        let mut edges = vec![row.field];
        edges.extend(&row.buttons);
        for pair in edges.windows(2) {
            let between = pair[1].left() - pair[0].right();
            assert!(
                (between - gap).abs() <= 0.5,
                "{what}: a gap of {between}, not {gap}"
            );
        }
    }

    #[test]
    fn the_link_row_of_each_tab_lines_up_in_both_languages() {
        use crate::i18n::Language::{English, Russian};

        let size = egui::vec2(1440.0, 1000.0);
        for language in [English, Russian] {
            i18n::in_language(language, || {
                let mut subscription = AddDialog::default();
                let (ctx, _) = settled_frame(&mut subscription, size);
                let gap = ctx.global_style().spacing.item_spacing.x;
                let row = link_row(&ctx, SUBSCRIPTION_URL_ID);
                check_link_row(&row, 2, gap, &format!("{language:?} subscription"));

                let mut proxy = AddDialog::default();
                assert!(proxy.select_proxy_tab(true));
                let (ctx, _) = settled_frame(&mut proxy, size);
                let row = link_row(&ctx, PROXY_LINK_ID);
                check_link_row(&row, 1, gap, &format!("{language:?} proxy"));
            });
        }
    }

    #[test]
    fn the_qr_button_has_no_padding_and_holds_its_chevron() {
        use crate::i18n::Language::{English, Russian};

        for language in [English, Russian] {
            i18n::in_language(language, || {
                let (ctx, shapes) =
                    settled_frame(&mut AddDialog::default(), egui::vec2(1440.0, 1000.0));
                let button = *link_row(&ctx, SUBSCRIPTION_URL_ID).buttons.last().unwrap();
                let shapes = painted(&shapes);
                let label = tr!("qr-code");
                let texts: Vec<_> = shapes
                    .iter()
                    .filter_map(|shape| match shape {
                        egui::Shape::Text(text) => Some(text.galley.text().to_owned()),
                        _ => None,
                    })
                    .collect();
                assert!(texts.contains(&label), "{language:?}: {texts:?}");
                assert!(
                    texts.iter().all(|text| text == text.trim_end()),
                    "{language:?}: {texts:?}"
                );
                let chevrons: Vec<_> = shapes
                    .iter()
                    .filter_map(|shape| match shape {
                        egui::Shape::Path(path)
                            if path.points.len() == 3
                                && button.intersects(path.visual_bounding_rect()) =>
                        {
                            Some(path.visual_bounding_rect())
                        }
                        _ => None,
                    })
                    .collect();
                assert_eq!(chevrons.len(), 1, "{language:?}: {chevrons:?}");
                assert!(
                    button.contains_rect(chevrons[0]),
                    "{language:?}: chevron {:?} outside button {button:?}",
                    chevrons[0]
                );
            });
        }
    }

    #[test]
    fn the_http_proxy_tab_is_shorter_than_the_old_form() {
        let mut dialog = AddDialog::default();
        assert!(dialog.select_proxy_tab(true));
        let height = settled_area(&mut dialog, egui::vec2(1440.0, 1000.0)).height();
        assert!(
            height < OLD_HTTP_PROXY_HEIGHT - 100.0,
            "{height} against {OLD_HTTP_PROXY_HEIGHT}"
        );
    }

    #[test]
    fn the_proxy_dialog_stays_below_the_header_at_the_smallest_window() {
        let size = egui::vec2(960.0, 640.0);
        for uri in [
            "http://192.0.2.10:8080",
            "https://user:pass@proxy.example.com:443",
            "socks5://user:pass@[2001:db8::1]:1080",
        ] {
            let mut dialog = proxy_dialog(uri);
            dialog.error = Some(rosetun_core::AddFromUrlError::Proxy);
            let area = settled_area(&mut dialog, size);
            assert!(area.top() >= header::HEIGHT, "{uri}: top {}", area.top());
            assert!(
                area.bottom() <= size.y - header::HEIGHT,
                "{uri}: bottom {}",
                area.bottom()
            );
        }
    }

    #[test]
    fn the_longest_proxy_form_keeps_both_buttons_in_the_smallest_window() {
        use crate::i18n::Language::{English, Russian};

        let size = egui::vec2(960.0, 640.0);
        let window = egui::Rect::from_min_size(egui::Pos2::ZERO, size);
        for language in [Russian, English] {
            i18n::in_language(language, || {
                let mut dialog = proxy_dialog("https://user:pass@proxy.example.com:443");
                // A newer settings file is the longest message a save can answer with.
                let failure =
                    rosetun_core::AddFromUrlError::Store(rosetun_core::StoreError::Invalid {
                        path: "settings.json".into(),
                        source: rosetun_config::ConfigError::UnsupportedVersion {
                            found: 99,
                            expected: 8,
                        },
                    });
                let error = errors::add_subscription(language, &failure);
                dialog.error = Some(failure);
                let (ctx, shapes) = settled_frame(&mut dialog, size);
                let rows = painted(&shapes)
                    .iter()
                    .find_map(|shape| match shape {
                        egui::Shape::Text(text) if text.galley.text() == error => {
                            Some(text.galley.rows.len())
                        }
                        _ => None,
                    })
                    .expect("the error is shown");
                assert_eq!(rows, 2, "{language:?}: the error takes {rows} lines");
                let buttons = [tr!("cancel"), tr!("add")].map(|label| {
                    painted(&shapes)
                        .iter()
                        .find_map(|shape| match shape {
                            egui::Shape::Text(text) if text.galley.text() == label => {
                                Some(text.visual_bounding_rect())
                            }
                            _ => None,
                        })
                        .unwrap_or_else(|| panic!("{language:?}: no button {label}"))
                });
                let area = ctx
                    .memory(|memory| memory.area_rect(egui::Id::new("add_subscription")))
                    .unwrap();
                for (label, rect) in ["cancel", "add"].into_iter().zip(buttons) {
                    assert!(
                        window.contains_rect(rect),
                        "{language:?}: {label} at {rect:?} is outside the window"
                    );
                    assert!(
                        rect.bottom() <= area.bottom(),
                        "{language:?}: {label} at {rect:?} is below the dialog {area:?}"
                    );
                }
                assert!(
                    area.bottom() <= size.y - header::HEIGHT,
                    "{language:?}: the dialog ends at {}",
                    area.bottom()
                );
            });
        }
    }

    #[test]
    fn the_proxy_form_grows_with_the_window_up_to_its_own_height() {
        let mut dialog = proxy_dialog("https://user:pass@proxy.example.com:443");
        let small = settled_area(&mut dialog, egui::vec2(960.0, 640.0)).height();
        let large = settled_area(&mut dialog, egui::vec2(1440.0, 1400.0)).height();
        assert!(large > small, "{small} then {large}");
    }

    #[test]
    fn enter_in_the_link_field_fills_the_form_like_the_button() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut dialog = AddDialog::default();
        assert!(dialog.select_proxy_tab(true));
        dialog.proxy_uri = "socks5://user:pass@192.0.2.10:1080".into();
        let size = egui::vec2(1440.0, 1000.0);
        show_frames(&ctx, &mut dialog, size, 1..=3, |_| Vec::new());
        ctx.memory_mut(|memory| memory.request_focus(egui::Id::new(PROXY_LINK_ID)));
        show_frames(&ctx, &mut dialog, size, 4..=5, |_| Vec::new());
        let enter = |pressed| egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: Some(egui::Key::Enter),
            pressed,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        };
        show_frames(&ctx, &mut dialog, size, 6..=7, |frame| {
            vec![enter(frame == 6)]
        });
        let node = dialog.proxy.as_ref().unwrap();
        assert_eq!(node.server, "192.0.2.10");
        assert_eq!(dialog.proxy_port, "1080");
        assert!(dialog.proxy_uri.is_empty());
        assert_eq!(ProxyProtocol::of(node), ProxyProtocol::Socks5);
    }

    #[test]
    fn switching_the_protocol_keeps_the_login() {
        let mut node = rosetun_core::parse_proxy_uri("http://user:pass@192.0.2.10:8080").unwrap();
        for protocol in [
            ProxyProtocol::Https,
            ProxyProtocol::Socks5,
            ProxyProtocol::Http,
            ProxyProtocol::Socks5,
            ProxyProtocol::Https,
        ] {
            protocol.apply(&mut node);
            assert_eq!(ProxyProtocol::of(&node), protocol);
            let (Outbound::Http(credentials) | Outbound::Socks5(credentials)) = &node.outbound
            else {
                panic!("a proxy keeps a proxy outbound");
            };
            assert_eq!(credentials.username, "user");
            assert_eq!(credentials.password, "pass");
            assert_eq!(
                matches!(node.stream.tls, TlsMode::Tls(_)),
                protocol == ProxyProtocol::Https
            );
            assert!(node.validate_proxy().is_ok(), "{protocol:?}");
        }
    }

    #[test]
    fn the_protocol_line_changes_with_the_protocol_in_both_languages() {
        use crate::i18n::Language::{English, Russian};

        let tcp = |language| ProxyProtocol::Http.note(language);
        assert_eq!(tcp(English), ProxyProtocol::Https.note(English));
        assert_eq!(tcp(Russian), ProxyProtocol::Https.note(Russian));
        assert_eq!(
            ProxyProtocol::Http.note(English),
            "Calls and games will not work through this proxy."
        );
        assert_eq!(
            ProxyProtocol::Socks5.note(English),
            "Calls and games work if the server supports it."
        );
        assert_eq!(
            ProxyProtocol::Http.note(Russian),
            "Звонки и игры через такой прокси не заработают."
        );
        assert_eq!(
            ProxyProtocol::Socks5.note(Russian),
            "Звонки и игры работают, если сервер это поддерживает."
        );
        for language in [English, Russian] {
            assert_ne!(tcp(language), ProxyProtocol::Socks5.note(language));
        }
    }

    #[test]
    fn qr_choices_show_the_host_and_hide_the_token() {
        let label = choice_label(
            1,
            "happ://add/https://sub.example.com/private-token?key=secret",
        );
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
