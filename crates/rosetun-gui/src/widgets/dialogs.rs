use eframe::egui;

use crate::theme;

use super::{TextField, button_fill, field_height, outline_button, show_modal};

/// The room a wide dialog leaves at the sides of a narrow window.
const WIDE_SIDE_ROOM: f32 = 144.0;
/// The least a wide dialog shrinks to.
const WIDE_FLOOR: f32 = 320.0;

/// The widths a dialog has, by what it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DialogWidth {
    /// A question with a short text, or one name to type.
    Narrow,
    /// A confirmation with a longer text, a form, details.
    Standard,
    /// A form with a list in it. It gives way to a narrow window.
    Wide,
}

impl DialogWidth {
    pub(crate) const fn points(self) -> f32 {
        match self {
            Self::Narrow => 400.0,
            Self::Standard => 520.0,
            Self::Wide => 640.0,
        }
    }

    /// The width in a window that is `window` points wide.
    pub(crate) fn within(self, window: f32) -> f32 {
        match self {
            Self::Wide => self.points().min((window - WIDE_SIDE_ROOM).max(WIDE_FLOOR)),
            Self::Narrow | Self::Standard => self.points(),
        }
    }
}

/// A dialog in the shared frame: its width, and where it hangs when it is not centred.
pub(crate) struct Dialog {
    id: &'static str,
    width: DialogWidth,
    top: Option<f32>,
}

impl Dialog {
    pub(crate) fn new(id: &'static str, width: DialogWidth) -> Self {
        Self {
            id,
            width,
            top: None,
        }
    }

    /// Hangs the dialog this far from the top of the window instead of centring it.
    pub(crate) fn top(mut self, top: f32) -> Self {
        self.top = Some(top);
        self
    }

    pub(crate) fn show<T>(
        self,
        ctx: &egui::Context,
        content: impl FnOnce(&mut egui::Ui) -> T,
    ) -> egui::ModalResponse<T> {
        let id = egui::Id::unique(self.id);
        let modal = egui::Modal::new(id);
        let modal = match self.top {
            Some(top) => modal.area(
                egui::Modal::default_area(id)
                    .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, top)),
            ),
            None => modal,
        };
        let width = self.width.within(ctx.content_rect().width());
        show_modal(ctx, modal, |ui| {
            ui.set_width(width);
            content(ui)
        })
    }
}

/// The buttons that close a dialog: the main one at the right edge, Cancel to its left and,
/// when there is one, a second way forward between them.
#[must_use = "a footer does nothing until it is shown"]
pub(crate) struct DialogFooter<'a> {
    primary: egui::WidgetText,
    primary_enabled: bool,
    primary_hint: Option<&'a str>,
    other: Option<egui::WidgetText>,
    cancel: egui::WidgetText,
    cancel_enabled: bool,
    gap: f32,
}

/// What the footer's buttons answered.
pub(crate) struct FooterResponses {
    pub(crate) primary: egui::Response,
    pub(crate) other: Option<egui::Response>,
    pub(crate) cancel: egui::Response,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FooterChoice {
    None,
    Cancel,
    Other,
    Primary,
}

impl FooterResponses {
    pub(crate) fn choice(&self) -> FooterChoice {
        if self.primary.clicked() {
            FooterChoice::Primary
        } else if self.other.as_ref().is_some_and(egui::Response::clicked) {
            FooterChoice::Other
        } else if self.cancel.clicked() {
            FooterChoice::Cancel
        } else {
            FooterChoice::None
        }
    }
}

impl<'a> DialogFooter<'a> {
    pub(crate) fn new(
        primary: impl Into<egui::WidgetText>,
        cancel: impl Into<egui::WidgetText>,
    ) -> Self {
        Self {
            primary: primary.into(),
            primary_enabled: true,
            primary_hint: None,
            other: None,
            cancel: cancel.into(),
            cancel_enabled: true,
            gap: theme::space::XL,
        }
    }

    /// Whether the main button can be pressed.
    pub(crate) fn primary_enabled(mut self, enabled: bool) -> Self {
        self.primary_enabled = enabled;
        self
    }

    /// Why the main button cannot be pressed, shown when the pointer rests on it.
    pub(crate) fn primary_hint(mut self, hint: Option<&'a str>) -> Self {
        self.primary_hint = hint;
        self
    }

    /// A second way forward, between Cancel and the main button.
    #[cfg(any(windows, test))]
    pub(crate) fn other(mut self, other: impl Into<egui::WidgetText>) -> Self {
        self.other = Some(other.into());
        self
    }

    /// Cancel cannot be pressed while the dialog works.
    pub(crate) fn busy(mut self, busy: bool) -> Self {
        self.cancel_enabled = !busy;
        self
    }

    /// For a footer under a divider, which already sets it apart.
    pub(crate) fn under_divider(mut self) -> Self {
        self.gap = 0.0;
        self
    }
}

/// The footer of a dialog, a field high, after the gap every dialog keeps above it.
pub(crate) fn dialog_footer(ui: &mut egui::Ui, footer: DialogFooter<'_>) -> FooterResponses {
    dialog_footer_with_note(ui, footer, |_| {})
}

/// The footer with `note` at the left edge, on the row of the buttons.
pub(crate) fn dialog_footer_with_note(
    ui: &mut egui::Ui,
    footer: DialogFooter<'_>,
    note: impl FnOnce(&mut egui::Ui),
) -> FooterResponses {
    ui.add_space(footer.gap);
    let ((), responses) = egui::Sides::new()
        .height(field_height(ui))
        .show(ui, note, |ui| {
            let mut primary = button_fill(ui, footer.primary, footer.primary_enabled);
            if let Some(hint) = footer.primary_hint {
                primary = primary.on_disabled_hover_text(hint);
            }
            let other = footer.other.map(|other| outline_button(ui, other, true));
            let cancel = outline_button(ui, footer.cancel, footer.cancel_enabled);
            FooterResponses {
                primary,
                other,
                cancel,
            }
        });
    responses
}

/// The footer of a dialog that only reports a result: the one button, at the right edge, on a
/// row a field high after the same gap.
pub(crate) fn dialog_done(ui: &mut egui::Ui, label: impl Into<egui::WidgetText>) -> egui::Response {
    ui.add_space(theme::space::XL);
    let ((), done) = egui::Sides::new().height(field_height(ui)).show(
        ui,
        |_| {},
        |ui| button_fill(ui, label, true),
    );
    done
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModalChoice {
    None,
    Cancel,
    Confirm,
}

impl From<FooterChoice> for ModalChoice {
    fn from(choice: FooterChoice) -> Self {
        match choice {
            FooterChoice::Primary => Self::Confirm,
            FooterChoice::Cancel => Self::Cancel,
            FooterChoice::Other | FooterChoice::None => Self::None,
        }
    }
}

pub(crate) struct ConfirmModal {
    pub(crate) id: &'static str,
    pub(crate) title: String,
    pub(crate) cancel: String,
    pub(crate) confirm: String,
    pub(crate) busy: bool,
    pub(crate) confirm_enabled: bool,
    pub(crate) width: DialogWidth,
}

pub(crate) fn confirm_modal(
    ctx: &egui::Context,
    options: ConfirmModal,
    body: impl FnOnce(&mut egui::Ui),
) -> ModalChoice {
    let mut choice = ModalChoice::None;
    let response = Dialog::new(options.id, options.width).show(ctx, |ui| {
        ui.heading(options.title);
        body(ui);
        let footer = DialogFooter::new(options.confirm, options.cancel)
            .primary_enabled(options.confirm_enabled)
            .busy(options.busy);
        choice = dialog_footer(ui, footer).choice().into();
    });
    if choice == ModalChoice::None && !options.busy && response.should_close() {
        ModalChoice::Cancel
    } else {
        choice
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreeWayChoice {
    None,
    Cancel,
    Other,
    Confirm,
}

/// A confirmation with a second way forward between Cancel and the main button.
#[cfg(windows)]
pub(crate) struct ThreeWayModal {
    pub(crate) id: &'static str,
    pub(crate) title: String,
    pub(crate) cancel: String,
    pub(crate) other: String,
    pub(crate) confirm: String,
}

#[cfg(windows)]
pub(crate) fn three_way_modal(
    ctx: &egui::Context,
    options: ThreeWayModal,
    body: impl FnOnce(&mut egui::Ui),
) -> ThreeWayChoice {
    let mut choice = ThreeWayChoice::None;
    let response = Dialog::new(options.id, DialogWidth::Standard).show(ctx, |ui| {
        ui.heading(options.title);
        body(ui);
        let footer = DialogFooter::new(options.confirm, options.cancel).other(options.other);
        choice = match dialog_footer(ui, footer).choice() {
            FooterChoice::Primary => ThreeWayChoice::Confirm,
            FooterChoice::Other => ThreeWayChoice::Other,
            FooterChoice::Cancel => ThreeWayChoice::Cancel,
            FooterChoice::None => ThreeWayChoice::None,
        };
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
    let response = Dialog::new(options.id, DialogWidth::Narrow).show(ctx, |ui| {
        ui.heading(options.title);
        ui.add_space(theme::space::M);
        ui.label(options.label);
        let mut field = TextField::new(options.name).enabled(!options.busy);
        if let Some(limit) = options.char_limit {
            field = field.char_limit(limit);
        }
        let input = ui.add(field);
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
        let footer = DialogFooter::new(options.submit, tr!("cancel"))
            .primary_enabled(valid)
            .busy(options.busy);
        let clicked = ModalChoice::from(dialog_footer(ui, footer).choice());
        if clicked != ModalChoice::None {
            choice = clicked;
        }
    });
    if choice == ModalChoice::None && !options.busy && response.should_close() {
        ModalChoice::Cancel
    } else {
        choice
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(read: impl FnOnce(&mut egui::Ui)) {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut read = Some(read);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                if let Some(read) = read.take() {
                    read(ui);
                }
            });
        });
        output.textures_delta.clear();
    }

    #[test]
    fn the_three_widths_grow_and_only_the_widest_gives_way_to_a_window() {
        assert!(DialogWidth::Narrow.points() < DialogWidth::Standard.points());
        assert!(DialogWidth::Standard.points() < DialogWidth::Wide.points());
        for width in [DialogWidth::Narrow, DialogWidth::Standard] {
            assert_eq!(width.within(300.0), width.points());
        }
        assert_eq!(DialogWidth::Wide.within(1440.0), DialogWidth::Wide.points());
        assert_eq!(DialogWidth::Wide.within(640.0), 496.0);
        assert_eq!(DialogWidth::Wide.within(100.0), WIDE_FLOOR);
    }

    #[test]
    fn the_footer_buttons_are_a_field_high_with_the_main_one_at_the_right_edge() {
        run(|ui| {
            ui.set_width(DialogWidth::Standard.points());
            let right = ui.max_rect().right();
            let height = field_height(ui);
            for other in [None, Some("Keep VPN and quit")] {
                let mut footer = DialogFooter::new("Add", "Cancel");
                if let Some(other) = other {
                    footer = footer.other(other);
                }
                let answered = dialog_footer(ui, footer);
                assert_eq!(answered.primary.rect.height(), height);
                assert_eq!(answered.cancel.rect.height(), height);
                assert_eq!(answered.primary.rect.right(), right);
                assert!(answered.cancel.rect.right() < answered.primary.rect.left());
                if let Some(second) = answered.other {
                    assert_eq!(second.rect.height(), height);
                    assert!(answered.cancel.rect.right() < second.rect.left());
                    assert!(second.rect.right() < answered.primary.rect.left());
                }
            }
        });
    }

    #[test]
    fn every_footer_keeps_the_same_gap_above_it() {
        run(|ui| {
            for footer in [
                DialogFooter::new("Add", "Cancel"),
                DialogFooter::new("Add", "Cancel").primary_enabled(false),
                DialogFooter::new("Add", "Cancel").busy(true),
                DialogFooter::new("Add", "Cancel").other("Keep VPN and quit"),
            ] {
                let above = ui.cursor().top();
                let answered = dialog_footer(ui, footer);
                assert_eq!(answered.primary.rect.top() - above, theme::space::XL);
            }
            let above = ui.cursor().top();
            let answered = dialog_footer(ui, DialogFooter::new("Add", "Cancel").under_divider());
            assert_eq!(answered.primary.rect.top(), above);
        });
    }

    #[test]
    fn a_footer_that_cannot_be_used_keeps_its_size_and_says_what_it_cannot_do() {
        run(|ui| {
            let ready = dialog_footer(ui, DialogFooter::new("Add", "Cancel"));
            let waiting = dialog_footer(
                ui,
                DialogFooter::new("Add", "Cancel")
                    .primary_enabled(false)
                    .primary_hint(Some("Enter a site"))
                    .busy(true),
            );
            assert!(ready.primary.enabled() && ready.cancel.enabled());
            assert!(!waiting.primary.enabled() && !waiting.cancel.enabled());
            assert_eq!(ready.primary.rect.size(), waiting.primary.rect.size());
            assert_eq!(ready.cancel.rect.size(), waiting.cancel.rect.size());
            assert_eq!(waiting.choice(), FooterChoice::None);
        });
    }

    #[test]
    fn a_lone_done_button_stands_at_the_right_edge_a_field_high_after_the_gap() {
        run(|ui| {
            ui.set_width(DialogWidth::Standard.points());
            let right = ui.max_rect().right();
            let before = ui.cursor().top();
            let done = dialog_done(ui, "Done");
            assert_eq!(done.rect.right(), right);
            assert_eq!(done.rect.height(), field_height(ui));
            assert!((done.rect.top() - before - theme::space::XL).abs() < 0.5);
        });
    }

    #[test]
    fn a_note_stands_at_the_left_edge_of_the_footer_row() {
        run(|ui| {
            ui.set_width(DialogWidth::Standard.points());
            let left = ui.max_rect().left();
            let mut note = None;
            let answered = dialog_footer_with_note(
                ui,
                DialogFooter::new("Add", "Cancel").under_divider(),
                |ui| note = Some(ui.label("Enter a site").rect),
            );
            let note = note.unwrap();
            assert_eq!(note.left(), left);
            assert!(note.right() < answered.cancel.rect.left());
        });
    }
}
