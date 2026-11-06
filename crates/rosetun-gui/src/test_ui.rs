//! A headless window to click through in tests: it runs frames, tells what was painted and
//! presses where a text stands.

use eframe::egui;

use crate::theme;

/// What one frame painted: each text with the rectangle it fills.
pub(crate) type Texts = Vec<(String, egui::Rect)>;

/// What one frame painted: each circle with its centre and radius.
pub(crate) type Circles = Vec<(egui::Pos2, f32)>;

pub(crate) struct TestScreen {
    ctx: egui::Context,
    size: egui::Vec2,
    frame: u32,
}

fn flatten(shape: &egui::Shape, out: &mut Texts) {
    match shape {
        egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| flatten(shape, out)),
        egui::Shape::Text(text) => out.push((
            text.galley.text().to_owned(),
            text.galley.rect.translate(text.pos.to_vec2()),
        )),
        _ => {}
    }
}

fn flatten_circles(shape: &egui::Shape, out: &mut Circles) {
    match shape {
        egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| flatten_circles(shape, out)),
        egui::Shape::Circle(circle) => out.push((circle.center, circle.radius)),
        _ => {}
    }
}

impl TestScreen {
    pub(crate) fn new(size: egui::Vec2) -> Self {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        Self {
            ctx,
            size,
            frame: 0,
        }
    }

    /// Runs one frame with `events` and returns what it painted.
    pub(crate) fn run(
        &mut self,
        events: Vec<egui::Event>,
        show: impl FnMut(&mut egui::Ui),
    ) -> Texts {
        let mut texts = Vec::new();
        for shape in self.paint(events, show) {
            flatten(&shape, &mut texts);
        }
        texts
    }

    /// Settles and returns the texts and the circles of the last frame.
    pub(crate) fn settle_with_circles(
        &mut self,
        mut show: impl FnMut(&mut egui::Ui),
    ) -> (Texts, Circles) {
        self.settle(&mut show);
        let (mut texts, mut circles) = (Vec::new(), Vec::new());
        for shape in self.paint(Vec::new(), &mut show) {
            flatten(&shape, &mut texts);
            flatten_circles(&shape, &mut circles);
        }
        (texts, circles)
    }

    fn paint(
        &mut self,
        events: Vec<egui::Event>,
        mut show: impl FnMut(&mut egui::Ui),
    ) -> Vec<egui::Shape> {
        self.frame += 1;
        let mut output = self.ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, self.size)),
                time: Some(f64::from(self.frame) * 0.1),
                events,
                ..Default::default()
            },
            &mut show,
        );
        output.textures_delta.clear();
        output
            .shapes
            .into_iter()
            .map(|clipped| clipped.shape)
            .collect()
    }

    /// Runs frames until what is shown has settled (layouts that need a second pass, fades).
    pub(crate) fn settle(&mut self, mut show: impl FnMut(&mut egui::Ui)) -> Texts {
        let mut texts = Vec::new();
        for _ in 0..8 {
            texts = self.run(Vec::new(), &mut show);
        }
        texts
    }

    /// Presses and releases the primary button on the middle of the text `label` and settles.
    pub(crate) fn click_text(&mut self, label: &str, mut show: impl FnMut(&mut egui::Ui)) -> Texts {
        let shown = self.settle(&mut show);
        let (_, rect) = shown
            .iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("no text {label:?} on the screen"));
        let pos = rect.center();
        let button = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        self.run(
            vec![egui::Event::PointerMoved(pos), button(true)],
            &mut show,
        );
        self.run(vec![button(false)], &mut show);
        self.settle(&mut show)
    }
}

/// A wheel turn by `delta` points, from an unknown source as egui-winit reports it on Windows,
/// so a test scrolls the way the user's wheel does.
pub(crate) fn wheel(delta: egui::Vec2) -> egui::Event {
    egui::Event::MouseWheel {
        unit: egui::MouseWheelUnit::Point,
        delta,
        phase: egui::TouchPhase::Move,
        source: egui::MouseWheelSource::Unknown,
        modifiers: egui::Modifiers::NONE,
    }
}
