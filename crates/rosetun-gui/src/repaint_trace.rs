//! Why frames are drawn, logged on request: with `ROSETUN_REPAINT_TRACE=1`
//! the GUI log gets a summary at most every 250 ms of the frames drawn since
//! the last one, the places that asked egui for them and the input that came
//! with them. Without the variable nothing is collected.
//!
//! Only source locations and kinds of input are logged: no text, keys,
//! positions or paths outside the source tree.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use eframe::egui;

const ENV: &str = "ROSETUN_REPAINT_TRACE";
const SUMMARY_INTERVAL: Duration = Duration::from_millis(250);
/// How many causes and kinds of input a summary names.
const TOP: usize = 6;
/// A frame nobody asked for in the pass before: egui's second, settling
/// frame after a request, or a redraw from the system.
const NO_CAUSE: &str = "none";
const NO_INPUT: &str = "none";

#[derive(Debug)]
pub(crate) struct RepaintTrace {
    tally: Tally,
    /// The window's outer rect at the last frame, to tell moves and resizes.
    last_rect: Option<egui::Rect>,
}

/// Frames counted since the last summary. Each cause and kind of input is
/// counted once per frame it appeared in.
#[derive(Debug, Default)]
struct Tally {
    started: Option<Instant>,
    frames: u32,
    causes: HashMap<String, u32>,
    inputs: HashMap<&'static str, u32>,
}

#[derive(Debug, PartialEq, Eq)]
struct Summary {
    frames: u32,
    elapsed_ms: u64,
    causes: Counts<String>,
    inputs: Counts<&'static str>,
}

/// The most frequent entries, most frequent first, as `name=count, …`.
#[derive(Debug, PartialEq, Eq)]
struct Counts<T>(Vec<(T, u32)>);

impl<T: fmt::Display> fmt::Display for Counts<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, (name, count)) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{name}={count}")?;
        }
        Ok(())
    }
}

impl RepaintTrace {
    pub(crate) fn from_env() -> Option<Self> {
        let value = std::env::var_os(ENV)?;
        (!value.is_empty() && value != "0").then(|| Self {
            tally: Tally::default(),
            last_rect: None,
        })
    }

    /// Call once per drawn frame, before the view consumes any input.
    pub(crate) fn observe(&mut self, ctx: &egui::Context) {
        let causes: Vec<String> = ctx.repaint_causes().iter().map(cause_label).collect();
        let (mut inputs, rect) = ctx.input(|input| {
            let inputs: Vec<&'static str> = input.raw.events.iter().map(event_kind).collect();
            (inputs, input.viewport().outer_rect)
        });
        if let (Some(last), Some(rect)) = (self.last_rect, rect) {
            if last.min != rect.min {
                inputs.push("window moved");
            }
            if last.size() != rect.size() {
                inputs.push("window resized");
            }
        }
        self.last_rect = rect;
        if let Some(summary) = self.tally.record(Instant::now(), causes, inputs) {
            tracing::info!(
                frames = summary.frames,
                elapsed_ms = summary.elapsed_ms,
                causes = %summary.causes,
                inputs = %summary.inputs,
                "repaint trace"
            );
        }
    }
}

impl Tally {
    /// Counts a frame; once `SUMMARY_INTERVAL` has passed since the first
    /// frame counted, returns the summary and starts over.
    fn record(
        &mut self,
        now: Instant,
        causes: impl IntoIterator<Item = String>,
        inputs: impl IntoIterator<Item = &'static str>,
    ) -> Option<Summary> {
        let started = *self.started.get_or_insert(now);
        self.frames += 1;
        let mut causes: Vec<String> = causes.into_iter().collect();
        if causes.is_empty() {
            causes.push(NO_CAUSE.to_owned());
        }
        causes.sort_unstable();
        causes.dedup();
        for cause in causes {
            *self.causes.entry(cause).or_default() += 1;
        }
        let mut inputs: Vec<&'static str> = inputs.into_iter().collect();
        if inputs.is_empty() {
            inputs.push(NO_INPUT);
        }
        inputs.sort_unstable();
        inputs.dedup();
        for input in inputs {
            *self.inputs.entry(input).or_default() += 1;
        }

        let elapsed = now.saturating_duration_since(started);
        if elapsed < SUMMARY_INTERVAL {
            return None;
        }
        let tally = std::mem::take(self);
        Some(Summary {
            frames: tally.frames,
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            causes: top(tally.causes),
            inputs: top(tally.inputs),
        })
    }
}

fn top<T: Ord>(counts: HashMap<T, u32>) -> Counts<T> {
    let mut counts: Vec<(T, u32)> = counts.into_iter().collect();
    counts.sort_unstable_by(|(a_name, a), (b_name, b)| b.cmp(a).then_with(|| a_name.cmp(b_name)));
    counts.truncate(TOP);
    Counts(counts)
}

fn cause_label(cause: &egui::RepaintCause) -> String {
    let file = short_source_path(cause.file);
    if cause.reason.is_empty() {
        format!("{file}:{}", cause.line)
    } else {
        format!("{file}:{} ({})", cause.line, cause.reason)
    }
}

/// The path from the crate's folder on: `egui-0.37.0/src/context.rs` rather
/// than the absolute registry path, which holds the user's home folder.
fn short_source_path(file: &str) -> String {
    let parts: Vec<&str> = file
        .split(['/', '\\'])
        .filter(|part| !part.is_empty())
        .collect();
    let start = parts
        .iter()
        .rposition(|part| *part == "src")
        .map_or(parts.len().saturating_sub(1), |src| src.saturating_sub(1));
    parts[start..].join("/")
}

fn event_kind(event: &egui::Event) -> &'static str {
    match event {
        egui::Event::PointerMoved(_) => "pointer moved",
        egui::Event::MouseMoved(_) => "raw mouse motion",
        egui::Event::PointerButton { .. } => "pointer button",
        egui::Event::PointerGone => "pointer gone",
        egui::Event::MouseWheel { .. } => "wheel",
        egui::Event::Key { .. } => "key",
        egui::Event::Text(_) | egui::Event::Ime(_) => "text",
        egui::Event::ModifiersChanged(_) => "modifiers",
        egui::Event::WindowFocused(_) => "focus",
        egui::Event::Zoom(_) | egui::Event::Rotate(_) | egui::Event::Touch { .. } => "touch",
        egui::Event::Copy
        | egui::Event::Cut
        | egui::Event::Paste(_)
        | egui::Event::PasteImage(_)
        | egui::Event::MiddleClickPaste { .. } => "clipboard",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_summary_comes_after_the_interval_with_the_most_frequent_first() {
        let mut tally = Tally::default();
        let start = Instant::now();
        let header = || "rosetun-gui/src/view/header.rs:156".to_owned();
        let input = || "egui-0.37.0/src/context.rs:579".to_owned();

        assert_eq!(
            tally.record(start, [input(), input()], ["raw mouse motion"]),
            None
        );
        assert_eq!(
            tally.record(
                start + Duration::from_millis(100),
                [input(), header()],
                ["raw mouse motion", "window moved"],
            ),
            None
        );
        assert_eq!(
            tally.record(start + Duration::from_millis(200), [], []),
            None
        );

        let summary = tally
            .record(start + Duration::from_millis(250), [header()], ["key"])
            .expect("a summary after 250 ms");
        assert_eq!(summary.frames, 4);
        assert_eq!(summary.elapsed_ms, 250);
        assert_eq!(
            summary.causes.to_string(),
            "egui-0.37.0/src/context.rs:579=2, rosetun-gui/src/view/header.rs:156=2, none=1",
            "a cause counts once per frame"
        );
        assert_eq!(
            summary.inputs.to_string(),
            "raw mouse motion=2, key=1, none=1, window moved=1"
        );

        assert_eq!(
            tally.record(start + Duration::from_millis(300), [], []),
            None,
            "the next summary starts over"
        );
        let next = tally
            .record(start + Duration::from_millis(600), [], [])
            .expect("a second summary");
        assert_eq!(next.frames, 2);
        assert_eq!(next.inputs.to_string(), "none=2");
    }

    #[test]
    fn a_summary_names_only_the_most_frequent_causes() {
        let mut tally = Tally::default();
        let start = Instant::now();
        let causes: Vec<String> = (0..10).map(|line| format!("a.rs:{line}")).collect();
        tally.record(start, causes, []);
        let summary = tally
            .record(start + SUMMARY_INTERVAL, ["a.rs:9".to_owned()], [])
            .expect("a summary");
        assert_eq!(summary.causes.0.len(), TOP);
        assert_eq!(summary.causes.0[0], ("a.rs:9".to_owned(), 2));
    }

    #[test]
    fn source_paths_keep_only_the_crate_folder_and_below() {
        assert_eq!(
            short_source_path(
                r"C:\Users\example\.cargo\registry\src\index.crates.io-0000\egui-0.37.0\src\context.rs"
            ),
            "egui-0.37.0/src/context.rs"
        );
        assert_eq!(
            short_source_path("/home/example/.cargo/registry/src/index/egui-0.37.0/src/ui.rs"),
            "egui-0.37.0/src/ui.rs"
        );
        assert_eq!(
            short_source_path(r"crates\rosetun-gui\src\view\header.rs"),
            "rosetun-gui/src/view/header.rs"
        );
        assert_eq!(short_source_path("src/app.rs"), "src/app.rs");
        assert_eq!(short_source_path("/somewhere/else/lib.rs"), "lib.rs");
        assert_eq!(short_source_path(""), "");
    }

    #[test]
    fn input_is_named_by_its_kind_never_by_its_content() {
        assert_eq!(
            event_kind(&egui::Event::MouseMoved(egui::Vec2::X)),
            "raw mouse motion"
        );
        assert_eq!(
            event_kind(&egui::Event::PointerMoved(egui::pos2(1.0, 2.0))),
            "pointer moved"
        );
        assert_eq!(event_kind(&egui::Event::Text("secret".to_owned())), "text");
        assert_eq!(
            event_kind(&egui::Event::Paste("secret".to_owned())),
            "clipboard"
        );
    }
}
