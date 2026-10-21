// Mirrors assets/icon/rosetun.svg through rose_shape.rs; change both together.
use eframe::egui::Color32;

use crate::{rose_shape::PETALS, theme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoseIcon {
    /// Inside the window, on the app's own background.
    Emblem,
    /// Outside the window (taskbar, Explorer, installer), on a dark plate.
    App,
    /// The tray: a rose with a state-specific corner badge.
    // The tray exists only on Windows.
    #[cfg_attr(not(any(test, windows)), allow(dead_code))]
    Tray(TrayState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
pub(crate) enum TrayState {
    Connected,
    Disconnected,
    Connecting,
    Blocked,
    Failed,
    ServiceUnavailable,
}

type Pt = (f32, f32);

fn segment_distance_squared(point: Pt, a: Pt, b: Pt) -> f32 {
    let dx = b.0 - a.0;
    let dy = b.1 - a.1;
    let length_squared = dx * dx + dy * dy;
    let t = if length_squared > 0.0 {
        ((point.0 - a.0) * dx + (point.1 - a.1) * dy) / length_squared
    } else {
        0.0
    }
    .clamp(0.0, 1.0);
    let x = point.0 - a.0 - t * dx;
    let y = point.1 - a.1 - t * dy;
    x * x + y * y
}

fn badge_color(state: TrayState) -> Option<Color32> {
    match state {
        TrayState::Connected | TrayState::Disconnected => None,
        TrayState::Connecting => Some(theme::ROSE_BRIGHT),
        TrayState::Blocked | TrayState::Failed => Some(theme::ERROR),
        TrayState::ServiceUnavailable => Some(theme::DISABLED),
    }
}

/// The badge's place in a raster of one size, in design units.
#[derive(Debug, Clone, Copy)]
struct BadgeGrid {
    /// How far the badge moves from the 48 px design so that the edge of its
    /// disc lies on a pixel boundary; a disc between pixels blurs on all sides.
    shift: f32,
    /// One pixel.
    pixel: f32,
}

impl BadgeGrid {
    fn new(size: u32) -> Self {
        let pixel = 48.0 / size as f32;
        // The disc (x 23..47) is half the icon wide; keep it inside the icon.
        let left = (23.0 / pixel).round().min(size as f32 / 2.0);
        Self {
            shift: left * pixel - 23.0,
            pixel,
        }
    }
}

fn badge_mark(point: Pt, state: TrayState, pixel: f32) -> bool {
    let (x, y) = point;
    // Below about a pixel a stroke turns into a grey smear on the disc.
    let half = |width: f32| width.max(pixel);
    match state {
        TrayState::Connecting => {
            let dx = x - 35.0;
            let dy = y - 35.0;
            let angle =
                (dy.atan2(dx) + std::f32::consts::FRAC_PI_2).rem_euclid(std::f32::consts::TAU);
            ((dx * dx + dy * dy).sqrt() - 7.5).abs() <= half(1.7)
                && angle <= 3.0 * std::f32::consts::FRAC_PI_2
        }
        TrayState::Blocked => {
            (29.5..=40.5).contains(&x) && (34.0..=42.5).contains(&y)
                || segment_distance_squared(point, (31.8, 34.0), (31.8, 31.6)) <= half(1.3).powi(2)
                || segment_distance_squared(point, (38.2, 31.6), (38.2, 34.0)) <= half(1.3).powi(2)
                || (y <= 31.6 && ((x - 35.0).hypot(y - 31.6) - 3.2).abs() <= half(1.3))
        }
        TrayState::Failed => {
            let dot = 2.1_f32.max(pixel);
            // Thicker strokes would close the gap between the bar and the dot.
            let bottom = (41.0 - dot - pixel - half(1.9)).min(36.2);
            segment_distance_squared(point, (35.0, 28.5), (35.0, bottom)) <= half(1.9).powi(2)
                || (x - 35.0).hypot(y - 41.0) <= dot
        }
        TrayState::ServiceUnavailable => {
            segment_distance_squared(point, (30.8, 30.8), (39.2, 39.2)) <= half(1.8).powi(2)
                || segment_distance_squared(point, (39.2, 30.8), (30.8, 39.2)) <= half(1.8).powi(2)
        }
        TrayState::Connected | TrayState::Disconnected => false,
    }
}

fn sample_badge(point: Pt, state: TrayState, grid: BadgeGrid) -> Option<Option<Color32>> {
    let color = badge_color(state)?;
    let point = (point.0 - grid.shift, point.1 - grid.shift);
    let distance = (point.0 - 35.0).hypot(point.1 - 35.0);
    // The cutout must stay at least a pixel wide, or the badge merges with the petals.
    if distance > 12.0 + grid.pixel.max(2.5) {
        return None;
    }
    if distance > 12.0 {
        return Some(None);
    }
    Some(Some(if badge_mark(point, state, grid.pixel) {
        Color32::WHITE
    } else {
        color
    }))
}

fn sample(point: Pt, icon: RoseIcon, inside: bool, grid: BadgeGrid) -> Option<(Color32, u8)> {
    if let RoseIcon::Tray(state) = icon
        && let Some(badge) = sample_badge(point, state, grid)
    {
        return badge.map(|color| (color, 255));
    }
    let color = match icon {
        RoseIcon::Emblem | RoseIcon::App | RoseIcon::Tray(TrayState::Connected) => theme::ROSE,
        RoseIcon::Tray(_) => theme::DISCONNECTED,
    };
    let opacity = if matches!(icon, RoseIcon::Tray(TrayState::ServiceUnavailable)) {
        140
    } else {
        255
    };
    inside.then_some((color, opacity))
}

fn scanline(y: f32, intersections: &mut Vec<f32>) {
    intersections.clear();
    for vertices in PETALS {
        for index in 0..vertices.len() {
            let a = vertices[index];
            let b = vertices[(index + 1) % vertices.len()];
            // A half-open edge counts shared vertices once and skips horizontal edges.
            if (a.1 > y) != (b.1 > y) {
                intersections.push(a.0 + (y - a.1) * (b.0 - a.0) / (b.1 - a.1));
            }
        }
    }
    intersections.sort_unstable_by(f32::total_cmp);
}

/// Straight-alpha RGBA of the icon, `size`×`size`.
pub(crate) fn rose_icon_rgba(size: u32, icon: RoseIcon) -> Vec<u8> {
    let mut rgba = rasterize(size, icon);
    if icon != RoseIcon::Emblem {
        back(&mut rgba, size as usize);
    }
    rgba
}

const BACKING_ALPHA: u32 = 160;

/// Square dilation by `reach` cells, done as a row pass and a column pass.
fn dilate(set: &[bool], side: usize, reach: usize) -> Vec<bool> {
    let pass = |set: &[bool], at: &dyn Fn(usize, usize) -> usize| {
        let mut out = vec![false; set.len()];
        for line in 0..side {
            let mut count = 0;
            for i in 0..side + reach {
                if i < side && set[at(line, i)] {
                    count += 1;
                }
                if i > 2 * reach && set[at(line, i - 2 * reach - 1)] {
                    count -= 1;
                }
                if i >= reach {
                    out[at(line, i - reach)] = count > 0;
                }
            }
        }
        out
    };
    let rows = pass(set, &|line, i| line * side + i);
    pass(&rows, &|line, i| i * side + line)
}

/// Rose petals vanish on a background of a similar colour (a red Windows
/// accent on the taskbar), so every icon shown outside the window sits on a
/// dark plate: the silhouette with the gaps between petals filled, plus a rim.
/// The gaps are channels open to the outside; a closing (dilate, flood the
/// outside, dilate it back) tells them from the outside itself.
fn back(rgba: &mut [u8], size: usize) {
    let radius = (size / 16).max(1);
    let rim = (size / 32).max(1);
    // A margin beyond the edges, so the outside also reaches petals that touch them.
    let pad = radius + rim + 1;
    let side = size + 2 * pad;
    let solid: Vec<bool> = (0..side * side)
        .map(|i| {
            let (x, y) = ((i % side).wrapping_sub(pad), (i / side).wrapping_sub(pad));
            x < size && y < size && rgba[(y * size + x) * 4 + 3] >= 128
        })
        .collect();
    let grown = dilate(&solid, side, radius);
    let mut outside = vec![false; side * side];
    let mut queue = vec![0];
    while let Some(i) = queue.pop() {
        if grown[i] || outside[i] {
            continue;
        }
        outside[i] = true;
        let (x, y) = (i % side, i / side);
        if x > 0 {
            queue.push(i - 1);
        }
        if x + 1 < side {
            queue.push(i + 1);
        }
        if y > 0 {
            queue.push(i - side);
        }
        if y + 1 < side {
            queue.push(i + side);
        }
    }
    let silhouette: Vec<bool> = dilate(&outside, side, radius)
        .into_iter()
        .map(|outside| !outside)
        .collect();
    let plate = dilate(&silhouette, side, rim);
    for (i, pixel) in rgba.chunks_exact_mut(4).enumerate() {
        if !plate[(i / size + pad) * side + i % size + pad] {
            continue;
        }
        // The icon's own pixel is drawn over the plate.
        let alpha = u32::from(pixel[3]);
        let under = BACKING_ALPHA * (255 - alpha) / 255;
        let total = alpha + under;
        for channel in &mut pixel[..3] {
            *channel = (u32::from(*channel) * alpha / total) as u8;
        }
        pixel[3] = total as u8;
    }
}

fn rasterize(size: u32, icon: RoseIcon) -> Vec<u8> {
    let scale = 48.0 / size as f32;
    let grid = BadgeGrid::new(size);
    let mut rgba = Vec::with_capacity(size as usize * size as usize * 4);
    let mut row = vec![[0_u32; 4]; size as usize];
    let mut intersections = Vec::new();
    for y in 0..size {
        row.fill([0; 4]);
        for j in 0..4 {
            let sample_y = (y as f32 + (j as f32 + 0.5) / 4.0) * scale;
            scanline(sample_y, &mut intersections);
            let mut crossing = 0;
            for (x, pixel) in row.iter_mut().enumerate() {
                for i in 0..4 {
                    let sample_x = (x as f32 + (i as f32 + 0.5) / 4.0) * scale;
                    while crossing < intersections.len() && intersections[crossing] <= sample_x {
                        crossing += 1;
                    }
                    if let Some((color, opacity)) =
                        sample((sample_x, sample_y), icon, crossing % 2 == 1, grid)
                    {
                        let opacity = u32::from(opacity);
                        pixel[0] += u32::from(color.r()) * opacity;
                        pixel[1] += u32::from(color.g()) * opacity;
                        pixel[2] += u32::from(color.b()) * opacity;
                        pixel[3] += opacity;
                    }
                }
            }
        }
        for &[red, green, blue, alpha] in &row {
            let divisor = alpha.max(1);
            rgba.extend_from_slice(&[
                (red / divisor) as u8,
                (green / divisor) as u8,
                (blue / divisor) as u8,
                (alpha / 16) as u8,
            ]);
        }
    }
    rgba
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRAY_STATES: [TrayState; 6] = [
        TrayState::Connected,
        TrayState::Disconnected,
        TrayState::Connecting,
        TrayState::Blocked,
        TrayState::Failed,
        TrayState::ServiceUnavailable,
    ];

    fn pixel(rgba: &[u8], size: usize, x: usize, y: usize) -> [u8; 4] {
        rgba[(y * size + x) * 4..(y * size + x + 1) * 4]
            .try_into()
            .unwrap()
    }

    #[test]
    fn emblem_has_solid_petals_and_transparent_gaps() {
        let rgba = rose_icon_rgba(48, RoseIcon::Emblem);
        // At y = 12.5, PETALS span x = 13.114..22.407, then 28.764..30.592.
        assert_eq!(pixel(&rgba, 48, 18, 12), theme::ROSE.to_array());
        for (x, y) in [(25, 12), (0, 0), (47, 47)] {
            assert_eq!(pixel(&rgba, 48, x, y), [0; 4], "({x}, {y})");
        }
        let filled = rgba.chunks_exact(4).filter(|pixel| pixel[3] != 0).count();
        let coverage = filled as f32 / (48 * 48) as f32;
        assert!((0.45..=0.75).contains(&coverage), "{coverage}");
        assert_eq!(rgba, rasterize(48, RoseIcon::Emblem), "no plate");
    }

    #[test]
    fn app_256_rasterizes_within_two_seconds() {
        let start = std::time::Instant::now();
        let rgba = rose_icon_rgba(256, RoseIcon::App);
        let elapsed = start.elapsed();
        assert_eq!(rgba.len(), 256 * 256 * 4);
        eprintln!("256 px rose rasterization: {elapsed:?}");
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn outside_icons_sit_on_a_plate_that_fills_the_gaps() {
        let icons = TRAY_STATES.map(RoseIcon::Tray);
        for icon in icons.into_iter().chain([RoseIcon::App]) {
            for size in [16, 24, 32, 48, 256] {
                let plain = rasterize(size, icon);
                let backed = rose_icon_rgba(size, icon);
                for (before, after) in plain.chunks_exact(4).zip(backed.chunks_exact(4)) {
                    assert!(after[3] >= before[3], "{icon:?} {size} px");
                    if before[3] == 255 {
                        assert_eq!(before, after, "{icon:?} {size} px: plate over the rose");
                    } else if before != after {
                        assert!(after[3] >= BACKING_ALPHA as u8, "{icon:?} {size} px");
                    }
                }
                let size = size as usize;
                assert_eq!(
                    pixel(&backed, size, 0, 0),
                    [0; 4],
                    "{icon:?} {size} px corner"
                );
            }
            let rgba = rose_icon_rgba(32, icon);
            assert_eq!(pixel(&rgba, 32, 3, 4), [0, 0, 0, 160], "{icon:?} rim");
            // A one-pixel channel between two petals, open to the outside.
            assert_eq!(pixel(&rgba, 32, 14, 4), [0, 0, 0, 160], "{icon:?} gap");
        }
    }

    #[test]
    fn tray_states_have_distinct_shapes_and_expected_petal_colors() {
        let states = TRAY_STATES;
        for size in [16, 32, 48] {
            let images = states.map(|state| rose_icon_rgba(size, RoseIcon::Tray(state)));
            assert_eq!(
                images
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                6,
                "{size} px"
            );
        }
        let images = states.map(|state| rose_icon_rgba(48, RoseIcon::Tray(state)));
        for (state, rgba) in states.into_iter().zip(&images) {
            let petal = pixel(rgba, 48, 18, 12);
            assert_eq!(
                petal,
                match state {
                    TrayState::Connected => theme::ROSE.to_array(),
                    // A dimmed rose (alpha 140) over the plate.
                    TrayState::ServiceUnavailable => [
                        (u32::from(theme::DISCONNECTED.r()) * 140 / 212) as u8,
                        (u32::from(theme::DISCONNECTED.g()) * 140 / 212) as u8,
                        (u32::from(theme::DISCONNECTED.b()) * 140 / 212) as u8,
                        212,
                    ],
                    _ => theme::DISCONNECTED.to_array(),
                },
                "{state:?} petal"
            );
            if state != TrayState::Connected {
                assert!(
                    !rgba
                        .chunks_exact(4)
                        .any(|pixel| pixel == theme::ROSE.to_array())
                );
                assert!(
                    !rgba
                        .chunks_exact(4)
                        .any(|pixel| pixel == theme::ROSE_DARK.to_array())
                );
            }
        }
    }

    #[test]
    fn tray_badges_have_coloured_discs_white_marks_and_transparent_cutouts() {
        for (state, color, mark) in [
            (TrayState::Connecting, theme::ROSE_BRIGHT, (35, 27)),
            (TrayState::Blocked, theme::ERROR, (35, 38)),
            (TrayState::Failed, theme::ERROR, (35, 32)),
            (TrayState::ServiceUnavailable, theme::DISABLED, (35, 35)),
        ] {
            let rgba = rose_icon_rgba(48, RoseIcon::Tray(state));
            assert_eq!(pixel(&rgba, 48, 35, 45), color.to_array(), "{state:?} disc");
            assert_eq!(
                pixel(&rgba, 48, mark.0, mark.1),
                Color32::WHITE.to_array(),
                "{state:?} mark"
            );
            assert_eq!(pixel(&rgba, 48, 34, 21), [0, 0, 0, 160], "{state:?} cutout");
        }
    }

    #[test]
    fn tray_icons_at_taskbar_sizes_keep_the_badge_mark_and_the_outline() {
        for size in [16, 20, 24] {
            for state in TRAY_STATES {
                let rgba = rose_icon_rgba(size, RoseIcon::Tray(state));
                assert_eq!(
                    rgba.len(),
                    (size * size * 4) as usize,
                    "{state:?} {size} px"
                );
                let count = |wanted: &dyn Fn(&[u8]) -> bool| {
                    rgba.chunks_exact(4).filter(|pixel| wanted(pixel)).count()
                };
                assert!(
                    count(&|pixel| pixel == [0, 0, 0, 160]) >= 4,
                    "{state:?} {size} px outline"
                );
                let Some(color) = badge_color(state) else {
                    continue;
                };
                assert!(
                    count(&|pixel| pixel == color.to_array()) >= 8,
                    "{state:?} {size} px disc"
                );
                assert!(
                    count(&|pixel| pixel[3] == 255 && pixel[..3].iter().all(|&c| c >= 230)) >= 3,
                    "{state:?} {size} px mark"
                );
            }
        }
    }

    #[test]
    fn badge_disc_edge_lies_on_the_pixel_grid() {
        for size in 16..=64 {
            let grid = BadgeGrid::new(size);
            let left = (23.0 + grid.shift) / grid.pixel;
            assert!((left - left.round()).abs() < 1e-3, "{size} px: {left}");
            assert!(left + size as f32 / 2.0 <= size as f32 + 1e-3, "{size} px");
        }
        assert_eq!(BadgeGrid::new(48).shift, 0.0);
        // At 20 px the disc covers columns 10..20: column 9 has no disc colour.
        let rgba = rose_icon_rgba(20, RoseIcon::Tray(TrayState::Failed));
        assert_eq!(pixel(&rgba, 20, 15, 10)[..3], theme::ERROR.to_array()[..3]);
        assert_ne!(pixel(&rgba, 20, 9, 15), theme::ERROR.to_array());
        assert_eq!(pixel(&rgba, 20, 10, 15), theme::ERROR.to_array());
    }

    #[test]
    fn rgba_has_the_requested_size() {
        assert_eq!(rose_icon_rgba(32, RoseIcon::Emblem).len(), 32 * 32 * 4);
    }
}
