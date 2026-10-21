// Mirrors assets/icon/rosetun.svg through rose_shape.rs; change both together.
use eframe::egui::Color32;

use crate::{rose_shape::PETALS, theme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoseIcon {
    Large,
    /// The tray: a rose with a state-specific corner badge.
    // The tray exists only on Windows.
    #[cfg_attr(not(any(test, windows)), allow(dead_code))]
    Tray(TrayState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

fn badge_mark(point: Pt, state: TrayState) -> bool {
    let (x, y) = point;
    match state {
        TrayState::Connecting => {
            let dx = x - 35.0;
            let dy = y - 35.0;
            let angle =
                (dy.atan2(dx) + std::f32::consts::FRAC_PI_2).rem_euclid(std::f32::consts::TAU);
            ((dx * dx + dy * dy).sqrt() - 7.5).abs() <= 1.7
                && angle <= 3.0 * std::f32::consts::FRAC_PI_2
        }
        TrayState::Blocked => {
            (29.5..=40.5).contains(&x) && (34.0..=42.5).contains(&y)
                || segment_distance_squared(point, (31.8, 34.0), (31.8, 31.6)) <= 1.3 * 1.3
                || segment_distance_squared(point, (38.2, 31.6), (38.2, 34.0)) <= 1.3 * 1.3
                || (y <= 31.6 && ((x - 35.0).hypot(y - 31.6) - 3.2).abs() <= 1.3)
        }
        TrayState::Failed => {
            segment_distance_squared(point, (35.0, 28.5), (35.0, 36.2)) <= 1.9 * 1.9
                || (x - 35.0).hypot(y - 41.0) <= 2.1
        }
        TrayState::ServiceUnavailable => {
            segment_distance_squared(point, (30.8, 30.8), (39.2, 39.2)) <= 1.8 * 1.8
                || segment_distance_squared(point, (39.2, 30.8), (30.8, 39.2)) <= 1.8 * 1.8
        }
        TrayState::Connected | TrayState::Disconnected => false,
    }
}

fn sample_badge(point: Pt, state: TrayState) -> Option<Option<Color32>> {
    let color = badge_color(state)?;
    let distance = (point.0 - 35.0).hypot(point.1 - 35.0);
    if distance > 14.5 {
        return None;
    }
    if distance > 12.0 {
        return Some(None);
    }
    Some(Some(if badge_mark(point, state) {
        Color32::WHITE
    } else {
        color
    }))
}

fn sample(point: Pt, icon: RoseIcon, inside: bool) -> Option<(Color32, u8)> {
    if let RoseIcon::Tray(state) = icon
        && let Some(badge) = sample_badge(point, state)
    {
        return badge.map(|color| (color, 255));
    }
    let color = match icon {
        RoseIcon::Large | RoseIcon::Tray(TrayState::Connected) => theme::ROSE,
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
    if matches!(icon, RoseIcon::Tray(_)) {
        outline(&mut rgba, size as usize);
    }
    rgba
}

const OUTLINE_ALPHA: u32 = 160;

/// Rose petals vanish on a taskbar of a similar colour (a red Windows accent),
/// so the tray icon gets a dark rim. The gaps between petals are channels that
/// open to the outside; a closing (dilate, flood the outside, dilate back) keeps
/// the rim on the silhouette's outer edge instead of filling those channels.
fn outline(rgba: &mut [u8], size: usize) {
    let radius = (size / 16).max(1) as isize;
    // A margin beyond the edges, so the outside also reaches petals that touch them.
    let pad = radius + 1;
    let side = size as isize + 2 * pad;
    let cell = |x: isize, y: isize| (y * side + x) as usize;
    let near = |set: &[bool], x: isize, y: isize, reach: isize| {
        (-reach..=reach).any(|dy| {
            (-reach..=reach).any(|dx| {
                let (nx, ny) = (x + dx, y + dy);
                (0..side).contains(&nx) && (0..side).contains(&ny) && set[cell(nx, ny)]
            })
        })
    };
    let cells = (0..side).flat_map(|y| (0..side).map(move |x| (x, y)));
    let solid: Vec<bool> = cells
        .clone()
        .map(|(x, y)| {
            let (px, py) = (x - pad, y - pad);
            (0..size as isize).contains(&px)
                && (0..size as isize).contains(&py)
                && rgba[(py as usize * size + px as usize) * 4 + 3] >= 128
        })
        .collect();
    let grown: Vec<bool> = cells.clone().map(|(x, y)| near(&solid, x, y, radius)).collect();
    let mut outside = vec![false; grown.len()];
    let mut queue = vec![(0, 0)];
    while let Some((x, y)) = queue.pop() {
        if !(0..side).contains(&x) || !(0..side).contains(&y) {
            continue;
        }
        let i = cell(x, y);
        if grown[i] || outside[i] {
            continue;
        }
        outside[i] = true;
        queue.extend([(x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)]);
    }
    let outside: Vec<bool> = cells.map(|(x, y)| near(&outside, x, y, radius)).collect();
    let silhouette: Vec<bool> = outside.iter().map(|outside| !outside).collect();
    for (i, pixel) in rgba.chunks_exact_mut(4).enumerate() {
        let (x, y) = ((i % size) as isize + pad, (i / size) as isize + pad);
        if solid[cell(x, y)] || !outside[cell(x, y)] || !near(&silhouette, x, y, 1) {
            continue;
        }
        // The icon's own pixel is drawn over the black rim.
        let alpha = u32::from(pixel[3]);
        let under = OUTLINE_ALPHA * (255 - alpha) / 255;
        let total = alpha + under;
        for channel in &mut pixel[..3] {
            *channel = (u32::from(*channel) * alpha / total) as u8;
        }
        pixel[3] = total as u8;
    }
}

fn rasterize(size: u32, icon: RoseIcon) -> Vec<u8> {
    let scale = 48.0 / size as f32;
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
                        sample((sample_x, sample_y), icon, crossing % 2 == 1)
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
    fn large_has_solid_petals_and_transparent_gaps() {
        let rgba = rose_icon_rgba(48, RoseIcon::Large);
        // At y = 12.5, PETALS span x = 13.114..22.407, then 28.764..30.592.
        assert_eq!(pixel(&rgba, 48, 18, 12), theme::ROSE.to_array());
        for (x, y) in [(25, 12), (0, 0), (47, 47)] {
            assert_eq!(pixel(&rgba, 48, x, y), [0; 4], "({x}, {y})");
        }
        let filled = rgba.chunks_exact(4).filter(|pixel| pixel[3] != 0).count();
        let coverage = filled as f32 / (48 * 48) as f32;
        assert!((0.45..=0.75).contains(&coverage), "{coverage}");
    }

    #[test]
    fn large_256_rasterizes_within_two_seconds() {
        let start = std::time::Instant::now();
        let rgba = rose_icon_rgba(256, RoseIcon::Large);
        let elapsed = start.elapsed();
        assert_eq!(rgba.len(), 256 * 256 * 4);
        eprintln!("256 px rose rasterization: {elapsed:?}");
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
        assert_eq!(rgba, rasterize(256, RoseIcon::Large), "no outline");
    }

    #[test]
    fn tray_outline_rims_the_silhouette_but_not_the_gaps() {
        let start = std::time::Instant::now();
        for state in TRAY_STATES {
            for size in [16, 24, 32] {
                let icon = RoseIcon::Tray(state);
                let plain = rasterize(size, icon);
                let outlined = rose_icon_rgba(size, icon);
                let mut rim = 0;
                for (before, after) in plain.chunks_exact(4).zip(outlined.chunks_exact(4)) {
                    if before != after {
                        rim += 1;
                        assert!(before[3] < 128, "{state:?} {size} px: rim over the rose");
                        assert!(after[3] >= OUTLINE_ALPHA as u8, "{state:?} {size} px");
                    }
                }
                assert!(rim >= size * 2, "{state:?} {size} px: {rim} rim pixels");
            }
            let rgba = rose_icon_rgba(32, RoseIcon::Tray(state));
            assert_eq!(pixel(&rgba, 32, 3, 4), [0, 0, 0, 160], "{state:?} rim");
            // A one-pixel channel between two petals, open to the outside.
            assert_eq!(pixel(&rgba, 32, 14, 4), [0; 4], "{state:?} gap");
        }
        let elapsed = start.elapsed();
        assert!(elapsed < std::time::Duration::from_secs(1), "{elapsed:?}");
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
                    TrayState::ServiceUnavailable => [
                        theme::DISCONNECTED.r(),
                        theme::DISCONNECTED.g(),
                        theme::DISCONNECTED.b(),
                        140,
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
            assert_eq!(pixel(&rgba, 48, 34, 21), [0; 4], "{state:?} cutout");
        }
    }

    #[test]
    fn rgba_has_the_requested_size() {
        assert_eq!(rose_icon_rgba(32, RoseIcon::Large).len(), 32 * 32 * 4);
    }
}
