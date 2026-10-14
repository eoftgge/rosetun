// Mirrors assets/icon/*.svg; change both together.
use eframe::egui::Color32;

use crate::theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoseIcon {
    /// 40 px and above: folds, centre disc and the full spiral.
    Large,
    /// 32 px and below: the same petals with a bolder, shorter spiral.
    // Only the test-only `.ico` generator draws it.
    #[cfg_attr(not(test), allow(dead_code))]
    Small,
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

#[derive(Debug, Clone, Copy)]
struct Bounds {
    min: Pt,
    max: Pt,
}

impl Bounds {
    /// The box around `vertices`, grown by `margin` on every side so that the
    /// stroke around the outline stays inside it.
    fn around(vertices: &[Pt], margin: f32) -> Self {
        let mut min = (f32::INFINITY, f32::INFINITY);
        let mut max = (f32::NEG_INFINITY, f32::NEG_INFINITY);
        for &(x, y) in vertices {
            min.0 = min.0.min(x);
            min.1 = min.1.min(y);
            max.0 = max.0.max(x);
            max.1 = max.1.max(y);
        }
        Self {
            min: (min.0 - margin, min.1 - margin),
            max: (max.0 + margin, max.1 + margin),
        }
    }

    fn contains(&self, point: Pt) -> bool {
        point.0 >= self.min.0
            && point.0 <= self.max.0
            && point.1 >= self.min.1
            && point.1 <= self.max.1
    }
}

/// `M inner L side Q control tip L far Z`; the fold is the triangle inner, tip, far.
struct Petal {
    inner: Pt,
    side: Pt,
    control: Pt,
    tip: Pt,
    far: Pt,
}

const PETALS: [Petal; 5] = [
    Petal {
        inner: (21.75, 21.32),
        side: (16.73, 13.22),
        control: (17.82, 4.98),
        tip: (27.91, 1.84),
        far: (31.08, 14.94),
    },
    Petal {
        inner: (25.85, 21.03),
        side: (32.00, 13.76),
        control: (40.18, 12.24),
        tip: (46.28, 20.87),
        far: (34.81, 27.93),
    },
    Petal {
        inner: (27.40, 24.85),
        side: (36.22, 28.45),
        control: (40.18, 35.76),
        tip: (33.86, 44.22),
        far: (23.60, 35.49),
    },
    Petal {
        inner: (24.24, 27.49),
        side: (23.55, 36.99),
        control: (17.82, 43.02),
        tip: (7.81, 39.63),
        far: (12.95, 27.17),
    },
    Petal {
        inner: (20.75, 25.31),
        side: (11.50, 27.58),
        control: (4.00, 24.00),
        tip: (4.13, 13.44),
        far: (17.57, 14.47),
    },
];

const LARGE_SPIRAL: [Pt; 9] = [
    (24.0, 31.0),
    (18.0, 27.0),
    (18.0, 21.0),
    (24.0, 17.0),
    (30.0, 21.0),
    (30.0, 25.0),
    (26.0, 28.0),
    (22.0, 25.0),
    (23.0, 22.0),
];
const SMALL_SPIRAL: [Pt; 7] = [
    (24.0, 30.0),
    (18.5, 26.5),
    (18.5, 21.0),
    (24.0, 17.5),
    (29.5, 21.0),
    (29.5, 25.0),
    (25.0, 27.5),
];

fn face_points(petal: &Petal) -> [Pt; 19] {
    let mut points = [(0.0, 0.0); 19];
    points[0] = petal.inner;
    points[1] = petal.side;
    for step in 1..=16 {
        let t = step as f32 / 16.0;
        let u = 1.0 - t;
        points[step + 1] = (
            u * u * petal.side.0 + 2.0 * u * t * petal.control.0 + t * t * petal.tip.0,
            u * u * petal.side.1 + 2.0 * u * t * petal.control.1 + t * t * petal.tip.1,
        );
    }
    points[18] = petal.far;
    points
}

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

fn in_polygon(point: Pt, vertices: &[Pt]) -> bool {
    let mut inside = false;
    for index in 0..vertices.len() {
        let a = vertices[index];
        let b = vertices[(index + 1) % vertices.len()];
        if (a.1 > point.1) != (b.1 > point.1)
            && point.0 < a.0 + (point.1 - a.1) * (b.0 - a.0) / (b.1 - a.1)
        {
            inside = !inside;
        }
    }
    inside
}

fn in_path(point: Pt, vertices: &[Pt], half_stroke: f32) -> bool {
    in_polygon(point, vertices)
        || (0..vertices.len()).any(|index| {
            segment_distance_squared(
                point,
                vertices[index],
                vertices[(index + 1) % vertices.len()],
            ) <= half_stroke * half_stroke
        })
}

fn on_spiral(point: Pt, spiral: &[Pt], half_stroke: f32) -> bool {
    spiral.windows(2).any(|segment| {
        segment_distance_squared(point, segment[0], segment[1]) <= half_stroke * half_stroke
    })
}

fn sample_rose(
    point: Pt,
    icon: RoseIcon,
    faces: &[[Pt; 19]; 5],
    face_bounds: &[Bounds; 5],
    fold_bounds: &[Bounds; 5],
) -> Option<Color32> {
    let (spiral, half_stroke, spiral_color): (&[Pt], _, _) = match icon {
        RoseIcon::Large => (&LARGE_SPIRAL, 0.9, theme::ROSE_LIGHT),
        RoseIcon::Small => (&SMALL_SPIRAL, 1.2, theme::ROSE_LIGHT),
        RoseIcon::Tray(_) => (&SMALL_SPIRAL, 1.3, theme::TEXT),
    };
    if on_spiral(point, spiral, half_stroke) {
        return Some(spiral_color);
    }
    let (petal_color, folds, radius) = match icon {
        RoseIcon::Large => (theme::ROSE, true, 8.4),
        RoseIcon::Small => (theme::ROSE, true, 8.0),
        RoseIcon::Tray(TrayState::Connected) => (theme::ROSE, true, 9.0),
        RoseIcon::Tray(_) => (theme::DISCONNECTED, false, 9.0),
    };
    let dx = point.0 - 24.0;
    let dy = point.1 - 24.0;
    if dx * dx + dy * dy <= radius * radius {
        return Some(petal_color);
    }
    for index in (0..PETALS.len()).rev() {
        let petal = &PETALS[index];
        if folds
            && fold_bounds[index].contains(point)
            && in_path(point, &[petal.inner, petal.tip, petal.far], 0.3)
        {
            return Some(theme::ROSE_DARK);
        }
        if face_bounds[index].contains(point) && in_path(point, &faces[index], 0.6) {
            return Some(petal_color);
        }
    }
    None
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
            let angle = (dy.atan2(dx) + std::f32::consts::FRAC_PI_2)
                .rem_euclid(std::f32::consts::TAU);
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

fn sample(
    point: Pt,
    icon: RoseIcon,
    faces: &[[Pt; 19]; 5],
    face_bounds: &[Bounds; 5],
    fold_bounds: &[Bounds; 5],
) -> Option<(Color32, u8)> {
    if let RoseIcon::Tray(state) = icon {
        if let Some(badge) = sample_badge(point, state) {
            return badge.map(|color| (color, 255));
        }
    }
    let opacity = if matches!(icon, RoseIcon::Tray(TrayState::ServiceUnavailable)) {
        140
    } else {
        255
    };
    sample_rose(point, icon, faces, face_bounds, fold_bounds).map(|color| (color, opacity))
}

/// Straight-alpha RGBA of the icon, `size`×`size`.
pub(crate) fn rose_icon_rgba(size: u32, icon: RoseIcon) -> Vec<u8> {
    let faces = PETALS.each_ref().map(face_points);
    let face_bounds = faces.each_ref().map(|face| Bounds::around(face, 0.6));
    let fold_bounds = PETALS
        .each_ref()
        .map(|petal| Bounds::around(&[petal.inner, petal.tip, petal.far], 0.3));
    let scale = 48.0 / size as f32;
    let mut rgba = Vec::with_capacity(size as usize * size as usize * 4);
    for y in 0..size {
        for x in 0..size {
            let mut alpha = 0_u32;
            let (mut red, mut green, mut blue) = (0_u32, 0_u32, 0_u32);
            for j in 0..4 {
                for i in 0..4 {
                    let point = (
                        (x as f32 + (i as f32 + 0.5) / 4.0) * scale,
                        (y as f32 + (j as f32 + 0.5) / 4.0) * scale,
                    );
                    if let Some((color, opacity)) =
                        sample(point, icon, &faces, &face_bounds, &fold_bounds)
                    {
                        let opacity = u32::from(opacity);
                        alpha += opacity;
                        red += u32::from(color.r()) * opacity;
                        green += u32::from(color.g()) * opacity;
                        blue += u32::from(color.b()) * opacity;
                    }
                }
            }
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

    fn pixel(rgba: &[u8], size: usize, x: usize, y: usize) -> [u8; 4] {
        rgba[(y * size + x) * 4..(y * size + x + 1) * 4]
            .try_into()
            .unwrap()
    }

    #[test]
    fn bounds_hold_every_shape() {
        for petal in &PETALS {
            let face = face_points(petal);
            let fold = [petal.inner, petal.tip, petal.far];
            let face_bounds = Bounds::around(&face, 0.6);
            let fold_bounds = Bounds::around(&fold, 0.3);
            for y in 0..=192 {
                for x in 0..=192 {
                    let point = (x as f32 / 4.0, y as f32 / 4.0);
                    if in_path(point, &face, 0.6) {
                        assert!(face_bounds.contains(point), "face at {point:?}");
                    }
                    if in_path(point, &fold, 0.3) {
                        assert!(fold_bounds.contains(point), "fold at {point:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn large_has_petals_folds_disc_and_spiral() {
        let rgba = rose_icon_rgba(48, RoseIcon::Large);
        for (x, y) in [(0, 0), (47, 47)] {
            assert_eq!(pixel(&rgba, 48, x, y), [0; 4]);
        }
        for (x, y) in [(20, 12), (10, 20), (24, 24)] {
            assert_eq!(pixel(&rgba, 48, x, y), theme::ROSE.to_array(), "({x}, {y})");
        }
        for (x, y) in [(26, 12), (40, 22)] {
            assert_eq!(
                pixel(&rgba, 48, x, y),
                theme::ROSE_DARK.to_array(),
                "({x}, {y})"
            );
        }
    }

    #[test]
    fn small_has_bold_short_spiral() {
        let rgba = rose_icon_rgba(48, RoseIcon::Small);
        for (x, y) in [(18, 24), (24, 27)] {
            assert_eq!(
                pixel(&rgba, 48, x, y),
                theme::ROSE_LIGHT.to_array(),
                "({x}, {y})"
            );
        }
        assert_eq!(pixel(&rgba, 48, 23, 23), theme::ROSE.to_array());
        assert_eq!(pixel(&rgba, 48, 26, 12), theme::ROSE_DARK.to_array());
    }

    #[test]
    fn tray_states_have_distinct_shapes_and_filled_centres() {
        let states = [
            TrayState::Connected,
            TrayState::Disconnected,
            TrayState::Connecting,
            TrayState::Blocked,
            TrayState::Failed,
            TrayState::ServiceUnavailable,
        ];
        for size in [16, 32, 48] {
            let images = states.map(|state| rose_icon_rgba(size, RoseIcon::Tray(state)));
            assert_eq!(
                images.iter().collect::<std::collections::HashSet<_>>().len(),
                6,
                "{size} px"
            );
        }
        let images = states.map(|state| rose_icon_rgba(48, RoseIcon::Tray(state)));
        for (state, rgba) in states.into_iter().zip(&images) {
            let centre = pixel(rgba, 48, 22, 24);
            assert_eq!(
                centre,
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
                "{state:?} centre"
            );
            let mut spiral = theme::TEXT.to_array();
            if state == TrayState::ServiceUnavailable {
                spiral[3] = 140;
            }
            assert_eq!(pixel(rgba, 48, 18, 24), spiral, "{state:?} spiral");
            if state == TrayState::Connected {
                assert_eq!(pixel(rgba, 48, 26, 12), theme::ROSE_DARK.to_array());
            } else {
                assert!(!rgba.chunks_exact(4).any(|pixel| pixel == theme::ROSE.to_array()));
                assert!(!rgba.chunks_exact(4).any(|pixel| pixel == theme::ROSE_DARK.to_array()));
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
            assert_eq!(pixel(&rgba, 48, mark.0, mark.1), Color32::WHITE.to_array(), "{state:?} mark");
            assert_eq!(pixel(&rgba, 48, 34, 21), [0; 4], "{state:?} cutout");
        }
    }

    #[test]
    fn rgba_has_the_requested_size() {
        assert_eq!(rose_icon_rgba(32, RoseIcon::Small).len(), 32 * 32 * 4);
    }
}
