use crate::{brand, theme};

/// Sizes Explorer, the Start menu and the taskbar ask for at 100–200 % scaling.
const SIZES: [u32; 8] = [16, 20, 24, 32, 40, 48, 64, 256];
/// Below this the spiral blurs into the petals, as in the tray icon.
const SPIRAL_FROM: u32 = 32;

/// The `.ico` embedded in the executable: the window icon's emblem at every size.
fn app_icon() -> Vec<u8> {
    let mut ico = Vec::new();
    ico.extend_from_slice(&0_u16.to_le_bytes());
    ico.extend_from_slice(&1_u16.to_le_bytes());
    ico.extend_from_slice(&(SIZES.len() as u16).to_le_bytes());

    let mut images = Vec::new();
    for size in SIZES {
        let spiral = (size >= SPIRAL_FROM).then_some(theme::ROSE_LIGHT);
        let rgba = brand::emblem_rgba(size, theme::ROSE, spiral);
        let image = dib(&rgba, size);
        let offset = (6 + 16 * SIZES.len() + images.len()) as u32;
        ico.extend_from_slice(&[size as u8, size as u8, 0, 0]);
        ico.extend_from_slice(&1_u16.to_le_bytes());
        ico.extend_from_slice(&32_u16.to_le_bytes());
        ico.extend_from_slice(&(image.len() as u32).to_le_bytes());
        ico.extend_from_slice(&offset.to_le_bytes());
        images.extend_from_slice(&image);
    }
    ico.extend_from_slice(&images);
    ico
}

/// One 32-bit image of an `.ico`: a BITMAPINFOHEADER, bottom-up BGRA rows and
/// an empty AND mask, since the alpha channel already carries transparency.
fn dib(rgba: &[u8], size: u32) -> Vec<u8> {
    let row_bytes = size as usize * 4;
    assert_eq!(rgba.len(), row_bytes * size as usize);
    let mask_row_bytes = (size as usize).div_ceil(32) * 4;
    let mut image = Vec::with_capacity(40 + rgba.len() + mask_row_bytes * size as usize);
    image.extend_from_slice(&40_u32.to_le_bytes());
    image.extend_from_slice(&size.to_le_bytes());
    image.extend_from_slice(&(2 * size).to_le_bytes());
    image.extend_from_slice(&1_u16.to_le_bytes());
    image.extend_from_slice(&32_u16.to_le_bytes());
    image.extend_from_slice(&[0; 24]);
    for row in rgba.chunks_exact(row_bytes).rev() {
        for pixel in row.chunks_exact(4) {
            image.extend_from_slice(&[pixel[2], pixel[1], pixel[0], pixel[3]]);
        }
    }
    image.resize(image.len() + mask_row_bytes * size as usize, 0);
    image
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    #[ignore = "writes assets/rosetun.ico; run after changing the emblem"]
    fn write_app_icon() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/rosetun.ico");
        std::fs::write(path, app_icon()).unwrap();
    }

    #[test]
    fn dib_is_bottom_up_bgra_with_an_empty_and_mask() {
        let rgba = [
            1, 2, 3, 4, 5, 6, 7, 8, // top row
            9, 10, 11, 12, 13, 14, 15, 16, // bottom row
        ];
        let image = dib(&rgba, 2);
        assert_eq!(image.len(), 40 + 2 * 2 * 4 + 2 * 4);
        assert_eq!(
            &image[..16],
            &[40, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 1, 0, 32, 0]
        );
        assert_eq!(&image[16..40], &[0; 24]);
        assert_eq!(
            &image[40..56],
            &[11, 10, 9, 12, 15, 14, 13, 16, 3, 2, 1, 4, 7, 6, 5, 8]
        );
        assert_eq!(&image[56..], &[0; 8]);
    }

    #[test]
    fn committed_icon_has_all_sizes() {
        let ico = include_bytes!("../assets/rosetun.ico");
        assert_eq!(&ico[..4], &[0, 0, 1, 0]);
        assert_eq!(
            u16::from_le_bytes(ico[4..6].try_into().unwrap()),
            SIZES.len() as u16
        );
        let mut next_offset = 6 + 16 * SIZES.len();
        for (index, size) in SIZES.into_iter().enumerate() {
            let entry = &ico[6 + 16 * index..6 + 16 * (index + 1)];
            assert_eq!(entry[0], size as u8);
            assert_eq!(entry[1], size as u8);
            assert_eq!(u16::from_le_bytes(entry[6..8].try_into().unwrap()), 32);
            let length = u32_at(entry, 8) as usize;
            let offset = u32_at(entry, 12) as usize;
            assert_eq!(offset, next_offset);
            assert!(offset + length <= ico.len());
            assert_eq!(u32_at(ico, offset + 4), size);
            assert_eq!(u32_at(ico, offset + 8), 2 * size);
            next_offset += length;
        }
        assert_eq!(next_offset, ico.len());
    }
}
