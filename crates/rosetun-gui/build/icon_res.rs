/// A compiled resource file (`.res`) with the icon group of `ico` as the
/// executable's icon: the MSVC linker takes it as an input and embeds it.
pub(crate) fn icon_res(ico: &[u8]) -> Result<Vec<u8>, String> {
    let header = ico
        .get(..6)
        .ok_or("icon directory is shorter than 6 bytes")?;
    if header[..2] != [0, 0] || header[2..4] != [1, 0] {
        return Err("icon directory must have reserved 0 and type 1".into());
    }
    let count = usize::from(u16::from_le_bytes([header[4], header[5]]));
    if count == 0 {
        return Err("icon directory contains no images".into());
    }
    let entries_end = 6 + count * 16;
    let entries = ico
        .get(6..entries_end)
        .ok_or("icon directory entries extend beyond the file")?;

    let mut resource = Vec::new();
    write_resource(&mut resource, &[], 0, 0, 0, 0);
    let mut group = Vec::with_capacity(6 + count * 14);
    group.extend_from_slice(header);
    for (index, entry) in entries.chunks_exact(16).enumerate() {
        if entry[3] != 0 {
            return Err(format!(
                "icon image {} has a nonzero reserved byte",
                index + 1
            ));
        }
        let size = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(entry[12..16].try_into().unwrap()) as usize;
        let end = offset
            .checked_add(size)
            .ok_or_else(|| format!("icon image {} has an invalid offset or size", index + 1))?;
        if size == 0 || offset < entries_end {
            return Err(format!(
                "icon image {} has an invalid offset or size",
                index + 1
            ));
        }
        let image = ico
            .get(offset..end)
            .ok_or_else(|| format!("icon image {} extends beyond the file", index + 1))?;
        write_resource(&mut resource, image, 3, (index + 1) as u16, 0x1010, 0x0409);
        group.extend_from_slice(&entry[..12]);
        group.extend_from_slice(&((index + 1) as u16).to_le_bytes());
    }
    write_resource(&mut resource, &group, 14, 1, 0x1030, 0x0409);
    Ok(resource)
}

fn write_resource(
    resource: &mut Vec<u8>,
    data: &[u8],
    kind: u16,
    name: u16,
    flags: u16,
    language: u16,
) {
    resource.extend_from_slice(&(data.len() as u32).to_le_bytes());
    resource.extend_from_slice(&32_u32.to_le_bytes());
    resource.extend_from_slice(&0xffff_u16.to_le_bytes());
    resource.extend_from_slice(&kind.to_le_bytes());
    resource.extend_from_slice(&0xffff_u16.to_le_bytes());
    resource.extend_from_slice(&name.to_le_bytes());
    resource.extend_from_slice(&0_u32.to_le_bytes());
    resource.extend_from_slice(&flags.to_le_bytes());
    resource.extend_from_slice(&language.to_le_bytes());
    resource.extend_from_slice(&0_u32.to_le_bytes());
    resource.extend_from_slice(&0_u32.to_le_bytes());
    resource.extend_from_slice(data);
    resource.resize(resource.len() + (4 - data.len() % 4) % 4, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_image_icon() -> Vec<u8> {
        let mut ico = vec![0, 0, 1, 0, 2, 0];
        for (size, length, offset) in [(16_u8, 3_u32, 38_u32), (32, 5, 41)] {
            ico.extend_from_slice(&[size, size, 0, 0]);
            ico.extend_from_slice(&1_u16.to_le_bytes());
            ico.extend_from_slice(&32_u16.to_le_bytes());
            ico.extend_from_slice(&length.to_le_bytes());
            ico.extend_from_slice(&offset.to_le_bytes());
        }
        ico.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        ico
    }

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn writes_two_icons_and_group_with_aligned_resource_data() {
        let res = icon_res(&two_image_icon()).unwrap();
        assert_eq!(res.len(), 176);
        assert_eq!(
            &res[..32],
            &[
                0, 0, 0, 0, 32, 0, 0, 0, 0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(u32_at(&res, 32), 3);
        assert_eq!(u32_at(&res, 36), 32);
        assert_eq!(u16_at(&res, 40), 0xffff);
        assert_eq!(u16_at(&res, 42), 3);
        assert_eq!(u16_at(&res, 46), 1);
        assert_eq!(u16_at(&res, 52), 0x1010);
        assert_eq!(u16_at(&res, 54), 0x0409);
        assert_eq!(&res[64..68], &[1, 2, 3, 0]);

        assert_eq!(u32_at(&res, 68), 5);
        assert_eq!(u16_at(&res, 78), 3);
        assert_eq!(u16_at(&res, 82), 2);
        assert_eq!(&res[100..108], &[4, 5, 6, 7, 8, 0, 0, 0]);

        assert_eq!(u32_at(&res, 108), 6 + 2 * 14);
        assert_eq!(u16_at(&res, 118), 14);
        assert_eq!(u16_at(&res, 122), 1);
        assert_eq!(u16_at(&res, 128), 0x1030);
        assert_eq!(u16_at(&res, 130), 0x0409);
        assert_eq!(&res[140..146], &[0, 0, 1, 0, 2, 0]);
        assert_eq!(&res[146..150], &[16, 16, 0, 0]);
        assert_eq!(u32_at(&res, 154), 3);
        assert_eq!(u16_at(&res, 158), 1);
        assert_eq!(&res[160..164], &[32, 32, 0, 0]);
        assert_eq!(u32_at(&res, 168), 5);
        assert_eq!(u16_at(&res, 172), 2);
        assert_eq!(&res[174..], &[0, 0]);
    }

    #[test]
    fn rejects_invalid_icons() {
        let mut ico = two_image_icon();
        ico[2] = 2;
        assert!(icon_res(&ico).is_err());

        let mut ico = two_image_icon();
        ico[4] = 0;
        assert!(icon_res(&ico).is_err());

        let mut ico = two_image_icon();
        ico[18..22].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(icon_res(&ico).is_err());
    }

    #[test]
    fn committed_icon_has_eight_group_entries() {
        let res = icon_res(include_bytes!("../assets/rosetun.ico")).unwrap();
        let group_length = 6 + 8 * 14;
        let padding = (4 - group_length % 4) % 4;
        let group_start = res.len() - group_length - padding;
        assert_eq!(u32_at(&res, group_start - 32), group_length as u32);
        assert_eq!(u16_at(&res, group_start - 22), 14);
        let group = &res[group_start..group_start + group_length];
        assert_eq!(&group[..6], &[0, 0, 1, 0, 8, 0]);
        assert_eq!(u16_at(group, 6 + 7 * 14 + 12), 8);
    }
}
