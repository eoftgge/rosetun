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

pub(crate) fn executable_res(
    ico: Option<&[u8]>,
    version: &str,
    description: &str,
    filename: &str,
) -> Result<Vec<u8>, String> {
    let mut resource = if let Some(ico) = ico {
        icon_res(ico)?
    } else {
        let mut resource = Vec::new();
        write_resource(&mut resource, &[], 0, 0, 0, 0);
        resource
    };
    let info = version_info(version, description, filename)?;
    write_resource(&mut resource, &info, 16, 1, 0x1030, 0x0409);
    Ok(resource)
}

fn parse_version(version: &str) -> Result<([u16; 4], bool), String> {
    let (numeric, prerelease) = match version.split_once('-') {
        Some((numeric, suffix)) if !suffix.is_empty() => (numeric, true),
        Some(_) => return Err(format!("invalid package version: {version}")),
        None => (version, false),
    };
    let components = numeric.split('.').collect::<Vec<_>>();
    if components.len() != 3 {
        return Err(format!("invalid package version: {version}"));
    }
    let mut numbers = [0; 4];
    for (number, component) in numbers.iter_mut().zip(components) {
        if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("invalid package version: {version}"));
        }
        *number = component
            .parse()
            .map_err(|_| format!("invalid package version: {version}"))?;
    }
    Ok((numbers, prerelease))
}

fn version_info(version: &str, description: &str, filename: &str) -> Result<Vec<u8>, String> {
    let (numbers, prerelease) = parse_version(version)?;
    let mut fixed = Vec::with_capacity(52);
    for field in [
        0xfeef04bd,
        0x00010000,
        u32::from(numbers[0]) << 16 | u32::from(numbers[1]),
        u32::from(numbers[2]) << 16 | u32::from(numbers[3]),
        u32::from(numbers[0]) << 16 | u32::from(numbers[1]),
        u32::from(numbers[2]) << 16 | u32::from(numbers[3]),
        0x3f,
        if prerelease { 0x2 } else { 0 },
        0x00040004,
        0x1,
        0,
        0,
        0,
    ] {
        fixed.extend_from_slice(&field.to_le_bytes());
    }

    let strings = [
        ("FileDescription", description),
        ("ProductName", "Rosetun"),
        ("FileVersion", version),
        ("ProductVersion", version),
        ("OriginalFilename", filename),
        (
            "InternalName",
            filename.strip_suffix(".exe").unwrap_or(filename),
        ),
        ("LegalCopyright", "Rosetun contributors · GPL-3.0-or-later"),
    ]
    .map(|(key, value)| {
        let data = utf16z(value);
        block(key, &data, (data.len() / 2) as u16, 1, &[])
    });
    let string_table = block("040904B0", &[], 0, 1, &strings);
    let string_file_info = block("StringFileInfo", &[], 0, 1, &[string_table]);
    let translation = block("Translation", &[0x09, 0x04, 0xb0, 0x04], 4, 0, &[]);
    let var_file_info = block("VarFileInfo", &[], 0, 1, &[translation]);
    Ok(block(
        "VS_VERSION_INFO",
        &fixed,
        fixed.len() as u16,
        0,
        &[string_file_info, var_file_info],
    ))
}

fn utf16z(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn align4(bytes: &mut Vec<u8>) {
    bytes.resize((bytes.len() + 3) & !3, 0);
}

fn block(key: &str, value: &[u8], value_length: u16, kind: u16, children: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![0; 6];
    bytes.extend_from_slice(&utf16z(key));
    align4(&mut bytes);
    bytes.extend_from_slice(value);
    for child in children {
        align4(&mut bytes);
        bytes.extend_from_slice(child);
    }
    let length = u16::try_from(bytes.len()).expect("version resource block fits in u16");
    bytes[..2].copy_from_slice(&length.to_le_bytes());
    bytes[2..4].copy_from_slice(&value_length.to_le_bytes());
    bytes[4..6].copy_from_slice(&kind.to_le_bytes());
    bytes
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
    fn committed_icon_has_eleven_group_entries() {
        let res = icon_res(include_bytes!("rosetun-gui/assets/rosetun.ico")).unwrap();
        let group_length = 6 + 11 * 14;
        let padding = (4 - group_length % 4) % 4;
        let group_start = res.len() - group_length - padding;
        assert_eq!(u32_at(&res, group_start - 32), group_length as u32);
        assert_eq!(u16_at(&res, group_start - 22), 14);
        let group = &res[group_start..group_start + group_length];
        assert_eq!(&group[..6], &[0, 0, 1, 0, 11, 0]);
        assert_eq!(u16_at(group, 6 + 10 * 14 + 12), 11);
    }

    #[test]
    fn parses_numeric_and_prerelease_versions() {
        assert_eq!(parse_version("0.2.0"), Ok(([0, 2, 0, 0], false)));
        assert_eq!(parse_version("0.2.0-alpha.1"), Ok(([0, 2, 0, 0], true)));
        assert_eq!(parse_version("1.10.3-rc.2"), Ok(([1, 10, 3, 0], true)));
        for invalid in ["nonsense", "1.2", "1.2.3.4", "1.2.3-", "1.x.3", "65536.1.2"] {
            assert!(parse_version(invalid).is_err(), "{invalid}");
        }
    }

    fn check_block(bytes: &[u8], start: usize, end: usize, strings: &mut Vec<(String, String)>) {
        assert_eq!(start % 4, 0);
        let length = usize::from(u16_at(bytes, start));
        assert!(length >= 6 && start + length <= end);
        let value_length = usize::from(u16_at(bytes, start + 2));
        let kind = u16_at(bytes, start + 4);
        let mut cursor = start + 6;
        let mut key = Vec::new();
        loop {
            let unit = u16_at(bytes, cursor);
            cursor += 2;
            if unit == 0 {
                break;
            }
            key.push(unit);
        }
        let key = String::from_utf16(&key).unwrap();
        let aligned = (cursor + 3) & !3;
        assert!(bytes[cursor..aligned].iter().all(|byte| *byte == 0));
        cursor = aligned;
        let value_bytes = if kind == 1 {
            value_length * 2
        } else {
            value_length
        };
        assert!(cursor + value_bytes <= start + length, "{key}");
        if key == "VS_VERSION_INFO" {
            assert_eq!(kind, 0);
            assert_eq!(value_length, 52);
            assert_eq!(u32_at(bytes, cursor), 0xfeef04bd);
        } else if key == "Translation" {
            assert_eq!(kind, 0);
            assert_eq!(value_length, 4);
            assert_eq!(&bytes[cursor..cursor + 4], &[0x09, 0x04, 0xb0, 0x04]);
        } else if value_length != 0 {
            assert_eq!(kind, 1);
            let units = bytes[cursor..cursor + value_bytes]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            assert_eq!(units.last(), Some(&0));
            strings.push((
                key.clone(),
                String::from_utf16(&units[..units.len() - 1]).unwrap(),
            ));
        }
        cursor += value_bytes;
        while cursor < start + length {
            let aligned = (cursor + 3) & !3;
            assert!(aligned < start + length);
            assert!(bytes[cursor..aligned].iter().all(|byte| *byte == 0));
            check_block(bytes, aligned, start + length, strings);
            cursor = aligned + usize::from(u16_at(bytes, aligned));
        }
        assert_eq!(cursor, start + length, "{key}");
    }

    #[test]
    fn writes_version_resource_with_aligned_blocks_and_strings() {
        for (description, filename, ico) in [
            ("Rosetun", "rosetun-gui.exe", Some(two_image_icon())),
            ("Rosetun Service", "rosetun-helper-privileged.exe", None),
            ("Rosetun CLI", "rosetun.exe", None),
        ] {
            let res =
                executable_res(ico.as_deref(), "0.2.0-alpha.1", description, filename).unwrap();
            let mut offset = 0;
            let mut kinds = Vec::new();
            let mut version_data = None;
            while offset < res.len() {
                assert_eq!(offset % 4, 0);
                let size = u32_at(&res, offset) as usize;
                assert_eq!(u32_at(&res, offset + 4), 32);
                assert_eq!(u16_at(&res, offset + 8), 0xffff);
                assert_eq!(u16_at(&res, offset + 12), 0xffff);
                let kind = u16_at(&res, offset + 10);
                kinds.push(kind);
                if kind == 16 {
                    assert_eq!(u16_at(&res, offset + 14), 1);
                    assert_eq!(u16_at(&res, offset + 22), 0x0409);
                    version_data = Some(&res[offset + 32..offset + 32 + size]);
                }
                offset += 32 + ((size + 3) & !3);
            }
            assert_eq!(offset, res.len());
            if ico.is_some() {
                assert_eq!(kinds, [0, 3, 3, 14, 16]);
            } else {
                assert_eq!(kinds, [0, 16]);
            }
            let data = version_data.unwrap();
            assert_eq!(usize::from(u16_at(data, 0)), data.len());
            assert_eq!(u32_at(data, 48), 0x0000_0002);
            assert_eq!(u32_at(data, 52), 0);
            assert_eq!(u32_at(data, 56), 0x0000_0002);
            assert_eq!(u32_at(data, 60), 0);
            assert_eq!(u32_at(data, 64), 0x3f);
            assert_eq!(u32_at(data, 68), 0x2);
            assert_eq!(u32_at(data, 72), 0x0004_0004);
            assert_eq!(u32_at(data, 76), 0x1);
            let mut strings = Vec::new();
            check_block(data, 0, data.len(), &mut strings);
            assert_eq!(strings.len(), 7);
            for (key, value) in [
                ("FileDescription", description),
                ("ProductName", "Rosetun"),
                ("FileVersion", "0.2.0-alpha.1"),
                ("ProductVersion", "0.2.0-alpha.1"),
                ("OriginalFilename", filename),
                ("InternalName", filename.strip_suffix(".exe").unwrap()),
                ("LegalCopyright", "Rosetun contributors · GPL-3.0-or-later"),
            ] {
                assert!(strings.contains(&(key.into(), value.into())), "{key}");
            }
        }
    }

    #[test]
    fn release_version_has_no_prerelease_flag() {
        let info = version_info("1.10.3", "Rosetun", "rosetun-gui.exe").unwrap();
        assert_eq!(u32_at(&info, 48), 0x0001_000a);
        assert_eq!(u32_at(&info, 52), 0x0003_0000);
        assert_eq!(u32_at(&info, 56), 0x0001_000a);
        assert_eq!(u32_at(&info, 60), 0x0003_0000);
        assert_eq!(u32_at(&info, 68), 0);
    }
}
