//! A program's own icon, read from its executable through the shell.

use std::path::Path;

/// The largest icon side, in physical pixels, the shell is asked for.
const MAX_ICON_PX: u32 = 256;

/// An icon as straight (not premultiplied) RGBA, rows top to bottom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconImage {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// The icon of the executable at `path`, `size_px` physical pixels square.
///
/// Only a `.exe` on a local drive is read; anything else is `None` before
/// the system is asked. On Windows the calling thread must have entered a
/// single-threaded COM apartment ([`ComApartment`]).
pub fn program_icon(path: &Path, size_px: u32) -> Option<IconImage> {
    if !(1..=MAX_ICON_PX).contains(&size_px) {
        return None;
    }
    let path = local_executable(path)?;
    native::read(&path, size_px)
}

/// `path` as a plain `X:\…\name.exe`, with a `\\?\` prefix removed.
///
/// A UNC path, `\\?\UNC\…` or any other device form is refused: resolving
/// it makes Windows connect to that server and offer it the user's NTLM
/// hash. Network drive letters are refused later by the drive type.
fn local_executable(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    let text = text.strip_prefix(r"\\?\").unwrap_or(text);
    let bytes = text.as_bytes();
    let drive_form =
        bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    // A later colon names an alternate data stream; NUL would cut the
    // wide string short.
    if !drive_form || text[2..].contains([':', '\0']) {
        return None;
    }
    let extension = text.get(text.len().saturating_sub(4)..)?;
    extension
        .eq_ignore_ascii_case(".exe")
        .then(|| text.to_owned())
}

/// Shell bitmaps carry premultiplied BGRA; an icon without an alpha
/// channel comes back with every alpha byte zero and is opaque.
#[cfg_attr(not(any(windows, test)), expect(dead_code, reason = "Windows only"))]
fn straight_rgba(mut pixels: Vec<u8>) -> Vec<u8> {
    let opaque = pixels.chunks_exact(4).all(|pixel| pixel[3] == 0);
    for pixel in pixels.chunks_exact_mut(4) {
        pixel.swap(0, 2);
        let alpha = u16::from(pixel[3]);
        if opaque {
            pixel[3] = u8::MAX;
        } else if alpha == 0 {
            pixel[..3].fill(0);
        } else if alpha < 255 {
            for channel in &mut pixel[..3] {
                let value = (u16::from(*channel) * 255 + alpha / 2) / alpha;
                *channel = value.min(255) as u8;
            }
        }
    }
    pixels
}

#[cfg(windows)]
pub use native::ComApartment;

#[cfg(windows)]
mod native {
    use std::ffi::c_void;
    use std::marker::PhantomData;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::SIZE;
    use windows_sys::Win32::Graphics::Gdi::{
        BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC,
        DeleteObject, GetDIBits, GetObjectW, HBITMAP, HDC,
    };
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    use windows_sys::Win32::System::Com::{
        APTTYPE_MAINSTA, APTTYPE_STA, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
        CoGetApartmentType, CoInitializeEx, CoUninitialize,
    };
    use windows_sys::Win32::System::WindowsProgramming::{
        DRIVE_CDROM, DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOVABLE,
    };
    use windows_sys::Win32::UI::Shell::{SHCreateItemFromParsingName, SIIGBF, SIIGBF_ICONONLY};
    use windows_sys::core::{GUID, HRESULT};

    use super::{IconImage, MAX_ICON_PX, straight_rgba};

    const IID_ISHELL_ITEM_IMAGE_FACTORY: GUID =
        GUID::from_u128(0xbcc18b79_ba16_442f_80c4_8a59c30c463b);

    /// `IShellItemImageFactory`'s vtable: `IUnknown`, then `GetImage`.
    /// windows-sys has no COM interfaces, so the layout is written out.
    #[repr(C)]
    struct ImageFactoryVtbl {
        _query_interface:
            unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
        _add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
        release: unsafe extern "system" fn(*mut c_void) -> u32,
        get_image: unsafe extern "system" fn(*mut c_void, SIZE, SIIGBF, *mut HBITMAP) -> HRESULT,
    }

    /// A single-threaded COM apartment entered by the current thread and
    /// left when dropped. Not `Send`: the apartment belongs to the thread.
    #[derive(Debug)]
    pub struct ComApartment {
        _thread: PhantomData<*const ()>,
    }

    impl ComApartment {
        /// `None` when the thread is already in a multithreaded apartment.
        pub fn enter() -> Option<Self> {
            // SAFETY: no reserved pointer; a success (S_OK, or S_FALSE when
            // already in an STA) is balanced by CoUninitialize in Drop on
            // this same thread, which `PhantomData<*const ()>` guarantees.
            let result = unsafe {
                CoInitializeEx(
                    null(),
                    (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
                )
            };
            (result >= 0).then_some(Self {
                _thread: PhantomData,
            })
        }
    }

    impl Drop for ComApartment {
        fn drop(&mut self) {
            // SAFETY: balances the successful CoInitializeEx in `enter` on
            // the thread that made it.
            unsafe { CoUninitialize() };
        }
    }

    /// An owned `IShellItemImageFactory` pointer, released once.
    struct ImageFactory(*mut c_void);

    impl ImageFactory {
        fn vtbl(&self) -> &ImageFactoryVtbl {
            // SAFETY: `self.0` is a live COM object whose first field is a
            // pointer to its vtable, valid while we hold the reference.
            unsafe { &**self.0.cast::<*const ImageFactoryVtbl>() }
        }
    }

    impl Drop for ImageFactory {
        fn drop(&mut self) {
            // SAFETY: we own one reference from SHCreateItemFromParsingName.
            unsafe { (self.vtbl().release)(self.0) };
        }
    }

    /// An owned GDI bitmap, deleted once.
    struct Bitmap(HBITMAP);

    impl Drop for Bitmap {
        fn drop(&mut self) {
            // SAFETY: GetImage hands the bitmap to the caller; it is not
            // selected into any DC.
            unsafe { DeleteObject(self.0) };
        }
    }

    /// A memory DC, deleted once.
    struct MemoryDc(HDC);

    impl Drop for MemoryDc {
        fn drop(&mut self) {
            // SAFETY: created by CreateCompatibleDC and owned here.
            unsafe { DeleteDC(self.0) };
        }
    }

    pub(super) fn read(path: &str, size_px: u32) -> Option<IconImage> {
        if !in_single_threaded_apartment() || !on_local_drive(path) {
            return None;
        }
        let wide = wide(path);
        let mut object = null_mut();
        // SAFETY: `wide` is NUL-terminated UTF-16 alive for the call; on
        // success `object` holds one reference to the requested interface,
        // owned by `ImageFactory` from here on.
        let result = unsafe {
            SHCreateItemFromParsingName(
                wide.as_ptr(),
                null_mut(),
                &IID_ISHELL_ITEM_IMAGE_FACTORY,
                &mut object,
            )
        };
        if result < 0 || object.is_null() {
            return None;
        }
        let factory = ImageFactory(object);
        let side = size_px as i32;
        let mut handle = null_mut();
        // SAFETY: `factory` is live; on success the bitmap is ours to delete.
        let result = unsafe {
            (factory.vtbl().get_image)(
                factory.0,
                SIZE { cx: side, cy: side },
                SIIGBF_ICONONLY,
                &mut handle,
            )
        };
        if result < 0 || handle.is_null() {
            return None;
        }
        pixels(&Bitmap(handle))
    }

    fn in_single_threaded_apartment() -> bool {
        let mut kind = 0;
        let mut qualifier = 0;
        // SAFETY: both out-pointers are valid locals.
        let result = unsafe { CoGetApartmentType(&mut kind, &mut qualifier) };
        result >= 0 && matches!(kind, APTTYPE_STA | APTTYPE_MAINSTA)
    }

    /// Network drive letters are refused for the same reason as UNC paths.
    fn on_local_drive(path: &str) -> bool {
        let root = wide(&path[..3]);
        // SAFETY: `root` is a NUL-terminated `X:\` alive for the call; the
        // lookup reads the drive letter's mapping and touches no server.
        let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
        matches!(
            kind,
            DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_CDROM | DRIVE_RAMDISK
        )
    }

    fn pixels(bitmap: &Bitmap) -> Option<IconImage> {
        let mut info = BITMAP::default();
        // SAFETY: `info` is a BITMAP of the size passed.
        let filled =
            unsafe { GetObjectW(bitmap.0, size_of::<BITMAP>() as i32, (&raw mut info).cast()) };
        if filled == 0 {
            return None;
        }
        let width = u32::try_from(info.bmWidth).ok()?;
        let height = info.bmHeight.unsigned_abs();
        if !(1..=MAX_ICON_PX).contains(&width) || !(1..=MAX_ICON_PX).contains(&height) {
            return None;
        }
        // SAFETY: a memory DC compatible with the screen, owned by `dc`.
        let dc = MemoryDc(unsafe { CreateCompatibleDC(null_mut()) });
        if dc.0.is_null() {
            return None;
        }
        let mut header = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width as i32,
                // Negative: rows top to bottom.
                biHeight: -(height as i32),
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut pixels = vec![0; width as usize * height as usize * 4];
        // SAFETY: `pixels` holds exactly `height` rows of `width` 32-bit
        // pixels as `header` describes; the bitmap is in no DC.
        let lines = unsafe {
            GetDIBits(
                dc.0,
                bitmap.0,
                0,
                height,
                pixels.as_mut_ptr().cast(),
                &mut header,
                DIB_RGB_COLORS,
            )
        };
        (lines == height as i32).then(|| IconImage {
            width,
            height,
            rgba: straight_rgba(pixels),
        })
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }
}

#[cfg(not(windows))]
mod native {
    use super::IconImage;

    pub(super) fn read(_path: &str, _size_px: u32) -> Option<IconImage> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_and_device_paths_are_refused() {
        for path in [
            r"\\server.invalid\share\app.exe",
            r"\\?\UNC\server.invalid\share\app.exe",
            r"\\.\C:\Program Files\App\app.exe",
            r"\??\C:\Program Files\App\app.exe",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\app.exe",
            "//server.invalid/share/app.exe",
        ] {
            assert_eq!(local_executable(Path::new(path)), None, "{path}");
            assert_eq!(program_icon(Path::new(path), 32), None, "{path}");
        }
    }

    #[test]
    fn relative_paths_and_other_files_are_refused() {
        for path in [
            "app.exe",
            r"Program Files\App\app.exe",
            r"C:app.exe",
            r"\Program Files\App\app.exe",
            r"C:\Program Files\App\app.dll",
            r"C:\Program Files\App\app.lnk",
            r"C:\Program Files\App\app.exe:stream",
            r"C:\Program Files\App\app",
        ] {
            assert_eq!(local_executable(Path::new(path)), None, "{path}");
        }
    }

    #[test]
    fn a_local_executable_is_accepted_and_a_verbatim_prefix_dropped() {
        assert_eq!(
            local_executable(Path::new(r"C:\Program Files\App\App.EXE")).as_deref(),
            Some(r"C:\Program Files\App\App.EXE")
        );
        assert_eq!(
            local_executable(Path::new(r"\\?\D:\Tools\app.exe")).as_deref(),
            Some(r"D:\Tools\app.exe")
        );
    }

    #[test]
    fn sizes_outside_the_shell_range_are_refused() {
        let path = Path::new(r"C:\Windows\System32\notepad.exe");
        assert_eq!(program_icon(path, 0), None);
        assert_eq!(program_icon(path, MAX_ICON_PX + 1), None);
    }

    #[test]
    fn premultiplied_bgra_becomes_straight_rgba() {
        let pixels = vec![10, 20, 30, 255, 0, 64, 128, 128, 9, 9, 9, 0];
        assert_eq!(
            straight_rgba(pixels),
            vec![30, 20, 10, 255, 255, 128, 0, 128, 0, 0, 0, 0]
        );
    }

    #[test]
    fn a_bitmap_without_alpha_is_opaque() {
        let pixels = vec![10, 20, 30, 0, 40, 50, 60, 0];
        assert_eq!(
            straight_rgba(pixels),
            vec![30, 20, 10, 255, 60, 50, 40, 255]
        );
    }

    #[cfg(windows)]
    #[test]
    fn notepad_has_an_icon_of_the_requested_size() {
        let _apartment = ComApartment::enter().unwrap();
        let path = Path::new(r"C:\Windows\System32\notepad.exe");
        let icon = program_icon(path, 32).unwrap();
        assert_eq!((icon.width, icon.height), (32, 32));
        assert_eq!(icon.rgba.len(), 32 * 32 * 4);
        assert!(icon.rgba.chunks_exact(4).any(|pixel| pixel[3] > 0));
    }

    #[cfg(windows)]
    #[test]
    fn no_icon_is_read_outside_a_single_threaded_apartment() {
        let path = Path::new(r"C:\Windows\System32\notepad.exe");
        let icon = std::thread::spawn(move || program_icon(path, 32))
            .join()
            .unwrap();
        assert_eq!(icon, None);
    }
}
