//! Desktop language lookup and folder opening on macOS.

use std::ffi::{CStr, c_char, c_void};
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

type CFTypeRef = *const c_void;
type CFArrayRef = *const c_void;
type CFStringRef = *const c_void;

const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const OPEN_BIN: &str = "/usr/bin/open";

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(cf: CFTypeRef);
    fn CFGetTypeID(cf: CFTypeRef) -> usize;
    fn CFArrayGetCount(the_array: CFArrayRef) -> isize;
    fn CFArrayGetValueAtIndex(the_array: CFArrayRef, idx: isize) -> CFTypeRef;
    fn CFStringGetTypeID() -> usize;
    fn CFStringGetLength(the_string: CFStringRef) -> isize;
    fn CFStringGetMaximumSizeForEncoding(length: isize, encoding: u32) -> isize;
    fn CFStringGetCString(
        the_string: CFStringRef,
        buffer: *mut c_char,
        buffer_size: isize,
        encoding: u32,
    ) -> u8;
    fn CFLocaleCopyPreferredLanguages() -> CFArrayRef;
}

struct CfRef(CFTypeRef);

impl CfRef {
    fn from_owned(ptr: CFTypeRef) -> Option<Self> {
        (!ptr.is_null()).then_some(Self(ptr))
    }

    fn as_ptr(&self) -> CFTypeRef {
        self.0
    }
}

impl Drop for CfRef {
    fn drop(&mut self) {
        // SAFETY: `self.0` was created via a CoreFoundation Copy rule call and is non-null.
        unsafe { CFRelease(self.0) };
    }
}

/// The user's preferred interface language tag (such as `ru-RU` or `en-US`),
/// read from macOS CoreFoundation with POSIX environment fallback.
pub fn user_language() -> Option<String> {
    preferred_macos_language().or_else(|| language_from(|name| std::env::var(name).ok()))
}

fn preferred_macos_language() -> Option<String> {
    // SAFETY: `CFLocaleCopyPreferredLanguages` takes no arguments and returns an owned CFArrayRef.
    let languages = CfRef::from_owned(unsafe { CFLocaleCopyPreferredLanguages() })?;
    // SAFETY: `languages` is a live `CFArrayRef`.
    let count = unsafe { CFArrayGetCount(languages.as_ptr()) };
    for index in 0..count {
        // SAFETY: `0 <= index < count` on a live `CFArrayRef`.
        let entry = unsafe { CFArrayGetValueAtIndex(languages.as_ptr(), index) };
        if let Some(tag) = cf_string_to_rust(entry) {
            let trimmed = tag.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
    }
    None
}

fn cf_string_to_rust(value: CFTypeRef) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: `value` is a non-null borrowed CoreFoundation object.
    let is_string = unsafe { CFGetTypeID(value) == CFStringGetTypeID() };
    if !is_string {
        return None;
    }
    // SAFETY: `value` was verified to be a `CFString`.
    let utf16_len = unsafe { CFStringGetLength(value) };
    if utf16_len <= 0 {
        return None;
    }
    // SAFETY: `CFStringGetMaximumSizeForEncoding` is a pure size query.
    let max_bytes =
        unsafe { CFStringGetMaximumSizeForEncoding(utf16_len, CF_STRING_ENCODING_UTF8) };
    let buf_len = usize::try_from(max_bytes).ok()?.checked_add(1)?;
    let buf_size = isize::try_from(buf_len).ok()?;
    let mut buf = vec![0 as c_char; buf_len];
    // SAFETY: `buf` has space for `buf_size` bytes including the trailing NUL terminator.
    let ok =
        unsafe { CFStringGetCString(value, buf.as_mut_ptr(), buf_size, CF_STRING_ENCODING_UTF8) };
    if ok == 0 {
        return None;
    }
    // SAFETY: `CFStringGetCString` succeeded and NUL-terminated `buf`.
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_str()
        .ok()
        .map(ToOwned::to_owned)
}

fn language_from(variable: impl Fn(&str) -> Option<String>) -> Option<String> {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .filter_map(variable)
        .find(|value| !value.trim().is_empty())
}

/// Opens `folder` in Finder using `/usr/bin/open`.
pub fn open_folder(folder: &Path) -> io::Result<()> {
    if !folder.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the folder path is not absolute",
        ));
    }
    Command::new(OPEN_BIN)
        .arg(folder)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|mut child| {
            // Reap the short-lived launcher process so it leaves no zombie behind.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_fallback_follows_locale_precedence() {
        let language = |set: &[(&str, &str)]| {
            language_from(|name| {
                set.iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            })
        };
        assert_eq!(language(&[]), None);
        assert_eq!(language(&[("LANG", "ru_RU.UTF-8")]).unwrap(), "ru_RU.UTF-8");
        assert_eq!(
            language(&[("LANG", "en_US"), ("LC_MESSAGES", "ru_RU")]).unwrap(),
            "ru_RU"
        );
        assert_eq!(
            language(&[("LC_ALL", " "), ("LANG", "en_US")]).unwrap(),
            "en_US"
        );
    }

    #[test]
    fn a_relative_folder_is_refused_before_open_runs() {
        let error = open_folder(Path::new("relative/dir")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn macos_reports_a_preferred_language_tag() {
        let language = user_language().expect("preferred language on macOS");
        assert!(!language.trim().is_empty());
    }
}
