//! macOS process enumeration via Darwin `libproc` and `.app` bundle names via
//! CoreFoundation `Info.plist` parsing.
//!
//! `proc_pidpath` returns the exact executable path that `sing-box` matches in
//! `process_path` and `process_path_regex` rules on macOS.

use std::ffi::{CStr, OsStr, c_char, c_int, c_void};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use crate::{ProcessListError, RunningProcess};

/// `PROC_PIDPATHINFO_MAXSIZE` (`4 * MAXPATHLEN`) from Darwin `<sys/proc_info.h>`.
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
/// Generous buffer for `proc_name` (`2 * MAXCOMLEN` is 32 bytes on Darwin).
const PROC_NAME_MAXSIZE: usize = 256;
/// Upper bound on reading an application's `Info.plist`.
const MAX_PLIST_BYTES: u64 = 1024 * 1024;

const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const CF_PROPERTY_LIST_IMMUTABLE: usize = 0;

type CFTypeRef = *const c_void;
type CFAllocatorRef = *const c_void;
type CFDataRef = *const c_void;
type CFStringRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFTypeID = usize;

unsafe extern "C" {
    fn proc_listallpids(buffer: *mut c_void, buffersize: c_int) -> c_int;
    fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
    fn proc_name(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(cf: CFTypeRef);
    fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
    fn CFDictionaryGetTypeID() -> CFTypeID;
    fn CFStringGetTypeID() -> CFTypeID;
    fn CFDataCreate(alloc: CFAllocatorRef, bytes: *const u8, length: isize) -> CFDataRef;
    fn CFPropertyListCreateWithData(
        alloc: CFAllocatorRef,
        data: CFDataRef,
        options: usize,
        format: *mut isize,
        error: *mut CFTypeRef,
    ) -> CFTypeRef;
    fn CFStringCreateWithBytes(
        alloc: CFAllocatorRef,
        bytes: *const u8,
        num_bytes: isize,
        encoding: u32,
        is_external_representation: u8,
    ) -> CFStringRef;
    fn CFDictionaryGetValue(dict: CFDictionaryRef, key: CFTypeRef) -> CFTypeRef;
    fn CFStringGetLength(string: CFStringRef) -> isize;
    fn CFStringGetMaximumSizeForEncoding(length: isize, encoding: u32) -> isize;
    fn CFStringGetCString(
        string: CFStringRef,
        buffer: *mut c_char,
        buffer_size: isize,
        encoding: u32,
    ) -> u8;
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
        if !self.0.is_null() {
            // SAFETY: `self.0` is exclusively owned from a CoreFoundation `Create` call.
            unsafe { CFRelease(self.0) };
        }
    }
}

pub(super) fn running_processes() -> Result<Vec<RunningProcess>, ProcessListError> {
    let pids = list_all_pids().map_err(ProcessListError::Snapshot)?;
    let mut processes = Vec::with_capacity(pids.len());
    let mut path_buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    let mut name_buf = [0u8; PROC_NAME_MAXSIZE];

    for pid in pids {
        if pid <= 0 {
            continue;
        }
        let path = read_pid_path(pid, &mut path_buf);
        let name = path
            .as_deref()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
            .or_else(|| read_pid_name(pid, &mut name_buf));
        let Some(name) = name else {
            continue;
        };
        let has_window = path.as_deref().is_some_and(is_top_level_app_executable);
        processes.push(RunningProcess {
            pid: pid.cast_unsigned(),
            name,
            path,
            has_window,
        });
    }
    Ok(processes)
}

fn list_all_pids() -> io::Result<Vec<i32>> {
    // SAFETY: Passing `(NULL, 0)` queries the current number of active PIDs.
    let estimated = unsafe { proc_listallpids(ptr::null_mut(), 0) };
    if estimated < 0 {
        return Err(io::Error::last_os_error());
    }
    if estimated == 0 {
        return Ok(Vec::new());
    }

    let mut capacity = estimated.cast_unsigned() as usize + 128;
    for _ in 0..3 {
        let mut pids = vec![0i32; capacity];
        let byte_len = c_int::try_from(pids.len().saturating_mul(std::mem::size_of::<i32>()))
            .map_err(|_| io::Error::other("PID buffer exceeds c_int::MAX"))?;
        // SAFETY: `pids` is writable for `byte_len` bytes and aligned for `i32`.
        let actual = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), byte_len) };
        if actual < 0 {
            return Err(io::Error::last_os_error());
        }
        let count = actual.cast_unsigned() as usize;
        if count < capacity {
            pids.truncate(count);
            return Ok(pids);
        }
        capacity = capacity.saturating_mul(2);
    }

    let mut pids = vec![0i32; capacity];
    let byte_len = c_int::try_from(pids.len().saturating_mul(std::mem::size_of::<i32>()))
        .map_err(|_| io::Error::other("PID buffer exceeds c_int::MAX"))?;
    // SAFETY: `pids` is writable for `byte_len` bytes and aligned for `i32`.
    let actual = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), byte_len) };
    if actual < 0 {
        return Err(io::Error::last_os_error());
    }
    pids.truncate((actual.cast_unsigned() as usize).min(pids.len()));
    Ok(pids)
}

fn read_pid_path(pid: c_int, buf: &mut [u8]) -> Option<PathBuf> {
    let size = u32::try_from(buf.len()).ok()?;
    // SAFETY: `buf` is writable for `size` bytes (`PROC_PIDPATHINFO_MAXSIZE`).
    let len = unsafe { proc_pidpath(pid, buf.as_mut_ptr().cast(), size) };
    if len <= 0 {
        return None;
    }
    let len = (len.cast_unsigned() as usize).min(buf.len());
    let slice = &buf[..len];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    if end == 0 {
        return None;
    }
    Some(PathBuf::from(OsStr::from_bytes(&slice[..end])))
}

fn read_pid_name(pid: c_int, buf: &mut [u8]) -> Option<String> {
    let size = u32::try_from(buf.len()).ok()?;
    // SAFETY: `buf` is writable for `size` bytes.
    let len = unsafe { proc_name(pid, buf.as_mut_ptr().cast(), size) };
    if len <= 0 {
        return None;
    }
    let len = (len.cast_unsigned() as usize).min(buf.len());
    let slice = &buf[..len];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    if end == 0 {
        return None;
    }
    let text = String::from_utf8_lossy(&slice[..end]).into_owned();
    (!text.is_empty()).then_some(text)
}

/// Whether `path` is the main executable of a top-level macOS `.app` bundle
/// (`.../<App>.app/Contents/MacOS/<Binary>`), excluding nested helper/XPC
/// bundles inside another `.app`.
fn is_top_level_app_executable(path: &Path) -> bool {
    let Some(macos_dir) = path.parent() else {
        return false;
    };
    if macos_dir.file_name() != Some(OsStr::new("MacOS")) {
        return false;
    }
    let Some(contents_dir) = macos_dir.parent() else {
        return false;
    };
    if contents_dir.file_name() != Some(OsStr::new("Contents")) {
        return false;
    }
    let Some(bundle_dir) = contents_dir.parent() else {
        return false;
    };
    if !has_app_extension(bundle_dir) {
        return false;
    }
    // Nested helper apps live inside `Outer.app/Contents/.../Helper.app`.
    !bundle_dir.ancestors().skip(1).any(has_app_extension)
}

fn has_app_extension(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
}

fn enclosing_app_bundle(path: &Path) -> Option<&Path> {
    if !path.is_absolute() {
        return None;
    }
    path.ancestors()
        .skip(1)
        .find(|ancestor| has_app_extension(ancestor))
}

/// The human-readable macOS application name for executables inside an `.app`
/// bundle (`CFBundleDisplayName`, then `CFBundleName` from `Contents/Info.plist`,
/// falling back to the `.app` bundle stem).
pub(super) fn file_description(path: &Path) -> Option<String> {
    let bundle = enclosing_app_bundle(path)?;
    let info_plist = bundle.join("Contents").join("Info.plist");
    if let Some(name) = read_plist_bundle_name(&info_plist) {
        return Some(name);
    }
    bundle
        .file_stem()
        .and_then(OsStr::to_str)
        .map(str::trim)
        .filter(|stem| !stem.is_empty())
        .map(ToOwned::to_owned)
}

fn read_plist_bundle_name(plist_path: &Path) -> Option<String> {
    let file = File::open(plist_path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_PLIST_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_PLIST_BYTES {
        return None;
    }
    parse_plist_bundle_name(&bytes)
}

fn parse_plist_bundle_name(bytes: &[u8]) -> Option<String> {
    let len = isize::try_from(bytes.len()).ok()?;
    // SAFETY: `bytes` is valid for `len` bytes; null allocator selects default.
    let data = CfRef::from_owned(unsafe { CFDataCreate(ptr::null(), bytes.as_ptr(), len) })?;
    // SAFETY: `data` is a live `CFDataRef`; format and error outputs are null.
    let plist = CfRef::from_owned(unsafe {
        CFPropertyListCreateWithData(
            ptr::null(),
            data.as_ptr(),
            CF_PROPERTY_LIST_IMMUTABLE,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    })?;
    // SAFETY: `plist` is a valid non-null CoreFoundation object.
    let is_dict = unsafe { CFGetTypeID(plist.as_ptr()) == CFDictionaryGetTypeID() };
    if !is_dict {
        return None;
    }
    for key_name in ["CFBundleDisplayName", "CFBundleName"] {
        if let Some(value) = cf_dict_string(plist.as_ptr(), key_name) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
    }
    None
}

fn cf_dict_string(dict: CFDictionaryRef, key_name: &str) -> Option<String> {
    let bytes = key_name.as_bytes();
    let len = isize::try_from(bytes.len()).ok()?;
    // SAFETY: `bytes` is valid UTF-8 for `len` bytes.
    let key = CfRef::from_owned(unsafe {
        CFStringCreateWithBytes(ptr::null(), bytes.as_ptr(), len, CF_STRING_ENCODING_UTF8, 0)
    })?;
    // SAFETY: `dict` was verified to be a `CFDictionary` and `key` is a live `CFString`.
    let value = unsafe { CFDictionaryGetValue(dict, key.as_ptr()) };
    if value.is_null() {
        return None;
    }
    // SAFETY: `value` is a non-null borrowed CFTypeRef owned by `dict`.
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
    // SAFETY: `buf` has space for `buf_size` bytes including trailing NUL.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_top_level_and_nested_app_bundle_executables() {
        assert!(is_top_level_app_executable(Path::new(
            "/Applications/Safari.app/Contents/MacOS/Safari"
        )));
        assert!(!is_top_level_app_executable(Path::new(
            "/Applications/Safari.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper"
        )));
        assert!(!is_top_level_app_executable(Path::new("/usr/bin/curl")));
        assert!(!is_top_level_app_executable(Path::new(
            "/Applications/Safari.app/Contents/XPCServices/net.xpc/Contents/MacOS/net"
        )));
    }

    #[test]
    fn parses_display_name_and_bundle_name_from_xml_plist() {
        let display = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleDisplayName</key><string>Visual Studio Code</string>
    <key>CFBundleName</key><string>Code</string>
</dict></plist>"#;
        assert_eq!(
            parse_plist_bundle_name(display).as_deref(),
            Some("Visual Studio Code")
        );

        let fallback = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
    <key>CFBundleName</key><string>Terminal</string>
</dict></plist>"#;
        assert_eq!(
            parse_plist_bundle_name(fallback).as_deref(),
            Some("Terminal")
        );
        assert_eq!(parse_plist_bundle_name(b"not a plist"), None);
    }

    #[test]
    fn relative_and_non_bundle_paths_have_no_description() {
        assert_eq!(
            file_description(Path::new("Safari.app/Contents/MacOS/Safari")),
            None
        );
        assert_eq!(file_description(Path::new("/usr/bin/curl")), None);
    }
}
