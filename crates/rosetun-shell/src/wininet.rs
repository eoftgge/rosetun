//! The current user's proxy settings on Windows, through WinINet.

use std::io;
use std::ptr;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::GlobalFree;
use windows_sys::Win32::Networking::WinInet::{
    INTERNET_OPTION_PER_CONNECTION_OPTION, INTERNET_OPTION_REFRESH,
    INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN, INTERNET_PER_CONN_AUTOCONFIG_URL,
    INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_OPTION_LISTW, INTERNET_PER_CONN_OPTIONW,
    INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER, InternetQueryOptionW,
    InternetSetOptionW, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
};

use crate::desktop_proxy::{Backend, LOOPBACK_V4, SavedSettings};

/// This computer and the private networks stay off the proxy, as other clients
/// set them; `<local>` is names without a dot.
const BYPASS: &str = "<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;\
                      172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;\
                      172.29.*;172.30.*;172.31.*;192.168.*";

/// The user's settings as WinINet reports them, the automatic script included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Saved {
    flags: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bypass: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    script: Option<String>,
}

fn ours(port: u16) -> Saved {
    Saved {
        flags: PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY,
        server: Some(server_for(port)),
        bypass: Some(BYPASS.to_owned()),
        script: None,
    }
}

fn server_for(port: u16) -> String {
    format!("{LOOPBACK_V4}:{port}")
}

/// Whether what WinINet reports is the local proxy: its server, in use.
fn is_ours(settings: &Saved, port: u16) -> bool {
    settings.flags & PROXY_TYPE_PROXY != 0 && settings.server.as_deref() == Some(&server_for(port))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// Copies and frees a string WinINet allocated for the caller.
///
/// # Safety
/// `value` is null, or a NUL-terminated string from `InternetQueryOptionW` that
/// nothing else frees.
unsafe fn take_string(value: *mut u16) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: Non-null and NUL-terminated by this function's contract.
    let length = unsafe { (0..).take_while(|&index| *value.add(index) != 0).count() };
    // SAFETY: `length` units were just read from this allocation.
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, length) });
    // SAFETY: WinINet documents these strings as freed with GlobalFree; this is
    // the only reference to the allocation.
    unsafe { GlobalFree(value.cast()) };
    (!text.is_empty()).then_some(text)
}

fn option(kind: INTERNET_PER_CONN) -> INTERNET_PER_CONN_OPTIONW {
    INTERNET_PER_CONN_OPTIONW {
        dwOption: kind,
        ..Default::default()
    }
}

fn read() -> io::Result<Saved> {
    let mut options = [
        option(INTERNET_PER_CONN_FLAGS),
        option(INTERNET_PER_CONN_PROXY_SERVER),
        option(INTERNET_PER_CONN_PROXY_BYPASS),
        option(INTERNET_PER_CONN_AUTOCONFIG_URL),
    ];
    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        // A null connection is the LAN settings, which is what is in use
        // without a dial-up connection.
        pszConnection: ptr::null_mut(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    };
    let mut size = size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32;
    // SAFETY: `list` and the options it points at outlive this synchronous call,
    // and `size` is the size of `list`.
    let done = unsafe {
        InternetQueryOptionW(
            ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&raw mut list).cast(),
            &mut size,
        )
    };
    if done == 0 {
        return Err(last_error());
    }
    // SAFETY: A successful query filled every option with the member its kind
    // selects: a number for the flags, strings for the rest, which the caller
    // owns and frees exactly once here.
    unsafe {
        Ok(Saved {
            flags: options[0].Value.dwValue,
            server: take_string(options[1].Value.pszValue),
            bypass: take_string(options[2].Value.pszValue),
            script: take_string(options[3].Value.pszValue),
        })
    }
}

fn write(settings: &Saved) -> io::Result<()> {
    let mut server = wide(settings.server.as_deref().unwrap_or_default());
    let mut bypass = wide(settings.bypass.as_deref().unwrap_or_default());
    let mut script = wide(settings.script.as_deref().unwrap_or_default());
    let string = |kind, value: &mut Vec<u16>| {
        let mut entry = option(kind);
        entry.Value.pszValue = value.as_mut_ptr();
        entry
    };
    let mut flags = option(INTERNET_PER_CONN_FLAGS);
    flags.Value.dwValue = settings.flags;
    let mut options = [
        flags,
        string(INTERNET_PER_CONN_PROXY_SERVER, &mut server),
        string(INTERNET_PER_CONN_PROXY_BYPASS, &mut bypass),
        string(INTERNET_PER_CONN_AUTOCONFIG_URL, &mut script),
    ];
    let list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: ptr::null_mut(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    };
    // SAFETY: `list`, its options and the wide strings they point at outlive this
    // synchronous call, which copies them; the size is that of `list`.
    let done = unsafe {
        InternetSetOptionW(
            ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&raw const list).cast(),
            size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        )
    };
    if done == 0 {
        return Err(last_error());
    }
    // Tells running programs; a failure here leaves the settings written, and
    // they see them on their next read.
    for notice in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
        // SAFETY: These two options take no buffer and no handle.
        let done = unsafe { InternetSetOptionW(ptr::null(), notice, ptr::null(), 0) };
        if done == 0 {
            tracing::warn!(error = %last_error(), "could not announce the proxy change");
        }
    }
    Ok(())
}

/// WinINet's settings of the user this process runs as.
pub(crate) struct WinInet;

impl Backend for WinInet {
    fn read(&self) -> io::Result<SavedSettings> {
        read().map(SavedSettings::WinInet)
    }

    fn apply(&self, port: u16) -> io::Result<()> {
        write(&ours(port))
    }

    fn write_back(&self, saved: &SavedSettings) -> io::Result<()> {
        match saved {
            SavedSettings::WinInet(settings) => write(settings),
            #[cfg(test)]
            SavedSettings::Fake(_) => Err(io::Error::other("settings of another desktop")),
        }
    }

    fn holds_ours(&self, port: u16) -> io::Result<bool> {
        read().map(|settings| is_ours(&settings, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_settings_are_recognised_by_server_and_use() {
        assert!(is_ours(&ours(10808), 10808));
        assert!(!is_ours(&ours(10808), 20808));

        let mut unused = ours(10808);
        unused.flags = PROXY_TYPE_DIRECT;
        assert!(!is_ours(&unused, 10808), "the user turned it off");

        let mut foreign = ours(10808);
        foreign.server = Some("proxy.example.com:3128".to_owned());
        assert!(!is_ours(&foreign, 10808));
    }

    #[test]
    fn the_proxy_points_at_loopback_and_private_networks_stay_off_it() {
        let settings = ours(10808);
        assert_eq!(settings.server.as_deref(), Some("127.0.0.1:10808"));
        assert_eq!(settings.flags, PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY);
        let bypass = settings.bypass.unwrap();
        for entry in [
            "<local>",
            "localhost",
            "127.*",
            "10.*",
            "172.16.*",
            "172.31.*",
            "192.168.*",
        ] {
            assert!(bypass.split(';').any(|item| item == entry), "{entry}");
        }
        assert!(!bypass.contains(' '));
        assert_eq!(settings.script, None);
    }

    #[test]
    fn a_saved_script_survives_the_record() {
        let saved = Saved {
            flags: 0x5,
            server: None,
            bypass: None,
            script: Some("http://proxy.example.com/wpad.dat".to_owned()),
        };
        let text = serde_json::to_string(&SavedSettings::WinInet(saved.clone())).unwrap();
        assert_eq!(
            serde_json::from_str::<SavedSettings>(&text).unwrap(),
            SavedSettings::WinInet(saved)
        );
    }
}
