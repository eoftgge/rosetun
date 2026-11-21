//! Crash-safe macOS system DNS registration via `SCDynamicStore` session keys.
//!
//! `sing-box`'s CLI TUN on macOS configures `utun` addresses and routes, and
//! intercepts port 53 traffic to the tunnel DNS address, but does not register
//! DNS servers with `configd`. Publishing a dedicated per-session key
//! (`State:/Network/Service/io.github.eoftgge.rosetun.dns/DNS`) with
//! `kSCDynamicStoreUseSessionKeys = true`, `SupplementalMatchDomains = [""]`,
//! and `SupplementalMatchOrders = [100000]` lets `configd`/`IPMonitor` update
//! `scutil --dns`, `State:/Network/Global/DNS`, and `/var/run/resolv.conf`
//! without touching persistent `Setup:` preferences or racing with DHCP on the
//! primary interface. If the helper exits or crashes unexpectedly (`SIGKILL`),
//! `configd` automatically removes the session key and restores normal DNS.

use std::ffi::{CStr, c_void};
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::ptr;

const STORE_NAME: &str = "io.github.eoftgge.rosetun";
const DNS_STATE_KEY: &str = "State:/Network/Service/io.github.eoftgge.rosetun.dns/DNS";
const SUPPLEMENTAL_ORDER: i32 = 100_000;

const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const CF_NUMBER_SINT32_TYPE: isize = 3;

type CFTypeRef = *const c_void;
type CFAllocatorRef = *const c_void;
type CFBooleanRef = *const c_void;
type CFStringRef = *const c_void;
type CFNumberRef = *const c_void;
type CFArrayRef = *const c_void;
type CFDictionaryRef = *const c_void;
type SCDynamicStoreRef = *const c_void;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFBooleanTrue: CFBooleanRef;
    static kCFTypeArrayCallBacks: c_void;
    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;

    fn CFRelease(cf: CFTypeRef);
    fn CFStringCreateWithBytes(
        alloc: CFAllocatorRef,
        bytes: *const u8,
        num_bytes: isize,
        encoding: u32,
        is_external_representation: u8,
    ) -> CFStringRef;
    fn CFNumberCreate(
        alloc: CFAllocatorRef,
        the_type: isize,
        value_ptr: *const c_void,
    ) -> CFNumberRef;
    fn CFArrayCreate(
        alloc: CFAllocatorRef,
        values: *const CFTypeRef,
        num_values: isize,
        callbacks: *const c_void,
    ) -> CFArrayRef;
    fn CFDictionaryCreate(
        alloc: CFAllocatorRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        num_values: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFDictionaryRef;
}

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    static kSCDynamicStoreUseSessionKeys: CFStringRef;

    fn SCDynamicStoreCreateWithOptions(
        allocator: CFAllocatorRef,
        name: CFStringRef,
        store_options: CFDictionaryRef,
        callout: *const c_void,
        context: *const c_void,
    ) -> SCDynamicStoreRef;
    fn SCDynamicStoreSetValue(store: SCDynamicStoreRef, key: CFStringRef, value: CFTypeRef) -> u8;
    fn SCDynamicStoreRemoveValue(store: SCDynamicStoreRef, key: CFStringRef) -> u8;
    fn SCError() -> i32;
    fn SCErrorString(status: i32) -> *const libc::c_char;
}

/// Owned CoreFoundation reference released via `CFRelease` on drop.
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
            // SAFETY: `self.0` was created by a CoreFoundation `Create` rule
            // and is owned exclusively by this wrapper.
            unsafe { CFRelease(self.0) };
        }
    }
}

fn sc_last_error(context: &str) -> io::Error {
    // SAFETY: `SCError` and `SCErrorString` take plain values and return a
    // static NUL-terminated description string owned by SystemConfiguration.
    let code = unsafe { SCError() };
    let description = unsafe {
        let raw = SCErrorString(code);
        if raw.is_null() {
            None
        } else {
            CStr::from_ptr(raw).to_str().ok()
        }
    };
    match description {
        Some(text) => io::Error::other(format!("{context}: {text} (SCError {code})")),
        None => io::Error::other(format!("{context}: SCError {code}")),
    }
}

fn cf_string(text: &str) -> io::Result<CfRef> {
    let bytes = text.as_bytes();
    let len = isize::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "CFString too long"))?;
    // SAFETY: `bytes` is valid UTF-8 for `len` bytes; null allocator selects
    // `kCFAllocatorDefault`.
    let raw = unsafe {
        CFStringCreateWithBytes(ptr::null(), bytes.as_ptr(), len, CF_STRING_ENCODING_UTF8, 0)
    };
    CfRef::from_owned(raw).ok_or_else(|| io::Error::other("CFStringCreateWithBytes returned null"))
}

fn cf_i32(value: i32) -> io::Result<CfRef> {
    // SAFETY: `value` is a valid `i32` matching `kCFNumberSInt32Type`.
    let raw = unsafe {
        CFNumberCreate(
            ptr::null(),
            CF_NUMBER_SINT32_TYPE,
            (&raw const value).cast(),
        )
    };
    CfRef::from_owned(raw).ok_or_else(|| io::Error::other("CFNumberCreate returned null"))
}

fn cf_array(items: &[CfRef]) -> io::Result<CfRef> {
    let ptrs: Vec<CFTypeRef> = items.iter().map(CfRef::as_ptr).collect();
    let len = isize::try_from(ptrs.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "CFArray too long"))?;
    // SAFETY: `ptrs` contains `len` live CFTypeRefs retained by `CFArrayCreate`
    // via `kCFTypeArrayCallBacks`.
    let raw = unsafe {
        CFArrayCreate(
            ptr::null(),
            ptrs.as_ptr(),
            len,
            &raw const kCFTypeArrayCallBacks,
        )
    };
    CfRef::from_owned(raw).ok_or_else(|| io::Error::other("CFArrayCreate returned null"))
}

fn cf_dictionary(pairs: &[(CFTypeRef, CFTypeRef)]) -> io::Result<CfRef> {
    let keys: Vec<CFTypeRef> = pairs.iter().map(|(key, _)| *key).collect();
    let values: Vec<CFTypeRef> = pairs.iter().map(|(_, value)| *value).collect();
    let len = isize::try_from(pairs.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "CFDictionary too long"))?;
    // SAFETY: `keys` and `values` hold `len` live CFTypeRefs retained by
    // `CFDictionaryCreate` via `kCFTypeDictionary{Key,Value}CallBacks`.
    let raw = unsafe {
        CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            len,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
        )
    };
    CfRef::from_owned(raw).ok_or_else(|| io::Error::other("CFDictionaryCreate returned null"))
}

fn open_session_store() -> io::Result<CfRef> {
    let name = cf_string(STORE_NAME)?;
    // SAFETY: Reading Apple's immutable framework pointer constants.
    let (session_key, cf_true) = unsafe { (kSCDynamicStoreUseSessionKeys, kCFBooleanTrue) };
    let options = cf_dictionary(&[(session_key, cf_true)])?;
    // SAFETY: `name` and `options` are live CoreFoundation objects; callout and
    // context are unused (null) because we never schedule a runloop callback.
    let raw = unsafe {
        SCDynamicStoreCreateWithOptions(
            ptr::null(),
            name.as_ptr(),
            options.as_ptr(),
            ptr::null(),
            ptr::null(),
        )
    };
    CfRef::from_owned(raw).ok_or_else(|| sc_last_error("SCDynamicStoreCreateWithOptions failed"))
}

fn build_dns_dictionary(servers: &[IpAddr]) -> io::Result<CfRef> {
    let server_strings: Vec<CfRef> = servers
        .iter()
        .map(|addr| cf_string(&addr.to_string()))
        .collect::<io::Result<_>>()?;
    let server_array = cf_array(&server_strings)?;

    let wildcard = cf_string("")?;
    let domains_array = cf_array(&[wildcard])?;

    let order = cf_i32(SUPPLEMENTAL_ORDER)?;
    let orders_array = cf_array(&[order])?;

    let key_servers = cf_string("ServerAddresses")?;
    let key_domains = cf_string("SupplementalMatchDomains")?;
    let key_orders = cf_string("SupplementalMatchOrders")?;

    cf_dictionary(&[
        (key_servers.as_ptr(), server_array.as_ptr()),
        (key_domains.as_ptr(), domains_array.as_ptr()),
        (key_orders.as_ptr(), orders_array.as_ptr()),
    ])
}

/// Computes the tunnel DNS servers to register in `SCDynamicStore`: always the
/// tunnel IPv4 DNS address, plus the tunnel IPv6 DNS address (`tun_ipv6 + 1`)
/// when IPv6 is configured on the TUN.
pub(super) fn tunnel_dns_servers(ipv4_dns: IpAddr, tun_ipv6: Option<&str>) -> Vec<IpAddr> {
    let mut servers = vec![ipv4_dns];
    if let Some(ipv6_dns) = tun_ipv6.and_then(next_ipv6_in_prefix) {
        servers.push(IpAddr::V6(ipv6_dns));
    }
    servers
}

fn next_ipv6_in_prefix(cidr: &str) -> Option<Ipv6Addr> {
    let (addr, prefix) = cidr.split_once('/')?;
    let address: Ipv6Addr = addr.parse().ok()?;
    let prefix_len: u8 = prefix.parse().ok()?;
    if prefix_len >= 128 {
        return None;
    }
    let host = u128::from(address);
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    };
    let network = host & mask;
    let next = host.checked_add(1)?;
    if next & mask != network {
        return None;
    }
    Some(Ipv6Addr::from(next))
}

/// Live per-session macOS DNS registration. Dropping it removes the dynamic
/// store key and closes the session handle so `configd` immediately restores
/// the primary interface's DNS.
pub(super) struct MacosSystemDns {
    store: CfRef,
    key: CfRef,
    servers: Vec<IpAddr>,
}

impl std::fmt::Debug for MacosSystemDns {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MacosSystemDns")
            .field("key", &DNS_STATE_KEY)
            .field("servers", &self.servers)
            .finish()
    }
}

// SAFETY: `SCDynamicStoreRef` is never scheduled on a CFRunLoop and is
// accessed exclusively behind `Session`'s mutex; Apple's SystemConfiguration
// framework serializes Mach IPC calls internally.
unsafe impl Send for MacosSystemDns {}

impl MacosSystemDns {
    pub(super) fn install(servers: &[IpAddr]) -> io::Result<Self> {
        if servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one tunnel DNS server is required",
            ));
        }
        let store = open_session_store()?;
        let key = cf_string(DNS_STATE_KEY)?;
        let dictionary = build_dns_dictionary(servers)?;
        // SAFETY: `store`, `key`, and `dictionary` are live CoreFoundation objects.
        let ok = unsafe {
            SCDynamicStoreSetValue(store.as_ptr(), key.as_ptr(), dictionary.as_ptr()) != 0
        };
        if !ok {
            return Err(sc_last_error("SCDynamicStoreSetValue failed"));
        }
        tracing::info!(
            key = DNS_STATE_KEY,
            servers = ?servers,
            "macOS session DNS registered via SCDynamicStore"
        );
        Ok(Self {
            store,
            key,
            servers: servers.to_vec(),
        })
    }
}

impl Drop for MacosSystemDns {
    fn drop(&mut self) {
        // SAFETY: `self.store` and `self.key` remain live until fields drop
        // after `Drop::drop` returns.
        let removed = unsafe { SCDynamicStoreRemoveValue(self.store.as_ptr(), self.key.as_ptr()) };
        if removed != 0 {
            tracing::info!(
                key = DNS_STATE_KEY,
                "macOS session DNS removed from SCDynamicStore"
            );
        } else {
            let error = sc_last_error("SCDynamicStoreRemoveValue failed");
            tracing::debug!(
                key = DNS_STATE_KEY,
                %error,
                "macOS session DNS key removal returned false (session handle release will clean up)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn tunnel_dns_servers_appends_next_ipv6_when_configured() {
        let v4 = IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2));
        assert_eq!(tunnel_dns_servers(v4, None), vec![v4]);
        assert_eq!(
            tunnel_dns_servers(v4, Some("fdfe:dcba:9876::1/126")),
            vec![v4, "fdfe:dcba:9876::2".parse().unwrap()]
        );
        assert_eq!(
            tunnel_dns_servers(v4, Some("fdfe:dcba:9876::1/128")),
            vec![v4]
        );
        assert_eq!(
            tunnel_dns_servers(v4, Some("fdfe:dcba:9876::3/126")),
            vec![v4]
        );
    }

    #[test]
    fn opens_session_dynamic_store_and_builds_dns_dictionary() {
        let store = open_session_store().expect("open SCDynamicStore session");
        assert!(!store.as_ptr().is_null());
        let servers = tunnel_dns_servers(
            IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)),
            Some("fdfe:dcba:9876::1/126"),
        );
        let dict = build_dns_dictionary(&servers).expect("build DNS dictionary");
        assert!(!dict.as_ptr().is_null());
    }
}
