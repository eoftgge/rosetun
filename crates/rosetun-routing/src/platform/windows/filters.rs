use std::net::IpAddr;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::{path::Path, ptr};

use super::{
    lockdown,
    policy::{Action, AddressFamily, Condition, Layer, Rule},
    session::{Engine, PROVIDER_KEY, SUBLAYER_KEY},
};
use crate::RoutingError;
use crate::platform::windows::policy::Subnet;
use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTRL_MATCH_FILTER, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE,
    FWP_MATCH_RANGE, FWP_RANGE_TYPE, FWP_RANGE0, FWP_SECURITY_DESCRIPTOR_TYPE,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0, FwpmFilterAdd0, FwpmFilterDeleteById0,
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::{
    Win32::NetworkManagement::{
        Ndis::NET_LUID_LH,
        WindowsFilteringPlatform::{
            FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK,
            FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET,
            FWP_UINT8, FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0,
            FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_LOCAL_PORT,
            FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER_CONDITION0,
            FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        },
    },
    Win32::Networking::WinSock::IPPROTO_UDP,
    core::GUID,
};

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

/// Where a filter goes and what it is called.
#[derive(Clone, Copy)]
pub(super) struct Placement {
    pub(super) provider: GUID,
    pub(super) sublayer: GUID,
    /// A fixed key for persistent filters; `None` lets BFE choose one.
    pub(super) key: Option<GUID>,
    pub(super) flags: u32,
    pub(super) name: &'static str,
}

impl Placement {
    /// A filter of the dynamic protection session.
    pub(super) fn session(lockdown: bool) -> Self {
        Self {
            provider: PROVIDER_KEY,
            sublayer: if lockdown {
                lockdown::SUBLAYER_KEY
            } else {
                SUBLAYER_KEY
            },
            key: None,
            flags: 0,
            name: "Rosetun routing filter",
        }
    }
}

pub(super) struct AppIdBlob(*mut FWP_BYTE_BLOB);

impl AppIdBlob {
    pub(super) fn from_path(path: &Path) -> Result<Self, RoutingError> {
        let path = wide_path(path)?;
        let mut blob = ptr::null_mut();

        let status = unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob) };
        if status != 0 {
            return Err(RoutingError::Wfp {
                code: status,
                context: "getting the WFP application ID of a program",
            });
        }

        Ok(Self(blob))
    }

    fn as_ptr(&self) -> *mut FWP_BYTE_BLOB {
        self.0
    }
}

/// The bytes of a blob BFE returned.
///
/// # Safety
/// `blob.data` must point to `blob.size` readable bytes for the returned lifetime.
pub(super) unsafe fn blob_bytes(blob: &FWP_BYTE_BLOB) -> &[u8] {
    if blob.data.is_null() || blob.size == 0 {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) }
}

impl Drop for AppIdBlob {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FwpmFreeMemory0((&raw mut self.0).cast());
            }
        }
    }
}

/// The value of an `ALE_USER_ID` condition: a self-relative security
/// descriptor whose DACL grants `FWP_ACTRL_MATCH_FILTER` to the user of this
/// process, so the filter matches only processes running as that user. The
/// way wireguard-windows limits its own permits (`tunnel/firewall`).
pub(super) struct AccountDescriptor {
    /// Allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`
    /// with `LocalAlloc`; freed once in `Drop`.
    descriptor: PSECURITY_DESCRIPTOR,
    /// Points into `descriptor`; boxed so a condition can point to it.
    blob: Box<FWP_BYTE_BLOB>,
}

impl AccountDescriptor {
    pub(super) fn current() -> Result<Self, RoutingError> {
        let sid = current_user_sid()?;
        let sddl = format!("O:SYG:SYD:(A;;{FWP_ACTRL_MATCH_FILTER:#x};;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor = ptr::null_mut();
        let mut size = 0;
        // SAFETY: `sddl` is NUL-terminated and outlives the synchronous call;
        // on success the descriptor is ours to free with LocalFree.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                &mut size,
            )
        };
        if converted == 0 || descriptor.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let blob = Box::new(FWP_BYTE_BLOB {
            size,
            data: descriptor.cast(),
        });
        Ok(Self { descriptor, blob })
    }

    fn as_ptr(&self) -> *mut FWP_BYTE_BLOB {
        (&raw const *self.blob).cast_mut()
    }
}

impl Drop for AccountDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by the system with LocalAlloc in `current` and
        // freed only here; no condition that points to it outlives `self`.
        unsafe { LocalFree(self.descriptor) };
    }
}

/// The SID of this process's user as a string (`S-1-5-18` for SYSTEM).
fn current_user_sid() -> Result<String, RoutingError> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the pseudo handle of the current process needs no closing; the
    // token handle is owned by `OwnedHandle` below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: OpenProcessToken returned a live handle that nothing else owns.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

    let mut length = 0;
    // SAFETY: a null buffer and zero length ask for the TokenUser size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut length,
        )
    };
    if (length as usize) < size_of::<TOKEN_USER>() {
        return Err(std::io::Error::last_os_error().into());
    }
    // usize gives TOKEN_USER and the SID it points to pointer alignment.
    let mut user = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    // SAFETY: the aligned buffer holds `length` bytes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            user.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: GetTokenInformation wrote a TOKEN_USER whose SID points into
    // `user`, which lives until the end of this function.
    let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut text = ptr::null_mut();
    // SAFETY: `sid` is valid as above; on success the string is ours to free
    // with LocalFree.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `text` is a NUL-terminated UTF-16 string from the call above,
    // copied out before it is freed once.
    let sid = unsafe {
        let length = (0..).take_while(|&index| *text.add(index) != 0).count();
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, length));
        LocalFree(text.cast());
        sid
    };
    Ok(sid)
}

/// A rule's WFP conditions together with the values they point to. Built
/// without a WFP engine, so tests can check that every rule has a shape.
pub(super) struct FilterConditions {
    conditions: Vec<FWPM_FILTER_CONDITION0>,
    // The conditions hold raw pointers into these; boxed so they never move.
    // They live until `FwpmFilterAdd0` returns, which copies the values.
    _app_id: Option<AppIdBlob>,
    _account: Option<AccountDescriptor>,
    _luids: Vec<NET_LUID_LH>,
    _v4: Box<FWP_V4_ADDR_AND_MASK>,
    _v6: Box<FWP_V6_ADDR_AND_MASK>,
    _ranges: RangeValues,
}

/// The values of remote-address range conditions. Both lists are filled once
/// in `new` and never grow; the ranges point into `bounds`, conditions into
/// `ranges`, and moving a `Vec` leaves its heap buffer in place.
struct RangeValues {
    _bounds: Vec<[FWP_BYTE_ARRAY16; 2]>,
    ranges: Vec<FWP_RANGE0>,
}

impl RangeValues {
    fn new(family: AddressFamily, conditions: &[Condition]) -> Result<Self, RoutingError> {
        let wanted: Vec<_> = conditions
            .iter()
            .filter_map(|condition| match condition {
                Condition::RemoteRange(range) => Some(*range),
                _ => None,
            })
            .collect();
        let mut bounds = vec![[FWP_BYTE_ARRAY16::default(); 2]; wanted.len()];
        let mut ranges = Vec::with_capacity(wanted.len());
        for (range, bound) in wanted.iter().zip(&mut bounds) {
            let [low, high] = bound;
            ranges.push(match (family, range.low, range.high) {
                (AddressFamily::Ipv4, IpAddr::V4(first), IpAddr::V4(last)) if first <= last => {
                    FWP_RANGE0 {
                        valueLow: v4_value(first.to_bits()),
                        valueHigh: v4_value(last.to_bits()),
                    }
                }
                (AddressFamily::Ipv6, IpAddr::V6(first), IpAddr::V6(last)) if first <= last => {
                    low.byteArray16 = first.octets();
                    high.byteArray16 = last.octets();
                    FWP_RANGE0 {
                        valueLow: v6_value(low),
                        valueHigh: v6_value(high),
                    }
                }
                _ => return Err(RoutingError::Unsupported),
            });
        }
        Ok(Self {
            _bounds: bounds,
            ranges,
        })
    }

    fn conditions(&mut self) -> impl Iterator<Item = FWPM_FILTER_CONDITION0> {
        self.ranges.iter_mut().map(|range| FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_RANGE,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_RANGE_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { rangeValue: range },
            },
        })
    }
}

/// WFP IPv4 values use host-order integers.
fn v4_value(address: u32) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT32,
        Anonymous: FWP_VALUE0_0 { uint32: address },
    }
}

fn v6_value(address: &mut FWP_BYTE_ARRAY16) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_BYTE_ARRAY16_TYPE,
        Anonymous: FWP_VALUE0_0 {
            byteArray16: address,
        },
    }
}

impl FilterConditions {
    pub(super) fn build(rule: &Rule) -> Result<Self, RoutingError> {
        // Filled before any condition points into it and never grown after.
        let mut luids: Vec<NET_LUID_LH> = rule
            .conditions
            .iter()
            .filter_map(|condition| match condition {
                Condition::LocalInterface(value) => Some(NET_LUID_LH { Value: *value }),
                _ => None,
            })
            .collect();
        let mut app_id = None;
        let mut account = None;
        let mut v4 = Box::new(FWP_V4_ADDR_AND_MASK::default());
        let mut v6 = Box::new(FWP_V6_ADDR_AND_MASK::default());
        let mut conditions = Vec::with_capacity(3);
        let mut ranges = RangeValues::new(rule.family, &rule.conditions)?;
        let range_count = rule
            .conditions
            .iter()
            .take_while(|condition| matches!(condition, Condition::RemoteRange(_)))
            .count();

        match &rule.conditions[range_count..] {
            // A shared local proxy: one connected network, or the ranges of
            // it around the VPN servers, on its adapter, for the engine.
            [
                subnet @ ..,
                Condition::Application(binary),
                Condition::ServiceAccount,
                Condition::Protocol(protocol),
                Condition::LocalPort(port),
                Condition::LocalInterface(_),
            ] if matches!(
                (range_count, subnet),
                (1.., []) | (0, [Condition::RemoteSubnet(_)])
            ) =>
            {
                conditions.extend(ranges.conditions());
                if let [Condition::RemoteSubnet(subnet)] = subnet {
                    conditions.push(subnet_condition(rule.family, *subnet, &mut v4, &mut v6)?);
                }
                let blob = app_id.insert(AppIdBlob::from_path(binary)?);
                let descriptor = account.insert(AccountDescriptor::current()?);
                conditions.extend([
                    application_condition(blob),
                    account_condition(descriptor),
                    protocol_condition(*protocol),
                    port_condition(FWPM_CONDITION_IP_LOCAL_PORT, *port),
                    interface_condition(&mut luids[0]),
                ]);
            }
            // A private range around the VPN servers in it, on any adapter.
            [] if range_count > 0 => conditions.extend(ranges.conditions()),
            // A connected network around the VPN servers in it, on its
            // adapter, and the DNS block of the same addresses.
            interfaces
                if range_count > 0
                    && !interfaces.is_empty()
                    && interfaces
                        .iter()
                        .all(|condition| matches!(condition, Condition::LocalInterface(_))) =>
            {
                conditions.extend(ranges.conditions());
                conditions.extend(luids.iter_mut().map(interface_condition));
            }
            [Condition::Protocol(protocol), Condition::RemotePort(port)] if range_count > 0 => {
                conditions.extend(ranges.conditions());
                conditions.extend([
                    protocol_condition(*protocol),
                    port_condition(FWPM_CONDITION_IP_REMOTE_PORT, *port),
                ]);
            }
            _ if range_count > 0 => return Err(RoutingError::Unsupported),
            [] => {}
            [Condition::Application(engine_binary)] => {
                let blob = app_id.insert(AppIdBlob::from_path(engine_binary)?);
                conditions.push(application_condition(blob));
            }
            // An engine permit and a server check's permit.
            [Condition::Application(binary), Condition::ServiceAccount] => {
                let blob = app_id.insert(AppIdBlob::from_path(binary)?);
                let descriptor = account.insert(AccountDescriptor::current()?);
                conditions.extend([application_condition(blob), account_condition(descriptor)]);
            }
            [Condition::LocalInterface(_)] => {
                conditions.push(interface_condition(&mut luids[0]));
            }
            // "Local network": a network on the adapters it belongs to.
            [Condition::RemoteSubnet(subnet), interfaces @ ..]
                if !interfaces.is_empty()
                    && interfaces
                        .iter()
                        .all(|condition| matches!(condition, Condition::LocalInterface(_))) =>
            {
                conditions.push(subnet_condition(rule.family, *subnet, &mut v4, &mut v6)?);
                conditions.extend(luids.iter_mut().map(interface_condition));
            }
            [Condition::Loopback] => {
                conditions.push(loopback_condition());
            }
            [Condition::DhcpV4] if rule.family == AddressFamily::Ipv4 => {
                conditions.extend([
                    protocol_condition(IPPROTO_UDP as u8),
                    port_condition(FWPM_CONDITION_IP_LOCAL_PORT, DHCP_CLIENT_PORT),
                    port_condition(FWPM_CONDITION_IP_REMOTE_PORT, DHCP_SERVER_PORT),
                ]);
            }
            [Condition::RemoteSubnet(subnet)] => {
                conditions.push(subnet_condition(rule.family, *subnet, &mut v4, &mut v6)?);
            }
            [Condition::Protocol(protocol), Condition::RemotePort(port)] => {
                conditions.extend([
                    protocol_condition(*protocol),
                    port_condition(FWPM_CONDITION_IP_REMOTE_PORT, *port),
                ]);
            }
            // A shared local proxy: everyone but its networks and loopback.
            [Condition::Protocol(protocol), Condition::LocalPort(port)] => {
                conditions.extend([
                    protocol_condition(*protocol),
                    port_condition(FWPM_CONDITION_IP_LOCAL_PORT, *port),
                ]);
            }
            [
                Condition::Protocol(protocol),
                Condition::LocalPort(port),
                Condition::Loopback,
            ] => {
                conditions.extend([
                    protocol_condition(*protocol),
                    port_condition(FWPM_CONDITION_IP_LOCAL_PORT, *port),
                    loopback_condition(),
                ]);
            }
            // Lockdown's TCP permits for Rosetun's own programs.
            [
                Condition::Application(binary),
                Condition::Protocol(protocol),
            ] => {
                let blob = app_id.insert(AppIdBlob::from_path(binary)?);
                conditions.extend([application_condition(blob), protocol_condition(*protocol)]);
            }
            // Lockdown's DNS permits for Rosetun's own programs.
            [
                Condition::Application(binary),
                Condition::Protocol(protocol),
                Condition::RemotePort(port),
            ] => {
                let blob = app_id.insert(AppIdBlob::from_path(binary)?);
                conditions.extend([
                    application_condition(blob),
                    protocol_condition(*protocol),
                    port_condition(FWPM_CONDITION_IP_REMOTE_PORT, *port),
                ]);
            }
            // Lockdown's DNS permit for the service.
            [
                Condition::Application(binary),
                Condition::ServiceAccount,
                Condition::Protocol(protocol),
                Condition::RemotePort(port),
            ] => {
                let blob = app_id.insert(AppIdBlob::from_path(binary)?);
                let descriptor = account.insert(AccountDescriptor::current()?);
                conditions.extend([
                    application_condition(blob),
                    account_condition(descriptor),
                    protocol_condition(*protocol),
                    port_condition(FWPM_CONDITION_IP_REMOTE_PORT, *port),
                ]);
            }
            [
                Condition::RemoteSubnet(subnet),
                Condition::Protocol(protocol),
                Condition::RemotePort(port),
            ] => {
                conditions.extend([
                    subnet_condition(rule.family, *subnet, &mut v4, &mut v6)?,
                    protocol_condition(*protocol),
                    port_condition(FWPM_CONDITION_IP_REMOTE_PORT, *port),
                ]);
            }
            // A new combination of conditions needs a branch here and a case
            // in `tests::every_policy_rule_builds`, or the whole transaction
            // that adds it fails.
            _ => return Err(RoutingError::Unsupported),
        }

        Ok(Self {
            conditions,
            _app_id: app_id,
            _account: account,
            _luids: luids,
            _v4: v4,
            _v6: v6,
            _ranges: ranges,
        })
    }
}

impl FilterConditions {
    /// Whether a stored filter has exactly these conditions, in any order.
    ///
    /// # Safety
    /// Every pointer in `stored` must be valid, as BFE returns them from
    /// `FwpmFilterGetByKey0`, for the duration of the call.
    pub(super) unsafe fn same_as(&self, stored: &[FWPM_FILTER_CONDITION0]) -> bool {
        if stored.len() != self.conditions.len() {
            return false;
        }
        let mut used = vec![false; stored.len()];
        self.conditions.iter().all(|wanted| {
            let found = stored.iter().enumerate().position(|(index, condition)| {
                // SAFETY: the caller vouches for `stored`; `wanted` points
                // into values `self` owns.
                !used[index] && unsafe { same_condition(wanted, condition) }
            });
            found.map(|index| used[index] = true).is_some()
        })
    }
}

/// # Safety
/// The values both conditions point to must be valid.
unsafe fn same_condition(a: &FWPM_FILTER_CONDITION0, b: &FWPM_FILTER_CONDITION0) -> bool {
    let kind = a.conditionValue.r#type;
    if !same_guid(&a.fieldKey, &b.fieldKey)
        || a.matchType != b.matchType
        || kind != b.conditionValue.r#type
    {
        return false;
    }
    let (a, b) = (a.conditionValue.Anonymous, b.conditionValue.Anonymous);
    let blobs = |a: *mut FWP_BYTE_BLOB, b: *mut FWP_BYTE_BLOB| {
        // SAFETY: non-null blobs are valid by the caller's contract.
        !a.is_null() && !b.is_null() && unsafe { blob_bytes(&*a) == blob_bytes(&*b) }
    };
    // SAFETY: the type tag says which union field is set; pointers are valid
    // by the caller's contract and null ones are never dereferenced.
    unsafe {
        match kind {
            FWP_UINT8 => a.uint8 == b.uint8,
            FWP_UINT16 => a.uint16 == b.uint16,
            FWP_UINT32 => a.uint32 == b.uint32,
            FWP_UINT64 => !a.uint64.is_null() && !b.uint64.is_null() && *a.uint64 == *b.uint64,
            FWP_BYTE_BLOB_TYPE => blobs(a.byteBlob, b.byteBlob),
            FWP_SECURITY_DESCRIPTOR_TYPE => blobs(a.sd, b.sd),
            FWP_V4_ADDR_MASK => {
                let (a, b) = (a.v4AddrMask, b.v4AddrMask);
                !a.is_null() && !b.is_null() && (*a).addr == (*b).addr && (*a).mask == (*b).mask
            }
            FWP_V6_ADDR_MASK => {
                let (a, b) = (a.v6AddrMask, b.v6AddrMask);
                !a.is_null()
                    && !b.is_null()
                    && (*a).addr == (*b).addr
                    && (*a).prefixLength == (*b).prefixLength
            }
            FWP_RANGE_TYPE => {
                let (a, b) = (a.rangeValue, b.rangeValue);
                !a.is_null()
                    && !b.is_null()
                    && same_value(&(*a).valueLow, &(*b).valueLow)
                    && same_value(&(*a).valueHigh, &(*b).valueHigh)
            }
            _ => false,
        }
    }
}

/// The bound of a range: what `RangeValues` writes, anything else differs.
///
/// # Safety
/// The values both point to must be valid.
unsafe fn same_value(a: &FWP_VALUE0, b: &FWP_VALUE0) -> bool {
    if a.r#type != b.r#type {
        return false;
    }
    // SAFETY: the type tag says which union field is set; pointers are valid
    // by the caller's contract and null ones are never dereferenced.
    unsafe {
        match a.r#type {
            FWP_UINT32 => a.Anonymous.uint32 == b.Anonymous.uint32,
            FWP_BYTE_ARRAY16_TYPE => {
                let (a, b) = (a.Anonymous.byteArray16, b.Anonymous.byteArray16);
                !a.is_null() && !b.is_null() && (*a).byteArray16 == (*b).byteArray16
            }
            _ => false,
        }
    }
}

/// `GUID` has no `PartialEq` in windows-sys.
fn same_guid(a: &GUID, b: &GUID) -> bool {
    (a.data1, a.data2, a.data3, a.data4) == (b.data1, b.data2, b.data3, b.data4)
}

pub(super) fn add_rule(
    session: &Engine,
    rule: &Rule,
    placement: &Placement,
) -> Result<u64, RoutingError> {
    let mut conditions = FilterConditions::build(rule)?;

    let mut display_name = placement
        .name
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();

    let filter = FWPM_FILTER0 {
        displayData: FWPM_DISPLAY_DATA0 {
            name: display_name.as_mut_ptr(),
            description: ptr::null_mut(),
        },
        filterKey: placement.key.unwrap_or_default(),
        flags: if rule.hard {
            placement.flags | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
        } else {
            placement.flags
        },
        providerKey: (&placement.provider as *const GUID).cast_mut(),
        layerKey: layer_key(rule.family, rule.layer),
        subLayerKey: placement.sublayer,
        action: action(rule.action),
        weight: weight(rule.weight),
        numFilterConditions: conditions.conditions.len() as u32,
        filterCondition: conditions.conditions.as_mut_ptr(),
        ..Default::default()
    };

    tracing::debug!(
        family = ?rule.family,
        layer = ?rule.layer,
        action = ?rule.action,
        conditions = ?rule.conditions,
        "adding Rosetun WFP filter"
    );

    let mut id = 0;
    let status = unsafe { FwpmFilterAdd0(session.handle(), &filter, ptr::null_mut(), &mut id) };
    if status != 0 {
        return Err(RoutingError::Wfp {
            code: status,
            context: "adding a Rosetun WFP filter",
        });
    }

    Ok(id)
}

pub(super) fn delete_rule(session: &Engine, id: u64) -> Result<(), RoutingError> {
    let status = unsafe { FwpmFilterDeleteById0(session.handle(), id) };
    if status != 0 {
        return Err(RoutingError::Wfp {
            code: status,
            context: "deleting a Rosetun WFP filter",
        });
    }
    Ok(())
}

fn subnet_condition(
    family: AddressFamily,
    subnet: Subnet,
    v4: &mut FWP_V4_ADDR_AND_MASK,
    v6: &mut FWP_V6_ADDR_AND_MASK,
) -> Result<FWPM_FILTER_CONDITION0, RoutingError> {
    if family != subnet.family() {
        return Err(RoutingError::Unsupported);
    }

    let condition_value = match subnet {
        Subnet::V4 { address, prefix } if prefix <= 32 => {
            // WFP IPv4 values use host-order integers.
            v4.addr = u32::from_be_bytes(address);
            v4.mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: v4 },
            }
        }
        Subnet::V6 { address, prefix } if prefix <= 128 => {
            // IPv6 uses raw network-order octets.
            v6.addr = address;
            v6.prefixLength = prefix;
            FWP_CONDITION_VALUE0 {
                r#type: FWP_V6_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: v6 },
            }
        }
        _ => return Err(RoutingError::Unsupported),
    };

    Ok(FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: condition_value,
    })
}

fn application_condition(app_id: &AppIdBlob) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_APP_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                byteBlob: app_id.as_ptr(),
            },
        },
    }
}

fn account_condition(descriptor: &AccountDescriptor) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_USER_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                sd: descriptor.as_ptr(),
            },
        },
    }
}

fn layer_key(family: AddressFamily, layer: Layer) -> GUID {
    match (layer, family) {
        (Layer::Connect, AddressFamily::Ipv4) => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        (Layer::Connect, AddressFamily::Ipv6) => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        (Layer::RecvAccept, AddressFamily::Ipv4) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        (Layer::RecvAccept, AddressFamily::Ipv6) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

fn action(action: Action) -> FWPM_ACTION0 {
    FWPM_ACTION0 {
        r#type: match action {
            Action::Allow => FWP_ACTION_PERMIT,
            Action::Block => FWP_ACTION_BLOCK,
        },
        ..Default::default()
    }
}

fn weight(value: u8) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT8,
        Anonymous: FWP_VALUE0_0 { uint8: value },
    }
}

fn loopback_condition() -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_FLAGS,
        matchType: FWP_MATCH_FLAGS_ALL_SET,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
            },
        },
    }
}

fn protocol_condition(protocol: u8) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_PROTOCOL,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint8: protocol },
        },
    }
}

fn port_condition(field_key: GUID, port: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
        },
    }
}

fn interface_condition(luid: &mut NET_LUID_LH) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                uint64: unsafe { &mut luid.Value },
            },
        },
    }
}

fn wide_path(path: &Path) -> Result<Vec<u16>, RoutingError> {
    let path = path.to_str().ok_or_else(|| RoutingError::Tun {
        name: path.display().to_string(),
        reason: "the executable path is not valid UTF-8".to_owned(),
    })?;

    Ok(path.encode_utf16().chain(Some(0)).collect())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWP_BYTE_ARRAY16_TYPE, FWP_MATCH_EQUAL, FWP_MATCH_RANGE, FWP_RANGE_TYPE,
        FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT32, FWPM_CONDITION_ALE_USER_ID,
        FWPM_CONDITION_IP_REMOTE_ADDRESS,
    };

    use super::{FilterConditions, blob_bytes, same_guid};
    use crate::platform::windows::lockdown;
    use crate::platform::windows::policy::{
        AddressFamily, AddressRange, BOOTSTRAP_ALLOW_WEIGHT, BootstrapPolicy, Condition, Rule,
        engine_permit, lan_rules, probe_authorization, tunnel_authorization,
    };
    use crate::{ProtectionScope, RoutingError, RoutingPlan};

    /// Every rule a policy can hand to `add_rule`, with program paths that
    /// exist, since a WFP application ID needs the file.
    /// Networks of both families, link-local on two adapters, IPv6
    /// multicast and the private ranges: every shape a LAN rule takes.
    fn every_lan_shape() -> crate::lan::LanAccess {
        use crate::lan::{InterfaceId, LanAccess, LanSegment, SegmentNetwork};
        let network = |address: &str, length, interface| SegmentNetwork {
            prefix: rosetun_config::IpPrefix::new(address.parse().unwrap(), length).unwrap(),
            interface: InterfaceId(interface),
        };
        LanAccess {
            segment: LanSegment::from_parts(
                vec![network("192.0.2.0", 24, 7), network("2001:db8:1::", 64, 8)],
                vec![InterfaceId(7), InterfaceId(8)],
            ),
            private_networks: true,
            ipv6_multicast: true,
            servers: Vec::new(),
        }
    }

    /// One address in each network of `every_lan_shape`.
    fn server_addresses() -> [IpAddr; 2] {
        [
            "192.0.2.10".parse().unwrap(),
            "2001:db8:1::5".parse().unwrap(),
        ]
    }

    fn range_rules(servers: &[IpAddr]) -> Vec<Rule> {
        let mut lan = every_lan_shape();
        lan.segment = lan.segment.leaving_out(servers);
        lan_rules(&lan)
            .into_iter()
            .map(|(_, rule)| rule)
            .filter(|rule| {
                rule.conditions
                    .iter()
                    .any(|condition| matches!(condition, Condition::RemoteRange(_)))
            })
            .collect()
    }

    #[test]
    fn a_range_becomes_a_range_condition_on_the_remote_address() {
        let rules = range_rules(&server_addresses());
        // Permit and two DNS blocks, for each of the two networks.
        assert_eq!(rules.len(), 6);
        for rule in &rules {
            let built = FilterConditions::build(rule).unwrap();
            let ranges: Vec<_> = built
                .conditions
                .iter()
                .filter(|condition| condition.matchType == FWP_MATCH_RANGE)
                .collect();
            assert_eq!(ranges.len(), 2, "{rule:?}");
            for condition in ranges {
                assert!(same_guid(
                    &condition.fieldKey,
                    &FWPM_CONDITION_IP_REMOTE_ADDRESS
                ));
                assert_eq!(condition.conditionValue.r#type, FWP_RANGE_TYPE);
                // SAFETY: the range and its bounds are owned by `built`, alive here.
                let range = unsafe { &*condition.conditionValue.Anonymous.rangeValue };
                assert_eq!(range.valueLow.r#type, range.valueHigh.r#type);
                match rule.family {
                    AddressFamily::Ipv4 => {
                        assert_eq!(range.valueLow.r#type, FWP_UINT32);
                        // SAFETY: the type tag above says this field is set.
                        let (low, high) = unsafe {
                            (
                                range.valueLow.Anonymous.uint32,
                                range.valueHigh.Anonymous.uint32,
                            )
                        };
                        assert!(low <= high);
                        // Host order: 192.0.2.x, not x.2.0.192.
                        assert_eq!(low >> 24, 192);
                    }
                    AddressFamily::Ipv6 => {
                        assert_eq!(range.valueLow.r#type, FWP_BYTE_ARRAY16_TYPE);
                        // SAFETY: as above; the pointer goes into `built`.
                        let low = unsafe { (*range.valueLow.Anonymous.byteArray16).byteArray16 };
                        assert_eq!(low[..6], [0x20, 0x01, 0x0d, 0xb8, 0, 1]);
                    }
                }
            }
        }
    }

    #[test]
    fn a_stored_filter_around_another_server_is_stale() {
        let other: [IpAddr; 2] = [
            "192.0.2.11".parse().unwrap(),
            "2001:db8:1::6".parse().unwrap(),
        ];
        let wanted = range_rules(&server_addresses());
        let moved = range_rules(&other);
        assert_eq!(wanted.len(), moved.len());
        for (wanted, moved) in wanted.iter().zip(&moved) {
            let built = FilterConditions::build(wanted).unwrap();
            let again = FilterConditions::build(wanted).unwrap();
            let moved = FilterConditions::build(moved).unwrap();
            // SAFETY: every condition points into values its builder owns, alive here.
            unsafe {
                assert!(built.same_as(&again.conditions));
                assert!(!built.same_as(&moved.conditions));
            }
        }
    }

    #[test]
    fn a_range_that_does_not_fit_its_rule_is_refused() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let later: IpAddr = "192.0.2.9".parse().unwrap();
        let rule = |low, high, rest: &[Condition]| {
            let mut conditions = vec![Condition::RemoteRange(AddressRange { low, high })];
            conditions.extend_from_slice(rest);
            Rule::allow(AddressFamily::Ipv4, conditions, BOOTSTRAP_ALLOW_WEIGHT)
        };
        let interface = [Condition::LocalInterface(7)];
        assert!(FilterConditions::build(&rule(v4, later, &interface)).is_ok());
        assert!(FilterConditions::build(&rule(v4, later, &[])).is_ok());
        for wrong in [
            rule(later, v4, &interface),
            rule(v4, v6, &interface),
            rule(v6, v6, &interface),
            // A protocol alone is not a shape any rule has.
            rule(v4, later, &[Condition::Protocol(6)]),
        ] {
            assert!(matches!(
                FilterConditions::build(&wrong),
                Err(RoutingError::Unsupported)
            ));
        }
    }

    fn every_policy_rule() -> Vec<Rule> {
        let program = std::env::current_exe().expect("the test binary has a path");
        let mut rules = lockdown::every_filter()
            .into_iter()
            .map(|filter| filter.rule)
            .collect::<Vec<_>>();
        for scope in [
            ProtectionScope::AllTraffic,
            ProtectionScope::DnsOnly,
            ProtectionScope::SharedProxy,
        ] {
            for allow_lan in [false, true] {
                for lockdown in [false, true] {
                    let plan = RoutingPlan {
                        scope,
                        allow_lan,
                        lan: every_lan_shape(),
                        lockdown,
                        shared_proxy: Some(10808),
                    };
                    rules.extend(BootstrapPolicy::from_plan(&plan, &[&program, &program]).rules);
                    let mut around_servers = plan.clone();
                    around_servers.lan.segment =
                        around_servers.lan.segment.leaving_out(&server_addresses());
                    around_servers.lan.servers = vec![
                        "192.168.3.1".parse().unwrap(),
                        "fd00::5".parse().unwrap(),
                        "169.254.3.4".parse().unwrap(),
                        "fe80::5".parse().unwrap(),
                    ];
                    rules.extend(
                        BootstrapPolicy::from_plan(&around_servers, &[&program, &program]).rules,
                    );
                }
            }
        }
        for lockdown in [false, true] {
            rules.extend(tunnel_authorization(7, lockdown));
        }
        rules.extend(probe_authorization(&program));
        for rule in &mut rules {
            for condition in &mut rule.conditions {
                if let Condition::Application(path) = condition {
                    path.clone_from(&program);
                }
            }
        }
        rules
    }

    #[test]
    fn every_policy_rule_builds() {
        let rules = every_policy_rule();
        assert!(rules.len() > 100);
        for rule in &rules {
            let built = FilterConditions::build(rule)
                .unwrap_or_else(|error| panic!("{rule:?} does not build: {error}"));
            // DHCP is one condition in the policy and three in WFP.
            let expected = match rule.conditions.as_slice() {
                [Condition::DhcpV4] => 3,
                conditions => conditions.len(),
            };
            assert_eq!(built.conditions.len(), expected, "{rule:?}");
        }
    }

    fn engine_rule(conditions: Vec<Condition>) -> Rule {
        Rule::allow(AddressFamily::Ipv4, conditions, BOOTSTRAP_ALLOW_WEIGHT)
    }

    #[test]
    fn the_service_account_becomes_an_ale_user_id_descriptor() {
        let program = std::env::current_exe().expect("the test binary has a path");
        let built = FilterConditions::build(&engine_rule(engine_permit(&program))).unwrap();
        let account = built
            .conditions
            .iter()
            .find(|condition| same_guid(&condition.fieldKey, &FWPM_CONDITION_ALE_USER_ID))
            .expect("an ALE_USER_ID condition");
        assert_eq!(account.matchType, FWP_MATCH_EQUAL);
        assert_eq!(account.conditionValue.r#type, FWP_SECURITY_DESCRIPTOR_TYPE);
        // SAFETY: the descriptor is owned by `built`, alive here.
        let descriptor = unsafe { blob_bytes(&*account.conditionValue.Anonymous.sd) };
        // A self-relative descriptor starts with revision 1 and the
        // SE_SELF_RELATIVE control bit.
        assert!(descriptor.len() > 20);
        assert_eq!(descriptor[0], 1);
        assert_ne!(
            u16::from_le_bytes([descriptor[2], descriptor[3]]) & 0x8000,
            0
        );
    }

    #[test]
    fn a_stored_permit_without_the_service_account_is_stale() {
        let program = std::env::current_exe().expect("the test binary has a path");
        let wanted = FilterConditions::build(&engine_rule(engine_permit(&program))).unwrap();
        let again = FilterConditions::build(&engine_rule(engine_permit(&program))).unwrap();
        let older =
            FilterConditions::build(&engine_rule(vec![Condition::Application(program.clone())]))
                .unwrap();
        let mut reversed = again.conditions.clone();
        reversed.reverse();
        // SAFETY: every condition points into values its builder owns, alive here.
        unsafe {
            assert!(wanted.same_as(&again.conditions));
            assert!(wanted.same_as(&reversed));
            assert!(!wanted.same_as(&older.conditions));
            assert!(!older.same_as(&wanted.conditions));
        }
    }
}
