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
    FWP_ACTION_BLOCK, FWP_ACTRL_MATCH_FILTER, FWP_SECURITY_DESCRIPTOR_TYPE, FWP_V4_ADDR_AND_MASK,
    FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWPM_CONDITION_ALE_APP_ID,
    FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_DISPLAY_DATA0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0,
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
            FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
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
    _luid: Box<NET_LUID_LH>,
    _v4: Box<FWP_V4_ADDR_AND_MASK>,
    _v6: Box<FWP_V6_ADDR_AND_MASK>,
}

impl FilterConditions {
    pub(super) fn build(rule: &Rule) -> Result<Self, RoutingError> {
        let mut luid = Box::new(NET_LUID_LH::default());
        let mut app_id = None;
        let mut account = None;
        let mut v4 = Box::new(FWP_V4_ADDR_AND_MASK::default());
        let mut v6 = Box::new(FWP_V6_ADDR_AND_MASK::default());
        let mut conditions = Vec::with_capacity(3);

        match rule.conditions.as_slice() {
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
            [Condition::LocalInterface(value)] => {
                luid.Value = *value;
                conditions.push(interface_condition(&mut luid));
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
            _luid: luid,
            _v4: v4,
            _v6: v6,
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
        flags: placement.flags,
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
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWP_MATCH_EQUAL, FWP_SECURITY_DESCRIPTOR_TYPE, FWPM_CONDITION_ALE_USER_ID,
    };

    use super::{FilterConditions, blob_bytes, same_guid};
    use crate::platform::windows::lockdown;
    use crate::platform::windows::policy::{
        AddressFamily, BOOTSTRAP_ALLOW_WEIGHT, BootstrapPolicy, Condition, Rule, engine_permit,
        probe_authorization, tunnel_authorization,
    };
    use crate::{ProtectionScope, RoutingPlan};

    /// Every rule a policy can hand to `add_rule`, with program paths that
    /// exist, since a WFP application ID needs the file.
    fn every_policy_rule() -> Vec<Rule> {
        let program = std::env::current_exe().expect("the test binary has a path");
        let mut rules = lockdown::every_filter()
            .into_iter()
            .map(|filter| filter.rule)
            .collect::<Vec<_>>();
        for scope in [ProtectionScope::AllTraffic, ProtectionScope::DnsOnly] {
            for allow_lan in [false, true] {
                for lockdown in [false, true] {
                    let plan = RoutingPlan {
                        scope,
                        allow_lan,
                        lockdown,
                    };
                    rules.extend(BootstrapPolicy::from_plan(&plan, &[&program, &program]).rules);
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
        assert_ne!(u16::from_le_bytes([descriptor[2], descriptor[3]]) & 0x8000, 0);
    }

    #[test]
    fn a_stored_permit_without_the_service_account_is_stale() {
        let program = std::env::current_exe().expect("the test binary has a path");
        let wanted = FilterConditions::build(&engine_rule(engine_permit(&program))).unwrap();
        let again = FilterConditions::build(&engine_rule(engine_permit(&program))).unwrap();
        let older = FilterConditions::build(&engine_rule(vec![Condition::Application(
            program.clone(),
        )]))
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
