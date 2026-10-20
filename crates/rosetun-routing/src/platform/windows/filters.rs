use std::{path::Path, ptr};

use super::{
    lockdown,
    policy::{Action, AddressFamily, Condition, Layer, Rule},
    session::{Engine, PROVIDER_KEY, SUBLAYER_KEY},
};
use crate::RoutingError;
use crate::platform::windows::policy::Subnet;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK,
    FWP_V6_ADDR_MASK, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0, FwpmFilterAdd0, FwpmFilterDeleteById0,
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
};
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

    pub(super) fn bytes(&self) -> &[u8] {
        // SAFETY: the blob came from FwpmGetAppIdFromFileName0 and lives until
        // Drop; `data` holds `size` bytes.
        unsafe { blob_bytes(&*self.0) }
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

/// A rule's WFP conditions together with the values they point to. Built
/// without a WFP engine, so tests can check that every rule has a shape.
pub(super) struct FilterConditions {
    conditions: Vec<FWPM_FILTER_CONDITION0>,
    // The conditions hold raw pointers into these; boxed so they never move.
    _app_id: Option<AppIdBlob>,
    _luid: Box<NET_LUID_LH>,
    _v4: Box<FWP_V4_ADDR_AND_MASK>,
    _v6: Box<FWP_V6_ADDR_AND_MASK>,
}

impl FilterConditions {
    pub(super) fn build(rule: &Rule) -> Result<Self, RoutingError> {
        let mut luid = Box::new(NET_LUID_LH::default());
        let mut app_id = None;
        let mut v4 = Box::new(FWP_V4_ADDR_AND_MASK::default());
        let mut v6 = Box::new(FWP_V6_ADDR_AND_MASK::default());
        let mut conditions = Vec::with_capacity(3);

        match rule.conditions.as_slice() {
            [] => {}
            [Condition::Application(engine_binary)] => {
                let blob = app_id.insert(AppIdBlob::from_path(engine_binary)?);
                conditions.push(application_condition(blob));
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
            _luid: luid,
            _v4: v4,
            _v6: v6,
        })
    }
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
    use super::FilterConditions;
    use crate::platform::windows::lockdown;
    use crate::platform::windows::policy::{
        BootstrapPolicy, Condition, Rule, probe_authorization, tunnel_authorization,
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
}
