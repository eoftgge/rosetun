use std::{net::IpAddr, path::Path, ptr};

use super::{
    policy::{Action, AddressFamily, Condition, Rule},
    session::DynamicSession,
};
use crate::RoutingError;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{FwpmFilterAdd0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FWP_ACTION_BLOCK, FWPM_CONDITION_FLAGS, FWPM_CONDITION_ALE_APP_ID};
use windows_sys::{
    Win32::NetworkManagement::{
        Ndis::NET_LUID_LH,
        WindowsFilteringPlatform::{
            FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB,
            FWP_BYTE_BLOB_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0,
            FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT8,
            FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0,
            FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_LOCAL_PORT,
            FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
            FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER_CONDITION0, FWPM_FILTER0,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        },
    },
    Win32::Networking::WinSock::{IPPROTO_ICMPV6, IPPROTO_UDP},
    core::GUID
};

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

struct AppIdBlob(*mut FWP_BYTE_BLOB);

impl AppIdBlob {
    fn from_path(path: &Path) -> Result<Self, RoutingError> {
        let path = wide_path(path)?;
        let mut blob = ptr::null_mut();

        let status = unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob) };
        if status != 0 {
            return Err(RoutingError::Wfp {
                code: status,
                context: "getting the WFP application ID for the engine",
            });
        }

        Ok(Self(blob))
    }

    fn as_ptr(&self) -> *mut FWP_BYTE_BLOB {
        self.0
    }
}

impl Drop for AppIdBlob {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FwpmFreeMemory0((&mut self.0).cast());
            }
        }
    }
}

pub(super) fn add_rule(session: &DynamicSession, rule: &Rule) -> Result<(), RoutingError> {
    let mut luid = NET_LUID_LH::default();
    let mut app_id = None;
    let mut ipv4 = 0_u32;
    let mut ipv6 = FWP_BYTE_ARRAY16 {
        byteArray16: [0; 16],
    };
    let mut conditions = Vec::with_capacity(3);

    match rule.conditions.as_slice() {
        [] => {}
        [Condition::LocalInterface(value)] => {
            unsafe {
                luid.Value = *value;
            }
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
        [
        Condition::Application(engine_binary),
        Condition::RemoteAddress(endpoint),
        ] => {
            app_id = Some(AppIdBlob::from_path(engine_binary)?);
            conditions.push(application_condition(
                app_id.as_ref().expect("application ID was initialized"),
            ));
            conditions.push(remote_address_condition(
                rule.family,
                *endpoint,
                &mut ipv4,
                &mut ipv6,
            )?);
        }
        _ => return Err(RoutingError::Unsupported),
    }

    let filter = FWPM_FILTER0 {
        layerKey: layer_key(rule.family),
        subLayerKey: sublayer_key(),
        action: action(rule.action),
        weight: weight(rule.weight),
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        ..Default::default()
    };

    let status =
        unsafe { FwpmFilterAdd0(session.handle(), &filter, ptr::null_mut(), ptr::null_mut()) };
    if status != 0 {
        return Err(RoutingError::Wfp {
            code: status,
            context: "adding a Rosetun WFP filter",
        });
    }

    Ok(())
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

fn remote_address_condition(
    family: AddressFamily,
    endpoint: IpAddr,
    ipv4: &mut u32,
    ipv6: &mut FWP_BYTE_ARRAY16,
) -> Result<FWPM_FILTER_CONDITION0, RoutingError> {
    let value = match (family, endpoint) {
        (AddressFamily::Ipv4, IpAddr::V4(address)) => {
            // WFP expects the IPv4 address in network-byte-order representation.
            *ipv4 = u32::from_ne_bytes(address.octets());

            FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint32: *ipv4 },
            }
        }
        (AddressFamily::Ipv6, IpAddr::V6(address)) => {
            ipv6.byteArray16 = address.octets();

            FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_ARRAY16_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteArray16: ipv6 },
            }
        }
        _ => return Err(RoutingError::Unsupported),
    };

    Ok(FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: value,
    })
}

fn layer_key(family: AddressFamily) -> GUID {
    match family {
        AddressFamily::Ipv4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        AddressFamily::Ipv6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
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

fn sublayer_key() -> GUID {
    GUID {
        data1: 0x0c03_5ef5,
        data2: 0x4c5c,
        data3: 0x4583,
        data4: [0xad, 0x9c, 0x17, 0x97, 0x91, 0x36, 0x0f, 0x5e],
    }
}

fn wide_path(path: &Path) -> Result<Vec<u16>, RoutingError> {
    let path = path.to_str().ok_or_else(|| RoutingError::Tun {
        name: path.display().to_string(),
        reason: "the engine executable path is not valid UTF-8".to_owned(),
    })?;

    Ok(path.encode_utf16().chain(Some(0)).collect())
}
