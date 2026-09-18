use std::ptr;

use windows_sys::{
    core::GUID,
    Win32::NetworkManagement::{
        Ndis::NET_LUID_LH,
        WindowsFilteringPlatform::{
            FwpmFilterAdd0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_CONDITION_VALUE0,
            FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT64, FWP_VALUE0,
            FWP_VALUE0_0, FWPM_ACTION0, FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_FILTER0,
            FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        },
    },
};

use super::{
    policy::{Action, AddressFamily, Condition, Rule},
    session::DynamicSession,
};
use crate::RoutingError;

pub(super) fn add_rule(session: &DynamicSession, rule: &Rule) -> Result<(), RoutingError> {
    let mut luid = NET_LUID_LH::default();
    let mut condition = FWPM_FILTER_CONDITION0::default();

    let conditions = match rule.conditions.as_slice() {
        [] => ptr::null_mut(),
        [Condition::LocalInterface(value)] => {
            luid.Value = *value;
            condition = interface_condition(&mut luid);
            &mut condition
        }
        _ => return Err(RoutingError::Unsupported),
    };

    let filter = FWPM_FILTER0 {
        layerKey: layer_key(rule.family),
        subLayerKey: sublayer_key(),
        action: action(rule.action),
        weight: weight(rule.weight),
        numFilterConditions: u32::from(!conditions.is_null()),
        filterCondition: conditions,
        ..Default::default()
    };

    let status = unsafe { FwpmFilterAdd0(session.handle(), &filter, ptr::null_mut(), ptr::null_mut()) };
    if status != 0 {
        return Err(RoutingError::Wfp {
            code: status,
            context: "adding a Rosetun WFP filter",
        });
    }

    Ok(())
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

fn interface_condition(luid: &mut NET_LUID_LH) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                uint64: unsafe { (&mut luid.Value) } as *mut u64,
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
