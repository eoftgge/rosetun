use std::{ptr, slice};

use windows_sys::Win32::{
    NetworkManagement::{
        IpHelper::{
            ConvertInterfaceLuidToAlias, FreeMibTable, GetIfEntry2, GetIpForwardTable2,
            GetIpInterfaceEntry, MIB_IF_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
        },
        Ndis::{IfOperStatusUp, NET_LUID_LH},
    },
    Networking::WinSock::AF_INET,
};

struct ForwardTable(*mut MIB_IPFORWARD_TABLE2);

impl ForwardTable {
    fn get() -> Option<Self> {
        let mut table = ptr::null_mut();
        // The API allocates the table and transfers ownership to the caller.
        let status = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
        if table.is_null() {
            return None;
        }
        let table = Self(table);
        (status == 0).then_some(table)
    }

    fn routes(&self) -> &[windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2] {
        // The allocation holds NumEntries consecutive rows starting at Table.
        unsafe { slice::from_raw_parts((*self.0).Table.as_ptr(), (*self.0).NumEntries as usize) }
    }
}

impl Drop for ForwardTable {
    fn drop(&mut self) {
        // FreeMibTable owns the allocation even when a later lookup fails.
        unsafe { FreeMibTable(self.0.cast()) };
    }
}

fn alias(luid: &NET_LUID_LH) -> Option<String> {
    let mut buffer = [0u16; 257];
    // The API writes a NUL-terminated alias into our stack buffer.
    if unsafe { ConvertInterfaceLuidToAlias(luid, buffer.as_mut_ptr(), buffer.len()) } != 0 {
        return None;
    }
    let end = buffer.iter().position(|&c| c == 0)?;
    String::from_utf16(&buffer[..end]).ok()
}

/// Avoid the live TUN even when its route has the best metric.
pub(super) fn physical_default_interface(exclude_alias: &str) -> Option<String> {
    let routes = ForwardTable::get()?;
    let mut best: Option<(u64, String)> = None;
    for route in routes.routes() {
        if route.DestinationPrefix.PrefixLength != 0 {
            continue;
        }
        let Some(name) = alias(&route.InterfaceLuid) else {
            continue;
        };
        if name.to_lowercase() == exclude_alias.to_lowercase() {
            continue;
        }

        let mut interface = MIB_IF_ROW2 {
            InterfaceLuid: route.InterfaceLuid,
            ..MIB_IF_ROW2::default()
        };
        // Both calls fill our stack rows; the LUID is the same as the route's.
        if unsafe { GetIfEntry2(&mut interface) } != 0 || interface.OperStatus != IfOperStatusUp {
            continue;
        }
        let mut ip_interface = MIB_IPINTERFACE_ROW {
            Family: AF_INET,
            InterfaceLuid: route.InterfaceLuid,
            ..MIB_IPINTERFACE_ROW::default()
        };
        if unsafe { GetIpInterfaceEntry(&mut ip_interface) } != 0 {
            continue;
        }
        let metric = u64::from(route.Metric) + u64::from(ip_interface.Metric);
        if best.as_ref().is_none_or(|(current, _)| metric < *current) {
            best = Some((metric, name));
        }
    }
    best.map(|(_, name)| name)
}
