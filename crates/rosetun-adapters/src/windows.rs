use std::collections::HashMap;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::net::Ipv4Addr;
use std::ptr::{self, NonNull};
use std::slice;

use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA},
    NetworkManagement::{
        IpHelper::{
            FreeMibTable, GAA_FLAG_INCLUDE_ALL_INTERFACES, GetAdaptersAddresses,
            GetIpForwardTable2, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
        },
        Ndis::IfOperStatusUp,
    },
    Networking::WinSock::AF_INET,
};

use crate::{Adapter, DefaultRoutes, is_other_tunnel};

struct ForwardTable(NonNull<MIB_IPFORWARD_TABLE2>);

impl ForwardTable {
    fn get() -> io::Result<Self> {
        let mut table = ptr::null_mut();
        // SAFETY: the ABI fills the writable pointer with an API-owned table; no
        // borrow is created until the synchronous call returns.
        let status = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
        let table = NonNull::new(table);
        // The API can allocate even when it returns an error. Own that allocation
        // before checking status so Drop frees it on every failure path.
        let table = table.map(Self);
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        table.ok_or_else(|| io::Error::other("route enumeration returned no table"))
    }

    fn routes(&self) -> &[MIB_IPFORWARD_ROW2] {
        // SAFETY: GetIpForwardTable2 allocated NumEntries contiguous rows in its
        // trailing ABI array; the borrow cannot outlive this owner or FreeMibTable.
        unsafe {
            let table = self.0.as_ref();
            slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize)
        }
    }
}

impl Drop for ForwardTable {
    fn drop(&mut self) {
        // SAFETY: this is the original allocation from GetIpForwardTable2, owned
        // exactly once here; FreeMibTable is its matching Windows ABI deallocator.
        unsafe { FreeMibTable(self.0.as_ptr().cast()) };
    }
}

fn ipv4_prefix(route: &MIB_IPFORWARD_ROW2) -> Option<(Ipv4Addr, u8)> {
    let prefix = &route.DestinationPrefix;
    if prefix.PrefixLength > 32 {
        return None;
    }
    // SAFETY: si_family is the active ABI discriminator, checked before accessing
    // the IPv4 union arm; SOCKADDR_IN's S_addr holds network-order bytes.
    unsafe {
        if prefix.Prefix.si_family != AF_INET {
            return None;
        }
        let octets = prefix.Prefix.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
        Some((Ipv4Addr::from(octets), prefix.PrefixLength))
    }
}

fn routes_by_interface() -> io::Result<HashMap<u64, DefaultRoutes>> {
    let table = ForwardTable::get()?;
    let mut routes = HashMap::<u64, DefaultRoutes>::new();
    for route in table.routes() {
        if let Some((address, prefix)) = ipv4_prefix(route) {
            // SAFETY: Value is the initialized u64 view of the NET_LUID_LH ABI
            // union provided by GetIpForwardTable2; copy it while the table lives.
            let luid = unsafe { route.InterfaceLuid.Value };
            routes.entry(luid).or_default().observe(address, prefix);
        }
    }
    Ok(routes)
}

fn wide_string(value: *const u16) -> String {
    if value.is_null() {
        return String::new();
    }
    let mut length = 0;
    // SAFETY: GetAdaptersAddresses supplies a NUL-terminated UTF-16 pointer
    // backed by the still-live caller buffer. Bound the scan and copy the text
    // before that buffer is freed; never retain a Windows pointer in Adapter.
    unsafe {
        while length < 512 && *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(slice::from_raw_parts(value, length))
    }
}

fn adapters() -> io::Result<Vec<Adapter>> {
    let mut bytes = 0_u32;
    // SAFETY: first synchronous ABI call only writes the required size through
    // the live stack pointer. No adapter pointer is returned or dereferenced.
    let status = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            GAA_FLAG_INCLUDE_ALL_INTERFACES,
            ptr::null(),
            ptr::null_mut(),
            &mut bytes,
        )
    };
    if status == ERROR_NO_DATA {
        return Ok(Vec::new());
    }
    if status != ERROR_BUFFER_OVERFLOW {
        return Err(io::Error::from_raw_os_error(status as i32));
    }

    for _ in 0..4 {
        let count = (bytes as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut buffer = Vec::<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>::new();
        buffer.resize_with(count, MaybeUninit::uninit);
        // SAFETY: Vec owns at least `bytes` writable, correctly aligned bytes;
        // Windows initializes the linked ABI records synchronously. Its pointers
        // are used only after a successful result and while the Vec stays alive.
        let status = unsafe {
            GetAdaptersAddresses(
                AF_INET as u32,
                GAA_FLAG_INCLUDE_ALL_INTERFACES,
                ptr::null(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if status == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if status == ERROR_NO_DATA {
            return Ok(Vec::new());
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        let mut found = Vec::new();
        let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !current.is_null() {
            // SAFETY: on success, GetAdaptersAddresses created this linked list
            // in the live caller buffer. Copy all scalar fields and both UTF-16
            // strings before dropping the Vec; never expose ABI pointers.
            let adapter = unsafe { &*current };
            found.push(Adapter {
                name: wide_string(adapter.FriendlyName),
                description: wide_string(adapter.Description),
                // SAFETY: Luid.Value is the initialized ABI union view, copied
                // before the caller-owned adapter buffer is dropped.
                luid: unsafe { adapter.Luid.Value },
                interface_type: adapter.IfType,
                up: adapter.OperStatus == IfOperStatusUp,
            });
            current = adapter.Next;
        }
        return Ok(found);
    }
    Err(io::Error::other("adapter enumeration kept changing"))
}

pub(super) fn other_tunnels(own_alias: &str) -> io::Result<Vec<String>> {
    let routes = routes_by_interface()?;
    Ok(adapters()?
        .into_iter()
        .filter(|adapter| {
            is_other_tunnel(
                adapter,
                routes.get(&adapter.luid).copied().unwrap_or_default(),
                own_alias,
            )
        })
        .map(|adapter| adapter.name)
        .collect())
}
