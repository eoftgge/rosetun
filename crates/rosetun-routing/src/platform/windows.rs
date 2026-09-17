use std::ffi::c_void;
use std::ptr;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmProviderAdd0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_DISPLAY_DATA0, FWPM_PROVIDER0,
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_BYTE_BLOB,
};

use crate::{RoutingBackend, RoutingError, RoutingGuard, RoutingPlan};

mod policy;

use policy::OutboundPolicy;

const PROVIDER_KEY: GUID = GUID {
    data1: 0x51a4_7ec7,
    data2: 0x6459,
    data3: 0x4b84,
    data4: [0x88, 0x54, 0x07, 0x5e, 0x15, 0x76, 0xe7, 0xf9],
};

const SUBLAYER_KEY: GUID = GUID {
    data1: 0x0c03_5ef5,
    data2: 0x4c5c,
    data3: 0x4583,
    data4: [0xad, 0x9c, 0x17, 0x97, 0x91, 0x36, 0x0f, 0x5e],
};

const SUBLAYER_WEIGHT: u16 = 0x8000;

#[link(name = "fwpuclnt")]
unsafe extern "system" {
    fn FwpmEngineOpen0(
        server_name: *const u16,
        authn_service: u32,
        auth_identity: *const c_void,
        session: *const FWPM_SESSION0,
        engine_handle: *mut HANDLE,
    ) -> u32;
}

#[derive(Debug, Default)]
pub(super) struct WfpBackend;

impl WfpBackend {
    pub(super) fn new() -> Self {
        Self
    }
}

impl RoutingBackend for WfpBackend {
    fn name(&self) -> &'static str {
        "windows-wfp"
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        let session = DynamicSession::open()?;
        let transaction = session.transaction()?;
        session.add_provider_and_sublayer()?;
        transaction.commit()
    }

    fn begin_protection(
        &mut self,
        _plan: &RoutingPlan,
        _engine_binary: &std::path::Path,
    ) -> Result<RoutingGuard, RoutingError> {
        Err(RoutingError::Unsupported)
    }
}

/// A dynamic WFP session owns all objects created through its engine handle.
/// Windows removes those objects automatically when the handle is closed,
/// providing fail-open recovery if the helper crashes.
#[derive(Debug)]
struct DynamicSession {
    handle: HANDLE,
}

impl DynamicSession {
    fn open() -> Result<Self, RoutingError> {
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut handle = ptr::null_mut();

        let status = unsafe { FwpmEngineOpen0(ptr::null(), 0, ptr::null(), &session, &mut handle) };
        if status != 0 {
            return Err(wfp_error(status, "opening the dynamic WFP session"));
        }

        Ok(Self { handle })
    }

    fn transaction(&self) -> Result<Transaction<'_>, RoutingError> {
        let status = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        if status != 0 {
            return Err(wfp_error(status, "starting a WFP transaction"));
        }

        Ok(Transaction {
            session: self,
            completed: false,
        })
    }

    fn add_provider_and_sublayer(&self) -> Result<(), RoutingError> {
        let provider_name = wide("Rosetun");
        let provider_description = wide("Rosetun dynamic kill-switch policy");
        let sublayer_name = wide("Rosetun kill switch");
        let sublayer_description = wide("Rosetun dynamic outbound protection layer");

        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: display_data(&provider_name, &provider_description),
            flags: 0,
            providerData: empty_blob(),
            serviceName: ptr::null_mut(),
        };
        let status = unsafe { FwpmProviderAdd0(self.handle, &provider, ptr::null_mut()) };
        if status != 0 {
            return Err(wfp_error(status, "adding the Rosetun WFP provider"));
        }

        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: display_data(&sublayer_name, &sublayer_description),
            flags: 0,
            providerKey: (&PROVIDER_KEY as *const GUID).cast_mut(),
            providerData: empty_blob(),
            weight: SUBLAYER_WEIGHT,
        };
        let status = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, ptr::null_mut()) };
        if status != 0 {
            return Err(wfp_error(status, "adding the Rosetun WFP sublayer"));
        }

        Ok(())
    }
}

/// An active WFP transaction. Dropping an uncommitted transaction aborts it,
/// so failures while installing a protection policy cannot leave partial
/// filters behind.
#[derive(Debug)]
struct Transaction<'session> {
    session: &'session DynamicSession,
    completed: bool,
}

impl Transaction<'_> {
    fn commit(mut self) -> Result<(), RoutingError> {
        let status = unsafe { FwpmTransactionCommit0(self.session.handle) };
        if status != 0 {
            return Err(wfp_error(status, "committing the WFP transaction"));
        }

        self.completed = true;
        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let status = unsafe { FwpmTransactionAbort0(self.session.handle) };
            if status != 0 {
                tracing::error!(
                    code = status,
                    "failed to abort the WFP transaction during cleanup"
                );
            }
        }
    }
}

impl Drop for DynamicSession {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let status = unsafe { FwpmEngineClose0(self.handle) };
            if status != 0 {
                tracing::error!(
                    code = status,
                    "failed to close the dynamic WFP session during cleanup"
                );
            }
            self.handle = ptr::null_mut();
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn display_data(name: &[u16], description: &[u16]) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: name.as_ptr().cast_mut(),
        description: description.as_ptr().cast_mut(),
    }
}

fn empty_blob() -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: 0,
        data: ptr::null_mut(),
    }
}

fn wfp_error(code: u32, context: &'static str) -> RoutingError {
    RoutingError::Wfp { code, context }
}
