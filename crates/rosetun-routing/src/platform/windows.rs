use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
};

use crate::{RoutingBackend, RoutingError, RoutingGuard, RoutingPlan};

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
        session.verify_transaction()
    }

    fn apply(&mut self, _plan: &RoutingPlan) -> Result<RoutingGuard, RoutingError> {
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

        let status = unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                0,
                ptr::null(),
                &session,
                &mut handle,
            )
        };
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

    fn verify_transaction(&self) -> Result<(), RoutingError> {
        self.transaction()?.commit()
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

fn wfp_error(code: u32, context: &'static str) -> RoutingError {
    RoutingError::Wfp { code, context }
}