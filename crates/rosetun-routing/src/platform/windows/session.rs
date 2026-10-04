use std::ffi::c_void;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_BYTE_BLOB, FWPM_DISPLAY_DATA0, FWPM_PROVIDER0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0,
    FWPM_SUBLAYER0, FwpmEngineClose0, FwpmProviderAdd0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::core::GUID;

use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::{
    filters,
    policy::{self, BootstrapPolicy},
    tunnel,
};
use crate::{ProtectionSession, RoutingError, RoutingPlan, TunnelInterface};

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

/// A dynamic WFP session owns all objects created through its engine handle.
/// Windows removes those objects automatically when the handle is closed,
/// providing fail-open recovery if the helper crashes.
#[derive(Debug)]
pub(super) struct DynamicSession {
    handle: HANDLE,
}

impl DynamicSession {
    pub(super) fn open() -> Result<Self, RoutingError> {
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut handle = ptr::null_mut();

        tracing::debug!("opening dynamic WFP engine session");
        let status = unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &session,
                &mut handle,
            )
        };
        if status != 0 {
            return Err(wfp_error(status, "opening the dynamic WFP session"));
        }

        tracing::debug!("dynamic WFP engine session opened");
        Ok(Self { handle })
    }

    pub(super) fn transaction(&self) -> Result<Transaction<'_>, RoutingError> {
        tracing::debug!("starting WFP transaction");
        let status = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        if status != 0 {
            return Err(wfp_error(status, "starting a WFP transaction"));
        }

        tracing::debug!("WFP transaction started");
        Ok(Transaction {
            session: self,
            completed: false,
        })
    }

    pub(super) fn handle(&self) -> HANDLE {
        self.handle
    }

    pub(super) fn add_provider_and_sublayer(&self) -> Result<(), RoutingError> {
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

        tracing::debug!("adding Rosetun WFP provider");
        let status = unsafe { FwpmProviderAdd0(self.handle, &provider, ptr::null_mut()) };
        if status != 0 {
            return Err(wfp_error(status, "adding the Rosetun WFP provider"));
        }

        tracing::debug!("Rosetun WFP provider added");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: display_data(&sublayer_name, &sublayer_description),
            flags: 0,
            providerKey: (&PROVIDER_KEY as *const GUID).cast_mut(),
            providerData: empty_blob(),
            weight: SUBLAYER_WEIGHT,
        };

        tracing::debug!("adding Rosetun WFP sublayer");
        let status = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, ptr::null_mut()) };
        if status != 0 {
            return Err(wfp_error(status, "adding the Rosetun WFP sublayer"));
        }

        tracing::debug!("Rosetun WFP sublayer added");
        Ok(())
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

/// Bootstrap policy is installed before the engine starts. Tunnel authorization
/// is added later to this same session after routing has discovered and
/// validated the engine-created adapter.
#[derive(Debug)]
pub(super) struct WfpProtectionSession {
    session: Option<DynamicSession>,
    bootstrap_policy: BootstrapPolicy,
    bootstrap_filter_ids: Vec<u64>,
    tunnel_filter_ids: Vec<u64>,
    tunnel_authorized: bool,
}

impl WfpProtectionSession {
    pub(super) fn begin(plan: &RoutingPlan, engine_binary: &Path) -> Result<Self, RoutingError> {
        let session = DynamicSession::open()?;
        let transaction = session.transaction()?;

        session.add_provider_and_sublayer()?;

        let bootstrap_policy = BootstrapPolicy::from_plan(plan, engine_binary);
        let mut bootstrap_filter_ids = Vec::with_capacity(bootstrap_policy.rules.len());
        for rule in &bootstrap_policy.rules {
            bootstrap_filter_ids.push(filters::add_rule(&session, rule)?);
        }

        transaction.commit()?;

        Ok(Self {
            session: Some(session),
            bootstrap_policy,
            bootstrap_filter_ids,
            tunnel_filter_ids: Vec::new(),
            tunnel_authorized: false,
        })
    }

    fn active_session(&self) -> Result<&DynamicSession, RoutingError> {
        self.session.as_ref().ok_or_else(|| {
            RoutingError::Route("the WFP protection session has been torn down".to_owned())
        })
    }
}

/// WFP engine handles are not shared concurrently. A `RoutingGuard` owns the
/// session and may move with its helper session, but it is never `Sync`.
unsafe impl Send for WfpProtectionSession {}

impl ProtectionSession for WfpProtectionSession {
    fn prepare_reconnect(
        &mut self,
        plan: &RoutingPlan,
        engine_binary: &Path,
    ) -> Result<(), RoutingError> {
        let policy = BootstrapPolicy::from_plan(plan, engine_binary);
        let replace_bootstrap = policy != self.bootstrap_policy;
        let session = self.active_session()?;
        let transaction = session.transaction()?;

        for &id in &self.tunnel_filter_ids {
            filters::delete_rule(session, id)?;
        }

        let mut replacement_ids = Vec::new();
        if replace_bootstrap {
            for &id in &self.bootstrap_filter_ids {
                filters::delete_rule(session, id)?;
            }
            replacement_ids.reserve(policy.rules.len());
            for rule in &policy.rules {
                replacement_ids.push(filters::add_rule(session, rule)?);
            }
        }

        transaction.commit()?;

        // Publish bookkeeping only after the OS has committed the replacement.
        if replace_bootstrap {
            self.bootstrap_policy = policy;
            self.bootstrap_filter_ids = replacement_ids;
        }
        self.tunnel_filter_ids.clear();
        self.tunnel_authorized = false;
        Ok(())
    }

    fn authorize_tunnel(&mut self, tunnel: &TunnelInterface) -> Result<(), RoutingError> {
        if self.tunnel_authorized {
            return Ok(());
        }

        let luid = tunnel::resolve_luid(tunnel)?;
        let session = self.active_session()?;
        let transaction = session.transaction()?;
        let mut ids = Vec::with_capacity(2);

        for rule in policy::tunnel_authorization(luid.value()) {
            ids.push(filters::add_rule(session, &rule)?);
        }

        transaction.commit()?;
        self.tunnel_filter_ids = ids;
        self.tunnel_authorized = true;
        Ok(())
    }

    fn teardown(&mut self) -> Result<(), RoutingError> {
        self.session.take();
        self.bootstrap_filter_ids.clear();
        self.tunnel_filter_ids.clear();
        self.tunnel_authorized = false;
        Ok(())
    }
}

/// An active WFP transaction. Dropping an uncommitted transaction aborts it,
/// so failures while installing a protection policy cannot leave partial
/// filters behind.
#[derive(Debug)]
pub(super) struct Transaction<'session> {
    session: &'session DynamicSession,
    completed: bool,
}

impl Transaction<'_> {
    pub(super) fn commit(mut self) -> Result<(), RoutingError> {
        tracing::debug!("committing WFP transaction");
        let status = unsafe { FwpmTransactionCommit0(self.session.handle) };
        if status != 0 {
            return Err(wfp_error(status, "committing the WFP transaction"));
        }

        self.completed = true;
        tracing::debug!("WFP transaction committed");
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

pub(crate) const PROVIDER_KEY: GUID = GUID {
    data1: 0x51a4_7ec7,
    data2: 0x6459,
    data3: 0x4b84,
    data4: [0x88, 0x54, 0x07, 0x5e, 0x15, 0x76, 0xe7, 0xf9],
};
pub(super) const SUBLAYER_KEY: GUID = GUID {
    data1: 0x0c03_5ef5,
    data2: 0x4c5c,
    data3: 0x4583,
    data4: [0xad, 0x9c, 0x17, 0x97, 0x91, 0x36, 0x0f, 0x5e],
};
const SUBLAYER_WEIGHT: u16 = 0x8000;

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
