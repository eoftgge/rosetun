//! The user's sign-in task in Task Scheduler, through `ITaskService`.
//!
//! windows-sys has no COM interfaces, so the three vtables used here are
//! written out in `taskschd.h` order. Every interface derives from
//! `IDispatch`; its four methods are never called and only hold places.

use std::ffi::c_void;
use std::io;
use std::marker::PhantomData;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, RPC_E_CHANGED_MODE,
    SysAllocString, SysFreeString, SysStringLen, VARIANT_BOOL,
};
use windows_sys::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::Variant::VARIANT;
use windows_sys::core::{BSTR, GUID, HRESULT};

use super::TaskState;

const CLSID_TASK_SCHEDULER: GUID = GUID::from_u128(0x0f87369f_a4e5_4cfc_bd3e_73e6154572dd);
const IID_ITASK_SERVICE: GUID = GUID::from_u128(0x2faba4c7_4da9_4013_9697_20cc3fd40f85);
const TASK_CREATE_OR_UPDATE: i32 = 6;
const TASK_LOGON_INTERACTIVE_TOKEN: i32 = 3;
/// Rosetun's folder under the Task Scheduler root.
pub(super) const FOLDER: &str = "Rosetun";

type Unused = unsafe extern "system" fn();

#[repr(C)]
struct DispatchVtbl {
    _query_interface: Unused,
    _add_ref: Unused,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    _get_type_info_count: Unused,
    _get_type_info: Unused,
    _get_ids_of_names: Unused,
    _invoke: Unused,
}

#[repr(C)]
struct TaskServiceVtbl {
    base: DispatchVtbl,
    get_folder: unsafe extern "system" fn(*mut c_void, BSTR, *mut *mut c_void) -> HRESULT,
    _get_running_tasks: Unused,
    _new_task: Unused,
    connect: unsafe extern "system" fn(*mut c_void, VARIANT, VARIANT, VARIANT, VARIANT) -> HRESULT,
}

#[repr(C)]
struct TaskFolderVtbl {
    base: DispatchVtbl,
    _get_name: Unused,
    _get_path: Unused,
    get_folder: unsafe extern "system" fn(*mut c_void, BSTR, *mut *mut c_void) -> HRESULT,
    _get_folders: Unused,
    create_folder:
        unsafe extern "system" fn(*mut c_void, BSTR, VARIANT, *mut *mut c_void) -> HRESULT,
    delete_folder: unsafe extern "system" fn(*mut c_void, BSTR, i32) -> HRESULT,
    get_task: unsafe extern "system" fn(*mut c_void, BSTR, *mut *mut c_void) -> HRESULT,
    _get_tasks: Unused,
    delete_task: unsafe extern "system" fn(*mut c_void, BSTR, i32) -> HRESULT,
    register_task: unsafe extern "system" fn(
        *mut c_void,
        BSTR,
        BSTR,
        i32,
        VARIANT,
        VARIANT,
        i32,
        VARIANT,
        *mut *mut c_void,
    ) -> HRESULT,
}

#[repr(C)]
struct RegisteredTaskVtbl {
    base: DispatchVtbl,
    _get_name: Unused,
    _get_path: Unused,
    _get_state: Unused,
    get_enabled: unsafe extern "system" fn(*mut c_void, *mut VARIANT_BOOL) -> HRESULT,
    _put_enabled: Unused,
    _run: Unused,
    _run_ex: Unused,
    _get_instances: Unused,
    _get_last_run_time: Unused,
    _get_last_task_result: Unused,
    _get_number_of_missed_runs: Unused,
    _get_next_run_time: Unused,
    _get_definition: Unused,
    get_xml: unsafe extern "system" fn(*mut c_void, *mut BSTR) -> HRESULT,
}

/// COM entered on this thread for the length of one operation. A thread
/// already in a single-threaded apartment keeps it and is not uninitialized.
struct Apartment {
    entered: bool,
    _thread: PhantomData<*const ()>,
}

impl Apartment {
    fn enter() -> io::Result<Self> {
        // SAFETY: no reserved pointer. A success is balanced by
        // CoUninitialize in Drop on this thread (`PhantomData<*const ()>`
        // keeps the value on it); RPC_E_CHANGED_MODE means COM is already
        // initialized here in another mode and must not be balanced.
        let result = unsafe { CoInitializeEx(null(), COINIT_MULTITHREADED as u32) };
        if result >= 0 {
            Ok(Self {
                entered: true,
                _thread: PhantomData,
            })
        } else if result == RPC_E_CHANGED_MODE {
            Ok(Self {
                entered: false,
                _thread: PhantomData,
            })
        } else {
            Err(error(result))
        }
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.entered {
            // SAFETY: balances the successful CoInitializeEx in `enter` on
            // the same thread.
            unsafe { CoUninitialize() };
        }
    }
}

/// One owned COM reference with a vtable of type `V`, released once.
struct Com<V> {
    raw: *mut c_void,
    _vtbl: PhantomData<*const V>,
}

impl<V> Com<V> {
    /// Takes ownership of one reference returned through an out-pointer.
    fn own(raw: *mut c_void) -> io::Result<Self> {
        if raw.is_null() {
            return Err(io::Error::other("Task Scheduler returned no object"));
        }
        Ok(Self {
            raw,
            _vtbl: PhantomData,
        })
    }

    fn vtbl(&self) -> &V {
        // SAFETY: `raw` is a live COM object of the interface `V` describes;
        // its first field points to that vtable, which outlives the object.
        unsafe { &**self.raw.cast::<*const V>() }
    }
}

impl<V> Drop for Com<V> {
    fn drop(&mut self) {
        // SAFETY: every vtable here starts with IDispatch's (and so
        // IUnknown's) layout, and this value owns exactly one reference.
        let base = unsafe { &**self.raw.cast::<*const DispatchVtbl>() };
        // SAFETY: as above; the reference is not used after release.
        unsafe { (base.release)(self.raw) };
    }
}

/// A BSTR this module allocated, freed once.
struct OwnedBstr(BSTR);

impl OwnedBstr {
    fn new(text: &str) -> io::Result<Self> {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is NUL-terminated UTF-16 alive for the call; the
        // returned string is owned by this value and freed in Drop.
        let raw = unsafe { SysAllocString(wide.as_ptr()) };
        if raw.is_null() {
            return Err(io::Error::from(io::ErrorKind::OutOfMemory));
        }
        Ok(Self(raw))
    }

    fn text(&self) -> String {
        // SAFETY: a valid BSTR carries its length; the slice is read before
        // the string is freed.
        let length = unsafe { SysStringLen(self.0) } as usize;
        // SAFETY: SysStringLen counts the u16 units at `self.0`.
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(self.0, length) })
    }
}

impl Drop for OwnedBstr {
    fn drop(&mut self) {
        // SAFETY: allocated by SysAllocString or handed to us by an [out]
        // BSTR parameter; freed exactly once.
        unsafe { SysFreeString(self.0) };
    }
}

/// The connected Task Scheduler of this computer, for the current user.
pub(super) struct Scheduler {
    service: Com<TaskServiceVtbl>,
    folder_name: &'static str,
    _apartment: Apartment,
}

impl Scheduler {
    /// Tasks go to `folder_name` under the root, created on first use.
    pub(super) fn connect(folder_name: &'static str) -> io::Result<Self> {
        let apartment = Apartment::enter()?;
        let mut raw = null_mut();
        // SAFETY: both GUIDs are constants alive for the call; on success
        // `raw` holds one ITaskService reference, owned by `Com` below.
        check(unsafe {
            CoCreateInstance(
                &CLSID_TASK_SCHEDULER,
                null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_ITASK_SERVICE,
                &mut raw,
            )
        })?;
        let service = Com::<TaskServiceVtbl>::own(raw)?;
        let empty = VARIANT::default();
        // SAFETY: empty VARIANTs mean the local computer and the current
        // user; they own nothing.
        check(unsafe { (service.vtbl().connect)(service.raw, empty, empty, empty, empty) })?;
        Ok(Self {
            service,
            folder_name,
            _apartment: apartment,
        })
    }

    fn open_folder(&self, path: &str) -> io::Result<Option<Com<TaskFolderVtbl>>> {
        let path = OwnedBstr::new(path)?;
        let mut raw = null_mut();
        // SAFETY: the service is live and `path` outlives the call; on
        // success `raw` is one ITaskFolder reference.
        let result =
            unsafe { (self.service.vtbl().get_folder)(self.service.raw, path.0, &mut raw) };
        if missing(result) {
            return Ok(None);
        }
        check(result)?;
        Com::own(raw).map(Some)
    }

    fn root(&self) -> io::Result<Com<TaskFolderVtbl>> {
        self.open_folder("\\")?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn own_folder(&self) -> io::Result<Com<TaskFolderVtbl>> {
        if let Some(folder) = self.open_folder(self.folder_name)? {
            return Ok(folder);
        }
        let root = self.root()?;
        let name = OwnedBstr::new(self.folder_name)?;
        let mut raw = null_mut();
        // SAFETY: the root folder is live; an empty VARIANT keeps the
        // inherited security descriptor. On success `raw` is the new folder.
        let result =
            unsafe { (root.vtbl().create_folder)(root.raw, name.0, VARIANT::default(), &mut raw) };
        if result == hresult(ERROR_ALREADY_EXISTS) {
            return self
                .open_folder(self.folder_name)?
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound));
        }
        check(result)?;
        Com::own(raw)
    }

    pub(super) fn register(&self, name: &str, xml: &str) -> io::Result<()> {
        let folder = self.own_folder()?;
        let name = OwnedBstr::new(name)?;
        let xml = OwnedBstr::new(xml)?;
        let empty = VARIANT::default();
        let mut raw = null_mut();
        // SAFETY: the folder is live, both strings outlive the call, and the
        // empty VARIANTs (user, password, SDDL) own nothing: the principal
        // comes from the XML. On success `raw` is one IRegisteredTask.
        check(unsafe {
            (folder.vtbl().register_task)(
                folder.raw,
                name.0,
                xml.0,
                TASK_CREATE_OR_UPDATE,
                empty,
                empty,
                TASK_LOGON_INTERACTIVE_TOKEN,
                empty,
                &mut raw,
            )
        })?;
        Com::<RegisteredTaskVtbl>::own(raw).map(drop)
    }

    pub(super) fn state(&self, name: &str) -> io::Result<Option<TaskState>> {
        let Some(folder) = self.open_folder(self.folder_name)? else {
            return Ok(None);
        };
        let name = OwnedBstr::new(name)?;
        let mut raw = null_mut();
        // SAFETY: the folder is live and `name` outlives the call; on success
        // `raw` is one IRegisteredTask reference.
        let result = unsafe { (folder.vtbl().get_task)(folder.raw, name.0, &mut raw) };
        if missing(result) {
            return Ok(None);
        }
        check(result)?;
        let task = Com::<RegisteredTaskVtbl>::own(raw)?;
        let mut enabled: VARIANT_BOOL = 0;
        // SAFETY: the task is live and `enabled` is a writable local.
        check(unsafe { (task.vtbl().get_enabled)(task.raw, &mut enabled) })?;
        let mut xml: BSTR = null();
        // SAFETY: the task is live; on success the BSTR is ours to free.
        check(unsafe { (task.vtbl().get_xml)(task.raw, &mut xml) })?;
        if xml.is_null() {
            return Err(io::Error::other("Task Scheduler returned no task XML"));
        }
        let xml = OwnedBstr(xml);
        Ok(Some(TaskState {
            enabled: enabled != 0,
            command: super::task::command_of(&xml.text()),
        }))
    }

    /// Deletes the task, then the folder if no other user's task is left.
    pub(super) fn delete(&self, name: &str) -> io::Result<()> {
        let Some(folder) = self.open_folder(self.folder_name)? else {
            return Ok(());
        };
        let name = OwnedBstr::new(name)?;
        // SAFETY: the folder is live and `name` outlives the call.
        let result = unsafe { (folder.vtbl().delete_task)(folder.raw, name.0, 0) };
        if !missing(result) {
            check(result)?;
        }
        drop(folder);
        let root = self.root()?;
        let folder = OwnedBstr::new(self.folder_name)?;
        // Another user's task in the folder, or missing rights, keep it; the
        // uninstaller removes it then. The task itself is already gone.
        // SAFETY: the root folder is live and `folder` outlives the call.
        let _ = unsafe { (root.vtbl().delete_folder)(root.raw, folder.0, 0) };
        Ok(())
    }
}

fn hresult(win32: u32) -> HRESULT {
    (0x8007_0000 | (win32 & 0xffff)) as HRESULT
}

fn missing(result: HRESULT) -> bool {
    result == hresult(ERROR_FILE_NOT_FOUND) || result == hresult(ERROR_PATH_NOT_FOUND)
}

fn check(result: HRESULT) -> io::Result<()> {
    if result >= 0 {
        Ok(())
    } else {
        Err(error(result))
    }
}

/// A Win32 HRESULT as its Windows error, anything else as the HRESULT.
fn error(result: HRESULT) -> io::Error {
    let code = result as u32;
    if code & 0xffff_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((code & 0xffff) as i32)
    } else {
        io::Error::from_raw_os_error(result)
    }
}
