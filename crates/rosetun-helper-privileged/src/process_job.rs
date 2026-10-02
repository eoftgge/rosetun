//! Windows process-lifetime job.
//!
//! The helper joins this job before spawning engines. Its children inherit job
//! membership, without a separate post-spawn assignment window.

use std::io;
use std::mem::size_of;
use std::os::windows::io::{
    AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle,
};
use std::ptr;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

fn create_job() -> io::Result<OwnedHandle> {
    // Null security attributes make this handle non-inheritable.
    // An unnamed job cannot be reopened by name.
    let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: CreateJobObjectW returned a valid handle owned by this function.
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };

    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    // SAFETY: The handle and information buffer remain valid during the call.
    let result = unsafe {
        SetInformationJobObject(
            job.as_raw_handle() as HANDLE,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(job)
}

pub(crate) fn install() -> io::Result<()> {
    let job = create_job()?;

    // SAFETY: job is valid; GetCurrentProcess returns the current process's
    // pseudo-handle. No engine has been started at this point.
    let assigned = unsafe {
        AssignProcessToJobObject(job.as_raw_handle() as HANDLE, GetCurrentProcess())
    };
    if assigned == 0 {
        // No process was assigned to this job, so dropping it is safe.
        return Err(io::Error::last_os_error());
    }

    // Deliberately retain one non-inheritable handle until process termination.
    //
    // Closing it in Rust Drop would terminate the helper itself along with its
    // children. Windows closes it when the helper exits or is forcibly killed.
    // Do not return an owning RAII guard for this process-lifetime resource.
    let _process_lifetime_handle = job.into_raw_handle();

    tracing::info!("helper joined process-lifetime job; engine children cannot outlive it");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::JobObjects::{
        QueryInformationJobObject, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
        JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    };

    #[test]
    fn job_kills_on_close_and_disallows_breakaway() {
        // Only create/query a job. Never assign the test runner to it.
        let job = create_job().expect("job creation succeeds");
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();

        let queried = unsafe {
            QueryInformationJobObject(
                job.as_raw_handle() as HANDLE,
                JobObjectExtendedLimitInformation,
                (&raw mut limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        };
        assert_ne!(
            queried,
            0,
            "query failed: {}",
            io::Error::last_os_error()
        );

        let flags = limits.BasicLimitInformation.LimitFlags;
        assert_ne!(flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 0);
        assert_eq!(
            flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK
                | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK),
            0
        );
    }
}