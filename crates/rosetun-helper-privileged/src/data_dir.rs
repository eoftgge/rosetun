use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
};

const DATA_DACL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
// Unlike data, installed binaries are readable and executable by Users.
const INSTALL_DACL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
// Upgrades also repair ownership; ordinary service startup changes only the DACL.
const OWNED_DATA_DACL: &str = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

struct SecurityDescriptor(*mut c_void);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: This descriptor was allocated by the Windows system ABI.
        // It is released exactly once, after all borrowed owner/DACL pointers.
        unsafe { LocalFree(self.0) };
    }
}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = ptr::null_mut();
        // SAFETY: The NUL-terminated UTF-16 string and writable output live
        // throughout the synchronous Windows ABI call. LocalFree owns its result.
        let result = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        if descriptor.is_null() {
            return Err(io::Error::other(
                "Windows returned an empty security descriptor",
            ));
        }
        Ok(Self(descriptor))
    }

    fn dacl(&self) -> io::Result<*mut windows_sys::Win32::Security::ACL> {
        let mut present = 0;
        let mut dacl = ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: The descriptor remains live while Windows writes into these
        // locals. The borrowed DACL must not outlive this descriptor.
        let result =
            unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        if present == 0 || dacl.is_null() {
            return Err(io::Error::other("security descriptor DACL is missing"));
        }
        Ok(dacl)
    }

    fn owner(&self) -> io::Result<*mut c_void> {
        let mut owner = ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: The descriptor stays alive while Windows fills these locals.
        // The returned SID is borrowed and remains live through SetSecurityInfo.
        if unsafe { GetSecurityDescriptorOwner(self.0, &mut owner, &mut defaulted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if owner.is_null() {
            return Err(io::Error::other("security descriptor owner is missing"));
        }
        Ok(owner)
    }
}

pub(crate) fn data_dir() -> io::Result<PathBuf> {
    if let Some(custom) = std::env::var_os("ROSETUN_DATA_DIR") {
        return Ok(PathBuf::from(custom));
    }
    let exe = std::env::current_exe()?;
    let parent = exe
        .parent()
        .ok_or_else(|| io::Error::other("helper executable has no parent"))?;
    Ok(parent.join("data"))
}

/// sing-box runs as SYSTEM with a config here, so only SYSTEM and
/// Administrators may write files it will consume.
pub(crate) fn secure(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let descriptor = SecurityDescriptor::from_sddl(DATA_DACL)?;
    let dacl = descriptor.dacl()?;
    let mut path: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: The path is NUL-terminated; DACL is borrowed from the live
    // descriptor until SetNamedSecurityInfoW completes its Windows ABI call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

fn open_no_follow(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .access_mode(0x0002_0000 | 0x0004_0000 | 0x0008_0000 | 0x0000_0080)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other(format!(
            "reparse point in installation: {}",
            path.display()
        )));
    }
    Ok(file)
}

fn set_security(file: &File, descriptor: &SecurityDescriptor, protected: bool) -> io::Result<()> {
    let owner = descriptor.owner()?;
    let dacl = descriptor.dacl()?;
    let inheritance = if protected {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    // SAFETY: The open no-follow handle is valid for this synchronous Windows
    // ABI call and denies concurrent write/delete opens. The borrowed owner SID
    // and DACL stay live in the descriptor; Windows copies the security data.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | inheritance,
            owner,
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

fn create_secure_dir(path: &Path, descriptor: &SecurityDescriptor) -> io::Result<()> {
    let name: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: The NUL-terminated name and borrowed descriptor remain live for
    // this synchronous Windows ABI call. Windows copies the owner and protected
    // DACL atomically when creating the directory; no user-writable interval.
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn secure_contents(
    dir: &Path,
    install: &SecurityDescriptor,
    data: &SecurityDescriptor,
    in_data: bool,
) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        // Check before opening; the handle below also refuses a swapped link.
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::other(format!(
                "reparse point in installation: {}",
                path.display()
            )));
        }
        let is_data = !in_data
            && entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case("data");
        let file = open_no_follow(&path)?;
        set_security(
            &file,
            if in_data || is_data { data } else { install },
            is_data,
        )?;
        if metadata.is_dir() {
            secure_contents(&path, install, data, in_data || is_data)?;
        }
        // Keep the handle open while processing children: a writable handle or
        // a concurrent delete/rename would fail the no-follow open above.
        drop(file);
    }
    Ok(())
}

pub(crate) fn secure_install(dir: &Path, replace_empty: bool) -> io::Result<()> {
    // Only newly created components are secured; pre-existing ancestors were
    // checked by install_dir::verify and must never have their ACLs changed.
    let mut missing = Vec::new();
    let mut next = dir.to_owned();
    while !next.exists() {
        missing.push(next.clone());
        next = next
            .parent()
            .ok_or_else(|| io::Error::other("install path has no parent"))?
            .to_owned();
    }
    let install = SecurityDescriptor::from_sddl(&format!("O:BA{INSTALL_DACL}"))?;
    let data = SecurityDescriptor::from_sddl(OWNED_DATA_DACL)?;
    if replace_empty {
        if !missing.is_empty() {
            return Err(io::Error::other("empty install directory disappeared"));
        }
        // Existing user-owned directories can retain attacker-held handles
        // after an ACL change. Removing one severs those handles from this name.
        // If removal or the subsequent atomic create is raced, fail closed.
        fs::remove_dir(dir)?;
        missing.push(dir.to_owned());
    }
    for path in missing.iter().rev() {
        create_secure_dir(path, &install)?;
        let file = open_no_follow(path)?;
        set_security(&file, &install, true)?;
    }
    let root = open_no_follow(dir)?;
    if !root.metadata()?.is_dir() {
        return Err(io::Error::other("install path is not a directory"));
    }
    set_security(&root, &install, true)?;
    secure_contents(dir, &install, &data, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use windows_sys::Win32::Security::{
        ACL_SIZE_INFORMATION, AclSizeInformation, CheckTokenMembership, GetAce, GetAclInformation,
        GetSecurityDescriptorControl, IsWellKnownSid, SE_DACL_PROTECTED,
        WinBuiltinAdministratorsSid, WinBuiltinUsersSid, WinLocalSystemSid,
    };

    fn check_acl(path: &Path, expected_users: bool, protected: bool) {
        let name: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut owner = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut raw = ptr::null_mut();
        // SAFETY: Windows writes the owned descriptor and interior SID/DACL
        // pointers to live locals via its system ABI. LocalFree releases it once.
        let code = unsafe {
            windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut raw,
            )
        };
        assert_eq!(code, 0);
        let descriptor = SecurityDescriptor(raw);
        assert!(!owner.is_null() && !dacl.is_null());
        // SAFETY: The SID is borrowed from the live descriptor; Windows only
        // reads it during this ABI call.
        assert_ne!(
            unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid) },
            0
        );
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: Both outputs are writable locals and descriptor stays live
        // throughout this Windows ABI call.
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) },
            0
        );
        assert_eq!(control & SE_DACL_PROTECTED != 0, protected);
        let mut size = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        // SAFETY: The DACL is borrowed from the live descriptor; output is
        // exactly sized and writable during this Windows ABI call.
        assert_ne!(
            unsafe {
                GetAclInformation(
                    dacl,
                    (&raw mut size).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            },
            0
        );
        let mut system = false;
        let mut admins = false;
        let mut users = false;
        for index in 0..size.AceCount {
            let mut ace: *mut c_void = ptr::null_mut();
            // SAFETY: The index is below the ACL count; the returned ACE is
            // borrowed from the live descriptor and contains mask and SID.
            assert_ne!(unsafe { GetAce(dacl, index, &mut ace) }, 0);
            // SAFETY: This ACE was generated from our SDDL and has at least
            // 16 bytes; GetAce borrows it from the live descriptor.
            let bytes = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), 16) };
            assert_eq!(bytes[0], 0); // ACCESS_ALLOWED_ACE_TYPE
            let mask = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            // SAFETY: The SID starts at offset 8 of the live, validated ACE.
            let sid = unsafe { ace.cast::<u8>().add(8).cast() };
            // SAFETY: These ACE SID pointers remain live inside the descriptor
            // for the duration of each Windows ABI identity comparison.
            unsafe {
                if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
                    assert_eq!(mask, 0x1f01ff);
                    system = true;
                } else if IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 {
                    assert_eq!(mask, 0x1f01ff);
                    admins = true;
                } else if IsWellKnownSid(sid, WinBuiltinUsersSid) != 0 {
                    assert!(expected_users);
                    assert_eq!(mask, 0x1200a9);
                    users = true;
                } else {
                    panic!("unexpected ACE principal");
                }
            }
        }
        assert!(system && admins);
        assert_eq!(users, expected_users);
    }

    #[test]
    fn install_tree_has_administrator_owner_and_expected_acls() {
        let admin = SecurityDescriptor::from_sddl("O:BA").unwrap();
        let mut is_admin = 0;
        // SAFETY: A null token asks the Windows system ABI for the effective
        // caller token; the SID is borrowed from the live descriptor, and the
        // membership output is a writable local for this synchronous call.
        assert_ne!(
            unsafe { CheckTokenMembership(ptr::null_mut(), admin.owner().unwrap(), &mut is_admin) },
            0
        );
        if is_admin == 0 {
            eprintln!("skipping elevated install ACL test without an administrator token");
            return;
        }
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "rosetun-install-acl-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("old.txt"), "test").unwrap();
        fs::create_dir(dir.join("data")).unwrap();
        fs::write(dir.join("data").join("old.log"), "test").unwrap();
        secure_install(&dir, false).unwrap();
        check_acl(&dir, true, true);
        check_acl(&dir.join("data"), false, true);
        // Existing files must lose stale ACLs and inherit from the safe parent.
        check_acl(&dir.join("old.txt"), true, false);
        check_acl(&dir.join("data").join("old.log"), false, false);
        secure_install(&dir.join("new"), false).unwrap();
        check_acl(&dir.join("new"), true, true);
        fs::create_dir(dir.join("oldempty")).unwrap();
        secure_install(&dir.join("oldempty"), true).unwrap();
        check_acl(&dir.join("oldempty"), true, true);
        fs::remove_dir_all(&dir).unwrap();
    }
}
