use std::ffi::{OsString, c_void};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetAclInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSID,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, GetDriveTypeW, GetFileAttributesW,
    GetVolumeInformationW, INVALID_FILE_ATTRIBUTES,
};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, REG_EXPAND_SZ, REG_SZ, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
    RRF_SUBKEY_WOW6464KEY, RegGetValueW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, FILE_PERSISTENT_ACLS, SYSTEM_ALARM_ACE_TYPE,
    SYSTEM_AUDIT_ACE_TYPE,
};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

use crate::data_dir;

const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const PROFILE_LIST_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
const HELPER_EXE: &str = "rosetun-helper-privileged.exe";

const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const DELETE: u32 = 0x0001_0000;
const FILE_DELETE_CHILD: u32 = 0x0000_0040;
const INHERIT_ONLY: u8 = 0x08;
const DANGEROUS: u32 =
    GENERIC_ALL | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER | DELETE | FILE_DELETE_CHILD;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    Path = 2,
    Drive = 3,
    Filesystem = 4,
    SystemFolder = 5,
    Reparse = 6,
    Owner = 7,
    Permissions = 8,
    Occupied = 9,
    Inspection = 10,
}

impl Reason {
    pub(crate) fn description(self) -> &'static str {
        match self {
            Self::Path => "invalid install path",
            Self::Drive => "not a local fixed drive",
            Self::Filesystem => "filesystem does not support persistent ACLs",
            Self::SystemFolder => "inside a user profile or Windows directory",
            Self::Reparse => "reparse point in install path",
            Self::Owner => "untrusted directory owner",
            Self::Permissions => "directory can be changed by a non-administrator",
            Self::Occupied => "directory is not empty or a Rosetun installation",
            Self::Inspection => "cannot inspect or secure install directory",
        }
    }
}

#[derive(Debug)]
pub(crate) struct Failure {
    pub(crate) reason: Reason,
    pub(crate) path: PathBuf,
    detail: Option<String>,
}

impl Failure {
    fn at(reason: Reason, path: &Path) -> Self {
        Self {
            reason,
            path: path.to_owned(),
            detail: None,
        }
    }

    pub(crate) fn message(&self) -> String {
        // An untrusted path or OS error must not inject extra log lines.
        let path = self.path.to_string_lossy();
        let mut message = format!("{}: {}", self.reason.description(), one_line(&path));
        if let Some(detail) = &self.detail {
            message.push_str(&format!(" ({})", one_line(detail)));
        }
        message
    }
}

pub(crate) fn one_line(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_control() {
                ch.escape_default().to_string()
            } else {
                ch.to_string()
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Principal {
    System,
    Administrators,
    TrustedInstaller,
    Other,
}

impl Principal {
    fn trusted(self) -> bool {
        self != Self::Other
    }
}

#[derive(Debug, Clone, Copy)]
struct Ace {
    allow: bool,
    principal: Principal,
    flags: u8,
    mask: u32,
}

#[derive(Debug, Clone)]
struct Component {
    path: PathBuf,
    reparse: bool,
    owner: Principal,
    aces: Vec<Ace>,
    target: bool,
    child: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Missing,
    Empty,
    ExistingInstall,
    Occupied,
    Service,
}

#[derive(Debug, Clone)]
struct Facts {
    path: PathBuf,
    drive_fixed: bool,
    persistent_acls: bool,
    excluded_roots: Vec<PathBuf>,
    components: Vec<Component>,
    target: Target,
}

fn normalize_path(raw: &Path) -> Result<PathBuf, Failure> {
    let invalid = || Failure::at(Reason::Path, raw);
    let path = raw.to_str().ok_or_else(invalid)?.replace('/', "\\");
    let bytes = path.as_bytes();
    if bytes.len() < 4 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err(invalid());
    }
    let mut parts = Vec::new();
    for part in path[3..].split('\\') {
        if part.is_empty() {
            continue;
        }
        if part == "."
            || part == ".."
            || part.ends_with(&['.', ' '][..])
            || part
                .chars()
                .any(|ch| ch.is_control() || matches!(ch, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        {
            return Err(invalid());
        }
        let stem = part.split('.').next().unwrap_or_default();
        if [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ]
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
        {
            return Err(invalid());
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return Err(invalid());
    }
    Ok(PathBuf::from(format!(
        "{}:\\{}",
        (bytes[0] as char).to_ascii_uppercase(),
        parts.join("\\")
    )))
}

fn within(path: &Path, parent: &Path) -> bool {
    let path = path.to_string_lossy();
    let parent = parent.to_string_lossy();
    let prefix = parent.trim_end_matches('\\');
    path.eq_ignore_ascii_case(prefix)
        || (path
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
            && path.as_bytes().get(prefix.len()) == Some(&b'\\'))
}

fn decide(facts: &Facts) -> Result<(), Failure> {
    let path = &facts.path;
    if !facts.drive_fixed {
        return Err(Failure::at(Reason::Drive, path));
    }
    if !facts.persistent_acls {
        return Err(Failure::at(Reason::Filesystem, path));
    }
    if facts.excluded_roots.iter().any(|root| within(path, root)) {
        return Err(Failure::at(Reason::SystemFolder, path));
    }
    for component in &facts.components {
        if component.reparse {
            return Err(Failure::at(Reason::Reparse, &component.path));
        }
        if component.target && matches!(facts.target, Target::Empty | Target::Occupied) {
            continue;
        }
        if !component.owner.trusted() {
            return Err(Failure::at(Reason::Owner, &component.path));
        }
        if component.aces.iter().any(|ace| {
            ace.allow
                && !ace.principal.trusted()
                && ace.flags & INHERIT_ONLY == 0
                && ace.mask
                    & (DANGEROUS
                        | if component.child {
                            0x0000_0116
                        } else if component.target {
                            0x0000_0006
                        } else {
                            0
                        })
                    != 0
        }) {
            return Err(Failure::at(Reason::Permissions, &component.path));
        }
    }
    if facts.target == Target::Occupied {
        return Err(Failure::at(Reason::Occupied, path));
    }
    Ok(())
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: LocalFree uses the Windows system ABI and releases this one
        // LocalAlloc-owned result after all borrowed SID/ACL pointers are gone.
        unsafe { LocalFree(self.0) };
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn wide_str(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn inspection(path: &Path, error: impl std::fmt::Display) -> Failure {
    let mut failure = Failure::at(Reason::Inspection, path);
    failure.detail = Some(error.to_string());
    failure
}

fn status(path: &Path, code: u32) -> Failure {
    inspection(path, io::Error::from_raw_os_error(code as i32))
}

fn attributes(path: &Path) -> Result<Option<u32>, Failure> {
    let name = wide(path);
    // SAFETY: The UTF-16 path is NUL-terminated and stays live during this
    // synchronous Windows ABI call. No ownership transfers to Windows.
    let value = unsafe { GetFileAttributesW(name.as_ptr()) };
    if value != INVALID_FILE_ATTRIBUTES {
        return Ok(Some(value));
    }
    let error = io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(code) if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32)
    {
        Ok(None)
    } else {
        Err(inspection(path, error))
    }
}

fn trusted_installer_sid(path: &Path) -> Result<LocalAllocation, Failure> {
    let mut sid: PSID = ptr::null_mut();
    let value = wide_str(TRUSTED_INSTALLER_SID);
    // SAFETY: The SID text is NUL-terminated, its storage and the writable
    // output pointer live for this Windows ABI call. LocalFree owns the result.
    if unsafe { ConvertStringSidToSidW(value.as_ptr(), &mut sid) } == 0 {
        return Err(inspection(path, io::Error::last_os_error()));
    }
    if sid.is_null() {
        return Err(inspection(path, "missing TrustedInstaller SID"));
    }
    Ok(LocalAllocation(sid))
}

fn principal(sid: PSID, installer: &LocalAllocation) -> Principal {
    // SAFETY: The SID is bounds-checked in its ACE (or borrowed from the live
    // descriptor), and installer owns its SID throughout these Windows ABI calls.
    unsafe {
        if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
            Principal::System
        } else if IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 {
            Principal::Administrators
        } else if EqualSid(sid, installer.0) != 0 {
            Principal::TrustedInstaller
        } else {
            Principal::Other
        }
    }
}

#[derive(Debug)]
struct ParsedAce<'a> {
    allow: bool,
    flags: u8,
    mask: u32,
    sid: &'a [u8],
}

fn parse_ace(bytes: &[u8]) -> Result<Option<ParsedAce<'_>>, &'static str> {
    if bytes.len() < 4 || usize::from(u16::from_le_bytes([bytes[2], bytes[3]])) != bytes.len() {
        return Err("invalid ACE size");
    }
    let ace_type = u32::from(bytes[0]);
    if matches!(ace_type, SYSTEM_AUDIT_ACE_TYPE | SYSTEM_ALARM_ACE_TYPE) {
        return Ok(None);
    }
    if !matches!(ace_type, ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE) || bytes.len() < 16 {
        return Err("unsupported ACE type");
    }
    let sid_size = 8usize + 4 * usize::from(bytes[9]);
    if bytes[8] != 1 || sid_size > bytes.len() - 8 {
        return Err("invalid ACE SID");
    }
    let mask = u32::from_le_bytes(bytes[4..8].try_into().expect("four mask bytes"));
    Ok(Some(ParsedAce {
        allow: ace_type == ACCESS_ALLOWED_ACE_TYPE,
        flags: bytes[1],
        mask,
        sid: &bytes[8..8 + sid_size],
    }))
}

fn security(path: &Path, installer: &LocalAllocation) -> Result<(Principal, Vec<Ace>), Failure> {
    let name = wide(path);
    let mut owner: PSID = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: The NUL-terminated path and all writable outputs stay live for
    // this Windows ABI call. owner/DACL are borrowed from the descriptor,
    // which is released once by LocalFree after ACE inspection.
    let code = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(status(path, code));
    }
    if descriptor.is_null() {
        return Err(inspection(path, "missing security descriptor"));
    }
    let _descriptor = LocalAllocation(descriptor);
    if owner.is_null() || dacl.is_null() {
        return Err(inspection(path, "missing owner or DACL"));
    }
    let owner = principal(owner, installer);
    let mut size = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    // SAFETY: The DACL is borrowed from a live Windows descriptor. The output
    // struct is initialized, sized exactly and writable for this ABI call.
    let success = unsafe {
        GetAclInformation(
            dacl,
            (&raw mut size).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if success == 0 {
        return Err(inspection(path, io::Error::last_os_error()));
    }
    let mut aces = Vec::new();
    for index in 0..size.AceCount {
        let mut raw: *mut c_void = ptr::null_mut();
        // SAFETY: The DACL remains owned by the live descriptor and index is
        // below the reported count. GetAce borrows, not transfers, its pointer.
        if unsafe { GetAce(dacl, index, &mut raw) } == 0 || raw.is_null() {
            return Err(inspection(path, io::Error::last_os_error()));
        }
        // SAFETY: GetAce returned a valid pointer to at least an ACE_HEADER.
        // Read individual bytes to avoid assuming alignment for arbitrary ACEs.
        let header = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), 4) };
        let ace_size = u16::from_le_bytes([header[2], header[3]]) as usize;
        let offset = (raw as usize).checked_sub(dacl as usize);
        if ace_size < 4
            || offset
                .and_then(|start| start.checked_add(ace_size))
                .is_none_or(|end| end > size.AclBytesInUse as usize)
        {
            return Err(inspection(path, "invalid ACE bounds"));
        }
        // SAFETY: The ACE range is inside the borrowed ACL as reported by
        // GetAclInformation, and its descriptor stays live through this ABI read.
        let bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), ace_size) };
        let Some(ace) = parse_ace(bytes).map_err(|error| inspection(path, error))? else {
            continue;
        };
        // SAFETY: The complete SID slice was checked to lie inside the live
        // ACE; IsWellKnownSid/EqualSid borrow it only during this ABI call.
        let sid = ace.sid.as_ptr().cast_mut().cast();
        aces.push(Ace {
            allow: ace.allow,
            principal: principal(sid, installer),
            flags: ace.flags,
            mask: ace.mask,
        });
    }
    Ok((owner, aces))
}

fn windows_root(candidate: &Path) -> Result<PathBuf, Failure> {
    let mut buffer = vec![0u16; 260];
    for _ in 0..4 {
        // SAFETY: The initialized UTF-16 vector is writable and remains live
        // during the Windows ABI call; its capacity is passed in wide units.
        let length = unsafe { GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) }
            as usize;
        if length == 0 {
            return Err(inspection(candidate, io::Error::last_os_error()));
        }
        if length < buffer.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buffer[..length])));
        }
        buffer.resize(length + 1, 0);
    }
    Err(inspection(
        candidate,
        "Windows directory changed during inspection",
    ))
}

fn profiles_root(candidate: &Path, windows: &Path) -> Result<PathBuf, Failure> {
    let key = wide_str(PROFILE_LIST_KEY);
    let value = wide_str("ProfilesDirectory");
    for _ in 0..4 {
        let mut kind = 0;
        let mut length = 0;
        let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND | RRF_SUBKEY_WOW6464KEY;
        // SAFETY: HKLM is a borrowed predefined handle; NUL-terminated names
        // and the writable type/length locals live for this Windows ABI call.
        let code = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                flags,
                &mut kind,
                ptr::null_mut(),
                &mut length,
            )
        };
        if code != ERROR_SUCCESS && code != ERROR_MORE_DATA {
            return Err(status(candidate, code));
        }
        if !(2..=64 * 1024).contains(&length) || length % 2 != 0 {
            return Err(inspection(candidate, "invalid ProfilesDirectory length"));
        }
        let mut bytes = vec![0u8; length as usize];
        let mut used = length;
        // SAFETY: The output byte buffer is initialized and writable for the
        // supplied size; both NUL-terminated names and the borrowed HKLM handle
        // remain valid throughout this synchronous Windows ABI call.
        let code = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                flags,
                &mut kind,
                bytes.as_mut_ptr().cast(),
                &mut used,
            )
        };
        if code == ERROR_MORE_DATA {
            continue;
        }
        if code != ERROR_SUCCESS {
            return Err(status(candidate, code));
        }
        if used < 2 || used > length || used % 2 != 0 || (kind != REG_SZ && kind != REG_EXPAND_SZ) {
            return Err(inspection(candidate, "invalid ProfilesDirectory value"));
        }
        let units: Vec<u16> = bytes[..used as usize]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let text = String::from_utf16(&units[..units.len() - 1])
            .map_err(|error| inspection(candidate, error))?;
        if units.last() != Some(&0) || text.contains('\0') {
            return Err(inspection(candidate, "malformed ProfilesDirectory string"));
        }
        // Avoid environment overrides supplied by the process invoking setup.
        // Windows expands %SystemDrive% to the drive containing Windows here.
        let drive = windows
            .to_str()
            .and_then(|text| text.get(..2))
            .ok_or_else(|| inspection(candidate, "invalid Windows drive"))?;
        let expanded = if text
            .get(..13)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("%SystemDrive%"))
        {
            format!("{}{}", drive, &text[13..])
        } else {
            text
        };
        if expanded.contains('%') {
            return Err(inspection(
                candidate,
                "unsupported ProfilesDirectory variable",
            ));
        }
        return normalize_path(Path::new(&expanded))
            .map_err(|_| inspection(candidate, "invalid ProfilesDirectory path"));
    }
    Err(inspection(
        candidate,
        "ProfilesDirectory changed during inspection",
    ))
}

fn canonical(path: &Path, candidate: &Path) -> Result<PathBuf, Failure> {
    let result = std::fs::canonicalize(path).map_err(|error| inspection(candidate, error))?;
    let name = result
        .to_str()
        .ok_or_else(|| inspection(candidate, "invalid canonical path"))?;
    let name = name.strip_prefix(r"\\?\").unwrap_or(name);
    if name.starts_with(r"UNC\") {
        return Err(Failure::at(Reason::Drive, candidate));
    }
    Ok(PathBuf::from(name))
}

fn collect_children(facts: &mut Facts, installer: &LocalAllocation) -> Result<(), Failure> {
    let mut pending = vec![facts.path.clone()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).map_err(|error| inspection(&dir, error))? {
            let path = entry.map_err(|error| inspection(&dir, error))?.path();
            let attrs =
                attributes(&path)?.ok_or_else(|| inspection(&path, "install file disappeared"))?;
            if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(Failure::at(Reason::Reparse, &path));
            }
            let (owner, aces) = security(&path, installer)?;
            facts.components.push(Component {
                path: path.clone(),
                reparse: false,
                owner,
                aces,
                target: false,
                child: true,
            });
            if facts.components.len() > 100_000 {
                return Err(inspection(&path, "install tree is too large to inspect"));
            }
            if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
                pending.push(path);
            }
        }
    }
    Ok(())
}

fn collect(path: &Path, include_contents: bool, check_children: bool) -> Result<Facts, Failure> {
    let path = normalize_path(path)?;
    let root = PathBuf::from(&path.to_str().expect("normalized path")[..3]);
    let root_wide = wide(&root);
    // SAFETY: The drive root is NUL-terminated and lives for the Windows ABI
    // call. GetDriveTypeW does not retain any pointer.
    let drive = unsafe { GetDriveTypeW(root_wide.as_ptr()) } == DRIVE_FIXED;
    if !drive {
        return Err(Failure::at(Reason::Drive, &root));
    }
    let mut fs_flags = 0;
    // SAFETY: The NUL-terminated root and writable flags live for the call;
    // null output pointers request no volume name or serial information.
    let fs_ok = unsafe {
        GetVolumeInformationW(
            root_wide.as_ptr(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut fs_flags,
            ptr::null_mut(),
            0,
        )
    } != 0;
    if !fs_ok {
        return Err(inspection(&root, io::Error::last_os_error()));
    }
    if fs_flags & FILE_PERSISTENT_ACLS == 0 {
        return Err(Failure::at(Reason::Filesystem, &root));
    }
    let windows = windows_root(&path)?;
    let profiles = profiles_root(&path, &windows)?;
    let canonical_root = canonical(&root, &path)?;
    if !canonical_root
        .to_string_lossy()
        .eq_ignore_ascii_case(&root.to_string_lossy())
    {
        return Err(Failure::at(Reason::Drive, &root));
    }
    let canonical_path = canonical_root.join(
        path.strip_prefix(&root)
            .map_err(|error| inspection(&path, error))?,
    );
    let system = canonical(&windows, &path)?;
    let users = canonical(&profiles, &path)?;
    let mut facts = Facts {
        path: canonical_path,
        drive_fixed: drive,
        persistent_acls: fs_flags & FILE_PERSISTENT_ACLS != 0,
        excluded_roots: vec![system, users],
        components: Vec::new(),
        target: Target::Missing,
    };
    // Evaluate the cheaper, higher-priority facts before touching any child.
    decide(&facts)?;
    let installer = trusted_installer_sid(&path)?;
    let mut current = root;
    let mut missing = false;
    let segments: Vec<_> = path
        .strip_prefix(&current)
        .map_err(|error| inspection(&path, error))?
        .components()
        .map(|part| part.as_os_str().to_owned())
        .collect();
    for (index, part) in std::iter::once(None)
        .chain(segments.iter().map(Some))
        .enumerate()
    {
        if let Some(part) = part {
            current.push(part);
        }
        if missing {
            continue;
        }
        let Some(attrs) = attributes(&current)? else {
            missing = true;
            continue;
        };
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Failure::at(Reason::Reparse, &current));
        }
        if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(inspection(
                &current,
                "install path component is not a directory",
            ));
        }
        let resolved = canonical(&current, &current)?;
        if facts
            .excluded_roots
            .iter()
            .any(|root| within(&resolved, root))
        {
            return Err(Failure::at(Reason::SystemFolder, &current));
        }
        let is_target = index == segments.len();
        if is_target && include_contents {
            let mut entries =
                std::fs::read_dir(&current).map_err(|error| inspection(&current, error))?;
            facts.target = if entries
                .next()
                .transpose()
                .map_err(|error| inspection(&current, error))?
                .is_none()
            {
                Target::Empty
            } else if attributes(&current.join(HELPER_EXE))?.is_some() {
                Target::ExistingInstall
            } else {
                Target::Occupied
            };
        }
        let (owner, aces) = if is_target && matches!(facts.target, Target::Empty | Target::Occupied)
        {
            (Principal::Other, Vec::new())
        } else {
            security(&current, &installer)?
        };
        facts.components.push(Component {
            path: current.clone(),
            reparse: false,
            owner,
            aces,
            target: is_target,
            child: false,
        });
    }
    if !include_contents {
        if missing {
            return Err(inspection(&path, "service install directory is missing"));
        }
        facts.target = Target::Service;
    }
    decide(&facts)?;
    if check_children && matches!(facts.target, Target::ExistingInstall | Target::Service) {
        collect_children(&mut facts, &installer)?;
        decide(&facts)?;
    }
    Ok(facts)
}

pub(crate) fn verify(path: &Path, include_contents: bool) -> Result<(), Failure> {
    collect(path, include_contents, true).map(|_| ())
}

pub(crate) fn secure(path: &Path) -> Result<(), Failure> {
    let facts = collect(path, true, true)?;
    data_dir::secure_install(&facts.path, facts.target == Target::Empty)
        .map_err(|error| inspection(&facts.path, error))?;
    verify(&facts.path, false)
}

pub(crate) fn finalize(path: &Path) -> Result<(), Failure> {
    // Setup has already verified and secured the tree before copying files.
    // Freshly copied files can have the elevated user's SID as owner; repair
    // their ownership before the service is allowed to execute any of them.
    let facts = collect(path, false, false)?;
    data_dir::secure_install(&facts.path, false).map_err(|error| inspection(&facts.path, error))?;
    verify(&facts.path, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            path: PathBuf::from(r"D:\Example\Rosetun"),
            drive_fixed: true,
            persistent_acls: true,
            excluded_roots: vec![PathBuf::from(r"C:\Users"), PathBuf::from(r"C:\Windows")],
            components: vec![Component {
                path: PathBuf::from(r"D:\"),
                reparse: false,
                owner: Principal::Administrators,
                aces: vec![Ace {
                    allow: true,
                    principal: Principal::Other,
                    flags: 0,
                    mask: 0x0000_0004, // FILE_ADD_SUBDIRECTORY
                }],
                target: false,
                child: false,
            }],
            target: Target::Missing,
        }
    }

    fn fails(facts: Facts, reason: Reason) {
        assert_eq!(decide(&facts).unwrap_err().reason, reason);
    }

    #[test]
    fn diagnostic_path_cannot_inject_log_lines() {
        assert_eq!(one_line("D:\\Example\\Ro\nsetun"), r"D:\Example\Ro\nsetun");
    }

    #[test]
    fn path_must_be_a_normal_drive_absolute_directory_below_the_root() {
        for path in [
            r"D:\",
            r"D:Rosetun",
            r"\\server\share\Rosetun",
            r"\\?\D:\Rosetun",
            r"D:\Example\..\Rosetun",
            r"D:\Example\CON",
            r"D:\Example\Rosetun.",
            r"D:\Example\Rosetun:stream",
        ] {
            assert_eq!(
                normalize_path(Path::new(path)).unwrap_err().reason,
                Reason::Path,
                "{path}"
            );
        }
        assert_eq!(
            normalize_path(Path::new(r"d:\Example\\Rosetun\")).unwrap(),
            PathBuf::from(r"D:\Example\Rosetun")
        );
    }

    #[test]
    fn unknown_and_malformed_aces_fail_closed() {
        let mut ace = [0u8; 16];
        ace[2..4].copy_from_slice(&16u16.to_le_bytes());
        ace[8] = 1; // SID revision
        assert!(parse_ace(&ace).unwrap().is_some());
        ace[0] = 0xff;
        assert_eq!(parse_ace(&ace).unwrap_err(), "unsupported ACE type");
        ace[0] = 0;
        ace[9] = 8;
        assert_eq!(parse_ace(&ace).unwrap_err(), "invalid ACE SID");
        ace[9] = 0;
        ace[2] = 15;
        assert_eq!(parse_ace(&ace).unwrap_err(), "invalid ACE size");
    }

    #[test]
    fn safe_root_allows_creating_a_subdirectory() {
        assert!(decide(&facts()).is_ok());
    }

    #[test]
    fn only_fixed_acl_capable_drives_are_accepted() {
        let mut case = facts();
        case.drive_fixed = false;
        fails(case, Reason::Drive);
        let mut case = facts();
        case.persistent_acls = false;
        fails(case, Reason::Filesystem);
    }

    #[test]
    fn profile_and_system_roots_match_whole_components_without_case() {
        let mut case = facts();
        case.path = PathBuf::from(r"c:\USERS\Example\Rosetun");
        fails(case, Reason::SystemFolder);
        let mut case = facts();
        case.path = PathBuf::from(r"c:\wInDoWs\Rosetun");
        fails(case, Reason::SystemFolder);
        let mut case = facts();
        case.path = PathBuf::from(r"C:\Users2\Rosetun");
        assert!(decide(&case).is_ok());
    }

    #[test]
    fn reparse_points_and_untrusted_owners_are_rejected() {
        let mut case = facts();
        case.components[0].reparse = true;
        fails(case, Reason::Reparse);
        let mut case = facts();
        case.components[0].owner = Principal::Other;
        fails(case, Reason::Owner);
        for principal in [
            Principal::System,
            Principal::Administrators,
            Principal::TrustedInstaller,
        ] {
            let mut case = facts();
            case.components[0].owner = principal;
            assert!(decide(&case).is_ok());
        }
    }

    #[test]
    fn dangerous_aces_must_apply_to_the_parent_itself() {
        let mut case = facts();
        case.components[0].aces[0].mask = GENERIC_WRITE | DELETE;
        case.components[0].aces[0].flags = INHERIT_ONLY;
        assert!(decide(&case).is_ok());
        case.components[0].aces[0].flags = 0;
        fails(case, Reason::Permissions);
        for mask in [
            GENERIC_ALL,
            GENERIC_WRITE,
            WRITE_DAC,
            WRITE_OWNER,
            DELETE,
            FILE_DELETE_CHILD,
        ] {
            let mut case = facts();
            case.components[0].aces[0].mask = mask;
            fails(case, Reason::Permissions);
        }
        let mut case = facts();
        case.components[0].aces[0].allow = false;
        case.components[0].aces[0].mask = GENERIC_ALL;
        assert!(decide(&case).is_ok());
    }

    #[test]
    fn empty_target_is_resecured_but_an_existing_install_must_be_safe() {
        let mut case = facts();
        case.target = Target::Empty;
        case.components.push(Component {
            path: case.path.clone(),
            reparse: false,
            owner: Principal::Other,
            aces: vec![Ace {
                allow: true,
                principal: Principal::Other,
                flags: 0,
                mask: GENERIC_ALL,
            }],
            target: true,
            child: false,
        });
        assert!(decide(&case).is_ok());
        case.components[1].reparse = true;
        fails(case.clone(), Reason::Reparse);
        case.components[1].reparse = false;
        case.target = Target::Occupied;
        fails(case, Reason::Occupied);
        let mut case = facts();
        case.target = Target::ExistingInstall;
        case.components.push(Component {
            path: case.path.clone(),
            reparse: false,
            owner: Principal::Administrators,
            aces: vec![Ace {
                allow: true,
                principal: Principal::Other,
                flags: 0,
                mask: GENERIC_WRITE,
            }],
            target: true,
            child: false,
        });
        fails(case.clone(), Reason::Permissions);
        case.components[1].aces[0].mask = 0x0000_0002; // FILE_ADD_FILE
        fails(case.clone(), Reason::Permissions);
        case.target = Target::Service;
        fails(case.clone(), Reason::Permissions);
        case.components[1].aces.clear();
        assert!(decide(&case).is_ok());
    }

    #[test]
    fn previous_install_contents_must_not_allow_writes_or_user_ownership() {
        let mut case = facts();
        case.target = Target::ExistingInstall;
        case.components.push(Component {
            path: case.path.join("sing-box.exe"),
            reparse: false,
            owner: Principal::Administrators,
            aces: vec![Ace {
                allow: true,
                principal: Principal::Other,
                flags: 0,
                mask: 0x0000_0002, // FILE_WRITE_DATA
            }],
            target: false,
            child: true,
        });
        fails(case.clone(), Reason::Permissions);
        case.components[1].aces[0].flags = INHERIT_ONLY;
        assert!(decide(&case).is_ok());
        case.components[1].owner = Principal::Other;
        fails(case.clone(), Reason::Owner);
        case.components[1].reparse = true;
        fails(case, Reason::Reparse);
    }
}
