//! Hands a `rosetun://` link from a later GUI instance to the running one.
//! The link is as secret as the subscription, so the pipe is per user and
//! session, and the sender checks that the server is the same executable.

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsValidSid, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenSessionId,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_INBOUND, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

/// The longest link accepted over the pipe, the same bound as the link parser.
pub const MAX_LINK_BYTES: usize = 8 * 1024;
const PIPE_PREFIX: &str = r"\\.\pipe\Rosetun.Gui.Link";
const BUFFER_BYTES: u32 = MAX_LINK_BYTES as u32 + 4;
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_millis(50);

#[link(name = "kernel32")]
unsafe extern "system" {
    // windows-sys declares it behind the `Win32_System_IO` feature for
    // `OVERLAPPED`; this pipe is synchronous and passes null.
    fn ConnectNamedPipe(named_pipe: HANDLE, overlapped: *mut c_void) -> i32;
}

/// The first instance's end of the link pipe. Created early so the name is
/// taken before anything else can claim it.
#[derive(Debug)]
pub struct LinkListener {
    pipe: File,
}

impl LinkListener {
    pub fn bind() -> io::Result<Self> {
        Self::bind_named(&pipe_name()?)
    }

    fn bind_named(name: &str) -> io::Result<Self> {
        let user = current_user_sid()?;
        let descriptor = SecurityDescriptor::new(&format!("D:P(A;;GA;;;{user})"))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let name = wide(name);
        // SAFETY: The name and security attributes outlive the call. One
        // instance only, reused for every client, so the name stays taken.
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                0,
                BUFFER_BYTES,
                0,
                &attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateNamedPipeW returned a live handle owned from here on.
        let pipe = File::from(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) });
        Ok(Self { pipe })
    }

    /// Blocks, handing every link a later instance sends to `handler`. A
    /// malformed message closes that connection and waits for the next one.
    pub fn serve(self, mut handler: impl FnMut(String)) -> io::Result<()> {
        let handle = self.pipe.as_raw_handle() as HANDLE;
        loop {
            // SAFETY: The pipe handle stays live for the synchronous call.
            if unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) } == 0 {
                // SAFETY: Read right after the failed call on this thread.
                let error = unsafe { GetLastError() };
                // A client that already wrote and closed leaves its data readable.
                if error != ERROR_PIPE_CONNECTED && error != ERROR_NO_DATA {
                    return Err(io::Error::from_raw_os_error(error as i32));
                }
            }
            let link = read_message(&mut &self.pipe);
            // SAFETY: The pipe handle stays live; disconnecting drops whatever
            // the client left unread and frees the instance for the next one.
            if unsafe { DisconnectNamedPipe(handle) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if let Some(link) = link {
                handler(link);
            }
        }
    }
}

/// Sends `link` to the running instance, waiting up to 5 s while it starts.
/// Nothing is sent unless the pipe's server is this same executable.
pub fn send_link(link: &str) -> io::Result<()> {
    send_named(&pipe_name()?, link)
}

fn send_named(name: &str, link: &str) -> io::Result<()> {
    if link.len() > MAX_LINK_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the link is too long",
        ));
    }
    let mut pipe = open_pipe(name)?;
    let server = server_image(&pipe)?;
    if !same_executable(&server, &std::env::current_exe()?) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the link pipe belongs to another program",
        ));
    }
    let mut message = Vec::with_capacity(4 + link.len());
    message.extend_from_slice(&(link.len() as u32).to_le_bytes());
    message.extend_from_slice(link.as_bytes());
    pipe.write_all(&message)
}

fn open_pipe(name: &str) -> io::Result<File> {
    let deadline = Instant::now() + SEND_TIMEOUT;
    loop {
        match OpenOptions::new()
            .write(true)
            .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
            .open(name)
        {
            Ok(pipe) => return Ok(pipe),
            Err(error)
                if Instant::now() < deadline
                    && (error.kind() == io::ErrorKind::NotFound
                        || error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)) =>
            {
                std::thread::sleep(RETRY_DELAY);
            }
            Err(error) => return Err(error),
        }
    }
}

fn read_message(pipe: &mut impl Read) -> Option<String> {
    let mut length = [0; 4];
    pipe.read_exact(&mut length).ok()?;
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_LINK_BYTES {
        return None;
    }
    let mut link = vec![0; length];
    pipe.read_exact(&mut link).ok()?;
    String::from_utf8(link).ok()
}

/// Whether two executable paths name the same file, compared canonically
/// and without regard to case, as Windows paths are.
fn same_executable(left: &Path, right: &Path) -> bool {
    let (Ok(left), Ok(right)) = (left.canonicalize(), right.canonicalize()) else {
        return false;
    };
    left.as_os_str()
        .to_string_lossy()
        .to_lowercase()
        .eq(&right.as_os_str().to_string_lossy().to_lowercase())
}

fn server_image(pipe: &File) -> io::Result<PathBuf> {
    let mut pid = 0;
    // SAFETY: The connected pipe handle stays live and pid is writable.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcess takes the pipe server's process ID by value.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcess returned a live handle owned from here on.
    let process = unsafe { OwnedHandle::from_raw_handle(process as RawHandle) };
    let mut path = vec![0u16; 32 * 1024];
    let mut length = path.len() as u32;
    // SAFETY: The process handle is live and the buffer holds `length` units.
    if unsafe {
        QueryFullProcessImageNameW(
            process.as_raw_handle() as HANDLE,
            PROCESS_NAME_WIN32,
            path.as_mut_ptr(),
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    path.truncate(length as usize);
    Ok(PathBuf::from(String::from_utf16_lossy(&path)))
}

/// `\\.\pipe\Rosetun.Gui.Link.<SID>.<session>`: another user's or another
/// sign-in's GUI never receives the link.
fn pipe_name() -> io::Result<String> {
    let token = current_token()?;
    let mut session = 0u32;
    let mut length = 0;
    // SAFETY: The token is live and the output is sized for a session ID.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenSessionId,
            (&raw mut session).cast(),
            size_of::<u32>() as u32,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(format!("{PIPE_PREFIX}.{}.{session}", user_sid(&token)?))
}

fn current_user_sid() -> io::Result<String> {
    user_sid(&current_token()?)
}

fn current_token() -> io::Result<OwnedHandle> {
    let mut token = std::ptr::null_mut();
    // SAFETY: The pseudo handle needs no closing and the output is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned a live handle owned from here on.
    Ok(unsafe { OwnedHandle::from_raw_handle(token as RawHandle) })
}

fn user_sid(token: &OwnedHandle) -> io::Result<String> {
    let mut length = 0;
    // SAFETY: A null buffer and zero length ask for the required size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut length,
        )
    };
    if (length as usize) < size_of::<TOKEN_USER>() {
        return Err(io::Error::other("invalid token user"));
    }
    // usize gives TOKEN_USER and the SID it points to pointer alignment.
    let mut user = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    // SAFETY: The aligned buffer holds at least `length` bytes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            user.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetTokenInformation wrote TOKEN_USER at the start of the buffer.
    let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: The SID points into the live buffer.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::other("invalid token SID"));
    }
    let mut text = std::ptr::null_mut();
    // SAFETY: The valid SID lives in `user`; Windows allocates `text`, freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ConvertSidToStringSidW returned a null-terminated wide string.
    let length = (0..)
        .take_while(|&index| unsafe { *text.add(index) } != 0)
        .count();
    // SAFETY: `length` units before the terminator are initialised.
    let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    // SAFETY: The string was allocated by Windows and is freed exactly once.
    unsafe { LocalFree(text.cast()) };
    Ok(sid)
}

struct SecurityDescriptor(*mut c_void);

impl SecurityDescriptor {
    fn new(sddl: &str) -> io::Result<Self> {
        let sddl = wide(sddl);
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: The SDDL string and output pointer are valid for the call.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: Windows allocated the descriptor; it is freed exactly once.
        unsafe { LocalFree(self.0) };
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    fn test_name(tag: &str) -> String {
        format!("{PIPE_PREFIX}.Test.{tag}.{}", std::process::id())
    }

    fn serve_in_background(listener: LinkListener) -> mpsc::Receiver<String> {
        let (sender, links) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = listener.serve(|link| {
                let _ = sender.send(link);
            });
        });
        links
    }

    #[test]
    fn a_link_reaches_the_first_instance() {
        let name = test_name("Reach");
        let listener = LinkListener::bind_named(&name).unwrap();
        // Sent before the server starts reading, as while the first GUI loads.
        send_named(&name, "rosetun://add/https://example.com/sub").unwrap();
        let links = serve_in_background(listener);

        assert_eq!(
            links.recv_timeout(Duration::from_secs(5)).unwrap(),
            "rosetun://add/https://example.com/sub"
        );
        send_named(&name, "rosetun://add/https://example.com/other").unwrap();
        assert_eq!(
            links.recv_timeout(Duration::from_secs(5)).unwrap(),
            "rosetun://add/https://example.com/other"
        );
    }

    #[test]
    fn a_second_listener_cannot_take_the_name() {
        let name = test_name("Twice");
        let _listener = LinkListener::bind_named(&name).unwrap();

        assert!(LinkListener::bind_named(&name).is_err());
    }

    #[test]
    fn a_too_long_message_is_dropped() {
        let name = test_name("Long");
        let links = serve_in_background(LinkListener::bind_named(&name).unwrap());

        let mut pipe = open_pipe(&name).unwrap();
        pipe.write_all(&(MAX_LINK_BYTES as u32 + 1).to_le_bytes())
            .unwrap();
        let _ = pipe.write_all(&[b'a'; 64]);
        drop(pipe);
        assert!(send_named(&name, &"a".repeat(MAX_LINK_BYTES + 1)).is_err());
        send_named(&name, "rosetun://add/https://example.com/sub").unwrap();

        assert_eq!(
            links.recv_timeout(Duration::from_secs(5)).unwrap(),
            "rosetun://add/https://example.com/sub"
        );
    }

    #[test]
    fn only_the_same_executable_passes_the_server_check() {
        let exe = std::env::current_exe().unwrap();
        let upper = PathBuf::from(exe.to_string_lossy().to_uppercase());
        let other = std::env::temp_dir().join(format!("rosetun-other-{}.exe", std::process::id()));
        std::fs::write(&other, b"").unwrap();

        assert!(same_executable(&exe, &exe));
        assert!(same_executable(&upper, &exe));
        assert!(!same_executable(&other, &exe));
        assert!(!same_executable(&exe.with_file_name("missing.exe"), &exe));
        std::fs::remove_file(other).unwrap();
    }
}
