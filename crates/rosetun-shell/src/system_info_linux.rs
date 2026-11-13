//! What a support report says about the machine on Linux: the local time for the file
//! name, and the distribution and kernel for the versions block.

use std::mem::MaybeUninit;

const OS_RELEASE: [&str; 2] = ["/etc/os-release", "/usr/lib/os-release"];
const KERNEL_RELEASE: &str = "/proc/sys/kernel/osrelease";

/// `YYYYMMDD-HHMM` in local time, as on Windows.
pub fn local_report_timestamp() -> String {
    // SAFETY: `time` with a null pointer only returns the current time.
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    let mut local = MaybeUninit::<libc::tm>::uninit();
    // SAFETY: `localtime_r` writes a complete `tm` into the buffer we give it and
    // returns null on failure, which is checked before the buffer is read.
    let local = unsafe {
        if libc::localtime_r(&raw const now, local.as_mut_ptr()).is_null() {
            return "unknown-time".to_owned();
        }
        local.assume_init()
    };
    format!(
        "{:04}{:02}{:02}-{:02}{:02}",
        local.tm_year + 1900,
        local.tm_mon + 1,
        local.tm_mday,
        local.tm_hour,
        local.tm_min
    )
}

/// The distribution and the kernel, such as `Debian GNU/Linux 13 (trixie), kernel 6.12.9`.
/// No host name and no machine identifier.
pub fn os_description() -> Option<String> {
    let name = OS_RELEASE
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| pretty_name(&text));
    let kernel = std::fs::read_to_string(KERNEL_RELEASE)
        .ok()
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty());
    match (name, kernel) {
        (Some(name), Some(kernel)) => Some(format!("{name}, kernel {kernel}")),
        (Some(name), None) => Some(name),
        (None, Some(kernel)) => Some(format!("Linux, kernel {kernel}")),
        (None, None) => None,
    }
}

fn pretty_name(os_release: &str) -> Option<String> {
    let value = os_release
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))?;
    let value = value.trim().trim_matches(['"', '\'']);
    // The file is shell syntax; a value that needs an escape is not worth guessing at.
    (!value.is_empty() && !value.contains('\\')).then(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pretty_name_is_read_without_quotes() {
        assert_eq!(
            pretty_name(
                "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n"
            )
            .as_deref(),
            Some("Debian GNU/Linux 13 (trixie)")
        );
        assert_eq!(pretty_name("NAME=Arch\n"), None);
        assert_eq!(pretty_name("PRETTY_NAME=\"a\\\"b\"\n"), None);
    }

    #[test]
    fn the_timestamp_has_the_shape_of_the_windows_one() {
        let stamp = local_report_timestamp();
        assert_eq!(stamp.len(), 13, "{stamp}");
        assert_eq!(stamp.as_bytes()[8], b'-');
        assert!(stamp.bytes().filter(u8::is_ascii_digit).count() == 12);
    }

    #[test]
    fn this_machine_describes_itself() {
        assert!(os_description().is_some());
    }
}
