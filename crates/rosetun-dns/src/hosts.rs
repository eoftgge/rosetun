//! The hosts file, which the system resolver reads before any server.

use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;

/// More than any real hosts file; ad-blocking lists stay far below it.
const MAX_HOSTS_BYTES: u64 = 16 * 1024 * 1024;

fn path() -> PathBuf {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

/// The addresses the hosts file gives `name` (lowercase, no trailing dot).
pub(crate) fn lookup(name: &str) -> Vec<IpAddr> {
    let Ok(file) = std::fs::File::open(path()) else {
        return Vec::new();
    };
    let mut bytes = Vec::new();
    if file.take(MAX_HOSTS_BYTES).read_to_end(&mut bytes).is_err() {
        return Vec::new();
    }
    find(&String::from_utf8_lossy(&bytes), name)
}

fn find(text: &str, name: &str) -> Vec<IpAddr> {
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut fields = line.split_whitespace();
        let Some(Ok(address)) = fields.next().map(str::parse::<IpAddr>) else {
            continue;
        };
        if fields.any(|host| host.trim_end_matches('.').eq_ignore_ascii_case(name))
            && !found.contains(&address)
        {
            found.push(address);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::find;

    #[test]
    fn names_are_matched_case_insensitively_with_aliases_and_comments() {
        let text = "\
# 192.0.2.1 node.example.com
192.0.2.2\tNode.Example.com alias.example.com # comment
  2001:db8::5   node.example.com.
192.0.2.2 node.example.com
not-an-address node.example.com
198.51.100.3 other.example.com#node.example.com
";
        assert_eq!(
            find(text, "node.example.com"),
            [
                "192.0.2.2".parse::<IpAddr>().unwrap(),
                "2001:db8::5".parse().unwrap()
            ]
        );
        assert_eq!(
            find(text, "alias.example.com"),
            ["192.0.2.2".parse::<IpAddr>().unwrap()]
        );
        assert!(find(text, "missing.example.com").is_empty());
        assert!(find(text, "example.com").is_empty());
    }
}
