//! cgroup v2 leaves of the helper's systemd unit (Linux).
//!
//! The kill switch tells engines from everything else by the cgroup of the
//! socket. systemd gives the service a cgroup of its own and, with
//! `Delegate=yes`, hands its subtree to the helper. In cgroup v2 processes
//! live only in leaves once the subtree is used, so the helper makes two:
//! `helper` for itself and `engines` for the engines it starts. Paths here
//! end up in nftables rules, so every component is checked against a strict
//! pattern before a path exists at all.

use std::fmt;
use std::path::{Path, PathBuf};

/// The unit whose cgroup the helper manages. Another unit's cgroup (a
/// terminal session's, say) is never treated as the helper's: permitting it
/// would open the network to everything in that session.
pub const UNIT: &str = "rosetun-helper.service";
pub const HELPER_LEAF: &str = "helper";
pub const ENGINES_LEAF: &str = "engines";
/// Where the unified hierarchy is mounted.
pub const MOUNT: &str = "/sys/fs/cgroup";

const MAX_COMPONENT_BYTES: usize = 255;
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CgroupError {
    #[error("the process is not in a pure cgroup v2 hierarchy")]
    NotUnified,
    #[error("invalid cgroup path")]
    InvalidPath,
    #[error("the helper does not run in the cgroup of {UNIT}")]
    NotOurUnit,
}

/// A path in the cgroup hierarchy, from its root. Components are limited
/// to `[A-Za-z0-9_.@:-]`, never `.` or `..`, so the path can go into a rule
/// and onto the file system as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupPath {
    components: Vec<String>,
}

impl CgroupPath {
    /// Parses an absolute path such as `/system.slice/rosetun-helper.service`.
    pub fn parse(path: &str) -> Result<Self, CgroupError> {
        let rest = path.strip_prefix('/').ok_or(CgroupError::InvalidPath)?;
        if rest.is_empty() {
            return Ok(Self {
                components: Vec::new(),
            });
        }
        let components = rest
            .split('/')
            .map(|component| {
                valid_component(component)
                    .then(|| component.to_owned())
                    .ok_or(CgroupError::InvalidPath)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if components.len() > MAX_DEPTH {
            return Err(CgroupError::InvalidPath);
        }
        Ok(Self { components })
    }

    /// How deep the path lies: the root is 0. nftables' `socket cgroupv2
    /// level` takes this number.
    pub fn level(&self) -> usize {
        self.components.len()
    }

    pub fn last(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }

    pub fn parent(&self) -> Option<Self> {
        let (_, rest) = self.components.split_last()?;
        Some(Self {
            components: rest.to_vec(),
        })
    }

    pub fn child(&self, name: &str) -> Result<Self, CgroupError> {
        if !valid_component(name) || self.components.len() >= MAX_DEPTH {
            return Err(CgroupError::InvalidPath);
        }
        let mut components = self.components.clone();
        components.push(name.to_owned());
        Ok(Self { components })
    }

    /// The path without the leading slash, as nftables wants it.
    pub fn relative(&self) -> String {
        self.components.join("/")
    }

    /// The folder of this cgroup under the mount point.
    pub fn under(&self, mount: &Path) -> PathBuf {
        let mut path = mount.to_path_buf();
        path.extend(&self.components);
        path
    }
}

impl fmt::Display for CgroupPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{}", self.relative())
    }
}

/// The unit's cgroup and the two leaves below it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaves {
    pub service: CgroupPath,
    pub helper: CgroupPath,
    pub engines: CgroupPath,
}

impl Leaves {
    /// From the helper's own cgroup: the unit's cgroup itself (before the
    /// helper moved into its leaf) or the `helper` leaf below it.
    pub fn of(own: &CgroupPath) -> Result<Self, CgroupError> {
        let service = match own.last() {
            Some(UNIT) => own.clone(),
            Some(HELPER_LEAF) => own
                .parent()
                .filter(|parent| parent.last() == Some(UNIT))
                .ok_or(CgroupError::NotOurUnit)?,
            _ => return Err(CgroupError::NotOurUnit),
        };
        Ok(Self {
            helper: service.child(HELPER_LEAF)?,
            engines: service.child(ENGINES_LEAF)?,
            service,
        })
    }
}

/// Reads `/proc/self/cgroup`. Under the unified hierarchy it holds exactly
/// one line, `0::<path>`; a hybrid or legacy setup has more, and is refused.
pub fn own_cgroup(text: &str) -> Result<CgroupPath, CgroupError> {
    let mut lines = text.lines().filter(|line| !line.is_empty());
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return Err(CgroupError::NotUnified);
    };
    let path = line.strip_prefix("0::").ok_or(CgroupError::NotUnified)?;
    CgroupPath::parse(path)
}

fn valid_component(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= MAX_COMPONENT_BYTES
        && component != "."
        && component != ".."
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'@' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: &str = "/system.slice/rosetun-helper.service";

    #[test]
    fn the_unified_hierarchy_gives_the_helpers_cgroup() {
        let own = own_cgroup("0::/system.slice/rosetun-helper.service\n").unwrap();
        assert_eq!(own.to_string(), SERVICE);
        assert_eq!(own.level(), 2);
    }

    #[test]
    fn a_hybrid_or_legacy_hierarchy_is_refused() {
        let hybrid = "12:pids:/system.slice/x.service\n0::/system.slice/x.service\n";
        assert_eq!(own_cgroup(hybrid), Err(CgroupError::NotUnified));
        assert_eq!(
            own_cgroup("1:name=systemd:/user.slice\n"),
            Err(CgroupError::NotUnified)
        );
        assert_eq!(own_cgroup(""), Err(CgroupError::NotUnified));
    }

    #[test]
    fn leaves_lie_below_the_units_cgroup() {
        let leaves = Leaves::of(&CgroupPath::parse(SERVICE).unwrap()).unwrap();
        assert_eq!(leaves.service.to_string(), SERVICE);
        assert_eq!(
            leaves.helper.to_string(),
            "/system.slice/rosetun-helper.service/helper"
        );
        assert_eq!(
            leaves.engines.relative(),
            "system.slice/rosetun-helper.service/engines"
        );
        assert_eq!(leaves.engines.level(), 3);
    }

    #[test]
    fn a_helper_already_in_its_leaf_finds_the_same_leaves() {
        let moved = CgroupPath::parse("/system.slice/rosetun-helper.service/helper").unwrap();
        assert_eq!(
            Leaves::of(&moved).unwrap(),
            Leaves::of(&CgroupPath::parse(SERVICE).unwrap()).unwrap()
        );
    }

    #[test]
    fn another_units_or_a_sessions_cgroup_is_not_ours() {
        for path in [
            "/user.slice/user-1000.slice/session-2.scope",
            "/system.slice/ssh.service",
            "/user.slice/helper",
            "/",
        ] {
            assert_eq!(
                Leaves::of(&CgroupPath::parse(path).unwrap()),
                Err(CgroupError::NotOurUnit),
                "{path}"
            );
        }
    }

    #[test]
    fn unsafe_components_never_make_a_path() {
        for path in [
            "system.slice",
            "/system.slice/../x",
            "/system.slice/./x",
            "/a//b",
            "/a/b/",
            "/a/\"b",
            "/a/b c",
            "/a/b;c",
            "/a/b\nc",
            "/a/b\\x2dc",
            "/a/b}",
        ] {
            assert_eq!(CgroupPath::parse(path), Err(CgroupError::InvalidPath), "{path:?}");
        }
        let base = CgroupPath::parse(SERVICE).unwrap();
        assert!(base.child("..").is_err());
        assert!(base.child("a/b").is_err());
        assert!(base.child("").is_err());
    }

    #[test]
    fn a_path_maps_onto_the_mount() {
        let path = CgroupPath::parse(SERVICE).unwrap();
        assert_eq!(
            path.under(Path::new("/sys/fs/cgroup")),
            PathBuf::from("/sys/fs/cgroup/system.slice/rosetun-helper.service")
        );
    }
}
