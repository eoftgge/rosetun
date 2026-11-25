use std::fmt;
use std::io;
use std::process::{Command, Stdio};

use rosetun_config::IpPrefix;

use super::RouteBackend;

/// Exact routes through an owned utun interface.
pub struct MacosRoutes {
    interface: String,
}

impl fmt::Debug for MacosRoutes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacosRoutes").finish_non_exhaustive()
    }
}

impl MacosRoutes {
    pub fn new(interface: &str) -> io::Result<Self> {
        if interface
            .strip_prefix("utun")
            .is_none_or(|index| index.parse::<u16>().is_err())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid utun interface",
            ));
        }
        Ok(Self {
            interface: interface.to_owned(),
        })
    }

    fn change(&self, operation: &str, prefix: IpPrefix) -> io::Result<()> {
        let family = if prefix.is_ipv4() { "-inet" } else { "-inet6" };
        let destination = prefix.to_string();
        let status = Command::new("/sbin/route")
            .args([
                "-n",
                operation,
                family,
                "-net",
                &destination,
                "-interface",
                &self.interface,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("could not update native utun route"))
        }
    }
}

impl RouteBackend for MacosRoutes {
    fn add(&mut self, prefix: IpPrefix) -> io::Result<()> {
        self.change("add", prefix)
    }

    fn delete(&mut self, prefix: IpPrefix) -> io::Result<()> {
        self.change("delete", prefix)
    }
}
