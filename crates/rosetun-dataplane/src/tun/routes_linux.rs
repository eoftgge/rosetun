//! Policy routing for sockets captured by the Linux packet device.

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rosetun_config::IpPrefix;

use super::{CaptureRoutes, RouteBackend, RouteLease};

#[derive(Clone)]
struct IpRoute {
    command: PathBuf,
    table: NonZeroU32,
    interface: String,
}

impl RouteBackend for IpRoute {
    fn add(&mut self, prefix: IpPrefix) -> io::Result<()> {
        self.change(prefix, "add")
    }

    fn delete(&mut self, prefix: IpPrefix) -> io::Result<()> {
        self.change(prefix, "del")
    }
}

impl IpRoute {
    fn change(&self, prefix: IpPrefix, operation: &str) -> io::Result<()> {
        let family = family(prefix.is_ipv4());
        let prefix = prefix.to_string();
        let table = self.table.to_string();
        run(
            &self.command,
            &[
                family,
                "route",
                operation,
                &prefix,
                "dev",
                &self.interface,
                "table",
                &table,
            ],
        )
    }
}

#[derive(Clone, Copy)]
enum Lookup {
    Physical,
    Unreachable,
    Endpoint(IpAddr),
    Capture,
}

struct Rule {
    ipv4: bool,
    priority: u16,
    lookup: Lookup,
}

/// A normal-route lease and the policy rules that make a marked physical
/// socket skip capture. An unsuccessful lookup of a marked socket terminates
/// before the tunnel table instead of falling through into it.
pub struct LinuxRoutes {
    backend: IpRoute,
    capture: Option<RouteLease<IpRoute>>,
    mark: NonZeroU32,
    rules: Vec<Rule>,
    endpoint_priority: u16,
}

impl fmt::Debug for LinuxRoutes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxRoutes")
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}

impl LinuxRoutes {
    pub fn install(
        interface: &str,
        routes: &CaptureRoutes,
        table: NonZeroU32,
        mark: NonZeroU32,
        first_priority: u16,
        endpoints: &[IpAddr],
        ipv6: bool,
    ) -> io::Result<Self> {
        if interface.is_empty()
            || interface.len() >= 16
            || !interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || interface.starts_with('-')
            || table.get() <= 255
            || !(1..=32_763).contains(&first_priority)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid native policy route",
            ));
        }
        let command = ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "iproute2 is unavailable"))?;
        let backend = IpRoute {
            interface: interface.to_owned(),
            table,
            command: command.to_owned(),
        };
        let mut lease = Self {
            backend,
            capture: None,
            mark,
            rules: Vec::new(),
            endpoint_priority: first_priority + 2,
        };
        lease.capture = Some(RouteLease::install(lease.backend.clone(), routes)?);
        for ipv4 in [true, false] {
            if !ipv4 && !ipv6 {
                continue;
            }
            let capture = routes
                .prefixes()
                .iter()
                .any(|prefix| prefix.is_ipv4() == ipv4);
            lease.check_free_priority(&Rule {
                ipv4,
                priority: lease.endpoint_priority,
                lookup: Lookup::Capture,
            })?;
            for (offset, lookup) in [
                (0, Lookup::Physical),
                (1, Lookup::Unreachable),
                (3, Lookup::Capture),
            ] {
                if !capture && matches!(lookup, Lookup::Capture) {
                    continue;
                }
                let rule = Rule {
                    ipv4,
                    priority: first_priority + offset,
                    lookup,
                };
                lease.check_free_priority(&rule)?;
                lease.change(&rule, "add")?;
                lease.rules.push(rule);
            }
        }
        lease.ensure_endpoints(endpoints)?;
        Ok(lease)
    }

    /// A worker opens its own socket before any packet-level mark can change
    /// the route. Give each resolved worker endpoint its physical route at
    /// connect time. The standing kill switch still controls who may use it.
    pub fn ensure_endpoints(&mut self, endpoints: &[IpAddr]) -> io::Result<()> {
        for &address in endpoints {
            if self
                .rules
                .iter()
                .any(|rule| matches!(rule.lookup, Lookup::Endpoint(ip) if ip == address))
            {
                continue;
            }
            let rule = Rule {
                ipv4: address.is_ipv4(),
                priority: self.endpoint_priority,
                lookup: Lookup::Endpoint(address),
            };
            self.change(&rule, "add")?;
            self.rules.push(rule);
        }
        Ok(())
    }

    pub fn retain_endpoints(&mut self, endpoints: &[IpAddr]) -> io::Result<()> {
        let mut index = 0;
        while index < self.rules.len() {
            let rule = &self.rules[index];
            if matches!(rule.lookup, Lookup::Endpoint(ip) if !endpoints.contains(&ip)) {
                self.change(rule, "del")?;
                self.rules.remove(index);
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    fn check_free_priority(&self, rule: &Rule) -> io::Result<()> {
        let priority = rule.priority.to_string();
        let output = Command::new(&self.backend.command)
            .args([
                family(rule.ipv4),
                "-j",
                "rule",
                "show",
                "priority",
                &priority,
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(
                "could not inspect native policy rule priority",
            ));
        }
        let rows: Vec<serde_json::Value> =
            serde_json::from_slice(&output.stdout).map_err(io::Error::other)?;
        if !rows.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "native policy rule priority is occupied",
            ));
        }
        Ok(())
    }

    fn change(&self, rule: &Rule, operation: &str) -> io::Result<()> {
        let family = family(rule.ipv4);
        let priority = rule.priority.to_string();
        let mark = format!("{}/0xffffffff", self.mark.get());
        let table = self.backend.table.to_string();
        let mut args = vec![family, "rule", operation, "priority", &priority];
        let endpoint;
        match rule.lookup {
            Lookup::Physical => args.extend(["fwmark", &mark, "lookup", "main"]),
            Lookup::Unreachable => args.extend(["fwmark", &mark, "type", "unreachable"]),
            Lookup::Capture => args.extend(["lookup", &table]),
            Lookup::Endpoint(ip) => {
                endpoint = format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 });
                args.extend(["to", &endpoint, "lookup", "main"]);
            }
        }
        run(&self.backend.command, &args)
    }

    pub fn close(&mut self) -> io::Result<()> {
        let mut retained = Vec::new();
        let mut first_error = None;
        while let Some(rule) = self.rules.pop() {
            if let Err(error) = self.change(&rule, "del") {
                retained.push(rule);
                first_error.get_or_insert(error);
            }
        }
        self.rules.extend(retained.into_iter().rev());
        if let Some(capture) = self.capture.as_mut()
            && let Err(error) = capture.close()
        {
            first_error.get_or_insert(error);
        }
        if first_error.is_none() {
            self.capture = None;
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for LinuxRoutes {
    fn drop(&mut self) {
        if self.close().is_err() {
            tracing::error!("could not remove all native policy rules");
        }
    }
}

fn family(ipv4: bool) -> &'static str {
    if ipv4 { "-4" } else { "-6" }
}

fn run(command: &Path, args: &[&str]) -> io::Result<()> {
    let status = Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("could not update native policy routing"))
    }
}
