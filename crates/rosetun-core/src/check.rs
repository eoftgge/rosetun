//! Where the rules would send a site, an address or a program, without a
//! connection. [`explain`] answers for the request the client would send; this
//! module turns what a person typed into a destination and says when the
//! answer rests on something the client cannot know. What is typed is the
//! user's browsing history: nothing here logs or keeps it, and no `Debug`
//! shows it.

use std::fmt;
use std::net::IpAddr;

use rosetun_config::{
    DomainMatch, ProcessMatch, Rule, RuleInputError, RuleMatcher, parse_domain_input,
};
use rosetun_ipc::ConnectRequest;
use url::Host;

use crate::explain::{
    Cidr, Destination, Explanation, Reason, SessionLists, consulted, explain, is_link_local,
    is_private,
};
use crate::parse_process_input;

/// What was typed, as a destination.
#[derive(Clone, PartialEq, Eq)]
pub enum Subject {
    /// A site name in lower case, as sing-box matches it.
    Site(String),
    Address(IpAddr),
    /// A program by its file name only.
    ProgramName(String),
    /// A program by its full path.
    ProgramPath(String),
}

impl fmt::Debug for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Site(_) => "Subject::Site",
            Self::Address(_) => "Subject::Address",
            Self::ProgramName(_) => "Subject::ProgramName",
            Self::ProgramPath(_) => "Subject::ProgramPath",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InputError {
    #[error("nothing entered")]
    Empty,
    #[error("enter a site, an IP address or a program")]
    Unrecognised,
}

/// What the answer cannot say for certain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unknown {
    /// "Local network" is on and the address is private: the computer's own
    /// segment goes direct before any rule, and only the service knows it.
    Network,
    /// A rule on a program's full path comes before the answer, and only the
    /// program's name was given.
    ProgramPath,
    /// A rule on an address comes before the answer, and only a site name
    /// was given: it depends on the address the site resolves to.
    SiteAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The rules decide.
    Known(Explanation),
    /// The rules say `otherwise` unless `on` turns out the other way.
    Depends { on: Unknown, otherwise: Explanation },
}

impl Subject {
    /// A site (with a scheme, port or path: dropped), an IP address, a
    /// program's name or its full path.
    pub fn parse(input: &str) -> Result<Self, InputError> {
        let input = input.trim();
        let input = input
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or(input)
            .trim();
        if input.is_empty() {
            return Err(InputError::Empty);
        }
        if is_absolute_path(input) {
            return match parse_process_input(input) {
                Ok(ProcessMatch::Path(path)) => {
                    Ok(Self::ProgramPath(path.to_string_lossy().into_owned()))
                }
                _ => Err(InputError::Unrecognised),
            };
        }
        let host = match host_of(input) {
            Some(Typed::Address(ip)) => return Ok(Self::Address(ip)),
            Some(Typed::Name(name)) => name,
            None => return Err(InputError::Unrecognised),
        };
        if host.contains(['\\', '/']) || has_program_extension(&host) {
            return program_name(&host);
        }
        match parse_domain_input(&host) {
            Ok(DomainMatch::Exact(domain) | DomainMatch::Suffix(domain)) => Ok(Self::Site(domain)),
            Ok(DomainMatch::Keyword(_)) => Err(InputError::Unrecognised),
            Err(RuleInputError::SingleLabel) => program_name(&host),
            Err(_) => Err(InputError::Unrecognised),
        }
    }

    fn destination(&self) -> Destination<'_> {
        let mut destination = Destination {
            domain: None,
            ip: None,
            process: None,
        };
        match self {
            Self::Site(domain) => destination.domain = Some(domain),
            Self::Address(ip) => destination.ip = Some(*ip),
            Self::ProgramName(process) | Self::ProgramPath(process) => {
                destination.process = Some(process);
            }
        }
        destination
    }
}

fn program_name(name: &str) -> Result<Subject, InputError> {
    match parse_process_input(name) {
        Ok(ProcessMatch::Name(name)) => Ok(Subject::ProgramName(name)),
        _ => Err(InputError::Unrecognised),
    }
}

fn has_program_extension(name: &str) -> bool {
    name.len() > ".exe".len()
        && name.is_char_boundary(name.len() - ".exe".len())
        && name[name.len() - ".exe".len()..].eq_ignore_ascii_case(".exe")
}

/// A drive path, a network path or a rooted path.
fn is_absolute_path(input: &str) -> bool {
    let bytes = input.as_bytes();
    input.starts_with(['/', '\\'])
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
}

enum Typed {
    Address(IpAddr),
    Name(String),
}

/// The host of what was typed: a link's host, `host:port`, `[v6]:port`, or the
/// text itself.
fn host_of(input: &str) -> Option<Typed> {
    if input.contains("://") {
        return match url::Url::parse(input).ok()?.host()? {
            Host::Domain(name) => Some(Typed::Name(name.to_owned())),
            Host::Ipv4(ip) => Some(Typed::Address(IpAddr::V4(ip))),
            Host::Ipv6(ip) => Some(Typed::Address(IpAddr::V6(ip))),
        };
    }
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Some(Typed::Address(ip));
    }
    let (authority, rest) = input.split_at(input.find(['/', '?', '#']).unwrap_or(input.len()));
    // A subnet such as `192.0.2.0/24` is a block of addresses, not one.
    if authority.parse::<IpAddr>().is_ok() && rest.strip_prefix('/').is_some_and(is_port) {
        return None;
    }
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        if !(after.is_empty() || after.strip_prefix(':').is_some_and(is_port)) {
            return None;
        }
        host
    } else {
        match authority.split_once(':') {
            Some((host, port)) if is_port(port) => host,
            Some(_) => return None,
            None => authority,
        }
    };
    match host.parse::<IpAddr>() {
        Ok(ip) => Some(Typed::Address(ip)),
        Err(_) => Some(Typed::Name(host.to_owned())),
    }
}

fn is_port(text: &str) -> bool {
    !text.is_empty() && text.len() <= 5 && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Where the rules of `request` send `subject`, and what the answer leaves
/// open.
pub fn check(request: &ConnectRequest, lists: &SessionLists, subject: &Subject) -> Answer {
    let destination = subject.destination();
    let explanation = explain(request, lists, &destination);
    if request.settings.allow_lan
        && let Subject::Address(ip) = subject
        && is_private(*ip)
        && !ip.is_loopback()
        && !is_link_local(*ip)
    {
        return Answer::Depends {
            on: Unknown::Network,
            otherwise: explanation,
        };
    }
    let rules = request.effective_rule_set();
    let decided_by = match &explanation {
        Explanation::Routed {
            reason: Reason::Rule { id, temporary, .. },
            ..
        }
        | Explanation::Unverifiable {
            rule: id,
            temporary,
        } => Some((id, *temporary)),
        Explanation::Routed { .. } => None,
    };
    let mut open = None;
    for (temporary, rule) in consulted(request, &rules) {
        if decided_by
            .is_some_and(|(id, decided_temporary)| *id == rule.id && decided_temporary == temporary)
        {
            break;
        }
        open = open.or_else(|| unknown_of(subject, rule, lists));
    }
    match open {
        Some(on) => Answer::Depends {
            on,
            otherwise: explanation,
        },
        None => Answer::Known(explanation),
    }
}

/// Whether `rule`, which did not match, might have matched had the client
/// known more about `subject`.
fn unknown_of(subject: &Subject, rule: &Rule, lists: &SessionLists) -> Option<Unknown> {
    let (address, path) = match &rule.matcher {
        RuleMatcher::IpCidr(cidr) => (Cidr::parse(cidr).is_some_and(Cidr::reaches_public), false),
        RuleMatcher::Process(ProcessMatch::Path(_)) => (false, true),
        RuleMatcher::List { list, category } => {
            let needs = lists.needs(list, category.as_deref());
            (needs.address, needs.path)
        }
        RuleMatcher::Domain(_)
        | RuleMatcher::Process(ProcessMatch::Name(_))
        | RuleMatcher::Group { .. } => (false, false),
    };
    match subject {
        Subject::Site(_) if address => Some(Unknown::SiteAddress),
        Subject::ProgramName(_) if path => Some(Unknown::ProgramPath),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
