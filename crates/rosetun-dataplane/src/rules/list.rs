//! Compiled rule-list representation shared by `.srs`, JSON source, and Xray `.dat` parsers.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

use regex_automata::meta::{Config as RegexConfig, Regex};

use super::cidr::CidrTree;
use super::domain::{SuccinctDomainSet, SuffixTrie};
use super::{EvalCtx, RulesError};

/// Maximum accepted raw or decompressed list size (128 MiB).
pub(crate) const MAX_LIST_BYTES: usize = 128 * 1024 * 1024;
/// Maximum compiled condition entries per list.
pub(crate) const MAX_LIST_ENTRIES: usize = 1_000_000;
/// Maximum logical rule nesting depth (matches sing-box `maxLogicalRuleDepth`).
pub(crate) const MAX_LOGICAL_DEPTH: usize = 100;
/// Maximum compiled regular expressions per list.
pub(crate) const MAX_REGEXES: usize = 4096;
/// Maximum byte length of a single regular expression pattern.
pub(crate) const MAX_REGEX_LEN: usize = 4096;
/// Per-regex NFA size cap (2 MiB).
const REGEX_NFA_SIZE_LIMIT: usize = 2 * 1024 * 1024;
/// Per-regex DFA size cap (2 MiB).
const REGEX_DFA_SIZE_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct CompiledList {
    pub(crate) rules: Vec<CompiledListRule>,
}

impl fmt::Debug for CompiledList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledList")
            .field("rule_count", &self.rules.len())
            .finish()
    }
}

impl CompiledList {
    pub(crate) fn matches(&self, ctx: &mut EvalCtx<'_, '_>) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.evaluate(ctx) == Some(true))
    }
}

pub(crate) enum CompiledListRule {
    Default(Box<DefaultListRule>),
    Logical(LogicalListRule),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogicalMode {
    And,
    Or,
}

pub(crate) struct LogicalListRule {
    pub(crate) mode: LogicalMode,
    pub(crate) rules: Vec<CompiledListRule>,
    pub(crate) invert: bool,
}

#[derive(Default)]
pub(crate) struct DefaultListRule {
    pub(crate) domains: HashSet<String>,
    pub(crate) suffixes: SuffixTrie,
    pub(crate) succinct_domains: Vec<SuccinctDomainSet>,
    pub(crate) keywords: Vec<String>,
    pub(crate) domain_regexes: Vec<Regex>,
    pub(crate) cidrs: CidrTree,
    pub(crate) process_names: Option<HashSet<String>>,
    pub(crate) process_paths: Option<HashSet<String>>,
    pub(crate) process_path_regexes: Option<Vec<Regex>>,
    /// True when the rule contains an item that cannot be evaluated in proxy
    /// mode (source IP/port, destination port, network/Wi-Fi, Android package,
    /// interface address, DNS query type).
    pub(crate) has_unmatchable: bool,
    pub(crate) invert: bool,
}

impl DefaultListRule {
    pub(crate) fn has_address(&self) -> bool {
        !self.domains.is_empty()
            || !self.suffixes.is_empty()
            || !self.succinct_domains.is_empty()
            || !self.keywords.is_empty()
            || !self.domain_regexes.is_empty()
            || !self.cidrs.is_empty()
    }

    pub(crate) fn has_process(&self) -> bool {
        self.process_names.is_some()
            || self.process_paths.is_some()
            || self.process_path_regexes.is_some()
    }

    pub(crate) fn has_any_condition(&self) -> bool {
        self.has_address() || self.has_process() || self.has_unmatchable
    }

    /// Evaluates the rule using 3-valued logic: `None` means the rule contains
    /// an item that cannot be evaluated in proxy mode and therefore never
    /// matches, even under `invert`.
    fn evaluate(&self, ctx: &mut EvalCtx<'_, '_>) -> Option<bool> {
        if self.has_unmatchable {
            return None;
        }
        if !self.has_any_condition() {
            return Some(false);
        }

        // Check process conditions lazily and before touching DNS resolution so
        // non-process rules never query the OS process table and a process
        // mismatch never triggers a DNS lookup.
        if self.has_process() && !self.matches_process(ctx.process()) {
            return Some(self.invert);
        }

        let address_matched = if !self.has_address() || self.matches_domain(ctx.domain()) {
            true
        } else if !self.cidrs.is_empty() {
            ctx.resolve_ips()
                .iter()
                .any(|ip: &IpAddr| self.cidrs.contains(*ip))
        } else {
            false
        };

        Some(if self.invert {
            !address_matched
        } else {
            address_matched
        })
    }

    fn matches_domain(&self, domain: Option<&str>) -> bool {
        let Some(domain) = domain else {
            return false;
        };
        self.domains.contains(domain)
            || self.suffixes.matches(domain)
            || self
                .succinct_domains
                .iter()
                .any(|matcher| matcher.matches(domain))
            || self
                .keywords
                .iter()
                .any(|keyword| domain.contains(keyword.as_str()))
            || self
                .domain_regexes
                .iter()
                .any(|regex| regex.is_match(domain))
    }

    fn matches_process(&self, process: Option<&str>) -> bool {
        if let Some(names) = &self.process_names {
            let base = process.map(|path| path.rsplit(['\\', '/']).next().unwrap_or(path));
            if !base.is_some_and(|base| names.contains(base)) {
                return false;
            }
        }
        if let Some(paths) = &self.process_paths
            && !process.is_some_and(|path| paths.contains(path))
        {
            return false;
        }
        if let Some(regexes) = &self.process_path_regexes
            && !process.is_some_and(|path| regexes.iter().any(|regex| regex.is_match(path)))
        {
            return false;
        }
        true
    }
}

impl CompiledListRule {
    fn evaluate(&self, ctx: &mut EvalCtx<'_, '_>) -> Option<bool> {
        match self {
            Self::Default(rule) => rule.evaluate(ctx),
            Self::Logical(rule) => rule.evaluate(ctx),
        }
    }
}

impl LogicalListRule {
    fn evaluate(&self, ctx: &mut EvalCtx<'_, '_>) -> Option<bool> {
        let mut saw_unknown = false;
        let result = match self.mode {
            LogicalMode::And => {
                for rule in &self.rules {
                    match rule.evaluate(ctx) {
                        Some(false) => {
                            return Some(self.invert);
                        }
                        Some(true) => {}
                        None => saw_unknown = true,
                    }
                }
                if saw_unknown { None } else { Some(true) }
            }
            LogicalMode::Or => {
                for rule in &self.rules {
                    match rule.evaluate(ctx) {
                        Some(true) => {
                            return Some(!self.invert);
                        }
                        Some(false) => {}
                        None => saw_unknown = true,
                    }
                }
                if saw_unknown { None } else { Some(false) }
            }
        };
        result.map(|matched| if self.invert { !matched } else { matched })
    }
}

/// Compiles a single regular expression with bounded NFA/DFA memory limits.
pub(crate) fn compile_regex(pattern: &str, count: &mut usize) -> Result<Regex, RulesError> {
    if *count >= MAX_REGEXES {
        return Err(RulesError::TooManyEntries);
    }
    if pattern.len() > MAX_REGEX_LEN {
        return Err(RulesError::InvalidRegex);
    }
    *count += 1;
    let config = RegexConfig::new()
        .nfa_size_limit(Some(REGEX_NFA_SIZE_LIMIT))
        .dfa_size_limit(Some(REGEX_DFA_SIZE_LIMIT));
    Regex::builder()
        .configure(config)
        .build(pattern)
        .map_err(|_| RulesError::InvalidRegex)
}

/// Checks and increments a shared entry budget.
pub(crate) fn count_entries(total: &mut usize, add: usize) -> Result<(), RulesError> {
    let next = total.checked_add(add).ok_or(RulesError::TooManyEntries)?;
    if next > MAX_LIST_ENTRIES {
        return Err(RulesError::TooManyEntries);
    }
    *total = next;
    Ok(())
}
