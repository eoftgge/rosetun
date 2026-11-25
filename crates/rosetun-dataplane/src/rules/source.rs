//! sing-box JSON rule-set source (`{"version":N,"rules":[...]}`) parser.

use std::collections::HashSet;

use serde_json::{Map, Value};

use super::RulesError;
use super::cidr::parse_cidr;
use super::list::{
    CompiledList, CompiledListRule, DefaultListRule, LogicalListRule, LogicalMode, MAX_LIST_BYTES,
    MAX_LOGICAL_DEPTH, compile_regex, count_entries,
};

pub(crate) fn parse_source(bytes: &[u8]) -> Result<CompiledList, RulesError> {
    if bytes.len() > MAX_LIST_BYTES {
        return Err(RulesError::ListTooLarge);
    }
    let root: Value = serde_json::from_slice(bytes).map_err(|_| RulesError::InvalidSource)?;
    let obj = root.as_object().ok_or(RulesError::InvalidSource)?;

    for key in obj.keys() {
        if key != "version" && key != "rules" {
            return Err(RulesError::InvalidSource);
        }
    }
    if let Some(version) = obj.get("version") {
        let version = version.as_u64().ok_or(RulesError::InvalidSource)?;
        if !(1..=5).contains(&version) {
            return Err(RulesError::InvalidSource);
        }
    }

    let raw_rules = obj
        .get("rules")
        .and_then(Value::as_array)
        .ok_or(RulesError::InvalidSource)?;

    let mut entries = 0_usize;
    let mut regex_count = 0_usize;
    let mut rules = Vec::with_capacity(raw_rules.len());
    for raw in raw_rules {
        rules.push(parse_rule(raw, 0, &mut entries, &mut regex_count)?);
    }
    Ok(CompiledList { rules })
}

fn parse_rule(
    value: &Value,
    depth: usize,
    entries: &mut usize,
    regex_count: &mut usize,
) -> Result<CompiledListRule, RulesError> {
    if depth > MAX_LOGICAL_DEPTH {
        return Err(RulesError::InvalidSource);
    }
    let obj = value.as_object().ok_or(RulesError::InvalidSource)?;
    let rule_type = match obj.get("type") {
        None => "default",
        Some(value) => value.as_str().ok_or(RulesError::InvalidSource)?,
    };
    match rule_type {
        "default" => parse_default_rule(obj, entries, regex_count)
            .map(|rule| CompiledListRule::Default(Box::new(rule))),
        "logical" => {
            parse_logical_rule(obj, depth, entries, regex_count).map(CompiledListRule::Logical)
        }
        _ => Err(RulesError::InvalidSource),
    }
}

fn parse_logical_rule(
    obj: &Map<String, Value>,
    depth: usize,
    entries: &mut usize,
    regex_count: &mut usize,
) -> Result<LogicalListRule, RulesError> {
    let mut mode = None;
    let mut sub_rules = None;
    let mut invert = false;

    for (key, value) in obj {
        match key.as_str() {
            "type" => {}
            "mode" => {
                mode = Some(match value.as_str() {
                    Some("and") => LogicalMode::And,
                    Some("or") => LogicalMode::Or,
                    _ => return Err(RulesError::InvalidSource),
                });
            }
            "rules" => {
                let array = value.as_array().ok_or(RulesError::InvalidSource)?;
                if array.is_empty() {
                    return Err(RulesError::InvalidSource);
                }
                let mut parsed = Vec::with_capacity(array.len());
                for item in array {
                    parsed.push(parse_rule(item, depth + 1, entries, regex_count)?);
                }
                sub_rules = Some(parsed);
            }
            "invert" => {
                invert = value.as_bool().ok_or(RulesError::InvalidSource)?;
            }
            _ => return Err(RulesError::InvalidSource),
        }
    }

    Ok(LogicalListRule {
        mode: mode.ok_or(RulesError::InvalidSource)?,
        rules: sub_rules.ok_or(RulesError::InvalidSource)?,
        invert,
    })
}

fn parse_default_rule(
    obj: &Map<String, Value>,
    entries: &mut usize,
    regex_count: &mut usize,
) -> Result<DefaultListRule, RulesError> {
    let mut rule = DefaultListRule::default();

    for (key, value) in obj {
        match key.as_str() {
            "type" => {}
            "invert" => {
                rule.invert = value.as_bool().ok_or(RulesError::InvalidSource)?;
            }
            "domain" => {
                let values = read_strings(value, entries)?;
                rule.domains
                    .extend(values.into_iter().map(str::to_lowercase));
            }
            "domain_suffix" => {
                for suffix in read_strings(value, entries)? {
                    rule.suffixes.insert(suffix);
                }
            }
            "domain_keyword" => {
                let values = read_strings(value, entries)?;
                rule.keywords
                    .extend(values.into_iter().map(str::to_lowercase));
            }
            "domain_regex" => {
                for pattern in read_strings(value, entries)? {
                    rule.domain_regexes
                        .push(compile_regex(pattern, regex_count)?);
                }
            }
            "ip_cidr" => {
                for cidr in read_strings(value, entries)? {
                    let prefix = parse_cidr(cidr).ok_or(RulesError::InvalidCidr)?;
                    rule.cidrs.insert(prefix);
                }
            }
            "process_name" => {
                let set = rule.process_names.get_or_insert_with(HashSet::new);
                set.extend(read_strings(value, entries)?.into_iter().map(str::to_owned));
            }
            "process_path" => {
                let set = rule.process_paths.get_or_insert_with(HashSet::new);
                set.extend(read_strings(value, entries)?.into_iter().map(str::to_owned));
            }
            "process_path_regex" => {
                let regexes = rule.process_path_regexes.get_or_insert_with(Vec::new);
                for pattern in read_strings(value, entries)? {
                    regexes.push(compile_regex(pattern, regex_count)?);
                }
            }
            "query_type"
            | "network"
            | "source_ip_cidr"
            | "source_port"
            | "source_port_range"
            | "port"
            | "port_range"
            | "package_name"
            | "package_name_regex"
            | "wifi_ssid"
            | "wifi_bssid"
            | "network_type"
            | "default_interface_address" => {
                validate_listable_scalar(value, entries)?;
                rule.has_unmatchable = true;
            }
            "network_is_expensive" | "network_is_constrained" => {
                if !value.is_boolean() {
                    return Err(RulesError::InvalidSource);
                }
                if value.as_bool() == Some(true) {
                    count_entries(entries, 1)?;
                    rule.has_unmatchable = true;
                }
            }
            "network_interface_address" => {
                let map = value.as_object().ok_or(RulesError::InvalidSource)?;
                for item in map.values() {
                    let _ = read_strings(item, entries)?;
                }
                if !map.is_empty() {
                    rule.has_unmatchable = true;
                }
            }
            _ => return Err(RulesError::InvalidSource),
        }
    }

    if !rule.has_any_condition() {
        return Err(RulesError::InvalidSource);
    }
    Ok(rule)
}

fn read_strings<'a>(value: &'a Value, entries: &mut usize) -> Result<Vec<&'a str>, RulesError> {
    match value {
        Value::String(text) => {
            count_entries(entries, 1)?;
            Ok(vec![text.as_str()])
        }
        Value::Array(items) => {
            count_entries(entries, items.len())?;
            items
                .iter()
                .map(|item| item.as_str().ok_or(RulesError::InvalidSource))
                .collect()
        }
        _ => Err(RulesError::InvalidSource),
    }
}

fn validate_listable_scalar(value: &Value, entries: &mut usize) -> Result<(), RulesError> {
    match value {
        Value::String(_) | Value::Number(_) => count_entries(entries, 1),
        Value::Array(items) => {
            count_entries(entries, items.len())?;
            if items
                .iter()
                .all(|item| item.is_string() || item.is_number())
            {
                Ok(())
            } else {
                Err(RulesError::InvalidSource)
            }
        }
        _ => Err(RulesError::InvalidSource),
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::IpAddr;

    use super::*;
    use crate::net::Resolve;
    use crate::rules::EvalCtx;

    struct NoResolve;

    impl Resolve for NoResolve {
        fn resolve(&self, _name: &str) -> io::Result<Vec<IpAddr>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "unused"))
        }
    }

    fn matches(
        list: &CompiledList,
        domain: Option<&str>,
        addr: Option<&str>,
        process: Option<&str>,
    ) -> bool {
        let lowered = domain.map(str::to_lowercase);
        let ip = addr.map(|s| s.parse::<IpAddr>().unwrap());
        let mut ctx = EvalCtx::new(lowered.as_deref(), ip, process, &NoResolve);
        list.matches(&mut ctx)
    }

    #[test]
    fn source_parses_all_meaningful_keys_and_logical_rules() {
        let json = br#"{
            "version": 3,
            "rules": [
                {
                    "domain": ["Exact.Example.Com"],
                    "domain_suffix": [".sub.example.org", "example.net"],
                    "domain_keyword": ["needle"],
                    "domain_regex": ["^host[0-9]+\\.invalid$"],
                    "ip_cidr": ["192.0.2.5/24", "2001:db8::/48"]
                },
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [
                        { "domain_suffix": ["corp.invalid"] },
                        { "process_name": ["client"], "process_path_regex": ["/bin/client$"] }
                    ]
                },
                {
                    "port": [443]
                }
            ]
        }"#;
        let list = parse_source(json).unwrap();
        assert!(matches(&list, Some("exact.example.com"), None, None));
        assert!(matches(&list, Some("a.sub.example.org"), None, None));
        assert!(!matches(&list, Some("sub.example.org"), None, None));
        assert!(matches(&list, Some("example.net"), None, None));
        assert!(matches(&list, Some("has-needle.invalid"), None, None));
        assert!(matches(&list, Some("host7.invalid"), None, None));
        assert!(matches(&list, None, Some("192.0.2.99"), None));
        assert!(matches(&list, None, Some("2001:db8::abcd"), None));

        assert!(matches(
            &list,
            Some("api.corp.invalid"),
            None,
            Some("/usr/bin/client")
        ));
        assert!(!matches(
            &list,
            Some("api.corp.invalid"),
            None,
            Some("/opt/client")
        ));
        assert!(!matches(&list, Some("other.invalid"), None, None));
    }

    #[test]
    fn source_rejects_unknown_keys_empty_rules_and_invalid_inputs() {
        for bad in [
            br#"not json"#.as_slice(),
            br#"[]"#,
            br#"{"version":99,"rules":[]}"#,
            br#"{"version":3,"rules":[{}]}"#,
            br#"{"version":3,"rules":[{"unknown_key":["example.com"]}]}"#,
            br#"{"version":3,"rules":[{"ip_cidr":["999.999.999.999/24"]}]}"#,
            br#"{"version":3,"rules":[{"domain_regex":["[unclosed"]}]}"#,
            br#"{"version":3,"rules":[{"type":"logical","mode":"xor","rules":[]}]}"#,
        ] {
            assert!(parse_source(bad).is_err());
        }
    }
}
