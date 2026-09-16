use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{RuleId, RuleSetId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    #[serde(default = "crate::default_true")]
    pub enabled: bool,
    pub matcher: RuleMatcher,
    pub target: RuleTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleMatcher {
    Domain(DomainMatch),
    Process(ProcessMatch),
    IpCidr(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainMatch {
    Exact(String),
    Suffix(String),
    Keyword(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMatch {
    Name(String),
    Path(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTarget {
    #[default]
    Proxy,
    Direct,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSet {
    pub id: RuleSetId,
    pub name: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub default_target: RuleTarget,
}

impl RuleSet {
    pub fn new(id: RuleSetId, name: impl Into<String>, default_target: RuleTarget) -> Self {
        Self {
            id,
            name: name.into(),
            rules: Vec::new(),
            default_target,
        }
    }

    pub fn enabled(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|rule| rule.enabled)
    }
}
