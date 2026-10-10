use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{ListId, RuleId, RuleSetId};

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
    List {
        list: ListId,
        category: Option<String>,
    },
    /// A named group of plain rules defined by the app. Clients expand it
    /// before connecting; an engine never sees one.
    Template(RuleTemplate),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTemplate {
    RussianSites,
    Messengers,
    Youtube,
    Torrents,
}

impl RuleTemplate {
    pub const ALL: [Self; 4] = [
        Self::RussianSites,
        Self::Messengers,
        Self::Youtube,
        Self::Torrents,
    ];

    /// Stable name for logs and the CLI.
    pub fn key(self) -> &'static str {
        match self {
            Self::RussianSites => "russian_sites",
            Self::Messengers => "messengers",
            Self::Youtube => "youtube",
            Self::Torrents => "torrents",
        }
    }

    pub fn default_target(self) -> RuleTarget {
        match self {
            Self::RussianSites | Self::Torrents => RuleTarget::Direct,
            Self::Messengers | Self::Youtube => RuleTarget::Proxy,
        }
    }

    /// The plain matchers the template stands for. They change with the app:
    /// a saved template rule follows them.
    pub fn matchers(self) -> Vec<RuleMatcher> {
        let (processes, domains): (&[&str], &[&str]) = match self {
            Self::RussianSites => (
                &[],
                &[
                    "ru",
                    "su",
                    "xn--p1ai",
                    "vk.com",
                    "vk.me",
                    "userapi.com",
                    "vkuser.net",
                    "mycdn.me",
                    "yandex.com",
                    "yandex.net",
                    "yastatic.net",
                ],
            ),
            Self::Messengers => (
                &[
                    "Telegram.exe",
                    "Discord.exe",
                    "DiscordPTB.exe",
                    "DiscordCanary.exe",
                    // Current WhatsApp for Windows uses WhatsApp.Root.exe; older releases use
                    // WhatsApp.exe. Its shared msedgewebview2.exe processes cannot be listed:
                    // doing so would route every WebView2 app through the VPN. The domains
                    // below catch the traffic those processes carry instead.
                    "WhatsApp.exe",
                    "WhatsApp.Root.exe",
                ],
                &[
                    "telegram.org",
                    "t.me",
                    "telegram.me",
                    "telesco.pe",
                    "tdesktop.com",
                    "telegra.ph",
                    "discord.com",
                    "discord.gg",
                    "discordapp.com",
                    "discordapp.net",
                    "discord.media",
                    "whatsapp.com",
                    "whatsapp.net",
                    "wa.me",
                ],
            ),
            Self::Youtube => (
                &[],
                &[
                    "youtube.com",
                    "youtu.be",
                    "googlevideo.com",
                    "ytimg.com",
                    "ggpht.com",
                    "youtube-nocookie.com",
                    "youtubei.googleapis.com",
                ],
            ),
            Self::Torrents => (
                &[
                    "qbittorrent.exe",
                    "utorrent.exe",
                    "bittorrent.exe",
                    "transmission-qt.exe",
                    "tixati.exe",
                    "deluge.exe",
                    "biglybt.exe",
                ],
                &[],
            ),
        };
        processes
            .iter()
            .map(|name| RuleMatcher::Process(ProcessMatch::Name((*name).to_owned())))
            .chain(
                domains
                    .iter()
                    .map(|domain| RuleMatcher::Domain(DomainMatch::Suffix((*domain).to_owned()))),
            )
            .collect()
    }
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

    /// The same rules with every template replaced, in place, by its plain
    /// matchers. Each expanded rule keeps the template rule's id, enabled flag
    /// and target, so an engine refusing one names the template.
    pub fn with_templates_expanded(&self) -> RuleSet {
        let mut expanded = self.clone();
        expanded.rules = self
            .rules
            .iter()
            .flat_map(|rule| match &rule.matcher {
                RuleMatcher::Template(template) => template
                    .matchers()
                    .into_iter()
                    .map(|matcher| Rule {
                        matcher,
                        ..rule.clone()
                    })
                    .collect(),
                _ => vec![rule.clone()],
            })
            .collect();
        expanded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_expand_in_place_with_original_rule_metadata() {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Test", RuleTarget::Proxy);
        let before = Rule {
            id: RuleId::new("a"),
            enabled: true,
            matcher: RuleMatcher::Domain(DomainMatch::Exact("a.example".into())),
            target: RuleTarget::Block,
        };
        let template = Rule {
            id: RuleId::new("template"),
            enabled: false,
            matcher: RuleMatcher::Template(RuleTemplate::Torrents),
            target: RuleTarget::Block,
        };
        let after = Rule {
            id: RuleId::new("b"),
            enabled: true,
            matcher: RuleMatcher::Process(ProcessMatch::Name("b.exe".into())),
            target: RuleTarget::Direct,
        };
        set.rules = vec![before.clone(), template.clone(), after.clone()];
        let expanded = set.with_templates_expanded();
        assert_eq!(expanded.id, set.id);
        assert_eq!(expanded.name, set.name);
        assert_eq!(expanded.default_target, set.default_target);
        assert_eq!(expanded.rules.len(), 9);
        assert_eq!(expanded.rules.first(), Some(&before));
        assert_eq!(expanded.rules.last(), Some(&after));
        for (rule, matcher) in expanded.rules[1..8]
            .iter()
            .zip(RuleTemplate::Torrents.matchers())
        {
            assert_eq!(rule.id, template.id);
            assert!(!rule.enabled);
            assert_eq!(rule.target, RuleTarget::Block);
            assert_eq!(rule.matcher, matcher);
        }
        assert_eq!(set.rules[1], template);
    }

    #[test]
    fn rule_set_without_templates_is_unchanged() {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Test", RuleTarget::Direct);
        set.rules.push(Rule {
            id: RuleId::new("plain"),
            enabled: false,
            matcher: RuleMatcher::IpCidr("10.0.0.0/8".into()),
            target: RuleTarget::Block,
        });
        assert_eq!(set.with_templates_expanded(), set);
    }

    #[test]
    fn template_matchers_are_distinct() {
        for template in RuleTemplate::ALL {
            let matchers = template.matchers();
            assert!(!matchers.is_empty(), "{}", template.key());
            for (index, matcher) in matchers.iter().enumerate() {
                assert!(
                    !matchers[..index].contains(matcher),
                    "duplicate in {}: {matcher:?}",
                    template.key()
                );
            }
        }
    }

    #[test]
    fn template_serde_uses_stable_keys() {
        for (template, key, target) in [
            (
                RuleTemplate::RussianSites,
                "russian_sites",
                RuleTarget::Direct,
            ),
            (RuleTemplate::Messengers, "messengers", RuleTarget::Proxy),
            (RuleTemplate::Youtube, "youtube", RuleTarget::Proxy),
            (RuleTemplate::Torrents, "torrents", RuleTarget::Direct),
        ] {
            assert_eq!(template.key(), key);
            assert_eq!(template.default_target(), target);
            let matcher = RuleMatcher::Template(template);
            assert_eq!(
                serde_json::to_value(&matcher).unwrap(),
                serde_json::json!({ "template": key })
            );
            assert_eq!(
                serde_json::from_value::<RuleMatcher>(serde_json::json!({ "template": key }))
                    .unwrap(),
                matcher
            );
        }
    }
}
