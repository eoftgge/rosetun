use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{ExitId, ListId, RuleId, RuleSetId};

/// Maximum number of characters in a rule group's name.
pub const RULE_GROUP_NAME_LIMIT: usize = 64;
/// Maximum number of conditions inside a single rule group.
pub const MAX_GROUP_ITEMS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    #[serde(default = "crate::default_true")]
    pub enabled: bool,
    pub matcher: RuleMatcher,
    pub target: RuleTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<ExitId>,
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
    /// A named group of plain rules. Clients expand it in place before
    /// connecting; an engine never sees one.
    Group {
        name: String,
        items: Vec<RuleMatcher>,
    },
}

/// Built-in preset catalog used to create editable rule groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTemplate {
    RussianSites,
    Messengers,
    Youtube,
    Torrents,
    AiServices,
    Social,
    Streaming,
    Gaming,
}

impl RuleTemplate {
    pub const ALL: [Self; 8] = [
        Self::RussianSites,
        Self::Messengers,
        Self::Youtube,
        Self::Torrents,
        Self::AiServices,
        Self::Social,
        Self::Streaming,
        Self::Gaming,
    ];

    /// Compact starter presets shown on an empty rule set.
    pub const STARTER: [Self; 4] = [
        Self::RussianSites,
        Self::Messengers,
        Self::Youtube,
        Self::Torrents,
    ];

    /// Stable key for logs, migrations, and exchange compatibility.
    pub fn key(self) -> &'static str {
        match self {
            Self::RussianSites => "russian_sites",
            Self::Messengers => "messengers",
            Self::Youtube => "youtube",
            Self::Torrents => "torrents",
            Self::AiServices => "ai_services",
            Self::Social => "social",
            Self::Streaming => "streaming",
            Self::Gaming => "gaming",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|preset| preset.key() == key)
    }

    /// Default group name used when migrating or importing a legacy template.
    pub fn default_name(self, russian: bool) -> &'static str {
        match (self, russian) {
            (Self::RussianSites, true) => "Российские сайты",
            (Self::RussianSites, false) => "Russian sites",
            (Self::Messengers, true) => "Мессенджеры",
            (Self::Messengers, false) => "Messengers",
            (Self::Youtube, _) => "YouTube",
            (Self::Torrents, true) => "Торренты",
            (Self::Torrents, false) => "Torrents",
            (Self::AiServices, true) => "ИИ-сервисы",
            (Self::AiServices, false) => "AI services",
            (Self::Social, true) => "Соцсети",
            (Self::Social, false) => "Social media",
            (Self::Streaming, true) => "Стриминг и музыка",
            (Self::Streaming, false) => "Streaming & music",
            (Self::Gaming, true) => "Игры и лаунчеры",
            (Self::Gaming, false) => "Games & launchers",
        }
    }

    pub fn default_target(self) -> RuleTarget {
        match self {
            Self::RussianSites | Self::Torrents | Self::Gaming => RuleTarget::Direct,
            Self::Messengers
            | Self::Youtube
            | Self::AiServices
            | Self::Social
            | Self::Streaming => RuleTarget::Proxy,
        }
    }

    /// Builds an editable group matcher initialized with this preset's conditions.
    pub fn to_group(self, name: impl Into<String>) -> RuleMatcher {
        RuleMatcher::Group {
            name: name.into(),
            items: self.matchers(),
        }
    }

    /// The plain matchers the preset supplies when creating a rule group.
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
                #[cfg(windows)]
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
                #[cfg(not(windows))]
                &[
                    "Telegram",
                    "telegram-desktop",
                    "Discord",
                    "DiscordPTB",
                    "DiscordCanary",
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
                #[cfg(windows)]
                &[
                    "qbittorrent.exe",
                    "utorrent.exe",
                    "bittorrent.exe",
                    "transmission-qt.exe",
                    "tixati.exe",
                    "deluge.exe",
                    "biglybt.exe",
                ],
                #[cfg(not(windows))]
                &[
                    "qbittorrent",
                    "qbittorrent-nox",
                    "transmission-gtk",
                    "transmission-qt",
                    "transmission-daemon",
                    "deluge",
                    "deluged",
                    "ktorrent",
                    "rtorrent",
                ],
                &[],
            ),
            Self::AiServices => (
                &[],
                &[
                    "openai.com",
                    "chatgpt.com",
                    "oaistatic.com",
                    "oaiusercontent.com",
                    "claude.ai",
                    "anthropic.com",
                    "gemini.google.com",
                    "aistudio.google.com",
                    "perplexity.ai",
                    "copilot.microsoft.com",
                    "githubcopilot.com",
                ],
            ),
            Self::Social => (
                &[],
                &[
                    "instagram.com",
                    "cdninstagram.com",
                    "x.com",
                    "twitter.com",
                    "twimg.com",
                    "t.co",
                    "facebook.com",
                    "fbcdn.net",
                    "linkedin.com",
                    "reddit.com",
                    "redd.it",
                    "redditmedia.com",
                ],
            ),
            Self::Streaming => (
                &[],
                &[
                    "spotify.com",
                    "scdn.co",
                    "netflix.com",
                    "nflxvideo.net",
                    "twitch.tv",
                    "ttvnw.net",
                    "jtvnw.net",
                    "soundcloud.com",
                ],
            ),
            Self::Gaming => (
                #[cfg(windows)]
                &[
                    "steam.exe",
                    "EpicGamesLauncher.exe",
                    "Battle.net.exe",
                    "RiotClientServices.exe",
                    "EADesktop.exe",
                    "upc.exe",
                ],
                #[cfg(not(windows))]
                &["steam", "heroic", "lutris", "bottles"],
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
    Exit,
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

    /// The same rules with every group replaced, in place, by its plain
    /// matchers. Each expanded rule keeps the group rule's id, enabled flag
    /// and target, so an engine refusing one names the group.
    pub fn with_groups_expanded(&self) -> RuleSet {
        self.expand_groups().0
    }

    /// [`Self::with_groups_expanded`], plus which group name each expanded
    /// rule id came from: the expanded rules no longer carry it.
    pub fn expand_groups(&self) -> (RuleSet, Vec<(RuleId, String)>) {
        let mut expanded = self.clone();
        let mut origins = Vec::new();
        expanded.rules = self
            .rules
            .iter()
            .flat_map(|rule| match &rule.matcher {
                RuleMatcher::Group { name, items } => {
                    origins.push((rule.id.clone(), name.clone()));
                    items
                        .iter()
                        .filter(|matcher| !matches!(matcher, RuleMatcher::Group { .. }))
                        .map(|matcher| Rule {
                            matcher: matcher.clone(),
                            ..rule.clone()
                        })
                        .collect()
                }
                _ => vec![rule.clone()],
            })
            .collect();
        (expanded, origins)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_expand_in_place_with_original_rule_metadata() {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Test", RuleTarget::Proxy);
        let before = Rule {
            id: RuleId::new("a"),
            enabled: true,
            matcher: RuleMatcher::Domain(DomainMatch::Exact("a.example".into())),
            target: RuleTarget::Block,
            exit: None,
        };
        let group = Rule {
            id: RuleId::new("group"),
            enabled: false,
            matcher: RuleTemplate::Torrents.to_group("Torrents"),
            target: RuleTarget::Exit,
            exit: Some(ExitId::new("selected")),
        };
        let after = Rule {
            id: RuleId::new("b"),
            enabled: true,
            matcher: RuleMatcher::Process(ProcessMatch::Name("b.exe".into())),
            target: RuleTarget::Direct,
            exit: None,
        };
        set.rules = vec![before.clone(), group.clone(), after.clone()];
        let expanded = set.with_groups_expanded();
        assert_eq!(expanded.id, set.id);
        assert_eq!(expanded.name, set.name);
        assert_eq!(expanded.default_target, set.default_target);
        let conditions = RuleTemplate::Torrents.matchers().len();
        assert_eq!(expanded.rules.len(), conditions + 2);
        assert_eq!(expanded.rules.first(), Some(&before));
        assert_eq!(expanded.rules.last(), Some(&after));
        for (rule, matcher) in expanded.rules[1..=conditions]
            .iter()
            .zip(RuleTemplate::Torrents.matchers())
        {
            assert_eq!(rule.id, group.id);
            assert!(!rule.enabled);
            assert_eq!(rule.target, RuleTarget::Exit);
            assert_eq!(rule.exit, group.exit);
            assert_eq!(rule.matcher, matcher);
        }
        assert_eq!(set.rules[1], group);
        assert_eq!(
            set.expand_groups().1,
            [(group.id.clone(), "Torrents".to_owned())]
        );
    }

    #[test]
    fn rule_set_without_groups_is_unchanged() {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Test", RuleTarget::Direct);
        set.rules.push(Rule {
            id: RuleId::new("plain"),
            enabled: false,
            matcher: RuleMatcher::IpCidr("10.0.0.0/8".into()),
            target: RuleTarget::Block,
            exit: None,
        });
        assert_eq!(set.with_groups_expanded(), set);
    }

    #[test]
    fn preset_matchers_are_distinct() {
        for preset in RuleTemplate::ALL {
            let matchers = preset.matchers();
            assert!(!matchers.is_empty(), "{}", preset.key());
            for (index, matcher) in matchers.iter().enumerate() {
                assert!(
                    !matchers[..index].contains(matcher),
                    "duplicate in {}: {matcher:?}",
                    preset.key()
                );
            }
        }
    }

    #[test]
    fn preset_keys_and_group_serde_round_trip() {
        for preset in RuleTemplate::ALL {
            assert_eq!(RuleTemplate::from_key(preset.key()), Some(preset));
            assert!(!preset.default_name(false).is_empty());
            assert!(!preset.default_name(true).is_empty());
        }
        let matcher = RuleMatcher::Group {
            name: "Video".into(),
            items: vec![
                RuleMatcher::Domain(DomainMatch::Suffix("youtube.com".into())),
                RuleMatcher::Domain(DomainMatch::Suffix("youtu.be".into())),
            ],
        };
        let encoded = serde_json::to_value(&matcher).unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({
                "group": {
                    "name": "Video",
                    "items": [
                        { "domain": { "suffix": "youtube.com" } },
                        { "domain": { "suffix": "youtu.be" } }
                    ]
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<RuleMatcher>(encoded).unwrap(),
            matcher
        );
    }
}
