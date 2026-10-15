use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};

use crate::{ExitId, Node, Selection, Subscription, node_country};

const ISO_CODES: &str = concat!(
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ ",
    "BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ ",
    "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ ",
    "DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR ",
    "GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY ",
    "HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT ",
    "JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ ",
    "LA LB LC LI LK LR LS LT LU LV LY ",
    "MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ ",
    "NA NC NE NF NG NI NL NO NP NR NU NZ OM ",
    "PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA ",
    "RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ ",
    "TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ ",
    "UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW",
);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct CountryCode(String);

impl CountryCode {
    pub fn parse(value: &str) -> Option<Self> {
        (value.len() == 2
            && value.bytes().all(|byte| byte.is_ascii_uppercase())
            && ISO_CODES.split_ascii_whitespace().any(|code| code == value))
        .then(|| Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Every accepted code, in alphabetical order.
    pub fn all() -> impl Iterator<Item = Self> {
        ISO_CODES
            .split_ascii_whitespace()
            .map(|code| Self(code.to_owned()))
    }
}

impl<'de> Deserialize<'de> for CountryCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let code = String::deserialize(deserializer)?;
        Self::parse(&code).ok_or_else(|| serde::de::Error::custom("invalid ISO country code"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exit {
    pub id: ExitId,
    pub name: String,
    pub target: ExitTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitTarget {
    Node {
        selection: Selection,
        fallback: Option<CountryCode>,
    },
    Country(CountryCode),
}

fn selected_node<'a>(subscriptions: &'a [Subscription], selection: &Selection) -> Option<&'a Node> {
    subscriptions
        .iter()
        .find(|subscription| subscription.id == selection.subscription)
        .and_then(|subscription| subscription.node(&selection.node))
}

fn country_node(
    code: &CountryCode,
    subscriptions: &[Subscription],
    delays: &[(Selection, Duration)],
    selected: Option<&Selection>,
) -> Option<Selection> {
    if let Some(selection) = selected
        && selected_node(subscriptions, selection)
            .and_then(|node| node_country(&node.name))
            .as_ref()
            == Some(code)
    {
        return Some(selection.clone());
    }

    let mut first = None;
    let mut best: Option<(Duration, Selection)> = None;
    for subscription in subscriptions {
        for node in &subscription.nodes {
            if node_country(&node.name).as_ref() != Some(code) {
                continue;
            }
            let selection = Selection {
                subscription: subscription.id.clone(),
                node: node.id.clone(),
            };
            if first.is_none() {
                first = Some(selection.clone());
            }
            if let Some((_, delay)) = delays.iter().find(|(node, _)| node == &selection)
                && best.as_ref().is_none_or(|(fastest, _)| delay < fastest)
            {
                best = Some((*delay, selection));
            }
        }
    }
    best.map(|(_, selection)| selection).or(first)
}

/// Retains a country's selected node while it still belongs to that country.
/// The caller passes the previous selections back on Apply to avoid changing exit IPs mid-session.
pub fn resolve_exits(
    exits: &[Exit],
    subscriptions: &[Subscription],
    delays: &[(Selection, Duration)],
    selected: &[(ExitId, Selection)],
) -> Vec<(ExitId, Option<Selection>)> {
    exits
        .iter()
        .map(|exit| {
            let previous = selected
                .iter()
                .find(|(id, _)| id == &exit.id)
                .map(|(_, selection)| selection);
            let node = match &exit.target {
                ExitTarget::Node {
                    selection,
                    fallback,
                } => {
                    if selected_node(subscriptions, selection).is_some() {
                        Some(selection.clone())
                    } else {
                        fallback.as_ref().and_then(|country| {
                            country_node(country, subscriptions, delays, previous)
                        })
                    }
                }
                ExitTarget::Country(code) => country_node(code, subscriptions, delays, previous),
            };
            (exit.id.clone(), node)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_code_accepts_only_iso_alpha_two() {
        for code in ["DE", "GB", "US", "AX", "ZW"] {
            assert_eq!(CountryCode::parse(code).unwrap().as_str(), code);
            assert!(serde_json::from_str::<CountryCode>(&format!("\"{code}\"")).is_ok());
        }
        for code in ["", "U", "USA", "uk", "UK", "ZZ", "XK", "12", "ÉU"] {
            assert!(CountryCode::parse(code).is_none(), "{code}");
            assert!(serde_json::from_str::<CountryCode>(&format!("\"{code}\"")).is_err());
        }
    }
}
