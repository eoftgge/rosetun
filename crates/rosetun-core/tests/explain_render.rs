//! The explainer against the rendered sing-box configuration: a small route
//! evaluator walks the real `route.rules` and list sources, and for every
//! input its answer must equal the explainer's.

use std::collections::HashMap;
use std::net::IpAddr;

use regex_automata::meta::Regex;
use rosetun_config::{
    DomainMatch, ListId, ListRef, Node, NodeId, Outbound, ProcessMatch, Rule, RuleId, RuleMatcher,
    RuleSet, RuleSetId, RuleTarget, RuleTemplate, Selection, Settings, StreamSettings,
    SubscriptionId, TrojanParams, UploadedListFormat, list_tag,
};
use rosetun_core::{
    Destination, ExplainedRoute, Explanation, ListPayload, PayloadFormat, Reason, SessionLists,
    explain,
};
use rosetun_engine::RenderRequest;
use rosetun_ipc::ConnectRequest;
use serde_json::{Value, json};

/// Every input goes to this port.
const PORT: u16 = 443;

const LIST_SOURCE: &str = r#"{"version":3,"rules":[{"domain_suffix":["list.example.com"],"ip_cidr":["203.0.113.0/24"]}]}"#;

fn rule(id: &str, matcher: RuleMatcher, target: RuleTarget) -> Rule {
    Rule {
        id: RuleId::new(id),
        enabled: true,
        matcher,
        target,
        exit: None,
    }
}

fn request(allow_lan: bool) -> ConnectRequest {
    let mut set = RuleSet::new(RuleSetId::new("set"), "Set", RuleTarget::Proxy);
    set.rules = vec![
        rule(
            "exact",
            RuleMatcher::Domain(DomainMatch::Exact("exact.example.com".into())),
            RuleTarget::Direct,
        ),
        rule(
            "shadowed",
            RuleMatcher::Domain(DomainMatch::Exact("temporary.example.com".into())),
            RuleTarget::Block,
        ),
        rule(
            "suffix",
            RuleMatcher::Domain(DomainMatch::Suffix("example.net".into())),
            RuleTarget::Direct,
        ),
        rule(
            "keyword",
            RuleMatcher::Domain(DomainMatch::Keyword("kwtest".into())),
            RuleTarget::Direct,
        ),
        rule(
            "cidr",
            RuleMatcher::IpCidr("198.51.100.0/24".into()),
            RuleTarget::Direct,
        ),
        rule(
            "name",
            RuleMatcher::Process(ProcessMatch::Name("Example.exe".into())),
            RuleTarget::Direct,
        ),
        rule(
            "path",
            RuleMatcher::Process(ProcessMatch::Path(
                r"C:\Program Files\Example\app.exe".into(),
            )),
            RuleTarget::Direct,
        ),
        rule(
            "list",
            RuleMatcher::List {
                list: ListId::new("list"),
                category: Some("example".into()),
            },
            RuleTarget::Direct,
        ),
        rule(
            "template",
            RuleMatcher::Template(RuleTemplate::Torrents),
            RuleTarget::Direct,
        ),
        Rule {
            enabled: false,
            ..rule(
                "disabled",
                RuleMatcher::Domain(DomainMatch::Suffix("nothing.invalid".into())),
                RuleTarget::Direct,
            )
        },
    ];
    let (rule_set, rule_templates) = set.expand_templates();
    ConnectRequest {
        selection: Selection {
            subscription: SubscriptionId::new("example"),
            node: NodeId::new("node"),
        },
        node: Node {
            id: NodeId::new("node"),
            name: "Example node".into(),
            server: "203.0.113.10".into(),
            port: 443,
            outbound: Outbound::Trojan(TrojanParams {
                password: "test-secret".into(),
            }),
            stream: StreamSettings::default(),
            raw: None,
        },
        rule_set,
        extra_nodes: Vec::new(),
        temporary_rules: vec![rule(
            "temporary",
            RuleMatcher::Domain(DomainMatch::Suffix("temporary.example.com".into())),
            RuleTarget::Direct,
        )],
        lists: vec![ListRef {
            tag: list_tag(&ListId::new("list"), Some("example")),
            sha256: "a".repeat(64),
            format: UploadedListFormat::Source,
        }],
        settings: Settings {
            allow_lan,
            ..Settings::default()
        },
        rule_templates,
    }
}

struct Input {
    domain: Option<&'static str>,
    ip: Option<&'static str>,
    process: Option<&'static str>,
}

const fn site(domain: &'static str, ip: &'static str) -> Input {
    Input {
        domain: Some(domain),
        ip: Some(ip),
        process: None,
    }
}

const fn program(process: &'static str) -> Input {
    Input {
        domain: Some("nothing.invalid"),
        ip: Some("192.0.2.1"),
        process: Some(process),
    }
}

const INPUTS: &[Input] = &[
    site("exact.example.com", "192.0.2.1"),
    site("www.exact.example.com", "192.0.2.1"),
    site("example.net", "192.0.2.1"),
    site("www.example.net", "192.0.2.1"),
    site("badexample.net", "192.0.2.1"),
    site("a-kwtest-b.invalid", "192.0.2.1"),
    site("nothing.invalid", "198.51.100.7"),
    Input {
        domain: None,
        ip: Some("198.51.100.7"),
        process: None,
    },
    Input {
        domain: None,
        ip: Some("192.0.2.1"),
        process: None,
    },
    program(r"C:\Program Files\Example\EXAMPLE.EXE"),
    program(r"C:\Program Files\Example\NotExample.exe"),
    program(r"C:\Program Files\Example\app.exe"),
    program(r"C:\PROGRAM FILES\EXAMPLE\APP.EXE"),
    program(r"C:\Program Files\Example\qbittorrent.exe"),
    site("www.list.example.com", "192.0.2.1"),
    site("nothing.invalid", "203.0.113.5"),
    site("temporary.example.com", "192.0.2.1"),
    site("www.temporary.example.com", "192.0.2.1"),
    site("nothing.invalid", "127.0.0.1"),
    Input {
        domain: None,
        ip: Some("127.0.0.1"),
        process: None,
    },
    site("nothing.invalid", "192.0.2.1"),
    site("NOTHING.INVALID", "192.0.2.1"),
];

/// What the evaluator found: the matching route rule's index (`None` for
/// `final`) and its outbound (`None` for reject).
#[derive(Debug, PartialEq)]
struct Evaluated {
    index: Option<usize>,
    outbound: Option<String>,
}

fn evaluate(route: &Value, sources: &HashMap<String, Value>, input: &Input) -> Evaluated {
    for (index, rule) in route["rules"].as_array().unwrap().iter().enumerate() {
        let action = rule["action"].as_str().unwrap();
        if action == "sniff" || !matches(rule, sources, input) {
            continue;
        }
        return Evaluated {
            index: Some(index),
            outbound: match action {
                "route" => Some(rule["outbound"].as_str().unwrap().to_owned()),
                "reject" => None,
                other => panic!("unexpected action {other}"),
            },
        };
    }
    Evaluated {
        index: None,
        outbound: Some(route["final"].as_str().unwrap().to_owned()),
    }
}

fn strings(value: &Value) -> impl Iterator<Item = &str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
}

fn contains(cidr: &str, ip: IpAddr) -> bool {
    let (network, prefix) = cidr.split_once('/').unwrap();
    let network: IpAddr = network.parse().unwrap();
    let prefix: u32 = prefix.parse().unwrap();
    match (network, ip) {
        (IpAddr::V4(network), IpAddr::V4(ip)) => {
            let shift = 32 - prefix;
            u32::from(network).checked_shr(shift).unwrap_or(0)
                == u32::from(ip).checked_shr(shift).unwrap_or(0)
        }
        (IpAddr::V6(network), IpAddr::V6(ip)) => {
            let shift = 128 - prefix;
            u128::from(network).checked_shr(shift).unwrap_or(0)
                == u128::from(ip).checked_shr(shift).unwrap_or(0)
        }
        _ => false,
    }
}

/// sing-box rule matching: the destination address conditions match if any
/// one does, every other condition must match.
fn matches(rule: &Value, sources: &HashMap<String, Value>, input: &Input) -> bool {
    let domain = input.domain.map(str::to_lowercase);
    let ip: Option<IpAddr> = input.ip.map(|ip| ip.parse().unwrap());
    let mut address = None::<bool>;
    let mut others = true;
    for (key, value) in rule.as_object().unwrap() {
        let mut any_address = |hit: bool| *address.get_or_insert(false) |= hit;
        match key.as_str() {
            "action" | "outbound" | "sniffer" => {}
            "domain" => any_address(
                domain
                    .as_deref()
                    .is_some_and(|domain| strings(value).any(|entry| entry == domain)),
            ),
            "domain_suffix" => any_address(domain.as_deref().is_some_and(|domain| {
                strings(value).any(|entry| {
                    if entry.starts_with('.') {
                        domain.ends_with(entry)
                    } else {
                        domain == entry || domain.ends_with(&format!(".{entry}"))
                    }
                })
            })),
            "domain_keyword" => any_address(
                domain
                    .as_deref()
                    .is_some_and(|domain| strings(value).any(|entry| domain.contains(entry))),
            ),
            "ip_cidr" => {
                any_address(ip.is_some_and(|ip| strings(value).any(|cidr| contains(cidr, ip))))
            }
            // The documentation addresses are public; only loopback stands for
            // a local one here.
            "ip_is_private" => any_address(ip.is_some_and(|ip| ip.is_loopback())),
            "protocol" => others = false,
            "port" => others &= value.as_array().unwrap().contains(&json!(PORT)),
            "process_path" => {
                others &= input
                    .process
                    .is_some_and(|path| strings(value).any(|entry| entry == path));
            }
            "process_path_regex" => {
                others &= input.process.is_some_and(|path| {
                    strings(value).any(|pattern| Regex::new(pattern).unwrap().is_match(path))
                });
            }
            "rule_set" => {
                others &= strings(value).any(|tag| {
                    sources[tag]["rules"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|headless| matches(headless, sources, input))
                });
            }
            other => panic!("the evaluator does not know {other}"),
        }
    }
    address.unwrap_or(true) && others
}

#[test]
fn the_explainer_agrees_with_the_rendered_route() {
    let mut sources = HashMap::new();
    sources.insert(
        list_tag(&ListId::new("list"), Some("example")),
        serde_json::from_str::<Value>(LIST_SOURCE).unwrap(),
    );
    let mut lists = SessionLists::default();
    lists.insert(
        &ListId::new("list"),
        Some("example"),
        Some(&ListPayload {
            format: PayloadFormat::Source,
            bytes: LIST_SOURCE.as_bytes().to_vec(),
        }),
    );

    for allow_lan in [false, true] {
        let request = request(allow_lan);
        let effective = request.effective_rule_set();
        let rendered = rosetun_engine_singbox::render(&RenderRequest {
            node: &request.node,
            socks: None,
            extra: &[],
            rules: &effective,
            lists: &request.lists,
            settings: &request.settings,
            control: None,
            verbose_log: false,
        })
        .unwrap();
        assert!(rendered.unsupported.is_empty());
        let config: Value = serde_json::from_slice(&rendered.body).unwrap();
        let route_rules = config["route"]["rules"].as_array().unwrap();
        // Every rendered rule after the service's own stands for one enabled rule.
        let first_user_rule = route_rules.len()
            - effective.enabled().count()
            - usize::from(allow_lan)
            - usize::from(config["route"]["final"] != "proxy");
        let enabled: Vec<_> = effective.enabled().collect();

        for input in INPUTS {
            let label = format!("{:?} {:?} {:?}", input.domain, input.ip, input.process);
            let evaluated = evaluate(&config["route"], &sources, input);
            let explanation = explain(
                &request,
                &lists,
                &Destination {
                    domain: input.domain,
                    ip: input.ip.map(|ip| ip.parse().unwrap()),
                    process: input.process,
                },
            );
            let Explanation::Routed { reason, route } = explanation else {
                panic!("{label}: unverifiable");
            };
            let outbound = match route {
                ExplainedRoute::Proxy => Some("proxy".to_owned()),
                ExplainedRoute::Direct => Some("direct".to_owned()),
                ExplainedRoute::Block => None,
                ExplainedRoute::Exit(_) => panic!("{label}: no exits here"),
            };
            assert_eq!(
                outbound, evaluated.outbound,
                "{label}, allow_lan {allow_lan}"
            );
            match (reason, evaluated.index) {
                (Reason::Rule { id, temporary, .. }, Some(index)) => {
                    let matched = enabled[index - first_user_rule];
                    assert_eq!(id, matched.id, "{label}");
                    assert_eq!(temporary, matched.id.as_str() == "temporary", "{label}");
                }
                (Reason::LocalNetwork, Some(index)) => {
                    assert!(allow_lan, "{label}");
                    assert_eq!(route_rules[index]["ip_is_private"], true, "{label}");
                }
                (Reason::Default, None) => {}
                (Reason::Default, Some(index)) => {
                    assert_eq!(route_rules[index], json!({ "action": "reject" }), "{label}");
                }
                (reason, index) => panic!("{label}: {reason:?} against rule {index:?}"),
            }
        }
    }
}
