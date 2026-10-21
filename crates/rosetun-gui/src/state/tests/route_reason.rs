use rosetun_config::{ConnectionRoute, LiveConnection, ProcessMatch, RuleTemplate};
use rosetun_core::{ListPayload, PayloadFormat, SessionLists};

use super::super::route_reason::RouteReason;
use super::*;

fn rule(id: &str, matcher: RuleMatcher) -> Rule {
    Rule {
        id: RuleId::new(id),
        enabled: true,
        matcher,
        target: RuleTarget::Direct,
        exit: None,
    }
}

fn list_matcher(id: &str) -> RuleMatcher {
    RuleMatcher::List {
        list: ListId::new(id),
        category: Some("example".into()),
    }
}

/// Connected on the Traffic tab with these rules sent by the connect.
fn connected(rules: Vec<Rule>, temporary: Vec<Rule>) -> State {
    let mut state = state_for_auto_connect();
    let mut set = RuleSet::new(RuleSetId::new("set"), "Set", RuleTarget::Proxy);
    set.rules = rules;
    state.config.rule_sets.push(set);
    state.config.active_rule_set = Some(RuleSetId::new("set"));
    state.config.settings.allow_lan = true;
    let mut request = ConnectRequest::from_config(&state.config).unwrap();
    request.temporary_rules = temporary;
    state.reduce(WorkerEvent::Connect(Ok(request)));
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        ..Status::default()
    }));
    assert!(state.act(Action::OpenTraffic).is_none());
    state
}

fn connection(host: &str, process: Option<&str>, route: ConnectionRoute) -> LiveConnection {
    LiveConnection {
        id: format!("{host}-id"),
        start_unix_ms: 1_000,
        end_unix_ms: None,
        process: process.map(str::to_owned),
        host: host.to_owned(),
        ip: host
            .parse::<std::net::IpAddr>()
            .is_err()
            .then(|| "192.0.2.1".to_owned()),
        port: 443,
        network: rosetun_config::ConnectionNetwork::Tcp,
        route,
        download: 0,
        upload: 0,
    }
}

fn known(text: String, edit: Option<&str>) -> RouteReason {
    RouteReason {
        text,
        hint: None,
        edit: edit.map(RuleId::new),
        nameless: false,
        changed: false,
    }
}

fn open(state: &mut State, connection: &LiveConnection) -> Option<Job> {
    assert!(matches!(
        state.take_connections(now_unix()),
        Some(Job::Connections)
    ));
    state.reduce(WorkerEvent::Connections {
        result: Ok((vec![connection.clone()], Vec::new())),
        received_ms: 0,
    });
    state.act(Action::SelectConnection(Some(connection.id.clone())));
    state.take_session_lists()
}

#[test]
fn every_kind_of_answer_has_its_line() {
    let state = connected(
        vec![
            rule(
                "exact",
                RuleMatcher::Domain(DomainMatch::Exact("exact.example.com".into())),
            ),
            rule(
                "suffix",
                RuleMatcher::Domain(DomainMatch::Suffix("example.net".into())),
            ),
            rule("torrents", RuleMatcher::Template(RuleTemplate::Torrents)),
        ],
        vec![rule(
            "temporary",
            RuleMatcher::Domain(DomainMatch::Suffix("temporary.example.com".into())),
        )],
    );
    let reason = |host: &str, process: Option<&str>, route| {
        state.route_reason(&connection(host, process, route))
    };

    assert_eq!(
        reason("exact.example.com", None, ConnectionRoute::Direct),
        known(
            tr!(
                "connections-why-rule",
                number = "1".to_owned(),
                condition = "exact.example.com".to_owned()
            ),
            Some("exact")
        )
    );
    assert_eq!(
        reason("www.example.net", None, ConnectionRoute::Direct),
        known(
            tr!(
                "connections-why-rule",
                number = "2".to_owned(),
                condition = tr!(
                    "connections-why-subdomains",
                    site = "example.net".to_owned()
                )
            ),
            Some("suffix")
        )
    );
    assert_eq!(
        reason("www.temporary.example.com", None, ConnectionRoute::Direct),
        known(
            tr!(
                "connections-why-temporary",
                condition = tr!(
                    "connections-why-subdomains",
                    site = "temporary.example.com".to_owned()
                )
            ),
            None
        )
    );
    assert_eq!(
        reason(
            "nothing.invalid",
            Some(r"C:\Program Files\Example\qbittorrent.exe"),
            ConnectionRoute::Direct
        ),
        known(
            tr!(
                "connections-why-template",
                template = crate::i18n::template_name(RuleTemplate::Torrents),
                condition = "qbittorrent.exe".to_owned()
            ),
            None
        )
    );
    assert_eq!(
        reason("127.0.0.1", None, ConnectionRoute::Direct),
        RouteReason {
            nameless: true,
            ..known(tr!("connections-why-lan"), None)
        }
    );
    assert_eq!(
        reason("nothing.invalid", None, ConnectionRoute::Proxy),
        known(tr!("connections-why-default-proxy"), None)
    );
}

#[test]
fn a_route_the_engine_did_not_take_is_not_explained() {
    let state = connected(
        vec![rule(
            "exact",
            RuleMatcher::Domain(DomainMatch::Exact("exact.example.com".into())),
        )],
        Vec::new(),
    );

    for route in [ConnectionRoute::Proxy, ConnectionRoute::Other] {
        assert_eq!(
            state.route_reason(&connection("exact.example.com", None, route)),
            RouteReason {
                hint: Some(tr!("connections-why-unknown-mismatch")),
                ..known(tr!("connections-why-unknown"), None)
            }
        );
    }
}

#[test]
fn lists_are_read_once_for_the_session_and_forgotten_on_disconnect() {
    let mut state = connected(
        vec![
            rule("list", list_matcher("list")),
            rule("binary", list_matcher("binary")),
        ],
        Vec::new(),
    );
    state.config.lists.push(rosetun_config::List {
        id: ListId::new("list"),
        name: "My list".into(),
        source: rosetun_config::ListSource::File {
            original_name: "list.dat".into(),
        },
        format: rosetun_config::ListFormat::GeoSite,
        updated_at: None,
        size: None,
        sha256: None,
        categories: vec!["example".into()],
    });
    let listed = connection("www.list.example.com", None, ConnectionRoute::Direct);
    let other = connection("nothing.invalid", None, ConnectionRoute::Proxy);

    let Some(Job::SessionLists { request, session }) = open(&mut state, &listed) else {
        panic!("the lists are read");
    };
    assert_eq!(session.rule_set.rules.len(), 2);
    assert_eq!(
        state.route_reason(&listed).text,
        tr!("connections-why-checking")
    );
    assert!(state.take_session_lists().is_none(), "one read at a time");

    let mut lists = SessionLists::default();
    lists.insert(
        &ListId::new("list"),
        Some("example"),
        Some(&ListPayload {
            format: PayloadFormat::Source,
            bytes: br#"{"version":3,"rules":[{"domain_suffix":["list.example.com"]}]}"#.to_vec(),
        }),
    );
    lists.insert(
        &ListId::new("binary"),
        Some("example"),
        Some(&ListPayload {
            format: PayloadFormat::Binary,
            bytes: b"SRS".to_vec(),
        }),
    );
    state.reduce(WorkerEvent::SessionLists {
        request,
        result: Ok(lists),
    });
    assert!(state.take_session_lists().is_none(), "kept for the session");

    assert_eq!(
        state.route_reason(&listed),
        known(
            tr!(
                "connections-why-list",
                list = "My list: example".to_owned(),
                number = "1".to_owned()
            ),
            Some("list")
        )
    );
    assert_eq!(
        state.route_reason(&other),
        RouteReason {
            hint: Some(tr!("connections-why-unknown-list")),
            ..known(tr!("connections-why-unknown"), None)
        }
    );

    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Disconnected,
        ..Status::default()
    }));
    assert_eq!(
        state.route_reason(&listed),
        RouteReason {
            hint: Some(tr!("connections-why-unknown-session")),
            ..known(tr!("connections-why-unknown"), None)
        }
    );
    assert!(matches!(
        state.traffic.lists.read,
        super::super::route_reason::ListsRead::Unread
    ));
}

#[test]
fn changed_rules_that_are_not_applied_are_noted() {
    let mut state = connected(
        vec![rule(
            "path",
            RuleMatcher::Process(ProcessMatch::Path(
                r"C:\Program Files\Example\app.exe".into(),
            )),
        )],
        Vec::new(),
    );
    let program = connection(
        "nothing.invalid",
        Some(r"C:\Program Files\Example\app.exe"),
        ConnectionRoute::Direct,
    );
    assert!(!state.route_reason(&program).changed);

    state.config.rule_sets[0].rules[0].target = RuleTarget::Proxy;
    let reason = state.route_reason(&program);
    assert!(reason.changed);
    assert_eq!(
        reason.text,
        tr!(
            "connections-why-rule",
            number = "1".to_owned(),
            condition = "app.exe".to_owned()
        ),
        "the running session's rules still answer"
    );
}
