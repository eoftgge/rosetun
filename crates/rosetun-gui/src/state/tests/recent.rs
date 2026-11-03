use std::io;
use std::sync::{Arc, Mutex};

use rosetun_config::{ConnectionNetwork, ConnectionRoute, DomainMatch, LiveConnection};

use super::*;

fn live(host: &str, ip: Option<&str>, start: u64, end: Option<u64>) -> LiveConnection {
    LiveConnection {
        id: format!("{host}-{start}"),
        start_unix_ms: start,
        end_unix_ms: end,
        process: None,
        host: host.to_owned(),
        ip: ip.map(str::to_owned),
        port: 443,
        network: ConnectionNetwork::Tcp,
        route: ConnectionRoute::Proxy,
        download: 2,
        upload: 1,
    }
}

fn answer(active: Vec<LiveConnection>, closed: Vec<LiveConnection>) -> WorkerEvent {
    WorkerEvent::Connections {
        result: Ok((active, closed)),
        received_ms: 0,
    }
}

/// A tunnel that is up and the add-rule dialog open on the address kind.
fn address_dialog() -> State {
    let mut state = state_with_rules();
    state.helper_available = true;
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    state.act(Action::OpenRules);
    state.act(Action::OpenAddRule);
    state.act(Action::SelectRuleInput(RuleInputKind::Address));
    state
}

fn sites(state: &State) -> Vec<String> {
    state
        .recent_sites()
        .into_iter()
        .map(|site| site.address)
        .collect()
}

#[test]
fn the_address_tab_asks_for_the_connections_and_gives_them_up_when_it_is_left() {
    let mut state = state_with_rules();
    state.helper_available = true;
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    state.act(Action::OpenRules);
    state.act(Action::OpenAddRule);
    assert!(
        state.take_connections(100).is_none(),
        "the program tab does not need them"
    );

    state.act(Action::SelectRuleInput(RuleInputKind::Address));
    assert!(matches!(
        state.take_connections(100),
        Some(Job::Connections)
    ));
    state.reduce(answer(vec![live("example.com", None, 1_000, None)], vec![]));
    assert_eq!(sites(&state), ["example.com"]);
    assert!(
        state.take_connections(100).is_none(),
        "once a second, like the Traffic tab"
    );
    assert!(matches!(
        state.take_connections(101),
        Some(Job::Connections)
    ));
    state.reduce(answer(vec![live("example.com", None, 1_000, None)], vec![]));

    state.act(Action::SelectRuleInput(RuleInputKind::List));
    assert!(state.take_connections(102).is_none());
    assert!(sites(&state).is_empty());
    assert!(
        state.traffic.connections.active.is_empty(),
        "the list is not kept once nothing shows it"
    );

    state.act(Action::SelectRuleInput(RuleInputKind::Address));
    assert!(state.take_connections(103).is_some());
    state.reduce(answer(vec![live("example.com", None, 1_000, None)], vec![]));
    state.act(Action::CancelAddRule);
    assert!(state.take_connections(104).is_none());
    assert!(state.traffic.connections.active.is_empty());
}

#[test]
fn a_list_the_traffic_tab_holds_stays_when_the_dialog_closes() {
    let mut state = state_with_rules();
    state.helper_available = true;
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    state.act(Action::OpenTraffic);
    assert!(state.take_connections(100).is_some());
    state.reduce(answer(vec![live("example.com", None, 1_000, None)], vec![]));
    assert!(!state.traffic.connections.active.is_empty());
    assert!(state.take_connections(101).is_some());
    assert!(!state.traffic.connections.active.is_empty());
}

#[test]
fn recent_sites_are_the_latest_first_each_once_and_no_more_than_twelve() {
    let mut state = address_dialog();
    state.take_connections(100);
    let active = vec![
        live("www.example.com", None, 5_000, None),
        live("old.example.net", None, 1_000, None),
    ];
    let mut closed = vec![
        live("example.com", None, 4_000, Some(4_500)),
        live("later.example.org", None, 6_000, Some(7_000)),
    ];
    closed.extend((0..14).map(|index| {
        live(
            &format!("site{index}.example.org"),
            None,
            100 + index,
            Some(200 + index),
        )
    }));
    state.reduce(answer(active, closed));
    let shown = sites(&state);
    assert_eq!(shown.len(), 12);
    assert_eq!(
        shown[..3],
        ["example.com", "old.example.net", "later.example.org"],
        "active connections first, then the closed ones by when they ended"
    );
    assert_eq!(
        shown.iter().filter(|site| *site == "example.com").count(),
        1,
        "www.example.com and example.com are one site"
    );
}

#[test]
fn an_address_shows_only_when_no_domain_was_seen_for_it() {
    let mut state = address_dialog();
    state.take_connections(100);
    state.reduce(answer(
        vec![
            live("cdn.example.com", Some("192.0.2.5"), 3_000, None),
            live("192.0.2.5", None, 2_000, None),
            live("198.51.100.7", None, 1_000, None),
            live("2001:db8::1", None, 500, None),
            live("not a host!", None, 400, None),
        ],
        vec![],
    ));
    assert_eq!(
        sites(&state),
        ["cdn.example.com", "198.51.100.7", "2001:db8::1"]
    );
}

#[test]
fn a_site_with_a_rule_in_the_set_is_marked() {
    let mut state = address_dialog();
    state.config.rule_sets[1].rules.push(Rule {
        id: RuleId::new("saved"),
        enabled: true,
        matcher: RuleMatcher::Domain(DomainMatch::Suffix("example.com".into())),
        target: RuleTarget::Proxy,
        exit: None,
    });
    state.session.temporary_rules.push(Rule {
        id: RuleId::new("temporary"),
        enabled: true,
        matcher: RuleMatcher::IpCidr("198.51.100.7/32".into()),
        target: RuleTarget::Proxy,
        exit: None,
    });
    state.take_connections(100);
    state.reduce(answer(
        vec![
            live("m.example.com", None, 4_000, None),
            live("example.org", None, 3_000, None),
            live("notexample.com", None, 2_000, None),
            live("198.51.100.7", None, 1_000, None),
        ],
        vec![],
    ));
    let marked: Vec<_> = state
        .recent_sites()
        .into_iter()
        .map(|site| (site.address, site.has_rule))
        .collect();
    assert_eq!(
        marked,
        [
            ("m.example.com".to_owned(), true),
            ("example.org".to_owned(), false),
            ("notexample.com".to_owned(), false),
            ("198.51.100.7".to_owned(), true),
        ]
    );
}

#[test]
fn without_a_tunnel_an_answer_or_a_new_rule_there_are_no_recent_sites() {
    let mut state = address_dialog();
    assert!(sites(&state).is_empty(), "nothing has answered yet");
    state.take_connections(100);
    state.reduce(answer(vec![live("example.com", None, 1_000, None)], vec![]));
    assert_eq!(sites(&state), ["example.com"]);

    state.reduce(WorkerEvent::Status(Status::default()));
    assert!(sites(&state).is_empty(), "the tunnel is down");
    assert!(state.take_connections(101).is_none());

    let mut state = address_dialog();
    state.take_connections(100);
    state.reduce(answer(vec![live("example.com", None, 1_000, None)], vec![]));
    state.act(Action::CancelAddRule);
    state.rules.screen.add = Some(
        AddRuleDialog::for_rule(
            RuleSetId::new("2"),
            &Rule {
                id: RuleId::new("1"),
                enabled: true,
                matcher: RuleMatcher::Domain(DomainMatch::Exact("example.org".into())),
                target: RuleTarget::Proxy,
                exit: None,
            },
        )
        .unwrap(),
    );
    assert!(sites(&state).is_empty(), "an edit has no suggestions");
}

#[test]
fn a_click_on_a_recent_site_adds_its_chip_and_a_second_click_removes_it() {
    let mut state = address_dialog();
    let dialog = state.rules.screen.add.as_mut().unwrap();
    assert!(!dialog.has_address("example.com"));
    dialog.toggle_address("example.com");
    assert!(dialog.has_address("example.com"));
    assert_eq!(dialog.addresses.len(), 1);
    dialog.toggle_address("192.0.2.1");
    assert_eq!(dialog.addresses.len(), 2);
    dialog.toggle_address("example.com");
    assert!(!dialog.has_address("example.com"));
    assert_eq!(dialog.addresses.len(), 1);
    assert!(dialog.has_address("192.0.2.1"));
}

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);

impl io::Write for Log {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn no_recent_site_reaches_the_log_at_any_level() {
    let log = Log::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer({
            let log = log.clone();
            move || log.clone()
        })
        .finish();
    let shown = tracing::subscriber::with_default(subscriber, || {
        let mut state = address_dialog();
        state.take_connections(100);
        state.reduce(answer(
            vec![live("private.example.com", Some("192.0.2.9"), 1_000, None)],
            vec![live("198.51.100.99", None, 900, Some(950))],
        ));
        let recent = state.recent_sites();
        let dialog = state.rules.screen.add.as_mut().unwrap();
        dialog.toggle_address("private.example.com");
        state.act(Action::CancelAddRule);
        state.take_connections(101);
        format!("{recent:?}")
    });
    let written = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    for secret in ["private.example.com", "198.51.100.99", "192.0.2.9"] {
        assert!(!written.contains(secret), "{secret} in the log");
        assert!(!shown.contains(secret), "{secret} in the debug output");
    }
}
