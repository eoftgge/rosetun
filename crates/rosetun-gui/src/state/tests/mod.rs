use super::*;
use rosetun_config::{
    DomainMatch, Node, NodeId, Outbound, Rule, RuleMatcher, Selection, VlessParams,
};
use rosetun_core::{FetchError, ParseError, RemoveSubscriptionError, RuleSetError, StoreError};
use rosetun_ipc::ConnectRequestError;
use rosetun_processes::RunningProcess;

fn report() -> UpdateReport {
    UpdateReport {
        added: 2,
        removed: 1,
        retained: 3,
        selection_cleared: true,
        skipped: BTreeMap::new(),
        notices: vec![],
    }
}

fn subscription(id: &str) -> rosetun_config::Subscription {
    rosetun_config::Subscription {
        id: SubscriptionId::new(id),
        name: "Provider".into(),
        url: "https://example.com/secret-path".into(),
        nodes: vec![],
        auto_update: false,
        updated_at_unix: None,
        user_agent: None,
        send_hwid: true,
        info: None,
        update_interval_hours: None,
        support_url: None,
        web_page_url: None,
        announce: None,
        notices: vec![],
    }
}

fn rule_set(id: &str) -> RuleSet {
    let mut set = RuleSet::new(RuleSetId::new(id), id, RuleTarget::Proxy);
    for (index, domain) in ["first.example", "second.example", "third.example"]
        .into_iter()
        .enumerate()
    {
        set.rules.push(Rule {
            id: RuleId::new(index.to_string()),
            enabled: true,
            matcher: RuleMatcher::Domain(DomainMatch::Exact(domain.into())),
            target: RuleTarget::Proxy,
        });
    }
    set
}

fn state_with_subscriptions() -> State {
    State {
        config_ready: true,
        config: AppConfig {
            subscriptions: ["1", "2", "3"].map(subscription).to_vec(),
            ..AppConfig::default()
        },
        ..State::default()
    }
}

fn state_with_rules() -> State {
    State {
        config_ready: true,
        config: AppConfig {
            rule_sets: vec![rule_set("1"), rule_set("2")],
            active_rule_set: Some(RuleSetId::new("2")),
            ..AppConfig::default()
        },
        ..State::default()
    }
}

fn state_for_auto_connect() -> State {
    let mut provider = subscription("1");
    provider.nodes.push(Node {
        id: NodeId::new("node"),
        name: "Test".into(),
        server: "127.0.0.1".into(),
        port: 443,
        outbound: Outbound::Vless(VlessParams {
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            flow: None,
        }),
        stream: Default::default(),
        raw: None,
    });
    let mut config = AppConfig::default();
    config.subscriptions.push(provider);
    config.active = Some(Selection {
        subscription: SubscriptionId::new("1"),
        node: NodeId::new("node"),
    });
    config.interface.connect_on_start = true;
    State {
        config,
        config_ready: true,
        helper_available: true,
        ..State::default()
    }
}

fn exit_info(ip: &str) -> rosetun_core::ExitInfo {
    rosetun_core::ExitInfo {
        ip: ip.parse().unwrap(),
        country: Some("NL".into()),
    }
}

fn connected_state_for_apply() -> State {
    let mut state = state_for_auto_connect();
    state.config.rule_sets.push(rule_set("1"));
    state.config.active_rule_set = Some(RuleSetId::new("1"));
    let request = ConnectRequest::from_config(&state.config).unwrap();
    state.reduce(WorkerEvent::Connect(Ok(request)));
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        since_unix: Some(now_unix().saturating_sub(30)),
        ..Status::default()
    }));
    state
}

fn temporary_rule(id: &str, domain: &str) -> Rule {
    Rule {
        id: RuleId::new(id),
        enabled: true,
        matcher: RuleMatcher::Domain(DomainMatch::Exact(domain.into())),
        target: RuleTarget::Direct,
    }
}

fn temporary_dialog(state: &mut State, domain: &str) {
    let id = RuleSetId::new("1");
    state.rule_screen.selected_set = Some(id.clone());
    let mut dialog = AddRuleDialog::new(id);
    dialog.kind = RuleInputKind::Domain;
    dialog.domains = domain.into();
    dialog.subdomains = false;
    dialog.target = RuleTarget::Direct;
    dialog.temporary_only = true;
    state.rule_screen.add = Some(dialog);
}

fn complete_applied_restore(state: &mut State) -> AppliedSnapshot {
    let Some(Job::RestoreApplied(snapshot)) = state.take_restore() else {
        panic!("failed apply must restore the running configuration");
    };
    let failed = AppliedSnapshot::from_config(&state.config);
    let mut restored = state.config.clone();
    if let Some(set) = snapshot.rule_set {
        if let Some(current) = restored.rule_sets.iter_mut().find(|item| item.id == set.id) {
            *current = set.clone();
        } else {
            restored.rule_sets.push(set.clone());
        }
        restored.active_rule_set = Some(set.id);
    } else {
        restored.active_rule_set = None;
    }
    restored.settings.dns = snapshot.dns;
    state.reduce(WorkerEvent::Config {
        generation: state.config_generation + 1,
        config: restored,
    });
    state.reduce(WorkerEvent::RestoreApplied(Ok(failed.clone())));
    failed
}

mod connection;
mod rules;
mod session;
mod settings;
mod startup;
mod subscriptions;
mod traffic;
mod updates;
