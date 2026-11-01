use rosetun_config::{LogLevel, Node, NodeId, Outbound, ProxyCredentials, StreamSettings};
use rosetun_engine::errors::EngineError;
use rosetun_engine_xray::{SocksEndpoint, render};

#[test]
fn external_proxies_are_not_silently_rendered_by_the_xray_chain() {
    let socks = SocksEndpoint::local().unwrap();
    for outbound in [
        Outbound::Http(ProxyCredentials::default()),
        Outbound::Socks5(ProxyCredentials::default()),
    ] {
        let node = Node {
            id: NodeId::new("fixture"),
            name: "Example".into(),
            server: "192.0.2.1".into(),
            port: 1080,
            outbound,
            stream: StreamSettings::default(),
            raw: None,
        };
        assert!(matches!(
            render(
                &[("proxy", &node, &socks)],
                "fixture-interface",
                false,
                LogLevel::Info
            ),
            Err(EngineError::Unsupported(_))
        ));
    }
}
