use serde_json::Value;

use crate::common::{Fields, build, clean, hysteria_ports, is_service_address};
use crate::wireguard::{self, WireGuardInput};
use crate::{Entry, Format, ParseError, Record, SkipReason, UnsupportedTransport};

const PROTOCOLS: &[&str] = &[
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "hysteria2",
    "tuic",
    "anytls",
    "wireguard",
];
const XRAY_PROTOCOLS: &[&str] = &["vless", "vmess", "trojan", "shadowsocks", "wireguard"];

pub(crate) fn format(value: &Value) -> Result<Format, ParseError> {
    if value.is_array() {
        return Ok(Format::XrayJson);
    }
    let outbounds = value.get("outbounds").and_then(Value::as_array);
    let endpoints = value.get("endpoints").and_then(Value::as_array);

    if outbounds.is_some_and(|list| {
        list.iter()
            .any(|outbound| outbound.get("protocol").is_some())
    }) {
        Ok(Format::XrayJson)
    } else if outbounds
        .is_some_and(|list| list.iter().any(|outbound| outbound.get("type").is_some()))
        || endpoints.is_some_and(|list| list.iter().any(|endpoint| endpoint.get("type").is_some()))
    {
        Ok(Format::SingBoxJson)
    } else {
        Err(ParseError::UnsupportedFormat)
    }
}

pub(crate) fn records(value: &Value, format: Format) -> Vec<Record> {
    match format {
        Format::XrayJson => match value.as_array() {
            Some(configs) => configs.iter().map(xray).collect(),
            None => vec![xray(value)],
        },
        Format::SingBoxJson => {
            let mut result: Vec<Record> = value
                .get("outbounds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|outbound| {
                    !matches!(
                        outbound.get("type").and_then(Value::as_str),
                        Some("selector" | "urltest" | "direct" | "block" | "dns")
                    )
                })
                .map(sing_box)
                .collect();
            result.extend(
                value
                    .get("endpoints")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(sing_box_endpoint),
            );
            result
        }
        Format::Links { .. } | Format::WireGuardConf => Vec::new(),
    }
}

fn xray(config: &Value) -> Record {
    let Some(outbounds) = config.get("outbounds").and_then(Value::as_array) else {
        return (None, Entry::Skip(SkipReason::InvalidRecord));
    };
    let supported = |outbound: &&Value| {
        outbound
            .get("protocol")
            .and_then(Value::as_str)
            .is_some_and(|protocol| XRAY_PROTOCOLS.contains(&protocol))
    };
    let outbound = outbounds
        .iter()
        .filter(supported)
        .find(|outbound| outbound.get("tag").and_then(Value::as_str) == Some("proxy"))
        .or_else(|| outbounds.iter().find(supported));

    let Some(outbound) = outbound else {
        if let Some(entry) = service_notice(config, outbounds) {
            return (None, entry);
        }
        let scheme = outbounds
            .iter()
            .find(|outbound| outbound.get("tag").and_then(Value::as_str) == Some("proxy"))
            .or_else(|| {
                outbounds.iter().find(|outbound| {
                    !matches!(
                        outbound.get("protocol").and_then(Value::as_str),
                        Some("freedom" | "blackhole" | "dns") | None
                    )
                })
            })
            .and_then(|outbound| outbound.get("protocol").and_then(Value::as_str))
            .and_then(|protocol| crate::known_scheme(&protocol.to_ascii_lowercase()))
            .map(str::to_owned);
        return (scheme, Entry::Skip(SkipReason::UnsupportedProtocol));
    };
    let protocol = outbound
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("");
    if protocol == "wireguard" {
        return xray_wireguard(config, outbound);
    }
    let scheme = normalize_protocol(protocol);
    let mut fields = Fields::new();
    put(&mut fields, "name", config.get("remarks"));

    let settings = &outbound["settings"];
    match protocol {
        "vless" | "vmess" => {
            let server = settings.pointer("/vnext/0").unwrap_or(settings);
            let user = server.pointer("/users/0").unwrap_or(server);
            put(&mut fields, "server", server.get("address"));
            put(&mut fields, "port", server.get("port"));
            for (source, target) in [
                ("id", "uuid"),
                ("flow", "flow"),
                ("encryption", "encryption"),
                ("alterId", "aid"),
                ("security", "cipher"),
            ] {
                put(&mut fields, target, user.get(source));
            }
        }
        "trojan" | "shadowsocks" => {
            let server = settings.pointer("/servers/0").unwrap_or(settings);
            for (source, target) in [
                ("address", "server"),
                ("port", "port"),
                ("password", "password"),
                ("method", "method"),
            ] {
                put(&mut fields, target, server.get(source));
            }
        }
        _ => {}
    }

    let stream = &outbound["streamSettings"];
    put(&mut fields, "transport", stream.get("network"));
    fields.insert("security".to_owned(), "none".to_owned());
    put(&mut fields, "security", stream.get("security"));

    let tls = &stream["tlsSettings"];
    for (source, target) in [
        ("serverName", "sni"),
        ("alpn", "alpn"),
        ("fingerprint", "fingerprint"),
        ("allowInsecure", "insecure"),
    ] {
        put(&mut fields, target, tls.get(source));
    }
    if fields
        .get("security")
        .is_some_and(|value| value == "reality")
    {
        let reality = &stream["realitySettings"];
        for (source, target) in [
            ("serverName", "sni"),
            ("shortId", "short_id"),
            ("fingerprint", "fingerprint"),
        ] {
            put(&mut fields, target, reality.get(source));
        }
        let key = reality
            .get("publicKey")
            .filter(|value| value.as_str().is_some_and(|value| !value.is_empty()))
            .or_else(|| reality.get("password"));
        put(&mut fields, "public_key", key);
    }

    match fields.get("transport").map_or("tcp", String::as_str) {
        "tcp" => put(
            &mut fields,
            "header",
            stream.pointer("/tcpSettings/header/type"),
        ),
        "raw" => put(
            &mut fields,
            "header",
            stream.pointer("/rawSettings/header/type"),
        ),
        "ws" => {
            let ws = &stream["wsSettings"];
            put(&mut fields, "path", ws.get("path"));
            put(
                &mut fields,
                "host",
                ws.get("host").or_else(|| ws.pointer("/headers/Host")),
            );
        }
        "grpc" => {
            let grpc = &stream["grpcSettings"];
            put(&mut fields, "service", grpc.get("serviceName"));
            put(&mut fields, "multi", grpc.get("multiMode"));
        }
        "httpupgrade" => {
            let upgrade = &stream["httpupgradeSettings"];
            put(&mut fields, "path", upgrade.get("path"));
            put(&mut fields, "host", upgrade.get("host"));
        }
        network @ ("xhttp" | "splithttp") => {
            let settings = stream
                .get(format!("{network}Settings"))
                .or_else(|| stream.get("xhttpSettings"))
                .or_else(|| stream.get("splithttpSettings"))
                .unwrap_or(&Value::Null);
            put(&mut fields, "path", settings.get("path"));
            put(&mut fields, "host", settings.get("host"));
            put(&mut fields, "mode", settings.get("mode"));
            // Xray reads the options from `extra` when it is present and from the
            // settings themselves otherwise; it never merges the two.
            let options = match settings.get("extra") {
                Some(extra) if !extra.is_null() => extra,
                _ if settings.is_null() => &Value::Null,
                _ => settings,
            };
            if !options.is_null() {
                fields.insert("extra".to_owned(), options.to_string());
            }
        }
        _ => {}
    }

    (Some(scheme.to_owned()), build(scheme, &fields).into())
}

fn xray_wireguard(config: &Value, outbound: &Value) -> Record {
    let settings = &outbound["settings"];
    if has_amnezia_options(settings) {
        return (
            Some("amneziawg".to_owned()),
            Entry::Skip(SkipReason::UnsupportedProtocol),
        );
    }
    let Some(peers) = settings.get("peers").and_then(Value::as_array) else {
        return (
            Some("wireguard".to_owned()),
            Entry::Skip(SkipReason::MissingField),
        );
    };
    if peers.is_empty() {
        return (
            Some("wireguard".to_owned()),
            Entry::Skip(SkipReason::MissingField),
        );
    }
    if peers.len() > 1 {
        return (
            Some("wireguard".to_owned()),
            Entry::Skip(SkipReason::UnsupportedOption),
        );
    }
    let peer = &peers[0];
    if has_amnezia_options(peer) {
        return (
            Some("amneziawg".to_owned()),
            Entry::Skip(SkipReason::UnsupportedProtocol),
        );
    }

    let result = (|| -> Result<rosetun_config::Node, SkipReason> {
        let endpoint = peer
            .get("endpoint")
            .and_then(Value::as_str)
            .ok_or(SkipReason::MissingField)?;
        let (server, port) = wireguard::parse_endpoint(endpoint)?;
        let private_key = wireguard::canonical_key(
            settings
                .get("secretKey")
                .and_then(Value::as_str)
                .ok_or(SkipReason::MissingField)?,
        )?;
        let public_key = wireguard::canonical_key(
            peer.get("publicKey")
                .and_then(Value::as_str)
                .ok_or(SkipReason::MissingField)?,
        )?;
        let pre_shared_key =
            wireguard::optional_key(peer.get("preSharedKey").and_then(Value::as_str))?;
        let address = wireguard::parse_addresses(json_string_list(settings.get("address"))?)?;
        let reserved = match settings.get("reserved") {
            Some(value) => wireguard::parse_reserved_json(value)?,
            None => None,
        };
        let mtu = match settings.get("mtu") {
            Some(value) => wireguard::parse_mtu_json(value)?,
            None => None,
        };
        let persistent_keepalive = match peer.get("keepAlive") {
            Some(value) => wireguard::parse_keepalive_json(value)?,
            None => None,
        };
        let name = config
            .get("remarks")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        wireguard::build_node(WireGuardInput {
            name,
            server,
            port,
            private_key,
            public_key,
            pre_shared_key,
            address,
            reserved,
            mtu,
            persistent_keepalive,
        })
    })();
    (Some("wireguard".to_owned()), result.into())
}

fn sing_box_endpoint(endpoint: &Value) -> Record {
    let Some(protocol) = endpoint.get("type").and_then(Value::as_str) else {
        return (None, Entry::Skip(SkipReason::InvalidRecord));
    };
    if protocol.eq_ignore_ascii_case("awg") || protocol.eq_ignore_ascii_case("amneziawg") {
        return (
            Some("amneziawg".to_owned()),
            Entry::Skip(SkipReason::UnsupportedProtocol),
        );
    }
    if protocol != "wireguard" {
        let scheme = crate::known_scheme(&protocol.to_ascii_lowercase()).map(str::to_owned);
        return (scheme, Entry::Skip(SkipReason::UnsupportedProtocol));
    }
    if has_amnezia_options(endpoint) {
        return (
            Some("amneziawg".to_owned()),
            Entry::Skip(SkipReason::UnsupportedProtocol),
        );
    }
    if endpoint.get("system").and_then(Value::as_bool) == Some(true) {
        return (
            Some("wireguard".to_owned()),
            Entry::Skip(SkipReason::UnsupportedOption),
        );
    }
    let Some(peers) = endpoint.get("peers").and_then(Value::as_array) else {
        return (
            Some("wireguard".to_owned()),
            Entry::Skip(SkipReason::MissingField),
        );
    };
    if peers.is_empty() {
        return (
            Some("wireguard".to_owned()),
            Entry::Skip(SkipReason::MissingField),
        );
    }
    if peers.len() > 1 {
        return (
            Some("wireguard".to_owned()),
            Entry::Skip(SkipReason::UnsupportedOption),
        );
    }
    let peer = &peers[0];
    if has_amnezia_options(peer) {
        return (
            Some("amneziawg".to_owned()),
            Entry::Skip(SkipReason::UnsupportedProtocol),
        );
    }

    let result = (|| -> Result<rosetun_config::Node, SkipReason> {
        let server = wireguard::normalize_host(
            peer.get("address")
                .and_then(Value::as_str)
                .ok_or(SkipReason::MissingField)?,
        )?;
        let port = json_port(peer.get("port"))?;
        let private_key = wireguard::canonical_key(
            endpoint
                .get("private_key")
                .and_then(Value::as_str)
                .ok_or(SkipReason::MissingField)?,
        )?;
        let public_key = wireguard::canonical_key(
            peer.get("public_key")
                .and_then(Value::as_str)
                .ok_or(SkipReason::MissingField)?,
        )?;
        let pre_shared_key =
            wireguard::optional_key(peer.get("pre_shared_key").and_then(Value::as_str))?;
        let address = wireguard::parse_addresses(json_string_list(endpoint.get("address"))?)?;
        let reserved = match peer.get("reserved").or_else(|| endpoint.get("reserved")) {
            Some(value) => wireguard::parse_reserved_json(value)?,
            None => None,
        };
        let mtu = match endpoint.get("mtu") {
            Some(value) => wireguard::parse_mtu_json(value)?,
            None => None,
        };
        let persistent_keepalive = match peer.get("persistent_keepalive_interval") {
            Some(value) => wireguard::parse_keepalive_json(value)?,
            None => None,
        };
        let name = endpoint
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        wireguard::build_node(WireGuardInput {
            name,
            server,
            port,
            private_key,
            public_key,
            pre_shared_key,
            address,
            reserved,
            mtu,
            persistent_keepalive,
        })
    })();
    (Some("wireguard".to_owned()), result.into())
}

fn sing_box_wireguard_outbound(outbound: &Value) -> Record {
    if has_amnezia_options(outbound) {
        return (
            Some("amneziawg".to_owned()),
            Entry::Skip(SkipReason::UnsupportedProtocol),
        );
    }
    if outbound.get("system_interface").and_then(Value::as_bool) == Some(true)
        || outbound.get("system").and_then(Value::as_bool) == Some(true)
    {
        return (
            Some("wireguard".to_owned()),
            Entry::Skip(SkipReason::UnsupportedOption),
        );
    }
    let peer = if let Some(peers) = outbound.get("peers") {
        let Some(peers) = peers.as_array() else {
            return (
                Some("wireguard".to_owned()),
                Entry::Skip(SkipReason::InvalidRecord),
            );
        };
        if peers.is_empty() {
            return (
                Some("wireguard".to_owned()),
                Entry::Skip(SkipReason::MissingField),
            );
        }
        if peers.len() > 1 {
            return (
                Some("wireguard".to_owned()),
                Entry::Skip(SkipReason::UnsupportedOption),
            );
        }
        if has_amnezia_options(&peers[0]) {
            return (
                Some("amneziawg".to_owned()),
                Entry::Skip(SkipReason::UnsupportedProtocol),
            );
        }
        Some(&peers[0])
    } else {
        None
    };

    let result = (|| -> Result<rosetun_config::Node, SkipReason> {
        let server = wireguard::normalize_host(
            peer.and_then(|peer| peer.get("server").or_else(|| peer.get("address")))
                .or_else(|| outbound.get("server"))
                .and_then(Value::as_str)
                .ok_or(SkipReason::MissingField)?,
        )?;
        let port = json_port(
            peer.and_then(|peer| peer.get("server_port").or_else(|| peer.get("port")))
                .or_else(|| outbound.get("server_port")),
        )?;
        let private_key = wireguard::canonical_key(
            outbound
                .get("private_key")
                .and_then(Value::as_str)
                .ok_or(SkipReason::MissingField)?,
        )?;
        let public_key = wireguard::canonical_key(
            peer.and_then(|peer| peer.get("public_key"))
                .or_else(|| outbound.get("peer_public_key"))
                .or_else(|| outbound.get("public_key"))
                .and_then(Value::as_str)
                .ok_or(SkipReason::MissingField)?,
        )?;
        let pre_shared_key = wireguard::optional_key(
            peer.and_then(|peer| peer.get("pre_shared_key"))
                .or_else(|| outbound.get("pre_shared_key"))
                .and_then(Value::as_str),
        )?;
        let address = wireguard::parse_addresses(json_string_list(
            outbound
                .get("local_address")
                .or_else(|| outbound.get("address")),
        )?)?;
        let reserved = match peer
            .and_then(|peer| peer.get("reserved"))
            .or_else(|| outbound.get("reserved"))
        {
            Some(value) => wireguard::parse_reserved_json(value)?,
            None => None,
        };
        let mtu = match outbound.get("mtu") {
            Some(value) => wireguard::parse_mtu_json(value)?,
            None => None,
        };
        let persistent_keepalive = match peer
            .and_then(|peer| peer.get("persistent_keepalive_interval"))
            .or_else(|| outbound.get("persistent_keepalive_interval"))
        {
            Some(value) => wireguard::parse_keepalive_json(value)?,
            None => None,
        };
        let name = outbound
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        wireguard::build_node(WireGuardInput {
            name,
            server,
            port,
            private_key,
            public_key,
            pre_shared_key,
            address,
            reserved,
            mtu,
            persistent_keepalive,
        })
    })();
    (Some("wireguard".to_owned()), result.into())
}

fn has_amnezia_options(value: &Value) -> bool {
    value.as_object().is_some_and(|map| {
        map.iter().any(|(key, value)| {
            wireguard::is_amnezia_key(key)
                && !value.is_null()
                && value.as_str().is_none_or(|text| !text.trim().is_empty())
        })
    })
}

fn json_string_list(value: Option<&Value>) -> Result<Vec<&str>, SkipReason> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(text)) => Ok(vec![text.as_str()]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().ok_or(SkipReason::InvalidRecord))
            .collect(),
        _ => Err(SkipReason::InvalidRecord),
    }
}

fn json_port(value: Option<&Value>) -> Result<u16, SkipReason> {
    let port = match value {
        Some(Value::Number(number)) => number
            .as_u64()
            .and_then(|raw| u16::try_from(raw).ok())
            .ok_or(SkipReason::InvalidPort)?,
        Some(Value::String(text)) => text.trim().parse().map_err(|_| SkipReason::InvalidPort)?,
        _ => return Err(SkipReason::InvalidPort),
    };
    if port == 0 {
        return Err(SkipReason::InvalidPort);
    }
    Ok(port)
}

// 3x-ui sends its expiry and traffic notice as a socks outbound to 127.0.0.1.
fn service_notice(config: &Value, outbounds: &[Value]) -> Option<Entry> {
    let address = outbounds
        .iter()
        .find(|outbound| outbound.get("tag").and_then(Value::as_str) == Some("proxy"))
        .and_then(|outbound| {
            [
                "/settings/servers/0/address",
                "/settings/vnext/0/address",
                "/settings/address",
            ]
            .iter()
            .find_map(|pointer| outbound.pointer(pointer).and_then(Value::as_str))
        })?;
    let remarks = config.get("remarks").and_then(Value::as_str).unwrap_or("");
    is_service_address(address).then(|| Entry::Notice(clean(remarks, 128)))
}

fn sing_box(outbound: &Value) -> Record {
    let Some(protocol) = outbound.get("type").and_then(Value::as_str) else {
        return (None, Entry::Skip(SkipReason::InvalidRecord));
    };
    if !PROTOCOLS.contains(&protocol) {
        let scheme = crate::known_scheme(&protocol.to_ascii_lowercase()).map(str::to_owned);
        return (scheme, Entry::Skip(SkipReason::UnsupportedProtocol));
    }
    if protocol == "wireguard" {
        return sing_box_wireguard_outbound(outbound);
    }
    let scheme = normalize_protocol(protocol);
    let mut fields = Fields::new();
    for (source, target) in [
        ("tag", "name"),
        ("server", "server"),
        ("server_port", "port"),
        ("uuid", "uuid"),
        ("flow", "flow"),
        ("password", "password"),
        ("method", "method"),
        ("alter_id", "aid"),
        ("security", "cipher"),
        ("encryption", "encryption"),
    ] {
        put(&mut fields, target, outbound.get(source));
    }
    if outbound.get("plugin").is_some() {
        fields.insert("plugin".to_owned(), String::new());
    }

    if protocol == "hysteria2" {
        if let Some(value) = outbound.get("server_ports") {
            let ports = match value {
                Value::String(value) => value.clone(),
                Value::Array(values) => {
                    let Some(values) = values.iter().map(Value::as_str).collect::<Option<Vec<_>>>()
                    else {
                        return (
                            Some(scheme.to_owned()),
                            Entry::Skip(SkipReason::InvalidPort),
                        );
                    };
                    values.join(",")
                }
                _ => {
                    return (
                        Some(scheme.to_owned()),
                        Entry::Skip(SkipReason::InvalidPort),
                    );
                }
            };
            if !ports.is_empty() {
                let (port, ranges) = match hysteria_ports(&ports) {
                    Ok(ports) => ports,
                    Err(reason) => return (Some(scheme.to_owned()), Entry::Skip(reason)),
                };
                fields.insert("port".into(), port.to_string());
                fields.insert("port_ranges".into(), ranges.join(","));
            }
        }
        for (source, target) in [("up_mbps", "up_mbps"), ("down_mbps", "down_mbps")] {
            put(&mut fields, target, outbound.get(source));
        }
        let obfs = &outbound["obfs"];
        put(&mut fields, "obfs", obfs.get("type"));
        put(&mut fields, "obfs_password", obfs.get("password"));
    } else if protocol == "tuic" {
        if outbound.get("udp_over_stream").and_then(Value::as_bool) == Some(true)
            || outbound
                .get("network")
                .is_some_and(|value| !value.is_null() && value.as_str() != Some(""))
        {
            return (
                Some(scheme.to_owned()),
                Entry::Skip(SkipReason::UnsupportedOption),
            );
        }
        if outbound
            .get("transport")
            .is_some_and(|value| !value.is_null())
        {
            return (
                Some(scheme.to_owned()),
                Entry::Skip(SkipReason::UnsupportedTransport(
                    UnsupportedTransport::Other,
                )),
            );
        }
        for key in ["congestion_control", "udp_relay_mode", "heartbeat"] {
            if let Some(value) = outbound.get(key).filter(|value| !value.is_null()) {
                let Some(text) = value.as_str() else {
                    return (
                        Some(scheme.to_owned()),
                        Entry::Skip(SkipReason::InvalidRecord),
                    );
                };
                fields.insert(key.to_owned(), text.to_owned());
            }
        }
        if let Some(value) = outbound
            .get("zero_rtt_handshake")
            .filter(|value| !value.is_null())
        {
            let Some(flag) = value.as_bool() else {
                return (
                    Some(scheme.to_owned()),
                    Entry::Skip(SkipReason::InvalidRecord),
                );
            };
            fields.insert("zero_rtt_handshake".to_owned(), flag.to_string());
        }
    } else if protocol == "anytls" {
        if outbound
            .get("client_metadata")
            .is_some_and(|value| !value.is_null() && value.as_str() != Some(""))
            || outbound.get("tcp_fast_open").and_then(Value::as_bool) == Some(true)
        {
            return (
                Some(scheme.to_owned()),
                Entry::Skip(SkipReason::UnsupportedOption),
            );
        }
        if outbound
            .get("transport")
            .is_some_and(|value| !value.is_null())
        {
            return (
                Some(scheme.to_owned()),
                Entry::Skip(SkipReason::UnsupportedTransport(
                    UnsupportedTransport::Other,
                )),
            );
        }
        for key in ["idle_session_check_interval", "idle_session_timeout"] {
            if let Some(value) = outbound.get(key).filter(|value| !value.is_null()) {
                let Some(text) = value.as_str() else {
                    return (
                        Some(scheme.to_owned()),
                        Entry::Skip(SkipReason::InvalidRecord),
                    );
                };
                fields.insert(key.to_owned(), text.to_owned());
            }
        }
        if let Some(value) = outbound
            .get("min_idle_session")
            .filter(|value| !value.is_null())
        {
            let Some(count) = value.as_u64() else {
                return (
                    Some(scheme.to_owned()),
                    Entry::Skip(SkipReason::InvalidRecord),
                );
            };
            fields.insert("min_idle_session".to_owned(), count.to_string());
        }
    }

    fields.insert("security".to_owned(), "none".to_owned());
    let tls = &outbound["tls"];
    if matches!(protocol, "hysteria2" | "tuic" | "anytls") {
        if !tls.is_object() || tls.get("enabled").and_then(Value::as_bool) == Some(false) {
            return (
                Some(scheme.to_owned()),
                Entry::Skip(SkipReason::UnsupportedSecurity),
            );
        }
        if tls
            .get("certificate_public_key_sha256")
            .is_some_and(|value| !value.is_null())
        {
            return (
                Some(scheme.to_owned()),
                Entry::Skip(SkipReason::UnsupportedPin),
            );
        }
        if protocol == "tuic" {
            if tls.pointer("/reality/enabled").and_then(Value::as_bool) == Some(true) {
                return (
                    Some(scheme.to_owned()),
                    Entry::Skip(SkipReason::UnsupportedSecurity),
                );
            }
            if let Some(value) = tls.get("disable_sni").filter(|value| !value.is_null()) {
                let Some(flag) = value.as_bool() else {
                    return (
                        Some(scheme.to_owned()),
                        Entry::Skip(SkipReason::InvalidRecord),
                    );
                };
                fields.insert("disable_sni".to_owned(), flag.to_string());
            }
        }
        if protocol == "anytls" && tls.get("disable_sni").and_then(Value::as_bool) == Some(true) {
            return (
                Some(scheme.to_owned()),
                Entry::Skip(SkipReason::UnsupportedOption),
            );
        }
    }
    if matches!(protocol, "hysteria2" | "tuic" | "anytls")
        || tls.get("enabled").and_then(Value::as_bool) == Some(true)
    {
        fields.insert("security".to_owned(), "tls".to_owned());
        for (source, target) in [
            ("server_name", "sni"),
            ("alpn", "alpn"),
            ("insecure", "insecure"),
        ] {
            put(&mut fields, target, tls.get(source));
        }
        put(&mut fields, "fingerprint", tls.pointer("/utls/fingerprint"));
        if tls.pointer("/reality/enabled").and_then(Value::as_bool) == Some(true) {
            fields.insert("security".to_owned(), "reality".to_owned());
            put(
                &mut fields,
                "public_key",
                tls.pointer("/reality/public_key"),
            );
            put(&mut fields, "short_id", tls.pointer("/reality/short_id"));
        }
    }

    let transport = &outbound["transport"];
    for (source, target) in [
        ("type", "transport"),
        ("path", "path"),
        ("service_name", "service"),
        ("multi_mode", "multi"),
    ] {
        put(&mut fields, target, transport.get(source));
    }
    put(
        &mut fields,
        "host",
        transport
            .get("host")
            .or_else(|| transport.pointer("/headers/Host")),
    );

    (Some(scheme.to_owned()), build(scheme, &fields).into())
}

fn normalize_protocol(protocol: &str) -> &str {
    if protocol == "shadowsocks" {
        "ss"
    } else {
        protocol
    }
}

fn put(fields: &mut Fields, key: &str, value: Option<&Value>) {
    let Some(value) = value else {
        return;
    };
    let value = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(","),
        _ => return,
    };
    fields.insert(key.to_owned(), value);
}
