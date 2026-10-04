use serde_json::Value;

use crate::common::{Fields, build};
use crate::{Format, ParseError, Record, SkipReason};

const PROTOCOLS: &[&str] = &["vless", "vmess", "trojan", "shadowsocks"];

pub(crate) fn format(value: &Value) -> Result<Format, ParseError> {
    if value.is_array() {
        return Ok(Format::XrayJson);
    }
    let outbounds = value
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or(ParseError::UnsupportedFormat)?;

    if outbounds
        .iter()
        .any(|outbound| outbound.get("protocol").is_some())
    {
        Ok(Format::XrayJson)
    } else if outbounds
        .iter()
        .any(|outbound| outbound.get("type").is_some())
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
        Format::SingBoxJson => value
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
            .collect(),
        Format::Links { .. } => Vec::new(),
    }
}

fn xray(config: &Value) -> Record {
    let Some(outbounds) = config.get("outbounds").and_then(Value::as_array) else {
        return (None, Err(SkipReason::InvalidRecord));
    };
    let supported = |outbound: &&Value| {
        outbound
            .get("protocol")
            .and_then(Value::as_str)
            .is_some_and(|protocol| PROTOCOLS.contains(&protocol))
    };
    let outbound = outbounds
        .iter()
        .filter(supported)
        .find(|outbound| outbound.get("tag").and_then(Value::as_str) == Some("proxy"))
        .or_else(|| outbounds.iter().find(supported));

    let Some(outbound) = outbound else {
        return (None, Err(SkipReason::UnsupportedProtocol));
    };
    let protocol = outbound
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("");
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

    match fields.get("transport").map(String::as_str).unwrap_or("tcp") {
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
        _ => {}
    }

    (Some(scheme.to_owned()), build(scheme, &fields))
}

fn sing_box(outbound: &Value) -> Record {
    let Some(protocol) = outbound.get("type").and_then(Value::as_str) else {
        return (None, Err(SkipReason::InvalidRecord));
    };
    if !PROTOCOLS.contains(&protocol) {
        return (None, Err(SkipReason::UnsupportedProtocol));
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

    fields.insert("security".to_owned(), "none".to_owned());
    let tls = &outbound["tls"];
    if tls.get("enabled").and_then(Value::as_bool) == Some(true) {
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

    (Some(scheme.to_owned()), build(scheme, &fields))
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
