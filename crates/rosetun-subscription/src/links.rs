use serde_json::Value;
use url::{Host, Url};

use crate::common::{
    Fields, build, clean, decode_base64, hysteria_ports, is_service_address, parse_bool,
    percent_decode, truth,
};
use crate::{Entry, Record, SkipReason, UnsupportedTransport};

pub(crate) fn parse(line: &str) -> Record {
    let Some((scheme, rest)) = line.split_once("://") else {
        return (None, Entry::Skip(SkipReason::InvalidRecord));
    };
    let scheme = scheme.to_ascii_lowercase();
    let safe_scheme = crate::known_scheme(&scheme).map(str::to_owned);
    if let Some(notice) = service_notice(line) {
        return (safe_scheme, Entry::Notice(notice));
    }
    let result = match scheme.as_str() {
        "http" | "https" | "socks5" => crate::parse_proxy_uri(line),
        "vless" | "trojan" => ordinary(line, &scheme),
        "hysteria2" | "hy2" => hysteria2(rest),
        "tuic" => tuic(line),
        "anytls" => anytls(line),
        "wireguard" | "wg" => return crate::wireguard::parse_link(rest),
        "vmess" => vmess(rest),
        "ss" => shadowsocks(rest),
        "happ" | "incy" | "v2raytun" | "hiddify" | "streisand" | "sing-box" | "clash"
        | "clashmeta" => Err(SkipReason::ClientSettings),
        _ => Err(SkipReason::UnsupportedProtocol),
    };
    (safe_scheme, result.into())
}

fn service_notice(line: &str) -> Option<String> {
    let url = Url::parse(line).ok()?;
    is_service_address(url.host_str()?)
        .then(|| clean(&percent_decode(url.fragment().unwrap_or("")), 128))
}

fn ordinary(line: &str, protocol: &str) -> Result<rosetun_config::Node, SkipReason> {
    let url = Url::parse(line).map_err(|_| SkipReason::InvalidRecord)?;
    let mut fields = endpoint_fields(&url)?;

    let credential = match url.password() {
        Some(password) => format!("{}:{password}", url.username()),
        None => url.username().to_owned(),
    };
    fields.insert(
        if protocol == "vless" {
            "uuid"
        } else {
            "password"
        }
        .to_owned(),
        percent_decode(&credential),
    );

    let query: Fields = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();

    for (source, target) in [
        ("encryption", "encryption"),
        ("flow", "flow"),
        ("security", "security"),
        ("type", "transport"),
        ("headerType", "header"),
        ("path", "path"),
        ("host", "host"),
        ("serviceName", "service"),
        ("mode", "mode"),
        ("extra", "extra"),
        ("sni", "sni"),
        ("alpn", "alpn"),
        ("fp", "fingerprint"),
        ("pbk", "public_key"),
        ("sid", "short_id"),
    ] {
        if let Some(value) = query.get(source) {
            fields.insert(target.to_owned(), value.clone());
        }
    }
    if query.get("allowInsecure").is_some_and(|value| truth(value))
        || query.get("insecure").is_some_and(|value| truth(value))
    {
        fields.insert("insecure".to_owned(), "true".to_owned());
    }
    build(protocol, &fields)
}

fn endpoint_host(url: &Url) -> Result<String, SkipReason> {
    match url.host().ok_or(SkipReason::MissingField)? {
        Host::Domain(value) => {
            let decoded = percent_decode(value);
            match Host::parse(&decoded).map_err(|_| SkipReason::InvalidRecord)? {
                Host::Domain(value) => Ok(value),
                Host::Ipv4(value) => Ok(value.to_string()),
                Host::Ipv6(value) => Ok(value.to_string()),
            }
        }
        Host::Ipv4(value) => Ok(value.to_string()),
        Host::Ipv6(value) => Ok(value.to_string()),
    }
}

fn endpoint_fields(url: &Url) -> Result<Fields, SkipReason> {
    let server = endpoint_host(url)?;
    let port = url.port().ok_or(SkipReason::InvalidPort)?;
    Ok(Fields::from([
        ("server".to_owned(), server),
        ("port".to_owned(), port.to_string()),
        (
            "name".to_owned(),
            percent_decode(url.fragment().unwrap_or("")),
        ),
    ]))
}

fn tuic(line: &str) -> Result<rosetun_config::Node, SkipReason> {
    let url = Url::parse(line).map_err(|_| SkipReason::InvalidRecord)?;
    let mut fields = endpoint_fields(&url)?;
    fields.insert("uuid".to_owned(), percent_decode(url.username()));
    if let Some(password) = url.password() {
        fields.insert("password".to_owned(), percent_decode(password));
    }

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "congestion_control" | "congestion-control" => {
                fields.insert("congestion_control".to_owned(), value.into_owned());
            }
            "udp_relay_mode" | "udp-relay-mode" => {
                fields.insert("udp_relay_mode".to_owned(), value.into_owned());
            }
            "zero_rtt_handshake" | "zero-rtt-handshake" | "reduce_rtt" | "reduce-rtt" => {
                fields.insert("zero_rtt_handshake".to_owned(), value.into_owned());
            }
            "heartbeat" => {
                fields.insert("heartbeat".to_owned(), value.into_owned());
            }
            "sni" | "peer" => {
                fields.insert("sni".to_owned(), value.into_owned());
            }
            "alpn" => {
                fields.insert("alpn".to_owned(), value.into_owned());
            }
            "allow_insecure" | "allowInsecure" | "insecure" => {
                fields.insert("insecure".to_owned(), value.into_owned());
            }
            "disable_sni" | "disable-sni" => {
                fields.insert("disable_sni".to_owned(), value.into_owned());
            }
            "fp" | "fingerprint" => {
                fields.insert("fingerprint".to_owned(), value.into_owned());
            }
            "security" => {
                if !value.is_empty() {
                    fields.insert("security".to_owned(), value.into_owned());
                }
            }
            "version" => {
                if !value.is_empty() && value.as_ref() != "5" {
                    return Err(SkipReason::UnsupportedOption);
                }
            }
            "pinSHA256" | "hpkp" | "pcs" => {
                if !value.is_empty() {
                    return Err(SkipReason::UnsupportedPin);
                }
            }
            "pbk" | "sid" => {
                if !value.is_empty() {
                    return Err(SkipReason::UnsupportedSecurity);
                }
            }
            "udp_over_stream" | "udp-over-stream" | "tfo" | "fastopen" | "tcp_fast_open" => {
                if parse_bool(&value)? {
                    return Err(SkipReason::UnsupportedOption);
                }
            }
            "token" | "network" => {
                if !value.is_empty() {
                    return Err(SkipReason::UnsupportedOption);
                }
            }
            "type" | "transport" | "net" => {
                if !value.is_empty()
                    && !value.eq_ignore_ascii_case("quic")
                    && !value.eq_ignore_ascii_case("udp")
                {
                    return Err(SkipReason::UnsupportedTransport(
                        UnsupportedTransport::Other,
                    ));
                }
            }
            _ => {
                if !value.is_empty() {
                    return Err(SkipReason::UnsupportedOption);
                }
            }
        }
    }
    build("tuic", &fields)
}

fn anytls(line: &str) -> Result<rosetun_config::Node, SkipReason> {
    let url = Url::parse(line).map_err(|_| SkipReason::InvalidRecord)?;
    let server = endpoint_host(&url)?;
    let port = match url.port() {
        Some(0) => return Err(SkipReason::InvalidPort),
        Some(port) => port,
        // Per the AnyTLS URI specification, port defaults to 443 when omitted.
        None => 443,
    };
    let mut fields = Fields::from([
        ("server".to_owned(), server),
        ("port".to_owned(), port.to_string()),
        (
            "name".to_owned(),
            percent_decode(url.fragment().unwrap_or("")),
        ),
    ]);
    let credential = match url.password() {
        Some(password) => format!("{}:{password}", url.username()),
        None => url.username().to_owned(),
    };
    fields.insert("password".to_owned(), percent_decode(&credential));

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "sni" | "peer" => {
                fields.insert("sni".to_owned(), value.into_owned());
            }
            "alpn" => {
                fields.insert("alpn".to_owned(), value.into_owned());
            }
            "allow_insecure" | "allowInsecure" | "insecure" => {
                fields.insert("insecure".to_owned(), value.into_owned());
            }
            "fp" | "fingerprint" => {
                fields.insert("fingerprint".to_owned(), value.into_owned());
            }
            "security" => {
                if !value.is_empty() {
                    fields.insert("security".to_owned(), value.into_owned());
                }
            }
            "pbk" => {
                fields.insert("public_key".to_owned(), value.into_owned());
            }
            "sid" => {
                fields.insert("short_id".to_owned(), value.into_owned());
            }
            "idle_session_check_interval" | "idle-session-check-interval" => {
                fields.insert("idle_session_check_interval".to_owned(), value.into_owned());
            }
            "idle_session_timeout" | "idle-session-timeout" => {
                fields.insert("idle_session_timeout".to_owned(), value.into_owned());
            }
            "min_idle_session" | "min-idle-session" => {
                fields.insert("min_idle_session".to_owned(), value.into_owned());
            }
            "udp" => {
                if !value.is_empty() && !parse_bool(&value)? {
                    return Err(SkipReason::UnsupportedOption);
                }
            }
            "pinSHA256" | "hpkp" | "pcs" => {
                if !value.is_empty() {
                    return Err(SkipReason::UnsupportedPin);
                }
            }
            "tfo" | "fastopen" | "tcp_fast_open" => {
                if parse_bool(&value)? {
                    return Err(SkipReason::UnsupportedOption);
                }
            }
            "type" | "transport" | "net" => {
                if !value.is_empty() && !value.eq_ignore_ascii_case("tcp") {
                    return Err(SkipReason::UnsupportedTransport(
                        UnsupportedTransport::Other,
                    ));
                }
            }
            "client_metadata" | "client-metadata" | "padding_scheme" | "padding-scheme" => {
                if !value.is_empty() {
                    return Err(SkipReason::UnsupportedOption);
                }
            }
            _ => {
                if !value.is_empty() {
                    return Err(SkipReason::UnsupportedOption);
                }
            }
        }
    }
    if fields.get("public_key").is_some_and(|v| !v.is_empty())
        && fields.get("security").map(String::as_str) != Some("reality")
    {
        return Err(SkipReason::UnsupportedSecurity);
    }
    build("anytls", &fields)
}

fn hysteria2(rest: &str) -> Result<rosetun_config::Node, SkipReason> {
    let (address, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (address, query) = address.split_once('?').unwrap_or((address, ""));
    let address = address.split_once('/').map_or(address, |(value, _)| value);
    let (password, endpoint) = address.rsplit_once('@').ok_or(SkipReason::MissingField)?;
    let (host, ports) = if let Some(host) = endpoint.strip_prefix('[') {
        let closing = host.find(']').ok_or(SkipReason::MissingField)?;
        let remainder = &host[closing + 1..];
        if !remainder.is_empty() && !remainder.starts_with(':') {
            return Err(SkipReason::InvalidRecord);
        }
        (
            &endpoint[..closing + 2],
            remainder.strip_prefix(':').unwrap_or(remainder),
        )
    } else {
        endpoint.rsplit_once(':').unwrap_or((endpoint, ""))
    };
    if host.is_empty() || password.is_empty() {
        return Err(SkipReason::MissingField);
    }

    let query: Fields = url::form_urlencoded::parse(query.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    let ports = match (ports.is_empty(), query.get("mport")) {
        (true, Some(value)) => value.clone(),
        (false, Some(value)) if !value.is_empty() => format!("{ports},{value}"),
        _ => ports.to_owned(),
    };
    let (port, ranges) = hysteria_ports(&ports)?;
    let url =
        Url::parse(&format!("hysteria2://{host}:{port}")).map_err(|_| SkipReason::InvalidRecord)?;
    let mut fields = endpoint_fields(&url)?;
    fields.insert("name".into(), percent_decode(fragment));
    fields.insert("password".into(), percent_decode(password));
    fields.insert("port_ranges".into(), ranges.join(","));
    for (source, target) in [
        ("sni", "sni"),
        ("alpn", "alpn"),
        ("fp", "fingerprint"),
        ("obfs", "obfs"),
        ("obfs-password", "obfs_password"),
        ("upmbps", "up_mbps"),
        ("downmbps", "down_mbps"),
        ("pinSHA256", "pin"),
    ] {
        if let Some(value) = query.get(source) {
            fields.insert(target.into(), value.clone());
        }
    }
    if query.get("insecure").is_some_and(|value| truth(value)) {
        fields.insert("insecure".into(), "true".into());
    }
    build("hysteria2", &fields)
}

fn vmess(rest: &str) -> Result<rosetun_config::Node, SkipReason> {
    let bytes = decode_base64(rest).ok_or(SkipReason::UnsupportedVmessFormat)?;
    if bytes
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_none_or(|byte| *byte != b'{')
    {
        return Err(SkipReason::UnsupportedVmessFormat);
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| SkipReason::InvalidJson {
        line: error.line(),
        column: error.column(),
    })?;
    if !value.is_object() {
        return Err(SkipReason::UnsupportedVmessFormat);
    }
    let mut fields = Fields::new();
    for (source, target) in [
        ("ps", "name"),
        ("add", "server"),
        ("port", "port"),
        ("id", "uuid"),
        ("aid", "aid"),
        ("scy", "cipher"),
        ("net", "transport"),
        ("type", "header"),
        ("host", "host"),
        ("path", "path"),
        ("sni", "sni"),
        ("alpn", "alpn"),
        ("fp", "fingerprint"),
    ] {
        if let Some(value) = scalar(value.get(source)) {
            fields.insert(target.to_owned(), value);
        }
    }
    if let Some(value) = scalar(value.get("tls")) {
        fields.insert("security".to_owned(), value);
    }
    if let Some(value) = scalar(value.get("allowInsecure")) {
        fields.insert("insecure".to_owned(), value);
    }
    match fields.get("transport").map(String::as_str) {
        Some("grpc") => {
            if let Some(path) = fields.get("path").cloned() {
                fields.insert("service".to_owned(), path);
            }
            if let Some(mode) = fields.get("header").cloned() {
                fields.insert("mode".to_owned(), mode);
            }
        }
        // v2rayN keeps the XHTTP mode in the header type field.
        Some("xhttp" | "splithttp") => {
            if let Some(mode) = fields.remove("header") {
                fields.insert("mode".to_owned(), mode);
            }
        }
        _ => {}
    }
    build("vmess", &fields)
}

fn shadowsocks(rest: &str) -> Result<rosetun_config::Node, SkipReason> {
    let (payload, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (payload, query) = payload.split_once('?').unwrap_or((payload, ""));
    let has_plugin = url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == "plugin");

    let (userinfo, endpoint) = if let Some((userinfo, endpoint)) = payload.rsplit_once('@') {
        let decoded = percent_decode(userinfo);
        let userinfo = if decoded.contains(':') {
            decoded
        } else {
            String::from_utf8(decode_base64(&decoded).ok_or(SkipReason::InvalidRecord)?)
                .map_err(|_| SkipReason::InvalidRecord)?
        };
        (userinfo, endpoint.to_owned())
    } else {
        let decoded = String::from_utf8(decode_base64(payload).ok_or(SkipReason::InvalidRecord)?)
            .map_err(|_| SkipReason::InvalidRecord)?;
        let (userinfo, endpoint) = decoded.rsplit_once('@').ok_or(SkipReason::InvalidRecord)?;
        (userinfo.to_owned(), endpoint.to_owned())
    };

    let (method, password) = userinfo.split_once(':').ok_or(SkipReason::InvalidRecord)?;
    let url = Url::parse(&format!("ss://{endpoint}")).map_err(|_| SkipReason::InvalidRecord)?;
    let mut fields = endpoint_fields(&url)?;
    fields.insert("name".to_owned(), percent_decode(fragment));
    fields.insert("method".to_owned(), method.to_owned());
    fields.insert("password".to_owned(), password.to_owned());
    if has_plugin {
        fields.insert("plugin".to_owned(), String::new());
    }
    build("ss", &fields)
}

fn scalar(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Array(values) => Some(
            values
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(","),
        ),
        _ => None,
    }
}
