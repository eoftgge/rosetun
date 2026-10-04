use serde_json::Value;
use url::{Host, Url};

use crate::common::{Fields, build, decode_base64, percent_decode, truth};
use crate::{Record, SkipReason};

pub(crate) fn parse(line: &str) -> Record {
    let Some((scheme, rest)) = line.split_once("://") else {
        return (None, Err(SkipReason::InvalidRecord));
    };
    let scheme = scheme.to_ascii_lowercase();
    let safe_scheme = known_scheme(&scheme).map(str::to_owned);
    let result = match scheme.as_str() {
        "vless" | "trojan" => ordinary(line, &scheme),
        "vmess" => vmess(rest),
        "ss" => shadowsocks(rest),
        "happ" | "incy" | "v2raytun" | "hiddify" | "streisand" | "sing-box" => {
            Err(SkipReason::ClientSettings)
        }
        _ => Err(SkipReason::UnsupportedProtocol),
    };
    (safe_scheme, result)
}

fn known_scheme(scheme: &str) -> Option<&'static str> {
    Some(match scheme {
        "vless" => "vless",
        "vmess" => "vmess",
        "trojan" => "trojan",
        "ss" => "ss",
        "hysteria2" => "hysteria2",
        "hy2" => "hy2",
        "tuic" => "tuic",
        "wireguard" => "wireguard",
        "anytls" => "anytls",
        "socks" => "socks",
        "socks5" => "socks5",
        "http" => "http",
        "https" => "https",
        "ssr" => "ssr",
        "happ" => "happ",
        "incy" => "incy",
        "v2raytun" => "v2raytun",
        "hiddify" => "hiddify",
        "streisand" => "streisand",
        "sing-box" => "sing-box",
        _ => return None,
    })
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

fn endpoint_fields(url: &Url) -> Result<Fields, SkipReason> {
    let server = match url.host().ok_or(SkipReason::MissingField)? {
        Host::Domain(value) => {
            let decoded = percent_decode(value);
            match Host::parse(&decoded).map_err(|_| SkipReason::InvalidRecord)? {
                Host::Domain(value) => value,
                Host::Ipv4(value) => value.to_string(),
                Host::Ipv6(value) => value.to_string(),
            }
        }
        Host::Ipv4(value) => value.to_string(),
        Host::Ipv6(value) => value.to_string(),
    };
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
    if fields.get("transport").is_some_and(|value| value == "grpc") {
        if let Some(path) = fields.get("path").cloned() {
            fields.insert("service".to_owned(), path);
        }
        if let Some(mode) = fields.get("header").cloned() {
            fields.insert("mode".to_owned(), mode);
        }
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
