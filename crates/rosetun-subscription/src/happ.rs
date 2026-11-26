use std::fmt;

use serde_json::Value;
use url::Url;

use crate::common::{clean, decode_base64};

const MAX_ENTRIES: usize = 4096;
const MAX_JSON_BYTES: usize = 512 * 1024;

/// Order in which Happ evaluates block, proxy and direct rule groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HappRouteOrder {
    #[default]
    BlockProxyDirect,
    BlockDirectProxy,
    ProxyDirectBlock,
    ProxyBlockDirect,
    DirectProxyBlock,
    DirectBlockProxy,
}

impl HappRouteOrder {
    fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "block-direct-proxy" => Self::BlockDirectProxy,
            "proxy-direct-block" => Self::ProxyDirectBlock,
            "proxy-block-direct" => Self::ProxyBlockDirect,
            "direct-proxy-block" => Self::DirectProxyBlock,
            "direct-block-proxy" => Self::DirectBlockProxy,
            _ => Self::BlockProxyDirect,
        }
    }

    pub fn sequence(self) -> [HappBucket; 3] {
        match self {
            Self::BlockProxyDirect => [HappBucket::Block, HappBucket::Proxy, HappBucket::Direct],
            Self::BlockDirectProxy => [HappBucket::Block, HappBucket::Direct, HappBucket::Proxy],
            Self::ProxyDirectBlock => [HappBucket::Proxy, HappBucket::Direct, HappBucket::Block],
            Self::ProxyBlockDirect => [HappBucket::Proxy, HappBucket::Block, HappBucket::Direct],
            Self::DirectProxyBlock => [HappBucket::Direct, HappBucket::Proxy, HappBucket::Block],
            Self::DirectBlockProxy => [HappBucket::Direct, HappBucket::Block, HappBucket::Proxy],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HappBucket {
    Block,
    Proxy,
    Direct,
}

/// Decoded Happ routing profile from a subscription `routing` header or a
/// `happ://routing/{add,onadd}/<base64>` link.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct HappRouting {
    pub name: Option<String>,
    pub route_order: HappRouteOrder,
    pub global_proxy: bool,
    pub geosite_url: Option<String>,
    pub geoip_url: Option<String>,
    pub direct_sites: Vec<String>,
    pub direct_ips: Vec<String>,
    pub proxy_sites: Vec<String>,
    pub proxy_ips: Vec<String>,
    pub block_sites: Vec<String>,
    pub block_ips: Vec<String>,
}

impl fmt::Debug for HappRouting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HappRouting")
            .field("has_name", &self.name.is_some())
            .field("route_order", &self.route_order)
            .field("global_proxy", &self.global_proxy)
            .field("has_geosite_url", &self.geosite_url.is_some())
            .field("has_geoip_url", &self.geoip_url.is_some())
            .field("direct_sites", &self.direct_sites.len())
            .field("direct_ips", &self.direct_ips.len())
            .field("proxy_sites", &self.proxy_sites.len())
            .field("proxy_ips", &self.proxy_ips.len())
            .field("block_sites", &self.block_sites.len())
            .field("block_ips", &self.block_ips.len())
            .finish()
    }
}

impl HappRouting {
    pub fn is_empty(&self) -> bool {
        self.direct_sites.is_empty()
            && self.direct_ips.is_empty()
            && self.proxy_sites.is_empty()
            && self.proxy_ips.is_empty()
            && self.block_sites.is_empty()
            && self.block_ips.is_empty()
    }

    pub fn uses_geosite(&self) -> bool {
        self.direct_sites
            .iter()
            .chain(&self.proxy_sites)
            .chain(&self.block_sites)
            .any(|item| item.to_ascii_lowercase().starts_with("geosite:"))
    }

    pub fn uses_geoip(&self) -> bool {
        self.direct_ips
            .iter()
            .chain(&self.proxy_ips)
            .chain(&self.block_ips)
            .any(|item| item.to_ascii_lowercase().starts_with("geoip:"))
    }
}

/// Parses a `happ://routing/add/<base64>` or `happ://routing/onadd/<base64>` URI.
/// Returns `(profile, activate)` where `activate` is true for `onadd`.
pub fn parse_happ_routing_uri(uri: &str) -> Option<(HappRouting, bool)> {
    let trimmed = uri.trim();
    let lower = trimmed.to_ascii_lowercase();
    let (prefix_len, activate) = if lower.starts_with("happ://routing/onadd/") {
        ("happ://routing/onadd/".len(), true)
    } else if lower.starts_with("happ://routing/add/") {
        ("happ://routing/add/".len(), false)
    } else {
        return None;
    };
    let encoded = trimmed.get(prefix_len..)?.trim();
    let profile = parse_happ_routing_base64(encoded)?;
    Some((profile, activate))
}

/// Parses a Base64-encoded Happ routing JSON payload (as sent in the `routing`
/// subscription header or in `happ://routing/{add,onadd}/<base64>`).
pub fn parse_happ_routing_base64(encoded: &str) -> Option<HappRouting> {
    let encoded = encoded.trim();
    let encoded = encoded.strip_prefix("base64:").unwrap_or(encoded).trim();
    if encoded.is_empty() || encoded.len() > MAX_JSON_BYTES * 2 {
        return None;
    }
    let bytes = decode_base64(encoded)?;
    if bytes.len() > MAX_JSON_BYTES {
        return None;
    }
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    parse_happ_routing_json(&value)
}

fn parse_happ_routing_json(value: &Value) -> Option<HappRouting> {
    let object = value.as_object()?;
    let get = |name: &str| {
        object
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, val)| val)
    };
    let name = get("Name")
        .and_then(Value::as_str)
        .map(|s| clean(s, 128))
        .filter(|s| !s.is_empty());
    let route_order = get("RouteOrder")
        .and_then(Value::as_str)
        .map(HappRouteOrder::parse)
        .unwrap_or_default();
    let global_proxy = get("GlobalProxy").is_some_and(json_bool);
    let geosite_url = get("Geositeurl")
        .or_else(|| get("GeoSiteUrl"))
        .and_then(Value::as_str)
        .and_then(http_url);
    let geoip_url = get("Geoipurl")
        .or_else(|| get("GeoIpUrl"))
        .and_then(Value::as_str)
        .and_then(http_url);
    let routing = HappRouting {
        name,
        route_order,
        global_proxy,
        geosite_url,
        geoip_url,
        direct_sites: string_list(get("DirectSites")),
        direct_ips: string_list(get("DirectIp")),
        proxy_sites: string_list(get("ProxySites")),
        proxy_ips: string_list(get("ProxyIp")),
        block_sites: string_list(get("BlockSites")),
        block_ips: string_list(get("BlockIp")),
    };
    (!routing.is_empty()).then_some(routing)
}

fn json_bool(value: &Value) -> bool {
    match value {
        Value::Bool(flag) => *flag,
        Value::String(text) => text.trim().eq_ignore_ascii_case("true"),
        _ => false,
    }
}

fn http_url(raw: &str) -> Option<String> {
    let cleaned = clean(raw, 2048);
    let parsed = Url::parse(&cleaned).ok()?;
    matches!(parsed.scheme(), "http" | "https").then_some(cleaned)
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    let mut items = Vec::new();
    match value {
        Value::Array(array) => {
            for entry in array {
                if let Some(text) = entry.as_str() {
                    push_entries(&mut items, text);
                }
                if items.len() >= MAX_ENTRIES {
                    break;
                }
            }
        }
        Value::String(text) => push_entries(&mut items, text),
        _ => {}
    }
    items
}

fn push_entries(out: &mut Vec<String>, raw: &str) {
    for part in raw.split([',', '\n', '\r']) {
        let cleaned = clean(part, 512);
        if !cleaned.is_empty() {
            out.push(cleaned);
            if out.len() >= MAX_ENTRIES {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_b64(input: &str) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = input.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = u32::from(chunk[0]);
            let b1 = chunk.get(1).copied().map_or(0, u32::from);
            let b2 = chunk.get(2).copied().map_or(0, u32::from);
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 {
                TABLE[((n >> 6) & 63) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                TABLE[(n & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn parses_happ_routing_header_and_deep_links() {
        let json = r#"{
            "Name": "Provider RU",
            "GlobalProxy": "false",
            "RouteOrder": "block-direct-proxy",
            "Geositeurl": "https://lists.example.com/geosite.dat",
            "Geoipurl": "https://lists.example.com/geoip.dat",
            "DirectSites": ["geosite:category-ru", "domain:example.com"],
            "DirectIp": ["geoip:ru", "192.0.2.0/24"],
            "ProxySites": ["geosite:google"],
            "BlockSites": ["geosite:category-ads-all"]
        }"#;
        let b64 = encode_b64(json);
        let parsed = parse_happ_routing_base64(&b64).expect("valid happ routing");
        assert_eq!(parsed.name.as_deref(), Some("Provider RU"));
        assert_eq!(parsed.route_order, HappRouteOrder::BlockDirectProxy);
        assert!(!parsed.global_proxy);
        assert!(parsed.uses_geosite());
        assert!(parsed.uses_geoip());
        assert_eq!(
            parsed.geosite_url.as_deref(),
            Some("https://lists.example.com/geosite.dat")
        );
        assert_eq!(
            parsed.direct_sites,
            ["geosite:category-ru", "domain:example.com"]
        );
        assert_eq!(parsed.direct_ips, ["geoip:ru", "192.0.2.0/24"]);
        assert_eq!(parsed.proxy_sites, ["geosite:google"]);
        assert_eq!(parsed.block_sites, ["geosite:category-ads-all"]);

        let (uri_parsed, activate) =
            parse_happ_routing_uri(&format!("happ://routing/onadd/{b64}")).unwrap();
        assert!(activate);
        assert_eq!(uri_parsed, parsed);

        let (add_parsed, activate) =
            parse_happ_routing_uri(&format!("happ://routing/add/{b64}")).unwrap();
        assert!(!activate);
        assert_eq!(add_parsed, parsed);
    }

    #[test]
    fn rejects_empty_or_non_http_urls() {
        let json = r#"{"Name": "Empty", "Geositeurl": "file:///etc/passwd"}"#;
        assert!(parse_happ_routing_base64(&encode_b64(json)).is_none());
        let with_rule =
            r#"{"Name": "Ok", "Geositeurl": "file:///etc/passwd", "DirectSites": ["example.com"]}"#;
        let parsed = parse_happ_routing_base64(&encode_b64(with_rule)).unwrap();
        assert_eq!(parsed.geosite_url, None);
    }
}
