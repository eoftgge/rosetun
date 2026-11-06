use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::node::{Node, TlsMode, xray_supports};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    #[default]
    #[serde(rename = "sing-box", alias = "sing_box")]
    SingBox,
    Xray,
}

impl EngineKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingBox => "sing-box",
            Self::Xray => "xray",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XrayUse {
    #[default]
    Auto,
    Off,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FragmentError {
    #[error("expected a number or a range such as 100-200")]
    Malformed,
    #[error("numbers start at 1")]
    BelowOne,
    #[error("the first number is larger than the second")]
    Reversed,
    #[error("the number is above {max}")]
    AboveLimit { max: u32 },
}

/// An inclusive range of positive numbers, written `from-to` (or `n` for `n-n`) as Xray reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FragmentRange {
    from: u32,
    to: u32,
}

impl FragmentRange {
    pub fn new(from: u32, to: u32) -> Result<Self, FragmentError> {
        if from == 0 || to == 0 {
            Err(FragmentError::BelowOne)
        } else if from > to {
            Err(FragmentError::Reversed)
        } else {
            Ok(Self { from, to })
        }
    }

    pub fn from(self) -> u32 {
        self.from
    }

    pub fn to(self) -> u32 {
        self.to
    }

    fn within(self, max: u32) -> Result<Self, FragmentError> {
        if self.to > max {
            Err(FragmentError::AboveLimit { max })
        } else {
            Ok(self)
        }
    }
}

impl FromStr for FragmentRange {
    type Err = FragmentError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let number = |part: &str| {
            let part = part.trim();
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(FragmentError::Malformed);
            }
            // Only digits are left, so a failure here means the number does not fit.
            part.parse::<u32>()
                .map_err(|_| FragmentError::AboveLimit { max: u32::MAX })
        };
        match text.split_once('-') {
            Some((from, to)) => Self::new(number(from)?, number(to)?),
            None => {
                let value = number(text)?;
                Self::new(value, value)
            }
        }
    }
}

impl fmt::Display for FragmentRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}-{}", self.from, self.to)
    }
}

impl TryFrom<String> for FragmentRange {
    type Error = FragmentError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<FragmentRange> for String {
    fn from(range: FragmentRange) -> Self {
        range.to_string()
    }
}

/// Which writes to the server are split: the TLS hello or a range of packet numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum FragmentPackets {
    #[default]
    TlsHello,
    Range(FragmentRange),
}

impl FragmentPackets {
    const TLS_HELLO: &'static str = "tlshello";
}

impl FromStr for FragmentPackets {
    type Err = FragmentError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.trim().eq_ignore_ascii_case(Self::TLS_HELLO) {
            Ok(Self::TlsHello)
        } else {
            text.parse().map(Self::Range)
        }
    }
}

impl fmt::Display for FragmentPackets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsHello => formatter.write_str(Self::TLS_HELLO),
            Self::Range(range) => range.fmt(formatter),
        }
    }
}

impl TryFrom<String> for FragmentPackets {
    type Error = FragmentError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<FragmentPackets> for String {
    fn from(packets: FragmentPackets) -> Self {
        packets.to_string()
    }
}

/// Splits the first packets sent to the VPN server, so a provider that cuts the connection by
/// its first packet misses it. Only nodes that Xray runs can use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsFragment {
    pub enabled: bool,
    pub packets: FragmentPackets,
    /// Bytes per piece.
    pub length: FragmentRange,
    /// Pause after each piece, in milliseconds.
    pub interval: FragmentRange,
}

impl TlsFragment {
    /// The last packet number that can be split.
    pub const MAX_PACKET: u32 = 100;
    /// A piece longer than a TCP segment is not split any more.
    pub const MAX_LENGTH: u32 = 1500;
    pub const MAX_INTERVAL_MS: u32 = 1000;

    pub fn parse_packets(text: &str) -> Result<FragmentPackets, FragmentError> {
        match text.parse::<FragmentPackets>()? {
            FragmentPackets::TlsHello => Ok(FragmentPackets::TlsHello),
            FragmentPackets::Range(range) => {
                range.within(Self::MAX_PACKET).map(FragmentPackets::Range)
            }
        }
    }

    pub fn parse_length(text: &str) -> Result<FragmentRange, FragmentError> {
        text.parse::<FragmentRange>()?.within(Self::MAX_LENGTH)
    }

    pub fn parse_interval(text: &str) -> Result<FragmentRange, FragmentError> {
        text.parse::<FragmentRange>()?.within(Self::MAX_INTERVAL_MS)
    }

    /// Checks the limits that deserialization does not know.
    pub fn validate(&self) -> Result<(), FragmentError> {
        if let FragmentPackets::Range(range) = self.packets {
            range.within(Self::MAX_PACKET)?;
        }
        self.length.within(Self::MAX_LENGTH)?;
        self.interval.within(Self::MAX_INTERVAL_MS)?;
        Ok(())
    }

    /// Whether the node's connection to its server is split when this is on. It needs Xray to
    /// run the node, and the TLS hello mode needs a hello to split.
    pub fn applies_to(&self, node: &Node) -> bool {
        self.enabled
            && xray_supports(&node.outbound)
            && (matches!(self.packets, FragmentPackets::Range(_))
                || !matches!(node.stream.tls, TlsMode::Plain))
    }
}

impl Default for TlsFragment {
    fn default() -> Self {
        // The defaults of v2rayN's fragment settings for Xray: the TLS hello in pieces of
        // 50 to 100 bytes, 10 to 20 ms apart.
        Self {
            enabled: false,
            packets: FragmentPackets::TlsHello,
            length: FragmentRange { from: 50, to: 100 },
            interval: FragmentRange { from: 10, to: 20 },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunSettings {
    pub name: String,
    pub mtu: u16,
    pub ipv4: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    #[serde(default = "crate::default_true")]
    pub auto_route: bool,
}

impl Default for TunSettings {
    fn default() -> Self {
        Self {
            name: "rosetun0".to_owned(),
            mtu: 1500,
            ipv4: "172.19.0.1/30".to_owned(),
            ipv6: None,
            auto_route: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsSettings {
    // A hostname would require DNS through the tunnel being built, creating a
    // resolver cycle; the helper cannot resolve new names under the kill switch.
    pub server: IpAddr,
    pub server_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            server: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            server_name: "cloudflare-dns.com".to_owned(),
            port: None,
            path: None,
        }
    }
}

/// How the engine takes traffic from this computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    /// The engine's own adapter carries the computer's traffic.
    #[default]
    Tun,
    /// The engine listens as a local proxy; programs that read the desktop's
    /// proxy settings go through it, everything else does not.
    SystemProxy,
}

/// The local proxy of `ConnectionMode::SystemProxy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalProxySettings {
    #[serde(default = "LocalProxySettings::default_port")]
    pub port: u16,
    /// Other devices on the computer's own networks may use the proxy.
    #[serde(default)]
    pub share_on_lan: bool,
}

impl Default for LocalProxySettings {
    fn default() -> Self {
        Self {
            port: Self::DEFAULT_PORT,
            share_on_lan: false,
        }
    }
}

impl LocalProxySettings {
    pub const DEFAULT_PORT: u16 = 10808;
    /// Lower ports are reserved for system services.
    pub const MIN_PORT: u16 = 1024;

    fn default_port() -> u16 {
        Self::DEFAULT_PORT
    }

    pub fn port_is_valid(port: u16) -> bool {
        port >= Self::MIN_PORT
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub engine: EngineKind,
    /// Format 8. A file without it reads as TUN.
    #[serde(default)]
    pub connection_mode: ConnectionMode,
    #[serde(default)]
    pub local_proxy: LocalProxySettings,
    #[serde(default)]
    pub xray: XrayUse,
    #[serde(default)]
    pub tls_fragment: TlsFragment,
    #[serde(default)]
    pub kill_switch: bool,
    /// The helper restarts the engine by itself after it exits or after a resume from sleep.
    #[serde(default = "crate::default_true")]
    pub auto_reconnect: bool,
    #[serde(default)]
    pub allow_lan: bool,
    /// With `allow_lan`, private networks beyond the computer's own segment
    /// (behind the router) go around the tunnel too (format 8).
    #[serde(default)]
    pub private_networks: bool,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub tun: TunSettings,
    #[serde(default)]
    pub dns: DnsSettings,
    /// Sets only the depth of an enabled verbose log: trace or debug.
    #[serde(default)]
    pub log_level: LogLevel,
    /// The verbose log is on until this Unix time, in seconds. `None` or a past time means off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verbose_log_until: Option<u64>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            engine: EngineKind::default(),
            connection_mode: ConnectionMode::default(),
            local_proxy: LocalProxySettings::default(),
            xray: XrayUse::default(),
            tls_fragment: TlsFragment::default(),
            kill_switch: false,
            auto_reconnect: true,
            allow_lan: false,
            private_networks: false,
            autostart: false,
            tun: TunSettings::default(),
            dns: DnsSettings::default(),
            log_level: LogLevel::default(),
            verbose_log_until: None,
        }
    }
}

impl Settings {
    /// How long the verbose log stays on after it is turned on.
    pub const VERBOSE_LOG_SECONDS: u64 = 24 * 60 * 60;

    pub fn verbose_log_active(&self, now_unix: u64) -> bool {
        self.verbose_log_until.is_some_and(|until| now_unix < until)
    }
}

#[cfg(test)]
mod settings_tests {
    use super::{
        ConnectionMode, DnsSettings, FragmentError, FragmentPackets, FragmentRange,
        LocalProxySettings, Settings, TlsFragment,
    };
    use crate::{
        Node, NodeId, Outbound, ProxyCredentials, StreamSettings, TlsMode, TlsParams, VlessParams,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn old_settings_without_allow_lan_remain_valid() {
        let settings: Settings =
            serde_json::from_str(r#"{"kill_switch":true}"#).expect("old settings");
        assert!(settings.kill_switch);
        assert!(!settings.allow_lan);
        assert!(!Settings::default().allow_lan);
    }

    #[test]
    fn old_settings_enable_auto_reconnect_by_default() {
        let settings: Settings = serde_json::from_str(r#"{"kill_switch":true}"#)
            .expect("settings without auto reconnect");
        assert!(settings.auto_reconnect);
        assert!(Settings::default().auto_reconnect);
        let disabled: Settings = serde_json::from_str(r#"{"auto_reconnect":false}"#)
            .expect("settings with auto reconnect disabled");
        assert!(!disabled.auto_reconnect);
    }

    #[test]
    fn verbose_log_expires_at_its_deadline() {
        let mut settings = Settings::default();
        assert!(!settings.verbose_log_active(0));
        settings.verbose_log_until = Some(100);
        assert!(settings.verbose_log_active(99));
        assert!(!settings.verbose_log_active(100));
        assert!(!settings.verbose_log_active(101));
    }

    #[test]
    fn verbose_log_remains_off_in_old_settings() {
        let settings: Settings = serde_json::from_str(r#"{"log_level":"trace"}"#)
            .expect("old settings without verbose log");
        assert_eq!(settings.verbose_log_until, None);
        assert!(!settings.verbose_log_active(0));
        let encoded = serde_json::to_value(&settings).expect("serialized settings");
        assert!(encoded.get("verbose_log_until").is_none());

        let settings: Settings = serde_json::from_str(r#"{"verbose_log_until":123}"#)
            .expect("settings with verbose log deadline");
        assert_eq!(settings.verbose_log_until, Some(123));
    }

    #[test]
    fn dns_defaults_use_cloudflare_resolver() {
        let dns = DnsSettings::default();
        assert_eq!(dns.server, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(dns.server_name, "cloudflare-dns.com");
        assert_eq!(dns.port, None);
        assert_eq!(dns.path, None);
        assert_eq!(Settings::default().dns, dns);
    }

    #[test]
    fn dns_settings_round_trip_with_all_fields() {
        let input = serde_json::json!({
            "dns": {
                "server": "77.88.8.8",
                "server_name": "common.dot.dns.yandex.net",
                "port": 8443,
                "path": "/custom-dns-query"
            }
        });
        let settings: Settings = serde_json::from_value(input.clone()).expect("DNS settings");

        assert_eq!(settings.dns.server, IpAddr::V4(Ipv4Addr::new(77, 88, 8, 8)));
        assert_eq!(settings.dns.server_name, "common.dot.dns.yandex.net");
        assert_eq!(settings.dns.port, Some(8443));
        assert_eq!(settings.dns.path.as_deref(), Some("/custom-dns-query"));

        let encoded = serde_json::to_value(&settings).expect("serialized settings");
        assert_eq!(encoded["dns"], input["dns"]);
        let decoded: Settings = serde_json::from_value(encoded).expect("round-trip settings");
        assert_eq!(decoded, settings);
    }

    #[test]
    fn old_settings_without_dns_remain_valid() {
        let settings: Settings =
            serde_json::from_str(r#"{"kill_switch":true}"#).expect("old settings");
        assert!(settings.kill_switch);
        assert_eq!(settings.dns, DnsSettings::default());
    }

    #[test]
    fn omitted_dns_port_and_path_remain_absent() {
        let settings: Settings = serde_json::from_str(
            r#"{"dns":{"server":"77.88.8.8","server_name":"common.dot.dns.yandex.net"}}"#,
        )
        .expect("DNS settings without optional fields");

        assert_eq!(settings.dns.port, None);
        assert_eq!(settings.dns.path, None);

        let encoded = serde_json::to_value(&settings).expect("serialized settings");
        assert!(encoded["dns"].get("port").is_none());
        assert!(encoded["dns"].get("path").is_none());
    }

    #[test]
    fn dns_server_hostname_is_rejected() {
        let result = serde_json::from_str::<Settings>(
            r#"{"dns":{"server":"dns.google","server_name":"dns.google"}}"#,
        );
        assert!(result.is_err());
    }

    fn fragment_node(outbound: Outbound, tls: TlsMode) -> Node {
        Node {
            id: NodeId::new("fixture"),
            name: "Example".into(),
            server: "192.0.2.10".into(),
            port: 443,
            outbound,
            stream: StreamSettings {
                tls,
                ..Default::default()
            },
            raw: None,
        }
    }

    fn vless() -> Outbound {
        Outbound::Vless(VlessParams {
            uuid: "00000000-0000-4000-8000-000000000001".into(),
            flow: None,
        })
    }

    #[test]
    fn fragmentation_is_off_by_default_with_the_common_xray_values() {
        let fragment = Settings::default().tls_fragment;
        assert!(!fragment.enabled);
        assert_eq!(fragment.packets, FragmentPackets::TlsHello);
        assert_eq!(fragment.length.to_string(), "50-100");
        assert_eq!(fragment.interval.to_string(), "10-20");
        assert_eq!(fragment.validate(), Ok(()));
        let settings: Settings = serde_json::from_str(r#"{"kill_switch":true}"#).unwrap();
        assert_eq!(settings.tls_fragment, fragment);
    }

    #[test]
    fn fragmentation_round_trips_as_text() {
        let input = serde_json::json!({
            "tls_fragment": {
                "enabled": true, "packets": "1-3", "length": "100-200", "interval": "10-20"
            }
        });
        let settings: Settings = serde_json::from_value(input.clone()).unwrap();
        assert!(settings.tls_fragment.enabled);
        assert_eq!(
            settings.tls_fragment.packets,
            FragmentPackets::Range(FragmentRange::new(1, 3).unwrap())
        );
        assert_eq!(
            serde_json::to_value(&settings).unwrap()["tls_fragment"],
            input["tls_fragment"]
        );
        let partial: Settings =
            serde_json::from_str(r#"{"tls_fragment":{"enabled":true}}"#).unwrap();
        assert!(partial.tls_fragment.enabled);
        assert_eq!(partial.tls_fragment.length, TlsFragment::default().length);
    }

    #[test]
    fn ranges_accept_the_boundaries_and_refuse_the_rest() {
        assert_eq!(
            TlsFragment::parse_length("1-1500").unwrap().to_string(),
            "1-1500"
        );
        assert_eq!(TlsFragment::parse_length(" 7 ").unwrap().to_string(), "7-7");
        assert_eq!(TlsFragment::parse_interval("1-1000").unwrap().to(), 1000);
        assert_eq!(
            TlsFragment::parse_packets("TlsHello").unwrap(),
            FragmentPackets::TlsHello
        );
        assert_eq!(
            TlsFragment::parse_packets("1-100").unwrap().to_string(),
            "1-100"
        );

        assert_eq!(
            TlsFragment::parse_length("0-5"),
            Err(FragmentError::BelowOne)
        );
        assert_eq!(
            TlsFragment::parse_length("5-0"),
            Err(FragmentError::BelowOne)
        );
        assert_eq!(
            TlsFragment::parse_length("20-10"),
            Err(FragmentError::Reversed)
        );
        assert_eq!(
            TlsFragment::parse_length("1-1501"),
            Err(FragmentError::AboveLimit { max: 1500 })
        );
        assert_eq!(
            TlsFragment::parse_interval("1-1001"),
            Err(FragmentError::AboveLimit { max: 1000 })
        );
        assert_eq!(
            TlsFragment::parse_packets("1-101"),
            Err(FragmentError::AboveLimit { max: 100 })
        );
        for text in ["", "-", "1-", "-5", "a", "1-2-3", "+5", "1.5", "1 2"] {
            assert_eq!(
                TlsFragment::parse_length(text),
                Err(FragmentError::Malformed),
                "{text:?}"
            );
        }
        assert!(TlsFragment::parse_length("99999999999999999999").is_err());
    }

    #[test]
    fn the_hello_mode_needs_a_hello_and_the_range_mode_does_not() {
        let tls = || TlsMode::Tls(TlsParams::default());
        let mut fragment = TlsFragment {
            enabled: true,
            ..TlsFragment::default()
        };
        assert!(fragment.applies_to(&fragment_node(vless(), tls())));
        assert!(!fragment.applies_to(&fragment_node(vless(), TlsMode::Plain)));
        fragment.packets = FragmentPackets::Range(FragmentRange::new(1, 3).unwrap());
        assert!(fragment.applies_to(&fragment_node(vless(), TlsMode::Plain)));

        let hysteria_like = Outbound::Http(ProxyCredentials::default());
        assert!(!fragment.applies_to(&fragment_node(hysteria_like, tls())));
        fragment.enabled = false;
        assert!(!fragment.applies_to(&fragment_node(vless(), tls())));
    }

    #[test]
    fn settings_without_a_mode_read_as_tun_with_the_proxy_closed() {
        let settings: Settings = serde_json::from_str(r#"{"kill_switch":true}"#).unwrap();
        assert_eq!(settings.connection_mode, ConnectionMode::Tun);
        assert_eq!(settings.local_proxy.port, LocalProxySettings::DEFAULT_PORT);
        assert!(!settings.local_proxy.share_on_lan);
        assert_eq!(Settings::default().connection_mode, ConnectionMode::Tun);
        assert_eq!(Settings::default().local_proxy, settings.local_proxy);
    }

    #[test]
    fn the_proxy_mode_round_trips_under_its_stored_names() {
        let input = serde_json::json!({
            "connection_mode": "system_proxy",
            "local_proxy": { "port": 20808, "share_on_lan": true },
        });
        let settings: Settings = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(settings.connection_mode, ConnectionMode::SystemProxy);
        assert_eq!(settings.local_proxy.port, 20808);
        assert!(settings.local_proxy.share_on_lan);
        let encoded = serde_json::to_value(&settings).unwrap();
        assert_eq!(encoded["connection_mode"], input["connection_mode"]);
        assert_eq!(encoded["local_proxy"], input["local_proxy"]);

        let partial: Settings = serde_json::from_str(r#"{"local_proxy":{"share_on_lan":true}}"#)
            .expect("a proxy without a port");
        assert_eq!(partial.local_proxy.port, LocalProxySettings::DEFAULT_PORT);
    }

    #[test]
    fn a_proxy_port_below_the_system_range_is_refused() {
        assert!(!LocalProxySettings::port_is_valid(0));
        assert!(!LocalProxySettings::port_is_valid(1023));
        assert!(LocalProxySettings::port_is_valid(1024));
        assert!(LocalProxySettings::port_is_valid(u16::MAX));
    }

    #[test]
    fn unknown_settings_fields_remain_valid() {
        let settings: Settings =
            serde_json::from_str(r#"{"kill_switch":true,"future_setting":true}"#)
                .expect("settings with an unknown field");
        assert!(settings.kill_switch);
        assert_eq!(settings.dns, DnsSettings::default());
    }
}
