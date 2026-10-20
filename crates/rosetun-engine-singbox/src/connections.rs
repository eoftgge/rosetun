//! The `GET /connections` answer of the sing-box Clash API
//! (`experimental/clashapi/connections.go` in 1.14.1).
//!
//! The list is the user's browsing history: nothing here logs an entry, and a
//! parse error never quotes the body.

use rosetun_config::ConnectionNetwork;
use rosetun_engine::{EngineConnection, TrafficTotals};
use serde::Deserialize;
use serde_json::Value;

use crate::render;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Totals {
    upload_total: u64,
    download_total: u64,
}

impl Totals {
    pub(crate) fn totals(&self) -> TrafficTotals {
        TrafficTotals {
            up: self.upload_total,
            down: self.download_total,
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct WithConnections {
    #[serde(flatten)]
    pub(crate) totals: Totals,
    /// Kept untyped so that one entry sing-box writes differently is skipped
    /// instead of failing the whole poll.
    #[serde(default)]
    connections: Option<Vec<Value>>,
}

impl WithConnections {
    pub(crate) fn connections(self) -> Vec<EngineConnection> {
        self.connections
            .unwrap_or_default()
            .into_iter()
            .filter_map(|entry| serde_json::from_value::<Raw>(entry).ok())
            .filter_map(Raw::into_connection)
            .collect()
    }
}

#[derive(Deserialize)]
struct Raw {
    id: String,
    metadata: RawMetadata,
    upload: u64,
    download: u64,
    start: String,
    #[serde(default)]
    chains: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMetadata {
    network: String,
    #[serde(default, rename = "destinationIP")]
    destination_ip: String,
    destination_port: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    process_path: String,
}

impl Raw {
    fn into_connection(self) -> Option<EngineConnection> {
        let network = match self.metadata.network.as_str() {
            "tcp" => ConnectionNetwork::Tcp,
            "udp" => ConnectionNetwork::Udp,
            _ => return None,
        };
        let port = self.metadata.destination_port.parse().ok()?;
        let process = Some(self.metadata.process_path).filter(|path| !path.is_empty());
        if render::is_exit_trace(process.as_deref(), &self.metadata.destination_ip, port) {
            return None;
        }
        let host = if self.metadata.host.is_empty() {
            self.metadata.destination_ip
        } else {
            self.metadata.host
        };
        if host.is_empty() || self.id.is_empty() {
            return None;
        }
        // sing-box reverses the chain, so the outbound the route chose is last.
        let route = render::route_of(self.chains.last().map_or("", String::as_str));
        Some(EngineConnection {
            id: self.id,
            start_unix_ms: parse_rfc3339_ms(&self.start)?,
            process,
            host,
            port,
            network,
            route,
            upload: self.upload,
            download: self.download,
        })
    }
}

/// Milliseconds since the Unix epoch of a Go `time.Time` in JSON
/// (RFC 3339 with optional fraction and a `Z` or `±hh:mm` offset).
fn parse_rfc3339_ms(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = bytes.get(range)?;
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(digits).ok()?.parse().ok()
    };
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    if second > 60 {
        return None;
    }

    let mut index = 19;
    let mut millis = 0;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        let fraction = &text[start..index];
        if fraction.is_empty() {
            return None;
        }
        millis = format!("{fraction:0<3}")[..3].parse().ok()?;
    }
    let offset_seconds = match bytes.get(index)? {
        b'Z' | b'z' if index + 1 == bytes.len() => 0,
        sign @ (b'+' | b'-') if index + 6 == bytes.len() && bytes[index + 3] == b':' => {
            let hours = number(index + 1..index + 3)?;
            let minutes = number(index + 4..index + 6)?;
            let offset = hours * 3600 + minutes * 60;
            if *sign == b'-' { -offset } else { offset }
        }
        _ => return None,
    };

    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
        - offset_seconds;
    u64::try_from(seconds * 1000 + millis).ok()
}

/// Days since 1970-01-01 in the proleptic Gregorian calendar (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosetun_engine::EngineRoute;

    fn sample(connections: &str) -> String {
        format!(
            r#"{{"downloadTotal":20,"uploadTotal":10,"memory":1024,"connections":{connections}}}"#
        )
    }

    fn entry(id: &str, host: &str, chain: &str) -> String {
        format!(
            r#"{{"id":"{id}","metadata":{{"network":"tcp","type":"tun/tun-in",
            "sourceIP":"172.19.0.1","destinationIP":"192.0.2.10","sourcePort":"50000",
            "destinationPort":"443","host":"{host}","dnsMode":"normal",
            "processPath":"C:\\Program Files\\Example\\app.exe"}},
            "upload":5,"download":7,"start":"2026-10-20T12:00:01.25+03:00",
            "chains":["{chain}"],"rule":"final","rulePayload":"","extra":true}}"#
        )
    }

    fn parse(body: &str) -> Vec<EngineConnection> {
        serde_json::from_str::<WithConnections>(body)
            .expect("snapshot parses")
            .connections()
    }

    #[test]
    fn reads_a_connection_and_ignores_unknown_fields() {
        let connections = parse(&sample(&format!("[{}]", entry("a", "example.com", "proxy"))));

        assert_eq!(
            connections,
            vec![EngineConnection {
                id: "a".to_owned(),
                start_unix_ms: 1_792_486_801_250,
                process: Some(r"C:\Program Files\Example\app.exe".to_owned()),
                host: "example.com".to_owned(),
                port: 443,
                network: ConnectionNetwork::Tcp,
                route: EngineRoute::Proxy,
                upload: 5,
                download: 7,
            }]
        );
    }

    #[test]
    fn every_rendered_tag_has_its_route() {
        let body = sample(&format!(
            "[{},{},{},{},{}]",
            entry("proxy", "example.com", "proxy"),
            entry("direct", "example.com", "direct"),
            entry("exit", "example.com", "exit-1"),
            entry("dns", "example.com", "dns-proxy"),
            entry("odd", "example.com", "exit-01"),
        ));
        let routes: Vec<_> = parse(&body)
            .into_iter()
            .map(|connection| (connection.id, connection.route))
            .collect();

        assert_eq!(
            routes,
            vec![
                ("proxy".to_owned(), EngineRoute::Proxy),
                ("direct".to_owned(), EngineRoute::Direct),
                ("exit".to_owned(), EngineRoute::Exit("exit-1".to_owned())),
                ("dns".to_owned(), EngineRoute::Other),
                ("odd".to_owned(), EngineRoute::Other),
            ]
        );
    }

    #[test]
    fn the_last_chain_tag_is_the_route() {
        let body = sample(&format!(
            "[{}]",
            entry("a", "example.com", r#"direct","exit-0"#)
        ));

        assert_eq!(
            parse(&body)[0].route,
            EngineRoute::Exit("exit-0".to_owned())
        );
    }

    #[test]
    fn a_missing_host_falls_back_to_the_address() {
        let connections = parse(&sample(&format!("[{}]", entry("a", "", "direct"))));

        assert_eq!(connections[0].host, "192.0.2.10");
    }

    #[test]
    fn a_broken_entry_is_skipped() {
        let broken = [
            r#"{"id":"no-metadata","upload":1,"download":1,"start":"2026-10-20T12:00:00Z"}"#
                .to_owned(),
            entry("bad-start", "example.com", "proxy").replace("2026-10-20T12", "yesterday"),
            entry("bad-port", "example.com", "proxy").replace(r#""443""#, r#""https""#),
            entry("bad-network", "example.com", "proxy").replace(r#""tcp""#, r#""sctp""#),
            r#""not an object""#.to_owned(),
        ];
        let body = sample(&format!(
            "[{},{}]",
            broken.join(","),
            entry("good", "example.com", "proxy")
        ));
        let ids: Vec<_> = parse(&body).into_iter().map(|c| c.id).collect();

        assert_eq!(ids, ["good"]);
    }

    #[test]
    fn empty_and_missing_lists_are_empty() {
        assert!(parse(&sample("[]")).is_empty());
        assert!(parse(&sample("null")).is_empty());
        assert!(parse(r#"{"downloadTotal":2,"uploadTotal":1}"#).is_empty());
    }

    #[test]
    fn the_gui_exit_lookup_is_hidden() {
        let trace = entry("trace", "", "proxy")
            .replace("192.0.2.10", rosetun_config::EXIT_TRACE_IP)
            .replace(r"Example\\app.exe", r"Rosetun\\ROSETUN-GUI.EXE");
        let other_port = trace.replace(r#""443""#, r#""80""#).replace("trace", "port");
        let other_program = entry("program", "", "proxy")
            .replace("192.0.2.10", rosetun_config::EXIT_TRACE_IP);
        let body = sample(&format!("[{trace},{other_port},{other_program}]"));
        let ids: Vec<_> = parse(&body).into_iter().map(|c| c.id).collect();

        assert_eq!(ids, ["port", "program"]);
    }

    #[test]
    fn rfc3339_times_parse_with_offsets_and_fractions() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_ms("2026-10-20T09:00:01.123456789Z"),
            Some(1_792_486_801_123)
        );
        assert_eq!(
            parse_rfc3339_ms("2026-10-20T04:00:01.5-05:00"),
            Some(1_792_486_801_500)
        );
        assert_eq!(parse_rfc3339_ms("2024-02-29T00:00:00Z"), Some(1_709_164_800_000));
        for bad in [
            "",
            "2026-10-20",
            "2026-10-20T09:00:01",
            "2026-13-20T09:00:01Z",
            "2026-10-20T09:00:01.Z",
            "2026-10-20T09:00:01+0300",
            "1969-12-31T23:59:59Z",
        ] {
            assert_eq!(parse_rfc3339_ms(bad), None, "{bad}");
        }
    }
}
