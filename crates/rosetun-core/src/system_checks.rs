use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rosetun_dns::{AskError, Reply, Transport};
use rosetun_processes::RunningProcess;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKind {
    Clock,
    Proxy,
    PacketInterceptor,
    OtherVpn,
    DnsSubstitution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Warning,
    Unavailable,
    /// Not run: the check would say nothing true at this moment, such as
    /// a DNS check while the tunnel or its protection carries the traffic.
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckDetail {
    None,
    Clock {
        minutes: u64,
        ahead: bool,
    },
    Proxy {
        server: Option<String>,
        auto_config: Option<String>,
    },
    PacketInterceptor {
        processes: Vec<String>,
        driver: bool,
    },
    OtherVpn {
        processes: Vec<String>,
        adapters: Vec<String>,
    },
    /// The resolver whose UDP answers come from someone else. Never the
    /// answers themselves: they hold the user's address.
    DnsSubstitution {
        server: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub kind: CheckKind,
    pub status: CheckStatus,
    pub detail: CheckDetail,
}

impl CheckResult {
    fn ok(kind: CheckKind) -> Self {
        Self {
            kind,
            status: CheckStatus::Ok,
            detail: CheckDetail::None,
        }
    }

    pub fn skipped(kind: CheckKind) -> Self {
        Self {
            kind,
            status: CheckStatus::Skipped,
            detail: CheckDetail::None,
        }
    }

    fn unavailable(kind: CheckKind) -> Self {
        Self {
            kind,
            status: CheckStatus::Unavailable,
            detail: CheckDetail::None,
        }
    }

    fn warning(kind: CheckKind, detail: CheckDetail) -> Self {
        Self {
            kind,
            status: CheckStatus::Warning,
            detail,
        }
    }
}

/// Runs five independent, read-only checks on the caller's worker thread.
/// With `guarded` (a tunnel is up or protection holds the traffic) the DNS
/// check sends nothing and is skipped.
pub fn check_system(own_alias: &str, guarded: bool) -> Vec<CheckResult> {
    std::thread::scope(|scope| {
        let dns = (!guarded).then(|| scope.spawn(check_dns_substitution));
        let mut results = check_local(own_alias);
        results.push(match dns {
            Some(dns) => dns
                .join()
                .unwrap_or_else(|_| CheckResult::unavailable(CheckKind::DnsSubstitution)),
            None => CheckResult::skipped(CheckKind::DnsSubstitution),
        });
        results
    })
}

fn check_local(own_alias: &str) -> Vec<CheckResult> {
    let clock = check_clock();
    #[cfg(windows)]
    let proxy = rosetun_shell::proxy_settings()
        .map(|(enabled, server, auto_config)| proxy_result(enabled, server, auto_config))
        .unwrap_or_else(|_| CheckResult::unavailable(CheckKind::Proxy));
    #[cfg(not(windows))]
    let proxy = CheckResult::unavailable(CheckKind::Proxy);

    let processes = rosetun_processes::running_processes();
    #[cfg(windows)]
    let driver = rosetun_shell::windivert_running();
    #[cfg(not(windows))]
    let driver = Err(std::io::Error::other("not available on this platform"));
    let packet_interceptor = match &processes {
        Ok(processes) => packet_interceptor_result(processes, driver),
        Err(_) => CheckResult::unavailable(CheckKind::PacketInterceptor),
    };
    let adapters = rosetun_adapters::active_vpn_adapters(own_alias);
    let other_vpn = match (processes, adapters, std::env::current_exe()) {
        (Ok(processes), Ok(adapters), Ok(executable)) => {
            other_vpn_result(&processes, adapters, &executable)
        }
        _ => CheckResult::unavailable(CheckKind::OtherVpn),
    };
    vec![clock, proxy, packet_interceptor, other_vpn]
}

const OTHER_VPN_PROCESSES: &[&str] = &[
    "v2rayN.exe",
    "nekoray.exe",
    "Throne.exe",
    "Hiddify.exe",
    "clash-verge.exe",
    "mihomo.exe",
    "FlClash.exe",
    "AmneziaVPN.exe",
    "wireguard.exe",
    "openvpn.exe",
    "NetZapret.exe",
];

fn process_names(
    processes: &[RunningProcess],
    predicate: impl Fn(&RunningProcess) -> bool,
) -> Vec<String> {
    let mut names: Vec<_> = processes
        .iter()
        .filter(|process| predicate(process))
        .map(|process| process.name.clone())
        .collect();
    names.sort_by_key(|name| name.to_ascii_lowercase());
    names.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    names
}

fn packet_interceptor_result(
    processes: &[RunningProcess],
    driver: std::io::Result<bool>,
) -> CheckResult {
    let names = process_names(processes, |process| {
        process.name.eq_ignore_ascii_case("winws.exe")
            || process.name.eq_ignore_ascii_case("winws2.exe")
    });
    if !names.is_empty() || driver.as_ref().is_ok_and(|&running| running) {
        CheckResult::warning(
            CheckKind::PacketInterceptor,
            CheckDetail::PacketInterceptor {
                processes: names,
                driver: driver.unwrap_or(false),
            },
        )
    } else if driver.is_err() {
        CheckResult::unavailable(CheckKind::PacketInterceptor)
    } else {
        CheckResult::ok(CheckKind::PacketInterceptor)
    }
}

fn other_vpn_result(
    processes: &[RunningProcess],
    adapters: Vec<String>,
    own_executable: &Path,
) -> CheckResult {
    let own_dir = own_executable.parent();
    let names = process_names(processes, |process| {
        if OTHER_VPN_PROCESSES
            .iter()
            .any(|name| process.name.eq_ignore_ascii_case(name))
        {
            return true;
        }
        if !["sing-box.exe", "xray.exe"]
            .iter()
            .any(|name| process.name.eq_ignore_ascii_case(name))
        {
            return false;
        }
        match (process.path.as_deref(), own_dir) {
            (Some(path), Some(own_dir)) => !path
                .to_string_lossy()
                .replace('/', "\\")
                .eq_ignore_ascii_case(
                    &own_dir
                        .join(&process.name)
                        .to_string_lossy()
                        .replace('/', "\\"),
                ),
            _ => false,
        }
    });
    if names.is_empty() && adapters.is_empty() {
        CheckResult::ok(CheckKind::OtherVpn)
    } else {
        CheckResult::warning(
            CheckKind::OtherVpn,
            CheckDetail::OtherVpn {
                processes: names,
                adapters,
            },
        )
    }
}

fn proxy_result(
    enabled: Option<u32>,
    server: Option<String>,
    auto_config: Option<String>,
) -> CheckResult {
    let server = server.filter(|value| !value.trim().is_empty() && enabled == Some(1));
    let auto_config = auto_config.filter(|value| !value.trim().is_empty());
    if server.is_none() && auto_config.is_none() {
        CheckResult::ok(CheckKind::Proxy)
    } else {
        CheckResult::warning(
            CheckKind::Proxy,
            CheckDetail::Proxy {
                server,
                auto_config,
            },
        )
    }
}

const DNS_CHECK_SERVER: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53));
/// Cloudflare's resolver answers this CHAOS name itself with the address
/// the query came from, so it never leaves 1.1.1.1 and no blocked name is
/// asked. A resolver the query was redirected to does not know it.
const DNS_CHECK_NAME: &str = "whoami.cloudflare";
const DNS_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// The same question over UDP and TCP at once. Only the verdict leaves this
/// function: the answers carry the user's address and are never logged.
fn check_dns_substitution() -> CheckResult {
    let ask = |transport| {
        rosetun_dns::ask(
            DNS_CHECK_SERVER,
            transport,
            DNS_CHECK_NAME,
            rosetun_dns::wire::TYPE_TXT,
            rosetun_dns::wire::CLASS_CH,
            DNS_CHECK_TIMEOUT,
        )
    };
    let (udp, tcp) = std::thread::scope(|scope| {
        let udp = scope.spawn(|| ask(Transport::Udp));
        let tcp = ask(Transport::Tcp);
        (udp.join().unwrap_or(Err(AskError::NoReply)), tcp)
    });
    dns_substitution_result(&udp, &tcp, &DNS_CHECK_SERVER.ip().to_string())
}

/// Substitution only on a clear mismatch: TCP gets the real answer and UDP
/// gets another one, a refusal or an empty answer. Anything less certain
/// (TCP without an answer, UDP silent or truncated) is not an alarm.
fn dns_substitution_result(
    udp: &Result<Reply, AskError>,
    tcp: &Result<Reply, AskError>,
    server: &str,
) -> CheckResult {
    let kind = CheckKind::DnsSubstitution;
    let real = match tcp {
        Ok(reply) if reply.rcode == 0 && !reply.texts.is_empty() => reply,
        _ => return CheckResult::unavailable(kind),
    };
    match udp {
        Ok(reply) if same_client(reply, real) => CheckResult::ok(kind),
        Ok(_) => CheckResult::warning(
            kind,
            CheckDetail::DnsSubstitution {
                server: server.to_owned(),
            },
        ),
        Err(_) => CheckResult::unavailable(kind),
    }
}

/// Both answers name the same client. A carrier-grade NAT can send UDP and
/// TCP out from neighbouring addresses of its pool, so one /16 (IPv4) or
/// /48 (IPv6) counts as the same; a resolver the query was redirected to
/// answers with a refusal or with its own, distant address.
fn same_client(udp: &Reply, tcp: &Reply) -> bool {
    if udp == tcp {
        return true;
    }
    let address = |reply: &Reply| match reply.texts.as_slice() {
        [text] if reply.rcode == 0 => text.trim().parse::<IpAddr>().ok(),
        _ => None,
    };
    match (address(udp), address(tcp)) {
        (Some(IpAddr::V4(udp)), Some(IpAddr::V4(tcp))) => udp.octets()[..2] == tcp.octets()[..2],
        (Some(IpAddr::V6(udp)), Some(IpAddr::V6(tcp))) => {
            udp.segments()[..3] == tcp.segments()[..3]
        }
        _ => false,
    }
}

fn check_clock() -> CheckResult {
    let kind = CheckKind::Clock;
    let agent = crate::resolve::agent(
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(5)))
            .max_redirects(0)
            .https_only(false)
            .http_status_as_error(false)
            .build(),
    );
    let before = SystemTime::now();
    let response = agent.head("http://cp.cloudflare.com/").call();
    let after = SystemTime::now();
    let Ok(response) = response else {
        return CheckResult::unavailable(kind);
    };
    if !response.status().is_success() {
        return CheckResult::unavailable(kind);
    }
    let Some(server) = response
        .headers()
        .get("Date")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_date)
    else {
        return CheckResult::unavailable(kind);
    };
    let (Ok(before), Ok(after)) = (
        before.duration_since(UNIX_EPOCH),
        after.duration_since(UNIX_EPOCH),
    ) else {
        return CheckResult::unavailable(kind);
    };
    let local = (before.as_secs() as i64 + after.as_secs() as i64) / 2;
    clock_result(local, server)
}

fn clock_result(local: i64, server: i64) -> CheckResult {
    let seconds = local.abs_diff(server);
    if seconds <= 180 {
        CheckResult::ok(CheckKind::Clock)
    } else {
        CheckResult::warning(
            CheckKind::Clock,
            CheckDetail::Clock {
                minutes: seconds.div_ceil(60),
                ahead: local > server,
            },
        )
    }
}

fn leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn parse_http_date(value: &str) -> Option<i64> {
    let text = value.as_bytes();
    if text.len() != 29
        || text[3] != b','
        || text[4] != b' '
        || text[7] != b' '
        || text[11] != b' '
        || text[16] != b' '
        || text[19] != b':'
        || text[22] != b':'
        || &text[25..] != b" GMT"
        || !text[..3].iter().all(u8::is_ascii_alphabetic)
    {
        return None;
    }
    let number = |part: &[u8]| -> Option<i64> {
        part.iter().try_fold(0_i64, |n, &digit| {
            digit
                .is_ascii_digit()
                .then_some(n * 10 + i64::from(digit - b'0'))
        })
    };
    let day = number(&text[5..7])?;
    let month = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ]
    .iter()
    .position(|month| month.as_slice() == &text[8..11])?;
    let year = number(&text[12..16])?;
    let hours = number(&text[17..19])?;
    let minutes = number(&text[20..22])?;
    let seconds = number(&text[23..25])?;
    if !(1970..=9999).contains(&year) || hours > 23 || minutes > 59 || seconds > 59 {
        return None;
    }
    let days_in_month = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > days_in_month[month] {
        return None;
    }
    let days: i64 = (1970..year)
        .map(|year| if leap(year) { 366 } else { 365 })
        .sum::<i64>()
        + days_in_month[..month].iter().sum::<i64>()
        + day
        - 1;
    Some(days * 86_400 + hours * 3600 + minutes * 60 + seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn process(name: &str, path: Option<&str>) -> RunningProcess {
        RunningProcess {
            pid: 42,
            name: name.into(),
            path: path.map(PathBuf::from),
            has_window: false,
        }
    }

    #[test]
    fn parses_http_date_and_rejects_invalid_calendar_dates() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_http_date("Sat, 29 Feb 2020 12:00:00 GMT"),
            Some(1_582_977_600)
        );
        for value in [
            "Thu, 01 Jan 1970 00:00:00 UTC",
            "Thu, 29 Feb 2021 00:00:00 GMT",
            "Thu, 01 Foo 1970 00:00:00 GMT",
            "Thu, 01 Jan 1970 24:00:00 GMT",
        ] {
            assert_eq!(parse_http_date(value), None);
        }
    }

    #[test]
    fn clock_warning_uses_strict_threshold_and_direction() {
        assert_eq!(
            clock_result(181, 0).detail,
            CheckDetail::Clock {
                minutes: 4,
                ahead: true
            }
        );
        assert_eq!(
            clock_result(0, 181).detail,
            CheckDetail::Clock {
                minutes: 4,
                ahead: false
            }
        );
        assert_eq!(clock_result(180, 0).status, CheckStatus::Ok);
    }

    #[test]
    fn proxy_requires_an_enabled_manual_server_or_auto_config() {
        assert_eq!(
            proxy_result(Some(0), Some("192.0.2.1:1080".into()), None).status,
            CheckStatus::Ok
        );
        assert_eq!(proxy_result(Some(1), None, None).status, CheckStatus::Ok);
        assert_eq!(
            proxy_result(Some(1), Some("192.0.2.1:1080".into()), None).status,
            CheckStatus::Warning
        );
        assert_eq!(
            proxy_result(
                None,
                None,
                Some("http://proxy.example.com/config.pac".into())
            )
            .status,
            CheckStatus::Warning
        );
    }

    #[test]
    fn detects_interceptors_without_duplicate_process_names() {
        let processes = [
            process("WINWS2.EXE", None),
            process("winws2.exe", None),
            process("example.exe", None),
        ];
        assert_eq!(
            packet_interceptor_result(&processes, Ok(false)).detail,
            CheckDetail::PacketInterceptor {
                processes: vec!["WINWS2.EXE".into()],
                driver: false
            }
        );
        assert_eq!(
            packet_interceptor_result(&[], Ok(true)).status,
            CheckStatus::Warning
        );
        assert_eq!(
            packet_interceptor_result(&[], Err(std::io::Error::other("no access"))).status,
            CheckStatus::Unavailable
        );
    }

    #[test]
    fn ignores_own_engines_and_unknown_paths_but_detects_external_engines() {
        let exe = Path::new("C:/Example/Rosetun/rosetun-gui.exe");
        let own = [
            process("sing-box.exe", Some("C:/Example/Rosetun/sing-box.exe")),
            process("xray.exe", None),
        ];
        assert_eq!(other_vpn_result(&own, vec![], exe).status, CheckStatus::Ok);
        let other = [
            process("SING-BOX.EXE", Some("C:/Example/Other/sing-box.exe")),
            process("THRONE.EXE", None),
        ];
        assert_eq!(
            other_vpn_result(&other, vec![], exe).detail,
            CheckDetail::OtherVpn {
                processes: vec!["SING-BOX.EXE".into(), "THRONE.EXE".into()],
                adapters: vec![]
            }
        );
        assert_eq!(
            other_vpn_result(&[], vec!["Example WireGuard".into()], exe).status,
            CheckStatus::Warning
        );
    }

    fn reply(rcode: u8, texts: &[&str]) -> Result<Reply, AskError> {
        Ok(Reply {
            rcode,
            texts: texts.iter().map(|text| (*text).to_owned()).collect(),
        })
    }

    fn dns(udp: Result<Reply, AskError>, tcp: Result<Reply, AskError>) -> CheckResult {
        dns_substitution_result(&udp, &tcp, "192.0.2.53")
    }

    #[test]
    fn dns_answers_alike_over_udp_and_tcp_are_not_substituted() {
        assert_eq!(
            dns(reply(0, &["192.0.2.1"]), reply(0, &["192.0.2.1"])),
            CheckResult::ok(CheckKind::DnsSubstitution)
        );
    }

    #[test]
    fn neighbouring_nat_addresses_are_the_same_client() {
        for (udp, tcp) in [
            ("192.0.2.1", "192.0.200.7"),
            ("2001:db8:1:2::1", "2001:db8:1:ff::9"),
        ] {
            assert_eq!(
                dns(reply(0, &[udp]), reply(0, &[tcp])),
                CheckResult::ok(CheckKind::DnsSubstitution),
                "{udp} {tcp}"
            );
        }
        assert_eq!(
            dns(reply(0, &["2001:db8:2::1"]), reply(0, &["2001:db8:1::1"])).status,
            CheckStatus::Warning
        );
    }

    #[test]
    fn a_clear_udp_mismatch_is_substitution_of_that_server() {
        let substituted = CheckResult::warning(
            CheckKind::DnsSubstitution,
            CheckDetail::DnsSubstitution {
                server: "192.0.2.53".into(),
            },
        );
        let real = || reply(0, &["192.0.2.1"]);
        for udp in [
            reply(0, &["198.51.100.1"]),
            reply(rosetun_dns::wire::RCODE_REFUSED, &[]),
            reply(rosetun_dns::wire::RCODE_NOTIMP, &[]),
            reply(2, &[]),
            reply(rosetun_dns::wire::RCODE_NXDOMAIN, &[]),
            reply(0, &[]),
        ] {
            assert_eq!(dns(udp.clone(), real()), substituted, "{udp:?}");
        }
    }

    #[test]
    fn anything_doubtful_is_unavailable_not_an_alarm() {
        let unavailable = CheckResult::unavailable(CheckKind::DnsSubstitution);
        let real = || reply(0, &["192.0.2.1"]);
        for (udp, tcp) in [
            (Err(AskError::NoReply), real()),
            (Err(AskError::Truncated), real()),
            (real(), Err(AskError::NoReply)),
            (Err(AskError::NoReply), Err(AskError::NoReply)),
            (
                reply(rosetun_dns::wire::RCODE_REFUSED, &[]),
                reply(rosetun_dns::wire::RCODE_REFUSED, &[]),
            ),
            (reply(2, &[]), reply(2, &[])),
            (real(), reply(0, &[])),
        ] {
            assert_eq!(
                dns(udp.clone(), tcp.clone()),
                unavailable,
                "{udp:?} {tcp:?}"
            );
        }
    }
}
