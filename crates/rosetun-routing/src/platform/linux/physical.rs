//! The physical default route on Linux: the interface of the main table's
//! default route with the lowest metric, never loopback or the tunnel.
//! sing-tun puts its own routes in a table of its own (and policy rules),
//! so the main table keeps showing the physical path while a tunnel runs.

const RTF_UP: u32 = 0x1;

pub(in crate::platform) fn physical_default_interface(exclude_alias: &str) -> Option<String> {
    let ipv4 = std::fs::read_to_string("/proc/net/route").ok();
    let ipv6 = std::fs::read_to_string("/proc/net/ipv6_route").ok();
    ipv4.as_deref()
        .and_then(|table| ipv4_default(table, exclude_alias))
        .or_else(|| {
            ipv6.as_deref()
                .and_then(|table| ipv6_default(table, exclude_alias))
        })
}

fn usable(interface: &str, exclude_alias: &str) -> bool {
    !interface.is_empty() && interface != "lo" && interface != exclude_alias
}

/// `/proc/net/route`: `Iface Destination Gateway Flags RefCnt Use Metric Mask
/// ...`, numbers in hexadecimal, a header line first.
fn ipv4_default(table: &str, exclude_alias: &str) -> Option<String> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (&interface, &destination, &flags, &metric, &mask) = (
                fields.first()?,
                fields.get(1)?,
                fields.get(3)?,
                fields.get(6)?,
                fields.get(7)?,
            );
            let flags = u32::from_str_radix(flags, 16).ok()?;
            let metric = metric.parse::<u32>().ok()?;
            (destination == "00000000"
                && mask == "00000000"
                && flags & RTF_UP != 0
                && usable(interface, exclude_alias))
            .then(|| (metric, interface.to_owned()))
        })
        .min()
        .map(|(_, interface)| interface)
}

/// `/proc/net/ipv6_route`: `dest prefix src prefix next-hop metric refcnt use
/// flags iface`, all hexadecimal, no header.
fn ipv6_default(table: &str, exclude_alias: &str) -> Option<String> {
    table
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (&destination, &prefix, &metric, &flags, &interface) = (
                fields.first()?,
                fields.get(1)?,
                fields.get(5)?,
                fields.get(8)?,
                fields.get(9)?,
            );
            let flags = u32::from_str_radix(flags, 16).ok()?;
            let metric = u32::from_str_radix(metric, 16).ok()?;
            (destination.bytes().all(|byte| byte == b'0')
                && prefix == "00"
                && flags & RTF_UP != 0
                && usable(interface, exclude_alias))
            .then(|| (metric, interface.to_owned()))
        })
        .min()
        .map(|(_, interface)| interface)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";

    #[test]
    fn the_default_route_with_the_lowest_metric_wins() {
        let table = format!(
            "{HEADER}\
wlan0\t00000000\t0102000A\t0003\t0\t0\t600\t00000000\t0\t0\t0
eth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t000200C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
"
        );
        assert_eq!(ipv4_default(&table, "rosetun0").as_deref(), Some("eth0"));
    }

    #[test]
    fn the_tunnel_loopback_and_routes_that_are_down_are_not_physical() {
        let table = format!(
            "{HEADER}\
rosetun0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
lo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
eth1\t00000000\t010200C0\t0002\t0\t0\t0\t00000000\t0\t0\t0
"
        );
        assert_eq!(ipv4_default(&table, "rosetun0"), None);
        assert_eq!(ipv4_default(HEADER, "rosetun0"), None);
        assert_eq!(ipv4_default("", "rosetun0"), None);
    }

    #[test]
    fn a_host_with_ipv6_only_uses_its_ipv6_default_route() {
        let zeros = "00000000000000000000000000000000";
        let table = format!(
            "{zeros} 00 {zeros} 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003 eth0\n\
{zeros} 00 {zeros} 00 {zeros} ffffffff 00000001 00000000 00200200 lo\n\
20010db8000000000000000000000000 40 {zeros} 00 {zeros} 00000100 00000001 00000000 00000001 eth0\n"
        );
        assert_eq!(ipv6_default(&table, "rosetun0").as_deref(), Some("eth0"));
    }
}
