"""Fixed lab wire contract, strict offline evidence qualification and leak verdict."""
import ipaddress
import math
import struct
from typing import NamedTuple

MACS = {'test': '00:00:5e:00:53:61', 'lab': '00:00:5e:00:53:62'}
CLIENTS = {4: '192.0.2.2', 6: '2001:db8:6a:1::2'}
GATEWAYS = {4: '192.0.2.1', 6: '2001:db8:6a:1::1'}
TARGETS = {4: '203.0.113.2', 6: '2001:db8:6a:2::2'}
CAPTURE_LIMIT = 131072
LOG_LIMIT = 32768
DURATION = 60
SERVICES = ('http', 'udp', 'dns-udp', 'dns-tcp')
PORTS = {'http': 8080, 'udp': 9000, 'dns-udp': 53, 'dns-tcp': 53, 'marker': 9100}
# Nothing listens here and no expected exchange uses it: the deliberate leak control.
CANARY_PORT = 9999
CANARY_TCP_TARGET = '203.0.113.9'

# The only traffic between the two machines that is neither a probe nor a window
# marker. Rows are (name, kind, message code, where the frame may go); a frame must
# also come from one machine and be addressed to the other or to a link-scope group.
INFRASTRUCTURE = (
    ('arp-request', 'arp', 1, 'broadcast-or-peer'),
    ('arp-reply', 'arp', 2, 'peer'),
    ('neighbor-solicitation', 'icmpv6', 135, 'solicited-node-or-peer'),
    ('neighbor-advertisement', 'icmpv6', 136, 'all-nodes-or-peer'),
    ('router-solicitation', 'icmpv6', 133, 'all-routers'),
    ('router-advertisement', 'icmpv6', 134, 'all-nodes-or-peer'),
    ('multicast-listener-query', 'icmpv6', 130, 'link-multicast'),
    ('multicast-listener-report', 'icmpv6', 131, 'link-multicast'),
    ('multicast-listener-done', 'icmpv6', 132, 'link-multicast'),
    ('multicast-listener-report-v2', 'icmpv6', 143, 'link-multicast'),
)

BROADCAST = 'ff:ff:ff:ff:ff:ff'
PCAP_HEADER = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 2048, 1)
UNEXPECTED_LIMIT = 16
ENDPOINTS = {'test': (CLIENTS[4], CLIENTS[6]), 'lab': (GATEWAYS[4], GATEWAYS[6])}
LINK_LOCAL = ipaddress.ip_network('fe80::/10')
SOLICITED_NODE = ipaddress.ip_network('ff02::1:ff00:0/104')
LINK_MULTICAST = ipaddress.ip_network('ff02::/16')
IP_PROTOCOLS = {'tcp': 6, 'udp': 17}
PROTOCOL_NAMES = {1: 'icmp', 6: 'tcp', 17: 'udp', 58: 'icmpv6'}
ICMP_ERRORS = (3, 4, 5, 11, 12)


def interface(rows, role):
    if role not in MACS:
        raise ValueError('unknown-network-role')
    matches = [r['ifname'] for r in rows if r.get('address', '').lower() == MACS[role]]
    physical = [r for r in rows if r.get('link_type') == 'ether'
                and r.get('linkinfo', {}).get('info_kind') != 'veth']
    if len(matches) != 1 or len(physical) != 1:
        raise ValueError('ambiguous-or-foreign-interface')
    return matches[0]


def probes(run_id, nonce_factory):
    return [dict(run_id=run_id, nonce=nonce_factory(), family=f, service=s,
                 protocol='tcp' if s in ('http', 'dns-tcp') else 'udp',
                 source=CLIENTS[f], target=TARGETS[f], port=PORTS[s])
            for f in (4, 6) for s in SERVICES]


def markers(run_id, nonce_factory):
    """The two UDP datagrams that bracket one observation window."""
    return [dict(run_id=run_id, nonce=nonce_factory(), word=word, family=4, service='marker',
                 protocol='udp', source=CLIENTS[4], target=TARGETS[4], port=PORTS['marker'])
            for word in ('open', 'close')]


def token(probe):
    return (probe['run_id'] + '.' + probe['nonce'] + '.lab.test').encode('ascii')


def query(probe):
    if probe['service'].startswith('dns'):
        name = b''.join(bytes([len(p)]) + p for p in token(probe).split(b'.')) + b'\0'
        return b'\x6a\x06\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + name + b'\x00\x01\x00\x01'
    return token(probe)


def answer(probe):
    q = query(probe)
    if probe['service'].startswith('dns'):
        return q[:2] + b'\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00' + q[12:] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\xcb\x00\x71\x02'
    return b'rosetun-lab:' + token(probe)


def marker_query(marker):
    return ('rosetun-lab-marker:' + '.'.join((marker['run_id'], marker['nonce'], marker['word']))).encode('ascii')


def marker_answer(marker):
    return b'rosetun-lab-ack:' + marker_query(marker)


def _needle(probe, direction):
    if direction == 'request':
        return query(probe)[12:-4] if probe['service'].startswith('dns') else token(probe)
    return answer(probe)


class Frame(NamedTuple):
    """Headers of one captured Ethernet frame; the payload is the transport payload."""
    size: int
    src_mac: str
    dst_mac: str
    ethertype: int
    family: int | None
    proto: int | None
    src: str | None
    dst: str | None
    sport: int | None
    dport: int | None
    flags: int | None
    payload: bytes
    arp: tuple | None
    icmp: tuple | None
    inner: tuple | None


def _inner(quoted):
    """Source, target, protocol and ports of the datagram quoted by an ICMP error."""
    if len(quoted) < 20 or quoted[0] >> 4 != 4:
        return None
    start = (quoted[0] & 15) * 4
    ports = (None, None)
    if quoted[9] in (6, 17) and start >= 20 and len(quoted) >= start + 4:
        ports = struct.unpack_from('!HH', quoted, start)
    return (str(ipaddress.ip_address(quoted[12:16])), str(ipaddress.ip_address(quoted[16:20])), quoted[9], *ports)


def parse(packet):
    """Parse one frame's Ethernet, IP and transport headers, or raise ValueError."""
    fields = dict(size=len(packet), dst_mac=packet[0:6].hex(':'), src_mac=packet[6:12].hex(':'),
                  ethertype=int.from_bytes(packet[12:14], 'big'), family=None, proto=None, src=None,
                  dst=None, sport=None, dport=None, flags=None, payload=b'', arp=None, icmp=None, inner=None)
    ip = packet[14:]
    if fields['ethertype'] == 0x0806:
        if len(ip) < 28:
            raise ValueError('truncated-arp')
        if ip[:6] == b'\x00\x01\x08\x00\x06\x04':
            fields['arp'] = (int.from_bytes(ip[6:8], 'big'), ip[8:14].hex(':'),
                             str(ipaddress.ip_address(ip[14:18])), ip[18:24].hex(':'),
                             str(ipaddress.ip_address(ip[24:28])))
        return Frame(**fields)
    if fields['ethertype'] == 0x0800:
        if len(ip) < 20:
            raise ValueError('truncated-ipv4')
        length = int.from_bytes(ip[2:4], 'big')
        if ip[0] >> 4 != 4 or ip[6] & 0x3f or ip[7] or length > len(ip):
            raise ValueError('fragmented-or-invalid-ipv4')
        family, proto, start = 4, ip[9], (ip[0] & 15) * 4
        if not 20 <= start <= length:
            raise ValueError('invalid-ipv4-header')
        source, target = str(ipaddress.ip_address(ip[12:16])), str(ipaddress.ip_address(ip[16:20]))
        ip = ip[:length]
    elif fields['ethertype'] == 0x86dd:
        if len(ip) < 40:
            raise ValueError('truncated-ipv6')
        length = 40 + int.from_bytes(ip[4:6], 'big')
        if ip[0] >> 4 != 6 or length > len(ip):
            raise ValueError('invalid-ipv6')
        family, proto, start = 6, ip[6], 40
        source, target = str(ipaddress.ip_address(ip[8:24])), str(ipaddress.ip_address(ip[24:40]))
        ip = ip[:length]
        # Multicast listener messages travel behind a hop-by-hop header.
        while proto in (0, 43, 60):
            if start + 8 > len(ip):
                raise ValueError('invalid-ipv6')
            proto, start = ip[start], start + (ip[start + 1] + 1) * 8
        if proto == 44:
            raise ValueError('fragmented-ipv6')
        if start > len(ip):
            raise ValueError('invalid-ipv6')
    else:
        return Frame(**fields)
    fields.update(family=family, proto=proto, src=source, dst=target)
    data = ip[start:]
    if proto in (6, 17):
        minimum = 20 if proto == 6 else 8
        if len(data) < minimum:
            raise ValueError('incomplete-transport')
        if proto == 17 and int.from_bytes(data[4:6], 'big') != len(data):
            raise ValueError('invalid-udp-length')
        header = (data[12] >> 4) * 4 if proto == 6 else 8
        if not minimum <= header <= len(data):
            raise ValueError('invalid-transport-header')
        fields.update(sport=int.from_bytes(data[0:2], 'big'), dport=int.from_bytes(data[2:4], 'big'),
                      flags=data[13] if proto == 6 else None, payload=data[header:])
    elif proto == (1 if family == 4 else 58):
        if len(data) < 8:
            raise ValueError('incomplete-icmp')
        fields.update(icmp=(data[0], data[1]), payload=data[8:],
                      inner=_inner(data[8:]) if family == 4 and data[0] in ICMP_ERRORS else None)
    return Frame(**fields)


def records(raw):
    """Yield the frames of a pcap, failing closed on any irregular record."""
    if not 24 <= len(raw) <= CAPTURE_LIMIT or raw[:24] != PCAP_HEADER:
        raise ValueError('invalid-or-overlimit-pcap')
    offset = 24
    while offset < len(raw):
        if len(raw) - offset < 16:
            raise ValueError('incomplete-pcap')
        _, _, size, original = struct.unpack_from('<IIII', raw, offset)
        offset += 16
        if size != original or not 14 <= size <= 2048 or offset + size > len(raw):
            raise ValueError('truncated-pcap-frame')
        yield raw[offset:offset + size]
        offset += size


def frames(raw):
    packets = []
    for packet in records(raw):
        frame = parse(packet)
        if frame.proto in (6, 17):
            packets.append((frame.family, 'tcp' if frame.proto == 6 else 'udp', frame.src, frame.dst,
                            frame.sport, frame.dport, frame.payload))
    return packets


def _clean(health):
    return (type(health) is dict and health.get('error') is False
            and type(health.get('dropped')) is int and health['dropped'] == 0
            and health.get('finished') is True)


def qualify(expected, replies, logs, capture, ready, health):
    result = dict(ipv4='UNVERIFIED', ipv6='UNVERIFIED', services='UNVERIFIED',
                  observer='UNVERIFIED', evidence='UNVERIFIED', qualified=False)
    packets = frames(capture)
    if len(replies) != 8 or len(logs) != 8 or len(expected) != 8:
        return result
    if (len({p['nonce'] for p in expected}) != 8
            or {(p['family'], p['service']) for p in expected} != {(f, s) for f in (4, 6) for s in SERVICES}):
        return result
    for p in expected:
        key = {**p, 'response': answer(p).hex()}
        if (key not in replies or key not in logs or p['target'] != TARGETS[p['family']]
                or p['source'] != CLIENTS[p['family']]):
            return result
    result.update(ipv4='PASS', ipv6='PASS', services='PASS')
    if ready is not True or not _clean(health):
        return result
    for p in expected:
        matched = []
        for direction in ('request', 'response'):
            for f, proto, src, dst, sp, dp, data in packets:
                addresses = (p['source'], p['target']) if direction == 'request' else (p['target'], p['source'])
                if (f == p['family'] and proto == p['protocol'] and (src, dst) == addresses
                        and (dp if direction == 'request' else sp) == p['port']
                        and _needle(p, direction) in data):
                    matched.append((direction, sp if direction == 'request' else dp))
                    break
        if len(matched) != 2 or matched[0][1] != matched[1][1]:
            return result
    return dict(ipv4='PASS', ipv6='PASS', services='PASS', observer='PASS', evidence='PASS', qualified=True)


def _direction(frame, exchange):
    """'request' or 'response' when the frame travels along the exchange, else None."""
    if frame.family != exchange['family'] or frame.proto != IP_PROTOCOLS[exchange['protocol']]:
        return None
    if ((frame.src_mac, frame.dst_mac, frame.src, frame.dst, frame.dport)
            == (MACS['test'], MACS['lab'], exchange['source'], exchange['target'], exchange['port'])):
        return 'request'
    if ((frame.src_mac, frame.dst_mac, frame.src, frame.dst, frame.sport)
            == (MACS['lab'], MACS['test'], exchange['target'], exchange['source'], exchange['port'])):
        return 'response'
    return None


def _marker_hit(frame, window):
    for marker in window:
        direction = _direction(frame, marker)
        if direction and frame.payload == (marker_query if direction == 'request' else marker_answer)(marker):
            return marker['word'], direction
    return None


def _icmpv6_allowed(frame, sender, peer, destination):
    source, target = ipaddress.ip_address(frame.src), ipaddress.ip_address(frame.dst)
    if frame.src != ENDPOINTS[sender][1] and source not in LINK_LOCAL:
        return False
    group = frame.dst_mac.startswith('33:33:')
    unicast = (frame.dst == ENDPOINTS[peer][1] or target in LINK_LOCAL) and frame.dst_mac == MACS[peer]
    allowed = {'solicited-node-or-peer': unicast or (target in SOLICITED_NODE and group),
               'all-nodes-or-peer': unicast or (frame.dst == 'ff02::1' and group),
               'all-routers': frame.dst == 'ff02::2' and group,
               'link-multicast': target in LINK_MULTICAST and group}[destination]
    if not allowed:
        return False
    if frame.icmp[0] in (135, 136):
        if len(frame.payload) < 16:
            return False
        neighbor = ipaddress.ip_address(frame.payload[:16])
        return str(neighbor) in (CLIENTS[6], GATEWAYS[6]) or neighbor in LINK_LOCAL
    return True


def _infrastructure(frame):
    sender = next((role for role, mac in MACS.items() if mac == frame.src_mac), None)
    if sender is None:
        return False
    peer = 'lab' if sender == 'test' else 'test'
    for _, kind, code, destination in INFRASTRUCTURE:
        if kind == 'arp' and frame.arp is not None and frame.arp[0] == code:
            _, sha, spa, tha, tpa = frame.arp
            if (sha, spa, tpa) != (frame.src_mac, ENDPOINTS[sender][0], ENDPOINTS[peer][0]):
                continue
            if destination == 'peer':
                allowed = tha == frame.dst_mac == MACS[peer]
            else:
                allowed = tha == '00:00:00:00:00:00' and frame.dst_mac in (BROADCAST, MACS[peer])
        elif kind == 'icmpv6' and frame.family == 6 and frame.icmp is not None and frame.icmp[0] == code:
            allowed = _icmpv6_allowed(frame, sender, peer, destination)
        else:
            continue
        if allowed:
            return True
    return False


def _involves_test(frame):
    addresses = {frame.src, frame.dst}
    if frame.arp is not None:
        addresses |= {frame.arp[2], frame.arp[4]}
    return MACS['test'] in (frame.src_mac, frame.dst_mac) or bool(addresses & {CLIENTS[4], CLIENTS[6]})


def _canary_flow(frame):
    """Name of the deliberate leak flow a frame belongs to, including the errors it provokes."""
    if frame.family != 4:
        return None
    if (frame.src_mac, frame.dst_mac, frame.src, frame.dport) == (MACS['test'], MACS['lab'], CLIENTS[4], CANARY_PORT):
        if frame.proto == 17 and frame.dst == TARGETS[4]:
            return 'udp'
        if frame.proto == 6 and frame.dst == CANARY_TCP_TARGET and frame.flags & 0x17 == 0x02 and not frame.payload:
            return 'tcp'
    if ((frame.src_mac, frame.dst_mac, frame.dst) == (MACS['lab'], MACS['test'], CLIENTS[4])
            and frame.proto == 1 and frame.inner is not None):
        source, target, proto, _, dport = frame.inner
        if source == CLIENTS[4] and dport == CANARY_PORT:
            if proto == 17 and target == TARGETS[4]:
                return 'udp'
            if proto == 6 and target == CANARY_TCP_TARGET:
                return 'tcp'
    return None


def _describe(frame):
    """Header facts of a frame, never its payload."""
    if frame.arp is not None:
        protocol, addresses = 'arp', (frame.arp[2], frame.arp[4])
    elif frame.family is not None:
        protocol, addresses = PROTOCOL_NAMES.get(frame.proto, 'ip-%d' % frame.proto), (frame.src, frame.dst)
    else:
        protocol, addresses = None, (frame.src_mac, frame.dst_mac)
    ports = (frame.sport, frame.dport) if frame.sport is not None else None
    return ('0x%04x' % frame.ethertype, frame.family, protocol, addresses, ports, frame.size)


def classify(raw, expected, window):
    """Put every captured frame into exactly one category and check the window markers.

    Frames that cannot be parsed are counted apart and make the result unverified. A
    truncated record ends the walk, but frames already seen keep their category.
    """
    if [m['word'] for m in window] != ['open', 'close']:
        raise ValueError('invalid-window')
    parsed, unparsed, problem = [], [], None
    try:
        for index, packet in enumerate(records(raw)):
            try:
                parsed.append((index, parse(packet)))
            except ValueError as error:
                unparsed.append(str(error))
    except ValueError as error:
        problem = str(error)
    # A TCP segment without data belongs to a probe only on a connection that carried it.
    connections = [set() for _ in expected]
    for _, frame in parsed:
        for position, p in enumerate(expected):
            direction = _direction(frame, p)
            if p['protocol'] == 'tcp' and direction and frame.payload and _needle(p, direction) in frame.payload:
                connections[position].add(frame.sport if direction == 'request' else frame.dport)

    def is_probe(frame):
        for position, p in enumerate(expected):
            direction = _direction(frame, p)
            if direction is None:
                continue
            if p['protocol'] == 'tcp' and not frame.payload:
                if (frame.sport if direction == 'request' else frame.dport) in connections[position]:
                    return True
            elif _needle(p, direction) in frame.payload:
                return True
        return False

    counts = dict(probe=0, marker=0, infrastructure=0, unexpected=0, foreign=0, unparsed=len(unparsed))
    unexpected, canary = [], dict(udp=0, tcp=0, other=0)
    probe_at, seen = [], {(m['word'], d): [] for m in window for d in ('request', 'response')}
    for index, frame in parsed:
        if is_probe(frame):
            counts['probe'] += 1
            probe_at.append(index)
            continue
        hit = _marker_hit(frame, window)
        if hit:
            counts['marker'] += 1
            seen[hit].append(index)
        elif _infrastructure(frame):
            counts['infrastructure'] += 1
        elif _involves_test(frame):
            counts['unexpected'] += 1
            if len(unexpected) < UNEXPECTED_LIMIT:
                unexpected.append(_describe(frame))
            canary[_canary_flow(frame) or 'other'] += 1
        else:
            counts['foreign'] += 1
    found = all(len(indexes) == 1 for indexes in seen.values())
    ordered = False
    if found:
        (open_request,), (open_response,) = seen[('open', 'request')], seen[('open', 'response')]
        (close_request,), (close_response,) = seen[('close', 'request')], seen[('close', 'response')]
        ordered = (open_request < open_response < close_request < close_response
                   and all(open_response < at < close_request for at in probe_at))
    unverified = []
    if problem:
        unverified.append('invalid-pcap:' + problem)
    if unparsed:
        unverified.append('unparsed-frame:' + unparsed[0])
    if len(raw) + 16 + 2048 > CAPTURE_LIMIT:
        unverified.append('capture-limit-reached')
    if not found:
        unverified.append('window-markers-missing-or-repeated')
    elif not ordered:
        unverified.append('window-markers-out-of-order')
    return dict(categories=counts, unexpected=unexpected, canary=canary,
                window=dict(markers_found=found, ordered=ordered), unverified=unverified)


def _window_times(health, window):
    """Capture start, marker service times and capture end, all from the lab machine's clock."""
    if type(health) is not dict:
        return None
    rows = health.get('markers')
    if (type(rows) is not list or len(rows) != 2 or not all(type(row) is dict for row in rows)
            or [(row.get('word'), row.get('nonce')) for row in rows] != [(m['word'], m['nonce']) for m in window]):
        return None
    return [health.get('capture_started'), rows[0].get('at'), rows[1].get('at'), health.get('capture_ended')]


def _health_reasons(health, ready, window, marker_replies):
    reasons = []
    if ready is not True:
        reasons.append('observer-not-ready')
    if not _clean(health):
        reasons.append('observer-health')
    if marker_replies != [{**m, 'response': marker_answer(m).hex()} for m in window]:
        reasons.append('marker-reply-mismatch')
    # The test machine's own send times are never compared with these.
    times = _window_times(health, window)
    if times is None or not all(type(t) in (int, float) and math.isfinite(t) for t in times):
        reasons.append('capture-window-unrecorded')
    elif times[3] < times[2]:
        reasons.append('capture-ended-before-close')
    elif times != sorted(times):
        reasons.append('capture-window-inconsistent')
    return reasons


def leak_verdict(raw, expected, window, health, ready, marker_replies):
    """DETECTED, NONE or UNVERIFIED. Only a complete, healthy and bracketed capture says NONE."""
    result = classify(raw, expected, window)
    reasons = result.pop('unverified') + _health_reasons(health, ready, window, marker_replies)
    canary = result.pop('canary')
    if result['categories']['unexpected']:
        leak, reason = 'DETECTED', 'unexpected-frames'
    elif reasons:
        leak, reason = 'UNVERIFIED', reasons[0]
    else:
        leak, reason = 'NONE', 'clean'
    return dict(leak=leak, leak_reason=reason, categories=result['categories'], unexpected=result['unexpected'],
                canary_flows=sorted(name for name in ('udp', 'tcp') if canary[name]),
                canary_other=canary['other'], window=result['window'])
