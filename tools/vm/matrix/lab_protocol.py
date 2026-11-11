"""Fixed lab wire contract and strict offline evidence qualification."""
import ipaddress
import struct

MACS = {'test': '00:00:5e:00:53:61', 'lab': '00:00:5e:00:53:62'}
CLIENTS = {4: '192.0.2.2', 6: '2001:db8:6a:1::2'}
GATEWAYS = {4: '192.0.2.1', 6: '2001:db8:6a:1::1'}
TARGETS = {4: '203.0.113.2', 6: '2001:db8:6a:2::2'}
CAPTURE_LIMIT = 131072
LOG_LIMIT = 32768
DURATION = 60
PORTS = {'http': 8080, 'udp': 9000, 'dns-udp': 53, 'dns-tcp': 53}


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
            for f in (4, 6) for s in PORTS]


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


def frames(raw):
    if not 24 <= len(raw) <= CAPTURE_LIMIT or raw[:24] != struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 2048, 1):
        raise ValueError('invalid-or-overlimit-pcap')
    offset, packets = 24, []
    while offset < len(raw):
        if len(raw) - offset < 16:
            raise ValueError('incomplete-pcap')
        _, _, size, original = struct.unpack_from('<IIII', raw, offset)
        offset += 16
        if size != original or not 14 <= size <= 2048 or offset + size > len(raw):
            raise ValueError('truncated-pcap-frame')
        packet = raw[offset:offset + size]
        offset += size
        ether = packet[12:14]
        ip = packet[14:]
        if ether == b'\x08\x00' and len(ip) >= 20:
            length = int.from_bytes(ip[2:4], 'big')
            if ip[0] >> 4 != 4 or ip[6] & 0x3f or ip[7] or length > len(ip):
                raise ValueError('fragmented-or-invalid-ipv4')
            family, proto, start = 4, ip[9], (ip[0] & 15) * 4
            if not 20 <= start <= length:
                raise ValueError('invalid-ipv4-header')
            source, target = str(ipaddress.ip_address(ip[12:16])), str(ipaddress.ip_address(ip[16:20]))
            ip = ip[:length]
        elif ether == b'\x86\xdd' and len(ip) >= 40:
            length = 40 + int.from_bytes(ip[4:6], 'big')
            if ip[0] >> 4 != 6 or length > len(ip):
                raise ValueError('invalid-ipv6')
            family, proto, start = 6, ip[6], 40
            source, target = str(ipaddress.ip_address(ip[8:24])), str(ipaddress.ip_address(ip[24:40]))
            ip = ip[:length]
        else:
            continue
        if proto not in (6, 17):
            continue
        data = ip[start:]
        minimum = 20 if proto == 6 else 8
        if len(data) < minimum:
            raise ValueError('incomplete-transport')
        if proto == 17 and int.from_bytes(data[4:6], 'big') != len(data):
            raise ValueError('invalid-udp-length')
        sport, dport = struct.unpack_from('!HH', data)
        header = (data[12] >> 4) * 4 if proto == 6 else 8
        if not minimum <= header <= len(data):
            raise ValueError('invalid-transport-header')
        packets.append((family, 'tcp' if proto == 6 else 'udp', source, target, sport, dport, data[header:]))
    return packets


def qualify(expected, replies, logs, capture, ready, health):
    result = dict(ipv4='UNVERIFIED', ipv6='UNVERIFIED', services='UNVERIFIED',
                  observer='UNVERIFIED', evidence='UNVERIFIED', qualified=False)
    packets = frames(capture)
    if len(replies) != 8 or len(logs) != 8 or len(expected) != 8:
        return result
    if (len({p['nonce'] for p in expected}) != 8
            or {(p['family'], p['service']) for p in expected} != {(f, s) for f in (4, 6) for s in PORTS}):
        return result
    for p in expected:
        key = {**p, 'response': answer(p).hex()}
        if (key not in replies or key not in logs or p['target'] != TARGETS[p['family']]
                or p['source'] != CLIENTS[p['family']]):
            return result
    result.update(ipv4='PASS', ipv6='PASS', services='PASS')
    if (ready is not True or health != {'error': False, 'dropped': 0, 'finished': True}
            or type(health.get('dropped')) is not int or health['error'] is not False
            or health['finished'] is not True):
        return result
    for p in expected:
        marker = query(p)[12:-4] if p['service'].startswith('dns') else token(p)
        matched = []
        for direction in ('request', 'response'):
            for f, proto, src, dst, sp, dp, data in packets:
                addresses = (p['source'], p['target']) if direction == 'request' else (p['target'], p['source'])
                if (f == p['family'] and proto == p['protocol'] and (src, dst) == addresses
                        and (dp if direction == 'request' else sp) == p['port']
                        and (marker if direction == 'request' else answer(p)) in data):
                    matched.append((direction, sp if direction == 'request' else dp))
                    break
        if len(matched) != 2 or matched[0][1] != matched[1][1]:
            return result
    return dict(ipv4='PASS', ipv6='PASS', services='PASS', observer='PASS', evidence='PASS', qualified=True)
