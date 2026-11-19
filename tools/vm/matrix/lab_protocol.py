"""Fixed lab wire contract, strict offline evidence qualification and leak verdict."""
import base64
import binascii
import hashlib
import ipaddress
import math
import re
import struct
from typing import NamedTuple

MACS = {'test': '00:00:5e:00:53:61', 'lab': '00:00:5e:00:53:62'}
CLIENTS = {4: '192.0.2.2', 6: '2001:db8:6a:1::2'}
GATEWAYS = {4: '192.0.2.1', 6: '2001:db8:6a:1::1'}
TARGETS = {4: '203.0.113.2', 6: '2001:db8:6a:2::2'}


def eui64_link_local(mac):
    """The modified EUI-64 link-local address of a hardware address (RFC 4291, appendix A)."""
    octets = bytes.fromhex(mac.replace(':', ''))
    interface_id = bytes([octets[0] ^ 0x02]) + octets[1:3] + b'\xff\xfe' + octets[3:]
    return str(ipaddress.IPv6Address(b'\xfe\x80' + bytes(6) + interface_id))


# The link-local address of each machine on the lab wire. The lab's is the IPv6 router of an L3 run (stage 7e);
# the test image of contract v6b generates its own the same way.
LINK_LOCALS = {role: eui64_link_local(mac) for role, mac in MACS.items()}
CAPTURE_LIMIT = 131072
LOG_LIMIT = 32768
# What a helper prints after `lab-helper-failed:` and what the observer records in `health.json`:
# lowercase words, never an address outside the documentation ranges.
HELPER_REASON = re.compile(r'[a-z0-9:._-]{1,96}')
REASON_LIMIT = 96
# Where the observer was when it stopped, as `error_in` of `health.json`.
OBSERVER_PLACES = ('capture', 'marker', 'http', 'udp', 'dns-tcp', 'https', 'dns', 'doh', 'node', 'poller', 'setup',
                   'finish')
# Stage 7b2a: phase windows. Window N is bracketed by `open` and `close` markers that carry
# its index and the short name of the phase it observes.
WINDOW_WORDS = ('open', 'close')
WINDOW_LIMIT = 100
WINDOW_LABEL = re.compile(r'[a-z0-9_.-]{1,48}')
MARKER_PREFIX = 'rosetun-lab-marker:'
ACK_PREFIX = 'rosetun-lab-ack:'
_WINDOW_MARKER = re.compile(rb'rosetun-lab-marker:([0-9a-f]{32})\.(0|[1-9][0-9]{0,2})\.(open|close)\.([a-z0-9_.-]{1,48})')
DURATION = 60
# Stage 7c1: the negative controls of `lab-smoke --control`. The first needs nothing but the canary's packets;
# the others stop something between the markers, so the test machine waits there for this long, after its
# exchanges and before the closing marker. The pause is only in a request that names such a control.
CONTROLS = ('extra-packet', 'observer-stopped', 'observer-killed', 'link-down')
GUEST_CONTROLS = ('observer-stopped', 'observer-killed', 'link-down')
CONTROL_HOLD_SECONDS = 20
# Every wait of a lab socket, in seconds: a server for a request, a client for an answer, the test
# machine for the echo of a marker. Nested virtualization with one vCPU per machine can stall a
# guest for a second or more, which the old waits (1 for a server, 2 for a client) did not allow.
REQUEST_TIMEOUT = 5
RESPONSE_TIMEOUT = 5
MARKER_TIMEOUT = 5
# The longest legacy L3 job (run-l3.sh) plus the time to finish and read the evidence.
JOB_TIMEOUT_SECONDS = 1800
# The capture outlives the job by this much: it also covers the boot and the import of the test machine.
CAPTURE_SLACK = 300
# The longest capture: the job's span (`config.job_span`: every phase at its timeout and every planned reboot at
# `REBOOT_SECONDS`) plus CAPTURE_SLACK. Linux L4 has three phases and two reboots, so a phase of 600 seconds asks for
# 3 * 600 + 2 * 240 + 300 = 2580, and 640 seconds a phase is the most that fits. A one-phase job is held to
# JOB_TIMEOUT_SECONDS + CAPTURE_SLACK (2100) as before.
DURATION_MAX = 2700
# Stage 7b2a: the capture of a long run lives on its own disk, behind a fixed header.
EVIDENCE_SERIAL = 'rosetun-lab-evidence'
EVIDENCE_SIZE = 64 * 1024 * 1024
EVIDENCE_PCAP_LIMIT = 60 * 1024 * 1024
EVIDENCE_HEADER_SIZE = 4096
EVIDENCE_MAGIC = b'RTLABEV1'
EVIDENCE_VERSION = 1
# Magic, version, completion flag, run ID, pcap length, SHA-256 of the pcap; zeros to the block end.
_EVIDENCE_HEADER = struct.Struct('<8sHH32sQ32s')
SERVICES = ('http', 'udp', 'dns-udp', 'dns-tcp')
PORTS = {'http': 8080, 'udp': 9000, 'dns-udp': 53, 'dns-tcp': 53, 'marker': 9100}
# Nothing listens here and no expected exchange uses it: the deliberate leak control.
CANARY_PORT = 9999
CANARY_TCP_TARGET = '203.0.113.9'
# The VPN node of the tunnel stage listens on the lab address; the HTTPS target is the routed one.
NODE_PORT = 8388
HTTPS_PORT = 443
HTTPS_KINDS = ('https-direct', 'https-tunnel')
# What the HTTPS target sees when the request came through the node: the router's own side.
EGRESS = '203.0.113.1'
# The throwaway client of the test machine listens here, on loopback only.
SOCKS_PORT = 10808
# Stage 7b2a: the lab's resolver and DoH target, both inside the routed namespace.
RESOLVER = '203.0.113.53'
DOH_ADDRESS = '203.0.113.3'
DOH_NAME = 'doh.lab.test'
DOH_PATH = '/dns-query'
DOH_CONTENT_TYPE = 'application/dns-message'
DNS_ANSWER = TARGETS[4]
DNS_TTL = 60
DNS_LOG_ENTRIES = 256
DNS_NAME_LOG = 96
# RFC 8484 allows far more; a lab query is a few dozen bytes.
DOH_BODY_LIMIT = 512
DOH_HEAD_LIMIT = 8192
DNS_TYPES = {1: 'A', 28: 'AAAA'}
HTTP_REASONS = {200: 'OK', 400: 'Bad Request', 404: 'Not Found', 405: 'Method Not Allowed',
                413: 'Payload Too Large', 415: 'Unsupported Media Type'}
LAB_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32'))

# The only traffic between the two machines that is neither a probe nor a window
# marker. Rows are (name, kind, message code, where the frame may go); a frame must
# also come from one machine and be addressed to the other or to a link-scope group.
# `arp-neighbor-poll` is the unicast request with which a stack checks that a neighbor it knows still answers (RFC 1122,
# 2.3.2.1): only the test machine sends it, only for the lab's own address, to the lab's hardware address, which is also
# the target hardware address it names.
INFRASTRUCTURE = (
    ('arp-request', 'arp', 1, 'broadcast-or-peer'),
    ('arp-neighbor-poll', 'arp', 1, 'lab-unicast'),
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

# Link events a scenario that switches the network may declare legitimate. The lab
# smoke declares none. Rows are (name, kind, what the frame must be).
ALLOWANCES = (
    ('arp-announcement', 'arp', 'broadcast naming its own address as sender and target'),
    ('arp-probe', 'arp', 'broadcast from 0.0.0.0 asking for its own address'),
    ('ipv6-dad', 'icmpv6', 'neighbor solicitation from :: to the solicited-node group of its own address'),
    ('ipv6-unspecified-rs', 'icmpv6', 'router solicitation from :: to all routers'),
    ('ipv6-link-local-echo', 'icmpv6', "echo request (128, code 0) from the test machine's link-local address to "
                                       "the lab's, or the echo reply (129, code 0) back, between the two machines"),
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


def https_exchanges(run_id, nonce_factory):
    """The two HTTPS requests of the tunnel stage: one straight to the target, one through the node."""
    result = []
    for kind in HTTPS_KINDS:
        nonce = nonce_factory()
        result.append(dict(run_id=run_id, nonce=nonce, kind=kind, family=4, protocol='tcp',
                           source=CLIENTS[4], target=TARGETS[4], port=HTTPS_PORT,
                           path='/' + run_id + '/' + nonce))
    return result


DNS_CHECK_DOH = 'dns-doh-singbox'


def dns_checks(run_id, nonce_factory):
    """The two name lookups of `lab-smoke --dns`.

    `plain` is a probe-like exchange (service `dns-plain`): a stdlib A question over UDP from the
    test machine to the resolver. `doh` is an HTTPS exchange to the target, made by a sing-box
    client that must resolve its name through the DoH target and the node first. Each name is
    `<run>.<nonce>.lab.test`, so a row of the resolver's log tells which lookup it was.
    """
    plain = dict(run_id=run_id, nonce=nonce_factory(), family=4, service='dns-plain', protocol='udp',
                 source=CLIENTS[4], target=RESOLVER, port=53)
    doh = dict(run_id=run_id, nonce=nonce_factory(), kind=DNS_CHECK_DOH, family=4, protocol='tcp',
               source=CLIENTS[4], target=TARGETS[4], port=HTTPS_PORT)
    doh['path'] = '/' + run_id + '/' + doh['nonce']
    return dict(plain=plain, doh=doh)


def dns_name(check):
    return token(check).decode('ascii')


def plain_reply_ok(check, reply):
    """Whether `reply` is the resolver's answer to the plain question: the one fixed address."""
    question = query(check)[12:]
    if len(reply) != 12 + len(question) + 16 or reply[:2] != query(check)[:2]:
        return False
    flags, questions, answers = struct.unpack_from('!HHH', reply, 2)
    return (flags & 0x800f == 0x8000 and questions == 1 and answers == 1 and reply[12:12 + len(question)] == question
            and reply[-4:] == bytes(map(int, DNS_ANSWER.split('.'))))


def https_answer(exchange):
    return b'rosetun-lab-https:' + (exchange['run_id'] + '.' + exchange['nonce']).encode('ascii')


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


def marker_run_id(guest_run_id):
    """The 32 hexadecimal digits a window marker carries, derived from the guest's run ID.

    The marker grammar wants 32 hexadecimal digits and the script in the guest knows only its
    own run ID (`YYYYMMDDTHHMMSSZ-xxxxxxxx`). Both sides compute the same digits from it;
    run-l3.sh does it with `sha256sum`, and the lab machine's run uses them as its lab ID.
    """
    return hashlib.sha256(b'rosetun-lab-run:' + guest_run_id.encode('ascii')).hexdigest()[:32]


def window_marker(run_id, index, word, label):
    """The marker that opens or closes window `index`; the index replaces the nonce of stage 6b."""
    if (word not in WINDOW_WORDS or type(index) is not int or not 0 <= index < WINDOW_LIMIT
            or not WINDOW_LABEL.fullmatch(label)):
        raise ValueError('invalid-window-marker')
    return dict(run_id=run_id, index=index, word=word, label=label, family=4, service='marker',
                protocol='udp', source=CLIENTS[4], target=TARGETS[4], port=PORTS['marker'])


def parse_window_marker(data, run_id):
    """(index, word, label) of this run's phase marker datagram, else None."""
    found = _WINDOW_MARKER.fullmatch(data)
    if found is None or found[1].decode('ascii') != run_id or int(found[2]) >= WINDOW_LIMIT:
        return None
    return int(found[2]), found[3].decode('ascii'), found[4].decode('ascii')


def marker_query(marker):
    if 'index' in marker:
        tail = '.'.join((marker['run_id'], str(marker['index']), marker['word'], marker['label']))
    else:
        tail = '.'.join((marker['run_id'], marker['nonce'], marker['word']))
    return (MARKER_PREFIX + tail).encode('ascii')


def marker_answer(marker):
    return ACK_PREFIX.encode('ascii') + marker_query(marker)


class DnsRefusal(ValueError):
    """A query the resolver answers with an error code (or not at all when `rcode` is None)."""

    def __init__(self, reason, rcode):
        super().__init__(reason)
        self.rcode = rcode


def dns_question(packet):
    """(identifier, flags, name, type, class, question bytes) of a one-question query."""
    if len(packet) < 12:
        raise DnsRefusal('short-dns-message', None)
    identifier, flags, count = struct.unpack_from('!HHH', packet)
    if flags & 0x8000:
        raise DnsRefusal('dns-response', None)
    if flags & 0x7800:
        raise DnsRefusal('dns-opcode', 4)
    if count != 1:
        raise DnsRefusal('dns-question-count', 1)
    labels, offset = [], 12
    while True:
        if offset >= len(packet):
            raise DnsRefusal('truncated-dns-question', 1)
        size = packet[offset]
        if size == 0:
            offset += 1
            break
        if size & 0xc0:
            raise DnsRefusal('compressed-dns-question', 1)
        if offset + 1 + size > len(packet):
            raise DnsRefusal('truncated-dns-question', 1)
        labels.append(packet[offset + 1:offset + 1 + size])
        offset += 1 + size
        if offset - 12 > 255:
            raise DnsRefusal('dns-name-too-long', 1)
    if offset + 4 > len(packet):
        raise DnsRefusal('truncated-dns-question', 1)
    qtype, qclass = struct.unpack_from('!HH', packet, offset)
    name = b'.'.join(labels).decode('ascii', 'replace')
    return identifier, flags, name, qtype, qclass, packet[12:offset + 4]


def dns_reply(packet):
    """(reply or None, (name, type) or None) for one query; the lab answers and recurses to nothing.

    A question of class IN gets the one fixed address, any other question an empty
    NOERROR. A message that cannot be read is answered with an error code only when its
    identifier can be echoed; a response is never answered.
    """
    try:
        identifier, flags, name, qtype, qclass, question = dns_question(packet)
    except DnsRefusal as refusal:
        if refusal.rcode is None:
            return None, None
        return packet[:2] + struct.pack('!HHHHH', 0x8000 | refusal.rcode, 0, 0, 0, 0), None
    # Recursion is neither offered (RA clear) nor done; RD is echoed as DNS asks.
    header = 0x8400 | (flags & 0x0100)
    answered = qtype == 1 and qclass == 1
    reply = struct.pack('!HHHHHH', identifier, header, 1, 1 if answered else 0, 0, 0) + question
    if answered:
        reply += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, DNS_TTL, 4) + ipaddress.ip_address(DNS_ANSWER).packed
    return reply, (name[:DNS_NAME_LOG], DNS_TYPES.get(qtype, str(qtype)))


def parse_request_head(head):
    """(method, target, headers) of an HTTP/1.1 request head without its blank line."""
    try:
        lines = head.decode('ascii').split('\r\n')
    except UnicodeDecodeError:
        raise ValueError('bad-http-request') from None
    parts = lines[0].split(' ')
    if len(parts) != 3 or parts[2] != 'HTTP/1.1' or not parts[1].startswith('/') or not parts[0].isalpha():
        raise ValueError('bad-http-request')
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(':')
        if not separator or not name or name != name.strip() or name.lower() in headers:
            raise ValueError('bad-http-request')
        headers[name.lower()] = value.strip()
    return parts[0], parts[1], headers


def doh_reply(method, target, headers, body):
    """(status, headers, body, log entry) of the DoH target for one parsed request (RFC 8484)."""
    path, _, query = target.partition('?')
    if path != DOH_PATH:
        return 404, {}, b'', None
    if method == 'POST':
        if headers.get('content-type', '').split(';')[0].strip().lower() != DOH_CONTENT_TYPE:
            return 415, {}, b'', None
        message = body
    elif method == 'GET':
        values = [part[4:] for part in query.split('&') if part.startswith('dns=')]
        if len(values) != 1 or not re.fullmatch(r'[A-Za-z0-9_-]*={0,2}', values[0]):
            return 400, {}, b'', None
        if len(values[0]) > (DOH_BODY_LIMIT + 2) // 3 * 4:
            return 413, {}, b'', None
        try:
            message = base64.urlsafe_b64decode(values[0].rstrip('=') + '=' * (-len(values[0].rstrip('=')) % 4))
        except (binascii.Error, ValueError):
            return 400, {}, b'', None
    else:
        return 405, {'allow': 'GET, POST'}, b'', None
    if len(message) > DOH_BODY_LIMIT:
        return 413, {}, b'', None
    reply, entry = dns_reply(message)
    if entry is None:
        return 400, {}, b'', None
    return 200, {'content-type': DOH_CONTENT_TYPE, 'cache-control': 'max-age=0'}, reply, entry


def http_response(status, headers, body, *, close):
    """The bytes of an HTTP/1.1 response with an exact length and an explicit connection state."""
    fields = {**headers, 'content-length': str(len(body)), 'connection': 'close' if close else 'keep-alive'}
    head = 'HTTP/1.1 %d %s\r\n' % (status, HTTP_REASONS[status])
    return (head + ''.join('%s: %s\r\n' % item for item in fields.items()) + '\r\n').encode('ascii') + body


def evidence_header(run_id, length, digest, *, complete):
    """The fixed block at the start of the evidence disk; written last, after the pcap is durable."""
    block = _EVIDENCE_HEADER.pack(EVIDENCE_MAGIC, EVIDENCE_VERSION, 1 if complete else 0,
                                  run_id.encode('ascii'), length, digest)
    return block + bytes(EVIDENCE_HEADER_SIZE - len(block))


def parse_evidence_header(block, run_id):
    """(pcap length, SHA-256 digest) of a finished run's header, else a ValueError naming the defect."""
    if len(block) != EVIDENCE_HEADER_SIZE:
        raise ValueError('evidence-truncated')
    magic, version, complete, owner, length, digest = _EVIDENCE_HEADER.unpack_from(block)
    if magic != EVIDENCE_MAGIC:
        raise ValueError('evidence-magic')
    if version != EVIDENCE_VERSION:
        raise ValueError('evidence-version')
    if owner != run_id.encode('ascii'):
        raise ValueError('evidence-run-id')
    if complete != 1:
        raise ValueError('evidence-incomplete')
    if any(block[_EVIDENCE_HEADER.size:]):
        raise ValueError('evidence-header-padding')
    if length > EVIDENCE_PCAP_LIMIT:
        raise ValueError('evidence-length')
    return length, digest


def _needle(probe, direction):
    if probe['service'] == 'dns-plain':
        # The resolver's reply is its own message, not the 6a answer; it repeats the question.
        return query(probe)[12:-4]
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
    fragment: bool = False


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


def _fragment(packet):
    """A Frame for an IP fragment whose Ethernet and IP headers can be read, else None.

    The payload of a fragment is never looked at. Fragments of the lab's exchanges do
    not exist, so one that involves the test machine is judged from these headers alone.
    """
    ethertype, ip = int.from_bytes(packet[12:14], 'big'), packet[14:]
    if ethertype == 0x0800 and len(ip) >= 20 and ip[0] >> 4 == 4 and (ip[0] & 15) >= 5 and (ip[6] & 0x3f or ip[7]):
        family, source, target = 4, ip[12:16], ip[16:20]
    elif ethertype == 0x86dd and len(ip) >= 40 and ip[0] >> 4 == 6:
        proto, start = ip[6], 40
        while proto in (0, 43, 60):
            if start + 8 > len(ip):
                return None
            proto, start = ip[start], start + (ip[start + 1] + 1) * 8
        if proto != 44:
            return None
        family, source, target = 6, ip[8:24], ip[24:40]
    else:
        return None
    return Frame(size=len(packet), dst_mac=packet[0:6].hex(':'), src_mac=packet[6:12].hex(':'), ethertype=ethertype,
                 family=family, proto=None, src=str(ipaddress.ip_address(source)), dst=str(ipaddress.ip_address(target)),
                 sport=None, dport=None, flags=None, payload=b'', arp=None, icmp=None, inner=None, fragment=True)


def _timed_records(raw, limit=CAPTURE_LIMIT):
    """Yield (capture time in seconds, frame) of a pcap, failing closed on any irregular record."""
    if not 24 <= len(raw) <= limit or raw[:24] != PCAP_HEADER:
        raise ValueError('invalid-or-overlimit-pcap')
    offset = 24
    while offset < len(raw):
        if len(raw) - offset < 16:
            raise ValueError('incomplete-pcap')
        seconds, micro, size, original = struct.unpack_from('<IIII', raw, offset)
        offset += 16
        if size != original or not 14 <= size <= 2048 or offset + size > len(raw):
            raise ValueError('truncated-pcap-frame')
        yield seconds + micro / 1e6, raw[offset:offset + size]
        offset += size


def records(raw, limit=CAPTURE_LIMIT):
    """Yield the frames of a pcap, failing closed on any irregular record."""
    for _, packet in _timed_records(raw, limit):
        yield packet


def _record_times(raw, limit):
    """The capture time of every record up to the first irregular one, by record number."""
    times = []
    try:
        for seconds, _ in _timed_records(raw, limit):
            times.append(seconds)
    except ValueError:
        pass
    return times


def frames(raw, limit=CAPTURE_LIMIT):
    packets = []
    for packet in records(raw, limit):
        frame = parse(packet)
        if frame.proto in (6, 17):
            packets.append((frame.family, 'tcp' if frame.proto == 6 else 'udp', frame.src, frame.dst,
                            frame.sport, frame.dport, frame.payload))
    return packets


def _clean(health):
    return (type(health) is dict and health.get('error') is False
            and type(health.get('dropped')) is int and health['dropped'] == 0
            and health.get('finished') is True)


def qualify(expected, replies, logs, capture, ready, health, limit=CAPTURE_LIMIT):
    result = dict(ipv4='UNVERIFIED', ipv6='UNVERIFIED', services='UNVERIFIED',
                  observer='UNVERIFIED', evidence='UNVERIFIED', qualified=False)
    packets = frames(capture, limit)
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
            elif destination == 'lab-unicast':
                allowed = sender == 'test' and tha == frame.dst_mac == MACS['lab']
            else:
                allowed = tha == '00:00:00:00:00:00' and frame.dst_mac in (BROADCAST, MACS[peer])
        elif kind == 'icmpv6' and frame.family == 6 and frame.icmp is not None and frame.icmp[0] == code:
            allowed = _icmpv6_allowed(frame, sender, peer, destination)
        else:
            continue
        if allowed:
            return True
    return False


def _allowance(frame, names):
    """Name of the declared allowance a frame matches, else None."""
    sender = next((role for role, mac in MACS.items() if mac == frame.src_mac), None)
    if sender is None:
        return None
    own4, own6 = ENDPOINTS[sender]
    if frame.family == 6 and frame.proto == 58 and frame.icmp is not None and not frame.fragment:
        # Only the test machine asks and only the lab answers, each from its own link-local address to the other's.
        peer = 'lab' if sender == 'test' else 'test'
        kind = {'test': 128, 'lab': 129}[sender]
        if (frame.icmp == (kind, 0) and (frame.src, frame.dst) == (LINK_LOCALS[sender], LINK_LOCALS[peer])
                and frame.dst_mac == MACS[peer]):
            return 'ipv6-link-local-echo' if 'ipv6-link-local-echo' in names else None
    if frame.arp is not None:
        op, sha, spa, tha, tpa = frame.arp
        if sha != frame.src_mac or frame.dst_mac != BROADCAST:
            return None
        if op in (1, 2) and spa == tpa == own4 and tha in ('00:00:00:00:00:00', sha):
            return 'arp-announcement' if 'arp-announcement' in names else None
        if op == 1 and spa == '0.0.0.0' and tpa == own4 and tha == '00:00:00:00:00:00':
            return 'arp-probe' if 'arp-probe' in names else None
    elif frame.family == 6 and frame.icmp is not None and frame.src == '::':
        if frame.icmp[0] == 133 and frame.dst == 'ff02::2' and frame.dst_mac == '33:33:00:00:00:02':
            return 'ipv6-unspecified-rs' if 'ipv6-unspecified-rs' in names else None
        if frame.icmp[0] == 135 and len(frame.payload) >= 16:
            neighbor = ipaddress.ip_address(frame.payload[:16])
            group = ipaddress.ip_address(int(SOLICITED_NODE.network_address) | int(neighbor) & 0xffffff)
            if ((str(neighbor) == own6 or neighbor in LINK_LOCAL) and frame.dst == str(group)
                    and frame.dst_mac == '33:33:' + group.packed[-4:].hex(':')):
                return 'ipv6-dad' if 'ipv6-dad' in names else None
    return None


def _tunnel_port(port):
    if (type(port) is not int or not 1 <= port <= 65535 or port == HTTPS_PORT
            or port == CANARY_PORT or port in PORTS.values()):
        raise ValueError('invalid-tunnel-port')
    return port


def _tunnel_frame(frame, port):
    """TCP between the test machine and the lab's own address on the node port, either way."""
    if frame.family != 4 or frame.proto != 6:
        return False
    return ((frame.src_mac, frame.dst_mac, frame.src, frame.dst, frame.dport)
            == (MACS['test'], MACS['lab'], CLIENTS[4], GATEWAYS[4], port)
            or (frame.src_mac, frame.dst_mac, frame.src, frame.dst, frame.sport)
            == (MACS['lab'], MACS['test'], GATEWAYS[4], CLIENTS[4], port))


def direct_connection(https):
    """Client port of the https-direct connection, or None unless helper and target log agree.

    The helper of the test machine reports the port it used; the target's own log must
    hold exactly one request for the exchange, from the test machine, from that port.
    """
    if type(https) is not dict:
        return None
    exchange, reported, log = https.get('direct'), https.get('client_port'), https.get('log')
    if (type(exchange) is not dict or type(reported) is not int or type(reported) is bool
            or not 0 < reported < 65536 or type(log) is not list):
        return None
    rows = [row for row in log if type(row) is dict and row.get('path') == exchange.get('path')]
    if (len(rows) != 1 or rows[0].get('source') != exchange.get('source')
            or rows[0].get('port') != reported):
        return None
    return reported


def _direct_frame(frame, client_port):
    """A frame of the one https-direct connection, identified by its four-tuple (TLS is opaque)."""
    if frame.family != 4 or frame.proto != 6:
        return False
    return ((frame.src_mac, frame.dst_mac, frame.src, frame.dst, frame.sport, frame.dport)
            == (MACS['test'], MACS['lab'], CLIENTS[4], TARGETS[4], client_port, HTTPS_PORT)
            or (frame.src_mac, frame.dst_mac, frame.src, frame.dst, frame.sport, frame.dport)
            == (MACS['lab'], MACS['test'], TARGETS[4], CLIENTS[4], HTTPS_PORT, client_port))


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
    elif frame.fragment:
        protocol, addresses = 'fragment', (frame.src, frame.dst)
    elif frame.family is not None:
        protocol, addresses = PROTOCOL_NAMES.get(frame.proto, 'ip-%d' % frame.proto), (frame.src, frame.dst)
    else:
        protocol, addresses = None, (frame.src_mac, frame.dst_mac)
    ports = (frame.sport, frame.dport) if frame.sport is not None else None
    return ('0x%04x' % frame.ethertype, frame.family, protocol, addresses, ports, frame.size)


def _declared(allowances):
    names = frozenset(allowances)
    if not names <= {row[0] for row in ALLOWANCES}:
        raise ValueError('unknown-allowance')
    return names


def _parse_capture(raw, limit):
    """(parsed [(record, Frame)], unparsed [(record, reason)], pcap problem or None)."""
    parsed, unparsed, problem = [], [], None
    try:
        for index, packet in enumerate(records(raw, limit)):
            fragment = _fragment(packet)
            if fragment is not None and _involves_test(fragment):
                parsed.append((index, fragment))
                continue
            try:
                parsed.append((index, parse(packet)))
            except ValueError as error:
                unparsed.append((index, str(error)))
    except ValueError as error:
        problem = str(error)
    return parsed, unparsed, problem


def _probe_matcher(frames, expected, direct):
    """A predicate for the frames of the expected exchanges and of the one direct connection."""
    # A TCP segment without data belongs to a probe only on a connection that carried it.
    connections = [set() for _ in expected]
    for frame in frames:
        for position, p in enumerate(expected):
            direction = _direction(frame, p)
            if p['protocol'] == 'tcp' and direction and frame.payload and _needle(p, direction) in frame.payload:
                connections[position].add(frame.sport if direction == 'request' else frame.dport)

    def is_probe(frame):
        if direct is not None and _direct_frame(frame, direct):
            return True
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
    return is_probe


def classify(raw, expected, window, allowances=(), tunnel_port=None, https=None, limit=CAPTURE_LIMIT):
    """Put every captured frame into exactly one category and check the window markers.

    `allowances` names link events (see ALLOWANCES) that count as `allowed` instead of
    `unexpected`; the default is none, and an unknown name is an error before any parsing.

    `tunnel_port` turns on the category `tunnel`: TCP between the test machine and the
    lab address on that port, never parsed further. `https` (see direct_connection)
    makes the one https-direct connection a probe; without agreement between the
    helper and the target's log its frames stay `unexpected`.

    Frames that cannot be parsed are counted apart and make the result unverified. A
    truncated record ends the walk, but frames already seen keep their category.
    """
    names = _declared(allowances)
    if tunnel_port is not None:
        _tunnel_port(tunnel_port)
    direct = direct_connection(https)
    if [m['word'] for m in window] != ['open', 'close']:
        raise ValueError('invalid-window')
    parsed, unparsed, problem = _parse_capture(raw, limit)
    is_probe = _probe_matcher([frame for _, frame in parsed], expected, direct)
    counts = dict(probe=0, marker=0, infrastructure=0, unexpected=0, foreign=0, unparsed=len(unparsed))
    if names:
        counts['allowed'] = dict.fromkeys(sorted(names), 0)
    if tunnel_port is not None:
        counts['tunnel'] = 0
    unexpected, canary = [], dict(udp=0, tcp=0, other=0)
    probe_at, seen = [], {(m['word'], d): [] for m in window for d in ('request', 'response')}
    def count_unexpected(frame):
        counts['unexpected'] += 1
        if len(unexpected) < UNEXPECTED_LIMIT:
            unexpected.append(_describe(frame))
        canary[_canary_flow(frame) or 'other'] += 1

    for index, frame in parsed:
        if frame.fragment:
            count_unexpected(frame)
        elif is_probe(frame):
            counts['probe'] += 1
            # The last segments of a closing connection may follow the closing marker.
            if frame.proto != 6 or frame.payload or frame.flags & 0x02:
                probe_at.append(index)
        elif hit := _marker_hit(frame, window):
            counts['marker'] += 1
            seen[hit].append(index)
        elif _infrastructure(frame):
            counts['infrastructure'] += 1
        elif tunnel_port is not None and _tunnel_frame(frame, tunnel_port):
            counts['tunnel'] += 1
        elif allowed := _allowance(frame, names):
            counts['allowed'][allowed] += 1
        elif _involves_test(frame):
            count_unexpected(frame)
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
        unverified.append('unparsed-frame:' + unparsed[0][1])
    if len(raw) + 16 + 2048 > limit:
        unverified.append('capture-limit-reached')
    if not found:
        unverified.append('window-markers-missing-or-repeated')
    elif not ordered:
        unverified.append('window-markers-out-of-order')
    return dict(categories=counts, unexpected=unexpected, canary=canary,
                window=dict(markers_found=found, ordered=ordered), unverified=unverified)


def _window_specs(windows_expected):
    """The phase labels of the windows the controller expects, in order; only NONE is expected."""
    if type(windows_expected) is not list or not 1 <= len(windows_expected) <= WINDOW_LIMIT:
        raise ValueError('invalid-windows')
    labels = []
    for spec in windows_expected:
        if type(spec) is not dict or not set(spec) <= {'label', 'expected'} or type(spec.get('label')) is not str:
            raise ValueError('invalid-windows')
        if not WINDOW_LABEL.fullmatch(spec['label']):
            raise ValueError('invalid-windows')
        if spec.get('expected', 'NONE') != 'NONE':
            raise ValueError('unsupported-window-expectation')
        labels.append(spec['label'])
    return labels


def _phase_hit(frame, run):
    """(direction, index, word, label) when the frame is this run's phase marker or its answer."""
    if frame.family != 4 or frame.proto != 17:
        return None
    if ((frame.src_mac, frame.dst_mac, frame.src, frame.dst, frame.dport)
            == (MACS['test'], MACS['lab'], CLIENTS[4], TARGETS[4], PORTS['marker'])):
        direction, data = 'request', frame.payload
    elif ((frame.src_mac, frame.dst_mac, frame.src, frame.dst, frame.sport)
            == (MACS['lab'], MACS['test'], TARGETS[4], CLIENTS[4], PORTS['marker'])):
        if not frame.payload.startswith(ACK_PREFIX.encode('ascii')):
            return None
        direction, data = 'response', frame.payload[len(ACK_PREFIX):]
    else:
        return None
    found = parse_window_marker(data, run)
    return (direction, *found) if found else None


def _category(frame, is_probe, names, tunnel_port):
    """The category of a frame that is no marker; an allowance is ('allowed', name)."""
    if frame.fragment:
        return 'unexpected'
    if is_probe(frame):
        return 'probe'
    if _infrastructure(frame):
        return 'infrastructure'
    if tunnel_port is not None and _tunnel_frame(frame, tunnel_port):
        return 'tunnel'
    if allowed := _allowance(frame, names):
        return 'allowed', allowed
    return 'unexpected' if _involves_test(frame) else 'foreign'


FLOW_LIMIT = 64
TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10


def _endpoint(address, port):
    return f'[{address}]:{port}' if ':' in address else f'{address}:{port}'


def _flow_kind(peer, tunnel_port):
    """`node` for the node's own port, `target` for the HTTPS target, else `other`."""
    address, port = peer
    if tunnel_port is not None and port == tunnel_port and address in (GATEWAYS[4], GATEWAYS[6]):
        return 'node'
    if port == HTTPS_PORT and address in (TARGETS[4], TARGETS[6]):
        return 'target'
    return 'other'


class _Flows:
    """The TCP connections of the test machine seen in one window, by four-tuple.

    Only headers are read: frame and payload byte counts per direction, the capture time of the first
    and the last frame (milliseconds after the opening marker) and which of SYN, SYN-ACK, FIN and RST were
    seen, and for FIN and RST from which side. At most `FLOW_LIMIT` connections are kept; the rest are counted.
    """

    def __init__(self, tunnel_port):
        self.tunnel_port, self.start = tunnel_port, None
        self.table, self.omitted = {}, set()

    def add(self, frame, seconds):
        tests = (CLIENTS[4], CLIENTS[6])
        if frame.src in tests:
            outbound, client, peer = True, (frame.src, frame.sport), (frame.dst, frame.dport)
        elif frame.dst in tests:
            outbound, client, peer = False, (frame.dst, frame.dport), (frame.src, frame.sport)
        else:
            return
        key = (client, peer)
        row = self.table.get(key)
        if row is None:
            if len(self.table) >= FLOW_LIMIT:
                self.omitted.add(key)
                return
            row = self.table[key] = dict(
                kind=_flow_kind(peer, self.tunnel_port), client=_endpoint(*client), server=_endpoint(*peer),
                frames_out=0, frames_back=0, bytes_out=0, bytes_back=0, first_ms=None, last_ms=None,
                syn=False, syn_ack=False, fin=[], rst=[])
        side = 'out' if outbound else 'back'
        row['frames_' + side] += 1
        row['bytes_' + side] += len(frame.payload)
        if seconds is not None and self.start is not None:
            at = round((seconds - self.start) * 1000)
            row['first_ms'] = at if row['first_ms'] is None else row['first_ms']
            row['last_ms'] = at
        flags = frame.flags or 0
        if flags & TCP_SYN:
            row['syn_ack' if flags & TCP_ACK else 'syn'] = True
        for name, bit in (('fin', TCP_FIN), ('rst', TCP_RST)):
            if flags & bit and side not in row[name]:
                row[name].append(side)

    def document(self):
        return dict(connections=list(self.table.values()), omitted=len(self.omitted))


# What a flow of unexpected frames is (stage 7c3): a TCP connection to the HTTPS target, a UDP exchange with the
# lab resolver on port 53, the test machine resolving an address of its own network that is not the lab's (stage
# 7e), or anything else. The controller compares them with what it expects of a window.
DIRECT_KINDS = ('target', 'resolver', 'neighbor', 'other')
ZERO_MAC = '00:00:00:00:00:00'


def _direct_kind(protocol, peer):
    address, port = peer
    if protocol == 'tcp' and port == HTTPS_PORT and address in (TARGETS[4], TARGETS[6]):
        return 'target'
    if protocol == 'udp' and port == PORTS['dns-udp'] and address == RESOLVER:
        return 'resolver'
    return 'other'


class _Direct:
    """The `unexpected` frames of one window, by flow, so the controller can hold them against an expectation.

    A flow is a TCP connection or a UDP exchange of the test machine, by protocol and four-tuple, with the frames
    each way. `opened` says the test machine started it inside the window: a SYN without ACK that it sent, or for
    UDP an outbound first frame. A retransmission stays in its flow. Two more kinds of frame belong to a flow
    (stage 7e): an ARP request the test machine broadcasts from its own address for another address than the lab's
    is the flow `arp` to that address (`neighbor`, opened, every request again one more frame out; an answer is no
    part of it), and a destination
    unreachable error the lab's router sends the test machine about a datagram of a UDP flow already in the window
    is a frame back of that flow. Every other unexpected frame (another ARP frame, ICMP, a fragment, a frame that
    names no address of the test machine) is counted in `other_frames`, and one beyond `FLOW_LIMIT` flows in
    `omitted_frames`, so the three account for every unexpected frame of the window.
    """

    def __init__(self):
        self.table, self.other, self.omitted = {}, 0, 0

    def _neighbor_request(self, frame):
        """The address a broadcast ARP request of the test machine, from its own address, asks for; else None."""
        if frame.arp is None or frame.fragment:
            return None
        op, sha, spa, tha, tpa = frame.arp
        if ((op, sha, spa, tha, frame.src_mac, frame.dst_mac)
                == (1, MACS['test'], CLIENTS[4], ZERO_MAC, MACS['test'], BROADCAST) and tpa != spa):
            return tpa
        return None

    def _unreachable_flow(self, frame):
        """The UDP flow of this window an ICMP destination unreachable from the lab's router is about; else None."""
        if (frame.fragment or frame.family != 4 or frame.proto != 1 or frame.icmp is None or frame.icmp[0] != 3
                or frame.inner is None or (frame.src_mac, frame.dst_mac, frame.src, frame.dst)
                != (MACS['lab'], MACS['test'], GATEWAYS[4], CLIENTS[4])):
            return None
        source, target, proto, sport, dport = frame.inner
        if proto != 17 or source != CLIENTS[4] or sport is None:
            return None
        return self.table.get(('udp', (source, sport), (target, dport)))

    def add(self, frame):
        asked = self._neighbor_request(frame)
        if asked is not None:
            key = ('arp', (CLIENTS[4], None), (asked, None))
            row = self.table.get(key)
            if row is None:
                if len(self.table) >= FLOW_LIMIT:
                    self.omitted += 1
                    return
                row = self.table[key] = dict(protocol='arp', kind='neighbor', client=CLIENTS[4], server=asked,
                                             frames_out=0, frames_back=0, opened=True)
            row['frames_out'] += 1
            return
        flow = self._unreachable_flow(frame)
        if flow is not None:
            flow['frames_back'] += 1
            return
        protocol = {6: 'tcp', 17: 'udp'}.get(frame.proto)
        tests = (CLIENTS[4], CLIENTS[6])
        if frame.fragment or frame.arp is not None or protocol is None or frame.sport is None:
            self.other += 1
            return
        if frame.src in tests:
            outbound, client, peer = True, (frame.src, frame.sport), (frame.dst, frame.dport)
        elif frame.dst in tests:
            outbound, client, peer = False, (frame.dst, frame.dport), (frame.src, frame.sport)
        else:
            self.other += 1
            return
        key = (protocol, client, peer)
        row = self.table.get(key)
        if row is None:
            if len(self.table) >= FLOW_LIMIT:
                self.omitted += 1
                return
            row = self.table[key] = dict(protocol=protocol, kind=_direct_kind(protocol, peer),
                                         client=_endpoint(*client), server=_endpoint(*peer), frames_out=0,
                                         frames_back=0, opened=protocol == 'udp' and outbound)
        row['frames_out' if outbound else 'frames_back'] += 1
        if protocol == 'tcp' and outbound and (frame.flags or 0) & (TCP_SYN | TCP_ACK) == TCP_SYN:
            row['opened'] = True

    def document(self):
        return dict(flows=list(self.table.values()), other_frames=self.other, omitted_frames=self.omitted)


def _no_direct():
    return dict(flows=[], other_frames=0, omitted_frames=0)


# The link between the lab node and the routed namespace, and the most flows kept of what crosses it.
ROUTE_INTERFACE = 'rt-route'
ROUTE_FLOW_LIMIT = 512
# The bound of `route-flows.json`: 512 rows of at most about 400 bytes each, with room to spare.
ROUTE_FLOWS_LIMIT = 256 * 1024


def route_header(packet):
    """(protocol, source, target, TCP flags, payload size) of a TCP or UDP packet of the routed link, else None.

    The payload size comes from the length fields of the IP header and not from the bytes captured, since
    a veth pair may hand over segments far larger than a frame. A fragment, any other protocol and a packet
    whose headers do not fit are None.
    """
    if len(packet) < 14:
        return None
    ethertype, ip = int.from_bytes(packet[12:14], 'big'), packet[14:]
    if ethertype == 0x0800 and len(ip) >= 20 and ip[0] >> 4 == 4 and (ip[0] & 15) >= 5:
        start, proto = (ip[0] & 15) * 4, ip[9]
        if ip[6] & 0x3f or ip[7]:
            return None
        span = (int.from_bytes(ip[2:4], 'big') or len(ip)) - start
        source, target = ip[12:16], ip[16:20]
    elif ethertype == 0x86dd and len(ip) >= 40 and ip[0] >> 4 == 6:
        proto, start = ip[6], 40
        while proto in (0, 43, 60):
            if start + 8 > len(ip):
                return None
            proto, start = ip[start], start + (ip[start + 1] + 1) * 8
        if proto == 44:
            return None
        length = int.from_bytes(ip[4:6], 'big')
        span = (length + 40 if length else len(ip)) - start
        source, target = ip[8:24], ip[24:40]
    else:
        return None
    if proto not in (6, 17):
        return None
    data = ip[start:]
    minimum = 20 if proto == 6 else 8
    if len(data) < minimum:
        return None
    header = (data[12] >> 4) * 4 if proto == 6 else 8
    if header < minimum or header > len(data) or span < header:
        return None
    return (proto, (str(ipaddress.ip_address(source)), int.from_bytes(data[0:2], 'big')),
            (str(ipaddress.ip_address(target)), int.from_bytes(data[2:4], 'big')),
            data[13] if proto == 6 else 0, span - header)


class RouteFlows:
    """The TCP and UDP flows that cross the link between the node and the routed namespace, by four-tuple.

    A diagnostic count and nothing else: it judges no leak and feeds no verdict. Every flow has the frames and
    the payload bytes each way, the time of its first and its last packet by the clock of the machine that
    counts (seconds since the epoch, three decimals) and which of SYN, SYN-ACK, FIN and RST were seen. The side
    that sent the first packet is the client, except that a SYN-ACK seen first names the other side. At most
    `limit` flows are kept; the packets of any other are counted in `omitted_frames`.
    """

    def __init__(self, limit=ROUTE_FLOW_LIMIT):
        self.limit, self.table = limit, {}
        self.omitted_frames = self.other_frames = self.unparsed_frames = 0

    def add(self, packet, now):
        try:
            header = route_header(packet)
        except (ValueError, IndexError):
            self.unparsed_frames += 1
            return
        if header is None:
            self.other_frames += 1
            return
        proto, source, target, flags, size = header
        side = 'out'
        row = self.table.get((proto, source, target))
        if row is None:
            row, side = self.table.get((proto, target, source)), 'back'
        if row is None:
            if len(self.table) >= self.limit:
                self.omitted_frames += 1
                return
            side = 'back' if proto == 6 and flags & TCP_SYN and flags & TCP_ACK else 'out'
            client, server = (target, source) if side == 'back' else (source, target)
            row = self.table[(proto, client, server)] = dict(
                proto='tcp' if proto == 6 else 'udp', client=_endpoint(*client), server=_endpoint(*server),
                frames_out=0, frames_back=0, bytes_out=0, bytes_back=0, first_at=round(now, 3),
                last_at=round(now, 3), syn=False, syn_ack=False, fin=[], rst=[])
        row['frames_' + side] += 1
        row['bytes_' + side] += size
        row['last_at'] = round(now, 3)
        if proto == 6:
            if flags & TCP_SYN:
                row['syn_ack' if flags & TCP_ACK else 'syn'] = True
            for name, bit in (('fin', TCP_FIN), ('rst', TCP_RST)):
                if flags & bit and side not in row[name]:
                    row[name].append(side)

    def document(self, *, error=None, dropped=None):
        """What `route-flows.json` holds. `error` is the reason counting stopped early; `dropped`, the kernel's drops."""
        return dict(flows=list(self.table.values()), omitted_frames=self.omitted_frames,
                    other_frames=self.other_frames, unparsed_frames=self.unparsed_frames,
                    error=error, dropped=dropped)


def _window_clock(row, times):
    """When the lab machine captured the request that opened the window and the one that closed it.

    Seconds since the epoch by the clock of the lab machine, which stamps every record of the capture;
    None for one that is missing, repeated or has no time. The test machine's own clock is not in the capture.
    """
    seen = row.get('seen') or {}
    clock = {}
    for name, word in (('open_at', 'open'), ('close_at', 'close')):
        positions = seen.get((word, 'request'), [])
        clock[name] = times[positions[0]] if len(positions) == 1 and positions[0] < len(times) else None
    return clock


def _window_counts(names, tunnel_port, poll=False):
    counts = dict(probe=0, marker=0, infrastructure=0, unexpected=0, foreign=0, unparsed=0)
    if names:
        counts['allowed'] = dict.fromkeys(sorted(names), 0)
    if tunnel_port is not None:
        counts['tunnel'] = 0
    if poll:
        counts[POLL_CATEGORY] = 0
    return counts


# Stage 8d: the lab's SSH poller of Linux L4 (`inbound.lan-open` waits for a new connection from the host node, which
# in the lab is the lab machine). The category `inbound-poll` is exactly one connection pattern: TCP from the lab's
# address to the test machine's port 22, whenever it is sent (a SYN nobody answers is the poller's own business), and
# the test machine's segments from port 22 back to a port the poller used, from the moment its local network went on.
# A reply before that moment, or to any other port, is an unexpected frame like any other. Both ends are fixed by the
# MACs and the addresses of the lab, so nothing wider than the poller's four-tuple is let through.
POLL_CATEGORY = 'inbound-poll'
POLL_PORT = 22


def _poll_direction(frame):
    """'request' for a TCP segment of the lab to the test machine's sshd, 'reply' for one of it back, else None."""
    if frame.family != 4 or frame.proto != 6 or frame.fragment or frame.arp is not None:
        return None
    if ((frame.src, frame.dst, frame.dport) == (GATEWAYS[4], CLIENTS[4], POLL_PORT)
            and (frame.src_mac, frame.dst_mac) == (MACS['lab'], MACS['test'])):
        return 'request'
    if ((frame.src, frame.dst, frame.sport) == (CLIENTS[4], GATEWAYS[4], POLL_PORT)
            and (frame.src_mac, frame.dst_mac) == (MACS['test'], MACS['lab'])):
        return 'reply'
    return None


def _poll_ports(frames):
    """The source ports the lab's poller used, from the segments it sent to the test machine's sshd."""
    return {frame.sport for frame in frames if _poll_direction(frame) == 'request'}


def _count(counts, category, frame, listing, unexpected_key):
    if category == 'unexpected':
        counts[unexpected_key] += 1
        if len(listing) < UNEXPECTED_LIMIT:
            listing.append(_describe(frame))
    elif type(category) is tuple:
        counts['allowed'][category[1]] += 1
    else:
        counts[category] += 1


def _window_health_reasons(health, ready, served):
    reasons = []
    if ready is not True:
        reasons.append('observer-not-ready')
    if not _clean(health):
        reasons.append('observer-health')
    rows = health.get('markers') if type(health) is dict else None
    logged = None
    if type(rows) is list and all(type(row) is dict for row in rows):
        logged = [(row.get('index'), row.get('word'), row.get('label')) for row in rows]
    # What the lab machine says it served must be what the wire shows it was asked.
    if logged != served:
        reasons.append('marker-log-mismatch')
    times = None
    if logged is not None:
        times = [health.get('capture_started'), *[row.get('at') for row in rows], health.get('capture_ended')]
    if times is None or not all(type(t) in (int, float) and math.isfinite(t) for t in times):
        reasons.append('capture-window-unrecorded')
    elif times != sorted(times):
        reasons.append('capture-window-inconsistent')
    return reasons


def _required_labels(required_labels):
    """The labels that must have a window when the windows are found in the capture."""
    if (type(required_labels) not in (list, tuple) or len(set(required_labels)) != len(required_labels)
            or not all(type(label) is str and WINDOW_LABEL.fullmatch(label) for label in required_labels)):
        raise ValueError('invalid-windows')
    return list(required_labels)


def _window_allowances(window_allowances, found_mode):
    """{label: names}: allowances declared for the windows with that label only, when the windows are found."""
    if not window_allowances:
        return {}
    if not found_mode or type(window_allowances) is not dict:
        raise ValueError('invalid-windows')
    declared = {}
    for label, names in window_allowances.items():
        if type(label) is not str or not WINDOW_LABEL.fullmatch(label) or type(names) not in (list, tuple):
            raise ValueError('invalid-windows')
        declared[label] = _declared(names)
    return declared


def classify_windows(raw, run, windows_expected, *, health, ready, allowances=(), tunnel_port=None,
                     https=None, probes=(), limit=CAPTURE_LIMIT, required_labels=(), flows=False,
                     window_allowances=None, inbound_poll=None):
    """Split one capture into phase windows and give every expected window its own leak verdict.

    `windows_expected` lists, in order, the windows the controller expects: dicts with the
    `label` of the phase and `expected`, which may only be `NONE` here. `allowances`,
    `tunnel_port` and `https` are those of the whole run; `probes` is the list of stage 6a
    exchanges and is normally empty.

    A window is the span from its opening marker to its closing marker. A frame inside it is
    judged by the rules of stage 6b: any `unexpected` frame makes the window `DETECTED`. A
    frame outside every window is only counted, in `outside_window`, and changes no verdict.
    `NONE` needs both markers asked and answered once each in order, the indexes in sequence
    from zero without a gap, the label the controller expects, a whole capture and a clean
    observer. Anything else is `UNVERIFIED`; a seen leak stays `DETECTED`. After the first
    marker out of sequence (an index repeated, skipped or reversed, an opening inside an open
    window, a closing without its opening) no later window can be `NONE`.

    With `windows_expected=None` the windows are found in the capture instead: window `n` is
    the one whose markers carry index `n`, its label the one its markers name (a label may
    repeat), and any number of windows is accepted, so one more session than the controller
    guessed spoils nothing. The rules above are otherwise the same, each window by itself.
    `required_labels` are the labels of the stage's group: each needs at least one window, and
    one without any is listed in `missing_labels` for the controller to answer for the
    scenarios of that label only. Every row says whether its label is in the group.

    With `flows` every window row also has `flows`: the TCP connections of the test machine inside
    it (`_Flows`), from the headers of the frames already captured, and `direct`: its `unexpected` frames by
    flow (`_Direct`). Neither changes the verdict here; the controller holds `direct` against what it expects.

    `window_allowances` maps a label to allowance names that hold, beside `allowances`, inside the windows
    whose markers name that label and nowhere else (found mode only); their counts are in that window's
    `categories.allowed`.

    `inbound_poll` turns on the category `inbound-poll` (see POLL_CATEGORY): a dict with `replies_from`, the capture
    time in seconds from which the test machine's answers to the poller are admitted, or None for never. Without it
    the poller's frames are unexpected frames, as for every other suite. Poller frames are never part of `flows`.
    """
    found_mode = windows_expected is None
    if found_mode:
        required = _required_labels(required_labels)
        labels = None
    else:
        if required_labels:
            raise ValueError('invalid-windows')
        required = []
        labels = _window_specs(windows_expected)
    names = _declared(allowances)
    by_label = _window_allowances(window_allowances, found_mode)
    if tunnel_port is not None:
        _tunnel_port(tunnel_port)
    parsed, unparsed, problem = _parse_capture(raw, limit)
    is_probe = _probe_matcher([frame for _, frame in parsed], probes, direct_connection(https))
    poll = inbound_poll is not None
    if poll and (type(inbound_poll) is not dict or set(inbound_poll) != {'replies_from'}
                 or not (inbound_poll['replies_from'] is None or (
                     type(inbound_poll['replies_from']) in (int, float) and math.isfinite(inbound_poll['replies_from'])))):
        raise ValueError('invalid-windows')
    times = _record_times(raw, limit) if flows or poll else []
    polled = _poll_ports(frame for _, frame in parsed) if poll else set()
    windows, requests = {}, []
    outside = _window_counts(names, tunnel_port, poll)
    outside['outside-window'] = outside.pop('unexpected')
    outside_frames = []
    current, broken, next_index = None, None, 0

    def window(index, label):
        if index not in windows:
            own = names | by_label.get(label, frozenset())
            windows[index] = dict(categories=_window_counts(own, tunnel_port, poll), names=own, unexpected=[], reasons=[],
                                  labels=[], first=None, last=None, flows=_Flows(tunnel_port) if flows else None,
                                  direct=_Direct() if flows else None,
                                  seen={(word, kind): [] for word in WINDOW_WORDS for kind in ('request', 'response')})
        return windows[index]

    for position, item in sorted([*parsed, *unparsed], key=lambda row: row[0]):
        if type(item) is str:
            if current is None:
                outside['unparsed'] += 1
            else:
                windows[current]['categories']['unparsed'] += 1
                windows[current]['reasons'].append('unparsed-frame:' + item)
            continue
        hit = _phase_hit(item, run)
        if hit is not None:
            direction, index, word, label = hit
            row = window(index, label)
            row['categories']['marker'] += 1
            row['labels'].append(label)
            row['seen'][(word, direction)].append(position)
            if row['flows'] is not None and row['first'] is None and position < len(times):
                row['flows'].start = times[position]
            row['first'] = position if row['first'] is None else row['first']
            row['last'] = position
            if direction == 'request':
                requests.append((index, word, label))
                fault = None
                if word == 'open':
                    if current is not None:
                        fault = 'open-inside-open-window'
                    elif index != next_index:
                        fault = 'window-index-out-of-sequence'
                    current = index
                else:
                    if current is None:
                        fault = 'close-without-open'
                    elif index != current:
                        fault = 'close-index-mismatch'
                    else:
                        next_index = index + 1
                    current = None
                if fault is not None and broken is None:
                    broken = (fault, position)
            continue
        direction = _poll_direction(item) if poll else None
        if direction == 'request' or (direction == 'reply' and item.dport in polled
                                      and inbound_poll['replies_from'] is not None and position < len(times)
                                      and times[position] >= inbound_poll['replies_from']):
            category = POLL_CATEGORY
        else:
            category = _category(item, is_probe, names if current is None else windows[current]['names'],
                                 tunnel_port)
        if current is None:
            _count(outside, category, item, outside_frames, 'outside-window')
        else:
            _count(windows[current]['categories'], category, item, windows[current]['unexpected'], 'unexpected')
            if flows and item.proto == 6 and not item.fragment and category != POLL_CATEGORY:
                windows[current]['flows'].add(item, times[position] if position < len(times) else None)
            if flows and category == 'unexpected':
                windows[current]['direct'].add(item)
    shared = []
    if problem:
        shared.append('invalid-pcap:' + problem)
    if len(raw) + 16 + 2048 > limit:
        shared.append('capture-limit-reached')
    shared += _window_health_reasons(health, ready, requests)
    if found_mode:
        # A gap in the indexes leaves a window nobody can name; the sequence fault covers what follows.
        labels = [windows[index]['labels'][0] if index in windows else None
                  for index in range(max(windows) + 1 if windows else 0)]
        extra = []
    else:
        extra = sorted(index for index in windows if index >= len(labels))
    if extra:
        shared.append('window-count-mismatch')
    results = []
    for index, label in enumerate(labels):
        row, reasons = windows.get(index), []
        if row is None:
            reasons.append('window-missing')
            row = dict(categories=_window_counts(names, tunnel_port, poll), unexpected=[], reasons=[])
        else:
            seen = row['seen']
            if any(len(positions) != 1 for positions in seen.values()):
                reasons.append('window-markers-missing-or-repeated')
            elif not (seen[('open', 'request')][0] < seen[('open', 'response')][0]
                      < seen[('close', 'request')][0] < seen[('close', 'response')][0]):
                reasons.append('window-markers-out-of-order')
            if any(seen_label != label for seen_label in row['labels']):
                reasons.append('window-label-mismatch')
            if broken is not None and row['last'] >= broken[1]:
                reasons.append(broken[0])
        reasons += row['reasons'] + shared
        if row['categories']['unexpected']:
            leak, reason = 'DETECTED', 'unexpected-frames'
        elif reasons:
            leak, reason = 'UNVERIFIED', reasons[0]
        else:
            leak, reason = 'NONE', 'clean'
        results.append(dict(index=index, label=label, expected='NONE', leak=leak, leak_reason=reason,
                            observer_reasons=reasons, categories=row['categories'], unexpected=row['unexpected'],
                            **({'flows': row['flows'].document() if row.get('flows') else dict(connections=[], omitted=0),
                                'direct': row['direct'].document() if row.get('direct') else _no_direct(),
                                'clock': _window_clock(row, times)} if flows else {})))
    answer = dict(windows=results, outside_window=dict(categories=outside, frames=outside_frames),
                  extra_windows=extra, observer_reasons=shared)
    if found_mode:
        for row in results:
            row['in_group'] = row['label'] in required
        answer.update(windows_found=True, required_labels=required,
                      missing_labels=[label for label in required if label not in {row['label'] for row in results}])
    return answer


def classified_frames(raw, run, *, probes=(), https=None, tunnel_port=None, allowances=(), limit=CAPTURE_LIMIT):
    """Every frame of a capture with its time, the window it fell in and the category the classifier gives it.

    Returns `(rows, unparsed, problem, labels)`: `labels` maps the index of each window the markers name to its label (the
    first one named, as `classify_windows` takes it); a row is `(record number, capture time in seconds, Frame, window index or
    None, category)`, the category being one of those of `classify_windows` (`marker`, `probe`, `infrastructure`,
    `tunnel`, `allowed:NAME`, `unexpected`, `foreign`). A window is the span between the markers of one index, as in
    `classify_windows`; only the frames, not the verdict, are given, so nothing here tolerates anything the
    classifier does not. `unparsed` counts the records that could not be read, `problem` is the pcap's own fault.
    """
    names = _declared(allowances)
    if tunnel_port is not None:
        _tunnel_port(tunnel_port)
    parsed, unparsed, problem = _parse_capture(raw, limit)
    is_probe = _probe_matcher([frame for _, frame in parsed], probes, direct_connection(https))
    times = _record_times(raw, limit)
    rows, labels, current = [], {}, None
    for position, frame in parsed:
        at = times[position] if position < len(times) else None
        hit = _phase_hit(frame, run)
        if hit is not None:
            direction, index, word, label = hit
            labels.setdefault(index, label)
            if direction == 'request':
                current = index if word == 'open' else None
            rows.append((position, at, frame, index, 'marker'))
            continue
        category = _category(frame, is_probe, names, tunnel_port)
        if type(category) is tuple:
            category = category[0] + ':' + category[1]
        rows.append((position, at, frame, current, category))
    return rows, len(unparsed), problem, labels


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
    if type(health) is dict and health.get('halted') is True:
        # Only the control's `halt` writes this: the capture was ended on request while the window was open.
        reasons.append('capture-halted-in-window')
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


def leak_verdict(raw, expected, window, health, ready, marker_replies, allowances=(),
                 tunnel_port=None, https=None, limit=CAPTURE_LIMIT):
    """DETECTED, NONE or UNVERIFIED. Only a complete, healthy and bracketed capture says NONE."""
    result = classify(raw, expected, window, allowances, tunnel_port, https, limit)
    reasons = result.pop('unverified') + _health_reasons(health, ready, window, marker_replies)
    canary = result.pop('canary')
    if result['categories']['unexpected']:
        leak, reason = 'DETECTED', 'unexpected-frames'
    elif reasons:
        leak, reason = 'UNVERIFIED', reasons[0]
    else:
        leak, reason = 'NONE', 'clean'
    return dict(leak=leak, leak_reason=reason, observer_reasons=reasons, categories=result['categories'],
                unexpected=result['unexpected'], canary_flows=sorted(name for name in ('udp', 'tcp') if canary[name]),
                canary_other=canary['other'], window=result['window'])
