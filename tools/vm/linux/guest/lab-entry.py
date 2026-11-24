#!/usr/bin/python3
"""Owner-installed root-only lab entry. Never invoked on the controller host."""
import base64
import ctypes
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import selectors
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid

from lab_protocol import (MACS, CLIENTS, GATEWAYS, TARGETS, PORTS, SERVICES, CAPTURE_LIMIT,
                          LOG_LIMIT, DURATION, interface, query, answer, token,
                          CANARY_PORT, CANARY_TCP_TARGET, marker_query, marker_answer,
                          HTTPS_PORT, HTTPS_KINDS, EGRESS, SOCKS_PORT, https_answer, LAB_NETWORKS,
                          RESOLVER, DOH_ADDRESS, DNS_LOG_ENTRIES, DOH_BODY_LIMIT, DOH_HEAD_LIMIT,
                          dns_reply, doh_reply, parse_request_head, http_response,
                          EVIDENCE_PCAP_LIMIT, EVIDENCE_HEADER_SIZE, DURATION_MAX, evidence_header,
                          WINDOW_LIMIT, ACK_PREFIX, parse_window_marker, DNS_CHECK_DOH, DOH_NAME,
                          dns_name, plain_reply_ok, REASON_LIMIT, REQUEST_TIMEOUT, RESPONSE_TIMEOUT, MARKER_TIMEOUT,
                          ROUTE_INTERFACE, ROUTE_FLOWS_LIMIT, RouteFlows, GUEST_CONTROLS, CONTROL_HOLD_SECONDS,
                          LINK_LOCALS, LAN_PEER, ROUTED_NODE, LAN_LISTENER_PORT, LAN_ECHO_PORT, LAN_HOLD_PORT,
                          LAN_BROADCAST_PORT, MDNS_GROUP, MDNS_PORT, SSDP_GROUP, SSDP_PORT, PRIVATE_BEHIND_ROUTER,
                          REALITY_PORT, SECOND_NODE_PORT, XHTTP_PORT, HYSTERIA2_PORT, TUIC_PORT, ANYTLS_PORT,
                          REALITY_COVER_PORT, SECOND_NODE_EGRESS, SECOND_NODE_EGRESS6, TWOHOP_B, TWOHOP_PORTS,
                          TWOHOP_USER, TWOHOP_PASSWORD, PROTO_PASSWORD, TUIC_UUID, REALITY_UUID,
                          REALITY_SHORT_ID, REALITY_SNI, XHTTP_PATH, DHCP_SERVER_PORT, DHCP_CLIENT_PORT,
                          parse)

ROOT = Path('/run/rosetun-lab')
ENTRY = '/usr/local/libexec/rosetun-lab/entry'
# Stage 7b1 fixtures. The paths are fixed here; a missing or different file is a refusal.
LIBEXEC = Path('/usr/local/libexec/rosetun-lab')
NODE_BINARY = LIBEXEC / 'sing-box'
XRAY_BINARY = LIBEXEC / 'xray'
HTTPS_CERT = LIBEXEC / 'https-cert.pem'
HTTPS_KEY = LIBEXEC / 'https-key.pem'
CA_CERT = Path('/usr/local/share/ca-certificates/rosetun-lab-ca.crt')
# Stage 7b2a: the DoH target's certificate (SAN doh.lab.test and 203.0.113.3), signed by the same lab CA.
DOH_CERT = LIBEXEC / 'doh-cert.pem'
DOH_KEY = LIBEXEC / 'doh-key.pem'
# Stage 10f: multi-protocol, Xray REALITY cover, and Two-Hop B-hop certificates.
PROTO_CERT = LIBEXEC / 'proto-cert.pem'
PROTO_KEY = LIBEXEC / 'proto-key.pem'
TWOHOP_CERT = LIBEXEC / 'twohop-b-cert.pem'
TWOHOP_KEY = LIBEXEC / 'twohop-b-key.pem'
TWOHOP_UNTRUSTED_CERT = LIBEXEC / 'twohop-b-untrusted-cert.pem'
TWOHOP_UNTRUSTED_KEY = LIBEXEC / 'twohop-b-untrusted-key.pem'
# Stage 7b2a: the evidence disk is found by its serial and by nothing else.
EVIDENCE_DEVICE = Path('/dev/disk/by-id/virtio-rosetun-lab-evidence')
DOH_REQUESTS = 16
DOH_CONNECTIONS = 8
HTTPS_LOG_ENTRIES = 16
# An L3 run: how many connections the HTTPS target serves at once, how many distinct counters it keeps
# and the longest request head it reads. Going over the first two loses detail, never the observer.
HTTPS_CONNECTIONS = 32
HTTPS_COUNT_KEYS = 64
HTTPS_HEAD_LIMIT = 4096
# The client's log in the helper's answer, which as a whole may not pass LOG_LIMIT.
CLIENT_LOG_LIMIT = 4096
# How much of the node's own log is read back, and the line that stands where older lines were dropped.
NODE_LOG_READ = 1024 * 1024
NODE_LOG_CUT = b'[earlier lines dropped]\n'
# What identifies a connection in a line of the node's log, the longest line kept and the room kept for the
# line that says how many lines were left out of the middle.
NODE_LOG_ID = re.compile(r'\[\d+(?: [^\]]*)?\]')
NODE_LOG_LINE = 512
NODE_LOG_GAP = 64
L3_BODY = b'rosetun-lab-target\n'
REFUSAL_ROWS = 8
TUNNEL_KEYS = {'port', 'method', 'password', 'sing_box_sha256', 'ca_sha256', 'https'}
# Stage 8d: the SSH poller of Linux L4 stands in for the host node that polls the guest legacy L4 runs beside: one
# `ssh` login of a restricted key every POLL_INTERVAL seconds, from the lab's own address to the test machine's
# sshd, whose journal then says `Accepted publickey ... from 192.0.2.1`. Each attempt is logged with its time and
# result (at most POLL_ROWS) and the log is a file of the run. The key is the run's own, made by the controller.
SSH = Path('/usr/bin/ssh')
POLL_INTERVAL = 10
POLL_TIMEOUT = 15
POLL_ROWS = 256
POLLER_KEYS = {'private_key'}
POLLER_KEY_PATTERN = re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----\n[A-Za-z0-9+/=\n]{1,1024}'
                                r'-----END OPENSSH PRIVATE KEY-----\n')
HTTPS_KEYS = {'run_id', 'nonce', 'kind', 'family', 'protocol', 'source', 'target', 'port', 'path'}
LAN_FIXTURE_TOKEN_LIMIT = 64
LAN_FIXTURE_TOKEN = re.compile(rb'^rosetun-lan-matrix ([A-Za-z0-9._-]{1,64})$')
LAN_FIXTURE_WORKERS = 16
LAN_ECHO_IDLE_SECONDS = 90
COVER_READ_TIMEOUT = 0.2
LAN_HOLD_SECONDS = 3.0
PROXY_PROBE_KEYS = {'source', 'port', 'mode'}
PROXY_PROBE_TARGET = 'listed.lab.test'
EXTENDED_BOOL_KEYS = ('protocols', 'second_node', 'xray', 'two_hop', 'dhcp')
EXTENDED_HASH_KEYS = ('xray_sha256', 'proto_cert_sha256', 'twohop_cert_sha256', 'twohop_untrusted_cert_sha256')
EXTENDED_KEYS = frozenset((*EXTENDED_BOOL_KEYS, *EXTENDED_HASH_KEYS))
CONTROL_SERVICES = ('primary_node', 'second_node', 'xray', 'twohop_b')
CONTROL_STATES = ('stop', 'start')
TWOHOP_EVENT_LIMIT = 256
TWOHOP_RELAY_IDLE = 30.0
DHCP_EVENT_LIMIT = 128
DHCP_LEASE_SECONDS = 300
DHCP_MAGIC = b'\x63\x82\x53\x63'
lstat = os.lstat


class Refused(ValueError):
    """A fixed, data-free reason the helper prints instead of a bare failure."""


class ExchangeFailed(Refused):
    """An exchange of the test machine failed. The text is `name:family:reason:<elapsed>ms`.

    The parts are kept as well, for a step that reports the failure instead of ending the run.
    """

    def __init__(self, text, *, name=None, reason=None, elapsed_ms=None):
        super().__init__(text)
        self.name, self.reason, self.elapsed_ms = name, reason, elapsed_ms


def command(*args):
    return subprocess.run(args, check=True, timeout=5, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def identity(request):
    if os.geteuid() != 0 or Path('/etc/rosetun-lab-role').read_text().strip() != request['role']:
        raise ValueError('wrong-guest-role')
    if request['role'] not in MACS or str(uuid.UUID(request['lab_id'])).replace('-', '') != request['lab_id']:
        raise ValueError('invalid-lab-identity')
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip() != request['boot_id']:
        raise ValueError('wrong-boot')
    if Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != request['vm_uuid']:
        raise ValueError('wrong-vm')
    rows = json.loads(command('/usr/sbin/ip', '-j', '-d', 'link', 'show'))
    iface = interface(rows, request['role'])
    expected = request['probes']
    if len(expected) != 8 or len({p['nonce'] for p in expected}) != 8:
        raise ValueError('invalid-probes')
    for p in expected:
        if (p['run_id'] != request['lab_id'] or len(p['nonce']) != 24
                or any(c not in '0123456789abcdef' for c in p['nonce'])
                or p['family'] not in CLIENTS or p['source'] != CLIENTS[p['family']]
                or p['target'] != TARGETS[p['family']] or p['port'] != PORTS[p['service']]
                or p['protocol'] != ('tcp' if p['service'] in ('http', 'dns-tcp') else 'udp')):
            raise ValueError('foreign-probe')
    if type(request['canary']) is not bool:
        raise ValueError('invalid-canary')
    if 'dns' in request and request['dns'] is not True:
        raise ValueError('invalid-dns')
    if 'evidence_disk' in request and request['evidence_disk'] is not True:
        raise ValueError('invalid-evidence-disk')
    if 'duration_seconds' in request and (type(request['duration_seconds']) is not int
                                          or not DURATION <= request['duration_seconds'] <= DURATION_MAX):
        raise ValueError('invalid-duration')
    if 'windows' in request and request['windows'] is not True:
        raise ValueError('invalid-windows')
    if 'lan_fixtures' in request and (request['lan_fixtures'] is not True or request.get('windows') is not True
                                      or 'tunnel' not in request):
        raise ValueError('invalid-lan-fixtures')
    extended = extended_fixtures_of(request)
    if 'action' in request:
        op = request.get('operation')
        if op in ('probe_proxy', 'lan_state'):
            if request.get('lan_fixtures') is not True:
                raise ValueError('invalid-action')
        elif op in ('fixture_state', 'fixture_control'):
            if extended is None:
                raise ValueError('invalid-action')
        else:
            raise ValueError('invalid-action')
    if 'control' in request and (request['control'] not in GUEST_CONTROLS or request['canary'] is not False
                                 or request.get('windows') is True or 'tunnel' in request):
        raise ValueError('invalid-control')
    if 'dns_check' in request:
        dns_check_of(request)
    poller_of(request)
    if 'certificates' in request:
        pinned = request['certificates']
        if (type(pinned) is not dict or set(pinned) != {'https_sha256', 'doh_sha256'}
                or any(type(v) is not str or not re.fullmatch('[0-9a-f]{64}', v) for v in pinned.values())):
            raise ValueError('invalid-certificates')
    window = request['markers']
    tunnel = tunnel_of(request)
    if request.get('windows') is True:
        # Phase windows: the markers come from the test machine's script, one pair per phase.
        if window != []:
            raise ValueError('invalid-markers')
    elif (type(window) is not list or [m.get('word') for m in window] != ['open', 'close']
            or len({m.get('nonce') for m in window + expected}) != 10):
        raise ValueError('invalid-markers')
    for m in window:
        if (set(m) != {'run_id', 'nonce', 'word', 'family', 'service', 'protocol', 'source', 'target', 'port'}
                or m['run_id'] != request['lab_id'] or len(m['nonce']) != 24
                or any(c not in '0123456789abcdef' for c in m['nonce'])
                or (m['family'], m['service'], m['protocol']) != (4, 'marker', 'udp')
                or m['source'] != CLIENTS[4] or m['target'] != TARGETS[4] or m['port'] != PORTS['marker']):
            raise ValueError('foreign-marker')
    checks = dns_check_of(request) if 'dns_check' in request else None
    extra = [checks['plain'], checks['doh']] if checks else []
    if tunnel is not None and len({m['nonce'] for m in window + expected + tunnel['https'] + extra}) != (
            len(window) + 10 + len(extra)):
        raise ValueError('invalid-tunnel')
    return iface


def extended_fixtures_of(request):
    """The validated opt-in `extended_fixtures` block of Stage 10f, or None."""
    if 'extended_fixtures' not in request:
        return None
    block = request['extended_fixtures']
    if (request.get('windows') is not True or 'tunnel' not in request or type(block) is not dict
            or not set(block) <= EXTENDED_KEYS or not any(block.get(k) is True for k in EXTENDED_BOOL_KEYS)):
        raise ValueError('invalid-extended-fixtures')
    for key in EXTENDED_BOOL_KEYS:
        if key in block and type(block[key]) is not bool:
            raise ValueError('invalid-extended-fixtures')
    for key in EXTENDED_HASH_KEYS:
        if key in block and (type(block[key]) is not str or not re.fullmatch('[0-9a-f]{64}', block[key])):
            raise ValueError('invalid-extended-fixtures')
    if block.get('xray') is True and 'xray_sha256' not in block:
        raise ValueError('invalid-extended-fixtures')
    return block


def dns_check_of(request):
    """The validated `dns_check` block: it needs the resolver, the DoH target and the tunnel."""
    checks = request['dns_check']
    if (request.get('dns') is not True or 'tunnel' not in request or type(checks) is not dict
            or set(checks) != {'plain', 'doh'} or not all(type(v) is dict for v in checks.values())):
        raise ValueError('invalid-dns-check')
    plain, doh = checks['plain'], checks['doh']
    for e in (plain, doh):
        if (e.get('run_id') != request['lab_id'] or type(e.get('nonce')) is not str or len(e['nonce']) != 24
                or any(c not in '0123456789abcdef' for c in e['nonce']) or e.get('family') != 4
                or e.get('source') != CLIENTS[4]):
            raise ValueError('foreign-dns-check')
    if (set(plain) != {'run_id', 'nonce', 'family', 'service', 'protocol', 'source', 'target', 'port'}
            or (plain['service'], plain['protocol'], plain['target'], plain['port']) != ('dns-plain', 'udp', RESOLVER, 53)):
        raise ValueError('foreign-dns-check')
    if (set(doh) != HTTPS_KEYS or (doh['kind'], doh['protocol'], doh['target'], doh['port'])
            != (DNS_CHECK_DOH, 'tcp', TARGETS[4], HTTPS_PORT) or doh['path'] != '/' + doh['run_id'] + '/' + doh['nonce']):
        raise ValueError('foreign-dns-check')
    return checks


def poller_of(request):
    """The validated `poller` block of a request, or None: the one-time private key of the SSH poller of Linux L4.

    The key is the whole block. It needs the windows of the phases and the evidence disk of a stage-8 run, and an
    OpenSSH private key file of a plain shape and a bounded size, nothing more.
    """
    if 'poller' not in request:
        return None
    block = request['poller']
    if (type(block) is not dict or set(block) != POLLER_KEYS or request.get('windows') is not True
            or request.get('control') is not None or type(block['private_key']) is not str
            or not POLLER_KEY_PATTERN.fullmatch(block['private_key'])):
        raise ValueError('invalid-poller')
    return block


def redacted(request):
    """The request as the lab machine keeps it on disk: the poller's private key is replaced by its hash."""
    if 'poller' not in request:
        return request
    block = request['poller']
    return {**request, 'poller': dict(private_key_sha256=hashlib.sha256(block['private_key'].encode()).hexdigest())}


def tunnel_of(request):
    """The validated tunnel block of a request, or None when the request has none."""
    if 'tunnel' not in request:
        return None
    tunnel = request['tunnel']
    if type(tunnel) is not dict or set(tunnel) != TUNNEL_KEYS:
        raise ValueError('invalid-tunnel')
    port = tunnel['port']
    if (type(port) is not int or not 1 <= port <= 65535
            or port in (*PORTS.values(), CANARY_PORT, HTTPS_PORT, SOCKS_PORT)):
        raise ValueError('invalid-tunnel')
    if (tunnel['method'] != 'aes-128-gcm' or type(tunnel['password']) is not str
            or not re.fullmatch(r'[A-Za-z0-9._~-]{8,64}', tunnel['password'])):
        raise ValueError('invalid-tunnel')
    for key in ('sing_box_sha256', 'ca_sha256'):
        if type(tunnel[key]) is not str or not re.fullmatch('[0-9a-f]{64}', tunnel[key]):
            raise ValueError('invalid-tunnel')
    exchanges = tunnel['https']
    if (type(exchanges) is not list or len(exchanges) != 2 or not all(type(e) is dict for e in exchanges)
            or [e.get('kind') for e in exchanges] != list(HTTPS_KINDS)):
        raise ValueError('invalid-tunnel')
    for e in exchanges:
        if (set(e) != HTTPS_KEYS or e['run_id'] != request['lab_id'] or type(e['nonce']) is not str
                or len(e['nonce']) != 24 or any(c not in '0123456789abcdef' for c in e['nonce'])
                or (e['family'], e['protocol'], e['source'], e['target'], e['port'])
                != (4, 'tcp', CLIENTS[4], TARGETS[4], HTTPS_PORT)
                or e['path'] != '/' + e['run_id'] + '/' + e['nonce']):
            raise ValueError('foreign-https-exchange')
    return tunnel


def fixture(path, reason, *, sha256=None, private=False):
    """A root-owned regular file at a fixed path, optionally of a known hash; else a refusal."""
    try:
        info = lstat(path)
    except OSError:
        raise Refused(reason) from None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & (0o077 if private else 0o022)):
        raise Refused(reason + '-unsafe')
    if sha256 is not None:
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != sha256:
            raise Refused(reason + '-hash')


def write(path, value, limit=LOG_LIMIT):
    raw = json.dumps(value).encode()
    if len(raw) > limit:
        raise ValueError('guest-log-limit')
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def receive(stream, size):
    data = bytearray()
    while len(data) < size:
        block = stream.recv(size - len(data))
        if not block:
            raise ValueError('short-response')
        data.extend(block)
    return bytes(data)


def probe_one(p):
    family = socket.AF_INET if p['family'] == 4 else socket.AF_INET6
    tcp = p['protocol'] == 'tcp'
    with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as stream:
        stream.settimeout(RESPONSE_TIMEOUT)
        stream.bind((p['source'], 0))
        stream.connect((p['target'], p['port']))
        data = query(p)
        if p['service'] == 'http':
            data = b'GET /' + data + b' HTTP/1.0\r\n\r\n'
        elif p['service'] == 'dns-tcp':
            data = struct.pack('!H', len(data)) + data
        stream.sendall(data)
        if p['service'] == 'dns-tcp':
            length = int.from_bytes(receive(stream, 2), 'big')
            if length > 1024:
                raise ValueError('dns-response-limit')
            response = receive(stream, length)
        elif p['service'] == 'http':
            response = bytearray()
            while True:
                block = stream.recv(1024)
                if not block:
                    break
                response.extend(block)
                if len(response) > 2048:
                    raise ValueError('http-response-limit')
            head, response = bytes(response).split(b'\r\n\r\n', 1)
            if not head.startswith(b'HTTP/1.0 200 OK\r\n'):
                raise ValueError('http-status')
        else:
            response = stream.recv(1024)
        if response != answer(p):
            raise ValueError('unexpected-target-answer')
        return {**p, 'response': response.hex()}


def probe_exchanges(request):
    return [exchange(p['service'], p['family'], lambda p=p: probe_one(p)) for p in request['probes']]


def exchange_marker(marker):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(MARKER_TIMEOUT)
        stream.bind((marker['source'], 0))
        stream.connect((marker['target'], marker['port']))
        stream.sendall(marker_query(marker))
        response = stream.recv(1024)
    if response != marker_answer(marker):
        raise ValueError('unexpected-marker-answer')
    return {**marker, 'response': response.hex()}


def send_canary():
    """A datagram to a port nobody serves and a SYN to an address nobody holds; no answer is awaited."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.bind((CLIENTS[4], 0))
        stream.sendto(b'rosetun-lab-canary', (TARGETS[4], CANARY_PORT))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.bind((CLIENTS[4], 0))
        stream.setblocking(False)
        # Closing the half-open socket sends nothing more.
        if stream.connect_ex((CANARY_TCP_TARGET, CANARY_PORT)) != errno.EINPROGRESS:
            raise ValueError('canary-not-sent')


def read_response(stream):
    """An HTTP/1.0 response of at most 2048 bytes, up to its Content-Length."""
    data = bytearray()
    while True:
        head, separator, body = bytes(data).partition(b'\r\n\r\n')
        if separator:
            length = re.search(rb'\r\nContent-Length: ([0-9]{1,4})(?:\r\n|$)', head)
            if length is None:
                raise ValueError('https-response-length')
            if len(body) >= int(length[1]):
                return head, body[:int(length[1])]
        if len(data) > 2048:
            raise ValueError('http-response-limit')
        try:
            block = stream.recv(1024)
        except ssl.SSLEOFError:
            block = b''
        if not block:
            raise ValueError('short-response')
        data.extend(block)


def https_get(sock, exchange, context):
    with context.wrap_socket(sock, server_hostname=exchange['target']) as stream:
        stream.sendall(b'GET ' + exchange['path'].encode('ascii') + b' HTTP/1.0\r\n\r\n')
        head, body = read_response(stream)
    if not head.startswith(b'HTTP/1.0 200 OK') or body != https_answer(exchange):
        raise ValueError('unexpected-https-answer')
    return body


def socks_connect(sock, address, port):
    """The SOCKS5 handshake and one CONNECT to an IPv4 address, by hand."""
    sock.sendall(b'\x05\x01\x00')
    if receive(sock, 2) != b'\x05\x00':
        raise ValueError('socks-method-refused')
    sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(address) + struct.pack('!H', port))
    head = receive(sock, 4)
    if head[:3] != b'\x05\x00\x00' or head[3] not in (1, 4):
        raise ValueError('socks-connect-refused')
    receive(sock, (4 if head[3] == 1 else 16) + 2)


def probe_tunnel(request):
    """https-direct, then the same kind of request through the node by a throwaway sing-box client."""
    tunnel = request['tunnel']
    direct, via_node = tunnel['https']
    context = ssl.create_default_context()

    def get_direct():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(RESPONSE_TIMEOUT)
            sock.bind((direct['source'], 0))
            sock.connect((direct['target'], direct['port']))
            return sock.getsockname()[1], https_get(sock, direct, context)

    def get_through_node():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(RESPONSE_TIMEOUT)
            sock.connect(('127.0.0.1', SOCKS_PORT))
            socks_connect(sock, via_node['target'], via_node['port'])
            return https_get(sock, via_node, context)

    client_port, direct_response = exchange(direct['kind'], 4, get_direct)
    directory = ROOT / request['lab_id']
    directory.mkdir(mode=0o700, exist_ok=True)
    client = exchange('client', 4, lambda: start_process(client_config(tunnel), directory, 'client',
                                                         '127.0.0.1', SOCKS_PORT))
    try:
        tunnel_response = exchange(via_node['kind'], 4, get_through_node)
    finally:
        _, client_exit = stop_process(client)
    return dict(direct=dict(direct, response=direct_response.hex(), client_port=client_port),
                tunnel=dict(via_node, response=tunnel_response.hex()), client_exit=client_exit)


def socks_connect_domain(sock, name, port):
    """The SOCKS5 handshake and one CONNECT to a domain name: the client has to resolve it."""
    sock.sendall(b'\x05\x01\x00')
    if receive(sock, 2) != b'\x05\x00':
        raise ValueError('socks-method-refused')
    raw = name.encode('ascii')
    sock.sendall(b'\x05\x01\x00\x03' + bytes([len(raw)]) + raw + struct.pack('!H', port))
    head = receive(sock, 4)
    if head[:3] != b'\x05\x00\x00' or head[3] not in (1, 4):
        raise ValueError('socks-connect-refused')
    receive(sock, (4 if head[3] == 1 else 16) + 2)


def client_log_of(directory, name):
    """What a throwaway sing-box client of the test machine said, as the text `node.log` is: bounded, addresses blanked."""
    stderr = directory / (name + '.stderr')
    raw = scrub_log(stderr.read_bytes() if stderr.exists() else b'')[:CLIENT_LOG_LIMIT]
    return raw.decode('utf-8', 'replace')


def probe_dns(request):
    """dns-plain over UDP, then dns-doh-singbox: a sing-box client that resolves through the node and DoH.

    A failed exchange ends the check but not the answer: it is returned as `failed` (which exchange, why,
    how long) beside the exit code and the log of the client, so that the run goes on to its closing
    marker and says why DNS did not work. The answers of the exchanges before it are kept.
    """
    checks = request['dns_check']
    plain, doh = checks['plain'], checks['doh']
    context = ssl.create_default_context()

    def ask_plain():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(RESPONSE_TIMEOUT)
            sock.bind((plain['source'], 0))
            sock.connect((plain['target'], plain['port']))
            sock.send(query(plain))
            answered = sock.recv(512)
        if not plain_reply_ok(plain, answered):
            raise ValueError('unexpected-resolver-answer')
        return answered

    def get_doh():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(RESPONSE_TIMEOUT)
            sock.connect(('127.0.0.1', SOCKS_PORT))
            socks_connect_domain(sock, dns_name(doh), doh['port'])
            return https_get(sock, doh, context)

    directory = ROOT / request['lab_id']
    report, client = {}, None
    try:
        report['plain'] = dict(plain, response=exchange(plain['service'], 4, ask_plain).hex())
        directory.mkdir(mode=0o700, exist_ok=True)
        client = exchange('dns-client', 4, lambda: start_process(dns_client_config(request['tunnel']), directory,
                                                                 'dns-client', '127.0.0.1', SOCKS_PORT))
        report['doh'] = dict(doh, response=exchange(doh['kind'], 4, get_doh).hex())
    except ExchangeFailed as error:
        report['failed'] = dict(exchange=error.name, reason=error.reason, elapsed_ms=error.elapsed_ms)
    finally:
        client_exit = stop_process(client)[1] if client is not None else None
    return dict(report, client_exit=client_exit, client_log=client_log_of(directory, 'dns-client'))


def probe_all(request):
    """The exchanges between an opening and a closing marker, each answered by the target."""
    opening, closing = request['markers']
    sent, marker_replies = {}, []
    tunnel = tunnel_of(request)
    if tunnel is not None:
        # A missing file stops the run before a single marker or packet leaves.
        fixture(NODE_BINARY, 'missing-sing-box', sha256=tunnel['sing_box_sha256'])
        fixture(CA_CERT, 'missing-ca-certificate', sha256=tunnel['ca_sha256'])
    # The clock below is this machine's and is only logged; verdicts never compare it.
    sent['open'] = time.monotonic()
    marker_replies.append(exchange('marker-open', 4, lambda: exchange_marker(opening)))
    replies = probe_exchanges(request)
    https = probe_tunnel(request) if tunnel is not None else None
    dns = probe_dns(request) if 'dns_check' in request else None
    if request['canary']:
        exchange('canary', 4, send_canary)
    if 'control' in request:
        # The controller reaches in here: it waits for the lab to mark the opening and then stops something.
        time.sleep(CONTROL_HOLD_SECONDS)
    # Let the last connection finish closing on the wire before the window ends.
    time.sleep(.2)
    sent['close'] = time.monotonic()
    marker_replies.append(exchange('marker-close', 4, lambda: exchange_marker(closing)))
    return dict(replies=replies, marker_replies=marker_replies, marker_sent=sent,
                **({'https': https} if https is not None else {}), **({'dns': dns} if dns is not None else {}))


def node_config(tunnel, *, lan_fixtures=False, protocols=False, dns_resolver=False):
    """The node: Shadowsocks inbound on the lab address (plus routed/multi-protocol inbounds when enabled), direct out.

    Its log is at `info` so that it names every connection it takes and the destination it opens.
    """
    inbounds = [{'type': 'shadowsocks', 'tag': 'node-in', 'listen': GATEWAYS[4],
                 'listen_port': tunnel['port'], 'method': tunnel['method'],
                 'password': tunnel['password']}]
    if lan_fixtures:
        inbounds.append({'type': 'shadowsocks', 'tag': 'node-routed-in', 'listen': ROUTED_NODE,
                         'listen_port': tunnel['port'], 'method': tunnel['method'],
                         'password': tunnel['password']})
    if protocols:
        inbounds.extend([
            {'type': 'hysteria2', 'tag': 'hysteria2-in', 'listen': GATEWAYS[4],
             'listen_port': HYSTERIA2_PORT, 'users': [{'password': PROTO_PASSWORD}],
             'tls': {'enabled': True, 'certificate_path': str(PROTO_CERT), 'key_path': str(PROTO_KEY)}},
            {'type': 'tuic', 'tag': 'tuic-in', 'listen': GATEWAYS[4],
             'listen_port': TUIC_PORT, 'users': [{'uuid': TUIC_UUID, 'password': PROTO_PASSWORD}],
             'congestion_control': 'bbr',
             'tls': {'enabled': True, 'alpn': ['h3'], 'certificate_path': str(PROTO_CERT),
                     'key_path': str(PROTO_KEY)}},
            {'type': 'anytls', 'tag': 'anytls-in', 'listen': GATEWAYS[4],
             'listen_port': ANYTLS_PORT, 'users': [{'password': PROTO_PASSWORD}],
             'tls': {'enabled': True, 'certificate_path': str(PROTO_CERT), 'key_path': str(PROTO_KEY)}},
        ])
    config = {'log': {'level': 'info', 'timestamp': False},
              'inbounds': inbounds,
              'outbounds': [{'type': 'direct', 'tag': 'direct'}],
              'route': {'final': 'direct'}}
    if lan_fixtures or protocols or dns_resolver:
        config['dns'] = {'servers': [{'type': 'udp', 'tag': 'lab-dns', 'server': RESOLVER}]}
        config['route']['default_domain_resolver'] = 'lab-dns'
    return config


def second_node_config(tunnel):
    """Second VPN node on port 8391 binding outbound traffic to distinct egress addresses."""
    return {
        'log': {'level': 'info', 'timestamp': False},
        'dns': {'servers': [{'type': 'udp', 'tag': 'lab-dns', 'server': RESOLVER}]},
        'inbounds': [{'type': 'shadowsocks', 'tag': 'second-node-in', 'listen': GATEWAYS[4],
                      'listen_port': SECOND_NODE_PORT, 'method': tunnel['method'],
                      'password': tunnel['password']}],
        'outbounds': [{'type': 'direct', 'tag': 'direct',
                       'inet4_bind_address': SECOND_NODE_EGRESS,
                       'inet6_bind_address': SECOND_NODE_EGRESS6}],
        'route': {'final': 'direct', 'default_domain_resolver': 'lab-dns'},
    }


def xray_config(private_key):
    """Xray server with VLESS REALITY + Vision (8390) and VLESS XHTTP + REALITY (8392)."""
    reality_settings = {
        'target': f'127.0.0.1:{REALITY_COVER_PORT}',
        'serverNames': [REALITY_SNI],
        'privateKey': private_key,
        'shortIds': [REALITY_SHORT_ID],
    }
    return {
        'log': {'loglevel': 'warning'},
        'dns': {'servers': [RESOLVER]},
        'inbounds': [
            {
                'tag': 'reality-in',
                'listen': GATEWAYS[4],
                'port': REALITY_PORT,
                'protocol': 'vless',
                'settings': {
                    'clients': [{'id': REALITY_UUID, 'flow': 'xtls-rprx-vision'}],
                    'decryption': 'none',
                },
                'streamSettings': {
                    'network': 'tcp',
                    'security': 'reality',
                    'realitySettings': dict(reality_settings),
                },
            },
            {
                'tag': 'xhttp-in',
                'listen': GATEWAYS[4],
                'port': XHTTP_PORT,
                'protocol': 'vless',
                'settings': {
                    'clients': [{'id': REALITY_UUID}],
                    'decryption': 'none',
                },
                'streamSettings': {
                    'network': 'xhttp',
                    'xhttpSettings': {'path': XHTTP_PATH, 'mode': 'auto'},
                    'security': 'reality',
                    'realitySettings': dict(reality_settings),
                },
            },
        ],
        'outbounds': [{
            'protocol': 'freedom',
            'tag': 'direct',
            'settings': {'finalRules': [{'action': 'allow', 'ip': ['0.0.0.0/0', '::/0']}]},
        }],
    }


def parse_x25519_output(text):
    """Parse `(private_key, public_key)` from `xray x25519` output (supports Xray 25.x and 26.x labels)."""
    private_key = public_key = None
    for line in text.splitlines():
        key, sep, value = line.partition(':')
        if not sep:
            continue
        label, val = key.strip().lower(), value.strip()
        if label in ('privatekey', 'private key'):
            private_key = val
        elif label in ('password (publickey)', 'publickey', 'public key', 'password'):
            public_key = val
    if not private_key or not public_key:
        raise Refused('xray-x25519-parse')
    return private_key, public_key


def generate_reality_keys():
    """Generate a per-run ephemeral X25519 keypair using the pinned Xray binary."""
    out = subprocess.run([str(XRAY_BINARY), 'x25519'], check=True, timeout=5,
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return parse_x25519_output(out.stdout.decode('utf-8', 'replace'))


def client_config(tunnel):
    """The test's check of the node: SOCKS on loopback only, Shadowsocks out, no DNS."""
    return {'log': {'level': 'warn', 'timestamp': False},
            'inbounds': [{'type': 'socks', 'tag': 'socks-in', 'listen': '127.0.0.1',
                          'listen_port': SOCKS_PORT}],
            'outbounds': [{'type': 'shadowsocks', 'tag': 'node', 'server': GATEWAYS[4],
                           'server_port': tunnel['port'], 'method': tunnel['method'],
                           'password': tunnel['password']}],
            'route': {'final': 'node'}}


def dns_client_config(tunnel):
    """The client of the DNS check: Rosetun's DNS server (`render.rs::dns_section`) and a resolving rule.

    The DoH server is the lab's, reached through the node (`detour`) with the name its
    certificate carries. The one rule resolves with that server, so a name asked of the
    SOCKS inbound is looked up through the node and DoH before anything is sent.
    """
    config = client_config(tunnel)
    config['dns'] = {'servers': [{'type': 'https', 'tag': 'dns-proxy', 'server': DOH_ADDRESS,
                                  'tls': {'server_name': DOH_NAME}, 'detour': 'node'}]}
    config['route'] = {'rules': [{'action': 'resolve', 'server': 'dns-proxy'}], 'final': 'node'}
    return config


def blank_foreign_addresses(text):
    """The text with every address outside the documentation ranges replaced by `[address]`."""
    def keep(match):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            return '[address]'
        return match.group(0) if any(address in net for net in LAB_NETWORKS) else '[address]'

    return re.sub(r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]*:[0-9a-fA-F]*', keep, text)


def scrub_log(raw):
    """A bounded sing-box log with every address outside the documentation ranges blanked."""
    text = blank_foreign_addresses(raw[:LOG_LIMIT].decode('utf-8', 'replace'))
    return text.encode('utf-8')[:LOG_LIMIT]


def node_log(raw, cut=False):
    """The node's log as `node.log` keeps it: repeated lines folded, addresses blanked, the beginning and the end kept.

    At `info` the node writes a line for every connection and most of them say the same. Lines that are
    equal once the numbers that identify a connection (`[3365492301 2ms]` becomes `[#]`) are removed fold
    into the place of the first, with how many there were and the numbers of the first and the last of
    them. If what is left is still over `LOG_LIMIT`, the beginning and the end are kept around one line
    saying how many lines were left out. `cut` says that `raw` is only the tail of the file: its first
    line is the tail of a longer one and a line in front says that earlier ones are gone. That line is
    part of the text and is not a fault of the observer.
    """
    lines = re.findall(r'[^\n]+', blank_foreign_addresses(raw.decode('utf-8', 'replace')))
    if cut:
        lines = lines[1:]
    folded = {}
    for number, line in enumerate(lines, 1):
        key = NODE_LOG_ID.sub('[#]', line)[:NODE_LOG_LINE]
        entry = folded.setdefault(key, [number, number, 0])
        entry[1], entry[2] = number, entry[2] + 1
    rows = [(key + (f'  [x{count}, lines {first}-{last}]' if count > 1 else '') + '\n', count)
            for key, (first, last, count) in folded.items()]
    lead = NODE_LOG_CUT.decode('ascii') if cut else ''
    if len(lead) + sum(len(row.encode('utf-8')) for row, _ in rows) > LOG_LIMIT:
        head, tail, size = [], [], len(lead) + NODE_LOG_GAP
        for row, _ in rows:
            size += len(row.encode('utf-8'))
            if size > LOG_LIMIT // 4:
                break
            head.append(row)
        size = 0
        for row, _ in reversed(rows[len(head):]):
            size += len(row.encode('utf-8'))
            if size > LOG_LIMIT - LOG_LIMIT // 4 - len(lead) - NODE_LOG_GAP:
                break
            tail.append(row)
        left = sum(count for _, count in rows[len(head):len(rows) - len(tail)])
        rows = [(row, 0) for row in head] + [(f'[{left} lines dropped here]\n', 0)] + [
            (row, 0) for row in reversed(tail)]
    return (lead + ''.join(row for row, _ in rows)).encode('utf-8')[:LOG_LIMIT]


def read_tail(path, limit):
    """The last `limit` bytes of a file (empty if it is missing) and whether earlier bytes were left out."""
    if not path.exists():
        return b'', False
    size = path.stat().st_size
    with path.open('rb') as stream:
        if size > limit:
            stream.seek(size - limit)
        return stream.read(limit), size > limit


def short_code(error, limit=48):
    """A lowercase code of `[a-z0-9:._-]` for an exception, never an address outside the lab ranges.

    The helper's own fixed words pass as they are, an OS error becomes its errno name and
    anything else is its message with every foreign address blanked and the rest flattened.
    """
    if isinstance(error, (subprocess.TimeoutExpired, TimeoutError, socket.timeout)):
        return 'timeout'
    if isinstance(error, subprocess.CalledProcessError):
        return 'exit-%d' % abs(error.returncode)
    text = str(error)
    if isinstance(error, ssl.SSLError):
        text = 'ssl-' + (getattr(error, 'reason', None) or 'error')
    elif isinstance(error, OSError) and error.errno in errno.errorcode:
        return errno.errorcode[error.errno].lower()
    text = scrub_log(text.encode('utf-8', 'replace')).decode('utf-8', 'replace').lower()
    return re.sub(r'[^a-z0-9:._-]+', '-', text).strip('-')[:limit] or type(error).__name__.lower()[:limit]


def reason_of(error):
    """`Class:code` for `error_reason` of `health.json`, at most 96 characters."""
    return (type(error).__name__ + ':' + short_code(error))[:REASON_LIMIT]


def failure_code(error):
    """What the helper prints after `lab-helper-failed:` for an exception it did not expect.

    The class and the short message as `error_reason` has them, in the lowercase alphabet the controller
    accepts. Nothing here may fail, or the one line that says why would be lost as well.
    """
    try:
        return reason_of(error).lower()
    except Exception:
        return 'unprintable-error'


def exchange(name, family, operation):
    """Run one exchange of the test machine; a failure names it, its family, why and how long it took."""
    started = time.monotonic()
    try:
        return operation()
    except Exception as error:
        elapsed = int((time.monotonic() - started) * 1000)
        reason = short_code(error)
        raise ExchangeFailed('%s:%s:%s:%dms' % (name, family, reason, elapsed), name=name, reason=reason,
                             elapsed_ms=elapsed) from None


def listening(address, port, table='/proc/net/tcp'):
    key = '%s:%04X' % (socket.inet_aton(address)[::-1].hex().upper(), port)
    for line in Path(table).read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) > 3 and fields[1] == key and fields[3] == '0A':
            return True
    return False


def listening_udp(address, port, table='/proc/net/udp', table6='/proc/net/udp6'):
    """True when `address:port` is bound as a UDP listener in IPv4 or v4-mapped IPv6."""
    ipv4 = socket.inet_aton(address)[::-1].hex().upper()
    key = '%s:%04X' % (ipv4, port)
    for line in Path(table).read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) > 3 and fields[1] == key and fields[3] == '07':
            return True
    mapped = '0000000000000000FFFF0000%s:%04X' % (ipv4, port)
    path6 = Path(table6)
    if path6.exists():
        for line in path6.read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) > 3 and fields[1] == mapped and fields[3] == '07':
                return True
    return False


def spawn(config_path, log_path, *, binary=None, append_log=False):
    """Run sing-box or xray in its own session; stderr goes to a file this helper reads back, bounded."""
    mode = 'ab' if append_log else 'xb'
    executable = NODE_BINARY if binary is None else binary
    with log_path.open(mode) as log:
        return subprocess.Popen([str(executable), 'run', '-c', str(config_path)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log,
                                start_new_session=True, close_fds=True)


def stop_process(process):
    """Stop a child and return whether it was still running and its exit code."""
    alive = process.poll() is None
    if alive:
        process.terminate()
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(5)
    return alive, process.returncode


def start_process(config, directory, name, address, port, *, extra_addresses=(), extra_tcp_ports=(),
                  udp_ports=(), binary=None, reuse_config=False):
    """Write the configuration (unless reusing on restart), start the engine and wait until all ports listen."""
    config_path = directory / (name + '.json')
    if not reuse_config:
        write(config_path, config)
    stderr_path = directory / (name + '.stderr')
    if binary is None and not reuse_config:
        process = spawn(config_path, stderr_path)
    else:
        process = spawn(config_path, stderr_path, binary=binary, append_log=reuse_config)
    tcp_checks = [(item, port) for item in (address, *extra_addresses)] + [(address, item) for item in extra_tcp_ports]
    udp_checks = [(address, item) for item in udp_ports]
    for _ in range(50):
        if process.poll() is not None:
            raise Refused(name + '-exited')
        if (all(listening(item, tcp_port) for item, tcp_port in tcp_checks)
                and all(listening_udp(item, udp_port) for item, udp_port in udp_checks)):
            return process
        time.sleep(.1)
    stop_process(process)
    raise Refused(name + '-not-listening')


def pinned(certificates, key):
    """The hash keyword for a certificate the controller pinned; the other runs pin none."""
    value = (certificates or {}).get(key)
    return {} if value is None else dict(sha256=value)


def check_lab_fixtures(tunnel, certificates=None):
    fixture(NODE_BINARY, 'missing-sing-box', sha256=tunnel['sing_box_sha256'])
    fixture(HTTPS_CERT, 'missing-https-certificate', **pinned(certificates, 'https_sha256'))
    fixture(HTTPS_KEY, 'missing-https-key', private=True)


def check_extended_fixtures(extended):
    """Verify pinned binaries and certificates required by opt-in Stage 10f fixtures before any mutation."""
    if extended.get('protocols') is True or extended.get('xray') is True:
        fixture(PROTO_CERT, 'missing-proto-certificate', **pinned(extended, 'proto_cert_sha256'))
        fixture(PROTO_KEY, 'missing-proto-key', private=True)
    if extended.get('xray') is True:
        fixture(XRAY_BINARY, 'missing-xray', sha256=extended['xray_sha256'])
    if extended.get('two_hop') is True:
        fixture(TWOHOP_CERT, 'missing-twohop-certificate', **pinned(extended, 'twohop_cert_sha256'))
        fixture(TWOHOP_KEY, 'missing-twohop-key', private=True)
        fixture(TWOHOP_UNTRUSTED_CERT, 'missing-twohop-untrusted-certificate',
                **pinned(extended, 'twohop_untrusted_cert_sha256'))
        fixture(TWOHOP_UNTRUSTED_KEY, 'missing-twohop-untrusted-key', private=True)


def evidence_device(path=EVIDENCE_DEVICE):
    """The evidence disk, or a refusal: no other device is ever written to."""
    try:
        info = os.stat(path)
    except OSError:
        raise Refused('missing-evidence-disk') from None
    if not stat.S_ISBLK(info.st_mode):
        raise Refused('evidence-disk-not-a-block-device')
    return path


class EvidenceWriter:
    """The pcap streamed behind a header block that is written last, after the pcap is durable."""

    def __init__(self, device, run_id):
        self.stream = open(device, 'r+b')
        self.run_id, self.digest, self.length = run_id, hashlib.sha256(), 0
        # A header of zeros says "not finished" until the real one replaces it.
        self.stream.write(bytes(EVIDENCE_HEADER_SIZE))

    def write(self, data):
        self.stream.write(data)
        self.digest.update(data)
        self.length += len(data)

    def finish(self, *, complete):
        try:
            self.stream.flush()
            os.fsync(self.stream.fileno())
            self.stream.seek(0)
            self.stream.write(evidence_header(self.run_id, self.length, self.digest.digest(), complete=complete))
            self.stream.flush()
            os.fsync(self.stream.fileno())
        finally:
            self.stream.close()


def check_dns_fixtures(certificates=None):
    fixture(DOH_CERT, 'missing-doh-certificate', **pinned(certificates, 'doh_sha256'))
    fixture(DOH_KEY, 'missing-doh-key', private=True)


class PollerLog:
    """The rows of poller.json: one per attempt of the poller, bounded by count."""

    def __init__(self):
        self.rows, self.overflow = [], False

    def record(self, attempt, started, result, code, elapsed_ms):
        if len(self.rows) >= POLL_ROWS:
            self.overflow = True
            return
        self.rows.append(dict(attempt=attempt, at=round(started, 3), result=result, code=code, elapsed_ms=elapsed_ms))


def poll_once(key_path):
    """One login of the poller: (result, exit code of ssh). `accepted` means the forced command ran and ended 0."""
    try:
        process = subprocess.run(
            [str(SSH), '-i', str(key_path), '-b', GATEWAYS[4], '-F', '/dev/null', '-o', 'BatchMode=yes',
             '-o', 'IdentitiesOnly=yes',
             '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
             '-o', 'ConnectTimeout=5', '-o', 'ConnectionAttempts=1', 'root@' + CLIENTS[4], 'true'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=POLL_TIMEOUT)
    except subprocess.TimeoutExpired:
        return 'timeout', None
    except OSError:
        return 'error', None
    return ('accepted' if process.returncode == 0 else 'failed'), process.returncode


def poller_loop(key_path, log, stop):
    attempt = 0
    while not stop.is_set():
        attempt += 1
        started, begun = time.time(), time.monotonic()
        result, code = poll_once(key_path)
        log.record(attempt, started, result, code, int((time.monotonic() - begun) * 1000))
        if stop.wait(POLL_INTERVAL):
            return


def disable_offloads(iface):
    """Disable NIC coalescing/segmentation offloads so raw packet capture never sees >MTU super-frames."""
    ethtool = '/sbin/ethtool' if Path('/sbin/ethtool').is_file() else '/usr/sbin/ethtool'
    if not Path(ethtool).is_file():
        return
    for feature in ('gro', 'gso', 'tso', 'lro'):
        try:
            subprocess.run([ethtool, '-K', iface, feature, 'off'], check=False, timeout=5,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass


def setup(request, iface, directory):
    # The role, VM, boot and one-shot run claim are checked before any mutation.
    tunnel = tunnel_of(request)
    extended = extended_fixtures_of(request)
    if poller_of(request) is not None:
        fixture(SSH, 'poller-ssh-missing')
    if tunnel is not None:
        check_lab_fixtures(tunnel, request.get('certificates'))
    if extended is not None:
        check_extended_fixtures(extended)
    if request.get('lan_fixtures') is True:
        fixture(CA_CERT, 'missing-ca-certificate', sha256=tunnel['ca_sha256'])
    if request.get('dns') is True:
        check_dns_fixtures(request.get('certificates'))
    if request.get('evidence_disk') is True:
        evidence_device()
    command('/usr/sbin/ip', 'addr', 'add', GATEWAYS[4] + '/24', 'dev', iface)
    if request.get('lan_fixtures') is True or (extended is not None and extended.get('two_hop') is True):
        # Secondary LAN peer IP stays non-primary so default router traffic keeps GATEWAYS[4].
        command('/usr/sbin/ip', 'addr', 'add', LAN_PEER + '/24', 'dev', iface)
    if request.get('lan_fixtures') is True:
        # Routed VPN node IP lives on lo so sing-box outbound to rtlab still sources from EGRESS.
        command('/usr/sbin/ip', 'addr', 'add', ROUTED_NODE + '/32', 'dev', 'lo')
    command('/usr/sbin/ip', '-6', 'addr', 'add', GATEWAYS[6] + '/64', 'dev', iface, 'nodad')
    command('/usr/sbin/ip', 'link', 'set', iface, 'up')
    disable_offloads(iface)
    if l3_mode(request):
        # The IPv6 router of an L3 run is this link-local address (`ipv6.neighbor`, test image v6b). The kernel
        # usually makes it itself when the link comes up; `replace` leaves one address either way, and an echo
        # request to it is answered whatever the image set.
        command('/usr/sbin/ip', '-6', 'addr', 'replace', LINK_LOCALS['lab'] + '/64', 'dev', iface, 'nodad')
        Path('/proc/sys/net/ipv6/icmp/echo_ignore_all').write_text('0')
    command('/usr/sbin/ip', 'netns', 'add', 'rtlab')
    command('/usr/sbin/ip', 'link', 'add', 'rt-route', 'type', 'veth', 'peer', 'name', 'rt-target')
    command('/usr/sbin/ip', 'link', 'set', 'rt-target', 'netns', 'rtlab')
    for flag, gateway in (('', '203.0.113.1/24'), ('-6', '2001:db8:6a:2::1/64')):
        prefix = ['/usr/sbin/ip'] + ([flag] if flag else [])
        command(*prefix, 'addr', 'add', gateway, 'dev', 'rt-route', *(['nodad'] if flag else []))
    if extended is not None and extended.get('second_node') is True:
        command('/usr/sbin/ip', 'addr', 'add', SECOND_NODE_EGRESS + '/24', 'dev', 'rt-route')
        command('/usr/sbin/ip', '-6', 'addr', 'add', SECOND_NODE_EGRESS6 + '/64', 'dev', 'rt-route', 'nodad')
    command('/usr/sbin/ip', 'link', 'set', 'rt-route', 'up')
    ns = ['/usr/sbin/ip', 'netns', 'exec', 'rtlab']
    command(*ns, '/usr/sbin/ip', 'link', 'set', 'lo', 'up')
    command(*ns, '/usr/sbin/ip', 'addr', 'add', TARGETS[4] + '/24', 'dev', 'rt-target')
    command(*ns, '/usr/sbin/ip', '-6', 'addr', 'add', TARGETS[6] + '/64', 'dev', 'rt-target', 'nodad')
    if request.get('dns') is True:
        for address in (RESOLVER, DOH_ADDRESS):
            command(*ns, '/usr/sbin/ip', 'addr', 'add', address + '/24', 'dev', 'rt-target')
    if extended is not None and extended.get('two_hop') is True:
        command(*ns, '/usr/sbin/ip', 'addr', 'add', TWOHOP_B[4] + '/24', 'dev', 'rt-target')
        command(*ns, '/usr/sbin/ip', '-6', 'addr', 'add', TWOHOP_B[6] + '/64', 'dev', 'rt-target', 'nodad')
    command(*ns, '/usr/sbin/ip', 'link', 'set', 'rt-target', 'up')
    command(*ns, '/usr/sbin/ip', 'route', 'add', '192.0.2.0/24', 'via', '203.0.113.1')
    command(*ns, '/usr/sbin/ip', '-6', 'route', 'add', '2001:db8:6a:1::/64', 'via', '2001:db8:6a:2::1')
    if request.get('lan_fixtures') is True:
        # Silently drop behind-router RFC 1918 TCP probes with zero ICMP noise so connection tables can observe them.
        command('/usr/sbin/ip', 'route', 'add', PRIVATE_BEHIND_ROUTER + '/32', 'via', TARGETS[4], 'dev', 'rt-route')
        command(*ns, '/usr/sbin/ip', 'route', 'add', 'blackhole', PRIVATE_BEHIND_ROUTER + '/32')
    Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
    Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1')
    # Capture stays in the router namespace; services run in the routed namespace.
    child = subprocess.Popen([ENTRY, json.dumps({**request, 'operation': 'serve', 'interface': iface})],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    if request.get('control') == 'observer-killed':
        # The lab machine knows its own observer; the controller never names a process.
        (directory / 'observer.pid').write_text(str(child.pid))
    # The node and its listeners start inside the observer, so they get a little longer.
    wait_ticks = 150 if extended is not None else (100 if tunnel is not None else 50)
    for _ in range(wait_ticks):
        if child.poll() is not None:
            raise ValueError('observer-start-failed')
        if (directory / 'ready.json').exists():
            return
        time.sleep(.1)
    raise ValueError('capture-ready-timeout')


class DnsLog:
    """The rows of dns.json: source, transport, name and type, bounded by count and size."""

    def __init__(self, *, aggregate=False):
        self.rows, self.lock, self.overflow, self.overflow_in = [], threading.Lock(), False, None
        self.aggregate = aggregate
        self._index = {}

    def record(self, source, transport, entry):
        with self.lock:
            key = (source, transport, entry[0], entry[1])
            if self.aggregate and key in self._index:
                row = self.rows[self._index[key]]
                row['count'] = row.get('count', 1) + 1
                return
            self.rows.append(dict(source=source, transport=transport, name=entry[0], type=entry[1]))
            if len(self.rows) > DNS_LOG_ENTRIES or len(json.dumps(self.rows)) > LOG_LIMIT:
                self.rows.pop()
                # The first overflow names the server that was asked; DoH has its own place.
                self.overflow_in = self.overflow_in or ('doh' if transport == 'doh' else 'dns')
                self.overflow = True
            elif self.aggregate:
                self._index[key] = len(self.rows) - 1


def dns_datagram(sock, log):
    data, peer = sock.recvfrom(1024)
    reply, entry = dns_reply(data)
    if reply is not None:
        sock.sendto(reply, peer)
    if entry is not None:
        log.record(peer[0], 'udp', entry)


def dns_stream(listener, log):
    connection, peer = listener.accept()
    with connection:
        connection.settimeout(REQUEST_TIMEOUT)
        size = int.from_bytes(receive(connection, 2), 'big')
        if size > 1024:
            raise ValueError('request-limit')
        reply, entry = dns_reply(receive(connection, size))
        if reply is not None:
            connection.sendall(struct.pack('!H', len(reply)) + reply)
        if entry is not None:
            log.record(peer[0], 'tcp', entry)


def dns_loop(udp, tcp, log, stop):
    """Answer every question on port 53 until told to stop; a bad client never ends the loop."""
    selector = selectors.DefaultSelector()
    selector.register(udp, selectors.EVENT_READ, dns_datagram)
    selector.register(tcp, selectors.EVENT_READ, dns_stream)
    try:
        while not stop.is_set():
            for key, _ in selector.select(.1):
                try:
                    key.data(key.fileobj, log)
                except (OSError, ValueError):
                    pass
    finally:
        selector.close()


def route_count(route, flows, stop, state):
    """Count the packets of the link behind the node until told to stop.

    A diagnostic and nothing the observer depends on: whatever goes wrong here ends the counting, is
    noted in `state` and reaches neither the failure of the observer nor the capture.
    """
    selector = selectors.DefaultSelector()
    try:
        selector.register(route, selectors.EVENT_READ)
        while not stop.is_set():
            if not selector.select(.1):
                continue
            for _ in range(256):
                try:
                    packet = route.recv(2049)
                except BlockingIOError:
                    break
                flows.add(packet, time.time())
    except Exception:
        state['error'] = 'route-count-failed'
    finally:
        selector.close()


def write_route_flows(path, flows, state):
    """`route-flows.json`: the document of the flows with every address outside the documentation ranges blanked."""
    text = blank_foreign_addresses(json.dumps(flows.document(error=state.get('error'), dropped=state.get('dropped'))))
    write(path, json.loads(text), ROUTE_FLOWS_LIMIT)


def read_doh_request(stream, buffer):
    """(method, target, headers, body) of the next request, or None when the peer is done.

    Raises ValueError for a request that cannot be answered as one. A body over the
    limit is reported as None without being read.
    """
    while b'\r\n\r\n' not in buffer:
        if len(buffer) > DOH_HEAD_LIMIT:
            raise ValueError('http-head-limit')
        block = stream.recv(4096)
        if not block:
            if buffer:
                raise ValueError('short-request')
            return None
        buffer.extend(block)
    head, _, rest = bytes(buffer).partition(b'\r\n\r\n')
    buffer[:] = rest
    method, target, headers = parse_request_head(head)
    if 'transfer-encoding' in headers or not headers.get('content-length', '0').isdecimal():
        raise ValueError('bad-http-request')
    size = int(headers.get('content-length', '0'))
    if size > DOH_BODY_LIMIT:
        return method, target, headers, None
    while len(buffer) < size:
        block = stream.recv(4096)
        if not block:
            raise ValueError('short-request')
        buffer.extend(block)
    body = bytes(buffer[:size])
    del buffer[:size]
    return method, target, headers, body


def doh_connection(stream, peer, log):
    """One TLS connection of the DoH target: a few requests, one answer each, HTTP/1.1 only."""
    buffer = bytearray()
    for count in range(DOH_REQUESTS):
        try:
            request = read_doh_request(stream, buffer)
        except (ValueError, OSError):
            stream.sendall(http_response(400, {}, b'', close=True))
            return
        if request is None:
            return
        method, target, headers, body = request
        if body is None:
            status, extra, payload, entry = 413, {}, b'', None
        else:
            status, extra, payload, entry = doh_reply(method, target, headers, body)
        if entry is not None:
            log.record(peer[0], 'doh', entry)
        close = (status != 200 or headers.get('connection', '').lower() == 'close'
                 or count == DOH_REQUESTS - 1)
        stream.sendall(http_response(status, extra, payload, close=close))
        if close:
            return


def doh_worker(connection, peer, context, log):
    try:
        connection.settimeout(REQUEST_TIMEOUT)
        with context.wrap_socket(connection, server_side=True) as stream:
            doh_connection(stream, peer, log)
    except (OSError, ssl.SSLError, ValueError):
        pass
    finally:
        connection.close()


def doh_loop(listener, context, log, stop):
    listener.settimeout(.2)
    workers = []
    while not stop.is_set():
        try:
            connection, peer = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        workers = [worker for worker in workers if worker.is_alive()]
        if len(workers) >= DOH_CONNECTIONS:
            connection.close()
            continue
        workers.append(threading.Thread(target=doh_worker, args=(connection, peer, context, log), daemon=True))
        workers[-1].start()


def doh_context():
    """TLS 1.2 or newer, HTTP/1.1 only, the DoH certificate of the image."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(['http/1.1'])
    context.load_cert_chain(str(DOH_CERT), str(DOH_KEY))
    return context


def accept_marker(request, marks, data, source):
    """The window marker a datagram carries, accepted once and only in open-then-close order."""
    word = ('open', 'close')[len(marks)] if len(marks) < 2 else None
    found = [m for m in request['markers'] if m['word'] == word and m['source'] == source
             and marker_query(m) == data]
    if len(found) != 1:
        raise ValueError('unexpected-marker')
    return found[0]


def accept_window_marker(request, marks, data, source):
    """(index, word, label) of a phase marker from the test machine; order is judged from the capture."""
    found = parse_window_marker(data, request['lab_id'])
    if found is None or source != CLIENTS[4] or len(marks) >= 2 * WINDOW_LIMIT:
        raise ValueError('unexpected-marker')
    return found


def https_exchange(connection, peer, context, request):
    """One request to the HTTPS target; the log row names who asked and from which port."""
    connection.settimeout(REQUEST_TIMEOUT)
    with context.wrap_socket(connection, server_side=True) as stream:
        data = bytearray()
        while b'\r\n\r\n' not in data:
            block = stream.recv(1024)
            if not block:
                break
            data.extend(block)
            if len(data) > 1024:
                raise ValueError('request-limit')
        known = request['tunnel']['https'] + ([request['dns_check']['doh']] if 'dns_check' in request else [])
        matches = [e for e in known
                   if bytes(data) == b'GET ' + e['path'].encode('ascii') + b' HTTP/1.0\r\n\r\n']
        if len(matches) != 1 or peer[0] not in (CLIENTS[4], EGRESS):
            raise ValueError('unexpected-request')
        body = https_answer(matches[0])
        stream.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
        try:
            stream.unwrap()
        except (OSError, ssl.SSLError):
            pass
    return dict(source=peer[0], port=peer[1], path=matches[0]['path'], at=time.monotonic())


def l3_mode(request):
    """An L3 run: the controller asks for phase windows, and the HTTPS target then serves what the script asks."""
    return request.get('windows') is True


def read_https_head(stream, deadline):
    """The request head, up to its blank line. The deadline bounds a client that sends a byte at a time."""
    data = bytearray()
    while b'\r\n\r\n' not in data:
        if time.monotonic() >= deadline:
            raise TimeoutError('request-timeout')
        block = stream.recv(1024)
        if not block:
            raise ValueError('short-request')
        data.extend(block)
        if len(data) > HTTPS_HEAD_LIMIT:
            raise ValueError('request-limit')
    return bytes(data[:data.index(b'\r\n\r\n') + 4])


def l3_request_line(head):
    """(method, version, path class) of a GET or HEAD request of HTTP/1.0 or 1.1; anything else is refused."""
    try:
        line = head.decode('ascii').split('\r\n')[0]
    except UnicodeDecodeError:
        raise ValueError('bad-http-request') from None
    parts = line.split(' ')
    if len(parts) != 3 or not parts[1].startswith('/'):
        raise ValueError('bad-http-request')
    if parts[0] not in ('GET', 'HEAD'):
        raise ValueError('unsupported-method')
    if parts[2] not in ('HTTP/1.0', 'HTTP/1.1'):
        raise ValueError('unsupported-version')
    return parts[0], parts[2], 'root' if parts[1].partition('?')[0] == '/' else 'other'


def l3_allowed_peers(request):
    """Allowed IPv4 client/egress sources for the L3 HTTPS target."""
    peers = [CLIENTS[4], EGRESS]
    extended = extended_fixtures_of(request)
    if extended is not None:
        if extended.get('second_node') is True:
            peers.append(SECOND_NODE_EGRESS)
        if extended.get('two_hop') is True:
            peers.extend((TWOHOP_B[4], LAN_PEER))
    return tuple(peers)


def l3_exchange(connection, peer, context, request):
    """One request to the HTTPS target of an L3 run: (row, method, path class) of what was answered.

    An exchange of stage 7b1 is still known by its exact request and answered with its nonce. Any other GET
    or HEAD gets a short fixed body without one, and the connection is closed after it.
    """
    if peer[0] not in l3_allowed_peers(request):
        raise ValueError('unexpected-request')
    connection.settimeout(REQUEST_TIMEOUT)
    deadline = time.monotonic() + 2 * REQUEST_TIMEOUT
    with context.wrap_socket(connection, server_side=True) as stream:
        head = read_https_head(stream, deadline)
        known = request['tunnel']['https'] + ([request['dns_check']['doh']] if 'dns_check' in request else [])
        exact = [e for e in known if head == b'GET ' + e['path'].encode('ascii') + b' HTTP/1.0\r\n\r\n']
        if len(exact) == 1:
            body = https_answer(exact[0])
            stream.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
            result = dict(source=peer[0], port=peer[1], path=exact[0]['path'], at=time.monotonic()), 'GET', 'other'
        else:
            method, version, path_class = l3_request_line(head)
            wire = ('%s 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n'
                    % (version, len(L3_BODY))).encode('ascii')
            stream.sendall(wire if method == 'HEAD' else wire + L3_BODY)
            result = dict(source=peer[0], port=peer[1], method=method, path_class=path_class,
                          at=time.monotonic()), method, path_class
        try:
            stream.unwrap()
        except (OSError, ssl.SSLError):
            pass
    return result


class HttpsLog:
    """What the HTTPS target of an L3 run saw: counters by (source, method, path class), the first lines whole.

    Written by one thread per connection. A refused connection is a row with its reason, as in the other
    logs. Too many distinct counters or too many lines is a loss of detail, counted in the last element of
    `document()`; it is never an error of the observer.
    """

    def __init__(self, state_path=None):
        self.lock, self.rows, self.counts = threading.Lock(), [], {}
        self.rows_dropped = self.counts_dropped = 0
        self.state_path = state_path
        if self.state_path is not None:
            self._flush_locked()

    def _flush_locked(self):
        by_source = {}
        for (source, _, _), count in self.counts.items():
            by_source[source] = by_source.get(source, 0) + count
        payload = dict(
            by_source=dict(sorted(by_source.items())),
            counts=[dict(source=source, method=method, path_class=path_class, count=count)
                    for (source, method, path_class), count in sorted(self.counts.items())],
            total=sum(by_source.values()))
        try:
            tmp = self.state_path.with_suffix('.tmp')
            tmp.write_bytes(json.dumps(payload).encode('utf-8'))
            os.replace(tmp, self.state_path)
        except OSError:
            pass

    def served(self, row, method, path_class):
        with self.lock:
            key = (row['source'], method, path_class)
            if key in self.counts or len(self.counts) < HTTPS_COUNT_KEYS:
                self.counts[key] = self.counts.get(key, 0) + 1
            else:
                self.counts_dropped += 1
            if sum('reason' not in entry for entry in self.rows) < HTTPS_LOG_ENTRIES:
                self.rows.append(row)
            else:
                self.rows_dropped += 1
            if self.state_path is not None:
                self._flush_locked()

    def refused(self, error):
        with self.lock:
            refuse(self.rows, 'https', 4, error)

    def document(self):
        """The rows, then one `counts` element: what `https.json` holds in an L3 run."""
        with self.lock:
            counts = [dict(source=source, method=method, path_class=path_class, count=count)
                      for (source, method, path_class), count in sorted(self.counts.items())]
            return self.rows + [dict(kind='counts', counts=counts, rows_dropped=self.rows_dropped,
                                     counts_dropped=self.counts_dropped)]


def l3_worker(connection, peer, context, request, log):
    try:
        row, method, path_class = l3_exchange(connection, peer, context, request)
    except Exception as error:
        log.refused(error)
    else:
        log.served(row, method, path_class)
    finally:
        connection.close()


class HttpsWorkers:
    """The connections of the HTTPS target in an L3 run, each on a thread of its own so that none delays the capture."""

    def __init__(self, context, request, log):
        self.context, self.request, self.log, self.threads = context, request, log, []

    def accept(self, listener):
        try:
            # Ready to read does not promise a connection still there: never wait in the observer's loop.
            listener.setblocking(False)
            connection, peer = listener.accept()
        except BlockingIOError:
            return
        except OSError as error:
            self.log.refused(error)
            return
        self.threads = [thread for thread in self.threads if thread.is_alive()]
        if len(self.threads) >= HTTPS_CONNECTIONS:
            connection.close()
            self.log.refused(ValueError('connection-limit'))
            return
        self.threads.append(threading.Thread(target=l3_worker, args=(connection, peer, self.context, self.request,
                                                                     self.log), daemon=True))
        self.threads[-1].start()

    def drain(self, timeout):
        """Let the connections in flight finish, so that the log is written whole."""
        end = time.monotonic() + timeout
        for thread in self.threads:
            thread.join(max(0, end - time.monotonic()))


def refuse(rows, service, family, error):
    """Log a refused exchange of a target: which service, which family and why.

    The row has no `response`, so the controller can never read it as an answered
    exchange. At most `REFUSAL_ROWS` are kept, which keeps a stream of bad clients bounded.
    """
    if sum('reason' in row for row in rows) < REFUSAL_ROWS:
        rows.append(dict(service=service, family=family, reason=short_code(error)))


def record_https(log, row):
    log.append(row)
    if sum('reason' not in entry for entry in log) > HTTPS_LOG_ENTRIES or len(json.dumps(log)) > LOG_LIMIT:
        raise ValueError('https-log-limit')


class Failure:
    """The first thing that went wrong in the observer: where, when on the lab's clock, and why."""

    def __init__(self):
        self.where = self.at = self.reason = None

    def note(self, where, error):
        if self.reason is None:
            self.where, self.at, self.reason = where, time.monotonic(), reason_of(error)

    def __bool__(self):
        return self.reason is not None


def guarded(where, failure, target, *args):
    """Run a server thread so that how it ended is noted instead of lost."""
    try:
        target(*args)
    except BaseException as error:
        failure.note(where, error)


# Where an exchange service of the target is named when the observer stops in it.
EXCHANGE_PLACES = {'http': 'http', 'udp': 'udp', 'dns-udp': 'udp', 'dns-tcp': 'dns-tcp'}


def open_capture(interface, *, allmulti=False):
    """The raw socket of the lab's ingress interface, non-blocking, with a 256 KiB receive buffer."""
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
    capture.bind((interface, 0))
    if allmulti:
        # PACKET_ADD_MEMBERSHIP (1) with PACKET_MR_ALLMULTI (2) receives L2 multicast without emitting IGMP.
        capture.setsockopt(263, 1, struct.pack('iHH8s', socket.if_nametoindex(interface), 2, 0, b''))
    capture.setblocking(False)
    return capture


class LanFixtures:
    """Router-namespace LAN peer/server TCP fixtures and live L2 multicast/broadcast token tracker."""

    BANNERS = {'peer': b'ROSETUN-LAN-PEER\n', 'server': b'ROSETUN-LAN-SERVER\n'}

    def __init__(self, state_path):
        self.state_path = state_path
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.sockets = []
        self.threads = []
        self.tokens = {'mdns': [], 'ssdp': [], 'broadcast': []}
        self.tcp = {'peer': 0, 'server': 0, 'echo': 0, 'hold': 0}

    def _snapshot(self):
        return dict(mdns=list(self.tokens['mdns']), ssdp=list(self.tokens['ssdp']),
                    broadcast=list(self.tokens['broadcast']), tcp=dict(self.tcp))

    def flush(self):
        with self.lock:
            raw = json.dumps(self._snapshot()).encode('utf-8')
        tmp = self.state_path.with_suffix('.tmp')
        tmp.write_bytes(raw)
        os.replace(tmp, self.state_path)

    def bind(self, selector):
        specs = (
            ('peer', LAN_PEER, LAN_LISTENER_PORT),
            ('server', GATEWAYS[4], LAN_LISTENER_PORT),
            ('echo', LAN_PEER, LAN_ECHO_PORT),
            ('hold', GATEWAYS[4], LAN_HOLD_PORT),
        )
        for kind, address, port in specs:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((address, port))
            listener.listen(8)
            listener.setblocking(False)
            self.sockets.append(listener)
            selector.register(listener, selectors.EVENT_READ, ('lan', kind))
        self.flush()

    def accept(self, listener, kind):
        try:
            connection, _ = listener.accept()
        except (BlockingIOError, OSError):
            return
        with self.lock:
            self.tcp[kind] += 1
        try:
            self.flush()
        except OSError:
            pass
        self.threads = [thread for thread in self.threads if thread.is_alive()]
        if len(self.threads) >= LAN_FIXTURE_WORKERS:
            connection.close()
            return
        worker = threading.Thread(target=self._serve, args=(connection, kind), daemon=True)
        self.threads.append(worker)
        worker.start()

    def _serve(self, connection, kind):
        try:
            if kind in self.BANNERS:
                connection.settimeout(REQUEST_TIMEOUT)
                connection.sendall(self.BANNERS[kind])
                return
            if kind == 'hold':
                deadline = time.monotonic() + LAN_HOLD_SECONDS
                while not self.stop.is_set() and time.monotonic() < deadline:
                    ready, _, _ = select.select([connection], [], [], 0.2)
                    if ready and not connection.recv(256):
                        return
                return
            if kind == 'echo':
                idle_until = time.monotonic() + LAN_ECHO_IDLE_SECONDS
                while not self.stop.is_set() and time.monotonic() < idle_until:
                    ready, _, _ = select.select([connection], [], [], 1.0)
                    if not ready:
                        continue
                    data = connection.recv(4096)
                    if not data:
                        return
                    connection.sendall(data)
                    idle_until = time.monotonic() + LAN_ECHO_IDLE_SECONDS
        except OSError:
            pass
        finally:
            try:
                connection.close()
            except OSError:
                pass

    def inspect_frame(self, raw_frame):
        """Record multicast/broadcast UDP tokens sent by the test machine without altering capture."""
        try:
            frame = parse(raw_frame)
        except ValueError:
            return
        if frame.fragment or frame.family != 4 or frame.proto != 17 or frame.src != CLIENTS[4]:
            return
        if (frame.dst, frame.dport) == (MDNS_GROUP, MDNS_PORT):
            channel = 'mdns'
        elif (frame.dst, frame.dport) == (SSDP_GROUP, SSDP_PORT):
            channel = 'ssdp'
        elif (frame.dst, frame.dport) == ('255.255.255.255', LAN_BROADCAST_PORT):
            channel = 'broadcast'
        else:
            return
        match = LAN_FIXTURE_TOKEN.fullmatch(frame.payload)
        if match is None:
            return
        value = match[1].decode('ascii')
        changed = False
        with self.lock:
            bucket = self.tokens[channel]
            if value not in bucket and len(bucket) < LAN_FIXTURE_TOKEN_LIMIT:
                bucket.append(value)
                changed = True
        if changed:
            try:
                self.flush()
            except OSError:
                pass

    def close(self):
        self.stop.set()
        for listener in self.sockets:
            try:
                listener.close()
            except OSError:
                pass
        for thread in self.threads:
            thread.join(2)
        try:
            self.flush()
        except OSError:
            pass


def probe_proxy(action):
    """Probe the Windows shared HTTP proxy from a lab LAN address; return structured pass/fail facts."""
    if type(action) is not dict or set(action) != PROXY_PROBE_KEYS:
        raise ValueError('invalid-proxy-probe')
    source, port, mode = action['source'], action['port'], action['mode']
    if source not in (LAN_PEER, GATEWAYS[4]) or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('invalid-proxy-probe')
    if mode not in ('connect', 'http_proxy'):
        raise ValueError('invalid-proxy-probe')
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(RESPONSE_TIMEOUT)
            sock.bind((source, 0))
            sock.connect((CLIENTS[4], port))
            if mode == 'connect':
                return dict(ok=True, reason='connected', elapsed_ms=int((time.monotonic() - started) * 1000))
            sock.sendall(f'CONNECT {PROXY_PROBE_TARGET}:443 HTTP/1.1\r\nHost: {PROXY_PROBE_TARGET}:443\r\n\r\n'.encode('ascii'))
            head = bytearray()
            while b'\r\n\r\n' not in head:
                block = sock.recv(1024)
                if not block:
                    raise ValueError('proxy-eof')
                head.extend(block)
                if len(head) > 2048:
                    raise ValueError('proxy-head-limit')
            first_line = bytes(head).split(b'\r\n', 1)[0]
            if not first_line.startswith((b'HTTP/1.1 200', b'HTTP/1.0 200')):
                raise ValueError('proxy-status')
            context = ssl.create_default_context(cafile=str(CA_CERT))
            with context.wrap_socket(sock, server_hostname=TARGETS[4]) as tls:
                tls.sendall(f'GET / HTTP/1.1\r\nHost: {PROXY_PROBE_TARGET}\r\nConnection: close\r\n\r\n'.encode('ascii'))
                response = bytearray()
                while True:
                    try:
                        block = tls.recv(1024)
                    except ssl.SSLEOFError:
                        block = b''
                    if not block:
                        break
                    response.extend(block)
                    if len(response) > 4096:
                        raise ValueError('http-response-limit')
            resp_head, separator, body = bytes(response).partition(b'\r\n\r\n')
            if not separator or not resp_head.startswith((b'HTTP/1.1 200 OK', b'HTTP/1.0 200 OK')):
                raise ValueError('http-status')
            if body != L3_BODY:
                raise ValueError('unexpected-body')
            return dict(ok=True, reason='ok', status=200, body_ok=True,
                        elapsed_ms=int((time.monotonic() - started) * 1000))
    except Exception as error:
        return dict(ok=False, reason=short_code(error), elapsed_ms=int((time.monotonic() - started) * 1000))


def lan_state(directory):
    """Current live LAN fixture observations (multicast/broadcast tokens and TCP accept counts)."""
    path = directory / 'lan-fixtures.json'
    if not path.exists():
        return dict(mdns=[], ssdp=[], broadcast=[], tcp=dict(peer=0, server=0, echo=0, hold=0))
    return json.loads(path.read_bytes())


def atomic_json(path, value):
    """Write a small JSON state file atomically via sibling `.tmp`."""
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_bytes(json.dumps(value).encode('utf-8'))
    os.replace(tmp, path)


class RealityCoverServer:
    """Minimal local TLS 1.3 cover target for Xray REALITY fallback on 127.0.0.1."""

    def __init__(self, *, address='127.0.0.1', port=REALITY_COVER_PORT, cert_path=PROTO_CERT, key_path=PROTO_KEY):
        self.address, self.port = address, port
        self.cert_path, self.key_path = cert_path, key_path
        self.stop = threading.Event()
        self.listener = None
        self.thread = None
        self.workers = []

    def start(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.num_tickets = 0
        context.set_alpn_protocols(['h2', 'http/1.1'])
        context.load_cert_chain(str(self.cert_path), str(self.key_path))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.address, self.port))
        sock.listen(16)
        sock.setblocking(False)
        self.listener = sock
        self.thread = threading.Thread(target=self._accept_loop, args=(context,), daemon=True)
        self.thread.start()

    def _accept_loop(self, context):
        while not self.stop.is_set():
            try:
                ready, _, _ = select.select([self.listener], [], [], 0.2)
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                conn, _ = self.listener.accept()
            except (BlockingIOError, OSError):
                continue
            self.workers = [worker for worker in self.workers if worker.is_alive()]
            if len(self.workers) >= 32:
                conn.close()
                continue
            worker = threading.Thread(target=self._serve, args=(conn, context), daemon=True)
            self.workers.append(worker)
            worker.start()

    def _serve(self, conn, context):
        try:
            conn.settimeout(REQUEST_TIMEOUT)
            with context.wrap_socket(conn, server_side=True) as tls:
                ready, _, _ = select.select([tls], [], [], COVER_READ_TIMEOUT)
                data = tls.recv(1024) if ready else b''
                if data:
                    body = b'ok\n'
                    tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n' + body)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self.stop.set()
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError:
                pass
            self.listener = None
        if self.thread is not None:
            self.thread.join(2)
            self.thread = None
        for worker in self.workers:
            worker.join(1)
        self.workers = []


def _parse_host_port(authority, default_port=80):
    """Parse `host:port` or `[ipv6]:port` authority string."""
    if authority.startswith('['):
        host, sep, rest = authority[1:].partition(']')
        if not sep:
            raise ValueError('bad-authority')
        port = int(rest[1:]) if rest.startswith(':') else default_port
    else:
        host, sep, port_text = authority.rpartition(':')
        if not sep:
            host, port = authority, default_port
        else:
            port = int(port_text)
    if not host or not 1 <= port <= 65535:
        raise ValueError('bad-authority')
    return host, port


def _resolve_lab_host(host, resolver=RESOLVER):
    """Resolve an IP literal or query the lab UDP DNS resolver for an A record."""
    try:
        addr = ipaddress.ip_address(host)
        return str(addr), addr.version
    except ValueError:
        pass
    labels = [part.encode('ascii') for part in host.rstrip('.').split('.') if part]
    if not labels or any(len(part) > 63 for part in labels):
        raise ValueError('bad-hostname')
    qname = b''.join(bytes([len(part)]) + part for part in labels) + b'\x00'
    packet = struct.pack('!HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0) + qname + struct.pack('!HH', 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(RESPONSE_TIMEOUT)
        sock.sendto(packet, (resolver, 53))
        reply = sock.recv(512)
    if len(reply) < 12:
        raise ValueError('dns-short-reply')
    _, _, qdcount, ancount, _, _ = struct.unpack_from('!HHHHHH', reply, 0)
    if ancount < 1:
        raise ValueError('dns-no-answer')
    offset = 12
    for _ in range(qdcount):
        while offset < len(reply):
            length = reply[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xc0 == 0xc0:
                offset += 2
                break
            offset += 1 + length
        offset += 4
    for _ in range(ancount):
        if offset >= len(reply):
            break
        if reply[offset] & 0xc0 == 0xc0:
            offset += 2
        else:
            while offset < len(reply) and reply[offset] != 0:
                offset += 1 + reply[offset]
            offset += 1
        if offset + 10 > len(reply):
            break
        rtype, rclass, _, rdlength = struct.unpack_from('!HHIH', reply, offset)
        offset += 10
        if rtype == 1 and rclass == 1 and rdlength == 4 and offset + 4 <= len(reply):
            return socket.inet_ntoa(reply[offset:offset + 4]), 4
        offset += rdlength
    raise ValueError('dns-no-a-record')


def _relay_pair(left, right, stop_event, idle=TWOHOP_RELAY_IDLE):
    """Bidirectional TCP/TLS relay honoring SSLSocket buffered bytes."""
    left.settimeout(REQUEST_TIMEOUT)
    right.settimeout(REQUEST_TIMEOUT)
    last = time.monotonic()

    def forward(src, dst):
        data = src.recv(16384)
        if not data:
            return False
        dst.sendall(data)
        return True

    while not stop_event.is_set() and time.monotonic() - last < idle:
        progressed = False
        for src, dst in ((left, right), (right, left)):
            if isinstance(src, ssl.SSLSocket) and src.pending() > 0:
                if not forward(src, dst):
                    return
                last = time.monotonic()
                progressed = True
        if progressed:
            continue
        ready, _, _ = select.select([left, right], [], [], 0.5)
        if not ready:
            continue
        for src in ready:
            dst = right if src is left else left
            try:
                if not forward(src, dst):
                    return
                last = time.monotonic()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                continue


class TwoHopProxy:
    """Two-Hop B-hop HTTP/HTTPS/SOCKS5 proxies in rtlab (plus optional LAN B-hop in router ns)."""

    def __init__(self, state_path, *, cert_path=TWOHOP_CERT, key_path=TWOHOP_KEY,
                 untrusted_cert_path=TWOHOP_UNTRUSTED_CERT, untrusted_key_path=TWOHOP_UNTRUSTED_KEY,
                 bind_v4=TWOHOP_B[4], bind_v6=TWOHOP_B[6], lan_bind=LAN_PEER, ports=None,
                 resolver=RESOLVER, use_netns=True):
        self.state_path = state_path
        self.cert_path, self.key_path = cert_path, key_path
        self.untrusted_cert_path, self.untrusted_key_path = untrusted_cert_path, untrusted_key_path
        self.bind_v4, self.bind_v6, self.lan_bind = bind_v4, bind_v6, lan_bind
        self.ports = dict(TWOHOP_PORTS if ports is None else ports)
        self.resolver = resolver
        self.use_netns = use_netns
        self.lock = threading.Lock()
        self.events = []
        self.dropped = 0
        self.running = False
        self._stop = threading.Event()
        self._listeners = []
        self._selector = None
        self._accept_thread = None
        self._workers = []
        self._trusted_ctx = None
        self._untrusted_ctx = None
        self._auth_header = 'Basic ' + base64.b64encode(
            f'{TWOHOP_USER}:{TWOHOP_PASSWORD}'.encode('ascii')).decode('ascii')

    def _snapshot(self):
        return dict(running=self.running, events=list(self.events), dropped=self.dropped)

    def _flush_locked(self):
        try:
            atomic_json(self.state_path, self._snapshot())
        except OSError:
            pass

    def _record(self, **event):
        with self.lock:
            if len(self.events) < TWOHOP_EVENT_LIMIT:
                self.events.append(event)
            else:
                self.dropped += 1
            self._flush_locked()

    def _make_context(self, cert_path, key_path):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        context.load_cert_chain(str(cert_path), str(key_path))
        return context

    def _bind_one(self, selector, kind, address, port, family, in_rtlab):
        sock = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == 6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((address, port))
        sock.listen(16)
        sock.setblocking(False)
        self._listeners.append(sock)
        selector.register(sock, selectors.EVENT_READ, (kind, address, port, in_rtlab))

    def start_listeners(self):
        if self.running:
            return
        self._stop = threading.Event()
        self._trusted_ctx = self._make_context(self.cert_path, self.key_path)
        self._untrusted_ctx = self._make_context(self.untrusted_cert_path, self.untrusted_key_path)
        selector = selectors.DefaultSelector()
        try:
            if self.use_netns:
                with open('/proc/self/ns/net', 'rb') as original, open('/run/netns/rtlab', 'rb') as target:
                    libc = ctypes.CDLL(None, use_errno=True)
                    if libc.setns(target.fileno(), 0) != 0:
                        raise OSError('twohop-setns')
                    try:
                        self._bind_rtlab(selector)
                    finally:
                        if libc.setns(original.fileno(), 0) != 0:
                            raise OSError('twohop-router-setns')
            else:
                self._bind_rtlab(selector)
            if self.lan_bind is not None:
                self._bind_one(selector, 'lan_http', self.lan_bind, self.ports['http'], 4, False)
        except Exception:
            for sock in self._listeners:
                try:
                    sock.close()
                except OSError:
                    pass
            self._listeners = []
            selector.close()
            raise
        self._selector = selector
        self._accept_thread = threading.Thread(target=self._accept_loop, args=(selector, self._stop), daemon=True)
        self._accept_thread.start()
        with self.lock:
            self.running = True
            self._flush_locked()

    def _bind_rtlab(self, selector):
        for kind, port in self.ports.items():
            if self.bind_v4 is not None:
                self._bind_one(selector, kind, self.bind_v4, port, 4, True)
            if self.bind_v6 is not None:
                self._bind_one(selector, kind, self.bind_v6, port, 6, True)

    def stop_listeners(self):
        self._stop.set()
        if self._accept_thread is not None:
            self._accept_thread.join(2)
            self._accept_thread = None
        if self._selector is not None:
            try:
                self._selector.close()
            except OSError:
                pass
            self._selector = None
        for sock in self._listeners:
            try:
                sock.close()
            except OSError:
                pass
        self._listeners = []
        for worker in self._workers:
            worker.join(1)
        self._workers = []
        with self.lock:
            self.running = False
            self._flush_locked()

    def _accept_loop(self, selector, stop_event):
        while not stop_event.is_set():
            try:
                ready = selector.select(0.1)
            except (OSError, ValueError):
                return
            for key, _ in ready:
                try:
                    conn, peer = key.fileobj.accept()
                except (BlockingIOError, OSError):
                    continue
                self._workers = [worker for worker in self._workers if worker.is_alive()]
                if len(self._workers) >= 32:
                    conn.close()
                    continue
                worker = threading.Thread(target=self._handle_client, args=(conn, peer, key.data, stop_event),
                                          daemon=True)
                self._workers.append(worker)
                worker.start()

    def _dial_outbound(self, host, port, in_rtlab):
        dst_ip, family = _resolve_lab_host(host, self.resolver)
        bind_addr = (self.bind_v4 if family == 4 else self.bind_v6) if in_rtlab else (
            self.lan_bind if family == 4 else None)
        out = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_STREAM)
        out.settimeout(REQUEST_TIMEOUT)
        try:
            if bind_addr is not None:
                out.bind((bind_addr, 0))
            out.connect((dst_ip, port))
            return out, dst_ip, family, bind_addr
        except Exception:
            out.close()
            raise

    def _handle_client(self, conn, peer, spec, stop_event):
        kind, listen_addr, listen_port, in_rtlab = spec
        client_ip = peer[0]
        stream = conn
        try:
            if in_rtlab and self.use_netns:
                with open('/run/netns/rtlab', 'rb') as target:
                    libc = ctypes.CDLL(None, use_errno=True)
                    if libc.setns(target.fileno(), 0) != 0:
                        raise OSError('twohop-worker-setns')
            conn.settimeout(REQUEST_TIMEOUT)
            if kind in ('https', 'https-untrusted'):
                ctx = self._trusted_ctx if kind == 'https' else self._untrusted_ctx
                try:
                    stream = ctx.wrap_socket(conn, server_side=True)
                except (OSError, ssl.SSLError):
                    self._record(kind=kind, listen=listen_addr, port=listen_port, client=client_ip,
                                 status='tls_error')
                    return
            if kind in ('socks5', 'socks5-auth'):
                self._serve_socks5(stream, kind, listen_addr, listen_port, client_ip, in_rtlab, stop_event)
            else:
                self._serve_http(stream, kind, listen_addr, listen_port, client_ip, in_rtlab, stop_event)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def _serve_http(self, stream, kind, listen_addr, listen_port, client_ip, in_rtlab, stop_event):
        buf = bytearray()
        while b'\r\n\r\n' not in buf:
            chunk = stream.recv(4096)
            if not chunk:
                return
            buf.extend(chunk)
            if len(buf) > 4096:
                return
        head_bytes, _, tail = bytes(buf).partition(b'\r\n\r\n')
        lines = head_bytes.decode('ascii', 'replace').split('\r\n')
        parts = lines[0].split(' ')
        if len(parts) != 3:
            return
        method, target, version = parts
        headers = {}
        raw_headers = []
        for line in lines[1:]:
            name, sep, value = line.partition(':')
            if sep:
                key = name.strip().lower()
                headers[key] = value.strip()
                if key not in ('proxy-authorization', 'proxy-connection'):
                    raw_headers.append(line)
        if kind == 'http-auth' and headers.get('proxy-authorization') != self._auth_header:
            stream.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                           b'Proxy-Authenticate: Basic realm="rosetun-lab"\r\n'
                           b'Content-Length: 0\r\nConnection: close\r\n\r\n')
            self._record(kind=kind, listen=listen_addr, port=listen_port, client=client_ip, status='auth_failed')
            return
        if method == 'CONNECT':
            host, port = _parse_host_port(target, 443)
            out, dst_ip, _, bind_addr = self._dial_outbound(host, port, in_rtlab)
            try:
                stream.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                if tail:
                    out.sendall(tail)
                self._record(kind=kind, listen=listen_addr, port=listen_port, client=client_ip,
                             target=f'{dst_ip}:{port}', out_source=bind_addr, status='ok')
                _relay_pair(stream, out, stop_event)
            finally:
                out.close()
            return
        if target.startswith('http://'):
            rest = target[7:]
            authority, slash, path = rest.partition('/')
            path = '/' + path if slash else '/'
            host, port = _parse_host_port(authority, 80)
        elif 'host' in headers:
            host, port = _parse_host_port(headers['host'], 80)
            path = target if target.startswith('/') else '/'
        else:
            return
        out, dst_ip, _, bind_addr = self._dial_outbound(host, port, in_rtlab)
        try:
            forwarded = (f'{method} {path} {version}\r\n' + '\r\n'.join(raw_headers) + '\r\n\r\n').encode('ascii')
            out.sendall(forwarded + tail)
            self._record(kind=kind, listen=listen_addr, port=listen_port, client=client_ip,
                         target=f'{dst_ip}:{port}', out_source=bind_addr, status='ok')
            _relay_pair(stream, out, stop_event)
        finally:
            out.close()

    def _serve_socks5(self, stream, kind, listen_addr, listen_port, client_ip, in_rtlab, stop_event):
        head = receive(stream, 2)
        if head[0] != 5:
            return
        methods = receive(stream, head[1])
        if kind == 'socks5-auth':
            if 2 not in methods:
                stream.sendall(b'\x05\xff')
                self._record(kind=kind, listen=listen_addr, port=listen_port, client=client_ip,
                             status='auth_method_rejected')
                return
            stream.sendall(b'\x05\x02')
            sub = receive(stream, 2)
            if sub[0] != 1:
                stream.sendall(b'\x01\x01')
                self._record(kind=kind, listen=listen_addr, port=listen_port, client=client_ip, status='auth_failed')
                return
            user = receive(stream, sub[1]).decode('utf-8', 'replace')
            plen = receive(stream, 1)[0]
            passwd = receive(stream, plen).decode('utf-8', 'replace')
            if (user, passwd) != (TWOHOP_USER, TWOHOP_PASSWORD):
                stream.sendall(b'\x01\x01')
                self._record(kind=kind, listen=listen_addr, port=listen_port, client=client_ip, status='auth_failed')
                return
            stream.sendall(b'\x01\x00')
        else:
            if 0 not in methods:
                stream.sendall(b'\x05\xff')
                return
            stream.sendall(b'\x05\x00')
        req = receive(stream, 4)
        ver, cmd, _, atyp = req
        if ver != 5:
            return
        if atyp == 1:
            host = socket.inet_ntoa(receive(stream, 4))
        elif atyp == 3:
            dlen = receive(stream, 1)[0]
            host = receive(stream, dlen).decode('ascii')
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, receive(stream, 16))
        else:
            stream.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            return
        port = int.from_bytes(receive(stream, 2), 'big')
        if cmd != 1:
            stream.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            self._record(kind=kind, listen=listen_addr, port=listen_port, client=client_ip,
                         target=f'{host}:{port}', status='cmd_unsupported')
            return
        out, dst_ip, family, bind_addr = self._dial_outbound(host, port, in_rtlab)
        try:
            local_ip, local_port = out.getsockname()[:2]
            if family == 4:
                reply = b'\x05\x00\x00\x01' + socket.inet_aton(local_ip) + struct.pack('!H', local_port)
            else:
                reply = b'\x05\x00\x00\x04' + socket.inet_pton(socket.AF_INET6, local_ip) + struct.pack('!H', local_port)
            stream.sendall(reply)
            self._record(kind=kind, listen=listen_addr, port=listen_port, client=client_ip,
                         target=f'{dst_ip}:{port}', out_source=bind_addr, status='ok')
            _relay_pair(stream, out, stop_event)
        finally:
            out.close()


_DHCP_TYPES = {1: 'discover', 2: 'offer', 3: 'request', 5: 'ack', 6: 'nak', 7: 'release', 8: 'inform'}


def dhcp_reply(packet, *, server_ip=GATEWAYS[4], client_ip=CLIENTS[4], dns_ip=RESOLVER,
               client_mac=MACS['test'], lease_seconds=DHCP_LEASE_SECONDS):
    """Build a deterministic RFC 2131 DHCPv4 reply for the lab test MAC; returns `(reply, event, broadcast)`."""
    if len(packet) < 240 or packet[0] != 1 or packet[1] != 1 or packet[2] != 6 or packet[236:240] != DHCP_MAGIC:
        return None, None, False
    expected_mac = bytes.fromhex(client_mac.replace(':', ''))
    if packet[28:34] != expected_mac:
        return None, None, False
    xid = packet[4:8]
    flags = int.from_bytes(packet[10:12], 'big')
    ciaddr = socket.inet_ntoa(packet[12:16])
    chaddr = packet[28:44]
    msg_type = requested_ip = server_id = None
    index = 240
    while index < len(packet):
        code = packet[index]
        index += 1
        if code == 0:
            continue
        if code == 255:
            break
        if index >= len(packet):
            break
        length = packet[index]
        index += 1
        value = packet[index:index + length]
        index += length
        if len(value) != length:
            break
        if code == 53 and length == 1:
            msg_type = value[0]
        elif code == 50 and length == 4:
            requested_ip = socket.inet_ntoa(value)
        elif code == 54 and length == 4:
            server_id = socket.inet_ntoa(value)
    if msg_type not in (1, 3, 7, 8):
        return None, None, False
    if msg_type == 3 and server_id is not None and server_id != server_ip:
        return None, None, False
    kind = _DHCP_TYPES[msg_type]
    if msg_type == 7:
        return None, dict(kind=kind, xid=xid.hex(), ciaddr=ciaddr, reply='none'), False
    if msg_type == 1:
        reply_type = 2
        yiaddr = client_ip
    elif msg_type == 8:
        reply_type = 5
        yiaddr = '0.0.0.0'
    else:
        wanted = requested_ip if requested_ip is not None else (ciaddr if ciaddr != '0.0.0.0' else client_ip)
        if wanted == client_ip:
            reply_type = 5
            yiaddr = client_ip
        else:
            reply_type = 6
            yiaddr = '0.0.0.0'
    reply_ciaddr = socket.inet_aton(ciaddr if msg_type == 8 else '0.0.0.0')
    header = (struct.pack('!BBBB4sHH', 2, 1, 6, 0, xid, 0, flags)
              + reply_ciaddr + socket.inet_aton(yiaddr) + socket.inet_aton(server_ip)
              + b'\x00\x00\x00\x00' + chaddr + bytes(192) + DHCP_MAGIC)
    options = bytearray()
    options += bytes([53, 1, reply_type])
    options += bytes([54, 4]) + socket.inet_aton(server_ip)
    if reply_type != 6:
        if msg_type != 8:
            options += bytes([51, 4]) + struct.pack('!I', lease_seconds)
            options += bytes([58, 4]) + struct.pack('!I', lease_seconds // 2)
            options += bytes([59, 4]) + struct.pack('!I', (lease_seconds * 7) // 8)
        options += bytes([1, 4]) + socket.inet_aton('255.255.255.0')
        options += bytes([3, 4]) + socket.inet_aton(server_ip)
        options += bytes([6, 4]) + socket.inet_aton(dns_ip)
    options.append(255)
    body = header + bytes(options)
    if len(body) < 300:
        body += bytes(300 - len(body))
    broadcast = (msg_type == 1 or ciaddr == '0.0.0.0' or bool(flags & 0x8000) or reply_type == 6)
    event = dict(kind=kind, xid=xid.hex(), ciaddr=ciaddr, requested=requested_ip,
                 reply=_DHCP_TYPES[reply_type], broadcast=broadcast)
    return body, event, broadcast


class DhcpServer:
    """Isolated RFC 2131 DHCPv4 server bound strictly to the lab wire interface."""

    def __init__(self, iface, state_path):
        self.iface = iface
        self.state_path = state_path
        self.stop = threading.Event()
        self.sock = None
        self.thread = None
        self.lock = threading.Lock()
        self.events = []
        self.dropped = 0

    def _flush_locked(self):
        try:
            atomic_json(self.state_path, dict(events=list(self.events), dropped=self.dropped))
        except OSError:
            pass

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.iface.encode('ascii') + b'\x00')
        sock.bind(('0.0.0.0', DHCP_SERVER_PORT))
        sock.setblocking(False)
        self.sock = sock
        with self.lock:
            self._flush_locked()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self.stop.is_set():
            ready, _, _ = select.select([self.sock], [], [], 0.1)
            if not ready:
                continue
            try:
                packet, peer = self.sock.recvfrom(2048)
            except OSError:
                return
            reply, event, broadcast = dhcp_reply(packet)
            if reply is not None:
                target = ('255.255.255.255', DHCP_CLIENT_PORT) if broadcast else (peer[0], DHCP_CLIENT_PORT)
                try:
                    self.sock.sendto(reply, target)
                except OSError:
                    pass
            if event is not None:
                with self.lock:
                    if len(self.events) < DHCP_EVENT_LIMIT:
                        self.events.append({**event, 'peer': peer[0], 'at': round(time.time(), 3)})
                    else:
                        self.dropped += 1
                    self._flush_locked()

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(2)
            self.thread = None
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


def fixture_state(directory):
    """Live extended-fixture state snapshot (public key, service statuses, HTTPS/TwoHop/DHCP counts)."""
    state = {}
    base = directory / 'fixture-state.json'
    if base.exists():
        state.update(json.loads(base.read_bytes()))
    for key, filename in (('https', 'https-state.json'), ('twohop', 'twohop-state.json'), ('dhcp', 'dhcp-state.json')):
        path = directory / filename
        if path.exists():
            state[key] = json.loads(path.read_bytes())
    return state


def fixture_control(directory, action):
    """Request the running observer to stop or start a named lab fixture service mid-run."""
    if (type(action) is not dict or set(action) != {'service', 'state'}
            or action['service'] not in CONTROL_SERVICES or action['state'] not in CONTROL_STATES):
        raise ValueError('invalid-fixture-control')
    req_id = uuid.uuid4().hex[:16]
    req_path = directory / 'control-req.json'
    rep_path = directory / 'control-rep.json'
    atomic_json(req_path, dict(id=req_id, service=action['service'], state=action['state']))
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if rep_path.exists():
            try:
                reply = json.loads(rep_path.read_bytes())
            except (OSError, ValueError):
                reply = None
            if type(reply) is dict and reply.get('id') == req_id:
                return reply
        time.sleep(0.05)
    raise ValueError('fixture-control-timeout')


def bind_targets(request, tunnel, selector, sockets, dns_sockets):
    """Bind every service of the routed namespace and register the ones the loop reads.

    Returns the TLS context of the HTTPS target and, with DNS, the servers the threads run
    as (UDP, TCP, DoH listener, DoH context).
    """
    context = servers = None
    # Switch only this process's thread into the disposable target namespace.
    with open('/proc/self/ns/net', 'rb') as original, open('/run/netns/rtlab', 'rb') as target:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.setns(target.fileno(), 0) != 0:
            raise OSError('target-setns')
        try:
            for family in (4, 6):
                for service in SERVICES:
                    tcp = service in ('http', 'dns-tcp')
                    stream = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6,
                                           socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
                    sockets.append(stream)
                    stream.bind((TARGETS[family], PORTS[service]))
                    if tcp:
                        stream.listen(4)
                    selector.register(stream, selectors.EVENT_READ, (family, service))
            stream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sockets.append(stream)
            stream.bind((TARGETS[4], PORTS['marker']))
            selector.register(stream, selectors.EVENT_READ, (4, 'marker'))
            if tunnel is not None:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(str(HTTPS_CERT), str(HTTPS_KEY))
                stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sockets.append(stream)
                stream.bind((TARGETS[4], HTTPS_PORT))
                stream.listen(4)
                selector.register(stream, selectors.EVENT_READ, (4, 'https'))
            if request.get('dns') is True:
                # Served by threads of their own, so a slow client never delays the capture.
                doh_tls = doh_context()
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                doh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dns_sockets.extend((udp, tcp, doh))
                udp.bind((RESOLVER, 53))
                tcp.bind((RESOLVER, 53))
                tcp.listen(4)
                doh.bind((DOH_ADDRESS, 443))
                doh.listen(4)
                servers = (udp, tcp, doh, doh_tls)
        finally:
            if libc.setns(original.fileno(), 0) != 0:
                raise OSError('router-setns')
    return context, servers


def answer_exchange(listener, family, service, request):
    """Read one request of a target service, answer it and return the row for the target log."""
    tcp = service in ('http', 'dns-tcp')
    connection = None
    try:
        if tcp:
            connection, peer = listener.accept()
            connection.settimeout(REQUEST_TIMEOUT)
            if service == 'dns-tcp':
                size = int.from_bytes(receive(connection, 2), 'big')
                if size > 1024:
                    raise ValueError('request-limit')
                data = receive(connection, size)
            else:
                data = connection.recv(1024)
        else:
            data, peer = listener.recvfrom(1024)
        matches = [p for p in request['probes'] if p['family'] == family and p['service'] == service
                   and p['source'] == peer[0] and (query(p) == data if service != 'http'
                   else data == b'GET /' + token(p) + b' HTTP/1.0\r\n\r\n')]
        if len(matches) != 1:
            raise ValueError('unexpected-request')
        p = matches[0]
        response = answer(p)
        if service == 'http':
            wire = b'HTTP/1.0 200 OK\r\nContent-Length: ' + str(len(response)).encode() + b'\r\n\r\n' + response
        elif service == 'dns-tcp':
            wire = struct.pack('!H', len(response)) + response
        else:
            wire = response
        if tcp:
            connection.sendall(wire)
        else:
            listener.sendto(wire, peer)
        return {**p, 'response': response.hex()}
    finally:
        if connection is not None:
            connection.close()


def exchanges_done(request, marks, logs):
    """The moment a control may act: the opening is served and every expected exchange has its answer."""
    answered = {row['nonce'] for row in logs if 'reason' not in row}
    return (bool(marks) and marks[0]['word'] == 'open'
            and {p['nonce'] for p in request['probes']} <= answered)


def observer_alive(pid, lab_id):
    """Whether `pid` is still the observer of this run, and not a zombie or a process that took its number."""
    try:
        state = Path('/proc/%d/stat' % pid).read_text().rpartition(')')[2].split()[0]
        arguments = Path('/proc/%d/cmdline' % pid).read_bytes().split(b'\0')
        served = json.loads(arguments[-2])
    except (OSError, ValueError, IndexError):
        return False
    return (state not in ('Z', 'X') and type(served) is dict and served.get('operation') == 'serve'
            and served.get('lab_id') == lab_id)


def serve(request, directory):
    deadline = time.monotonic() + request.get('duration_seconds', DURATION)
    logs, dropped, marks, ended, started = [], 0, [], None, None
    failure, place = Failure(), 'setup'
    tunnel = tunnel_of(request)
    extended = extended_fixtures_of(request)
    protocols_enabled = bool(extended and extended.get('protocols') is True)
    second_node_enabled = bool(extended and extended.get('second_node') is True)
    xray_enabled = bool(extended and extended.get('xray') is True)
    two_hop_enabled = bool(extended and extended.get('two_hop') is True)
    dhcp_enabled = bool(extended and extended.get('dhcp') is True)
    poller = poller_of(request)
    poller_log, poller_stop, poller_thread, poller_key = PollerLog(), threading.Event(), None, directory / 'poller.key'
    https_log, node, node_state, context, servers = [], None, None, None, None
    second_node = xray_proc = reality_cover = twohop = dhcp_server = None
    reality_public_key = None
    # An L3 run counts what the script asks of the HTTPS target; its connections run on threads.
    https_state_path = directory / 'https-state.json' if extended is not None else None
    https_requests = HttpsLog(state_path=https_state_path) if l3_mode(request) else None
    https_workers = None
    dns = request.get('dns') is True
    dns_log, dns_stop, dns_threads, dns_sockets = DnsLog(aggregate=extended is not None), threading.Event(), [], []
    lan_enabled = request.get('lan_fixtures') is True
    lan_fixtures = LanFixtures(directory / 'lan-fixtures.json') if lan_enabled else None
    node_extra_addresses = (ROUTED_NODE,) if lan_enabled else ()
    node_extra_tcp = (ANYTLS_PORT,) if protocols_enabled else ()
    node_udp_ports = (HYSTERIA2_PORT, TUIC_PORT) if protocols_enabled else ()
    selector = selectors.DefaultSelector()
    capture = raw = None
    # The diagnostic count of the link behind the node: its own socket and thread, and nothing the observer needs.
    route = route_thread = None
    route_flows, route_state, route_stop = RouteFlows(), {}, threading.Event()
    disk = request.get('evidence_disk') is True
    limit = EVIDENCE_PCAP_LIMIT if disk else CAPTURE_LIMIT
    count = 24
    sockets = []

    def write_fixture_state():
        if extended is None:
            return
        services = dict(
            primary_node=node is not None and node.poll() is None,
            second_node=second_node is not None and second_node.poll() is None,
            xray=xray_proc is not None and xray_proc.poll() is None,
            twohop_b=bool(twohop is not None and twohop.running),
        )
        payload = dict(services=services)
        if reality_public_key is not None:
            payload['reality_public_key'] = reality_public_key
        atomic_json(directory / 'fixture-state.json', payload)

    def handle_control_request():
        nonlocal node, second_node, xray_proc
        req_path = directory / 'control-req.json'
        if not req_path.exists():
            return
        try:
            req = json.loads(req_path.read_bytes())
        except (OSError, ValueError):
            return
        try:
            req_path.unlink()
        except OSError:
            pass
        req_id = req.get('id')
        service = req.get('service')
        state = req.get('state')
        reply = dict(id=req_id, ok=True, service=service, state=state, running=False, reason='ok')
        try:
            if service == 'primary_node':
                if state == 'stop':
                    if node is not None:
                        stop_process(node)
                        node = None
                    reply['running'] = False
                else:
                    if node is None or node.poll() is not None:
                        node = start_process(None, directory, 'node', GATEWAYS[4], tunnel['port'],
                                             extra_addresses=node_extra_addresses, extra_tcp_ports=node_extra_tcp,
                                             udp_ports=node_udp_ports, reuse_config=True)
                    reply['running'] = True
            elif service == 'second_node':
                if not second_node_enabled:
                    reply.update(ok=False, reason='service-not-enabled')
                elif state == 'stop':
                    if second_node is not None:
                        stop_process(second_node)
                        second_node = None
                    reply['running'] = False
                else:
                    if second_node is None or second_node.poll() is not None:
                        second_node = start_process(None, directory, 'second-node', GATEWAYS[4],
                                                    SECOND_NODE_PORT, reuse_config=True)
                    reply['running'] = True
            elif service == 'xray':
                if not xray_enabled:
                    reply.update(ok=False, reason='service-not-enabled')
                elif state == 'stop':
                    if xray_proc is not None:
                        stop_process(xray_proc)
                        xray_proc = None
                    reply['running'] = False
                else:
                    if xray_proc is None or xray_proc.poll() is not None:
                        xray_proc = start_process(None, directory, 'xray', GATEWAYS[4], REALITY_PORT,
                                                  extra_tcp_ports=(XHTTP_PORT,), binary=XRAY_BINARY,
                                                  reuse_config=True)
                    reply['running'] = True
            elif service == 'twohop_b':
                if not two_hop_enabled or twohop is None:
                    reply.update(ok=False, reason='service-not-enabled')
                elif state == 'stop':
                    twohop.stop_listeners()
                    reply['running'] = False
                else:
                    twohop.start_listeners()
                    reply['running'] = True
            else:
                reply.update(ok=False, reason='unsupported-service')
        except Exception as error:
            reply.update(ok=False, reason=short_code(error))
        write_fixture_state()
        atomic_json(directory / 'control-rep.json', reply)

    def record(frame):
        nonlocal count
        if len(frame) > 2048 or count + 16 + len(frame) > limit:
            raise ValueError('capture-limit')
        now = time.time()
        raw.write(struct.pack('<IIII', int(now), int(now % 1 * 1000000), len(frame), len(frame)) + frame)
        count += 16 + len(frame)
        if lan_fixtures is not None:
            lan_fixtures.inspect_frame(frame)

    def settle(operation):
        """Run a closing step; its failure is noted and the steps after it still run."""
        try:
            operation()
        except Exception as error:
            failure.note('finish', error)

    def close_pcap():
        if raw is None:
            return
        if disk:
            raw.finish(complete=not failure)
            return
        try:
            raw.flush()
            os.fsync(raw.fileno())
        finally:
            raw.close()

    def write_node_log():
        with (directory / 'node.log').open('xb') as stream:
            stream.write(node_log(*read_tail(directory / 'node.stderr', NODE_LOG_READ)))

    try:
        place = 'capture'
        capture = (open_capture(request['interface'], allmulti=True) if lan_enabled
                   else open_capture(request['interface']))
        started = time.monotonic()
        selector.register(capture, selectors.EVENT_READ, 'capture')
        raw = EvidenceWriter(evidence_device(), request['lab_id']) if disk else (directory / 'capture.pcap').open('xb')
        raw.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 2048, 1))
        place = 'setup'
        context, servers = bind_targets(request, tunnel, selector, sockets, dns_sockets)
        if lan_fixtures is not None:
            lan_fixtures.bind(selector)
        if https_requests is not None and context is not None:
            https_workers = HttpsWorkers(context, request, https_requests)
        if extended is not None:
            check_extended_fixtures(extended)
        if tunnel is not None:
            # Alive and listening, before the observer says it is ready.
            check_lab_fixtures(tunnel, request.get('certificates'))
            place = 'node'
            if lan_enabled or protocols_enabled or two_hop_enabled:
                node = start_process(node_config(tunnel, lan_fixtures=lan_enabled, protocols=protocols_enabled,
                                                 dns_resolver=two_hop_enabled),
                                     directory, 'node', GATEWAYS[4], tunnel['port'],
                                     extra_addresses=node_extra_addresses, extra_tcp_ports=node_extra_tcp,
                                     udp_ports=node_udp_ports)
            else:
                node = start_process(node_config(tunnel), directory, 'node', GATEWAYS[4], tunnel['port'])
            place = 'setup'
        if second_node_enabled:
            place = 'node'
            second_node = start_process(second_node_config(tunnel), directory, 'second-node', GATEWAYS[4],
                                        SECOND_NODE_PORT)
            place = 'setup'
        if xray_enabled:
            place = 'node'
            reality_cover = RealityCoverServer()
            reality_cover.start()
            reality_private_key, reality_public_key = generate_reality_keys()
            xray_proc = start_process(xray_config(reality_private_key), directory, 'xray', GATEWAYS[4],
                                      REALITY_PORT, extra_tcp_ports=(XHTTP_PORT,), binary=XRAY_BINARY)
            place = 'setup'
        if two_hop_enabled:
            twohop = TwoHopProxy(directory / 'twohop-state.json')
            twohop.start_listeners()
        if dhcp_enabled:
            dhcp_server = DhcpServer(request['interface'], directory / 'dhcp-state.json')
            dhcp_server.start()
        if dns:
            udp, tcp, doh, doh_tls = servers
            dns_threads = [threading.Thread(target=guarded, args=('dns', failure, dns_loop, udp, tcp, dns_log, dns_stop),
                                            daemon=True),
                           threading.Thread(target=guarded, args=('doh', failure, doh_loop, doh, doh_tls, dns_log, dns_stop),
                                            daemon=True)]
            for thread in dns_threads:
                thread.start()
        if request.get('route_flows') is True:
            try:
                route = open_capture(ROUTE_INTERFACE)
                route_thread = threading.Thread(target=route_count, args=(route, route_flows, route_stop, route_state),
                                                daemon=True)
                route_thread.start()
            except Exception:
                route_state['error'] = 'route-capture-unavailable'
        if poller is not None:
            # The key lives on this machine's tmpfs for the length of the capture and is removed with it.
            descriptor = os.open(poller_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w', encoding='ascii') as stream:
                stream.write(poller['private_key'])
            poller_thread = threading.Thread(target=guarded, args=('poller', failure, poller_loop, poller_key,
                                                                   poller_log, poller_stop), daemon=True)
            poller_thread.start()
        write_fixture_state()
        write(directory / 'ready.json', {'capture_ready': True})
        while time.monotonic() < deadline and not (directory / 'stop').exists():
            if extended is not None:
                handle_control_request()
            for key, _ in selector.select(.1):
                if key.data == 'capture':
                    place = 'capture'
                    record(capture.recv(2049))
                    continue
                family, service = key.data
                if family == 'lan':
                    place = 'lan'
                    lan_fixtures.accept(key.fileobj, service)
                    continue
                # A bad exchange is the exchange's failure: it is closed and logged as a refusal, and the
                # capture goes on. Only what the observer itself does (capture, limits, deadline) stops it.
                if service == 'https':
                    place = 'https'
                    if https_workers is not None:
                        https_workers.accept(key.fileobj)
                        continue
                    connection = None
                    try:
                        connection, peer = key.fileobj.accept()
                        row = https_exchange(connection, peer, context, request)
                    except Exception as error:
                        refuse(https_log, 'https', 4, error)
                    else:
                        record_https(https_log, row)
                    finally:
                        if connection is not None:
                            connection.close()
                    continue
                if service == 'marker':
                    place = 'marker'
                    try:
                        data, peer = key.fileobj.recvfrom(1024)
                        if request.get('windows') is True:
                            index, word, label = accept_window_marker(request, marks, data, peer[0])
                            key.fileobj.sendto(ACK_PREFIX.encode('ascii') + data, peer)
                            marks.append(dict(word=word, index=index, label=label, at=time.monotonic()))
                        else:
                            marker = accept_marker(request, marks, data, peer[0])
                            key.fileobj.sendto(marker_answer(marker), peer)
                            marks.append(dict(word=marker['word'], nonce=marker['nonce'], at=time.monotonic()))
                    except Exception as error:
                        refuse(logs, 'marker', 4, error)
                    continue
                place = EXCHANGE_PLACES[service]
                try:
                    row = answer_exchange(key.fileobj, family, service, request)
                except Exception as error:
                    refuse(logs, service, family, error)
                    continue
                logs.append(row)
                if sum('reason' not in entry for entry in logs) > 8 or len(json.dumps(logs)) > LOG_LIMIT:
                    raise ValueError('target-log-limit')
                # The control acts only once the last answer is out; the test machine's exchanges are over then.
                if 'control' in request and exchanges_done(request, marks, logs):
                    (directory / 'exchanges-done').touch()
        place = 'finish'
        if time.monotonic() >= deadline:
            raise ValueError('capture-deadline')
        if node is not None:
            # Whether the node was still there at finish, then its exit code.
            place = 'node'
            alive, code = stop_process(node)
            node_state = dict(alive_at_finish=alive, exit_code=code)
        # Frames queued since the last poll still belong to the window.
        place = 'capture'
        while True:
            try:
                frame = capture.recv(2049)
            except BlockingIOError:
                break
            record(frame)
        ended = time.monotonic()
        # Linux PACKET_STATISTICS reports kernel drops, not just process success.
        _, dropped = struct.unpack('II', capture.getsockopt(263, 6, 8))
    except BaseException as error:
        failure.note(place, error)
    finally:
        settle(close_pcap)
        selector.close()
        if capture is not None:
            capture.close()
        if dhcp_server is not None:
            dhcp_server.close()
        if twohop is not None:
            twohop.stop_listeners()
        if second_node is not None:
            try:
                stop_process(second_node)
            except Exception as error:
                failure.note('node', error)
        if xray_proc is not None:
            try:
                stop_process(xray_proc)
            except Exception as error:
                failure.note('node', error)
        if reality_cover is not None:
            reality_cover.close()
        if lan_fixtures is not None:
            lan_fixtures.close()
        for stream in sockets:
            stream.close()
        dns_stop.set()
        for thread in dns_threads:
            thread.join(2)
        for stream in dns_sockets:
            stream.close()
        extra = {}
        poller_stop.set()
        if poller_thread is not None:
            poller_thread.join(POLL_TIMEOUT + 2)
        if poller is not None:
            try:
                poller_key.unlink()
            except OSError:
                pass
            settle(lambda: write(directory / 'poller.json', poller_log.rows))
            if poller_log.overflow:
                failure.note('poller', ValueError('poller-log-limit'))
        route_stop.set()
        if route_thread is not None:
            route_thread.join(2)
        if route is not None:
            try:
                # Kernel drops of the route socket are a fact about the count, not a fault of the observer.
                route_state['dropped'] = struct.unpack('II', route.getsockopt(263, 6, 8))[1]
            except OSError:
                pass
            route.close()
        if request.get('route_flows') is True:
            # Written before health.json, which is what the finish waits for; a failure here is the diagnostic's own.
            try:
                write_route_flows(directory / 'route-flows.json', route_flows, route_state)
            except Exception:
                pass
        if dns:
            settle(lambda: write(directory / 'dns.json', dns_log.rows))
            if dns_log.overflow:
                failure.note(dns_log.overflow_in, ValueError('dns-log-limit'))
        if tunnel is not None:
            if node is not None and node_state is None:
                try:
                    alive, code = stop_process(node)
                    node_state = dict(alive_at_finish=alive, exit_code=code)
                except Exception as error:
                    failure.note('node', error)
            if https_workers is not None:
                https_workers.drain(2 * REQUEST_TIMEOUT)
            settle(lambda: write(directory / 'https.json',
                                 https_requests.document() if https_requests is not None else https_log))
            settle(write_node_log)
            extra['node'] = node_state or dict(alive_at_finish=False, exit_code=None)
        settle(lambda: write(directory / 'targets.json', logs))
        # Times are this machine's monotonic clock; a failed run records no end.
        health = dict(error=bool(failure), dropped=dropped, finished=True, capture_started=started,
                      capture_ended=ended, markers=marks, **extra)
        if (directory / 'halted').exists():
            # Only the control's `halt` leaves this: the capture ended because it was told to, inside the window.
            health['halted'] = True
        if failure:
            health.update(error_reason=failure.reason, error_at=failure.at, error_in=failure.where)
        write(directory / 'health.json', health)
    if failure or dropped:
        raise ValueError('observer-unverified')


def main(request):
    iface = identity(request)
    directory = ROOT / request['lab_id']
    operation = request['operation']
    if operation == 'setup' and request['role'] == 'lab':
        ROOT.mkdir(mode=0o700, exist_ok=True)
        # A single claim per boot prevents replay into another run or namespace.
        write(ROOT / 'claim.json', redacted(request))
        directory.mkdir(mode=0o700)
        write(directory / 'identity.json', redacted(request))
        setup(request, iface, directory)
        return dict(capture_ready=True)
    if operation == 'probe' and request['role'] == 'test':
        ROOT.mkdir(mode=0o700, exist_ok=True)
        write(ROOT / 'claim.json', request)
        return probe_all(request)
    saved = json.loads((directory / 'identity.json').read_bytes())
    if any(saved[k] != request[k] for k in ('lab_id', 'role', 'vm_uuid', 'boot_id', 'probes', 'markers')):
        raise ValueError('wrong-run')
    shown = redacted(request)
    if any(saved.get(key) != shown.get(key) for key in ('tunnel', 'dns', 'dns_check', 'evidence_disk',
                                                     'duration_seconds', 'windows', 'certificates',
                                                     'route_flows', 'control', 'poller', 'lan_fixtures',
                                                     'extended_fixtures')):
        raise ValueError('wrong-run')
    if request['role'] == 'lab' and operation == 'serve':
        if request.get('interface') != iface:
            raise ValueError('wrong-capture-interface')
        serve(request, directory)
        return {}
    if request['role'] == 'lab' and operation == 'probe_proxy' and request.get('lan_fixtures') is True:
        return probe_proxy(request.get('action'))
    if request['role'] == 'lab' and operation == 'lan_state' and request.get('lan_fixtures') is True:
        return lan_state(directory)
    if request['role'] == 'lab' and operation == 'fixture_state' and extended_fixtures_of(request) is not None:
        return fixture_state(directory)
    if request['role'] == 'lab' and operation == 'fixture_control' and extended_fixtures_of(request) is not None:
        return fixture_control(directory, request.get('action'))
    if request['role'] == 'lab' and operation == 'window' and 'control' in request:
        return dict(exchanges_done=(directory / 'exchanges-done').exists())
    if request['role'] == 'lab' and operation == 'halt' and request.get('control') == 'observer-stopped':
        # The control stops the observer between the markers; `finish` then finds it stopped.
        (directory / 'halted').touch(exist_ok=False)
        (directory / 'stop').touch(exist_ok=False)
        for _ in range(50):
            if (directory / 'health.json').exists():
                return dict(halted=True)
            time.sleep(.1)
        raise ValueError('observer-stop-timeout')
    if request['role'] == 'lab' and operation == 'halt' and request.get('control') == 'observer-killed':
        # No stop file and no health.json: the observer gets no chance to say anything.
        pid = int((directory / 'observer.pid').read_text())
        if not observer_alive(pid, request['lab_id']):
            raise ValueError('observer-not-running')
        os.kill(pid, signal.SIGKILL)
        for _ in range(50):
            if not observer_alive(pid, request['lab_id']):
                return dict(halted=True)
            time.sleep(.1)
        raise ValueError('observer-kill-timeout')
    if request['role'] == 'lab' and operation == 'finish' and request.get('control') == 'observer-killed':
        pid_file = directory / 'observer.pid'
        if (pid_file.exists() and not (directory / 'health.json').exists()
                and not observer_alive(int(pid_file.read_text()), request['lab_id'])):
            # Nothing to wait for: the observer is gone and will never write its health.
            return dict(finished=True, observer_gone=True)
    if request['role'] == 'lab' and operation == 'finish':
        time.sleep(.3)
        (directory / 'stop').touch(exist_ok=request.get('control') == 'observer-stopped')
        # A 60 MiB capture takes a while to reach the disk.
        for _ in range(150 if request.get('evidence_disk') is True else 50):
            if (directory / 'health.json').exists():
                return dict(finished=True)
            time.sleep(.1)
        raise ValueError('observer-stop-timeout')
    raise ValueError('unsupported-operation')


if __name__ == '__main__':
    try:
        request = json.loads(sys.argv[1])
        output = main(request)
        print(json.dumps(dict(lab_id=request['lab_id'], boot_id=request['boot_id'], **output)))
    except Refused as error:
        print('lab-helper-failed:' + str(error), file=sys.stderr)
        sys.exit(2)
    except Exception as error:
        print('lab-helper-failed:' + failure_code(error), file=sys.stderr)
        sys.exit(2)
