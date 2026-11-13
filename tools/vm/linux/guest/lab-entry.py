#!/usr/bin/python3
"""Owner-installed root-only lab entry. Never invoked on the controller host."""
import ctypes
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
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
                          dns_name, plain_reply_ok)

ROOT = Path('/run/rosetun-lab')
ENTRY = '/usr/local/libexec/rosetun-lab/entry'
# Stage 7b1 fixtures. The paths are fixed here; a missing or different file is a refusal.
LIBEXEC = Path('/usr/local/libexec/rosetun-lab')
NODE_BINARY = LIBEXEC / 'sing-box'
HTTPS_CERT = LIBEXEC / 'https-cert.pem'
HTTPS_KEY = LIBEXEC / 'https-key.pem'
CA_CERT = Path('/usr/local/share/ca-certificates/rosetun-lab-ca.crt')
# Stage 7b2a: the DoH target's certificate (SAN doh.lab.test and 203.0.113.3), signed by the same lab CA.
DOH_CERT = LIBEXEC / 'doh-cert.pem'
DOH_KEY = LIBEXEC / 'doh-key.pem'
# Stage 7b2a: the evidence disk is found by its serial and by nothing else.
EVIDENCE_DEVICE = Path('/dev/disk/by-id/virtio-rosetun-lab-evidence')
DOH_REQUESTS = 16
DOH_CONNECTIONS = 8
HTTPS_LOG_ENTRIES = 16
TUNNEL_KEYS = {'port', 'method', 'password', 'sing_box_sha256', 'ca_sha256', 'https'}
HTTPS_KEYS = {'run_id', 'nonce', 'kind', 'family', 'protocol', 'source', 'target', 'port', 'path'}
lstat = os.lstat


class Refused(ValueError):
    """A fixed, data-free reason the helper prints instead of a bare failure."""


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
    if 'dns_check' in request:
        dns_check_of(request)
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


def write(path, value):
    raw = json.dumps(value).encode()
    if len(raw) > LOG_LIMIT:
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


def probe_exchanges(request):
    replies = []
    for p in request['probes']:
        family = socket.AF_INET if p['family'] == 4 else socket.AF_INET6
        tcp = p['protocol'] == 'tcp'
        with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as stream:
            stream.settimeout(2)
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
            replies.append({**p, 'response': response.hex()})
    return replies


def exchange_marker(marker):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(2)
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        sock.bind((direct['source'], 0))
        sock.connect((direct['target'], direct['port']))
        client_port = sock.getsockname()[1]
        direct_response = https_get(sock, direct, context)
    directory = ROOT / request['lab_id']
    directory.mkdir(mode=0o700, exist_ok=True)
    client = start_process(client_config(tunnel), directory, 'client', '127.0.0.1', SOCKS_PORT)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect(('127.0.0.1', SOCKS_PORT))
            socks_connect(sock, via_node['target'], via_node['port'])
            tunnel_response = https_get(sock, via_node, context)
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


def probe_dns(request):
    """dns-plain over UDP, then dns-doh-singbox: a sing-box client that resolves through the node and DoH."""
    checks = request['dns_check']
    plain, doh = checks['plain'], checks['doh']
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.bind((plain['source'], 0))
        sock.connect((plain['target'], plain['port']))
        sock.send(query(plain))
        reply = sock.recv(512)
    if not plain_reply_ok(plain, reply):
        raise ValueError('unexpected-resolver-answer')
    directory = ROOT / request['lab_id']
    directory.mkdir(mode=0o700, exist_ok=True)
    client = start_process(dns_client_config(request['tunnel']), directory, 'dns-client', '127.0.0.1', SOCKS_PORT)
    context = ssl.create_default_context()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(('127.0.0.1', SOCKS_PORT))
            socks_connect_domain(sock, dns_name(doh), doh['port'])
            doh_response = https_get(sock, doh, context)
    finally:
        _, client_exit = stop_process(client)
        stderr = directory / 'dns-client.stderr'
        client_log = scrub_log(stderr.read_bytes() if stderr.exists() else b'')[:4096]
    return dict(plain=dict(plain, response=reply.hex()), doh=dict(doh, response=doh_response.hex()),
                client_exit=client_exit, client_log=client_log)


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
    marker_replies.append(exchange_marker(opening))
    replies = probe_exchanges(request)
    https = probe_tunnel(request) if tunnel is not None else None
    dns = probe_dns(request) if 'dns_check' in request else None
    if request['canary']:
        send_canary()
    # Let the last connection finish closing on the wire before the window ends.
    time.sleep(.2)
    sent['close'] = time.monotonic()
    marker_replies.append(exchange_marker(closing))
    return dict(replies=replies, marker_replies=marker_replies, marker_sent=sent,
                **({'https': https} if https is not None else {}), **({'dns': dns} if dns is not None else {}))


def node_config(tunnel):
    """The node: one Shadowsocks inbound on the lab address, direct out, no DNS and no other inbound."""
    return {'log': {'level': 'warn', 'timestamp': False},
            'inbounds': [{'type': 'shadowsocks', 'tag': 'node-in', 'listen': GATEWAYS[4],
                          'listen_port': tunnel['port'], 'method': tunnel['method'],
                          'password': tunnel['password']}],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}],
            'route': {'final': 'direct'}}


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


def scrub_log(raw):
    """A bounded sing-box log with every address outside the documentation ranges blanked."""
    text = raw[:LOG_LIMIT].decode('utf-8', 'replace')

    def keep(match):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            return '[address]'
        return match.group(0) if any(address in net for net in LAB_NETWORKS) else '[address]'

    text = re.sub(r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]*:[0-9a-fA-F]*', keep, text)
    return text.encode('utf-8')[:LOG_LIMIT]


def listening(address, port, table='/proc/net/tcp'):
    key = '%s:%04X' % (socket.inet_aton(address)[::-1].hex().upper(), port)
    for line in Path(table).read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) > 3 and fields[1] == key and fields[3] == '0A':
            return True
    return False


def spawn(config_path, log_path):
    """sing-box in its own session; its stderr goes to a file this helper reads back, bounded."""
    with log_path.open('xb') as log:
        return subprocess.Popen([str(NODE_BINARY), 'run', '-c', str(config_path)],
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


def start_process(config, directory, name, address, port):
    """Write the configuration, start sing-box and wait until it is alive and listening."""
    write(directory / (name + '.json'), config)
    process = spawn(directory / (name + '.json'), directory / (name + '.stderr'))
    for _ in range(50):
        if process.poll() is not None:
            raise Refused(name + '-exited')
        if listening(address, port):
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


def setup(request, iface, directory):
    # The role, VM, boot and one-shot run claim are checked before any mutation.
    tunnel = tunnel_of(request)
    if tunnel is not None:
        check_lab_fixtures(tunnel, request.get('certificates'))
    if request.get('dns') is True:
        check_dns_fixtures(request.get('certificates'))
    if request.get('evidence_disk') is True:
        evidence_device()
    command('/usr/sbin/ip', 'addr', 'add', GATEWAYS[4] + '/24', 'dev', iface)
    command('/usr/sbin/ip', '-6', 'addr', 'add', GATEWAYS[6] + '/64', 'dev', iface, 'nodad')
    command('/usr/sbin/ip', 'link', 'set', iface, 'up')
    command('/usr/sbin/ip', 'netns', 'add', 'rtlab')
    command('/usr/sbin/ip', 'link', 'add', 'rt-route', 'type', 'veth', 'peer', 'name', 'rt-target')
    command('/usr/sbin/ip', 'link', 'set', 'rt-target', 'netns', 'rtlab')
    for flag, gateway in (('', '203.0.113.1/24'), ('-6', '2001:db8:6a:2::1/64')):
        prefix = ['/usr/sbin/ip'] + ([flag] if flag else [])
        command(*prefix, 'addr', 'add', gateway, 'dev', 'rt-route', *(['nodad'] if flag else []))
    command('/usr/sbin/ip', 'link', 'set', 'rt-route', 'up')
    ns = ['/usr/sbin/ip', 'netns', 'exec', 'rtlab']
    command(*ns, '/usr/sbin/ip', 'link', 'set', 'lo', 'up')
    command(*ns, '/usr/sbin/ip', 'addr', 'add', TARGETS[4] + '/24', 'dev', 'rt-target')
    command(*ns, '/usr/sbin/ip', '-6', 'addr', 'add', TARGETS[6] + '/64', 'dev', 'rt-target', 'nodad')
    if request.get('dns') is True:
        for address in (RESOLVER, DOH_ADDRESS):
            command(*ns, '/usr/sbin/ip', 'addr', 'add', address + '/24', 'dev', 'rt-target')
    command(*ns, '/usr/sbin/ip', 'link', 'set', 'rt-target', 'up')
    command(*ns, '/usr/sbin/ip', 'route', 'add', '192.0.2.0/24', 'via', '203.0.113.1')
    command(*ns, '/usr/sbin/ip', '-6', 'route', 'add', '2001:db8:6a:1::/64', 'via', '2001:db8:6a:2::1')
    Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
    Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1')
    # Capture stays in the router namespace; services run in the routed namespace.
    child = subprocess.Popen([ENTRY, json.dumps({**request, 'operation': 'serve', 'interface': iface})],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    # The node and its listener start inside the observer, so they get a little longer.
    for _ in range(100 if tunnel is not None else 50):
        if child.poll() is not None:
            raise ValueError('observer-start-failed')
        if (directory / 'ready.json').exists():
            return
        time.sleep(.1)
    raise ValueError('capture-ready-timeout')


class DnsLog:
    """The rows of dns.json: source, transport, name and type, bounded by count and size."""

    def __init__(self):
        self.rows, self.lock, self.overflow = [], threading.Lock(), False

    def record(self, source, transport, entry):
        with self.lock:
            self.rows.append(dict(source=source, transport=transport, name=entry[0], type=entry[1]))
            if len(self.rows) > DNS_LOG_ENTRIES or len(json.dumps(self.rows)) > LOG_LIMIT:
                self.rows.pop()
                self.overflow = True


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
        connection.settimeout(1)
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
        connection.settimeout(5)
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
    connection.settimeout(1)
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


def record_https(log, row):
    log.append(row)
    if len(log) > HTTPS_LOG_ENTRIES or len(json.dumps(log)) > LOG_LIMIT:
        raise ValueError('https-log-limit')


def serve(request, directory):
    deadline = time.monotonic() + request.get('duration_seconds', DURATION)
    logs, error, dropped, marks, ended = [], False, 0, [], None
    tunnel = tunnel_of(request)
    https_log, node, node_state, context = [], None, None, None
    dns = request.get('dns') is True
    dns_log, dns_stop, dns_threads, dns_sockets = DnsLog(), threading.Event(), [], []
    selector = selectors.DefaultSelector()
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
    capture.bind((request['interface'], 0))
    capture.setblocking(False)
    started = time.monotonic()
    selector.register(capture, selectors.EVENT_READ, 'capture')
    disk = request.get('evidence_disk') is True
    limit = EVIDENCE_PCAP_LIMIT if disk else CAPTURE_LIMIT
    raw = EvidenceWriter(evidence_device(), request['lab_id']) if disk else (directory / 'capture.pcap').open('xb')
    raw.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 2048, 1))
    count = 24
    sockets = []

    def record(frame):
        nonlocal count
        if len(frame) > 2048 or count + 16 + len(frame) > limit:
            raise ValueError('capture-limit')
        now = time.time()
        raw.write(struct.pack('<IIII', int(now), int(now % 1 * 1000000), len(frame), len(frame)) + frame)
        count += 16 + len(frame)

    try:
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
                if dns:
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
            finally:
                if libc.setns(original.fileno(), 0) != 0:
                    raise OSError('router-setns')
        if tunnel is not None:
            # Alive and listening, before the observer says it is ready.
            check_lab_fixtures(tunnel, request.get('certificates'))
            node = start_process(node_config(tunnel), directory, 'node', GATEWAYS[4], tunnel['port'])
        if dns:
            dns_threads = [threading.Thread(target=dns_loop, args=(udp, tcp, dns_log, dns_stop), daemon=True),
                           threading.Thread(target=doh_loop, args=(doh, doh_tls, dns_log, dns_stop), daemon=True)]
            for thread in dns_threads:
                thread.start()
        write(directory / 'ready.json', {'capture_ready': True})
        while time.monotonic() < deadline and not (directory / 'stop').exists():
            for key, _ in selector.select(.1):
                if key.data == 'capture':
                    record(capture.recv(2049))
                    continue
                family, service = key.data
                if service == 'https':
                    connection, peer = key.fileobj.accept()
                    try:
                        record_https(https_log, https_exchange(connection, peer, context, request))
                    finally:
                        connection.close()
                    continue
                if service == 'marker':
                    data, peer = key.fileobj.recvfrom(1024)
                    if request.get('windows') is True:
                        index, word, label = accept_window_marker(request, marks, data, peer[0])
                        key.fileobj.sendto(ACK_PREFIX.encode('ascii') + data, peer)
                        marks.append(dict(word=word, index=index, label=label, at=time.monotonic()))
                        continue
                    marker = accept_marker(request, marks, data, peer[0])
                    key.fileobj.sendto(marker_answer(marker), peer)
                    marks.append(dict(word=marker['word'], nonce=marker['nonce'], at=time.monotonic()))
                    continue
                tcp = service in ('http', 'dns-tcp')
                connection = None
                try:
                    if tcp:
                        connection, peer = key.fileobj.accept()
                        connection.settimeout(1)
                        if service == 'dns-tcp':
                            size = int.from_bytes(receive(connection, 2), 'big')
                            if size > 1024:
                                raise ValueError('request-limit')
                            data = receive(connection, size)
                        else:
                            data = connection.recv(1024)
                    else:
                        data, peer = key.fileobj.recvfrom(1024)
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
                        key.fileobj.sendto(wire, peer)
                    logs.append({**p, 'response': response.hex()})
                    if len(logs) > 8 or len(json.dumps(logs)) > LOG_LIMIT:
                        raise ValueError('target-log-limit')
                finally:
                    if connection is not None:
                        connection.close()
        if time.monotonic() >= deadline:
            raise ValueError('capture-deadline')
        if node is not None:
            # Whether the node was still there at finish, then its exit code.
            alive, code = stop_process(node)
            node_state = dict(alive_at_finish=alive, exit_code=code)
        # Frames queued since the last poll still belong to the window.
        while True:
            try:
                frame = capture.recv(2049)
            except BlockingIOError:
                break
            record(frame)
        ended = time.monotonic()
        # Linux PACKET_STATISTICS reports kernel drops, not just process success.
        _, dropped = struct.unpack('II', capture.getsockopt(263, 6, 8))
    except BaseException:
        error = True
    finally:
        if disk:
            raw.finish(complete=not error)
        else:
            raw.flush()
            os.fsync(raw.fileno())
            raw.close()
        selector.close()
        capture.close()
        for stream in sockets:
            stream.close()
        dns_stop.set()
        for thread in dns_threads:
            thread.join(2)
        for stream in dns_sockets:
            stream.close()
        extra = {}
        if dns:
            write(directory / 'dns.json', dns_log.rows)
            error = error or dns_log.overflow
        if tunnel is not None:
            if node is not None and node_state is None:
                alive, code = stop_process(node)
                node_state = dict(alive_at_finish=alive, exit_code=code)
            write(directory / 'https.json', https_log)
            with (directory / 'node.log').open('xb') as stream:
                stream.write(scrub_log((directory / 'node.stderr').read_bytes()
                                       if (directory / 'node.stderr').exists() else b''))
            extra['node'] = node_state or dict(alive_at_finish=False, exit_code=None)
        write(directory / 'targets.json', logs)
        # Times are this machine's monotonic clock; a failed run records no end.
        write(directory / 'health.json', dict(error=error, dropped=dropped, finished=True,
                                              capture_started=started, capture_ended=ended, markers=marks,
                                              **extra))
    if error or dropped:
        raise ValueError('observer-unverified')


def main(request):
    iface = identity(request)
    directory = ROOT / request['lab_id']
    operation = request['operation']
    if operation == 'setup' and request['role'] == 'lab':
        ROOT.mkdir(mode=0o700, exist_ok=True)
        # A single claim per boot prevents replay into another run or namespace.
        write(ROOT / 'claim.json', request)
        directory.mkdir(mode=0o700)
        write(directory / 'identity.json', request)
        setup(request, iface, directory)
        return dict(capture_ready=True)
    if operation == 'probe' and request['role'] == 'test':
        ROOT.mkdir(mode=0o700, exist_ok=True)
        write(ROOT / 'claim.json', request)
        return probe_all(request)
    saved = json.loads((directory / 'identity.json').read_bytes())
    if any(saved[k] != request[k] for k in ('lab_id', 'role', 'vm_uuid', 'boot_id', 'probes', 'markers')):
        raise ValueError('wrong-run')
    if any(saved.get(key) != request.get(key) for key in ('tunnel', 'dns', 'dns_check', 'evidence_disk',
                                                       'duration_seconds', 'windows', 'certificates')):
        raise ValueError('wrong-run')
    if request['role'] == 'lab' and operation == 'serve':
        if request.get('interface') != iface:
            raise ValueError('wrong-capture-interface')
        serve(request, directory)
        return {}
    if request['role'] == 'lab' and operation == 'finish':
        time.sleep(.3)
        (directory / 'stop').touch(exist_ok=False)
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
    except Exception:
        print('lab-helper-failed', file=sys.stderr)
        sys.exit(2)
