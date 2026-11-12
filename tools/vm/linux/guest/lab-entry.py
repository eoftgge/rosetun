#!/usr/bin/python3
"""Owner-installed root-only lab entry. Never invoked on the controller host."""
import ctypes
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import time
import uuid

from lab_protocol import (MACS, CLIENTS, GATEWAYS, TARGETS, PORTS, SERVICES, CAPTURE_LIMIT,
                          LOG_LIMIT, DURATION, interface, query, answer, token,
                          marker_query, marker_answer)

ROOT = Path('/run/rosetun-lab')
ENTRY = '/usr/local/libexec/rosetun-lab/entry'


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
    window = request['markers']
    if (type(window) is not list or [m.get('word') for m in window] != ['open', 'close']
            or len({m.get('nonce') for m in window + expected}) != 10):
        raise ValueError('invalid-markers')
    for m in window:
        if (set(m) != {'run_id', 'nonce', 'word', 'family', 'service', 'protocol', 'source', 'target', 'port'}
                or m['run_id'] != request['lab_id'] or len(m['nonce']) != 24
                or any(c not in '0123456789abcdef' for c in m['nonce'])
                or (m['family'], m['service'], m['protocol']) != (4, 'marker', 'udp')
                or m['source'] != CLIENTS[4] or m['target'] != TARGETS[4] or m['port'] != PORTS['marker']):
            raise ValueError('foreign-marker')
    return iface


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


def probe_all(request):
    """The exchanges between an opening and a closing marker, each answered by the target."""
    opening, closing = request['markers']
    sent, marker_replies = {}, []
    # The clock below is this machine's and is only logged; verdicts never compare it.
    sent['open'] = time.monotonic()
    marker_replies.append(exchange_marker(opening))
    replies = probe_exchanges(request)
    # Let the last connection finish closing on the wire before the window ends.
    time.sleep(.2)
    sent['close'] = time.monotonic()
    marker_replies.append(exchange_marker(closing))
    return dict(replies=replies, marker_replies=marker_replies, marker_sent=sent)


def setup(request, iface, directory):
    # The role, VM, boot and one-shot run claim are checked before any mutation.
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
    command(*ns, '/usr/sbin/ip', 'link', 'set', 'rt-target', 'up')
    command(*ns, '/usr/sbin/ip', 'route', 'add', '192.0.2.0/24', 'via', '203.0.113.1')
    command(*ns, '/usr/sbin/ip', '-6', 'route', 'add', '2001:db8:6a:1::/64', 'via', '2001:db8:6a:2::1')
    Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
    Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1')
    # Capture stays in the router namespace; services run in the routed namespace.
    child = subprocess.Popen([ENTRY, json.dumps({**request, 'operation': 'serve', 'interface': iface})],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    for _ in range(50):
        if child.poll() is not None:
            raise ValueError('observer-start-failed')
        if (directory / 'ready.json').exists():
            return
        time.sleep(.1)
    raise ValueError('capture-ready-timeout')


def accept_marker(request, marks, data, source):
    """The window marker a datagram carries, accepted once and only in open-then-close order."""
    word = ('open', 'close')[len(marks)] if len(marks) < 2 else None
    found = [m for m in request['markers'] if m['word'] == word and m['source'] == source
             and marker_query(m) == data]
    if len(found) != 1:
        raise ValueError('unexpected-marker')
    return found[0]


def serve(request, directory):
    deadline = time.monotonic() + DURATION
    logs, error, dropped, marks, ended = [], False, 0, [], None
    selector = selectors.DefaultSelector()
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
    capture.bind((request['interface'], 0))
    capture.setblocking(False)
    started = time.monotonic()
    selector.register(capture, selectors.EVENT_READ, 'capture')
    raw = (directory / 'capture.pcap').open('xb')
    raw.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 2048, 1))
    count = 24
    sockets = []

    def record(frame):
        nonlocal count
        if len(frame) > 2048 or count + 16 + len(frame) > CAPTURE_LIMIT:
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
            finally:
                if libc.setns(original.fileno(), 0) != 0:
                    raise OSError('router-setns')
        write(directory / 'ready.json', {'capture_ready': True})
        while time.monotonic() < deadline and not (directory / 'stop').exists():
            for key, _ in selector.select(.1):
                if key.data == 'capture':
                    record(capture.recv(2049))
                    continue
                family, service = key.data
                if service == 'marker':
                    data, peer = key.fileobj.recvfrom(1024)
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
        raw.flush()
        os.fsync(raw.fileno())
        raw.close()
        selector.close()
        capture.close()
        for stream in sockets:
            stream.close()
        write(directory / 'targets.json', logs)
        # Times are this machine's monotonic clock; a failed run records no end.
        write(directory / 'health.json', dict(error=error, dropped=dropped, finished=True,
                                              capture_started=started, capture_ended=ended, markers=marks))
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
    if request['role'] == 'lab' and operation == 'serve':
        if request.get('interface') != iface:
            raise ValueError('wrong-capture-interface')
        serve(request, directory)
        return {}
    if request['role'] == 'lab' and operation == 'finish':
        time.sleep(.3)
        (directory / 'stop').touch(exist_ok=False)
        for _ in range(50):
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
    except Exception:
        print('lab-helper-failed', file=sys.stderr)
        sys.exit(2)
