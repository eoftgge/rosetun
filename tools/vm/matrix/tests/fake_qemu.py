"""A stand-in QEMU process for offline tests: it listens on the named control sockets.

It reads only what the controller passes: `-uuid` and the two `-chardev
socket,...,path=...,server=on,wait=off` options. QMP answers the commands the
controller uses; the agent socket answers a guest whose boot ID changes only
when a test says so. One client per socket at a time, as QEMU serves a
chardev. `quit` and `system_powerdown` end the process. Nothing here is a
real VM.

A test steers the guest through the control socket named by the environment
variable FAKE_QEMU_CONTROL, one line per command: `guest-reset [BOOT_ID]`
(the agent session ends, the boot ID changes if one is given, and the monitor
reports a RESET event of the guest), `host-reset` (a RESET that is not the
guest's), `boot BOOT_ID` (a boot ID changes with no event), `agent-down` and
`agent-up` (the agent socket stops answering, or answers again).
"""

import base64
import json
import os
import socket
import sys
import threading

BOOT = '12345678-1234-4234-8234-123456789abc'
AGENT_COMMANDS = ('guest-sync-delimited', 'guest-ping', 'guest-info', 'guest-file-open', 'guest-file-read',
                  'guest-file-close', 'guest-exec', 'guest-exec-status', 'guest-file-write')


def options(argv):
    paths, uuid = {}, None
    for index, value in enumerate(argv):
        if value == '-uuid':
            uuid = argv[index + 1]
        if value == '-chardev':
            fields = dict(part.partition('=')[::2] for part in argv[index + 1].split(',')[1:])
            paths[fields['id']] = fields['path']
    return uuid, paths


def listen(path):
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(4)
    return server


def lines(stream):
    buffer = b''
    while True:
        block = stream.recv(4096)
        if not block:
            return
        buffer += block
        while b'\n' in buffer:
            line, buffer = buffer.split(b'\n', 1)
            yield line


def send(stream, value, prefix=b''):
    stream.sendall(prefix + json.dumps(value).encode() + b'\n')


def monitor(server, uuid, state):
    while True:
        stream, _ = server.accept()
        state['monitor'] = stream
        with stream:
            send(stream, {'QMP': {'version': {'qemu': {'major': 10, 'minor': 0, 'micro': 13}}, 'capabilities': []}})
            for line in lines(stream):
                request = json.loads(line)
                name, ident = request.get('execute'), request.get('id')
                value = {}
                if name == 'query-uuid':
                    value = {'UUID': uuid}
                elif name == 'query-kvm':
                    value = {'enabled': True, 'present': True}
                elif name == 'query-status':
                    value = {'status': state['status'], 'running': state['status'] == 'running'}
                elif name == 'stop':
                    state['status'] = 'paused'
                elif name == 'cont':
                    state['status'] = 'running'
                elif name == 'system_reset':
                    event(state, False, 'host-qmp-system-reset')
                send(stream, {'return': value, 'id': ident})
                if name in ('quit', 'system_powerdown'):
                    os._exit(0)


def agent(server, files, state):
    handles = {}
    while True:
        stream, _ = server.accept()
        state['agent'] = stream
        with stream:
            for line in lines(stream):
                if not state['agent_up']:
                    continue
                synced = line.startswith(b'\xff')
                request = json.loads(line.lstrip(b'\xff'))
                name, ident, arguments = request.get('execute'), request.get('id'), request.get('arguments') or {}
                if name == 'guest-sync-delimited':
                    send(stream, {'return': arguments['id']}, prefix=b'\xff' if synced else b'')
                    continue
                if name == 'guest-info':
                    value = {'version': '9.2.0', 'supported_commands': [
                        {'name': n, 'enabled': True, 'success-response': True} for n in AGENT_COMMANDS]}
                elif name == 'guest-ping':
                    value = {}
                elif name == 'guest-file-open':
                    if arguments['path'] not in files:
                        send(stream, {'error': {'class': 'GenericError', 'desc': 'no such file'}, 'id': ident})
                        continue
                    value = len(handles) + 1
                    handles[value] = files[arguments['path']]
                elif name == 'guest-file-read':
                    data = handles[arguments['handle']][:arguments['count']]
                    handles[arguments['handle']] = handles[arguments['handle']][len(data):]
                    value = {'count': len(data), 'eof': not handles[arguments['handle']],
                             'buf-b64': base64.b64encode(data).decode()}
                elif name == 'guest-file-close':
                    handles.pop(arguments['handle'], None)
                    value = {}
                elif name == 'guest-exec':
                    value = {'pid': 4242}
                elif name == 'guest-exec-status':
                    value = {'exited': True, 'exitcode': 0}
                else:
                    value = {}
                send(stream, {'return': value, 'id': ident})


def steer(server, files, state):
    """The test's own channel: it is not part of QEMU and the controller never sees it."""
    while True:
        stream, _ = server.accept()
        with stream:
            for line in lines(stream):
                words = line.decode().split()
                if words[0] == 'guest-reset':
                    if len(words) > 1:
                        files['/proc/sys/kernel/random/boot_id'] = (words[1] + '\n').encode()
                    # The agent of the old guest is gone before the machine says it was reset.
                    try:
                        state['agent'].shutdown(socket.SHUT_RDWR)
                    except (OSError, AttributeError):
                        pass
                    event(state, True, 'guest-reset')
                elif words[0] == 'host-reset':
                    event(state, False, 'host-qmp-system-reset')
                elif words[0] == 'boot':
                    files['/proc/sys/kernel/random/boot_id'] = (words[1] + '\n').encode()
                elif words[0] in ('agent-down', 'agent-up'):
                    state['agent_up'] = words[0] == 'agent-up'
                send(stream, {'ok': words[0]})


def event(state, guest, reason):
    with state['lock']:
        send(state['monitor'], {'event': 'RESET', 'data': {'guest': guest, 'reason': reason},
                                'timestamp': {'seconds': 1, 'microseconds': 0}})


def main(argv):
    uuid, paths = options(argv)
    state = {'status': 'prelaunch', 'agent_up': True, 'lock': threading.Lock()}
    files = {'/proc/sys/kernel/random/boot_id': (BOOT + '\n').encode()}
    servers = [listen(paths['control'])]
    threads = [threading.Thread(target=monitor, args=(servers[0], uuid, state), daemon=True)]
    if 'guestagent' in paths:
        servers.append(listen(paths['guestagent']))
        threads.append(threading.Thread(target=agent, args=(servers[1], files, state), daemon=True))
    if os.environ.get('FAKE_QEMU_CONTROL'):
        # A run's fake guest before this one left its socket file behind, as a killed process does.
        if os.path.exists(os.environ['FAKE_QEMU_CONTROL']):
            os.unlink(os.environ['FAKE_QEMU_CONTROL'])
        servers.append(listen(os.environ['FAKE_QEMU_CONTROL']))
        threads.append(threading.Thread(target=steer, args=(servers[-1], files, state), daemon=True))
    for thread in threads:
        thread.start()
    threading.Event().wait()


if __name__ == '__main__':
    main(sys.argv[1:])
