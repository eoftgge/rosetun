"""A stand-in QEMU process for offline tests: it listens on the named control sockets.

It reads only what the controller passes: `-uuid` and the two `-chardev
socket,...,path=...,server=on,wait=off` options. QMP answers the commands the
controller uses; the agent socket answers a guest whose boot ID is fixed.
One client per socket at a time, as QEMU serves a chardev. `quit` and
`system_powerdown` end the process. Nothing here is a real VM.
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
                send(stream, {'return': value, 'id': ident})
                if name in ('quit', 'system_powerdown'):
                    os._exit(0)


def agent(server, files):
    handles = {}
    while True:
        stream, _ = server.accept()
        with stream:
            for line in lines(stream):
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


def main(argv):
    uuid, paths = options(argv)
    state = {'status': 'prelaunch'}
    files = {'/proc/sys/kernel/random/boot_id': (BOOT + '\n').encode()}
    servers = [listen(paths['control'])]
    threads = [threading.Thread(target=monitor, args=(servers[0], uuid, state), daemon=True)]
    if 'guestagent' in paths:
        servers.append(listen(paths['guestagent']))
        threads.append(threading.Thread(target=agent, args=(servers[1], files), daemon=True))
    for thread in threads:
        thread.start()
    threading.Event().wait()


if __name__ == '__main__':
    main(sys.argv[1:])
