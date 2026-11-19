"""A stand-in QEMU process for offline tests: it listens on the named control sockets.

It reads only what the controller passes: `-uuid` and the two `-chardev
socket,...,path=...,server=on,wait=off` options. QMP answers the commands the
controller uses; the agent socket answers a guest whose boot ID changes only
when a test says so. One client per socket at a time, as QEMU serves a
chardev. `quit` and `system_powerdown` end the process. Nothing here is a
real VM.

A Windows run's command line (a `chrtpm` chardev, a firmware-variables drive) adds three things: the process
connects to the TPM socket and keeps the connection until it ends, which is what makes the real swtpm end; it
appends to the variables file, as a guest writes its firmware store; and `screendump` writes a small file. With
FAKE_QEMU_IGNORE_POWERDOWN in the environment `system_powerdown` is answered and nothing more, like a guest that
does not react to its power button.

A Windows guest also answers the programs the controller starts through `guest-exec` (stage 9c): a PowerShell
command is read back from its encoded script and answered with the boot readings or the evidence, as JSON in UTF-8
bytes on the output stream, and `shutdown.exe /r /t 0` restarts the guest: the agent goes away, the monitor reports
`FAKE_QEMU_RESETS` RESET events (default 1, 67 ms apart), and after `FAKE_QEMU_BOOT_SECONDS` (default 0.3) the agent
answers again with the next boot count and time. `FAKE_QEMU_SECURE_BOOT=0`, `FAKE_QEMU_LATIN1=1` and
`FAKE_QEMU_PS_FAIL=1` make the guest say Secure Boot is off, answer in a code page that is not UTF-8, or fail.

A test steers the guest through the control socket named by the environment
variable FAKE_QEMU_CONTROL, one line per command: `guest-reset [BOOT_ID]`
(the agent session ends, the boot ID changes if one is given, and the monitor
reports a RESET event of the guest), `host-reset` (a RESET that is not the
guest's), `reset-event guest|host REASON SECONDS MICROSECONDS` (one more RESET at the time named, nothing
else changes), `boot BOOT_ID` (a boot ID changes with no event), `agent-down` and
`agent-up` (the agent socket stops answering, or answers again), and for a Windows guest `restart` (the restart
that `shutdown.exe` starts, with no request).
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
        if value == '-drive' and ',unit=1,' in argv[index + 1]:
            paths['vars'] = argv[index + 1].split('file=', 1)[1]
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
                elif name == 'screendump':
                    with open(request['arguments']['filename'], 'wb') as picture:
                        picture.write(b'PNG fake ' + request['arguments']['format'].encode())
                send(stream, {'return': value, 'id': ident})
                if name == 'quit' or (name == 'system_powerdown' and not os.environ.get('FAKE_QEMU_IGNORE_POWERDOWN')):
                    os._exit(0)


def windows_boot(state):
    """The two readings a Windows guest gives of its boot: the count of boots and the time of the last one."""
    guest = state['windows']
    return {'last_boot': '2026-11-19T07:%02d:50.5000000Z' % (10 + guest['boots']), 'counter': 100 + guest['boots']}


def windows_exec(state, arguments):
    """`guest-exec` of a Windows guest: `reg.exe` and PowerShell are answered, `shutdown.exe` restarts the guest."""
    guest = state['windows']
    guest['pid'] += 1
    pid = guest['pid']
    path, words = arguments['path'], arguments.get('arg') or []
    answer = {'exited': True, 'exitcode': 0}

    def say(data, code=0, err=b''):
        return {'exited': True, 'exitcode': code, 'out-data': base64.b64encode(data).decode(),
                'err-data': base64.b64encode(err).decode()}
    if path.lower().endswith('shutdown.exe') and words == ['/r', '/t', '0']:
        if not os.environ.get('FAKE_QEMU_NO_RESTART'):
            threading.Thread(target=windows_restart, args=(state,), daemon=True).start()
    elif path.lower().endswith('reg.exe') and words[:1] == ['query'] and words[-2:] == ['/v', 'BootId']:
        if os.environ.get('FAKE_QEMU_REG_FAIL'):
            answer = say(b'', 1, b'ERROR: The system was unable to find the specified registry key or value.')
        else:
            text = '\r\n%s\r\n    BootId    REG_DWORD    0x%x\r\n\r\n' % (words[1], windows_boot(state)['counter'])
            answer = say(text.encode('ascii'))
    elif path.lower().endswith('powershell.exe') and words[-2:-1] == ['-EncodedCommand']:
        script = base64.b64decode(words[-1]).decode('utf-16-le')
        if os.environ.get('FAKE_QEMU_PS_FAIL'):
            answer = say(b'', 1, b'System.Exception: failed')
        elif 'Confirm-SecureBootUEFI' in script:
            reading = windows_boot(state)
            evidence = dict(caption='Microsoft Windows 11 Pro', version='10.0.26200', build='26200',
                            architecture='64-bit', culture='en-US',
                            secure_boot=os.environ.get('FAKE_QEMU_SECURE_BOOT') != '0', secure_boot_error=None,
                            tpm={'present': True, 'ready': True}, last_boot=reading['last_boot'],
                            boot_counter=reading['counter'], uptime_ms=61000,
                            utf8_probe=(chr(0xc3) + chr(0xa9) + '?') if os.environ.get('FAKE_QEMU_LATIN1')
                            else chr(0xe9) + chr(0x4e16))
            if os.environ.get('FAKE_QEMU_COUNTER_LIE'):
                evidence['boot_counter'] += 1
            answer = say(json.dumps(evidence, ensure_ascii=False).encode('utf-8'))
    guest['execs'][pid] = answer
    return {'pid': pid}


def windows_restart(state):
    """What a restart of a Windows guest looks like from outside: the agent goes, RESETs, the agent comes back new."""
    import time
    time.sleep(float(os.environ.get('FAKE_QEMU_RESTART_DELAY', '0.2')))
    state['agent_up'] = False
    try:
        state['agent'].shutdown(socket.SHUT_RDWR)
    except (OSError, AttributeError):
        pass
    # With no controller connected the monitor's events go nowhere, as QEMU's do.
    for index in range(int(os.environ.get('FAKE_QEMU_RESETS', '1'))):
        try:
            event(state, True, 'guest-reset', (1, int(os.environ.get('FAKE_QEMU_RESET_GAP_US', '67000')) * index))
        except (KeyError, OSError):
            pass
    time.sleep(float(os.environ.get('FAKE_QEMU_BOOT_SECONDS', '0.3')))
    state['windows']['boots'] += 1
    state['agent_up'] = True


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
                elif name == 'guest-exec' and state.get('windows') is not None:
                    value = windows_exec(state, arguments)
                elif name == 'guest-exec-status' and state.get('windows') is not None:
                    value = state['windows']['execs'].pop(arguments['pid'], {'exited': True, 'exitcode': 0})
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
                if words[0] == 'restart' and state.get('windows') is not None:
                    threading.Thread(target=windows_restart, args=(state,), daemon=True).start()
                elif words[0] == 'guest-reset':
                    if state.get('windows') is not None:
                        state['windows']['boots'] += 1
                    elif len(words) > 1:
                        files['/proc/sys/kernel/random/boot_id'] = (words[1] + '\n').encode()
                    # The agent of the old guest is gone before the machine says it was reset.
                    try:
                        state['agent'].shutdown(socket.SHUT_RDWR)
                    except (OSError, AttributeError):
                        pass
                    event(state, True, 'guest-reset')
                elif words[0] == 'reset-event':
                    # `reset-event guest|host REASON SECONDS MICROSECONDS`: one RESET at the time the test names.
                    event(state, words[1] == 'guest', words[2], (int(words[3]), int(words[4])))
                elif words[0] == 'host-reset':
                    event(state, False, 'host-qmp-system-reset')
                elif words[0] == 'boot':
                    files['/proc/sys/kernel/random/boot_id'] = (words[1] + '\n').encode()
                elif words[0] in ('agent-down', 'agent-up'):
                    state['agent_up'] = words[0] == 'agent-up'
                send(stream, {'ok': words[0]})


def event(state, guest, reason, stamp=(1, 0)):
    with state['lock']:
        send(state['monitor'], {'event': 'RESET', 'data': {'guest': guest, 'reason': reason},
                                'timestamp': {'seconds': stamp[0], 'microseconds': stamp[1]}})


def main(argv):
    uuid, paths = options(argv)
    if 'vars' in paths:
        with open(paths['vars'], 'ab') as store:
            store.write(b'|written by the fake guest')
    if 'chrtpm' in paths:
        # The connection is held until the process ends; the real QEMU opens it while it starts.
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.connect(paths['chrtpm'])
    state = {'status': 'prelaunch', 'agent_up': True, 'lock': threading.Lock()}
    if 'chrtpm' in paths:
        state['windows'] = {'boots': 0, 'pid': 100, 'execs': {}}
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
