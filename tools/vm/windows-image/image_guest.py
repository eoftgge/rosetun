"""Small QMP and guest-agent clients for the image build, over any connected stream socket (stdlib only).

The matrix controller has its own hardened clients; the build runs outside it, before any run exists, so
these do only what the build needs: press a key, ping the agent, run one program, read one file.
"""

import base64
import json
import time

QGA_DELIMITER = b'\xff'
# `guest-exec` is CreateProcess without a shell. Output is read as bytes and decoded as the console
# code page of an en-US guest, which agrees with ASCII for what typeperf prints.
TYPEPERF = 'C:\\Windows\\System32\\typeperf.exe'


class GuestError(RuntimeError):
    pass


class _Lines:
    def __init__(self, stream, timeout):
        self.stream = stream
        self.stream.settimeout(timeout)
        self.buffer = b''

    def until(self, separator):
        while separator not in self.buffer:
            chunk = self.stream.recv(65536)
            if not chunk:
                raise GuestError('connection closed')
            self.buffer += chunk
        head, _, self.buffer = self.buffer.partition(separator)
        return head


class Qmp:
    def __init__(self, stream, timeout=10):
        self._in = _Lines(stream, timeout)
        self._out = stream
        json.loads(self._in.until(b'\n'))  # greeting
        self._call('qmp_capabilities')

    def _call(self, command, arguments=None):
        request = {'execute': command}
        if arguments is not None:
            request['arguments'] = arguments
        self._out.sendall(json.dumps(request).encode('ascii') + b'\r\n')
        while True:
            message = json.loads(self._in.until(b'\n'))
            if 'event' in message:
                continue
            if 'error' in message:
                raise GuestError('QMP command failed: ' + command)
            return message.get('return')

    def press(self, qcode):
        self._call('send-key', {'keys': [{'type': 'qcode', 'data': qcode}]})

    def close(self):
        self._out.close()


def press_until(open_connection, qcode, seconds, interval=0.5, clock=time.monotonic, sleep=time.sleep):
    """Send one key repeatedly for a while; the Windows disc asks for a key for a few seconds only.

    Returns the number of key presses. A connection that cannot be opened yet is retried, because
    the QMP socket appears a moment after QEMU starts.
    """
    deadline = clock() + seconds
    sent = 0
    qmp = None
    while clock() < deadline:
        try:
            if qmp is None:
                qmp = Qmp(open_connection())
            qmp.press(qcode)
            sent += 1
        except (OSError, GuestError):
            qmp = None
        sleep(interval)
    if qmp is not None:
        qmp.close()
    return sent


class Qga:
    def __init__(self, stream, timeout=10):
        self._in = _Lines(stream, timeout)
        self._out = stream
        self._counter = int(time.time()) % 100000 * 10

    def sync(self):
        """guest-sync-delimited: discard whatever an earlier client left in the channel."""
        self._counter += 1
        request = {'execute': 'guest-sync-delimited', 'arguments': {'id': self._counter}}
        self._out.sendall(QGA_DELIMITER + json.dumps(request).encode('ascii') + b'\n')
        # Everything up to the delimiter is stale; the answer follows it.
        self._in.until(QGA_DELIMITER)
        reply = json.loads(self._in.until(b'\n'))
        if reply.get('return') != self._counter:
            raise GuestError('guest agent answered another synchronization id')

    def call(self, command, arguments=None):
        request = {'execute': command}
        if arguments is not None:
            request['arguments'] = arguments
        self._out.sendall(json.dumps(request).encode('ascii') + b'\n')
        reply = json.loads(self._in.until(b'\n'))
        if 'error' in reply:
            raise GuestError('guest agent command failed: ' + command)
        return reply.get('return')

    def ping(self):
        self.sync()
        self.call('guest-ping')

    def run(self, path, arguments, *, timeout=300, poll=1.0, clock=time.monotonic, sleep=time.sleep):
        """Run one program and return (exit code, stdout bytes)."""
        pid = self.call('guest-exec', {'path': path, 'arg': list(arguments),
                                       'capture-output': True})['pid']
        deadline = clock() + timeout
        while clock() < deadline:
            status = self.call('guest-exec-status', {'pid': pid})
            if status.get('exited'):
                out = base64.b64decode(status.get('out-data', ''))
                return status.get('exitcode', -1), out
            sleep(poll)
        raise GuestError('guest program did not finish in time')

    def read_file(self, path, limit=1024 * 1024):
        handle = self.call('guest-file-open', {'path': path, 'mode': 'r'})
        try:
            data = b''
            while len(data) < limit:
                part = self.call('guest-file-read', {'handle': handle, 'count': 65536})
                data += base64.b64decode(part.get('buf-b64', ''))
                if part.get('eof'):
                    break
            return data
        finally:
            self.call('guest-file-close', {'handle': handle})


def wait_for_agent(open_connection, seconds, *, interval=2.0, clock=time.monotonic, sleep=time.sleep):
    """Seconds until the guest agent answers a ping, or None. Measured on the host's monotonic clock."""
    started = clock()
    while clock() - started < seconds:
        try:
            stream = open_connection()
            try:
                Qga(stream, timeout=interval).ping()
                return clock() - started
            finally:
                stream.close()
        except (OSError, GuestError, ValueError):
            sleep(interval)
    return None


def typeperf_arguments(samples):
    return ['\\Processor(_Total)\\% Processor Time', '-sc', str(samples), '-si', '1']


def average_cpu_percent(output):
    """Mean of the samples in typeperf's CSV output; raises if there is none."""
    values = []
    for line in output.decode('ascii', 'replace').splitlines():
        cells = [cell.strip().strip('"') for cell in line.split('","')]
        if len(cells) == 2:
            try:
                values.append(float(cells[1].strip('"')))
            except ValueError:
                continue
    if not values:
        raise GuestError('no typeperf samples')
    return sum(values) / len(values)


def failed_steps(log_text):
    """Lines of the first-logon log that report a failed step, and whether the log is complete."""
    lines = log_text.splitlines()
    failed = [line.split(' ', 1)[1] for line in lines if ' FAIL ' in line]
    complete = any(' done, failed steps:' in line for line in lines)
    return failed, complete
