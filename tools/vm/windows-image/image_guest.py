"""Small QMP and guest-agent clients for the image build, over any connected stream socket (stdlib only).

The matrix controller has its own hardened clients; the build runs outside it, before any run exists, so
these do only what the build needs: press a key, ping the agent, run one program, read one file.
"""

import base64
import csv
import json
import re
import time

QGA_DELIMITER = b'\xff'
# `guest-exec` is CreateProcess without a shell. Output is read as bytes and decoded as the console
# code page of an en-US guest, which agrees with ASCII for what typeperf prints.
TYPEPERF = 'C:\\Windows\\System32\\typeperf.exe'
TOP_PROCESSES = 8


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
                raise GuestError(f"QMP command failed: {command}: {message['error'].get('desc', '')}")
            return message.get('return')

    def press(self, qcode):
        self._call('send-key', {'keys': [{'type': 'qcode', 'data': qcode}]})

    def status(self):
        """The run state of the machine, such as `running` or `internal-error`."""
        return self._call('query-status')['status']

    def screendump(self, filename):
        self._call('screendump', {'filename': filename})

    def quit(self):
        """Ask QEMU to exit cleanly. It may close the connection before it answers."""
        try:
            self._call('quit')
        except (OSError, GuestError, ValueError):
            pass

    def close(self):
        self._out.close()


def press_until(open_connection, qcode, seconds, interval=0.5, clock=time.monotonic, sleep=time.sleep,
                inspect=None):
    """Send one key repeatedly for a while; the Windows disc asks for a key for a few seconds only.

    Returns the number of key presses. A connection that cannot be opened yet is retried, because
    the QMP socket appears a moment after QEMU starts. `inspect`, if given, is called with the live
    connection after each press, and whatever it raises ends the loop: QMP serves one client at a
    time, so a failure found while pressing must be examined over this very connection.
    """
    deadline = clock() + seconds
    sent = 0
    qmp = None
    try:
        while clock() < deadline:
            try:
                if qmp is None:
                    qmp = Qmp(open_connection())
                qmp.press(qcode)
                sent += 1
            except (OSError, GuestError):
                qmp = None
            if inspect is not None and qmp is not None:
                inspect(qmp)
            sleep(interval)
    finally:
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

    def start(self, path, arguments):
        """Start one program without waiting for it; returns its process id for `wait`."""
        return self.call('guest-exec', {'path': path, 'arg': list(arguments),
                                        'capture-output': True})['pid']

    def wait(self, pid, *, timeout=300, poll=1.0, clock=time.monotonic, sleep=time.sleep):
        """Wait for a program started with `start`; returns (exit code, stdout bytes)."""
        deadline = clock() + timeout
        while clock() < deadline:
            status = self.call('guest-exec-status', {'pid': pid})
            if status.get('exited'):
                out = base64.b64decode(status.get('out-data', ''))
                return status.get('exitcode', -1), out
            sleep(poll)
        raise GuestError('guest program did not finish in time')

    def run(self, path, arguments, *, timeout=300, poll=1.0, clock=time.monotonic, sleep=time.sleep):
        """Run one program and return (exit code, stdout bytes)."""
        return self.wait(self.start(path, arguments), timeout=timeout, poll=poll, clock=clock, sleep=sleep)

    def fire(self, command, arguments=None):
        """Send a command and do not wait for an answer.

        `guest-shutdown` has no reply by design: the agent goes down with the guest, and the channel
        closes. Waiting for an answer would turn the expected end of the connection into an error.
        """
        request = {'execute': command}
        if arguments is not None:
            request['arguments'] = arguments
        self._out.sendall(json.dumps(request).encode('ascii') + b'\n')

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


def wait_for_agent(open_connection, seconds, *, interval=2.0, check=None, clock=time.monotonic,
                   sleep=time.sleep):
    """Seconds until the guest agent answers a ping, or None. Measured on the host's monotonic clock.

    `check` runs before each attempt; whatever it raises ends the wait (a machine that has failed will
    never answer).
    """
    started = clock()
    while clock() - started < seconds:
        if check is not None:
            check()
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


def process_counter_arguments(samples):
    return ['\\Process(*)\\% Processor Time', '-sc', str(samples), '-si', '1']


def top_processes_from_csv(output, cpus, count=TOP_PROCESSES):
    r"""The busiest processes in the CSV of `typeperf \Process(*)\% Processor Time`, as {'name', 'percent'}.

    The process counter counts each logical processor as 100 %, so the mean of a column is divided by
    the number of processors to read on the same scale as `\Processor(_Total)`. Instances of one
    program (`svchost`, `svchost#1`) are added up; `_Total` and `Idle` are left out. The first sample
    of a rate counter is empty or zero and is a sample like the others. Counter names are English: the
    guest is en-US. Raises if the output has no samples.
    """
    rows = [row for row in csv.reader(output.decode('ascii', 'replace').splitlines()) if len(row) > 1]
    if len(rows) < 2:
        raise GuestError('no process counter samples')
    header = rows[0]
    # typeperf ends with a line of its own that contains a comma; a sample has one cell per counter.
    samples = [row for row in rows[1:] if len(row) == len(header)]
    if not samples:
        raise GuestError('no process counter samples')
    sums = {}
    for column in range(1, len(header)):
        found = re.search(r'\\Process\((.+)\)\\', header[column])
        if found is None:
            continue
        name = re.sub(r'#\d+$', '', found.group(1))
        if name.lower() in ('_total', 'idle'):
            continue
        values = []
        for row in samples:
            try:
                values.append(float(row[column]))
            except (IndexError, ValueError):
                continue
        if values:
            sums[name] = sums.get(name, 0.0) + sum(values) / len(samples)
    ranked = sorted(sums.items(), key=lambda item: item[1], reverse=True)[:count]
    return [{'name': name, 'percent': round(total / cpus, 1)} for name, total in ranked]


def top_processes(agent, samples, cpus, count=TOP_PROCESSES):
    """Run the process counter for `samples` seconds and return the busiest processes."""
    code, out = agent.run(TYPEPERF, process_counter_arguments(samples), timeout=samples + 60)
    return top_processes_from_csv(out, cpus, count)


def format_top_processes(processes):
    return ', '.join(f"{entry['name']} {entry['percent']}%" for entry in processes) or 'none'


def failed_steps(log_text):
    """Lines of the first-logon log that report a failed step, and whether the log is complete."""
    lines = log_text.splitlines()
    failed = [line.split(' ', 1)[1] for line in lines if ' FAIL ' in line]
    complete = any(' done, failed steps:' in line for line in lines)
    return failed, complete


POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'


def powershell(agent, command, *, timeout=120):
    """Run one PowerShell command through the agent; returns (exit code, output text)."""
    code, out = agent.run(POWERSHELL, ['-NoProfile', '-NonInteractive', '-Command', command],
                          timeout=timeout)
    return code, out.decode('utf-8', 'replace').strip()


def secure_boot_state(agent):
    """True when `Confirm-SecureBootUEFI` says so. Anything else, including an error, is a failure."""
    code, out = powershell(agent, 'Confirm-SecureBootUEFI')
    if code != 0 or out not in ('True', 'False'):
        raise GuestError(f'Confirm-SecureBootUEFI failed (exit code {code})')
    return out == 'True'


def tpm_state(agent):
    """`TpmPresent` and `TpmReady` of `Get-Tpm`, as booleans."""
    code, out = powershell(agent, 'Get-Tpm | Select-Object TpmPresent, TpmReady | ConvertTo-Json -Compress')
    try:
        value = json.loads(out)
        present, ready = value['TpmPresent'], value['TpmReady']
    except (ValueError, KeyError, TypeError):
        raise GuestError(f'Get-Tpm gave no usable answer (exit code {code})') from None
    if code != 0 or type(present) is not bool or type(ready) is not bool:
        raise GuestError(f'Get-Tpm failed (exit code {code})')
    return {'present': present, 'ready': ready}
