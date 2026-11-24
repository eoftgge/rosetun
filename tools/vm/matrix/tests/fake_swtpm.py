"""A stand-in swtpm process for offline tests: it listens on its control socket and ends like `--terminate`.

It reads only what the controller passes to the real program: `--tpmstate dir=DIR`, `--ctrl
type=unixio,path=SOCKET`, `--log file=FILE,...` and `--terminate`. It serves one connection, the fake QEMU's,
and exits with status 0 when that connection closes, so a run that ends QEMU ends the TPM too. While it is
connected it appends a line to the TPM state file in DIR, as the real emulator rewrites its state, so a test can
tell the run's copy from the image's own file. Nothing here is a TPM.

With FAKE_SWTPM_FAIL in the environment it exits at once with status 1 and never creates its socket.
"""

import os
import socket
import sys


def options(argv):
    values = {}
    for index, value in enumerate(argv):
        if value in ('--tpmstate', '--ctrl', '--log'):
            for part in argv[index + 1].split(','):
                key, _, item = part.partition('=')
                values.setdefault(value + ':' + key, item)
    return values


def main(argv):
    if os.environ.get('FAKE_SWTPM_FAIL'):
        sys.exit(1)
    values = options(argv)
    directory, path, log = values['--tpmstate:dir'], values['--ctrl:path'], values['--log:file']
    with open(log, 'ab') as stream:
        stream.write(b'fake swtpm started\n')
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    # The real swtpm gives its control socket mode 0660 unless `mode=` says otherwise, whatever its umask.
    os.chmod(path, int(values.get('--ctrl:mode', '0660'), 8))
    server.listen(1)
    stream, _ = server.accept()
    with open(os.path.join(directory, 'tpm2-00.permall'), 'ab') as state:
        state.write(b'\nwritten by the fake guest session')
    while stream.recv(4096):
        pass
    sys.exit(0)


if __name__ == '__main__':
    main(sys.argv[1:])
