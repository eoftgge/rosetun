"""Bounded stderr sink with streaming owner-token redaction; never publish raw logs."""

import os
import threading


class StderrSink:
    def __init__(self, path, token, limit=256 * 1024):
        self.file = path.open('xb', buffering=0)
        self.token = token.encode()
        self.limit = limit
        self.total = 0
        self.pending = b''
        self.overflow = False
        self.error = False
        self.thread = None
        self.pipe = None

    def feed(self, block, final=False):
        self.total += len(block)
        if self.total > self.limit:
            self.overflow = True
        block = block[:max(0, self.limit - (self.total - len(block)))]
        self.pending += block
        self.pending = self.pending.replace(self.token, b'[owner-redacted]')
        cut = len(self.pending) if final else max(0, len(self.pending) - len(self.token) + 1)
        self.file.write(self.pending[:cut])
        self.pending = self.pending[cut:]

    def start(self, pipe):
        self.pipe = pipe

        def drain():
            try:
                while block := pipe.read(4096):
                    self.feed(block)
                self.feed(b'', final=True)
            except (OSError, ValueError):
                self.error = True

        self.thread = threading.Thread(target=drain, daemon=True)
        self.thread.start()

    def close(self):
        if self.thread is not None:
            self.thread.join(timeout=1)
            if self.thread.is_alive():
                # Raw unbuffered pipe: closing does not wait on a reader lock.
                self.pipe.close()
                self.thread.join(timeout=1)
            if self.thread.is_alive():
                raise ValueError('stderr-reader-close-unconfirmed')
        if self.pipe is not None:
            self.pipe.close()
        if not self.file.closed:
            self.file.flush()
            os.fsync(self.file.fileno())
            self.file.close()
        if self.error:
            raise ValueError('stderr-evidence-failed')
