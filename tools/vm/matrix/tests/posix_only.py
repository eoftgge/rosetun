"""Skip markers for tests that exercise what only the Linux controller can do.

The QEMU controller runs on Linux alone: KVM, AF_UNIX control sockets under a path
the kernel limits to 107 bytes, pidfd and POSIX owner checks. A test that goes through
the real `lifecycle.start` or opens such a socket says nothing on Windows, where the
temporary directory is already longer than the socket path limit allows, so it is skipped
there with this reason instead of weakening the product checks.
"""

import os
import unittest

REASON = 'the QEMU controller runs on Linux only (KVM, AF_UNIX control sockets, pidfd)'

controller_only = unittest.skipUnless(os.name == 'posix', REASON)

# An example configuration names the Linux stand's own paths, which are not absolute on Windows.
linux_stand_paths = unittest.skipUnless(os.name == 'posix', 'the example configuration names Linux stand paths')
