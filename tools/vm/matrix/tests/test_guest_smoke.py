"""Linux shell checks are explicitly UNRUN on other hosts."""
import os
from pathlib import Path
import subprocess
import unittest


@unittest.skipUnless(os.name == 'posix', 'UNRUN: requires Linux bash/coreutils')
class GuestSmokeTests(unittest.TestCase):
    def test_verified_package_and_rejections_with_fake_systemd(self):
        script = Path(__file__).resolve().parents[2] / 'linux/tests/selftest-smoke.sh'
        subprocess.run(['/bin/bash', str(script)], check=True, timeout=15)
