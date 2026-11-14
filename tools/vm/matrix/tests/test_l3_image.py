"""The L3 image keeps the lab default without bypassing the tunnel for the probe."""

from pathlib import Path
import runpy
import unittest

prepare = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'linux/prepare-l3-image.py'))['network_for_l3']
DEFAULT = '[Route]\nDestination=0.0.0.0/0\nGateway=192.0.2.1\n'
LEGACY = '[Route]\nDestination=203.0.113.0/24\nGateway=192.0.2.1\n'
IPV6 = '[Route]\nDestination=2001:db8:6a:2::/64\nGateway=2001:db8:6a:1::1\n'


class PreparationTests(unittest.TestCase):
    def test_only_the_legacy_route_is_removed(self):
        head = '[Match]\nMACAddress=00:00:5e:00:53:61\n[Network]\nAddress=192.0.2.2/24\n'
        self.assertEqual(head + IPV6 + DEFAULT, prepare(head + LEGACY + IPV6 + DEFAULT))

    def test_an_already_prepared_network_is_unchanged(self):
        self.assertEqual(IPV6 + DEFAULT, prepare(IPV6 + DEFAULT))

    def test_a_missing_default_or_foreign_probe_route_is_refused(self):
        for text in (LEGACY, DEFAULT + LEGACY.replace('192.0.2.1', '192.0.2.9')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                prepare(text)
