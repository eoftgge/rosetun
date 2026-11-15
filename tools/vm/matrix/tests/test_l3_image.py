"""The L3 image keeps the lab default without bypassing the tunnel for the probe, and its sshd listens only for the peer."""

import contextlib
import hashlib
import io
import os
from pathlib import Path
import runpy
import tempfile
import unittest

tool = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'linux/prepare-l3-image.py'))
prepare = tool['network_for_l3']
DEFAULT = '[Route]\nDestination=0.0.0.0/0\nGateway=192.0.2.1\n'
LEGACY = '[Route]\nDestination=203.0.113.0/24\nGateway=192.0.2.1\n'
IPV6 = '[Route]\nDestination=2001:db8:6a:2::/64\nGateway=2001:db8:6a:1::1\n'
# The units of openssh-server 1:10.0p1-7+deb13u4 (Debian 13) that matter here: a socket on port 22 of every
# address that hands its socket to the daemon (Accept=no), and the per-connection template.
PACKAGED_SOCKET = ('[Unit]\nDescription=OpenBSD Secure Shell server socket\nBefore=sockets.target\n'
                   'ConditionPathExists=!/etc/ssh/sshd_not_to_be_run\n\n'
                   '[Socket]\nListenStream=22\nAccept=no\n\n[Install]\nWantedBy=sockets.target\n')
PACKAGED_TEMPLATE = ('[Unit]\nDescription=OpenBSD Secure Shell server per-connection daemon\n'
                     'Documentation=man:sshd(8) man:sshd_config(5)\nAfter=nss-user-lookup.target auditd.service\n\n'
                     '[Service]\nEnvironmentFile=-/etc/default/ssh\nExecStart=-/usr/sbin/sshd -i $SSHD_OPTS\n'
                     'StandardInput=socket\nRuntimeDirectory=sshd\nRuntimeDirectoryPreserve=yes\n'
                     'RuntimeDirectoryMode=0755\n')
REQUIRED = ['openssh-server_1%3a10.0p1-7_amd64.deb', 'openssh-client_1%3a10.0p1-7_amd64.deb',
            'openssh-sftp-server_1%3a10.0p1-7_amd64.deb']


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


class ArgumentTests(unittest.TestCase):
    BASE = ['/srv/old.qcow2', '/srv/new.qcow2', '--source-sha256', '0' * 64, '--descriptor', '/srv/new.json']

    def parse(self, *extra):
        self.errors = io.StringIO()
        with contextlib.redirect_stderr(self.errors):
            return tool['arguments'](self.BASE + list(extra))

    def test_the_sshd_mode_without_its_packages_is_refused(self):
        with self.assertRaises(SystemExit) as raised:
            self.parse('--sshd')
        self.assertEqual(2, raised.exception.code)
        self.assertIn('--sshd needs --sshd-debs DIR', self.errors.getvalue())

    def test_packages_without_the_sshd_mode_are_refused(self):
        with self.assertRaises(SystemExit):
            self.parse('--sshd-debs', '/srv/debs')
        self.assertIn('--sshd-debs is only for --sshd', self.errors.getvalue())

    def test_the_sshd_mode_with_its_packages_and_the_old_mode_are_accepted(self):
        args = self.parse('--sshd', '--sshd-debs', '/srv/debs')
        self.assertEqual((True, Path('/srv/debs')), (args.sshd, args.sshd_debs))
        args = self.parse()
        self.assertEqual((False, None), (args.sshd, args.sshd_debs))


class PackageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name) / 'debs'
        self.directory.mkdir()

    def write(self, names):
        for name in names:
            (self.directory / name).write_bytes(name.encode())

    def test_every_package_is_listed_with_its_hash_and_size(self):
        self.write(REQUIRED)
        debs = tool['sshd_debs'](self.directory)
        self.assertEqual(sorted(REQUIRED), [deb['name'] for deb in debs])
        for deb in debs:
            self.assertEqual((hashlib.sha256(deb['name'].encode()).hexdigest(), len(deb['name'].encode())),
                             (deb['sha256'], deb['size_bytes']))

    def test_a_directory_without_openssh_server_or_with_anything_else_is_refused(self):
        self.write(REQUIRED[1:])
        with self.assertRaisesRegex(ValueError, 'no openssh-server'):
            tool['sshd_debs'](self.directory)
        self.write(REQUIRED[:1] + ['notes.txt'])
        with self.assertRaisesRegex(ValueError, 'unexpected entry'):
            tool['sshd_debs'](self.directory)

    def test_a_linked_package_is_refused(self):
        self.write(REQUIRED[1:])
        os.symlink(self.directory / REQUIRED[1], self.directory / REQUIRED[0])
        with self.assertRaisesRegex(ValueError, 'unexpected entry'):
            tool['sshd_debs'](self.directory)

    def test_the_descriptor_carries_the_hashes_of_the_packages(self):
        self.write(REQUIRED)
        debs = tool['sshd_debs'](self.directory)
        image = self.directory.parent / 'test-l3-v6.qcow2'
        image.write_bytes(b'image')
        descriptor = tool['image_descriptor'](image, debs)
        self.assertEqual(dict(listen='198.51.100.1:22', socket='l3-lab-sshd.socket', debs=debs),
                         descriptor['sshd'])
        self.assertEqual((hashlib.sha256(b'image').hexdigest(), 5, 'test-l3-v6'),
                         (descriptor['sha256'], descriptor['size_bytes'], descriptor['identifier']))
        self.assertNotIn('sshd', tool['image_descriptor'](image))


class SshdCheckTests(unittest.TestCase):
    """What the read-only look at the prepared image accepts: a copy of its unit directories."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.etc, self.lib = self.root / 'etc', self.root / 'lib'
        (self.etc / 'sockets.target.wants').mkdir(parents=True)
        self.lib.mkdir()
        (self.lib / 'ssh.socket').write_text(PACKAGED_SOCKET, encoding='utf-8')
        (self.lib / 'sshd@.service').write_text(PACKAGED_TEMPLATE, encoding='utf-8')
        (self.etc / 'l3-lab-sshd.socket').write_text(tool['SOCKET_TEXT'], encoding='utf-8')
        (self.etc / 'l3-lab-sshd@.service').write_text(tool['SERVICE_TEXT'], encoding='utf-8')
        os.symlink('/etc/systemd/system/l3-lab-sshd.socket', self.etc / 'sockets.target.wants' / 'l3-lab-sshd.socket')
        for name in ('ssh.socket', 'ssh.service', 'sshd.service'):
            os.symlink('/dev/null', self.etc / name)

    def check(self, ssh_files=('ssh_host_ed25519_key', 'ssh_host_ed25519_key.pub', 'sshd_config'),
              leftovers=(False, False)):
        return tool['check_sshd'](self.root, list(ssh_files), list(leftovers))

    def dropin(self, text, name='zz-local.conf', unit='l3-lab-sshd.socket'):
        folder = self.etc / (unit + '.d')
        folder.mkdir(exist_ok=True)
        (folder / name).write_text(text, encoding='utf-8')

    def test_the_installed_socket_listens_only_on_the_peer_address_and_accepts_each_connection(self):
        settings = self.check()
        self.assertEqual((['198.51.100.1:22'], [], 'yes', 'yes'),
                         (settings['listen'], settings['other_listen'], settings['free_bind'], settings['accept']))

    def test_the_template_keeps_the_service_lines_of_the_packaged_one(self):
        service = lambda text: text.split('[Service]\n', 1)[1]
        self.assertEqual(service(PACKAGED_TEMPLATE), service(tool['SERVICE_TEXT']))
        self.assertEqual(('l3-lab-sshd.socket', 'l3-lab-sshd@.service'), (tool['SOCKET_UNIT'], tool['SERVICE_UNIT']))
        # preflight.no-foreign-service refuses every unit named rosetun*.
        self.assertFalse(tool['SOCKET_UNIT'].startswith('rosetun'))

    def test_a_further_listen_stream_is_refused(self):
        for text in ('[Socket]\nListenStream=192.0.2.2:22\n', '[Socket]\nListenStream=0.0.0.0:2222\n',
                     '[Socket]\nListenStream=\nListenStream=22\n', '[Socket]\nListenDatagram=198.51.100.1:22\n'):
            with self.subTest(text=text):
                self.dropin(text)
                with self.assertRaisesRegex(ValueError, 'listens on'):
                    self.check()
        (self.etc / 'l3-lab-sshd.socket.d' / 'zz-local.conf').unlink()
        (self.etc / 'l3-lab-sshd.socket').write_text(
            tool['SOCKET_TEXT'].replace('FreeBind=yes', 'ListenStream=22\nFreeBind=yes'), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'listens on'):
            self.check()

    def test_a_socket_drop_in_for_every_unit_counts_too(self):
        self.dropin('[Socket]\nListenStream=192.0.2.2:22\n', unit='socket')
        with self.assertRaisesRegex(ValueError, 'listens on'):
            self.check()

    def test_a_packaged_unit_that_is_not_masked_is_refused(self):
        for name in ('ssh.socket', 'ssh.service', 'sshd.service'):
            with self.subTest(name=name):
                (self.etc / name).unlink()
                with self.assertRaisesRegex(ValueError, name + ' is not masked'):
                    self.check()
                os.symlink('/usr/lib/systemd/system/ssh.service', self.etc / name)
                with self.assertRaisesRegex(ValueError, name + ' is not masked'):
                    self.check()
                (self.etc / name).unlink()
                os.symlink('/dev/null', self.etc / name)

    def test_a_packaged_unit_still_linked_from_a_target_is_refused(self):
        wants = self.etc / 'multi-user.target.wants'
        wants.mkdir()
        os.symlink('/usr/lib/systemd/system/ssh.service', wants / 'ssh.service')
        with self.assertRaisesRegex(ValueError, 'ssh.service is still linked'):
            self.check()
        (wants / 'ssh.service').unlink()
        os.symlink('/usr/lib/systemd/system/ssh.socket', self.etc / 'sockets.target.wants' / 'ssh.socket')
        with self.assertRaisesRegex(ValueError, 'ssh.socket is still linked'):
            self.check()

    def test_a_socket_that_is_not_enabled_or_missing_is_refused(self):
        (self.etc / 'sockets.target.wants' / 'l3-lab-sshd.socket').unlink()
        with self.assertRaisesRegex(ValueError, 'not enabled'):
            self.check()
        os.symlink('/etc/systemd/system/l3-lab-sshd.socket', self.etc / 'sockets.target.wants' / 'l3-lab-sshd.socket')
        (self.etc / 'l3-lab-sshd.socket').unlink()
        with self.assertRaisesRegex(ValueError, 'no l3-lab-sshd.socket'):
            self.check()

    def test_a_socket_that_hands_the_listening_to_sshd_is_refused(self):
        self.dropin('[Socket]\nAccept=no\n')
        with self.assertRaisesRegex(ValueError, 'Accept=yes'):
            self.check()

    def test_a_socket_without_free_bind_is_refused(self):
        self.dropin('[Socket]\nFreeBind=no\n')
        with self.assertRaisesRegex(ValueError, 'FreeBind'):
            self.check()

    def test_a_missing_changed_or_extended_template_is_refused(self):
        (self.etc / 'l3-lab-sshd@.service').write_text(tool['SERVICE_TEXT'].replace(' -i', ' -D'), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'is not the one'):
            self.check()
        (self.etc / 'l3-lab-sshd@.service').write_text(tool['SERVICE_TEXT'], encoding='utf-8')
        self.dropin('[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -D\n', unit='l3-lab-sshd@.service')
        with self.assertRaisesRegex(ValueError, 'is not the one'):
            self.check()
        (self.etc / 'l3-lab-sshd@.service.d' / 'zz-local.conf').unlink()
        (self.etc / 'l3-lab-sshd@.service').unlink()
        with self.assertRaisesRegex(ValueError, 'no l3-lab-sshd@.service'):
            self.check()

    def test_no_host_key_or_a_leftover_of_the_installation_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'host key'):
            self.check(ssh_files=('sshd_config',))
        for leftovers in ((True, False), (False, True)):
            with self.subTest(leftovers=leftovers), self.assertRaisesRegex(ValueError, 'left'):
                self.check(leftovers=leftovers)

    def test_the_install_script_starts_nothing_masks_the_packaged_units_and_enables_only_its_socket(self):
        script = tool['INSTALL_SCRIPT']
        self.assertIn('systemctl disable ssh.socket ssh.service', script)
        self.assertIn('systemctl mask ssh.socket ssh.service sshd.service', script)
        self.assertIn('systemctl enable l3-lab-sshd.socket', script)
        self.assertLess(script.index('systemctl disable'), script.index('systemctl mask'))
        self.assertIn('exit 101', script)
        self.assertNotIn('start', script)
        self.assertNotIn('apt', script)
        self.assertNotIn('ssh.socket.d', script)
        self.assertEqual('ListenAddress 198.51.100.1:22\n', tool['SSHD_CONFIG_TEXT'])


if __name__ == '__main__':
    unittest.main()
