"""The L4 test image (contract v7): the user bus, sshd where the job's peers look for it, the nftables unit as it is."""

import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest

from tools.vm.matrix.tests.test_l3_image import PACKAGED_SOCKET, PACKAGED_TEMPLATE, status, tool

LINKS = lambda *rows: set(rows)  # noqa: E731
ENABLED = ('etc', 'sockets.target.wants', 'l4-lab-sshd.socket', '/etc/systemd/system/l4-lab-sshd.socket')
V6_LINK = ('etc', 'sockets.target.wants', 'l3-lab-sshd.socket', '/etc/systemd/system/l3-lab-sshd.socket')
CONF = '#!/usr/sbin/nft -f\n\nflush ruleset\n\ntable inet filter {\n}\n'
FLAGS = (True, True, True, False, False, False)


def installed(**more):
    names = dict.fromkeys(tool['L4_DEPENDS'], '9.0')
    names.update(more)
    return status(**names)


class L4ImageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.etc, self.lib = self.root / 'etc', self.root / 'lib'
        (self.etc / 'sockets.target.wants').mkdir(parents=True)
        self.lib.mkdir()
        (self.lib / 'ssh.socket').write_text(PACKAGED_SOCKET, encoding='utf-8')
        (self.lib / 'sshd@.service').write_text(PACKAGED_TEMPLATE, encoding='utf-8')
        for name in ('l3-lab-sshd.socket', 'l3-lab-sshd@.service'):
            text = tool['SOCKET_TEXT'] if name.endswith('.socket') else tool['SERVICE_TEXT']
            (self.etc / name).write_text(text, encoding='utf-8')
        (self.etc / 'l4-lab-sshd.socket').write_text(tool['L4_SOCKET_TEXT'], encoding='utf-8')
        (self.etc / 'l4-lab-sshd@.service').write_text(tool['L4_SERVICE_TEXT'], encoding='utf-8')
        for name in ('l3', 'l4'):
            os.symlink(f'/etc/systemd/system/{name}-lab-sshd.socket', self.etc / 'sockets.target.wants' / f'{name}-lab-sshd.socket')
        for name in ('ssh.socket', 'ssh.service', 'sshd.service'):
            os.symlink('/dev/null', self.etc / name)
        self.before = LINKS(V6_LINK)
        self.after = LINKS(V6_LINK, ENABLED)

    def check(self, *, status_text=None, ssh_files=('ssh_host_ed25519_key', 'sshd_config'), flags=FLAGS, conf=CONF,
              before=None, after=None, quiet=None):
        return tool['check_l4'](self.root, status_text or installed(), list(ssh_files), list(flags), conf,
                                self.before if before is None else before, self.after if after is None else after,
                                quiet or dict(enabled=[], other_links=[]))

    def refused(self, pattern, **options):
        with self.assertRaisesRegex(ValueError, pattern):
            self.check(**options)

    def test_the_addresses_are_the_ones_the_job_names_and_the_units_are_not_rosetun(self):
        self.assertEqual(['192.0.2.2:22', '169.254.77.1:22'], tool['L4_LISTEN'])
        script = (Path(__file__).resolve().parents[2] / 'linux/guest/run-l4.sh').read_text(encoding='utf-8')
        self.assertIn('PEER_HOST_ADDRESS=169.254.77.1', script)
        for name in (tool['L4_SOCKET_UNIT'], tool['L4_SERVICE_UNIT']):
            self.assertFalse(name.startswith('rosetun'))
        text = tool['L4_SOCKET_TEXT']
        self.assertEqual(2, text.count('ListenStream='))
        self.assertIn('FreeBind=yes\nAccept=yes\n', text)
        self.assertEqual(tool['SERVICE_TEXT'].replace('L3', 'L4'), tool['L4_SERVICE_TEXT'])

    def test_the_prepared_image_is_accepted_and_recorded(self):
        record = self.check()
        self.assertEqual(['192.0.2.2:22', '169.254.77.1:22'], record['sockets']['listen'])
        self.assertEqual(['198.51.100.1:22'], record['v6_sshd']['listen'])
        self.assertEqual(sorted(tool['L4_DEPENDS']), sorted(record['installed']))
        self.assertTrue(record['nftables']['flush_ruleset'])
        self.assertEqual(64, len(record['nftables']['conf_sha256']))

    def test_the_user_bus_the_nftables_unit_and_its_configuration_are_required(self):
        self.refused('user bus', flags=(False, True, True, False, False, False))
        self.refused('nftables.service is missing', flags=(True, False, True, False, False, False))
        self.refused('does not flush', flags=(True, True, False, False, False, False), conf=None)
        self.refused('does not flush', conf='table inet filter {\n}\n')
        self.refused('does not flush', conf='# flush ruleset\n')
        self.refused('does not flush', conf='flush ruleset now\n')
        self.check(conf='\tflush ruleset  \n')

    def test_a_missing_dependency_or_a_rosetun_package_is_refused(self):
        names = {name: '9.0' for name in tool['L4_DEPENDS'] if name != 'dbus-user-session'}
        self.refused('not installed: dbus-user-session', status_text=status(**names))
        self.refused('rosetun package is installed', status_text=installed(rosetun='0.5.1'))

    def test_a_socket_that_listens_anywhere_else_is_refused(self):
        path = self.etc / 'l4-lab-sshd.socket'
        path.write_text(tool['L4_SOCKET_TEXT'].replace('ListenStream=169.254.77.1:22', 'ListenStream=22'), encoding='utf-8')
        self.refused('listens on')
        path.write_text(tool['L4_SOCKET_TEXT'].replace('[Install]', 'ListenStream=0.0.0.0:22\n\n[Install]'), encoding='utf-8')
        self.refused('listens on')
        path.write_text(tool['L4_SOCKET_TEXT'].replace('Accept=yes', 'Accept=yes\nListenDatagram=0.0.0.0:22'),
                        encoding='utf-8')
        self.refused('listens on')

    def test_a_socket_drop_in_counts_too(self):
        folder = self.etc / 'l4-lab-sshd.socket.d'
        folder.mkdir()
        (folder / 'zz.conf').write_text('[Socket]\nListenStream=0.0.0.0:22\n', encoding='utf-8')
        self.refused('listens on')

    def test_a_socket_without_free_bind_or_that_hands_its_listening_to_sshd_is_refused(self):
        path = self.etc / 'l4-lab-sshd.socket'
        path.write_text(tool['L4_SOCKET_TEXT'].replace('FreeBind=yes\n', ''), encoding='utf-8')
        self.refused('FreeBind=yes')
        path.write_text(tool['L4_SOCKET_TEXT'].replace('Accept=yes', 'Accept=no'), encoding='utf-8')
        self.refused('Accept=yes')

    def test_a_changed_or_extended_template_is_refused(self):
        (self.etc / 'l4-lab-sshd@.service').write_text(tool['L4_SERVICE_TEXT'] + 'ExecStartPre=/bin/true\n', encoding='utf-8')
        self.refused('not the one this tool writes')
        (self.etc / 'l4-lab-sshd@.service').write_text(tool['L4_SERVICE_TEXT'], encoding='utf-8')
        folder = self.etc / 'l4-lab-sshd@.service.d'
        folder.mkdir()
        (folder / 'zz.conf').write_text('[Service]\nExecStart=/bin/sh\n', encoding='utf-8')
        self.refused('not the one this tool writes')

    def test_the_installation_enables_the_socket_and_nothing_else(self):
        self.refused('other links', after=self.after | LINKS(('etc', 'timers.target.wants', 'x.timer', '/x')))
        self.refused('other links', after=self.before)
        self.refused('other links', after=self.after - LINKS(V6_LINK))
        wrong = ('etc', 'sockets.target.wants', 'l4-lab-sshd.socket', '/etc/systemd/system/other.socket')
        self.refused('other links', after=self.before | LINKS(wrong))

    def test_nftables_is_left_for_the_job_to_enable(self):
        enabled = ('etc', 'multi-user.target.wants', 'nftables.service', '/usr/lib/systemd/system/nftables.service')
        self.refused('nftables.service is enabled', before=self.before | LINKS(enabled), after=self.after | LINKS(enabled))
        # A mask or an alias of its own is no enabling.
        masked = ('etc', '.', 'nftables.service', '/dev/null')
        self.check(before=self.before | LINKS(masked), after=self.after | LINKS(masked))

    def test_the_sshd_of_v6_stays_and_a_leftover_of_the_installation_is_refused(self):
        os.unlink(self.etc / 'sockets.target.wants' / 'l3-lab-sshd.socket')
        self.refused('l3-lab-sshd.socket is not enabled')
        self.setUp()
        self.refused('no host key', ssh_files=('sshd_config',))
        for flags in ((True, True, True, True, False, False), (True, True, True, False, True, False),
                      (True, True, True, False, False, True)):
            self.refused('left policy-rc.d', flags=flags)

    def test_the_install_script_enables_only_its_socket_and_starts_nothing(self):
        script = tool['L4_INSTALL_SCRIPT']
        self.assertIn('systemctl enable l4-lab-sshd.socket\n', script)
        for word in ('start', 'apt', 'dpkg', 'curl', 'wget', 'nftables', 'rosetun', 'mask', 'disable'):
            self.assertNotIn(word, script)

    def test_the_dependencies_are_installed_as_for_l5_and_the_image_stays_quiet(self):
        self.assertEqual((), tool['L4_ALLOWED_UNITS'])
        before = LINKS(('etc', '.', 'ssh.socket', '/dev/null'))
        after = before | LINKS(('lib', 'sockets.target.wants', 'dbus.socket', '/usr/lib/systemd/system/dbus.socket'))
        with self.assertRaisesRegex(ValueError, 'enabled dbus.socket'):
            tool['check_quiet'](before, after, tool['L4_ALLOWED_UNITS'])
        script = tool['DEPS_INSTALL_SCRIPT']
        self.assertIn('policy-rc.d', script)
        self.assertIn('[ -z "$(dpkg --audit)" ]', script)

    def test_the_default_requirements_of_the_l5_check_are_unchanged(self):
        names = {name: '9.0' for name in tool['L5_DEPENDS']}
        result = tool['check_dependencies'](status(**names))
        self.assertEqual(sorted(tool['L5_DEPENDS']), sorted(result['installed']))


class L4ArgumentTests(unittest.TestCase):
    BASE = ['/srv/v6c.qcow2', '/srv/v7.qcow2', '--source-sha256', '0' * 64, '--descriptor', '/srv/v7.json']

    def parse(self, *extra):
        self.errors = io.StringIO()
        with contextlib.redirect_stderr(self.errors):
            return tool['arguments'](self.BASE + list(extra))

    def test_the_l4_image_needs_its_packages_and_goes_alone(self):
        args = self.parse('--l4', '--deps-debs', '/srv/l4-debs')
        self.assertEqual((True, Path('/srv/l4-debs')), (args.l4, args.deps_debs))
        for extra in ((), ('--deps-debs', '/srv/d', '--sshd', '--sshd-debs', '/srv/s'),
                      ('--deps-debs', '/srv/d', '--ipv6-router'), ('--deps-debs', '/srv/d', '--check-package', '/a.deb')):
            with self.subTest(extra=extra), self.assertRaises(SystemExit):
                self.parse('--l4', *extra)
            self.assertIn('--l4 needs --deps-debs DIR', self.errors.getvalue())
        self.assertFalse(self.parse().l4)
        self.assertFalse(self.parse('--deps-debs', '/srv/d').l4)

    def test_the_descriptor_records_the_additions_and_nothing_else_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            image = Path(temp) / 'test-l4-v7.qcow2'
            image.write_bytes(b'image')
            record = dict(debs=[], installed={}, sockets=dict(listen=tool['L4_LISTEN']))
            self.assertEqual(record, tool['image_descriptor'](image, None, None, None, record)['l4'])
            for name in ('sshd', 'ipv6_router', 'l5_dependencies', 'l4'):
                self.assertNotIn(name, tool['image_descriptor'](image))


if __name__ == '__main__':
    unittest.main()
