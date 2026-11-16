"""Linux L4 (stage 8d): the stage profile, its job.env with the lab's keys, the limits of a job that reboots twice."""

import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.vm.matrix import config as matrix_config, execution, l2_import as delivery, l2_media as media
from tools.vm.matrix import l3_requests, lab_protocol, linux_l2 as l2, orchestrator
from tools.vm.matrix.tests import test_jobs
from tools.vm.matrix.tests.posix_only import controller_only
from tools.vm.matrix.tests.test_jobs import GUEST
from tools.vm.matrix.tests.test_l2_media import helper
from tools.vm.matrix.tests.test_linux_l2 import CHECKOUT, SOURCE
from tools.vm.matrix.tests.test_stage_profiles import (L3, L3_BLOCK, SING_BOX_SHA, lines_of, package_l3)

L4 = l2.PROFILES['l4']
# The ssh-ed25519 blob of the public key of the first test vector of RFC 8032: a public value, no secret anywhere.
PUBLIC = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
KEY = base64.b64encode(l2.POLLER_KEY_HEAD + PUBLIC).decode()
MARKER = '203.0.113.2:9100'


class L4ProfileTests(unittest.TestCase):
    def test_l4_is_exactly_what_start_sh_requires(self):
        self.assertEqual(sorted(lines_of('tools/vm/linux/guest/start.sh', 'L4_START_REQUIRED')), sorted(L4.payload))
        self.assertEqual(('rosetun-helper-privileged', 'rosetun', 'sing-box'), L4.binaries)
        self.assertEqual(('rosetun-helper.service', 'rosetun-engine.rules', 'rosetun-lockdown.service'),
                         tuple(a for a, _ in L4.packaged))
        self.assertEqual(('request-kill-switch.json', 'request-lan.json', 'request-dns-lock.json'), L4.requests)
        self.assertEqual(l3_requests.L4_NAMES, L4.requests)
        self.assertEqual(('l4', 'l4', L3.env, ()), (L4.name, L4.stage, L4.env, L4.packages))
        self.assertIn('l4', l2.SERVICE_PROFILES)
        self.assertEqual(l2.evidence_files('l3'), l2.evidence_files('l4'))

    def test_the_l4_build_records_the_two_attested_programs_of_the_l3_build_under_its_own_stage(self):
        script = (CHECKOUT / 'tools/vm/linux/build-artifacts.sh').read_text(encoding='utf-8')
        self.assertIn('elif [ "${1-}" = --l4 ]; then\n    stage=l4\n', script)
        self.assertIn('elif [ "$stage" = l3 ] || [ "$stage" = l4 ]; then', script)
        self.assertEqual(('rosetun-helper-privileged', 'rosetun'), L4.attested)
        self.assertEqual(L3.attested, L4.attested)
        self.assertEqual('l4', L4.stage)

    def test_the_guest_importer_table_is_the_controller_table(self):
        entry = helper.PROFILES['l4']
        self.assertEqual(media.content('l4'), tuple(entry['content']))
        self.assertEqual(L4.binaries, tuple(entry['binaries']))
        self.assertEqual(list(L4.env), entry['env'])
        self.assertIn('l4', helper.SERVICE)

    def test_the_requests_are_the_l3_files_of_the_same_names(self):
        everything = l3_requests.render_all()
        self.assertEqual({name: everything[name] for name in L4.requests}, l3_requests.render_l4())
        self.assertEqual(l3_requests.render_for('l4'), l3_requests.render_l4())

    def test_the_stage_unit_of_start_sh_reads_the_lab_keys_of_l4_alone(self):
        text = (CHECKOUT / 'tools/vm/linux/guest/start.sh').read_text(encoding='utf-8')
        self.assertIn('case $stage in l3 | proxy | l5 | l4) keys+=(LAB_MARKER_ADDRESS LAB_CONTROL) ;; esac', text)
        self.assertIn('[ "$stage" != l4 ] || keys+=(LAB_POLLER_KEY)', text)


class L4LimitsTests(unittest.TestCase):
    def test_the_span_of_a_job_with_two_reboots_counts_three_phases_and_both_reboots(self):
        self.assertEqual(2, matrix_config.planned_reboots_of('linux-l4'))
        self.assertEqual(3 * 600 + 2 * matrix_config.REBOOT_SECONDS, matrix_config.job_span('linux-l4', 600))
        self.assertEqual(2280, matrix_config.job_span('linux-l4', 600))
        self.assertEqual(2405, matrix_config.wait_seconds('linux-l4', 600))
        # The one-phase suites and the smoke job, which reboots once inside its one phase, wait as they always did.
        for suite in ('linux-l2', 'linux-l3', 'linux-proxy', 'linux-l5', 'linux-reboot-smoke'):
            self.assertEqual(900, matrix_config.job_span(suite, 900))
            self.assertEqual(1025, matrix_config.wait_seconds(suite, 900))
        self.assertEqual(1, matrix_config.planned_reboots_of('linux-reboot-smoke'))
        self.assertEqual(matrix_config.planned_reboots_of('linux-l4') + 1, matrix_config.PHASES['linux-l4'])

    def test_the_capture_holds_the_span_and_the_room_for_the_boots_and_no_more_than_the_limit(self):
        self.assertEqual(2580, 2280 + lab_protocol.CAPTURE_SLACK)
        self.assertLessEqual(2580, lab_protocol.DURATION_MAX)
        # The most a phase may take is what still fits: 3 * 640 + 2 * 240 + 300 = 2700.
        self.assertEqual(lab_protocol.DURATION_MAX, 3 * 640 + 2 * matrix_config.REBOOT_SECONDS +
                         lab_protocol.CAPTURE_SLACK)
        block = dict(image={}, tunnel=dict(node_port=8388), https_cert_sha256='0' * 64, doh_cert_sha256='0' * 64)
        l3 = dict(L3_BLOCK)

        def check(job, span):
            with patch.object(execution, 'exact'), patch('tools.vm.matrix.lab.validate_tunnel'):
                execution.validate_lab(block, l3, job, span)

        check(640, matrix_config.job_span('linux-l4', 640))
        with self.assertRaisesRegex(ValueError, 'at most 2400 seconds'):
            check(641, matrix_config.job_span('linux-l4', 641))
        # A job of one phase is held to the old limit.
        check(1800, 1800)
        with self.assertRaises(ValueError):
            check(1801, 1801)

    def test_the_example_configurations_agree_with_the_span(self):
        import tomllib
        directory = Path(__file__).resolve().parents[1]
        for name in ('execution-l4.example.toml', 'execution-l4-lab.example.toml'):
            config = tomllib.loads((directory / name).read_text(encoding='utf-8'))
            self.assertEqual('linux-l4', config['suite'])
            self.assertEqual(matrix_config.job_span('linux-l4', config['timeouts']['job']) + 180,
                             config['deadlines']['execution'])
        self.assertEqual('rosetun.matrix.execution.v2', tomllib.loads(
            (directory / 'execution-l4.example.toml').read_text(encoding='utf-8'))['schema'])
        self.assertEqual('rosetun.matrix.execution.v3', tomllib.loads(
            (directory / 'execution-l4-lab.example.toml').read_text(encoding='utf-8'))['schema'])

    def test_the_orchestrator_runs_only_a_configuration_of_its_suite(self):
        with self.assertRaises(ValueError):
            orchestrator.run_linux_l4(dict(suite='linux-l5'))
        self.assertIn('linux-l4', execution.SERVICE_SUITES)
        self.assertEqual('l4', execution.PROFILE_OF['linux-l4'])
        self.assertNotIn('linux-l4', execution.WITHOUT_ENGINE)

    def test_the_cli_names_the_suite_and_keeps_the_lab_for_a_later_commit(self):
        from tools.vm.matrix import cli
        text = Path(cli.__file__).read_text(encoding='utf-8')
        self.assertIn("'linux-l4': orchestrator.run_linux_l4", text)


class L4EnvTests(unittest.TestCase):
    def raw(self, *extra):
        base = [f'{k}={v}' for k, v in dict(
            RUN_ID=GUEST, STAND_ID='synthetic', EXPECTED_BOOT_ID='1' * 8 + '-1111-1111-1111-' + '1' * 12,
            USER_A='l2a', USER_B='l2b', BIOS_GUID='2' * 8 + '-2222-2222-2222-' + '2' * 12,
            SCENARIO_TIMEOUT_SECONDS='30', UNIT_TIMEOUT_SECONDS='180', JOB_TIMEOUT_SECONDS='600',
            HOST_ADDRESS='192.0.2.1', NODE_PORT='8388', PROBE_ADDRESS='203.0.113.2',
            DNS_PROBE_ADDRESS='203.0.113.53').items()]
        return ('\n'.join(base + list(extra)) + '\n').encode()

    def test_the_poller_key_is_optional_comes_after_the_marker_and_only_for_l4(self):
        l2.validate_env(self.raw(), 'l4')
        l2.validate_env(self.raw('LAB_MARKER_ADDRESS=' + MARKER, 'LAB_CONTROL=stop-helper', 'LAB_POLLER_KEY=' + KEY), 'l4')
        l2.validate_env(self.raw('LAB_MARKER_ADDRESS=' + MARKER, 'LAB_POLLER_KEY=' + KEY), 'l4')
        with self.assertRaisesRegex(ValueError, 'l4-job-env-poller-key'):
            l2.validate_env(self.raw('LAB_POLLER_KEY=' + KEY), 'l4')
        for other in ('l3', 'proxy', 'l5'):
            with self.assertRaises(ValueError):
                l2.validate_env(self.raw('LAB_MARKER_ADDRESS=' + MARKER, 'LAB_POLLER_KEY=' + KEY), other)

    def test_only_the_blob_of_an_ed25519_public_key_is_a_poller_key(self):
        other_type = base64.b64encode(b'\x00\x00\x00\x07ssh-rsa' + bytes(44)).decode()
        for value in (KEY[:-1], KEY + 'A', other_type, 'A' * 68, KEY.replace('+', '-'),
                      base64.b64encode(l2.POLLER_KEY_HEAD + PUBLIC + b'x').decode()):
            with self.assertRaises(ValueError, msg=value):
                l2.validate_env(self.raw('LAB_MARKER_ADDRESS=' + MARKER, 'LAB_POLLER_KEY=' + value), 'l4')
        self.assertTrue(l2.poller_key_shape(KEY))
        self.assertEqual(68, len(KEY))
        self.assertTrue(KEY.startswith('AAAAC3NzaC1lZDI1NTE5AAAAI'))


@controller_only
class L4DeliveryTests(unittest.TestCase):
    """The package, the importer in the image and job.env with the poller's key."""

    def setUp(self):
        self.fixture = test_jobs.JobsTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.vm = self.fixture.vm
        del self.vm._smoke_job
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        package_l3(self.root, self.vm.vm_uuid, self.vm.run._identity[1], profile=L4)
        with patch.object(l2, 'source_identity', return_value=SOURCE):
            self.full = l2.validate_package(self.root, checkout=CHECKOUT, profile='l4', sing_box_sha256=SING_BOX_SHA)
        (self.root / 'job.env').unlink()
        (self.root / 'manifest.sha256').unlink()
        with patch.object(l2, 'source_identity', return_value=SOURCE):
            package = l2.validate_package(self.root, checkout=CHECKOUT, immutable=True, profile='l4',
                                          sing_box_sha256=SING_BOX_SHA)
        names = media.content('l4')
        listing = media.manifest(package['hashes'], names)
        self.vm._l2_media = dict(package=package, sha256='c' * 64, size=2048,
                                 content_sha256=hashlib.sha256(listing).hexdigest())
        from tools.vm.matrix.resources import _atomic_manifest
        record = self.vm.run._read()
        for index, name in enumerate(media.resources('l4')):
            record['resources'].append(dict(id='import-test-' + str(index), kind='file', path=name))
            path = self.vm.run.directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        _atomic_manifest(self.vm.run.directory, record)
        for name in names:
            (self.vm.run.directory / 'l2-package' / name).write_bytes((self.root / name).read_bytes())

    def importer(self, ids='d', **block):
        return delivery.L2Import(self.vm, guest_run_id=GUEST, import_id=ids * 32, user_a='l2a', user_b='l2b',
                                 enabled=True, l3=dict(L3_BLOCK, **block))

    def test_the_package_carries_the_l4_catalog_profile_engine_and_the_lockdown_unit(self):
        self.assertEqual('l4', self.full['profile'])
        self.assertEqual(27, len(self.full['catalog']))
        self.assertEqual(set(L4.files), set(self.full['hashes']))
        self.assertEqual(list(L3.env), list(self.full['env']))
        self.assertEqual(SING_BOX_SHA, self.full['hashes']['artifacts/sing-box'])
        self.assertIn('artifacts/rosetun-lockdown.service', self.full['hashes'])

    def test_a_package_of_another_profile_is_not_an_l4_package(self):
        with patch.object(l2, 'source_identity', return_value=SOURCE), self.assertRaises(ValueError):
            l2.validate_package(self.root, checkout=CHECKOUT, immutable=True, profile='l3',
                                sing_box_sha256=SING_BOX_SHA)

    def test_the_requests_must_be_the_generator_output(self):
        (self.root / 'artifacts/request-lan.json').write_bytes(l3_requests.render_l4()['request-dns-lock.json'])
        with patch.object(l2, 'source_identity', return_value=SOURCE), self.assertRaises(ValueError):
            l2.validate_package(self.root, checkout=CHECKOUT, immutable=True, profile='l4',
                                sing_box_sha256=SING_BOX_SHA)

    def test_job_env_takes_the_marker_the_control_and_the_key_in_that_order_and_the_image_agrees(self):
        plain = self.importer('a')
        package = self.vm.run.directory / 'l2-package'
        self.assertEqual('l4', plain.identity['profile'])
        self.assertNotIn('LAB_POLLER_KEY', plain.request['env'])
        for ids, extra in (('b', dict(lab_marker_address=MARKER, lab_poller_key=KEY)),
                           ('c', dict(lab_marker_address=MARKER, lab_control='stop-helper', lab_poller_key=KEY))):
            del self.vm._l2_import
            for name in ('job.env', 'manifest.sha256'):
                (package / name).write_bytes(b'')
            obj = self.importer(ids, **extra)
            raw = (package / 'job.env').read_bytes()
            rows = raw.decode().splitlines()
            self.assertEqual(['LAB_MARKER_ADDRESS=' + MARKER] + (['LAB_CONTROL=stop-helper'] if 'lab_control' in extra
                                                                 else []) + ['LAB_POLLER_KEY=' + KEY], rows[13:])
            l2.validate_env(raw, 'l4')
            identity, hashes, sizes, env, final = helper.request(
                base64.b64encode(json.dumps(obj.request).encode()).decode())
            self.assertEqual((raw, 'l4'), (env, identity['profile']))

    def test_a_key_without_the_marker_never_reaches_the_guest(self):
        with self.assertRaises(ValueError):
            self.importer('e', lab_poller_key=KEY)

    def test_the_importer_in_the_image_refuses_a_key_of_another_shape(self):
        obj = self.importer('f', lab_marker_address=MARKER, lab_poller_key=KEY)
        request = json.loads(json.dumps(obj.request))
        request['env']['LAB_POLLER_KEY'] = 'A' * 68
        with self.assertRaises(Exception):
            helper.request(base64.b64encode(json.dumps(request).encode()).decode())
        request['env']['LAB_POLLER_KEY'] = KEY
        helper.request(base64.b64encode(json.dumps(request).encode()).decode())


if __name__ == '__main__':
    unittest.main()
