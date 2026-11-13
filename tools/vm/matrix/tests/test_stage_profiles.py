"""Stage profiles: L3 delivery next to an L2 that must stay byte for byte as it was."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

from tools.vm.matrix import l2_import as delivery, l2_media as media, l3_requests, linux_l2 as l2
from tools.vm.matrix.jobs import JobError
from tools.vm.matrix.tests import test_jobs, test_l2_media, test_linux_l2
from tools.vm.matrix.tests.test_jobs import GUEST
from tools.vm.matrix.tests.test_l2_media import helper
from tools.vm.matrix.tests.test_linux_l2 import CHECKOUT, SOURCE
from tools.vm.matrix.tests.test_matrix import summarize, synthetic_inputs
from tools.vm.matrix.tests.test_qga import BOOT, read

L3 = l2.PROFILES['l3']
ELF = b'\x7fELF\x02\x01' + b'\0' * 10 + b'\x02\0\x3e\0'
SING_BOX = ELF + b'inert sing-box fixture; never execute'
SING_BOX_SHA = hashlib.sha256(SING_BOX).hexdigest()
L3_BLOCK = dict(sing_box_sha256=SING_BOX_SHA, **l2.L3_DEFAULTS)


def lines_of(path, array):
    text = (CHECKOUT / path).read_text(encoding='utf-8')
    return re.search(array + r'=\(([^)]*)\)', text).group(1).split()


def checkout_bytes(name):
    return (CHECKOUT / name).read_bytes().replace(b'\r\n', b'\n')


def package_l3(root, vm_uuid, stand='synthetic-l3', **env_overrides):
    """A complete L3 package: real scripts, units and requests, inert binaries."""
    for name in L3.sources:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(checkout_bytes('tools/vm/linux/' + name).rstrip(b'\n') + b'\n')
    (root / 'artifacts').mkdir()
    artifacts = {}
    for name in L3.binaries:
        data = SING_BOX if name == 'sing-box' else ELF + name.encode() + b' inert fixture'
        (root / 'artifacts' / name).write_bytes(data)
        artifacts[name] = dict(sha256=hashlib.sha256(data).hexdigest())
    for name, source in L3.packaged:
        (root / 'artifacts' / name).write_bytes(checkout_bytes(source))
    l3_requests.write_all(root / 'artifacts')
    provenance = dict(schema=1, stage='l3', target='x86_64-unknown-linux-gnu', **SOURCE,
                      artifacts={n: artifacts[n] for n in L3.attested})
    (root / 'artifacts/provenance.json').write_text(json.dumps(provenance), encoding='ascii')
    env = dict(RUN_ID=GUEST, STAND_ID=stand, EXPECTED_BOOT_ID=BOOT, USER_A='l2a', USER_B='l2b',
               BIOS_GUID=vm_uuid, SCENARIO_TIMEOUT_SECONDS='30', UNIT_TIMEOUT_SECONDS='180',
               JOB_TIMEOUT_SECONDS='900', HOST_ADDRESS='192.0.2.1', NODE_PORT='8388',
               PROBE_ADDRESS='203.0.113.2', DNS_PROBE_ADDRESS='203.0.113.53')
    env.update(env_overrides)
    (root / 'job.env').write_bytes(''.join(f'{k}={v}\n' for k, v in env.items()).encode())
    manifest_l3(root)


def manifest_l3(root):
    (root / 'manifest.sha256').write_bytes(''.join(
        hashlib.sha256((root / n).read_bytes()).hexdigest() + '  ' + n + '\n' for n in L3.payload).encode())


def register_evidence(run, stage):
    """What lifecycle.start reserves for the stage's job evidence (the fixture's run already started)."""
    from tools.vm.matrix.resources import _atomic_manifest
    record = run._read()
    for index, name in enumerate(l2.evidence_files(stage)):
        relative = 'linux-' + stage + '/' + name
        record['resources'].append(dict(id='linux-' + stage + '-' + str(index), kind='file', path=relative))
        path = run.directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=False)
    _atomic_manifest(run.directory, record)


class ProfileTableTests(unittest.TestCase):
    def test_l3_is_exactly_what_start_sh_requires_and_l2_is_unchanged(self):
        required = lines_of('tools/vm/linux/guest/start.sh', 'L3_START_REQUIRED')
        self.assertEqual(sorted(required), sorted(n for n in L3.payload))
        self.assertEqual(sorted(lines_of('tools/vm/linux/guest/start.sh', 'L2_START_REQUIRED')),
                         sorted(l2.PROFILES['l2'].payload))
        self.assertEqual(l2.PAYLOAD, l2.PROFILES['l2'].payload)
        self.assertEqual(l2.FILES, l2.PROFILES['l2'].files)

    def test_guest_importer_table_equals_the_controller_table(self):
        for name, profile in l2.PROFILES.items():
            entry = helper.PROFILES[name]
            self.assertEqual(media.content(name), tuple(entry['content']))
            self.assertEqual(profile.binaries, tuple(entry['binaries']))
            self.assertEqual(list(profile.env), entry['env'])
            self.assertEqual(5, len(profile.sources))
        self.assertEqual(media.CONTENT, media.content('l2'))

    def test_l3_delivers_the_documented_artifacts(self):
        self.assertEqual(('rosetun-helper-privileged', 'rosetun', 'sing-box'), L3.binaries)
        self.assertEqual(('rosetun-helper.service', 'rosetun-engine.rules'), tuple(a for a, _ in L3.packaged))
        self.assertEqual(l3_requests.NAMES, L3.requests)
        self.assertEqual('l3', L3.stage)
        self.assertEqual(13, len(L3.env))
        with self.assertRaises(JobError):
            l2.profile_of('l4')


class L2BytesTests(unittest.TestCase):
    """The old literals, written out so any drift in L2 is a visible edit."""

    SOURCES = ('guest/launch.sh', 'guest/start.sh', 'guest/lib.sh', 'guest/run-l2.sh', 'scenarios.tsv')
    ARTIFACTS = ('artifacts/l2_transport_fixture', 'artifacts/rosetun_helper_privileged_tests',
                 'artifacts/rosetun_ipc_tests', 'artifacts/provenance.json')
    ENV = ('RUN_ID', 'STAND_ID', 'EXPECTED_BOOT_ID', 'USER_A', 'USER_B', 'BIOS_GUID',
           'SCENARIO_TIMEOUT_SECONDS', 'UNIT_TIMEOUT_SECONDS', 'JOB_TIMEOUT_SECONDS')

    def test_package_media_and_resource_lists_are_the_old_ones(self):
        payload = self.SOURCES + ('job.env',) + self.ARTIFACTS
        self.assertEqual(payload, l2.PAYLOAD)
        self.assertEqual(payload + ('manifest.sha256',), l2.FILES)
        content = tuple(n for n in payload if n != 'job.env')
        self.assertEqual(content, media.CONTENT)
        self.assertEqual(('l2-media.iso', 'l2-media.jsonl', 'l2-media.json', 'l2-import.jsonl',
                          'l2-receipt.json') + tuple('l2-snapshot/' + n for n in content + ('content.sha256',)) +
                         tuple('l2-package/' + n for n in l2.FILES), media.RESOURCES)
        self.assertEqual(self.ENV, l2.PROFILES['l2'].env)

    def test_validated_l2_package_has_the_old_keys_and_no_profile(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(l2, 'source_identity', return_value=SOURCE):
            root = Path(temp)
            test_linux_l2.package(root, BOOT)
            package = l2.validate_package(root, checkout=CHECKOUT)
            self.assertEqual({'env', 'hashes', 'sizes', 'source', 'catalog', 'catalog_digest',
                              'provenance', 'origin'}, set(package))
            self.assertEqual(set(self.ENV), set(package['env']))
            self.assertEqual(l2.FILES, tuple(package['hashes']))

    def test_l2_import_job_env_request_and_receipt_are_the_old_bytes(self):
        fixture = test_l2_media.ImportTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        vm = fixture.vm
        fixture.obj.stage()
        expected = ''.join(f'{k}={v}\n' for k, v in zip(self.ENV, (
            GUEST, vm.run._identity[1], BOOT, 'l2a', 'l2b', vm.vm_uuid, '30', '180', '900'))).encode()
        self.assertEqual(expected, (vm.run.directory / 'l2-package/job.env').read_bytes())
        self.assertEqual(set(fixture.obj.identity), set(
            'host_run_id guest_run_id stand_id vm_uuid boot_id import_id media_sha256 media_size '
            'content_sha256 manifest_sha256'.split()))
        self.assertEqual({'identity', 'env', 'hashes', 'sizes'}, set(fixture.obj.request))
        manifest = ''.join(hashlib.sha256(
            (vm.run.directory / 'l2-package' / n).read_bytes()).hexdigest() + '  ' + n + '\n'
            for n in l2.PAYLOAD).encode()
        self.assertEqual(manifest, (vm.run.directory / 'l2-package/manifest.sha256').read_bytes())
        encoded = base64.b64encode(json.dumps(fixture.obj.request).encode()).decode()
        identity, hashes, sizes, env, final = helper.request(encoded)
        self.assertEqual((expected, manifest), (env, final))
        self.assertNotIn('profile', identity)
        self.assertEqual(dict(identity, schema='rosetun.l2-import.v1', state='ready'),
                         json.loads(fixture.fixture.files['ready.json']))

    def test_an_l2_request_may_not_name_a_profile(self):
        fixture = test_l2_media.ImportTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for profile in ('l2', 'l4', ['l3'], None):
            request = copy.deepcopy(fixture.obj.request)
            request['identity']['profile'] = profile
            with self.assertRaises((ValueError, TypeError), msg=repr(profile)):
                helper.request(base64.b64encode(json.dumps(request).encode()).decode())

    def test_l2_job_keeps_its_evidence_directory_and_identity(self):
        fixture = test_linux_l2.ExecutionTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.assertEqual('linux-l2', fixture.job.identity['job_id'])
        self.assertEqual('l2', fixture.job.profile.name)
        self.assertEqual('linux-l2', fixture.job.plan['suite'])
        self.assertTrue((fixture.vm.run.directory / 'linux-l2/plan.json').is_file())


class L3PackageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        package_l3(self.root, BOOT)
        patcher = patch.object(l2, 'source_identity', return_value=SOURCE)
        patcher.start()
        self.addCleanup(patcher.stop)

    def validate(self, **kwargs):
        kwargs.setdefault('sing_box_sha256', SING_BOX_SHA)
        return l2.validate_package(self.root, checkout=CHECKOUT, profile='l3', **kwargs)

    def rewrite_provenance(self, **changes):
        path = self.root / 'artifacts/provenance.json'
        data = json.loads(path.read_bytes())
        data.update(changes)
        path.write_text(json.dumps(data), encoding='ascii')
        manifest_l3(self.root)

    def test_complete_package_is_accepted_with_the_l3_catalog_and_env(self):
        package = self.validate()
        self.assertEqual('l3', package['profile'])
        self.assertEqual((39, 38), (len(package['catalog']), sum(r['required'] for r in package['catalog'])))
        self.assertEqual(list(L3.env), list(package['env']))
        self.assertEqual(set(L3.files), set(package['hashes']))
        self.assertEqual(SING_BOX_SHA, package['hashes']['artifacts/sing-box'])

    def test_immutable_package_has_no_job_env_or_manifest(self):
        (self.root / 'job.env').unlink()
        (self.root / 'manifest.sha256').unlink()
        package = self.validate(immutable=True)
        self.assertEqual({}, package['env'])
        self.assertEqual(set(media.content('l3')), set(package['hashes']))

    def test_an_extra_file_or_directory_is_refused(self):
        for make in (lambda r: (r / 'artifacts/extra').write_bytes(b'x'),
                     lambda r: (r / 'guest/run-l2.sh').write_bytes(b'x'),
                     lambda r: (r / 'empty').mkdir()):
            with self.subTest(make=make):
                make(self.root)
                with self.assertRaisesRegex(ValueError, 'composition'):
                    self.validate()
                extra = [p for p in (self.root / 'artifacts/extra', self.root / 'guest/run-l2.sh',
                                     self.root / 'empty') if p.exists()]
                for p in extra:
                    p.rmdir() if p.is_dir() else p.unlink()

    def test_every_missing_file_is_refused(self):
        for name in L3.files:
            with self.subTest(name=name):
                saved = (self.root / name).read_bytes()
                (self.root / name).unlink()
                with self.assertRaises(ValueError):
                    self.validate()
                (self.root / name).write_bytes(saved)
        self.validate()

    def test_l2_provenance_stage_in_an_l3_package_is_refused(self):
        self.rewrite_provenance(stage='l2')
        with self.assertRaisesRegex(ValueError, 'provenance'):
            self.validate()
        data = json.loads((self.root / 'artifacts/provenance.json').read_bytes())
        del data['stage']
        (self.root / 'artifacts/provenance.json').write_text(json.dumps(data), encoding='ascii')
        manifest_l3(self.root)
        with self.assertRaisesRegex(ValueError, 'provenance'):
            self.validate()

    def test_l3_stage_in_an_l2_package_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            test_linux_l2.package(root, BOOT)
            path = root / 'artifacts/provenance.json'
            data = json.loads(path.read_bytes())
            data['stage'] = 'l3'
            path.write_text(json.dumps(data), encoding='ascii')
            test_linux_l2.manifest(root)
            with self.assertRaisesRegex(ValueError, 'provenance'):
                l2.validate_package(root, checkout=CHECKOUT)

    def test_the_package_of_one_profile_is_not_the_package_of_the_other(self):
        with self.assertRaisesRegex(ValueError, 'composition'):
            l2.validate_package(self.root, checkout=CHECKOUT, profile='l2')
        with tempfile.TemporaryDirectory() as temp:
            test_linux_l2.package(Path(temp), BOOT)
            with self.assertRaisesRegex(ValueError, 'composition'):
                l2.validate_package(temp, checkout=CHECKOUT, profile='l3', sing_box_sha256=SING_BOX_SHA)

    def test_sing_box_hash_must_match_the_configuration(self):
        for pinned in ('0' * 64, SING_BOX_SHA.upper(), None, '', 7):
            with self.subTest(pinned=pinned), self.assertRaisesRegex(ValueError, 'sing-box'):
                self.validate(sing_box_sha256=pinned)
        (self.root / 'artifacts/sing-box').write_bytes(SING_BOX + b'changed')
        manifest_l3(self.root)
        with self.assertRaisesRegex(ValueError, 'sing-box'):
            self.validate()

    def test_each_binary_must_be_an_x86_64_elf(self):
        for name in L3.binaries:
            with self.subTest(name=name):
                path = self.root / 'artifacts' / name
                saved = path.read_bytes()
                path.write_bytes(b'MZ' + saved[2:])
                data = json.loads((self.root / 'artifacts/provenance.json').read_bytes())
                if name in data['artifacts']:
                    data['artifacts'][name]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                    (self.root / 'artifacts/provenance.json').write_text(json.dumps(data), encoding='ascii')
                manifest_l3(self.root)
                sha = hashlib.sha256(path.read_bytes()).hexdigest() if name == 'sing-box' else SING_BOX_SHA
                with self.assertRaisesRegex(ValueError, 'elf'):
                    self.validate(sing_box_sha256=sha)
                path.write_bytes(saved)
                package_l3_provenance = json.loads((self.root / 'artifacts/provenance.json').read_bytes())
                if name in package_l3_provenance['artifacts']:
                    package_l3_provenance['artifacts'][name]['sha256'] = hashlib.sha256(saved).hexdigest()
                    (self.root / 'artifacts/provenance.json').write_text(
                        json.dumps(package_l3_provenance), encoding='ascii')
                manifest_l3(self.root)

    def test_attested_binaries_must_match_provenance(self):
        path = self.root / 'artifacts/rosetun'
        path.write_bytes(path.read_bytes() + b'changed')
        manifest_l3(self.root)
        with self.assertRaisesRegex(ValueError, 'provenance'):
            self.validate()

    def test_unit_rules_scripts_and_catalog_must_be_the_checkout_bytes(self):
        for name in ('artifacts/rosetun-helper.service', 'artifacts/rosetun-engine.rules',
                     'guest/run-l3.sh', 'scenarios-l3.tsv'):
            with self.subTest(name=name):
                path = self.root / name
                saved = path.read_bytes()
                path.write_bytes(saved + b'# changed\n')
                manifest_l3(self.root)
                with self.assertRaisesRegex(ValueError, 'checkout'):
                    self.validate()
                path.write_bytes(saved)
                manifest_l3(self.root)
        self.validate()

    def test_checkout_without_the_packaging_files_refuses(self):
        with tempfile.TemporaryDirectory() as temp:
            shutil.copytree(CHECKOUT / 'tools/vm/linux', Path(temp) / 'tools/vm/linux',
                            ignore=shutil.ignore_patterns('logs', '__pycache__'))
            with self.assertRaises((ValueError, OSError)):
                l2.validate_package(self.root, checkout=Path(temp), profile='l3', sing_box_sha256=SING_BOX_SHA)

    def test_job_env_addresses_must_be_documentation_addresses(self):
        for key, value in (('HOST_ADDRESS', '10.0.0.1'), ('HOST_ADDRESS', '172.30.48.1'),
                           ('PROBE_ADDRESS', '1.1.1.1'), ('DNS_PROBE_ADDRESS', '8.8.8.8'),
                           ('PROBE_ADDRESS', '203.0.113.256'), ('HOST_ADDRESS', '192.0.2'),
                           ('PROBE_ADDRESS', '203.000.113.2'), ('NODE_PORT', '0'),
                           ('NODE_PORT', '65536'), ('NODE_PORT', '80a'), ('NODE_PORT', '')):
            with self.subTest(key=key, value=value):
                package_l3_env = {key: value}
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    package_l3(root, BOOT, **package_l3_env)
                    with self.assertRaises(ValueError):
                        l2.validate_package(root, checkout=CHECKOUT, profile='l3', sing_box_sha256=SING_BOX_SHA)

    def test_env_fields_belong_to_the_profile(self):
        with self.assertRaisesRegex(ValueError, 'fields'):
            l2.validate_env((self.root / 'job.env').read_bytes(), 'l2')
        legacy = b''.join(line + b'\n' for line in (self.root / 'job.env').read_bytes().splitlines()[:9])
        with self.assertRaisesRegex(ValueError, 'fields'):
            l2.validate_env(legacy, 'l3')
        self.assertEqual(9, len(l2.validate_env(legacy, 'l2')))
        self.assertEqual(13, len(l2.validate_env((self.root / 'job.env').read_bytes(), 'l3')))

    def test_the_lab_marker_address_is_optional_and_only_the_markers_of_the_lab(self):
        raw = (self.root / 'job.env').read_bytes()
        self.assertEqual(14, len(l2.validate_env(raw + b'LAB_MARKER_ADDRESS=203.0.113.2:9100\n', 'l3')))
        for value in ('203.0.113.2:9101', '203.0.113.2', '10.0.0.1:9100', '1.1.1.1:9100', '203.0.113.256:9100',
                      '203.000.113.2:9100', ':9100', '203.0.113.2:09100', 'doh.lab.test:9100'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                l2.validate_env(raw + b'LAB_MARKER_ADDRESS=' + value.encode() + b'\n', 'l3')
        with self.assertRaisesRegex(ValueError, 'fields'):
            l2.validate_env(raw + b'LAB_MARKER_ADDRESS=203.0.113.2:9100\n', 'l2')
        with self.assertRaisesRegex(ValueError, 'invalid'):
            l2.validate_env(raw + b'LAB_MARKER_ADDRESS=203.0.113.2:9100\nLAB_MARKER_ADDRESS=203.0.113.2:9100\n', 'l3')

    def test_requests_must_be_the_generator_output_for_one_node(self):
        path = self.root / 'artifacts/request-lan.json'
        saved = path.read_bytes()
        path.write_bytes(saved.replace(b'"allow_lan": true', b'"allow_lan": false'))
        manifest_l3(self.root)
        with self.assertRaisesRegex(ValueError, 'request'):
            self.validate()
        path.write_bytes(b'[]\n')
        manifest_l3(self.root)
        with self.assertRaisesRegex(ValueError, 'request'):
            self.validate()
        path.write_bytes(saved)
        manifest_l3(self.root)
        self.validate()

    def test_diagnostic_requests_are_accepted_only_all_together(self):
        diagnostic = l3_requests.render_all('192.0.2.1', 8388, diagnostic=True)
        for name, data in diagnostic.items():
            (self.root / 'artifacts' / name).write_bytes(data)
        manifest_l3(self.root)
        self.validate()
        # One ordinary connect request among diagnostic ones is a package nobody generated.
        ordinary = l3_requests.render_all('192.0.2.1', 8388)
        (self.root / 'artifacts/request-lan.json').write_bytes(ordinary['request-lan.json'])
        manifest_l3(self.root)
        with self.assertRaisesRegex(ValueError, 'request'):
            self.validate()

    def test_requests_must_name_the_node_of_job_env(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package_l3(root, BOOT)
            for name, data in l3_requests.render_all('198.51.100.7', 9000).items():
                (root / 'artifacts' / name).write_bytes(data)
            manifest_l3(root)
            with self.assertRaisesRegex(ValueError, 'node'):
                l2.validate_package(root, checkout=CHECKOUT, profile='l3', sing_box_sha256=SING_BOX_SHA)
            # One file for another node is refused even when the others agree.
            package_l3(root.with_name(root.name + '-b'), BOOT)
        other = l3_requests.render_all('198.51.100.7', 9000)
        (self.root / 'artifacts/request-lan.json').write_bytes(other['request-lan.json'])
        manifest_l3(self.root)
        with self.assertRaisesRegex(ValueError, 'node'):
            self.validate()

    def strip_to_input(self):
        """The owner's input tree: no job.env, no manifest and no generated requests."""
        (self.root / 'job.env').unlink()
        (self.root / 'manifest.sha256').unlink()
        full = self.validate(immutable=True)
        generated = {}
        for name in L3.requests:
            generated[name] = (self.root / 'artifacts' / name).read_bytes()
            (self.root / 'artifacts' / name).unlink()
        return full, generated

    def test_the_input_tree_has_no_requests_and_they_are_not_hashed_with_it(self):
        self.strip_to_input()
        with self.assertRaisesRegex(ValueError, 'composition'):
            self.validate(immutable=True)
        package = self.validate(immutable=True, without_requests=True)
        self.assertFalse(any(n.startswith('artifacts/request-') for n in package['hashes']))

    def test_requests_from_the_run_directory_give_the_package_of_the_full_tree(self):
        full, generated = self.strip_to_input()
        with tempfile.TemporaryDirectory() as temp:
            for name, data in generated.items():
                (Path(temp) / name).write_bytes(data)
            package = self.validate(immutable=True, requests_directory=temp)
        self.assertEqual(full, package)
        self.assertEqual(tuple(full['hashes']), tuple(package['hashes']))

    def test_a_request_file_in_the_content_directory_is_refused(self):
        _, generated = self.strip_to_input()
        with tempfile.TemporaryDirectory() as temp:
            for name, data in generated.items():
                (Path(temp) / name).write_bytes(data)
            for name in ('request-lan.json', 'request-dns-lock.json'):
                with self.subTest(name=name):
                    (self.root / 'artifacts' / name).write_bytes(generated[name])
                    with self.assertRaisesRegex(ValueError, 'l3-requests-in-content'):
                        self.validate(immutable=True, without_requests=True)
                    with self.assertRaisesRegex(ValueError, 'l3-requests-in-content'):
                        self.validate(immutable=True, requests_directory=temp)
                    (self.root / 'artifacts' / name).unlink()
        # Even a different file under a request name is a content error, not a generator one.
        (self.root / 'artifacts/request-lan.json').write_bytes(b'{}\n')
        with self.assertRaisesRegex(ValueError, 'l3-requests-in-content'):
            self.validate(immutable=True, without_requests=True)

    def test_requests_of_the_run_are_compared_with_the_generator(self):
        _, generated = self.strip_to_input()
        with tempfile.TemporaryDirectory() as temp:
            for name, data in generated.items():
                (Path(temp) / name).write_bytes(data)
            (Path(temp) / 'request-lan.json').write_bytes(b'{}\n')
            with self.assertRaisesRegex(ValueError, 'request'):
                self.validate(immutable=True, requests_directory=temp)
            (Path(temp) / 'request-lan.json').unlink()
            with self.assertRaisesRegex(ValueError, 'request'):
                self.validate(immutable=True, requests_directory=temp)

    def test_without_requests_does_not_excuse_a_missing_script(self):
        self.strip_to_input()
        (self.root / 'guest/lib.sh').unlink()
        with self.assertRaisesRegex(ValueError, 'composition'):
            self.validate(immutable=True, without_requests=True)

    def test_text_artifacts_have_the_l2_size_limit(self):
        (self.root / 'artifacts/rosetun-engine.rules').write_bytes(b'x' * (256 * 1024 + 1))
        manifest_l3(self.root)
        with self.assertRaises(ValueError):
            self.validate()


class L3MediaTests(unittest.TestCase):
    diagnostic = False

    def setUp(self):
        self.fixture = test_l2_media.MediaTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        for child in list(self.root.iterdir()):
            shutil.rmtree(child) if child.is_dir() else child.unlink()
        package_l3(self.root, BOOT)
        for name in ('job.env', 'manifest.sha256', *('artifacts/' + n for n in L3.requests)):
            (self.root / name).unlink()
        self.run = self.fixture.run
        media.write_requests(self.run, '192.0.2.1', 8388, **({'diagnostic': True} if self.diagnostic else {}))

    def tree(self):
        return {p.relative_to(self.root).as_posix(): (p.read_bytes() if p.is_file() else None)
                for p in self.root.rglob('*')}

    def build(self, **kwargs):
        options = dict(profile='l3', sing_box_sha256=SING_BOX_SHA)
        options.update(kwargs)
        return media.attach_media(self.run, directory=self.root, checkout=CHECKOUT,
                                  xorriso=self.fixture.plan['config']['executable'],
                                  executor=self.fixture.executor, **options)

    def test_snapshot_label_resources_and_record_carry_the_profile(self):
        record = self.build()
        snapshot = self.run.directory / 'l2-snapshot'
        found = {p.relative_to(snapshot).as_posix() for p in snapshot.rglob('*') if p.is_file()}
        self.assertEqual(set(media.content('l3')) | {'content.sha256'}, found)
        rendered = l3_requests.render_all('192.0.2.1', 8388)
        for name, data in rendered.items():
            self.assertEqual(data, (self.run.directory / 'l3-requests' / name).read_bytes())
            self.assertEqual(data, (snapshot / 'artifacts' / name).read_bytes())
            self.assertEqual(data, (self.run.directory / 'l2-package/artifacts' / name).read_bytes())
        self.assertEqual('l3', record['package']['profile'])
        argv = self.fixture.commands[1][0]
        self.assertEqual(['-as', 'mkisofs', '-iso-level', '3', '-R', '-V', 'ROSETUN_L3'], argv[2:9])
        registered = [r['path'] for r in self.run._read()['resources'] if r['id'].startswith('l2-media-')]
        self.assertEqual(list(media.resources('l3')), registered)
        plan = json.loads((self.run.directory / 'launch-plan.json').read_bytes())
        self.assertEqual('l3', plan['l2_media']['package']['profile'])
        media.verify_media(record)

    def test_diagnostic_requests_are_written_by_the_run_and_delivered_as_they_are(self):
        self.diagnostic = True
        self.setUp()
        record = self.build()
        rendered = l3_requests.render_all('192.0.2.1', 8388, diagnostic=True)
        self.assertNotEqual(l3_requests.render_all('192.0.2.1', 8388), rendered)
        for name, data in rendered.items():
            self.assertEqual(data, (self.run.directory / 'l3-requests' / name).read_bytes())
            self.assertEqual(data, (self.run.directory / 'l2-package/artifacts' / name).read_bytes())
        media.verify_media(record)

    def test_the_configured_sing_box_hash_is_required(self):
        for pinned in (None, '1' * 64):
            with self.subTest(pinned=pinned):
                with self.assertRaisesRegex(ValueError, 'sing-box'):
                    self.build(sing_box_sha256=pinned)
                self.assertEqual([], self.fixture.commands[2:])
                self.setUp()

    def test_a_package_of_the_other_profile_is_refused(self):
        with self.assertRaises(ValueError):
            self.build(profile='l2', sing_box_sha256=None)

    def test_start_accepts_the_l3_resources_and_refuses_a_foreign_profile(self):
        from tools.vm.matrix import lifecycle
        class Reached(Exception):
            pass
        def reached(*args, **kwargs):
            raise Reached()
        self.build()
        with patch.object(lifecycle, '_host'), self.assertRaises(Reached):
            lifecycle.start(self.run, executor=reached)

    def test_start_refuses_a_record_whose_profile_disagrees_with_the_resources(self):
        from tools.vm.matrix import lifecycle
        self.build()
        path = self.run.directory / 'launch-plan.json'
        plan = json.loads(path.read_bytes())
        del plan['l2_media']['package']['profile']
        path.write_text(json.dumps(plan, sort_keys=True))
        with patch.object(lifecycle, '_host'), self.assertRaises(lifecycle.LifecycleError):
            lifecycle.start(self.run, executor=lambda *a, **k: self.fail('no image tool before validation'))

    def test_the_owner_content_is_not_changed_and_the_requests_are_run_resources(self):
        before = self.tree()
        self.build()
        self.assertEqual(before, self.tree())
        paths = [r['path'] for r in self.run._read()['resources']]
        for name in media.request_resources('l3'):
            self.assertIn(name, paths)
        self.assertEqual(media.request_resources('l3'), media.resources('l3')[:6])
        self.assertEqual((), media.request_resources('l2'))

    def test_a_request_file_in_the_content_directory_is_refused(self):
        (self.root / 'artifacts/request-dns-lock.json').write_bytes(
            l3_requests.render_all()['request-dns-lock.json'])
        with self.assertRaisesRegex(ValueError, 'l3-requests-in-content'):
            self.build()
        self.assertEqual([], self.fixture.commands[2:])

    def test_a_request_of_the_run_that_differs_from_the_generator_is_refused(self):
        (self.run.directory / 'l3-requests/request-dns-lock.json').write_bytes(b'{}\n')
        with self.assertRaisesRegex(ValueError, 'request'):
            self.build()

    def test_attaching_without_the_requests_is_refused(self):
        (self.run.directory / 'l3-requests/request-lan.json').unlink()
        with self.assertRaisesRegex(ValueError, 'l3-requests-missing'):
            self.build()
        self.assertEqual([], self.fixture.commands)


class L3ImportTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_jobs.JobsTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.vm, self.agent = self.fixture.vm, self.fixture.agent
        del self.vm._smoke_job
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        package_l3(self.root, self.vm.vm_uuid, self.vm.run._identity[1])
        (self.root / 'job.env').unlink()
        (self.root / 'manifest.sha256').unlink()
        with patch.object(l2, 'source_identity', return_value=SOURCE):
            package = l2.validate_package(self.root, checkout=CHECKOUT, immutable=True, profile='l3',
                                          sing_box_sha256=SING_BOX_SHA)
        names = media.content('l3')
        listing = media.manifest(package['hashes'], names)
        (self.root / 'content.sha256').write_bytes(listing)
        self.vm._l2_media = dict(package=package, sha256='c' * 64, size=2048,
                                 content_sha256=hashlib.sha256(listing).hexdigest())
        from tools.vm.matrix.resources import _atomic_manifest
        record = self.vm.run._read()
        for index, name in enumerate(media.resources('l3')):
            record['resources'].append(dict(id='import-test-' + str(index), kind='file', path=name))
            path = self.vm.run.directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        _atomic_manifest(self.vm.run.directory, record)
        for name in names:
            (self.vm.run.directory / 'l2-package' / name).write_bytes((self.root / name).read_bytes())
        register_evidence(self.vm.run, 'l3')
        self.obj = delivery.L2Import(self.vm, guest_run_id=GUEST, import_id='d' * 32, user_a='l2a',
                                     user_b='l2b', enabled=True, l3=L3_BLOCK)
        self.fixture.files['ready.json'] = json.dumps(dict(
            self.obj.identity, schema='rosetun.l2-import.v1', state='ready')).encode()

    def test_job_env_carries_the_four_l3_fields_in_the_order_of_load_job(self):
        env = (self.vm.run.directory / 'l2-package/job.env').read_text().splitlines()
        self.assertEqual(list(L3.env), [line.split('=')[0] for line in env])
        self.assertEqual(['HOST_ADDRESS=192.0.2.1', 'NODE_PORT=8388', 'PROBE_ADDRESS=203.0.113.2',
                          'DNS_PROBE_ADDRESS=203.0.113.53'], env[9:])
        self.assertEqual('l3', self.obj.identity['profile'])
        self.assertEqual(set(media.content('l3')), set(self.obj.request['hashes']))

    def test_a_lab_marker_in_job_env_comes_last_and_the_helper_in_the_image_agrees(self):
        def request_with(value):
            request = copy.deepcopy(self.obj.request)
            request['env']['LAB_MARKER_ADDRESS'] = value
            raw = ''.join(k + '=' + v + chr(10) for k, v in request['env'].items()).encode('ascii')
            hashes = dict(request['hashes'], **{'job.env': hashlib.sha256(raw).hexdigest()})
            request['identity']['manifest_sha256'] = hashlib.sha256(media.manifest(hashes, L3.payload)).hexdigest()
            return request, raw
        def encode(value):
            return base64.b64encode(json.dumps(value).encode()).decode()
        request, raw = request_with('203.0.113.2:9100')
        self.assertEqual(14, len(raw.splitlines()))
        self.assertEqual(b'LAB_MARKER_ADDRESS=203.0.113.2:9100', raw.splitlines()[-1])
        l2.validate_env(raw, 'l3')
        identity, hashes, sizes, env, final = helper.request(encode(request))
        self.assertEqual(raw, env)
        for value in ('203.0.113.2:9101', '10.0.0.1:9100', '203.0.113.2', 'x', '203.0.113.2:9100 '):
            with self.subTest(value=value), self.assertRaises(ValueError):
                helper.request(encode(request_with(value)[0]))
        self.assertNotIn('LAB_MARKER_ADDRESS', self.obj.request['env'])

    def test_the_importer_writes_the_lab_marker_last_only_when_it_is_given(self):
        package = self.vm.run.directory / 'l2-package'
        plain = (package / 'job.env').read_bytes()
        del self.vm._l2_import
        for name in ('job.env', 'manifest.sha256'):
            (package / name).write_bytes(b'')
        delivery.L2Import(self.vm, guest_run_id=GUEST, import_id='c' * 32, user_a='l2a', user_b='l2b',
                          enabled=True, l3=dict(L3_BLOCK, lab_marker_address='203.0.113.2:9100'))
        marked = (package / 'job.env').read_bytes()
        self.assertEqual(plain + b'LAB_MARKER_ADDRESS=203.0.113.2:9100\n', marked)
        del self.vm._l2_import
        for name in ('job.env', 'manifest.sha256'):
            (package / name).write_bytes(b'')
        with self.assertRaises(ValueError):
            delivery.L2Import(self.vm, guest_run_id=GUEST, import_id='b' * 32, user_a='l2a', user_b='l2b',
                              enabled=True, l3=dict(L3_BLOCK, lab_marker_address='10.0.0.1:9100'))

    def test_the_l3_block_and_the_media_profile_must_agree(self):
        del self.vm._l2_import
        with self.assertRaisesRegex(ValueError, 'profile'):
            delivery.L2Import(self.vm, guest_run_id=GUEST, import_id='e' * 32, user_a='l2a',
                              user_b='l2b', enabled=True)
        self.vm._l2_media['package'] = {k: v for k, v in self.vm._l2_media['package'].items() if k != 'profile'}
        with self.assertRaisesRegex(ValueError, 'profile'):
            delivery.L2Import(self.vm, guest_run_id=GUEST, import_id='e' * 32, user_a='l2a',
                              user_b='l2b', enabled=True, l3=L3_BLOCK)

    def test_a_job_env_value_outside_documentation_never_reaches_the_guest(self):
        del self.vm._l2_import
        for key, value in (('host_address', '10.0.0.1'), ('probe_address', '8.8.8.8'),
                           ('dns_probe_address', '1.1.1.1'), ('node_port', 70000)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                delivery.L2Import(self.vm, guest_run_id=GUEST, import_id='f' * 32, user_a='l2a',
                                  user_b='l2b', enabled=True, l3=dict(L3_BLOCK, **{key: value}))

    def test_import_job_and_the_expected_7a_result(self):
        self.assertEqual('ready', self.obj.stage()['state'])
        encoded = base64.b64encode(json.dumps(self.obj.request).encode()).decode()
        identity, hashes, sizes, env, final = helper.request(encoded)
        self.assertEqual(self.obj.identity, identity)
        self.assertEqual((self.vm.run.directory / 'l2-package/job.env').read_bytes(), env)
        self.assertEqual((self.vm.run.directory / 'l2-package/manifest.sha256').read_bytes(), final)
        with patch.object(l2, 'source_identity', return_value=SOURCE):
            job = self.obj.linux_l2_job(checkout=CHECKOUT, enabled=True)
        self.assertEqual('l3', job.profile.name)
        self.assertEqual('linux-l3', job.identity['job_id'])
        self.assertEqual('linux-l3', job.plan['suite'])
        self.assertEqual(39, len(job.plan['catalog']))
        job.submit()
        plan, report, status = synthetic_inputs('linux-l3')
        report['run_id'] = GUEST
        report['guest'] = dict(boot_id=BOOT, boot_id_at_end=BOOT)
        status.update(run_id=GUEST, boot_id=BOOT)
        passed = ('preflight.identity', 'preflight.accounts', 'preflight.no-foreign-service', 'preflight.tools')
        for row in report['scenarios']:
            row['result'] = 'PASS' if row['id'] in passed else 'FAIL' if row['id'] == 'preflight.baseline' else 'ERROR'
        summarize(report)
        self.fixture.files.update({'report.json': json.dumps(report).encode(),
                                   'status.json': json.dumps(status).encode()})
        result = job.collect()
        counts = result['assessment']['execution']['counts']
        self.assertEqual((4, 1, 34, 0), (counts['PASS'], counts['FAIL'], counts['ERROR'], counts['SKIP']))
        self.assertFalse(result['accepted'])
        self.assertFalse(result['assessment']['acceptance']['accepted'])
        self.assertEqual('FAIL', result['assessment']['execution']['status'])
        # The report is complete; the one validation problem is the guest's own ERROR summary.
        self.assertEqual(['guest reports an infrastructure error or aborted run'],
                         result['assessment']['validation']['problems'])
        self.assertEqual(json.dumps(report).encode(),
                         (self.vm.run.directory / 'linux-l3/1/report.json').read_bytes())
        # The L2 reservation the fixture made at start stays untouched.
        self.assertEqual(0, (self.vm.run.directory / 'linux-l2/1/report.json').stat().st_size)
        paths = [a['path'] for n, a in self.agent.client.commands if n == 'guest-exec']
        self.assertEqual([delivery.HELPER, l2.LAUNCHER], paths)

    def test_the_helper_journal_is_kept_when_there_is_one_and_never_changes_the_assessment(self):
        self.obj.stage()
        with patch.object(l2, 'source_identity', return_value=SOURCE):
            job = self.obj.linux_l2_job(checkout=CHECKOUT, enabled=True)
        job.submit()
        plan, report, status = synthetic_inputs('linux-l3')
        report['run_id'] = GUEST
        report['guest'] = dict(boot_id=BOOT, boot_id_at_end=BOOT)
        status.update(run_id=GUEST, boot_id=BOOT)
        self.fixture.files.update({'report.json': json.dumps(report).encode(),
                                   'status.json': json.dumps(status).encode()})
        saved = self.vm.run.directory / 'linux-l3/1/helper-journal.txt'
        # A guest answers in blocks; the fixture's own peer sends a file whole.
        offset, opened = [0], self.agent.client.responses['guest-file-open']

        def opening():
            offset[0] = 0
            return opened()

        def reading():
            data = self.fixture.current
            count = min(self.agent.client.commands[-1][1]['count'], l2.BLOCK)
            block = data[offset[0]:offset[0] + count]
            offset[0] += len(block)
            return read(block, eof=offset[0] == len(data))

        self.agent.client.responses.update({'guest-file-open': opening, 'guest-file-read': reading})

        def collect():
            job.polls = job.calls = self.agent.calls = 0
            return job.collect()

        without = collect()
        self.assertEqual(b'', saved.read_bytes())
        # A file the guest wrote is saved as it is, in more than one block.
        text = b'42.000000 host rosetun-helper[1]: connected\n' * 2000
        self.fixture.files['helper-journal.txt'] = text
        with_journal = collect()
        self.assertEqual(text, saved.read_bytes())
        self.assertEqual(without['assessment'], with_journal['assessment'])
        self.assertEqual(without['verification'], with_journal['verification'])
        self.assertEqual(without['accepted'], with_journal['accepted'])
        # One more byte than the limit: the first bytes stay and nothing else changes.
        self.fixture.files['helper-journal.txt'] = b'x' * (l2.JOURNAL_LIMIT + 1)
        oversized = collect()
        self.assertEqual(b'x' * (l2.JOURNAL_LIMIT + 1), saved.read_bytes())
        self.assertEqual(without['assessment'], oversized['assessment'])
        rows = [json.loads(line) for line in (self.vm.run.directory / 'job-evidence.jsonl').read_text().splitlines()]
        journal = [row for row in rows if row['operation'] == 'l2-file' and row.get('file') == 'journal']
        self.assertTrue(journal[0]['absent'])
        self.assertEqual((True, len(text)), (journal[1]['complete'], journal[1]['size']))
        self.assertFalse(journal[2]['complete'])
        self.assertTrue(journal[3]['over_limit'])
        self.assertEqual(4, len(journal))

    def test_only_the_l3_stage_reserves_a_place_for_the_journal(self):
        self.assertEqual(l2.EVIDENCE_FILES, l2.evidence_files('l2'))
        self.assertEqual(l2.EVIDENCE_FILES + tuple(f'{i}/helper-journal.txt' for i in range(1, l2.POLLS + 1)),
                         l2.evidence_files('l3'))
        self.assertEqual(256 * 1024, l2.JOURNAL_LIMIT)

    def test_the_importer_installs_l3_content_and_names_the_profile_in_the_receipt(self):
        class Adapter:
            def find(inner): return Path('/unused'), 2048
            def verify(inner, *args): pass
            def mount(inner, device, target): shutil.copytree(self.root, target, dirs_exist_ok=True)
            def unmount(inner, target): pass
        def publish(source, target):
            source.rename(target)
        import os
        with tempfile.TemporaryDirectory() as temp, patch.object(helper, 'ROOT', Path(temp)), \
                patch.object(helper, 'sync_dir'), patch.object(helper, 'trusted'), patch.object(os, 'fsync'), \
                patch.object(helper, 'publish', side_effect=publish), \
                patch.object(os, 'chown', create=True), patch.object(os, 'fchown', create=True), \
                patch.object(os, 'fchmod', create=True), \
                patch.object(os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True), \
                patch.object(os, 'O_NONBLOCK', getattr(os, 'O_NONBLOCK', 0), create=True):
            i, hashes, sizes, env, final = helper.request(
                base64.b64encode(json.dumps(self.obj.request).encode()).decode())
            helper.import_media(i, hashes, sizes, env, final, Adapter())
            installed = Path(temp) / GUEST
            found = {p.relative_to(installed).as_posix() for p in installed.rglob('*') if p.is_file()}
            self.assertEqual(set(L3.files), found)
            self.assertEqual(env, (installed / 'job.env').read_bytes())
            receipt = json.loads((Path(temp) / ('.import-' + 'd' * 32) / 'ready.json').read_bytes())
            self.assertEqual('l3', receipt['profile'])
            self.assertEqual(dict(self.obj.identity, schema='rosetun.l2-import.v1', state='ready'), receipt)

    def test_the_importer_refuses_an_l2_tree_for_an_l3_request_and_the_reverse(self):
        import os
        class Adapter:
            def find(inner): return Path('/unused'), 2048
            def verify(inner, *args): pass
            def mount(inner, device, target):
                shutil.copytree(self.root, target, dirs_exist_ok=True)
                (target / 'guest/run-l2.sh').write_bytes(b'extra')
            def unmount(inner, target): pass
        with tempfile.TemporaryDirectory() as temp, patch.object(helper, 'ROOT', Path(temp)), \
                patch.object(helper, 'sync_dir'), patch.object(helper, 'trusted'), patch.object(os, 'fsync'), \
                patch.object(os, 'chown', create=True), patch.object(os, 'fchown', create=True), \
                patch.object(os, 'fchmod', create=True), \
                patch.object(os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True), \
                patch.object(os, 'O_NONBLOCK', getattr(os, 'O_NONBLOCK', 0), create=True):
            i, hashes, sizes, env, final = helper.request(
                base64.b64encode(json.dumps(self.obj.request).encode()).decode())
            with self.assertRaises(ValueError):
                helper.import_media(i, hashes, sizes, env, final, Adapter())
        with self.assertRaises(ValueError):
            helper.composition(self.root, helper.PROFILES['l2']['content'])

    def test_the_helper_checks_its_own_copy_of_the_rules(self):
        request = copy.deepcopy(self.obj.request)
        def encode(value):
            return base64.b64encode(json.dumps(value).encode()).decode()
        helper.request(encode(request))
        bad = copy.deepcopy(request)
        bad['env']['HOST_ADDRESS'] = '10.0.0.1'
        with self.assertRaises(ValueError):
            helper.request(encode(bad))
        bad = copy.deepcopy(request)
        bad['env']['NODE_PORT'] = '0'
        with self.assertRaises(ValueError):
            helper.request(encode(bad))
        bad = copy.deepcopy(request)
        del bad['env']['DNS_PROBE_ADDRESS']
        with self.assertRaises(ValueError):
            helper.request(encode(bad))
        bad = copy.deepcopy(request)
        bad['identity']['profile'] = 'l2'
        with self.assertRaises(ValueError):
            helper.request(encode(bad))
        bad = copy.deepcopy(request)
        bad['hashes'].pop('artifacts/sing-box')
        bad['sizes'].pop('artifacts/sing-box')
        with self.assertRaises(ValueError):
            helper.request(encode(bad))
        bad = copy.deepcopy(request)
        bad['sizes']['artifacts/rosetun-engine.rules'] = 512 * 1024
        with self.assertRaises(ValueError):
            helper.request(encode(bad))


if __name__ == '__main__':
    unittest.main()
