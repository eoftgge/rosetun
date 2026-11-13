"""Offline sequential controller tests, with owned ledgers and fake live APIs."""

import copy
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import orchestrator as o, execution, cli, lifecycle
from tools.vm.matrix.tests.test_linux_l2 import package, CHECKOUT, SOURCE
from tools.vm.matrix.tests.test_qga import BOOT
from tools.vm.matrix.tests import test_qemu


class Clock:
    now = 0
    def __call__(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = dict(state_directory=self.temp.name, stand_id='synthetic', image={}, qemu={},
                           content_directory=self.temp.name, source_checkout=self.temp.name,
                           xorriso='fake', accounts=dict(user_a='l2a', user_b='l2b'),
                           timeouts=dict(scenario=30, unit=180, job=900),
                           deadlines=dict(preparation=600, boot=300, **{'import':900}, execution=1080))
        self.clock = Clock()
        self.events = []
        self.failure = None
        self.unknown = None
        self.collects = self.imports = self.submits = 0
        self.accepted = True
        self.vm = SimpleNamespace(completed=False, last_boot_id=BOOT, vm_uuid=BOOT,
                                  qga=SimpleNamespace(valid=True))
        self.vm.resume = lambda: self.call('resume')
        self.vm.wait_initial_guest = self.boot
        self.vm.recover_guest = self.recover
        self.vm.close = self.close
        self.job = SimpleNamespace(submission='not-submitted', assessment=None)
        self.job.submit = self.submit
        self.job.collect = self.collect
        self.job.snapshot = lambda: dict(accepted=self.job.assessment is not None and self.accepted)
        self.attempt = SimpleNamespace(state='built', receipt_verified=False, deadline=900)
        self.attempt.stage = self.stage
        self.attempt.check_receipt = self.receipt
        self.attempt.linux_l2_job = self.create_job
        self.adapters = SimpleNamespace(image=lambda **k: None, config=lambda **k: None,
            prepare=lambda *a, **k: self.call('prepare'), attach=lambda *a, **k: self.call('media'),
            start=self.start, importer=self.importer, execute=lambda *a, **k: None)
        self.patches = [patch.object(o, 'preflight', side_effect=lambda c: self.call('preflight')),
                        patch.object(o, 'completion_verified', side_effect=lambda *a: self.vm.completed)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def call(self, name):
        self.events.append((name, self.clock()))
        if self.failure == name:
            raise ValueError('synthetic private stderr must never be published')

    def start(self, run):
        self.call('start')
        self.run = run
        run._lease._active.add(self.vm_token)
        def release_fake():
            run._lease._active.discard(self.vm_token)
            run._lease.release()
        self.addCleanup(release_fake)
        return self.vm

    @property
    def vm_token(self):
        return 'fake-owned-vm'

    def boot(self, **kwargs):
        self.clock.sleep(240)
        self.call('boot')

    def importer(self, *args, **kwargs):
        self.call('import-create')
        self.attempt.deadline = self.clock() + 900
        return self.attempt

    def stage(self):
        self.imports += 1
        self.call('import')
        if self.unknown == 'import':
            self.vm.qga.valid = False
            raise ValueError('unknown')
        self.attempt.state = 'ready'

    def recover(self):
        self.call('recovery')
        self.vm.qga.valid = True

    def receipt(self):
        self.call('receipt')
        self.attempt.state = 'ready'
        self.attempt.receipt_verified = True

    def create_job(self, **kwargs):
        self.call('job-create')
        return self.job

    def submit(self):
        self.submits += 1
        self.job.submission = 'unknown'
        self.call('submit')
        if self.unknown == 'submit':
            self.vm.qga.valid = False
            raise ValueError('unknown')
        self.job.submission = 'launcher-spawned'

    def collect(self):
        self.collects += 1
        self.call('collect')
        self.job.assessment = dict(acceptance=dict(accepted=self.accepted, release=False))

    def close(self, **kwargs):
        self.call('close')
        self.vm.completed = True
        self.run._lease._active.discard(self.vm_token)

    def execute(self):
        return o.run_linux_l2(self.config, adapters=self.adapters, clock=self.clock,
                             sleep=self.clock.sleep, progress=lambda stage: None)

    def test_complete_order_late_agent_and_no_early_collection(self):
        result = self.execute()
        self.assertEqual(0, result['exit_code'])
        self.assertEqual(['preflight','prepare','media','start','resume','boot','import-create',
                          'import','recovery','receipt','job-create','submit','collect','close'],
                         [e[0] for e in self.events])
        times = dict(self.events)
        self.assertEqual(1025, times['collect'] - times['submit'])
        self.assertEqual((1,1,1), (self.imports,self.submits,self.collects))
        summary = Path(result['artifact_directory']) / 'execution-summary.json'
        self.assertEqual(result, json.loads(summary.read_bytes()))
        self.assertNotIn(self.run._identity[2], summary.read_text())
        self.assertFalse(result['release_gate'])

    def test_failures_at_each_api_preserve_error_and_close(self):
        for failure in ('preflight','prepare','media','start','resume','boot','import-create',
                        'import','recovery','receipt','job-create','submit','collect','close'):
            with self.subTest(failure=failure):
                case = FlowTests('test_complete_order_late_agent_and_no_early_collection')
                case.setUp()
                try:
                    case.failure = failure
                    result = case.execute()
                    self.assertEqual(2, result['exit_code'])
                    self.assertTrue(result['errors'])
                    self.assertNotIn('private stderr', json.dumps(result))
                    if failure in ('prepare','media'):
                        self.assertTrue(result['manual_recovery_required'])
                        self.assertFalse(result['completion'])
                finally:
                    case.doCleanups()

    def test_unknown_import_and_submit_are_resolved_only_by_saved_evidence(self):
        self.unknown = 'import'
        result = self.execute()
        self.assertEqual(0, result['exit_code'])
        self.assertEqual(1, self.imports)
        self.assertEqual(1, self.submits)

    def test_unknown_submit_is_never_repeated(self):
        self.unknown = 'submit'
        self.assertEqual(0, self.execute()['exit_code'])
        self.assertEqual(1, self.submits)
        self.assertEqual(1, self.collects)

    def test_rejected_assessment_and_teardown_failure_are_not_success(self):
        self.accepted = False
        self.assertEqual(1, self.execute()['exit_code'])

    def test_accepted_assessment_and_failed_teardown_is_infrastructure_error(self):
        self.failure = 'close'
        result = self.execute()
        self.assertEqual(2, result['exit_code'])
        self.assertTrue(result['assessment']['acceptance']['accepted'])
        self.assertTrue(result['manual_recovery_required'])

    def test_keyboard_interrupt_preserves_original_and_close_error(self):
        self.job.submit = lambda: (_ for _ in ()).throw(KeyboardInterrupt())
        self.failure = 'close'
        result = self.execute()
        self.assertEqual(130, result['exit_code'])
        self.assertEqual(['KeyboardInterrupt','ValueError'], [e['kind'] for e in result['errors']])

    def test_missing_telemetry_never_passes(self):
        self.failure = 'collect'
        result = self.execute()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual(2, self.collects)
        self.assertIsNone(result['assessment'])

    def test_summary_write_failure_is_not_success(self):
        original = o.save
        def save(run, name, value, **kwargs):
            if not kwargs.get('initial'):
                raise OSError('synthetic write failure')
            return original(run, name, value, **kwargs)
        with patch.object(o, 'save', side_effect=save):
            result = self.execute()
        self.assertEqual(2, result['exit_code'])
        self.assertTrue(result['completion'])
        self.assertEqual('summary', result['errors'][-1]['stage'])

    def test_blocking_foreign_ledger_is_never_changed_or_removed(self):
        with o.StandLease(self.config['state_directory'], self.config['stand_id']) as lease:
            other = o.create_run(lease)
            path = other.directory / 'manifest.json'
            before = path.read_bytes()
        result = self.execute()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual(before, path.read_bytes())
        self.assertNotIn('artifact_directory', result)

    def test_identity_write_failure_precedes_preparation_and_has_no_completion(self):
        with patch.object(o, 'save', side_effect=OSError('synthetic write failure')):
            result = self.execute()
        self.assertEqual(2, result['exit_code'])
        self.assertNotIn('prepare', [e[0] for e in self.events])
        self.assertFalse(result['completion'])
        self.assertTrue(result['manual_recovery_required'])

    def test_maximum_duration_wait_is_finite_without_spending_collection_attempts(self):
        self.config['timeouts']['job'] = 7200
        self.config['deadlines']['execution'] = 7380
        result = self.execute()
        self.assertEqual(0, result['exit_code'])
        times = dict(self.events)
        self.assertEqual(7325, times['collect'] - times['submit'])
        self.assertEqual(1, self.collects)

    def test_failed_collection_recovers_and_reads_without_resubmitting(self):
        def collect():
            if self.collects == 0:
                self.collects += 1
                self.vm.qga.valid = False
                raise ValueError('lost response')
            return self.collect()
        self.job.collect = collect
        self.assertEqual(0, self.execute()['exit_code'])
        self.assertEqual((1,1,2), (self.imports, self.submits, self.collects))

    def test_preparation_executor_honors_shared_deadline(self):
        def execute(*args, **kwargs):
            self.clock.sleep(601)
        self.adapters.execute = execute
        self.adapters.prepare = lambda *a, executor, **k: executor(['fake'], timeout=30, output_limit=10)
        result = self.execute()
        self.assertEqual(2, result['exit_code'])
        self.assertNotIn('start', [e[0] for e in self.events])

    def test_owner_token_in_guest_assessment_is_never_published(self):
        def collect():
            self.collect()
            self.job.assessment['unsafe'] = self.run._identity[2]
        self.job.collect = collect
        result = self.execute()
        self.assertEqual(2, result['exit_code'])
        self.assertNotIn(self.run._identity[2], json.dumps(result))


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_qemu.PreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        package(root, BOOT)
        (root/'job.env').unlink()
        (root/'manifest.sha256').unlink()
        from dataclasses import asdict
        self.config = dict(schema=execution.SCHEMA, mode='exploratory', platform='linux-x86_64-kvm',
            state_directory=str(root/'absent-state'), stand_id='synthetic', image=self.fixture.image.record(),
            qemu=asdict(self.fixture.config), xorriso=self.fixture.config.executable,
            content_directory=str(root), source_checkout=str(CHECKOUT), accounts=dict(user_a='l2a',user_b='l2b'),
            timeouts=dict(scenario=30, unit=180, job=900),
            deadlines=dict(preparation=600, boot=300, **{'import':900}, execution=1080))
        self.config['qemu'].update(machine='pc-i440fx-10.0', qga=True)

    def test_dry_run_checks_local_bytes_without_subprocess_or_creating_state(self):
        with patch('subprocess.Popen', side_effect=AssertionError('external process forbidden')):
            result = execution.preflight(self.config, dry_run=True)
        self.assertFalse(Path(self.config['state_directory']).exists())
        self.assertFalse(result['backend_qualified'])
        self.assertIn('deferred', result['source_check'])

    def test_unknown_fields_and_unsupported_platform_and_release_rejected(self):
        for key, value in (('extra',True),('platform','windows'),('mode','release'),('boot_id',BOOT)):
            config = copy.deepcopy(self.config)
            config[key] = value
            with self.assertRaises(ValueError):
                execution.validate(config)
        config = copy.deepcopy(self.config)
        config['qemu']['argv'] = []
        with self.assertRaises(ValueError):
            execution.validate(config)

    def test_cli_dry_run_is_read_only_without_qmp_or_orchestrator(self):
        import builtins
        original = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name in ('qemu.qmp', 'orchestrator'):
                raise AssertionError('live import forbidden')
            return original(name, *args, **kwargs)
        with patch.object(execution, 'load_execution', return_value=self.config), \
             patch('builtins.__import__', side_effect=guarded), \
             patch('subprocess.Popen', side_effect=AssertionError('external program forbidden')), \
             patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(0, cli.main(['run','linux-l2','--config','synthetic','--dry-run']))
        self.assertTrue(json.loads(output.getvalue())['dry_run'])
        self.assertFalse(Path(self.config['state_directory']).exists())

    def test_read_only_inventory_does_not_spawn_or_create_state(self):
        with patch('subprocess.Popen', side_effect=AssertionError('external process forbidden')), \
             patch('sys.stdout', new_callable=io.StringIO):
            for command in ('runs','recover'):
                self.assertEqual(0, cli.main([command,'--state-directory',self.config['state_directory']]))
            self.assertEqual(0, cli.main(['doctor']))
        self.assertFalse(Path(self.config['state_directory']).exists())


class InitialAgentTests(unittest.TestCase):
    def test_late_first_agent_does_not_consume_recovery_slots(self):
        vm = object.__new__(lifecycle.Vm)
        vm.last_boot_id = None
        vm.timeout = 5
        vm.evidence_failed = False
        vm.process = SimpleNamespace(poll=lambda: None)
        vm.qga_recoveries = 0
        vm._sync_seed = 1
        clock = Clock()
        calls = []
        def new():
            vm.qga = SimpleNamespace(closed=False)
            vm.qga.close = lambda: setattr(vm.qga, 'closed', True)
        new()
        vm._new_qga = new
        def observe():
            calls.append(clock())
            if clock() < 240:
                raise lifecycle.LifecycleError('qga-connect-failed', vm)
            vm.last_boot_id = BOOT
            return dict(boot_id=BOOT)
        vm.observe_guest = observe
        self.assertEqual(BOOT, vm.wait_initial_guest(timeout=300, clock=clock,
                                                   sleep=clock.sleep)['boot_id'])
        self.assertEqual(0, vm.qga_recoveries)
        self.assertEqual(17, len(calls))
        self.assertEqual(5, vm.timeout)


class ReservationTests(unittest.TestCase):
    def test_prepare_accepts_only_complete_execution_reservations(self):
        fixture = test_qemu.PreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for identifier, name in o.EXECUTION_FILES.items():
            fixture.run.register(dict(id=identifier, kind='file', path=name))
            o.save(fixture.run, name, dict(schema='synthetic'), initial=True)
        fixture.prepare()
        self.assertEqual(3, len(fixture.calls))
        self.assertEqual(5, len(fixture.run._read()['resources']))

    def test_summary_finalization_does_not_invalidate_real_completion(self):
        from tools.vm.matrix.tests import test_lifecycle
        fixture = test_lifecycle.LifecycleTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        run = fixture.run
        for identifier, name in o.EXECUTION_FILES.items():
            run.register(dict(id=identifier, kind='file', path=name))
            o.save(run, name, dict(schema='synthetic', state='pending'), initial=True)
        vm = fixture.start()
        vm.close()
        journal = (run.directory / 'lifecycle.jsonl').read_bytes()
        self.assertTrue(o.completion_verified(run.directory, run._read()))
        o.save(run, 'execution-summary.json', dict(schema='synthetic', state='finished'))
        self.assertEqual(journal, (run.directory / 'lifecycle.jsonl').read_bytes())
        self.assertTrue(o.completion_verified(run.directory, run._read()))

    def test_media_accepts_execution_reservations_with_existing_fake_packager(self):
        from tools.vm.matrix.tests import test_l2_media
        fixture = test_l2_media.MediaTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for identifier, name in o.EXECUTION_FILES.items():
            fixture.run.register(dict(id=identifier, kind='file', path=name))
            o.save(fixture.run, name, dict(schema='synthetic'), initial=True)
        record = fixture.build()
        self.assertTrue(record['sha256'])
        self.assertEqual(2, len(fixture.commands))


def raised_in(filename, error):
    """An exception raised by code that lives in `filename`, as a frame of that file would raise it."""
    code = compile('def raiser(error):\n    raise error\n', filename, 'exec')
    scope = {}
    exec(code, scope)
    try:
        scope['raiser'](error)
    except BaseException as caught:
        return caught


def raised_by_the_package(error):
    raise error


class FailureReasonTests(unittest.TestCase):
    """The summary names why a stage failed, as long as the code of this package wrote the reason."""

    def row(self, error):
        try:
            raised_by_the_package(error)
        except BaseException as caught:
            return o.failure('stage', caught)

    def test_a_code_the_package_raised_in_a_builtin_value_error_is_shown(self):
        self.assertEqual(dict(stage='stage', kind='ValueError', reason='l3-requests-require-new-prepared-run'),
                         self.row(ValueError('l3-requests-require-new-prepared-run')))

    def test_a_code_the_package_raised_in_a_builtin_os_error_is_shown(self):
        self.assertEqual(dict(stage='stage', kind='OSError', reason='disk-full'), self.row(OSError('disk-full')))

    def test_a_value_error_of_the_standard_library_stays_operation_failed_even_with_a_fitting_message(self):
        stdlib = Path(tempfile.gettempdir()).resolve().parent / 'python' / 'Lib' / 'stdlib_module.py'
        for kind in (ValueError, OSError):
            with self.subTest(kind=kind.__name__):
                error = raised_in(str(stdlib), kind('looks-fine'))
                self.assertEqual(dict(stage='stage', kind=kind.__name__, reason='operation-failed'),
                                 o.failure('stage', error))

    def test_a_message_with_an_address_or_a_path_stays_operation_failed(self):
        for message in ('192.0.2.1:8388', 'connect to 192.0.2.1', r'C:\state\run', '/var/lib/run', 'a b',
                        '', 'x' * 97):
            with self.subTest(message=message):
                self.assertEqual('operation-failed', self.row(ValueError(message))['reason'])
        self.assertEqual('x' * 96, self.row(ValueError('x' * 96))['reason'])

    def test_an_exception_that_was_never_raised_has_no_frame_and_is_not_shown(self):
        self.assertEqual('operation-failed', o.failure('stage', ValueError('looks-fine'))['reason'])

    def test_another_builtin_class_stays_operation_failed(self):
        for error in (KeyError('looks-fine'), RuntimeError('looks-fine'), TypeError('looks-fine')):
            with self.subTest(kind=type(error).__name__):
                self.assertEqual('operation-failed', self.row(error)['reason'])

    def test_a_helper_reason_still_needs_a_class_of_the_package(self):
        error = ValueError('looks-fine')
        error.helper_reason = 'missing-sing-box'
        self.assertNotIn('helper_reason', self.row(error))
