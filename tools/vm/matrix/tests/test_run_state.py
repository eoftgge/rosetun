"""The run state on disk: one writer, intent before done, budgets that only grow."""

import json
import socket
import threading
import unittest
from unittest.mock import patch

from tools.vm.matrix import run_state
from tools.vm.matrix.qmp_adapter import ByteRelay, Qmp, RESERVATION_BYTES
from tools.vm.matrix.resources import read_manifest
from tools.vm.matrix.tests import test_orchestrator


def load(directory):
    manifest = read_manifest(directory)
    document = json.loads((directory / 'run-state.json').read_text())
    run_state.validate(document, run_id=manifest['run_id'], stand_id=manifest['stand_id'],
                       token=manifest['owner_token'])
    return manifest, document


class OrchestratorStateTests(unittest.TestCase):
    def setUp(self):
        self.flow = test_orchestrator.FlowTests()
        self.addCleanup(self.flow.doCleanups)
        self.flow.setUp()

    def test_a_complete_run_records_every_step_as_intent_then_done_and_ends_completed(self):
        from pathlib import Path
        result = self.flow.execute()
        self.assertEqual(0, result['exit_code'])
        directory = Path(result['artifact_directory'])
        manifest, document = load(directory)
        self.assertEqual('completed', document['phase'])
        self.assertNotIn(manifest['owner_token'], (directory / 'run-state.json').read_text())
        rows = [(row['step'], row['status']) for row in document['transitions']]
        steps = [stage['stage'] for stage in result['stages'] if stage['stage'] not in ('preflight', 'lease', 'create-run')]
        expected = [pair for name in steps for pair in ((name, 'intent'), (name, 'done'))] + [('summary', 'done')]
        self.assertEqual(expected, rows)
        phases = {row['step']: row['phase'] for row in document['transitions']}
        self.assertEqual(('preparing', 'running', 'running', 'collecting', 'closing'),
                         tuple(phases[name] for name in ('prepare', 'start', 'wait', 'collect', 'close')))
        self.assertEqual(result['identities']['guest_run_id'], document['identities']['guest_run_id'])
        self.assertIn('wait_until', document['deadlines'])
        self.assertEqual({'path': 'run-state.json', 'kind': 'file', 'id': 'run-state'},
                         next(r for r in manifest['resources'] if r['id'] == 'run-state'))

    def test_a_failed_step_is_left_as_error_and_the_run_ends_quarantined_with_its_reason(self):
        from pathlib import Path
        self.flow.failure = 'collect'
        result = self.flow.execute()
        _, document = load(Path(result['artifact_directory']))
        self.assertIn({'step': 'collect', 'status': 'error'},
                      [dict(step=r['step'], status=r['status']) for r in document['transitions']])
        # The fake completes its close, so the ledger is verified: a failed collection still completes the run.
        self.assertEqual('completed', document['phase'])
        self.flow.vm.completed = False

    def test_an_unverified_completion_ends_quarantined(self):
        from pathlib import Path
        with patch.object(test_orchestrator.o, 'completion_verified', return_value=False):
            result = self.flow.execute()
        _, document = load(Path(result['artifact_directory']))
        self.assertEqual('quarantined', document['phase'])
        self.assertEqual('completion-unverified', document['reason'])


class BudgetTests(unittest.TestCase):
    def state(self, phase='completed'):
        import tempfile
        from tools.vm.matrix.resources import StandLease, create_run
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        lease = StandLease(directory.name, 'synthetic').acquire()
        self.addCleanup(lease.release)
        run = create_run(lease)
        run.register(dict(run_state.RESOURCE))
        state = run_state.RunState.create(run, phase=phase)
        return run_state.RunState.load(run) if state else None

    def test_a_budget_only_grows_and_refuses_past_its_limit(self):
        state = self.state()
        state.record('qmp_calls', 5)
        state.record('qmp_calls', 3)
        self.assertEqual(5, state.budget('qmp_calls'))
        state.record('qmp_calls', 128)
        with self.assertRaisesRegex(ValueError, 'exhausted'):
            state.record('qmp_calls', 129)
        with self.assertRaisesRegex(ValueError, 'exhausted'):
            state.record('unknown', 1)
        reread = run_state.RunState.load(state.run)
        self.assertEqual(128, reread.budget('qmp_calls'))

    def test_a_final_phase_takes_no_further_transition(self):
        state = self.state()
        with self.assertRaisesRegex(ValueError, 'final'):
            state.transition('running', 'submit', 'intent')

    def test_a_secret_shaped_or_unknown_field_refuses_the_whole_file(self):
        state = self.state()
        run_id, stand_id, token = state.run._identity
        for change in (dict(extra=1), dict(owner_digest='0' * 64), dict(phase='paused'),
                       dict(budgets=dict(state.document["budgets"], qga_recoveries=7))):
            with self.assertRaises(ValueError):
                run_state.validate(dict(state.document, **change), run_id=run_id, stand_id=stand_id, token=token)
        with self.assertRaises(ValueError):
            state.update('identities', vm_uuid=token + ' ' + token)

    def test_a_leftover_scratch_file_never_blocks_the_next_write(self):
        state = self.state()
        (state.run.directory / 'run-state.0000000000000000.tmp').write_text('left by a dead controller')
        state.record('job_polls', 1)
        self.assertEqual(1, run_state.RunState.load(state.run).budget('job_polls'))


class Client:
    def __init__(self, **kwargs):
        from types import SimpleNamespace
        self.events = SimpleNamespace()
        self.sent = []

    async def execute(self, name, arguments=None):
        self.sent.append(name)
        return {}

    async def disconnect(self):
        pass


class Relay:
    def __init__(self, stream, **kwargs):
        self.kwargs = kwargs

    def close(self):
        pass


class AdapterBudgetTests(unittest.TestCase):
    def test_qmp_continues_the_recorded_count_and_records_before_sending(self):
        recorded = []
        qmp = Qmp(None, client_factory=Client, relay_factory=Relay,
                  spent=dict(calls=127, events=3, bytes=(10, 20)), persist=lambda n, v: recorded.append((n, v)))
        self.addCleanup(qmp.close)
        self.assertEqual((10, 20), qmp.relay.kwargs['used'])
        with self.assertRaisesRegex(ValueError, 'command-limit'):
            qmp.command('query-status', 1)
        self.assertEqual([], qmp.client.sent)
        qmp.calls = 125
        qmp.command('query-status', 1)
        self.assertEqual([('qmp_calls', 126)], recorded)
        # The last call stays reserved for quit, whichever controller makes it.
        qmp.command('quit', 1)
        self.assertEqual(['query-status', 'quit'], qmp.client.sent)
        self.assertEqual([('qmp_calls', 126), ('qmp_calls', 127)], recorded)

    def test_a_failed_record_sends_nothing_and_keeps_the_channel(self):
        def fail(name, value):
            raise OSError('disk full')
        qmp = Qmp(None, client_factory=Client, relay_factory=Relay, spent={}, persist=fail)
        self.addCleanup(qmp.close)
        with self.assertRaisesRegex(ValueError, 'budget-record-failed'):
            qmp.command('query-status', 1)
        self.assertEqual([], qmp.client.sent)
        self.assertTrue(qmp.valid)
        self.assertEqual(0, qmp.calls)

    def test_the_relay_records_a_new_ceiling_before_forwarding_past_the_old_one(self):
        stream, peer = socket.socketpair()
        ceilings = []
        relay = ByteRelay(stream, limit=1024 * 1024, used=(100, 0), reserve=lambda i, v: ceilings.append((i, v)))
        try:
            peer.sendall(b'x' * 10)
            relay.client.settimeout(2)
            self.assertEqual(b'x' * 10, relay.client.recv(10))
            self.assertEqual([(0, 110 + RESERVATION_BYTES)], ceilings)
        finally:
            relay.close()
            peer.close()

    def test_a_failed_ceiling_record_stops_the_relay_before_forwarding(self):
        stream, peer = socket.socketpair()
        def fail(index, value):
            raise ValueError('disk full')
        relay = ByteRelay(stream, reserve=fail)
        try:
            peer.sendall(b'reply')
            relay.thread.join(2)
            self.assertTrue(relay.failed)
            relay.client.settimeout(1)
            self.assertEqual(b'', relay.client.recv(10))
        finally:
            relay.close()
            peer.close()


class BootChainTests(unittest.TestCase):
    state = BudgetTests.state

    FIRST = '12345678-1234-4234-8234-123456789abc'
    SECOND = '22345678-1234-4234-8234-123456789abc'
    THIRD = '32345678-1234-4234-8234-123456789abc'

    def checked(self, state, **change):
        run_id, stand_id, token = state.run._identity
        return run_state.validate(dict(state.document, **change), run_id=run_id, stand_id=stand_id, token=token)

    def test_the_first_boot_starts_the_chain_and_identity_follows_it(self):
        state = self.state(phase='running')
        self.assertEqual([], state.boot_chain)
        state.update('identities', boot_id=self.FIRST)
        state.update('identities', boot_id=self.FIRST)
        self.assertEqual([self.FIRST], state.boot_chain)
        state.extend_boot_chain(self.SECOND)
        reread = run_state.RunState.load(state.run)
        self.assertEqual(([self.FIRST, self.SECOND], self.SECOND),
                         (reread.boot_chain, reread.document['identities']['boot_id']))

    def test_a_boot_joins_the_chain_only_through_extend_and_never_twice(self):
        state = self.state(phase='running')
        state.update('identities', boot_id=self.FIRST)
        with self.assertRaisesRegex(ValueError, 'boot-chain'):
            state.update('identities', boot_id=self.SECOND)
        state.extend_boot_chain(self.SECOND)
        with self.assertRaisesRegex(ValueError, 'boot-chain'):
            state.extend_boot_chain(self.SECOND)
        with self.assertRaisesRegex(ValueError, 'boot-chain'):
            state.extend_boot_chain(self.FIRST)
        state.extend_boot_chain(self.THIRD)
        with self.assertRaisesRegex(ValueError, 'boot-chain'):
            state.extend_boot_chain('42345678-1234-4234-8234-123456789abc')
        self.assertEqual([self.FIRST, self.SECOND, self.THIRD], state.boot_chain)

    def test_a_chain_that_does_not_end_in_the_identity_or_repeats_a_boot_refuses_the_file(self):
        state = self.state(phase='running')
        state.update('identities', boot_id=self.FIRST)
        state.extend_boot_chain(self.SECOND)
        for change in (dict(boot_chain=[self.FIRST]), dict(boot_chain=[self.SECOND, self.FIRST]),
                       dict(boot_chain=[self.FIRST, self.SECOND, self.SECOND]), dict(boot_chain=[]),
                       dict(boot_chain=self.FIRST), dict(boot_chain=[self.FIRST, 7])):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'boot-chain|identities'):
                self.checked(state, **change)

    def test_a_file_written_before_the_chain_existed_is_read_with_its_one_boot(self):
        state = self.state(phase='running')
        state.update('identities', boot_id=self.FIRST)
        document = dict(state.document)
        del document['boot_chain']
        (state.run.directory / 'run-state.json').write_text(json.dumps(document))
        self.assertEqual([self.FIRST], run_state.RunState.load(state.run).boot_chain)

    def test_a_planned_reset_earns_one_recovery_and_the_file_allows_the_most_a_run_may_plan(self):
        state = self.state(phase='running')
        state.record('qga_recoveries', 4)
        with self.assertRaisesRegex(ValueError, 'exhausted'):
            state.record('qga_recoveries', 5)
        state.planned_reboots = 2
        state.record('qga_recoveries', 6)
        with self.assertRaisesRegex(ValueError, 'exhausted'):
            state.record('qga_recoveries', 7)
        self.assertEqual(6, run_state.RunState.load(state.run).budget('qga_recoveries'))
        self.assertEqual((4, 5, 6), tuple(run_state.limit('qga_recoveries', n) for n in (0, 1, 2)))
        self.assertEqual(128, run_state.limit('qmp_calls', 2))


if __name__ == '__main__':
    unittest.main()
