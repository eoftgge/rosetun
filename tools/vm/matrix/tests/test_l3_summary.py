"""The summary of an L3 run in the lab: the cross-check of the group against the windows and the exit code."""
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from tools.vm.matrix import l3_summary as summary, lab_protocol as wire
from tools.vm.matrix.tests.test_l3_lab import Flow, Machines, scenario_ids
from tools.vm.matrix.tests.test_lab import icmp, ip_frame

LEAK = ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 1, icmp(8))
SCRIPT = Path(__file__).resolve().parents[2] / 'linux' / 'guest' / 'run-l3.sh'
SESSIONS = ('killswitch.direct-blocked', 'killswitch.tunnel-passes', 'lan.off', 'killswitch.foreign-table',
            'killswitch.engine-killed', 'killswitch.flush-restored', 'killswitch.disconnect')


def results(**changes):
    """Every scenario passes, but for the ones named (id with dots as underscores) in `changes`."""
    rows = {identifier: ('PASS', 'ok') for identifier in scenario_ids()}
    for key, value in changes.items():
        rows[key.replace('__', '.').replace('_', '-')] = value
    return rows


def windows(leak_in=None, *, unclosed=None, drop=None, extra=()):
    """The five windows of a clean run, with a leak in one, one never closed or one left out."""
    spec = []
    for label in ('reported', 'identity', 'connect_ks', 'capabilities', 'lan_on'):
        if label == drop:
            continue
        spec.append((label, (LEAK,) if label == leak_in else (), label != unclosed))
    return spec + list(extra)


class RunTests(Flow):
    def agreements(self, result):
        return {row['id']: row['agreement'] for row in result['crosscheck']}

    def test_everything_agrees_and_the_code_is_zero(self):
        result = self.go(Machines(self))
        self.assertEqual((0, 'group-clean'), (result['exit_code'], result['outcome']))
        agreements = self.agreements(result)
        self.assertEqual(['NOT_APPLICABLE'] * 6, [agreements[i] for i in summary.GROUP[:6]])
        self.assertEqual({'AGREE'}, {agreements[i] for i in summary.GROUP[6:]})
        self.assertEqual(16, len(result['crosscheck']))
        self.assertTrue(result['group']['passed'])
        self.assertEqual(([], []), (result['group']['findings'], result['group']['unproven']))
        self.assertFalse(result['release_gate'])
        self.assertEqual('UNVERIFIED', result['security_invariants'])

    def test_the_scenarios_outside_the_group_are_listed_without_a_verdict(self):
        result = self.go(Machines(self, rows=results(rules__capabilities=('FAIL', 'x'),
                                                      inbound__reply=('FAIL', 'no sshd'))))
        self.assertEqual(23, len(result['out_of_scope']))
        self.assertEqual({'out-of-scope'}, {row['agreement'] for row in result['out_of_scope']})
        self.assertFalse(any('window_verdict' in row for row in result['out_of_scope']))
        self.assertFalse({row['id'] for row in result['out_of_scope']} & set(summary.GROUP))
        by_id = {row['id']: row['legacy_result'] for row in result['out_of_scope']}
        self.assertEqual(('FAIL', 'FAIL'), (by_id['rules.capabilities'], by_id['inbound.reply']))
        self.assertEqual(0, result['exit_code'])

    def test_a_leak_in_the_window_of_the_kill_switch_session_contradicts_every_pass_that_ran_in_it(self):
        result = self.go(Machines(self, windows=windows(leak_in='connect_ks')))
        agreements = self.agreements(result)
        self.assertEqual('DISAGREE', agreements['killswitch.engine-killed'])
        self.assertEqual({'DISAGREE'}, {agreements[i] for i in SESSIONS})
        self.assertEqual({'AGREE'}, {agreements['protection.reported'], agreements['engine.identity'],
                                     agreements['engine.files']})
        self.assertEqual((1, 'findings'), (result['exit_code'], result['outcome']))
        self.assertIn('pass-contradicted-by-window', result['group']['findings'])
        self.assertIn('leak-in-group-window', result['group']['findings'])
        self.assertEqual('DETECTED', next(r for r in result['crosscheck'] if r['id'] == 'lan.off')['window_verdict'])

    def test_a_window_that_never_closed_is_unobserved_and_the_code_is_two(self):
        result = self.go(Machines(self, windows=windows(unclosed='connect_ks')))
        agreements = self.agreements(result)
        self.assertEqual({'UNOBSERVED'}, {agreements[i] for i in SESSIONS})
        self.assertEqual('AGREE', agreements['protection.reported'])
        self.assertEqual((2, 'unverified'), (result['exit_code'], result['outcome']))
        self.assertIn('pass-not-observed', result['group']['unproven'])
        self.assertEqual([], result['group']['findings'])

    def test_a_label_of_the_group_without_a_window_is_unobserved_for_its_own_scenarios_only(self):
        result = self.go(Machines(self, windows=windows(drop='connect_ks')))
        agreements = self.agreements(result)
        self.assertEqual({'UNOBSERVED'}, {agreements[i] for i in SESSIONS})
        self.assertEqual({'AGREE'}, {agreements[i] for i in ('protection.reported', 'engine.identity',
                                                              'engine.files')})
        self.assertEqual(['connect_ks'], result['group']['missing_labels'])
        self.assertEqual(2, result['exit_code'])

    def test_a_failed_scenario_of_the_group_is_a_finding_whatever_the_window_says(self):
        result = self.go(Machines(self, rows=results(lan__off=('FAIL', 'reached'))))
        self.assertEqual(1, result['exit_code'])
        self.assertEqual('NOT_APPLICABLE', self.agreements(result)['lan.off'])
        self.assertEqual(['lan.off'], result['group']['failed'])
        self.assertFalse(result['group']['passed'])
        self.assertEqual('FAIL', next(r for r in result['legacy']['scenarios'] if r['id'] == 'lan.off')['result'])

    def test_what_follows_a_failure_as_not_run_does_not_hide_it(self):
        later = {i: ('ERROR', 'not run: an earlier step failed') for i in scenario_ids()}
        later.update({i: ('PASS', 'ok') for i in summary.GROUP[:4]})
        later['preflight.baseline'] = ('FAIL', 'no route')
        result = self.go(Machines(self, rows=later, windows=[]))
        self.assertEqual(1, result['exit_code'])
        self.assertEqual(['preflight.baseline'], result['group']['failed'])

    def test_a_scenario_of_the_group_that_did_not_run_without_a_failure_is_two(self):
        result = self.go(Machines(self, rows=results(install__service=('ERROR', 'not run'))))
        self.assertEqual((2, ['install.service']), (result['exit_code'], result['group']['not_run']))
        self.assertIn('group-scenario-did-not-run', result['group']['unproven'])
        rows = results()
        del rows['engine.files']
        result = self.go(Machines(self, rows=rows))
        self.assertEqual((2, 'MISSING'), (result['exit_code'], result['group']['results']['engine.files']))

    def test_scenarios_and_windows_outside_the_group_change_nothing_unless_they_saw_a_leak(self):
        rows = results(rules__capabilities=('FAIL', 'x'), dnslock__direct_blocked=('ERROR', 'y'),
                       ipv6__neighbor=('SKIP', 'z'))
        result = self.go(Machines(self, rows=rows, windows=windows(unclosed='capabilities')))
        capabilities = next(w for w in result['lab']['windows'] if w['label'] == 'capabilities')
        self.assertEqual('UNVERIFIED', capabilities['leak'])
        self.assertFalse(capabilities['in_group'])
        self.assertEqual((0, []), (result['exit_code'], result['group']['unproven']))

    def test_a_leak_in_a_window_outside_the_group_is_listed_and_decides_nothing_by_default(self):
        result = self.go(Machines(self, windows=windows(leak_in='lan_on')))
        self.assertEqual(['NONE', 'NONE', 'NONE', 'NONE', 'DETECTED'], [w['leak'] for w in result['lab']['windows']])
        self.assertEqual({'AGREE'}, set(self.agreements(result).values()) - {'NOT_APPLICABLE'})
        self.assertEqual((0, ['lan_on'], []), (result['exit_code'], result['group']['outside_leaks'],
                                              result['group']['findings']))
        with patch.object(summary, 'LEAK_OUTSIDE_THE_GROUP_FAILS', True):
            result = self.go_again(windows=windows(leak_in='lan_on'))
        self.assertEqual((1, ['leak-outside-group']), (result['exit_code'], result['group']['findings']))

    def test_two_windows_of_one_label_are_each_judged_and_the_worse_one_counts(self):
        spec = windows(leak_in='connect_ks')
        result = self.go(Machines(self, windows=spec[:3] + [('connect_ks', ())] + spec[3:]))
        row = next(r for r in result['crosscheck'] if r['id'] == 'lan.off')
        self.assertEqual(([2, 3], 'DETECTED', 'DISAGREE'), (row['windows'], row['window_verdict'], row['agreement']))
        self.assertEqual(1, result['exit_code'])

    def test_a_fixture_the_observer_did_not_see_answer_is_two(self):
        for fixture in ('node', 'https', 'dns'):
            with self.subTest(fixture=fixture):
                case = RunTests()
                case.setUp()
                try:
                    result = case.go(Machines(case, fixtures={fixture: False}))
                    self.assertEqual(2, result['exit_code'])
                    self.assertEqual(['fixtures-not-seen:' + fixture], result['group']['unproven'])
                    self.assertFalse(result['lab']['qualification']['fixtures'][fixture].get(
                        'alive_at_finish', False) or result['lab']['qualification']['fixtures'][fixture].get(
                        'answered', False))
                finally:
                    case.doCleanups()

    def test_doh_is_reported_but_the_group_does_not_need_it(self):
        result = self.go(Machines(self, fixtures={'doh': False}))
        self.assertEqual(0, result['exit_code'])
        self.assertFalse(result['lab']['qualification']['fixtures']['doh']['answered'])

    def test_a_disk_that_cannot_be_trusted_is_two_and_a_failure_still_counts(self):
        result = self.go(Machines(self, fault='incomplete'))
        self.assertEqual(2, result['exit_code'])
        self.assertTrue({'controller-error', 'evidence-disk', 'pass-not-observed'} <= set(result['group']['unproven']))
        failed = self.go_again(rows=results(lan__off=('FAIL', 'reached')), fault='incomplete')
        self.assertEqual(1, failed['exit_code'])

    def go_again(self, **kwargs):
        case = RunTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case.go(Machines(case, **kwargs))

    def test_the_whole_summary_is_saved_with_its_cross_check_in_both_runs(self):
        machines = Machines(self)
        result = self.go(machines)
        for run in machines.runs.values():
            saved = json.loads((run.directory / 'execution-summary.json').read_bytes())
            self.assertEqual(result['crosscheck'], saved['crosscheck'])
            self.assertEqual(result['exit_code'], saved['exit_code'])
        self.assertEqual({'legacy', 'lab', 'crosscheck', 'out_of_scope', 'group'}, {
            k for k in ('legacy', 'lab', 'crosscheck', 'out_of_scope', 'group') if k in result})


def synthetic(**changes):
    """A result as the controller leaves it, but for the decision alone."""
    result = dict(errors=[], completed=True, legacy=dict(scenarios=[
        dict(id=i, result='PASS') for i in scenario_ids()]), lab=dict(
        windows=[dict(index=n, label=label, leak='NONE', in_group=True) for n, label in enumerate(summary.GROUP_LABELS)],
        missing_labels=[], qualification=dict(
            evidence=dict(verified=True), observer=dict(reasons=[]),
            fixtures=dict(node=dict(alive_at_finish=True), https=dict(answered=True), dns=dict(answered=True),
                          doh=dict(answered=False)))))
    result.update(changes)
    return result


class DecisionTests(unittest.TestCase):
    def decide(self, interrupted=False, **changes):
        result = synthetic(**changes)
        summary.decide(result, interrupted)
        return result

    def test_a_clean_result_is_zero_and_an_interrupt_is_130_whatever_else_there_is(self):
        self.assertEqual(0, self.decide()['exit_code'])
        self.assertEqual(130, self.decide(True, errors=[1])['exit_code'])

    def test_a_finding_comes_before_a_doubt_and_a_doubt_before_nothing(self):
        leak = synthetic()
        leak['lab']['windows'][2]['leak'] = 'DETECTED'
        summary.decide(leak, False)
        self.assertEqual(1, leak['exit_code'])
        both = synthetic(errors=[dict(stage='x')], completed=False)
        both['lab']['windows'][2]['leak'] = 'DETECTED'
        summary.decide(both, False)
        self.assertEqual((1, ['machine-not-completed', 'controller-error']),
                         (both['exit_code'], list(reversed(both['group']['unproven']))))
        doubt = self.decide(errors=[dict(stage='x')])
        self.assertEqual((2, ['controller-error']), (doubt['exit_code'], doubt['group']['unproven']))

    def test_every_doubt_alone_is_two(self):
        cases = {'machine-not-completed': dict(completed=False), 'controller-error': dict(errors=[dict(stage='x')]),
                 'no-report': dict(legacy=dict(scenarios=[]))}
        for reason, change in cases.items():
            with self.subTest(reason=reason):
                result = self.decide(**change)
                self.assertEqual(2, result['exit_code'])
                self.assertIn(reason, result['group']['unproven'])
        for path, value, reason in ((('evidence', 'verified'), False, 'evidence-disk'),
                                    (('observer', 'reasons'), ['capture-limit-reached'], 'observer-not-clean')):
            with self.subTest(reason=reason):
                result = synthetic()
                result['lab']['qualification'][path[0]][path[1]] = value
                summary.decide(result, False)
                self.assertEqual((2, reason), (result['exit_code'], result['group']['unproven'][0]))

    def test_the_truth_table_of_the_cross_check(self):
        self.assertEqual({('PASS', 'NONE'): 'AGREE', ('PASS', 'DETECTED'): 'DISAGREE',
                          ('PASS', 'UNVERIFIED'): 'UNOBSERVED', ('PASS', None): 'UNOBSERVED'},
                         {(r, v): summary.agree(r, v) for r in ('PASS',) for v in ('NONE', 'DETECTED', 'UNVERIFIED', None)})
        for legacy in ('FAIL', 'ERROR', 'SKIP', 'MISSING'):
            for verdict in ('NONE', 'DETECTED', 'UNVERIFIED', None):
                self.assertEqual('NOT_APPLICABLE', summary.agree(legacy, verdict))
        self.assertEqual('DETECTED', summary.window_verdict([dict(leak='NONE'), dict(leak='DETECTED'),
                                                             dict(leak='UNVERIFIED')]))
        self.assertEqual('UNVERIFIED', summary.window_verdict([dict(leak='NONE'), dict(leak='UNVERIFIED')]))
        self.assertIsNone(summary.window_verdict([]))


class TableTests(unittest.TestCase):
    """The group and its windows are facts about the catalog and the script; they may not drift apart."""

    def test_the_group_is_in_the_catalog_and_every_scenario_has_its_window_entry(self):
        ids = scenario_ids()
        self.assertEqual(39, len(ids))
        self.assertTrue(set(summary.GROUP) <= set(ids))
        self.assertEqual(set(summary.GROUP), set(summary.WINDOW_OF))
        self.assertEqual(('reported', 'identity', 'connect_ks'), summary.GROUP_LABELS)
        self.assertEqual([i for i in ids if i.startswith('preflight.')], list(summary.GROUP[:5]))

    def test_each_label_is_a_function_of_the_script_that_opens_a_session(self):
        text = SCRIPT.read_text(encoding='utf-8')
        opened = dict(re.findall(r'^\s+check (\S+) ".*" (\w+)$', text, re.M))
        for identifier, label in (('protection.reported', 'reported'), ('engine.identity', 'identity'),
                                  ('killswitch.direct-blocked', 'connect_ks')):
            self.assertEqual(label, opened[identifier])
            body = text.split('    ' + label + '() {\n', 1)[1].split('\n    }\n', 1)[0]
            self.assertIn('connect_with', body)
            self.assertTrue(re.fullmatch(r'[a-z0-9_.-]{1,48}', label))
        # The scenarios that run in a session someone else opened end it or use it.
        for identifier in ('engine.files', 'killswitch.tunnel-passes', 'killswitch.disconnect'):
            self.assertIn(identifier, opened)
        files = text.split('    files() {\n', 1)[1].split('\n    }\n', 1)[0]
        self.assertTrue(files.rstrip().endswith('disconnect'))
        self.assertIn('disconnect_removes() {' + chr(10) + '        disconnect', text)

    def test_the_session_of_the_kill_switch_group_is_one_window_in_the_script(self):
        text = SCRIPT.read_text(encoding='utf-8')
        scenario = text.split('scenario_kill_switch() {' + chr(10), 1)[1].split(chr(10) + '}' + chr(10), 1)[0]
        self.assertEqual(1, scenario.count('connect_with request-kill-switch.json'))
        self.assertIn('disconnect_removes() {' + chr(10) + '        disconnect', text)


if __name__ == '__main__':
    unittest.main()
