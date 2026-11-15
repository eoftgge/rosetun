"""The summary of an L3 run in the lab: the cross-check of the group against the windows and the exit code."""
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from tools.vm.matrix import l3_summary as summary, lab_protocol as wire
from tools.vm.matrix.tests.test_l3_lab import (Flow, Machines, passing_rows, scenario_ids, scenario_rows, unrun_ids,
                                               wire_frame)
from tools.vm.matrix.tests.test_lab import icmp, ip_frame, tcp

LEAK = ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 1, icmp(8))
SCRIPT = Path(__file__).resolve().parents[2] / 'linux' / 'guest' / 'run-l3.sh'
SESSIONS = ('killswitch.direct-blocked', 'killswitch.tunnel-passes', 'lan.off', 'killswitch.foreign-table',
            'killswitch.engine-killed', 'killswitch.flush-restored', 'killswitch.disconnect')


def results(**changes):
    """Every scenario passes, but for the ones named (id with dots as underscores) in `changes`."""
    rows = passing_rows()
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
        self.assertEqual(len(scenario_ids()) - len(summary.GROUP), len(result['out_of_scope']))
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

    def test_of_two_windows_of_one_label_only_the_expected_one_is_judged(self):
        spec = windows()
        result = self.go(Machines(self, windows=spec[:3] + [('connect_ks', (LEAK,))] + spec[3:]))
        row = next(r for r in result['crosscheck'] if r['id'] == 'lan.off')
        self.assertEqual(([2], 0, 'NONE', 'AGREE'), (row['windows'], row['window_number'], row['window_verdict'],
                                                    row['agreement']))
        extra = result['lab']['windows'][3]
        self.assertEqual(('connect_ks', 1, False, 'DETECTED'), (extra['label'], extra['number'], extra['judged'],
                                                              extra['leak']))
        self.assertEqual((0, ['connect_ks'], []), (result['exit_code'], result['group']['outside_leaks'],
                                                  result['group']['findings']))
        counts = {row['label']: row for row in result['lab']['window_counts']}
        self.assertEqual(dict(label='connect_ks', expected=1, seen=2, as_expected=False), counts['connect_ks'])
        self.assertTrue(counts['reported']['as_expected'])

    def test_a_leak_in_the_judged_window_of_a_label_with_two_windows_still_counts(self):
        spec = windows(leak_in='connect_ks')
        result = self.go(Machines(self, windows=spec[:3] + [('connect_ks', ())] + spec[3:]))
        row = next(r for r in result['crosscheck'] if r['id'] == 'lan.off')
        self.assertEqual(([2], 'DETECTED', 'DISAGREE'), (row['windows'], row['window_verdict'], row['agreement']))
        self.assertEqual(1, result['exit_code'])

    def test_a_fixture_the_observer_did_not_see_answer_is_two(self):
        for fixture in ('node', 'https', 'dns', 'doh'):
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

    def test_the_https_target_without_an_answer_through_the_node_is_not_a_working_fixture(self):
        for seen in ('direct-only', 'node-only'):
            with self.subTest(seen=seen):
                result = self.go_again(fixtures={'https': seen})
                https = result['lab']['qualification']['fixtures']['https']
                self.assertEqual((2, ['fixtures-not-seen:https'], False),
                                 (result['exit_code'], result['group']['unproven'], https['answered']))
                self.assertEqual((seen == 'direct-only', seen == 'node-only'), (https['direct'], https['via_node']))

    def test_the_https_target_that_answered_both_paths_is_a_working_fixture(self):
        result = self.go(Machines(self))
        self.assertEqual((0, dict(answered=True, direct=True, via_node=True, requests=6)),
                         (result['exit_code'], result['lab']['qualification']['fixtures']['https']))

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
                          doh=dict(answered=True)))))
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

    def capabilities(self, verdicts):
        """`rules.capabilities` judged in the first of two windows `capabilities`, with these window verdicts."""
        result = synthetic()
        result['lab']['windows'] += [dict(index=len(result['lab']['windows']) + n, label='capabilities', leak=leak,
                                          in_group=True) for n, leak in enumerate(verdicts)]
        with patch.object(summary, 'GROUP', summary.GROUP + ('rules.capabilities',)),                 patch.dict(summary.WINDOW_OF, {'rules.capabilities': ('capabilities', 0)}),                 patch.dict(summary.WINDOWS_PER_LABEL, capabilities=2),                 patch.object(summary, 'GROUP_LABELS', summary.GROUP_LABELS + ('capabilities',)):
            summary.decide(result, False)
        return result, next(row for row in result['crosscheck'] if row['id'] == 'rules.capabilities')

    def test_of_two_windows_with_one_label_the_first_is_judged(self):
        result, row = self.capabilities(['NONE', 'DETECTED'])
        self.assertEqual((('capabilities', 0), [3], 'NONE', 'AGREE'),
                         ((row['window'], row['window_number']), row['windows'], row['window_verdict'],
                          row['agreement']))
        self.assertEqual((0, [], ['capabilities']), (result['exit_code'], result['group']['findings'],
                                                    result['group']['outside_leaks']))
        self.assertEqual([True, False], [w['judged'] for w in result['lab']['windows'][3:]])
        self.assertEqual([0, 1], [w['number'] for w in result['lab']['windows'][3:]])

    def test_a_leak_in_the_first_of_two_windows_contradicts_the_pass(self):
        result, row = self.capabilities(['DETECTED', 'NONE'])
        self.assertEqual(('DISAGREE', 1), (row['agreement'], result['exit_code']))
        self.assertIn('leak-in-group-window', result['group']['findings'])

    def test_without_the_first_of_two_windows_the_scenario_is_unobserved(self):
        result, row = self.capabilities(['DETECTED'])
        self.assertEqual(([], None, 'UNOBSERVED'), (row['windows'], row['window_verdict'], row['agreement']))
        self.assertEqual((2, [], ['capabilities']), (result['exit_code'], result['group']['findings'],
                                                    result['group']['outside_leaks']))
        self.assertIn('pass-not-observed', result['group']['unproven'])
        counts = {row['label']: row for row in result['lab']['window_counts']}
        self.assertEqual((2, 1, False), (counts['capabilities']['expected'], counts['capabilities']['seen'],
                                         counts['capabilities']['as_expected']))

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
        self.assertEqual(59, len(ids))
        self.assertTrue(set(summary.GROUP) <= set(ids))
        # The group has windows; the two-hop scenarios, which have no check yet, have none and are outside it.
        self.assertEqual(set(summary.GROUP) | set(summary.TWO_HOP), set(summary.WINDOW_OF))
        self.assertEqual({None}, {summary.WINDOW_OF[i] for i in summary.TWO_HOP})
        self.assertFalse(set(summary.GROUP) & set(summary.TWO_HOP))
        self.assertEqual(('reported', 'identity', 'connect_ks'), summary.GROUP_LABELS)
        self.assertEqual([i for i in ids if i.startswith('preflight.')], list(summary.GROUP[:5]))

    def test_the_two_hop_scenarios_are_exactly_the_rows_of_the_catalog_that_were_never_run(self):
        self.assertEqual(sorted(summary.TWO_HOP), sorted(unrun_ids()))
        self.assertEqual(20, len(summary.TWO_HOP))
        for row in scenario_rows():
            if row[0] in summary.TWO_HOP:
                self.assertEqual(('no', 'not-run', 'two-hop'), (row[1], row[2], row[3]))
        self.assertEqual(len(set(summary.TWO_HOP)), len(summary.TWO_HOP))
        self.assertEqual(('reported', 'identity', 'connect_ks'), summary.GROUP_LABELS)

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

    def test_a_window_closes_after_the_service_stops_but_never_with_the_table_there(self):
        text = SCRIPT.read_text(encoding='utf-8')
        body = text.split('lab_mark() {' + chr(10), 1)[1].split(chr(10) + '}' + chr(10), 1)[0]
        guard = [line.strip() for line in body.splitlines()]
        self.assertLess(guard.index('table_present && return 0'),
                        guard.index('[ "${1-}" = close ] && ! systemctl is-active --quiet rosetun-helper.service || return 0'))
        self.assertIn('[[ $(state_line) =~ ^Disconnected ]]', body)
        self.assertEqual(1, body.count('systemctl is-active'))
        stopped = text.split('    stopped() {' + chr(10), 1)[1].split(chr(10) + '    }' + chr(10), 1)[0]
        self.assertLess(stopped.index('systemctl stop rosetun-helper.service'), stopped.index('lab_mark close'))
        self.assertLess(stopped.index('! table_present'), stopped.index('lab_mark close'))

    def test_without_a_lab_address_the_markers_do_nothing(self):
        text = SCRIPT.read_text(encoding='utf-8')
        body = text.split('lab_mark() {' + chr(10), 1)[1].split(chr(10) + '}' + chr(10), 1)[0]
        self.assertEqual('[ -n "$LAB_MARKER_ADDRESS" ] || return 0', body.splitlines()[0].strip())


DIRECT_FLOW = (wire_frame(wire.CLIENTS[4], wire.TARGETS[4], 6, tcp(40000, 443, flags=0x02)),
               wire_frame(wire.TARGETS[4], wire.CLIENTS[4], 6, tcp(443, 40000, flags=0x12), reply=True))


class ControlTests(Flow):
    """The positive control `stop-helper`: a success only if the observer saw what the stopped service allowed."""

    def agreements(self, result):
        return {row['id']: row['agreement'] for row in result['crosscheck']}

    def direct(self, label='connect_ks', frames=DIRECT_FLOW):
        return [(name, frames if name == label else (), True) for name in
                ('reported', 'identity', 'connect_ks', 'capabilities', 'lan_on')]

    def control(self, spec=None, **options):
        return self.go(Machines(self, windows=spec if spec is not None else self.direct(), **options),
                       control='stop-helper')

    def test_the_run_succeeds_when_the_window_shows_the_direct_flow_the_script_says_was_refused(self):
        result = self.control()
        self.assertEqual((0, 'control-met', 'stop-helper'), (result['exit_code'], result['outcome'], result['control']))
        self.assertEqual(dict(name='stop-helper', expected=summary.CONTROL_EXPECTATIONS['stop-helper'], met=True,
                              ordinary_exit_code=1), result['control_result'])
        self.assertEqual('DISAGREE', self.agreements(result)['killswitch.direct-blocked'])
        self.assertFalse(result['release_gate'])
        self.assertEqual('UNVERIFIED', result['security_invariants'])

    def test_the_same_windows_without_the_control_are_an_ordinary_run_that_found_something(self):
        result = self.go(Machines(self, windows=self.direct()))
        self.assertEqual((1, 'findings'), (result['exit_code'], result['outcome']))
        self.assertNotIn('control', result)
        self.assertNotIn('control_result', result)

    def test_a_clean_window_where_the_control_means_a_leak_is_exit_two(self):
        result = self.control(self.direct(frames=()))
        self.assertEqual((2, 'control-not-met', False, 0), (result['exit_code'], result['outcome'],
                                                          result['control_result']['met'],
                                                          result['control_result']['ordinary_exit_code']))

    def not_met(self, spec, ordinary):
        # One run per test: the runs of a test share one state directory.
        result = self.control(spec)
        self.assertEqual((2, False, ordinary), (result['exit_code'], result['control_result']['met'],
                                                result['control_result']['ordinary_exit_code']))
        self.assertEqual([], result['errors'])

    @staticmethod
    def flow(source, target, port):
        return (wire_frame(source, target, 6, tcp(40000, port, flags=0x02)),
                wire_frame(target, source, 6, tcp(port, 40000, flags=0x12), reply=True))

    def test_a_leak_that_is_not_a_flow_to_the_target_is_exit_two(self):
        self.not_met(self.direct(frames=(LEAK,)), 1)

    def test_a_syn_the_target_never_answered_is_exit_two(self):
        self.not_met(self.direct(frames=DIRECT_FLOW[:1]), 1)

    def test_a_flow_to_another_port_of_the_target_is_exit_two(self):
        self.not_met(self.direct(frames=self.flow(wire.CLIENTS[4], wire.TARGETS[4], 8080)), 1)

    def test_a_flow_to_another_address_is_exit_two(self):
        self.not_met(self.direct(frames=self.flow(wire.CLIENTS[4], '198.51.100.7', 443)), 1)

    def test_the_flow_in_the_window_of_the_first_session_does_not_count(self):
        self.not_met(self.direct('reported'), 1)

    def test_the_flow_in_the_window_of_the_identity_session_does_not_count(self):
        self.not_met(self.direct('identity'), 1)

    def test_the_flow_in_a_window_outside_the_group_does_not_count(self):
        self.not_met(self.direct('capabilities'), 0)

    def test_a_scenario_that_did_not_pass_cannot_disagree_with_the_window(self):
        result = self.control(rows=results(killswitch__direct_blocked=('FAIL', 'the direct path answered')))
        self.assertEqual('NOT_APPLICABLE', self.agreements(result)['killswitch.direct-blocked'])
        self.assertEqual((2, False), (result['exit_code'], result['control_result']['met']))

    def test_a_machine_that_did_not_stop_is_exit_two_whatever_the_observer_saw(self):
        result = self.control()
        self.assertEqual(0, result['exit_code'])
        result['completed'] = False
        summary.decide(result, False)
        self.assertEqual((2, False), (result['exit_code'], result['control_result']['met']))

    def test_an_interrupted_control_run_stays_130(self):
        result = self.control()
        summary.decide(result, True)
        self.assertEqual((130, 'interrupted'), (result['exit_code'], result['outcome']))

    def test_only_the_stop_helper_control_exists(self):
        self.assertEqual(('stop-helper',), summary.CONTROLS)
        with self.assertRaisesRegex(ValueError, 'lab-control-invalid'):
            self.go(Machines(self), control='other')


class ScriptControlTests(unittest.TestCase):
    """`run-l3.sh`: the control acts in one place, and nothing changes without it."""

    def setUp(self):
        self.text = SCRIPT.read_text(encoding='utf-8')

    def body(self, name):
        return self.text.split(name + '() {' + chr(10), 1)[1].split(chr(10) + '}' + chr(10), 1)[0]

    def test_the_control_stops_the_service_and_makes_one_direct_request_inside_the_kill_switch_window(self):
        body = self.body('control_stop_helper')
        self.assertEqual(['timeout "$UNIT_TIMEOUT_SECONDS" systemctl stop rosetun-helper.service',
                          'direct_https >/dev/null'], [line.strip() for line in body.splitlines()])
        scenario = self.body('scenario_kill_switch')
        lines = [line.strip() for line in scenario.splitlines()]
        gate = lines.index('if ! passed killswitch.direct-blocked; then')
        control = lines.index('[ "$LAB_CONTROL" != stop-helper ] || control_stop_helper')
        self.assertLess(gate, control)
        # Between the passed check and the control nothing opens or closes a session, and there is one session.
        self.assertNotIn('connect_with', ' '.join(lines[gate:control]))
        self.assertEqual(1, scenario.count('connect_with request-kill-switch.json'))

    def test_nothing_else_reads_the_control_and_without_it_the_script_acts_as_before(self):
        reads = [line.strip() for line in self.text.splitlines() if 'LAB_CONTROL' in line]
        self.assertEqual(4, len(reads))
        self.assertIn("LAB_CONTROL=''", reads)
        self.assertIn('[ "$LAB_CONTROL" != stop-helper ] || control_stop_helper', reads)
        self.assertIn('[ -z "$LAB_CONTROL" ] || { [ "$LAB_CONTROL" = stop-helper ] && [ -n "$LAB_MARKER_ADDRESS" ]; } ||',
                      reads)
        self.assertTrue(any('DNS_PROBE_ADDRESS LAB_MARKER_ADDRESS LAB_CONTROL || return 1' in line for line in reads))

    def test_the_job_may_name_the_control_only_for_an_l3_stage(self):
        start = (SCRIPT.parent / 'start.sh').read_text(encoding='utf-8')
        self.assertIn('[ "$stage" != l3 ] || keys+=(LAB_MARKER_ADDRESS LAB_CONTROL)', start)


if __name__ == '__main__':
    unittest.main()
