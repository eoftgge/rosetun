"""The summary of an L3 run in the lab: the cross-check of the group against the windows and the exit code."""
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from tools.vm.matrix import l3_summary as summary, lab_protocol as wire
from tools.vm.matrix.tests.test_l3_lab import (DIRECT_IN_A_CLEAN_RUN, WINDOWS_7B2B, WINDOWS_7C2, Flow, Machines,
                                               clean_windows, passing_rows, scenario_ids, scenario_rows, unrun_ids,
                                               wire_frame)
from tools.vm.matrix.tests.test_lab import icmp, ip_frame, tcp

LEAK = ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 1, icmp(8))
SCRIPT = Path(__file__).resolve().parents[2] / 'linux' / 'guest' / 'run-l3.sh'
SESSIONS = ('killswitch.direct-blocked', 'killswitch.tunnel-passes', 'lan.off', 'killswitch.foreign-table',
            'killswitch.engine-killed', 'killswitch.flush-restored', 'killswitch.disconnect')
# The scenarios stage 7c2 adds to the group, in order, with the window each is judged in.
ADDED = (('rules.capabilities', ('capabilities', 0)), ('rules.restart-guarded', ('restart_guarded', 0)),
         ('rules.search-misses', ('restart_guarded', 0)),
         ('inbound.reply', ('inbound', 0)), ('forward.blocked', ('inbound', 0)),
         ('crash.helper-killed', ('killed', 0)), ('crash.open-network', ('killed', 0)),
         ('crash.five-kills', ('five_kills', 0)), ('upgrade.restart', ('upgraded', 0)),
         ('upgrade.unprotected', None), ('stop.removes-table', ('stopped', 0)))
# The scenarios stage 7c3 adds: their windows show direct traffic by design and are held against an expectation.
ADDED_7C3 = (('rules.direct-other-account', ('capabilities', 1)),
             ('rules.proxy-default-direct', ('through_vpn_by_program', 0)),
             ('dnslock.direct-blocked', ('dns_lock', 0)), ('dnslock.tunnel-passes', ('dns_lock', 0)),
             ('dnslock.unavailable', ('dns_lock_unavailable', 0)),
             ('dnslock.unavailable-restart', ('missing_through_restart', 0)),
             ('crash.dns-lock-killed', ('dns_lock_killed', 0)))
LABELS = ('reported', 'identity', 'connect_ks', 'capabilities', 'restart_guarded', 'inbound', 'killed', 'five_kills',
          'upgraded', 'stopped', 'through_vpn_by_program', 'dns_lock', 'dns_lock_unavailable',
          'missing_through_restart', 'dns_lock_killed')
# Kept outside: Local network lets the own network through by design and the lab has no private host yet; the
# test machine has no IPv6 router.
OUTSIDE = ('lan.on', 'lan.private-closed', 'lan.private-open', 'lan.follows-change', 'ipv6.neighbor')


def results(**changes):
    """Every scenario passes, but for the ones named (id with dots as underscores) in `changes`."""
    rows = passing_rows()
    for key, value in changes.items():
        rows[key.replace('__', '.').replace('_', '-')] = value
    return rows


def windows(leak_in=None, *, unclosed=None, drop=None, extra=(), labels=WINDOWS_7C2):
    """The windows of a clean run, with a leak in one, one never closed or one left out.

    A window is named by its label (the first window with it) or by (label, number).
    """
    spec, seen = [], {}
    for label, direct in clean_windows(labels):
        number = seen.get(label, 0)
        seen[label] = number + 1
        named = {(label, number)} | ({label} if number == 0 else set())
        if drop in named:
            continue
        spec.append((label, tuple(direct) + ((LEAK,) if leak_in in named else ()), unclosed not in named))
    return spec + list(extra)


class RunTests(Flow):
    def agreements(self, result):
        return {row['id']: row['agreement'] for row in result['crosscheck']}

    def test_everything_agrees_and_the_code_is_zero(self):
        result = self.go(Machines(self))
        self.assertEqual((0, 'group-clean'), (result['exit_code'], result['outcome']))
        agreements = self.agreements(result)
        self.assertEqual({'NOT_APPLICABLE'}, {agreements[i] for i in summary.GROUP if summary.WINDOW_OF[i] is None})
        self.assertEqual({'AGREE'}, {agreements[i] for i in summary.GROUP if summary.WINDOW_OF[i] is not None})
        self.assertEqual(34, len(result['crosscheck']))
        self.assertEqual({True}, {row['as_expected'] for row in result['lab']['window_counts']})
        verdicts = {row['id']: row['window_verdict'] for row in result['crosscheck']}
        self.assertEqual({'EXPECTED'}, {verdicts[i] for i, _ in ADDED_7C3})
        self.assertTrue(result['group']['passed'])
        self.assertEqual(([], []), (result['group']['findings'], result['group']['unproven']))
        self.assertFalse(result['release_gate'])
        self.assertEqual('UNVERIFIED', result['security_invariants'])

    def test_the_scenarios_outside_the_group_are_listed_without_a_verdict(self):
        result = self.go(Machines(self, rows=results(lan__on=('FAIL', 'x'),
                                                      lan__private_closed=('FAIL', 'no private host'))))
        self.assertEqual(len(scenario_ids()) - len(summary.GROUP), len(result['out_of_scope']))
        self.assertEqual({'out-of-scope'}, {row['agreement'] for row in result['out_of_scope']})
        self.assertFalse(any('window_verdict' in row for row in result['out_of_scope']))
        self.assertFalse({row['id'] for row in result['out_of_scope']} & set(summary.GROUP))
        by_id = {row['id']: row['legacy_result'] for row in result['out_of_scope']}
        self.assertEqual(('FAIL', 'FAIL'), (by_id['lan.on'], by_id['lan.private-closed']))
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
        rows = results(lan__on=('FAIL', 'x'), lan__private_open=('ERROR', 'y'), ipv6__neighbor=('SKIP', 'z'))
        # A window that never closed spoils the ones after it, so the unclosed one is the last of the run.
        result = self.go(Machines(self, rows=rows, windows=windows(extra=[('lan_on', (), False)])))
        lan_on = result['lab']['windows'][-1]
        self.assertEqual(('lan_on', 'UNVERIFIED'), (lan_on['label'], lan_on['leak']))
        self.assertEqual((False, False), (lan_on['in_group'], lan_on['judged']))
        self.assertEqual((0, []), (result['exit_code'], result['group']['unproven']))

    def test_a_leak_in_a_window_outside_the_group_is_listed_and_decides_nothing_by_default(self):
        result = self.go(Machines(self, windows=windows(leak_in='lan_on')))
        self.assertEqual(['DETECTED' if w['label'] == 'lan_on' else 'EXPECTED' if w['expected_flows'] else 'NONE'
                          for w in result['lab']['windows']], [w['verdict'] for w in result['lab']['windows']])
        self.assertEqual({'AGREE'}, set(self.agreements(result).values()) - {'NOT_APPLICABLE'})
        self.assertEqual((0, ['lan_on'], []), (result['exit_code'], result['group']['outside_leaks'],
                                              result['group']['findings']))
        with patch.object(summary, 'LEAK_OUTSIDE_THE_GROUP_FAILS', True):
            result = self.go_again(windows=windows(leak_in='lan_on'))
        self.assertEqual((1, ['leak-outside-group']), (result['exit_code'], result['group']['findings']))

    def test_a_leak_in_a_window_beyond_the_count_of_a_label_of_the_group_is_a_finding(self):
        spec = windows()
        result = self.go(Machines(self, windows=spec[:3] + [('connect_ks', (LEAK,))] + spec[3:]))
        row = next(r for r in result['crosscheck'] if r['id'] == 'lan.off')
        self.assertEqual(([2], 0, 'NONE', 'AGREE'), (row['windows'], row['window_number'], row['window_verdict'],
                                                    row['agreement']))
        extra = result['lab']['windows'][3]
        self.assertEqual(('connect_ks', 1, False, True, 'DETECTED'),
                         (extra['label'], extra['number'], extra['judged'], extra['beyond'], extra['leak']))
        self.assertEqual((1, [], ['leak-in-group-window']), (result['exit_code'], result['group']['outside_leaks'],
                                                             result['group']['findings']))
        counts = {row['label']: row for row in result['lab']['window_counts']}
        self.assertEqual(dict(label='connect_ks', expected=1, at_most=None, seen=2, as_expected=False),
                         counts['connect_ks'])
        self.assertTrue(counts['reported']['as_expected'])

    def test_a_clean_window_beyond_the_count_leaves_the_run_unable_to_vouch(self):
        spec = windows()
        result = self.go(Machines(self, windows=spec[:3] + [('connect_ks', ())] + spec[3:]))
        self.assertEqual((2, 'unverified', []), (result['exit_code'], result['outcome'], result['group']['findings']))
        self.assertEqual(['window-count:connect_ks:expected=1,seen=2'], result['group']['unproven'])
        self.assertEqual({'AGREE', 'NOT_APPLICABLE'}, set(self.agreements(result).values()))

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


def direct_of(*kinds, opened=True, other_frames=0):
    """The `direct` of a window whose unexpected frames are one flow of each of these kinds."""
    servers = {'target': (f'{wire.TARGETS[4]}:443', 'tcp'), 'resolver': (f'{wire.RESOLVER}:53', 'udp'),
               'other': ('203.0.113.9:443', 'tcp')}
    return dict(flows=[dict(protocol=servers[kind][1], kind=kind, client=f'192.0.2.2:{44000 + n}',
                            server=servers[kind][0], frames_out=2, frames_back=1, opened=opened)
                       for n, kind in enumerate(kinds)], other_frames=other_frames, omitted_frames=0)


def synthetic(labels=WINDOWS_7C2, leaks=None, **changes):
    """A result as the controller leaves it, but for the decision alone; `leaks` maps a window's index to its verdict.

    The windows with an expectation show their one flow, as in a clean run, and the observer calls them DETECTED;
    a window `leaks` calls DETECTED shows one more flow, so it is a leak with or without an expectation.
    """
    leaks, rows, seen = leaks or {}, [], {}
    for n, label in enumerate(labels):
        number = seen.get(label, 0)
        seen[label] = number + 1
        kind, leak = DIRECT_IN_A_CLEAN_RUN.get((label, number)), leaks.get(n)
        kinds = ([kind] if kind else []) + (['other'] if leak == 'DETECTED' else [])
        rows.append(dict(index=n, label=label, leak=leak or ('DETECTED' if kind else 'NONE'),
                         in_group=label in summary.GROUP_LABELS, observer_reasons=[], direct=direct_of(*kinds)))
    result = dict(errors=[], completed=True, legacy=dict(scenarios=[
        dict(id=i, result='PASS') for i in scenario_ids()]), lab=dict(
        windows=rows,
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
        """`rules.capabilities` judged in the first of the windows `capabilities`, with these window verdicts."""
        labels = [label for label in WINDOWS_7C2 if label != 'capabilities']
        labels[3:3] = ['capabilities'] * len(verdicts)
        result = synthetic(labels, dict(enumerate(verdicts, start=3)))
        summary.decide(result, False)
        return result, next(row for row in result['crosscheck'] if row['id'] == 'rules.capabilities')

    def test_of_two_windows_with_one_label_each_scenario_is_judged_in_its_own(self):
        result, row = self.capabilities(['NONE', 'DETECTED'])
        self.assertEqual((('capabilities', 0), [3], 'NONE', 'AGREE'),
                         ((row['window'], row['window_number']), row['windows'], row['window_verdict'],
                          row['agreement']))
        other = next(r for r in result['crosscheck'] if r['id'] == 'rules.direct-other-account')
        self.assertEqual((('capabilities', 1), [4], 'DETECTED', 'DISAGREE'),
                         ((other['window'], other['window_number']), other['windows'], other['window_verdict'],
                          other['agreement']))
        self.assertEqual((1, []), (result['exit_code'], result['group']['outside_leaks']))
        self.assertIn('leak-in-group-window', result['group']['findings'])
        self.assertEqual([True, True], [w['judged'] for w in result['lab']['windows'][3:5]])
        self.assertEqual([0, 1], [w['number'] for w in result['lab']['windows'][3:5]])

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


class GroupOf7c2Tests(unittest.TestCase):
    """The group of stage 7c2: every session under the kill switch where no direct traffic is expected."""

    def decide(self, labels=WINDOWS_7C2, leaks=None, **rows):
        result = synthetic(labels, leaks)
        for row in result['legacy']['scenarios']:
            if row['id'] in rows:
                row['result'] = rows[row['id']]
        summary.decide(result, False)
        return result, {row['id']: row for row in result['crosscheck']}

    def test_the_table_of_the_added_windows_is_the_one_of_the_stage_in_its_order(self):
        self.assertEqual([identifier for identifier, _ in ADDED], list(summary.GROUP[16:27]))
        self.assertEqual(list(ADDED), [(i, summary.WINDOW_OF[i]) for i in summary.GROUP[16:27]])
        self.assertEqual(list(ADDED_7C3), [(i, summary.WINDOW_OF[i]) for i in summary.GROUP[27:]])
        self.assertEqual(34, len(summary.GROUP))
        self.assertEqual(LABELS, summary.GROUP_LABELS)
        self.assertEqual({'forward.blocked': ('forwarded', 0),
                          'rules.direct-other-account': ('direct_for_other_account', 0)},
                         summary.OWN_WINDOW_WHEN_OPENED)

    def test_every_scenario_of_the_group_is_in_the_catalog_and_has_a_window_entry(self):
        ids = scenario_ids()
        for identifier in summary.GROUP:
            self.assertIn(identifier, ids)
            self.assertIn(identifier, summary.WINDOW_OF)
        self.assertEqual(len(summary.GROUP), len(set(summary.GROUP)))
        self.assertFalse(set(OUTSIDE) & set(summary.GROUP))
        self.assertTrue(set(OUTSIDE) <= set(ids))
        for label, _ in filter(None, summary.WINDOW_OF.values()):
            self.assertIn(label, summary.WINDOWS_PER_LABEL)
        self.assertFalse(summary.LEAK_OUTSIDE_THE_GROUP_FAILS)

    def test_the_windows_of_a_run_with_sshd_make_the_whole_group_agree(self):
        # As in the 7b2b and 7c1 runs: the windows where a program or UDP 53 goes direct by design saw just that
        # (synthetic), and the Local network windows saw their own network.
        leaks = {n: 'DETECTED' for n, label in enumerate(WINDOWS_7C2) if label in ('lan_on', 'lan_private_open')}
        result, table = self.decide(leaks=leaks)
        self.assertEqual(20, len(result['lab']['windows']))
        self.assertEqual(34, len(table))
        self.assertEqual(['lan_on', 'lan_private_open'], result['group']['outside_leaks'])
        self.assertEqual({'AGREE', 'NOT_APPLICABLE'}, {row['agreement'] for row in table.values()})
        self.assertEqual({None}, {table[i]['window'] for i in summary.GROUP if table[i]['agreement'] != 'AGREE'})
        self.assertEqual((0, 'group-clean'), (result['exit_code'], result['outcome']))
        self.assertEqual(('inbound', [14]), (table['forward.blocked']['window'], table['forward.blocked']['windows']))
        self.assertEqual({True}, {row['as_expected'] for row in result['lab']['window_counts']})

    def test_the_windows_of_the_7b2b_runs_judge_forward_blocked_in_the_session_forwarded_opened(self):
        result, table = self.decide(WINDOWS_7B2B, None, **{'inbound.reply': 'FAIL'})
        self.assertEqual(('forwarded', [14], 'AGREE'), (table['forward.blocked']['window'],
                                                         table['forward.blocked']['windows'],
                                                         table['forward.blocked']['agreement']))
        self.assertEqual(('inbound', [], 'NOT_APPLICABLE'), (table['inbound.reply']['window'],
                                                             table['inbound.reply']['windows'],
                                                             table['inbound.reply']['agreement']))
        self.assertEqual({'AGREE', 'NOT_APPLICABLE'}, {row['agreement'] for row in table.values()})
        self.assertEqual((1, ['group-scenario-failed']), (result['exit_code'], result['group']['findings']))
        counts = {row['label']: row for row in result['lab']['window_counts']}
        self.assertEqual((1, 0), (counts['inbound']['expected'], counts['inbound']['seen']))

    def test_a_pass_of_inbound_reply_without_its_window_is_unobserved(self):
        result, table = self.decide(WINDOWS_7B2B)
        self.assertEqual(('UNOBSERVED', 'AGREE'), (table['inbound.reply']['agreement'],
                                                   table['forward.blocked']['agreement']))
        self.assertEqual(2, result['exit_code'])

    def test_a_leak_in_the_window_killed_is_a_finding(self):
        result, table = self.decide(leaks={WINDOWS_7C2.index('killed'): 'DETECTED'})
        self.assertEqual(('DISAGREE', 'DISAGREE'), (table['crash.helper-killed']['agreement'],
                                                    table['crash.open-network']['agreement']))
        self.assertEqual((1, 'findings'), (result['exit_code'], result['outcome']))
        self.assertIn('leak-in-group-window', result['group']['findings'])

    def test_a_leak_in_each_new_window_contradicts_the_scenarios_judged_in_it(self):
        for label in ('restart_guarded', 'inbound', 'five_kills', 'upgraded', 'stopped'):
            with self.subTest(label=label):
                result, table = self.decide(leaks={WINDOWS_7C2.index(label): 'DETECTED'})
                judged = [i for i in summary.GROUP if table[i]['window'] == label]
                self.assertTrue(judged)
                self.assertEqual({'DISAGREE'}, {table[i]['agreement'] for i in judged})
                self.assertEqual(1, result['exit_code'])

    def test_the_session_forwarded_opened_after_inbound_lost_its_own_is_the_one_judged(self):
        labels = list(WINDOWS_7C2)
        labels.insert(15, 'forwarded')
        result, table = self.decide(labels, {15: 'DETECTED'})
        self.assertEqual((('forwarded', 0), [15], 'DISAGREE'),
                         ((table['forward.blocked']['window'], table['forward.blocked']['window_number']),
                          table['forward.blocked']['windows'], table['forward.blocked']['agreement']))
        self.assertEqual('AGREE', table['inbound.reply']['agreement'])
        self.assertEqual(1, result['exit_code'])

    def test_each_label_of_the_group_is_a_function_of_the_script_that_opens_a_session(self):
        text = SCRIPT.read_text(encoding='utf-8')
        functions = dict(re.findall(r'^\s+check (\S+) ".*" (\w+)$', text, re.M))
        for label in summary.GROUP_LABELS + ('forwarded',):
            with self.subTest(label=label):
                body = text.split('    ' + label + '() {\n', 1)[1].split('\n    }\n', 1)[0]
                self.assertIn('connect_with', body)
        # The scenarios that do not open their window run after the one that did, in the same function or later.
        self.assertEqual(('forwarded', 'opened'), (functions['forward.blocked'], functions['crash.open-network']))
        self.assertEqual('idle_restart', functions['upgrade.unprotected'])

    def test_the_second_connect_of_five_kills_and_upgraded_happens_under_the_hold(self):
        text = SCRIPT.read_text(encoding='utf-8')
        for label, hold in (('five_kills', 'kill_helper'), ('upgraded', '--restart-for-upgrade')):
            with self.subTest(label=label):
                body = text.split('    ' + label + '() {\n', 1)[1].split('\n    }\n', 1)[0]
                lines = [line.strip() for line in body.splitlines()]
                connects = [n for n, line in enumerate(lines) if 'connect_with request-kill-switch.json' in line]
                self.assertEqual(2, len(connects))
                between = lines[connects[0] + 1:connects[1]]
                # Only a hold keeps the table between the two sessions; nothing in between disconnects.
                self.assertTrue(any(hold in line for line in between))
                self.assertFalse(any(line.startswith(('disconnect', 'cli 60 disconnect', 'lab_mark'))
                                     for line in between))
                self.assertEqual('disconnect', lines[connects[1]:][-1 if label == 'upgraded' else -2].split()[0])

    def test_the_window_killed_closes_after_open_network_removed_the_table_and_before_the_direct_probe(self):
        text = SCRIPT.read_text(encoding='utf-8')
        body = [line.strip() for line in text.split('    opened() {\n', 1)[1].split('\n    }\n', 1)[0].splitlines()]
        close = body.index('lab_mark close')
        self.assertLess(next(n for n, line in enumerate(body) if line.startswith('! table_present')), close)
        self.assertLess(close, next(n for n, line in enumerate(body) if 'direct_https' in line))

    def test_a_count_other_than_expected_without_a_finding_is_two_and_names_the_label(self):
        for labels, reason in (([label for label in WINDOWS_7C2 if label != 'stopped'],
                                'window-count:stopped:expected=1,seen=0'),
                               (list(WINDOWS_7C2) + ['upgraded'], 'window-count:upgraded:expected=1,seen=2'),
                               (list(WINDOWS_7C2) + ['forwarded', 'forwarded'],
                                'window-count:forwarded:expected=at-most-1,seen=2')):
            with self.subTest(reason=reason):
                result, _ = self.decide(labels)
                self.assertEqual(2, result['exit_code'])
                self.assertIn(reason, result['group']['unproven'])
                self.assertEqual([], result['group']['findings'])

    def test_a_leak_in_a_second_window_of_a_label_that_may_have_one_is_a_finding(self):
        labels = list(WINDOWS_7C2) + ['forwarded', 'forwarded']
        result, table = self.decide(labels, {21: 'DETECTED'})
        self.assertEqual((20, 'AGREE'), (table['forward.blocked']['windows'][0], table['forward.blocked']['agreement']))
        self.assertEqual((1, ['leak-in-group-window'], []), (result['exit_code'], result['group']['findings'],
                                                             result['group']['outside_leaks']))

    def test_the_second_capabilities_window_is_judged_for_the_direct_rule_of_another_account(self):
        result, table = self.decide(leaks={4: 'DETECTED'})
        window = result['lab']['windows'][4]
        self.assertEqual(('capabilities', 1, True, False), (window['label'], window['number'], window['judged'],
                                                            window['beyond']))
        self.assertEqual(('AGREE', 'DISAGREE'), (table['rules.capabilities']['agreement'],
                                                 table['rules.direct-other-account']['agreement']))
        self.assertEqual((1, []), (result['exit_code'], result['group']['outside_leaks']))

    def test_an_unprotected_restart_has_no_window(self):
        result, table = self.decide()
        self.assertEqual((None, None, 'NOT_APPLICABLE'), (table['upgrade.unprotected']['window'],
                                                          table['upgrade.unprotected']['window_number'],
                                                          table['upgrade.unprotected']['agreement']))


def function_body(text, name):
    return [line.strip() for line in text.split('    ' + name + '() {\n', 1)[1].split('\n    }\n', 1)[0].splitlines()]


class GroupOf7c3Tests(unittest.TestCase):
    """The group of stage 7c3: the windows where a program, a request or UDP 53 goes direct by design."""

    def decide(self, labels=WINDOWS_7C2, direct=None, **rows):
        """`direct` maps a window's index to the `direct` it showed instead of its expected flow."""
        result = synthetic(labels)
        for index, shown in (direct or {}).items():
            result['lab']['windows'][index].update(
                direct=shown, leak='DETECTED' if shown['flows'] or shown['other_frames'] else 'NONE')
        for row in result['legacy']['scenarios']:
            if row['id'] in rows:
                row['result'] = rows[row['id']]
        summary.decide(result, False)
        return result, {row['id']: row for row in result['crosscheck']}

    def test_every_expectation_names_a_window_the_group_counts_or_one_that_stands_in_for_it(self):
        for label, number in summary.EXPECTED_FLOWS:
            with self.subTest(label=label):
                limit = summary.WINDOWS_PER_LABEL.get(label, summary.WINDOWS_AT_MOST.get(label))
                self.assertIsNotNone(limit)
                self.assertLess(number, limit)
        judged = {summary.WINDOW_OF[i] for i, _ in ADDED_7C3} | {summary.OWN_WINDOW_WHEN_OPENED[ADDED_7C3[0][0]]}
        self.assertEqual(judged, set(summary.EXPECTED_FLOWS))

    def test_fewer_flows_than_expected_contradict_every_pass_judged_in_the_window(self):
        for identifier, (label, number) in ADDED_7C3:
            with self.subTest(identifier=identifier):
                index = [n for n, pair in enumerate(summary.numbered([dict(label=x) for x in WINDOWS_7C2]))
                         if pair == (label, number)][0]
                result, table = self.decide(direct={index: direct_of()})
                self.assertEqual(('MISMATCH', 'DISAGREE'), (table[identifier]['window_verdict'],
                                                            table[identifier]['agreement']))
                self.assertEqual((1, ['pass-contradicted-by-window']), (result['exit_code'],
                                                                        result['group']['findings']))

    def test_more_than_expected_is_a_leak_in_a_window_of_the_group(self):
        for identifier, (label, number) in ADDED_7C3:
            with self.subTest(identifier=identifier):
                index = [n for n, pair in enumerate(summary.numbered([dict(label=x) for x in WINDOWS_7C2]))
                         if pair == (label, number)][0]
                kind = DIRECT_IN_A_CLEAN_RUN[(label, number)]
                result, table = self.decide(direct={index: direct_of(kind, kind)})
                self.assertEqual('DISAGREE', table[identifier]['agreement'])
                self.assertEqual(1, result['exit_code'])
                self.assertIn('leak-in-group-window', result['group']['findings'])

    def test_a_failure_stays_a_failure_whatever_the_window_showed(self):
        result, table = self.decide(direct={WINDOWS_7C2.index('dns_lock_unavailable'): direct_of()},
                                    **{'dnslock.unavailable': 'FAIL'})
        self.assertEqual(('MISMATCH', 'NOT_APPLICABLE'), (table['dnslock.unavailable']['window_verdict'],
                                                          table['dnslock.unavailable']['agreement']))
        self.assertEqual((1, ['group-scenario-failed']), (result['exit_code'], result['group']['findings']))

    def test_the_session_another_account_opened_after_capabilities_lost_its_own_is_the_one_judged(self):
        labels = list(WINDOWS_7C2)
        labels.insert(5, 'direct_for_other_account')
        result, table = self.decide(labels, **{'rules.capabilities': 'FAIL'})
        row = table['rules.direct-other-account']
        self.assertEqual((('direct_for_other_account', 0), [5], 'EXPECTED', 'AGREE'),
                         ((row['window'], row['window_number']), row['windows'], row['window_verdict'],
                          row['agreement']))
        counts = {row['label']: row for row in result['lab']['window_counts']}
        self.assertEqual((1, True), (counts['direct_for_other_account']['seen'],
                                     counts['direct_for_other_account']['as_expected']))

    def test_a_dns_lock_session_opened_again_is_beyond_the_count_and_has_no_expectation(self):
        labels = list(WINDOWS_7C2)
        labels.insert(12, 'dns_lock')
        result, table = self.decide(labels, direct={12: direct_of('target')})
        extra = result['lab']['windows'][12]
        self.assertEqual(('dns_lock', 1, True, [], 'DETECTED'), (extra['label'], extra['number'], extra['beyond'],
                                                                extra['expected_flows'], extra['verdict']))
        self.assertEqual(1, result['exit_code'])
        self.assertIn('window-count:dns_lock:expected=1,seen=2', result['group']['unproven'])

    def test_the_expected_counts_are_what_the_functions_of_the_script_send(self):
        text = SCRIPT.read_text(encoding='utf-8')
        # One direct HTTPS request in `kill_helper`, while a DNS lock still stands in `dns_lock_killed`.
        self.assertEqual(1, text.split('\nkill_helper() {\n', 1)[1].split('\n}\n', 1)[0].count('direct_https'))
        dns_lock = function_body(text, 'dns_lock')
        self.assertEqual((1, 1, 0), (sum('direct_https' in line for line in dns_lock),
                                     sum('expect_udp_dns_refused' in line for line in dns_lock),
                                     sum('expect_udp_dns_sent' in line for line in dns_lock)))
        for name in ('dns_lock_unavailable', 'missing_through_restart'):
            body = function_body(text, name)
            self.assertEqual((1, 0), (sum('expect_udp_dns_sent' in line for line in body),
                                      sum('direct_https' in line for line in body)), name)
        for name in ('direct_for_other_account', 'through_vpn_by_program'):
            routes = [line for line in function_body(text, name) if 'expect_route' in line]
            self.assertEqual(2, len(routes), name)
            self.assertEqual(1, sum(line.endswith(' direct') or ' direct &&' in line for line in routes), name)
        # The window of a DNS lock that a crash left closes once the restarted helper removed it, before the
        # datagram and the request that are meant to leave afterwards.
        killed = function_body(text, 'dns_lock_killed')
        close = killed.index('lab_mark close')
        self.assertLess(next(n for n, line in enumerate(killed) if line.startswith('! table_present')), close)
        self.assertLess(next(n for n, line in enumerate(killed) if line.startswith('kill_helper')), close)
        self.assertLess(close, next(n for n, line in enumerate(killed) if 'expect_udp_dns_sent' in line))
        self.assertLess(close, next(n for n, line in enumerate(killed) if 'direct_https' in line))


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
        self.assertEqual(LABELS, summary.GROUP_LABELS)
        self.assertEqual([i for i in ids if i.startswith('preflight.')], list(summary.GROUP[:5]))

    def test_the_two_hop_scenarios_are_exactly_the_rows_of_the_catalog_that_were_never_run(self):
        self.assertEqual(sorted(summary.TWO_HOP), sorted(unrun_ids()))
        self.assertEqual(20, len(summary.TWO_HOP))
        for row in scenario_rows():
            if row[0] in summary.TWO_HOP:
                self.assertEqual(('no', 'not-run', 'two-hop'), (row[1], row[2], row[3]))
        self.assertEqual(len(set(summary.TWO_HOP)), len(summary.TWO_HOP))
        self.assertEqual(LABELS, summary.GROUP_LABELS)

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


class ExpectationTests(unittest.TestCase):
    """Stage 7c3: a window where direct traffic is expected by design passes only on exactly that traffic."""
    TARGET = ('tcp', 'target', '203.0.113.2:443')
    RESOLVER = ('udp', 'resolver', '203.0.113.53:53')

    def verdict(self, direct, expected=None, leak='DETECTED', reasons=()):
        window = dict(leak=leak, observer_reasons=list(reasons), direct=direct)
        return summary.expectation_verdict(window, {self.TARGET: 1} if expected is None else expected)

    def test_the_expectations_are_the_flows_the_functions_of_the_script_send(self):
        self.assertEqual({('capabilities', 1): {self.TARGET: 1}, ('direct_for_other_account', 0): {self.TARGET: 1},
                          ('through_vpn_by_program', 0): {self.TARGET: 1}, ('dns_lock', 0): {self.TARGET: 1},
                          ('dns_lock_unavailable', 0): {self.RESOLVER: 1},
                          ('missing_through_restart', 0): {self.RESOLVER: 1},
                          ('dns_lock_killed', 0): {self.TARGET: 1}}, summary.EXPECTED_FLOWS)
        self.assertEqual(set(DIRECT_IN_A_CLEAN_RUN), set(summary.EXPECTED_FLOWS))

    def test_exactly_the_expected_flows_is_expected(self):
        self.assertEqual('EXPECTED', self.verdict(direct_of('target')))
        self.assertEqual('EXPECTED', self.verdict(direct_of('resolver'), {self.RESOLVER: 1}))
        self.assertEqual('EXPECTED', self.verdict(direct_of('target', 'resolver'), {self.TARGET: 1, self.RESOLVER: 1}))

    def test_fewer_flows_than_expected_is_a_mismatch(self):
        self.assertEqual('MISMATCH', self.verdict(direct_of(), leak='NONE'))
        self.assertEqual('MISMATCH', self.verdict(direct_of('target'), {self.TARGET: 2}))
        self.assertEqual('MISMATCH', self.verdict(direct_of('target'), {self.TARGET: 1, self.RESOLVER: 1}))

    def test_more_or_other_than_expected_is_detected(self):
        for direct, expected in ((direct_of('target', 'target'), None), (direct_of('target', 'other'), None),
                                 (direct_of('resolver'), None), (direct_of('target', other_frames=1), None),
                                 (direct_of('target', opened=False), None),
                                 (direct_of('other'), {self.RESOLVER: 1}),
                                 (dict(direct_of('target'), omitted_frames=1), None)):
            with self.subTest(direct=direct):
                self.assertEqual('DETECTED', self.verdict(direct, expected))
        # A flow beyond the expectation is a leak whatever the observer's doubts, and fewer of one kind does not
        # make up for one of another.
        self.assertEqual('DETECTED', self.verdict(direct_of('target', 'target'), reasons=['observer-health']))
        self.assertEqual('DETECTED', self.verdict(direct_of('resolver'), {self.TARGET: 1, self.RESOLVER: 0}))

    def test_a_window_that_cannot_vouch_for_itself_is_unverified_unless_it_saw_more(self):
        self.assertEqual('UNVERIFIED', self.verdict(direct_of('target'), reasons=['observer-health']))
        self.assertEqual('UNVERIFIED', self.verdict(direct_of(), leak='UNVERIFIED', reasons=['window-missing']))
        self.assertEqual('UNVERIFIED', self.verdict(direct_of(), leak='UNVERIFIED'))

    def test_without_a_record_of_the_flows_only_a_window_without_a_leak_compares(self):
        self.assertEqual('DETECTED', summary.expectation_verdict(dict(leak='DETECTED'), {self.TARGET: 1}))
        self.assertEqual('MISMATCH', summary.expectation_verdict(dict(leak='NONE'), {self.TARGET: 1}))

    def test_an_expected_window_confirms_a_pass_and_a_mismatch_contradicts_it(self):
        self.assertEqual(('AGREE', 'DISAGREE', 'DISAGREE'),
                         tuple(summary.agree('PASS', v) for v in ('EXPECTED', 'MISMATCH', 'DETECTED')))
        for verdict in ('EXPECTED', 'MISMATCH'):
            self.assertEqual('NOT_APPLICABLE', summary.agree('FAIL', verdict))
        self.assertEqual('EXPECTED', summary.window_verdict([dict(leak='DETECTED', verdict='EXPECTED')]))
        self.assertEqual('MISMATCH', summary.window_verdict([dict(leak='NONE', verdict='MISMATCH'),
                                                             dict(leak='UNVERIFIED')]))
        self.assertEqual('DETECTED', summary.window_verdict([dict(leak='NONE', verdict='MISMATCH'),
                                                             dict(leak='DETECTED')]))

    def test_each_window_lists_its_expectation_and_its_verdict(self):
        result = synthetic()
        summary.decide(result, False)
        by_label = {(w['label'], w['number']): w for w in result['lab']['windows']}
        self.assertEqual([dict(protocol='udp', kind='resolver', server='203.0.113.53:53', direction='out', count=1)],
                         by_label[('dns_lock_unavailable', 0)]['expected_flows'])
        dns_lock = by_label[('dns_lock', 0)]
        self.assertEqual(('DETECTED', 'EXPECTED'), (dns_lock['leak'], dns_lock['verdict']))
        self.assertEqual(([], 'NONE'), (by_label[('capabilities', 0)]['expected_flows'],
                                        by_label[('capabilities', 0)]['verdict']))
        self.assertEqual({'NONE', 'EXPECTED'}, {w['verdict'] for w in result['lab']['windows']})
        self.assertEqual((0, []), (result['exit_code'], result['group']['outside_leaks']))

    def test_more_than_expected_in_a_window_with_an_expectation_is_a_leak(self):
        result = synthetic()
        window = result['lab']['windows'][WINDOWS_7C2.index('dns_lock')]
        window['direct'] = direct_of('target', 'resolver')
        summary.decide(result, False)
        self.assertEqual('DETECTED', window['verdict'])
        self.assertEqual(([], 1), (result['group']['outside_leaks'], result['exit_code']))
        self.assertEqual(['leak-in-group-window', 'pass-contradicted-by-window'], sorted(result['group']['findings']))


class FlowExpectationTests(Flow):
    def test_the_flows_a_clean_run_shows_by_design_make_their_windows_expected(self):
        result = self.go(Machines(self))
        verdicts = {(w['label'], w['number']): w['verdict'] for w in result['lab']['windows']}
        for key in summary.EXPECTED_FLOWS:
            if key[0] in WINDOWS_7C2:
                self.assertEqual('EXPECTED', verdicts[key], key)
        self.assertEqual({'NONE', 'EXPECTED'}, set(verdicts.values()))
        self.assertEqual((0, []), (result['exit_code'], result['group']['outside_leaks']))

    def test_a_retried_datagram_to_the_resolver_is_one_flow_and_a_second_request_is_a_leak(self):
        from tools.vm.matrix.tests.test_l3_lab import direct_flow
        spec = clean_windows()
        index = WINDOWS_7C2.index('dns_lock_unavailable')
        spec[index] = ('dns_lock_unavailable', spec[index][1] + direct_flow('resolver', 47000))
        result = self.go(Machines(self, windows=spec))
        window = result['lab']['windows'][index]
        self.assertEqual(2, len(window['direct']['flows']))
        self.assertEqual('DETECTED', window['verdict'])


DIRECT_FLOW = (wire_frame(wire.CLIENTS[4], wire.TARGETS[4], 6, tcp(40000, 443, flags=0x02)),
               wire_frame(wire.TARGETS[4], wire.CLIENTS[4], 6, tcp(443, 40000, flags=0x12), reply=True))


class ControlTests(Flow):
    """The positive control `stop-helper`: a success only if the observer saw what the stopped service allowed."""

    def agreements(self, result):
        return {row['id']: row['agreement'] for row in result['crosscheck']}

    def direct(self, label='connect_ks', frames=DIRECT_FLOW):
        return [(name, frames if name == label else body, True) for name, body in clean_windows()]

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

    def test_the_flow_in_another_window_of_the_group_does_not_count(self):
        self.not_met(self.direct('stopped'), 1)

    def test_the_flow_in_a_window_outside_the_group_does_not_count(self):
        self.not_met(self.direct('lan_on'), 0)

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
