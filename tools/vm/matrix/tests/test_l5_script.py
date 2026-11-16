"""run-l5.sh in the lab: where each window opens and closes, the control, and nothing new without the lab."""

from pathlib import Path
import re
import unittest

from tools.vm.matrix.tests.test_proxy_script import body, callers, lines

GUEST = Path(__file__).resolve().parents[2] / 'linux' / 'guest'
SCRIPT = GUEST / 'run-l5.sh'
L3_SCRIPT = GUEST / 'run-l3.sh'


class WindowTests(unittest.TestCase):
    def setUp(self):
        self.text = SCRIPT.read_text(encoding='utf-8')

    def test_the_session_helpers_and_the_control_are_those_of_run_l3_sh(self):
        l3 = L3_SCRIPT.read_text(encoding='utf-8')
        for name in ('connect_with', 'disconnect', 'control_stop_helper'):
            self.assertEqual(body(l3, name), body(self.text, name), name)

    def test_each_window_opens_in_a_function_named_after_it(self):
        # The one connect_with of the job; the reconnect of `do_reconnect` goes straight to the CLI under the hold,
        # whose table keeps any marker from going out, so it stays in the window `upgrade_ks`.
        self.assertEqual(['upgrade_ks'], callers(self.text, 'connect_with '))
        self.assertEqual(['connect_with', 'upgrade_lockdown'], callers(self.text, 'lab_mark open'))
        reconnect = lines(body(self.text, 'do_reconnect', '    '))
        self.assertIn('cli 120 connect request-kill-switch.json', reconnect)
        self.assertNotIn('connect_with', ' '.join(reconnect))

    def test_the_kill_switch_window_closes_with_the_disconnect_before_the_direct_request(self):
        reconnect = lines(body(self.text, 'do_reconnect', '    '))
        close = reconnect.index('disconnect || return 1')
        gone = next(i for i, line in enumerate(reconnect) if line.startswith('table_present && '))
        direct = next(i for i, line in enumerate(reconnect) if 'direct_https' in line)
        self.assertLess(close, gone)
        self.assertLess(gone, direct)
        self.assertEqual(direct, len(reconnect) - 1)
        self.assertEqual(['wait_state \'^Disconnected\' 30 || return 1', 'lab_mark close'],
                         lines(body(self.text, 'disconnect'))[-2:])

    def test_the_lockdown_window_opens_before_lockdown_and_closes_once_the_removal_took_the_table(self):
        lockdown = [line for line in lines(body(self.text, 'upgrade_lockdown', '    ')) if not line.startswith('#')]
        self.assertEqual('lab_mark close', lockdown[0])
        self.assertLess(lockdown.index('lab_mark close'), lockdown.index('install_package "$OLD_DEB" || return 1'))
        self.assertLess(lockdown.index('wait_service_answers || return 1'), lockdown.index('lab_mark open'))
        self.assertEqual(lockdown.index('lab_mark open') + 1, lockdown.index('lockdown_on || return 1'))
        remove = lines(body(self.text, 'do_remove', '    '))
        removal = next(i for i, line in enumerate(remove) if line == 'dpkg_run -r rosetun')
        gone = next(i for i, line in enumerate(remove) if line.startswith('table_present && '))
        close = remove.index('lab_mark close')
        direct = next(i for i, line in enumerate(remove) if 'direct_https' in line)
        self.assertLess(removal, gone)
        self.assertEqual(gone + 1, close)
        self.assertLess(close, direct)
        # `remove.refused` runs between them under Lockdown and touches no marker.
        self.assertNotIn('lab_mark', body(self.text, 'do_refused', '    '))

    def test_the_control_stops_the_service_inside_the_kill_switch_window_only_after_its_first_pass(self):
        upgrade = lines(body(self.text, 'scenario_upgrade'))
        check = upgrade.index('check upgrade.kill-switch-no-leak "the table stayed and nothing left past the tunnel" '
                              'upgrade_ks')
        self.assertEqual(['passed upgrade.kill-switch-no-leak || return 0',
                          '[ "$LAB_CONTROL" != stop-helper ] || control_stop_helper'], upgrade[check + 1:check + 3])
        self.assertLess(check, upgrade.index('check upgrade.kill-switch-hold "the hold, closed both ways" do_hold'))
        self.assertEqual(1, self.text.count('control_stop_helper\n'))

    def test_without_the_lab_nothing_new_runs(self):
        # lab_mark returns at once without LAB_MARKER_ADDRESS (lib.sh, the self-test); these are its only calls,
        # and LAB_CONTROL is read where it is set, checked and used, nowhere else.
        marks = [line.strip() for line in self.text.splitlines() if re.search(r'\blab_mark\b', line)
                 and not line.lstrip().startswith('#')]
        self.assertEqual(['lab_mark close', 'lab_mark open', 'lab_mark close', 'lab_mark close', 'lab_mark open',
                          'lab_mark close'], marks)
        reads = [line.strip() for line in self.text.splitlines() if 'LAB_CONTROL' in line
                 and not line.lstrip().startswith('#')]
        self.assertEqual(4, len(reads))
        self.assertEqual("LAB_MARKER_ADDRESS=''", next(line for line in lines(self.text)
                                                       if line.startswith('LAB_MARKER_ADDRESS=')))

    def test_the_counter_and_the_checks_of_the_scenarios_are_as_they_were(self):
        upgrade = body(self.text, 'upgrade_ks', '    ')
        for line in ('[ "${packets:-1}" -eq 0 ] || { fail_reason="$packets packets past the tunnel: '
                     '$(watch_senders "$since")"; return 1; }',
                     '[ "$missing" -eq 0 ] || { fail_reason="the table was gone at $missing of $attempts looks"; '
                     'return 1; }'):
            self.assertIn(line, upgrade)
        self.assertIn('oifname "$PHYS" ip daddr $PROBE_ADDRESS log prefix "rosetun-l5-watch: " flags skuid counter',
                      body(self.text, 'watch_up'))
        ids = re.findall(r'^ *check ([a-z.-]+) ', self.text, re.M)
        tsv = [row.split('\t')[0] for row in (GUEST.parent / 'scenarios-l5.tsv').read_text(encoding='utf-8')
               .splitlines()[1:] if row]
        self.assertEqual(tsv, ids)


if __name__ == '__main__':
    unittest.main()
