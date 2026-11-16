"""run-l4.sh in the lab: the one window, the poller's key, the control, and nothing new without the lab."""

from pathlib import Path
import re
import unittest

from tools.vm.matrix.tests.test_proxy_script import body, callers, lines

GUEST = Path(__file__).resolve().parents[2] / 'linux' / 'guest'
SCRIPT = GUEST / 'run-l4.sh'


class WindowTests(unittest.TestCase):
    def setUp(self):
        self.text = SCRIPT.read_text(encoding='utf-8')

    def test_the_window_opens_in_the_function_that_gives_it_its_name_right_before_lockdown_goes_on(self):
        self.assertEqual(['lockdown'], callers(self.text, 'lab_mark open'))
        self.assertEqual(['lab_mark open', 'lockdown_as_root on "$@"'], lines(body(self.text, 'lockdown')))
        # The label of a window is the name of the first caller that is no helper of the markers.
        lib = (GUEST / 'lib.sh').read_text(encoding='utf-8')
        self.assertIn('case $name in lab_* | connect_with | disconnect) continue ;; esac', lib)
        turned_on = lines(body(self.text, 'turned_on', '    '))
        self.assertEqual('lockdown --lan off || return 1', turned_on[0])
        self.assertEqual(1, self.text.count('lockdown --lan off'))
        # The one other way of turning Lockdown on keeps the local network and opens no window.
        self.assertEqual(['inbound_lan'], callers(self.text, 'lockdown_lan_on ||'))
        self.assertEqual(2, len(re.findall(r'^\s*lockdown_as_root on', self.text, re.M)))

    def test_the_window_closes_after_reset_firewall_took_the_table_before_the_direct_request(self):
        reset = lines(body(self.text, 'reset', '    '))
        gone = next(i for i, line in enumerate(reset) if line.startswith('! table_present ||'))
        close = reset.index('lab_mark close')
        direct = next(i for i, line in enumerate(reset) if 'direct_https' in line)
        self.assertEqual(gone + 1, close)
        self.assertLess(close, direct)
        self.assertEqual(['reset'], callers(self.text, 'lab_mark close'))

    def test_the_scenarios_between_the_two_touch_no_marker(self):
        marks = [line.strip() for line in self.text.splitlines() if re.search(r'\blab_mark\b', line)
                 and not line.lstrip().startswith('#')]
        self.assertEqual(['lab_mark open', 'lab_mark close'], marks)
        self.assertNotIn('connect_with', ' '.join(callers(self.text, 'lab_mark')))

    def test_the_local_network_is_noted_before_it_goes_on_and_only_in_the_lab(self):
        note = lines(body(self.text, 'lockdown_lan_on'))
        self.assertEqual(['[ -z "$LAB_MARKER_ADDRESS" ] || date +%s%3N >"$STATE/lan-on-ms"',
                          'lockdown_as_root on --lan on'], note)
        cleanup = body(self.text, 'cleanup')
        self.assertIn('note "lan-on-ms=$(cat -- "$STATE/lan-on-ms")"', cleanup)

    def test_the_poller_key_is_installed_for_root_with_restrictions_and_taken_out_again(self):
        authorize = body(self.text, 'poller_authorize')
        self.assertIn('printf \'restrict,command="/bin/true" ssh-ed25519 %s rosetun-lab-poller\\n\' "$LAB_POLLER_KEY"',
                      authorize)
        self.assertTrue(authorize.startswith('\n    [ -n "$LAB_POLLER_KEY" ] || return 0') or
                        '[ -n "$LAB_POLLER_KEY" ] || return 0' in authorize)
        self.assertEqual(['phase_one'], callers(self.text, 'poller_authorize'))
        phase = lines(body(self.text, 'phase_one'))
        self.assertLess(phase.index('scenario_preflight'), phase.index('poller_authorize'))
        self.assertLess(phase.index('poller_authorize'), phase.index('scenario_install'))
        cleanup = body(self.text, 'cleanup')
        self.assertLess(cleanup.index('poller-key'), cleanup.index('nftables-enabled'))
        self.assertIn('grep -vF -- "$LAB_POLLER_KEY"', cleanup)

    def test_the_control_turns_the_boot_unit_off_before_the_reboot_and_asks_once_after_it(self):
        phase = lines(body(self.text, 'phase_one'))
        stop = phase.index('timeout "$UNIT_TIMEOUT_SECONDS" systemctl stop rosetun-helper.service')
        self.assertEqual(['[ "$LAB_CONTROL" != stop-helper ] || control_stop_helper', 'reboot_now reboot-1 && return'],
                         phase[stop + 1:stop + 3])
        self.assertEqual('systemctl disable --quiet rosetun-lockdown.service', lines(body(self.text, 'control_stop_helper'))[0])
        after = lines(body(self.text, 'phase_after_first_reboot'))
        self.assertEqual('[ "$LAB_CONTROL" != stop-helper ] || control_direct_request', after[0])
        self.assertEqual(['direct_https >/dev/null'], lines(body(self.text, 'control_direct_request')))
        self.assertEqual(1, self.text.count('control_stop_helper\n'))

    def test_without_the_lab_nothing_new_runs(self):
        for name in ('LAB_MARKER_ADDRESS', 'LAB_CONTROL', 'LAB_POLLER_KEY'):
            self.assertEqual(f"{name}=''", next(line for line in lines(self.text) if line.startswith(name + '=')))
        reads = [line.strip() for line in self.text.splitlines() if 'LAB_CONTROL' in line
                 and not line.lstrip().startswith('#')]
        self.assertEqual(5, len(reads), reads)
        for line in ('[ -n "$LAB_POLLER_KEY" ] || return 0', '[ -z "$LAB_MARKER_ADDRESS" ] || date +%s%3N'):
            self.assertIn(line, self.text)

    def test_the_checks_of_the_scenarios_are_as_they_were(self):
        ids = re.findall(r'^ *check ([a-z.-]+) ', self.text, re.M)
        tsv = [row.split('\t')[0] for row in (GUEST.parent / 'scenarios-l4.tsv').read_text(encoding='utf-8')
               .splitlines()[1:] if row]
        self.assertEqual(sorted(tsv), sorted(ids))
        for line in ('expect_blocked "HTTPS to $PROBE_ADDRESS by the route" routed_https',
                     'scope_probe rosetun-gui || return 1', 'scope_probe rosetun-cli || return 1',
                     'wait_host_accept "$since" "$HOST_CONNECT_SECONDS" || {',
                     'expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https'):
            self.assertIn(line, self.text)

    def test_four_scope_probes_get_out_and_two_are_refused(self):
        # The numbers EXPECTED_FLOWS of l4_tables rests on: a probe of a permitted scope must be answered.
        text = self.text
        allowed = []
        for name in ('gui_scope', 'cli_scope', 'after', 'killed'):
            pattern = r'^ *' + name + r'\(\) \{\n(?:.*\n)*? *\}\n'
            match = re.search(pattern, text, re.M)
            self.assertIsNotNone(match, name)
            allowed += re.findall(r'scope_probe (rosetun-[a-z]+)', match[0])
        self.assertEqual(['rosetun-gui', 'rosetun-cli', 'rosetun-gui', 'rosetun-cli'], allowed)
        refused = []
        for name in ('others', 'scope_closed'):
            match = re.search(r'^ *' + name + r'\(\) \{\n(?:.*\n)*? *\}\n', text, re.M)
            self.assertIsNotNone(match, name)
            refused += re.findall(r'scope_probe (rosetun-[a-z]+)', match[0])
        self.assertEqual(['rosetun-other', 'rosetun-gui'], refused)
        self.assertEqual(6, len(re.findall(r'^\s+scope_probe rosetun', text, re.M)))


if __name__ == '__main__':
    unittest.main()
