"""run-proxy.sh in the lab: where each window opens and closes, the control, and nothing new without the lab."""

from pathlib import Path
import re
import unittest

GUEST = Path(__file__).resolve().parents[2] / 'linux' / 'guest'
SCRIPT = GUEST / 'run-proxy.sh'
L3_SCRIPT = GUEST / 'run-l3.sh'
# The functions that open a session, each the label of its window (lab_label names the window after the
# function that called connect_with or lab_mark open).
OPENERS = ('proxy_open', 'strict', 'mode_change', 'share', 'share_off', 'lockdown_share', 'stopped')


def body(text, name, indent=''):
    """The lines of the function `name` defined at `indent`, without its braces."""
    head = indent + name + '() {\n'
    return text.split(head, 1)[1].split('\n' + indent + '}\n', 1)[0]


def lines(text):
    return [line.strip() for line in text.splitlines()]


def callers(text, call):
    """The name of the innermost function around each line that starts with `call`."""
    found, current = [], {}
    for line in text.splitlines():
        match = re.match(r'^( *)([A-Za-z_][A-Za-z0-9_]*)\(\) \{$', line)
        if match:
            current = {k: v for k, v in current.items() if k < len(match[1])}
            current[len(match[1])] = match[2]
            continue
        if line.strip().startswith(call):
            depth = len(line) - len(line.lstrip())
            found.append(next((current[k] for k in sorted(current, reverse=True) if k < depth), None))
    return found


class WindowTests(unittest.TestCase):
    def setUp(self):
        self.text = SCRIPT.read_text(encoding='utf-8')

    def test_the_session_helpers_are_those_of_run_l3_sh(self):
        l3 = L3_SCRIPT.read_text(encoding='utf-8')
        for name in ('connect_with', 'disconnect', 'control_stop_helper'):
            self.assertEqual(body(l3, name), body(self.text, name), name)

    def test_every_session_opens_in_a_function_named_after_its_window(self):
        # `lockdown_share` and `opened` connect under Lockdown, whose table keeps their markers from going out:
        # both sessions are in the one window `lockdown_share` opened before Lockdown went on.
        self.assertEqual(set(OPENERS) | {'opened'}, set(callers(self.text, 'connect_with ')))
        opened = lines(body(self.text, 'opened', '    '))
        self.assertLess(opened.index('lockdown_cli on --lan on || return 1'),
                        opened.index('connect_with request-proxy-share.json || return 1'))
        self.assertEqual(['connect_with', 'lockdown_share'], callers(self.text, 'lab_mark open'))

    def test_the_port_check_opens_no_window(self):
        busy = lines(body(self.text, 'busy', '    '))
        self.assertEqual('disconnect || return 1', busy[0])
        self.assertNotIn('connect_with', ' '.join(busy))
        self.assertIn('cli 120 connect request-proxy-strict.json', busy)

    def test_the_lockdown_window_opens_before_lockdown_and_closes_once_its_table_is_gone(self):
        opened = lines(body(self.text, 'lockdown_share', '    '))
        self.assertEqual('lab_mark open', next(line for line in opened if not line.startswith('#')))
        self.assertLess(opened.index('lab_mark open'), opened.index('lockdown_cli on --lan off || return 1'))
        off = lines(body(self.text, 'off', '    '))
        self.assertEqual('lab_mark close', off[-1])
        self.assertLess(off.index('lockdown_cli off || return 1'), off.index('lab_mark close'))
        self.assertTrue(any(line.startswith('! table_present ||') for line in off[:-1]))

    def test_the_window_after_a_stop_closes_once_the_table_is_gone_and_before_the_direct_request(self):
        stopped = lines(body(self.text, 'stopped', '    '))
        stop = next(i for i, line in enumerate(stopped) if 'systemctl stop rosetun-helper.service' in line)
        gone = next(i for i, line in enumerate(stopped) if line.startswith('! table_present ||'))
        close = stopped.index('lab_mark close')
        direct = next(i for i, line in enumerate(stopped) if 'direct_https' in line)
        self.assertLess(stop, gone)
        self.assertLess(gone, close)
        self.assertLess(close, direct)

    def test_every_direct_request_meant_for_after_a_session_follows_its_close(self):
        # `gone` ends the strict session with the disconnect that closes the window, then asks directly.
        gone = lines(body(self.text, 'gone', '    '))
        self.assertEqual('disconnect || return 1', gone[0])
        self.assertTrue(gone[-1].startswith('expect_reached') and 'direct_https' in gone[-1])

    def test_the_control_stops_the_service_inside_the_strict_window_only_after_its_first_pass(self):
        strict = lines(body(self.text, 'scenario_strict'))
        check = strict.index('check strict.through "the kill switch stood, without an adapter, and the proxy answered" strict')
        self.assertEqual('[ "$LAB_CONTROL" != stop-helper ] || ! passed strict.through || control_stop_helper',
                         strict[check + 1])
        reads = [line.strip() for line in self.text.splitlines() if 'LAB_CONTROL' in line and not line.lstrip().startswith('#')]
        self.assertEqual(4, len(reads))
        self.assertEqual(1, self.text.count('control_stop_helper\n'))

    def test_without_the_lab_nothing_new_runs(self):
        # The markers return at once without LAB_MARKER_ADDRESS (lib.sh, the self-test), and so does the
        # private address; these are the only places that call them.
        marks = [line.strip() for line in self.text.splitlines() if re.search(r'\blab_mark\b', line)
                 and not line.lstrip().startswith('#')]
        self.assertEqual(['lab_mark close', 'lab_mark open', 'lab_mark close', 'lab_mark open', 'lab_mark close',
                          'lab_mark close'], marks)
        self.assertEqual('[ -n "$LAB_MARKER_ADDRESS" ] || return 0', lines(body(self.text, 'lab_share_up'))[0])
        self.assertEqual(1, len(re.findall(r'^ +lab_share_up$', self.text, re.M)))
        self.assertIn('if lab_share_present; then printf', body(self.text, 'share_address'))
        self.assertIn('else phys_address; fi', body(self.text, 'share_address'))

    def test_the_lab_never_changes_l3(self):
        l3 = L3_SCRIPT.read_text(encoding='utf-8')
        for word in ('LAB_SHARE_ADDRESS', '192.168.77', 'lab_share'):
            self.assertNotIn(word, l3)
            self.assertNotIn(word, (GUEST / 'lib.sh').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
